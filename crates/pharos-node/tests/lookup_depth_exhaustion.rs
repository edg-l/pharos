//! Integration test: lookup loop fires `notify_backfill` on depth exhaustion.
//!
//! **Scenario**: A chain longer than `MAX_LOOKUP_DEPTH` (MAX+3 blocks). The
//! fixture provider always returns a block when asked, but that block's own
//! parent is never in the fc_store (only genesis is seeded). The walk keeps
//! decrementing depth until it reaches 0 and fires `notify_backfill`.
//!
//! **Assertion**: `notify_backfill.notified()` resolves within 5 seconds.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::get_forkchoice_store;
use pharos_network::host::ForkContext as _;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::Fork as NetworkFork;
use pharos_ssz::Encode as _;
use pharos_stf::NullExecutionEngine;
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::primitives::Version;
use pharos_types::state::BeaconBlock as ForkBeaconBlock;
use pharos_types::{BeaconSpec, MinimalBeaconSpec};
use pharos_utils::{Epoch, Hash256};
use tokio::sync::{Notify, mpsc, watch};

use pharos_node::block_ingestion::ReinjectBlock;
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::lookup::{
    LookupBlockProvider, LookupError, LookupRequest, MAX_LOOKUP_DEPTH, run_lookup_loop,
};
use pharos_node::pending_blocks::PendingBlocks;

mod common;
use common::checkpoint_helpers::{
    BACKFILL_GENESIS_TIME_SECS, MinForkSignedBlock, TERMINAL_BLOCK_HASH_BYTES,
    build_anchor_bellatrix, build_backfill_chain,
};

// ── Fixture LookupBlockProvider ───────────────────────────────────────────────

/// A provider that serves the chain in a map. Whenever the walk requests a
/// root that exists in the map, it returns that block. If the root is unknown,
/// it returns `NoUsablePeers` (so the walk terminates early by the error path —
/// but in this test every requested root IS served, the parent is just never
/// in fc_store, so depth decrements all the way to 0).
#[derive(Clone)]
struct ChainLookupProvider {
    map: Arc<std::collections::HashMap<pharos_types::phase0::primitives::Root, MinForkSignedBlock>>,
}

impl ChainLookupProvider {
    fn new(
        blocks: &[MinForkSignedBlock],
        roots: &[pharos_types::phase0::primitives::Root],
    ) -> Self {
        let map = blocks
            .iter()
            .zip(roots.iter())
            .map(|(b, r)| (*r, b.clone()))
            .collect();
        Self { map: Arc::new(map) }
    }
}

impl LookupBlockProvider<MinimalBeaconSpec> for ChainLookupProvider {
    async fn blocks_by_root(
        &self,
        roots: Vec<pharos_types::phase0::primitives::Root>,
    ) -> Result<Vec<MinForkSignedBlock>, LookupError> {
        let mut out = Vec::new();
        for r in roots {
            if let Some(b) = self.map.get(&r) {
                out.push(b.clone());
            }
        }
        if out.is_empty() {
            Err(LookupError::NoUsablePeers)
        } else {
            Ok(out)
        }
    }

    async fn blobs_by_root(
        &self,
        _ids: Vec<pharos_types::deneb::BlobIdentifier>,
    ) -> Result<Vec<pharos_types::deneb::BlobSidecar>, LookupError> {
        // Bellatrix fixtures carry no blobs; the DA gate treats availability as
        // Irrelevant, so this is never reached.
        Ok(Vec::new())
    }

    async fn data_columns_by_root(
        &self,
        _ids: Vec<pharos_types::fulu::DataColumnsByRootIdentifier<128>>,
    ) -> Result<Vec<pharos_types::fulu::DataColumnSidecar<4096, 4>>, LookupError> {
        // Pre-Fulu fixtures: the column co-fetch path is never exercised.
        Ok(Vec::new())
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookup_depth_exhaustion_fires_notify_backfill() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build a chain that is MAX_LOOKUP_DEPTH+3 blocks long — longer than the
    // walk can cover in one pass.
    let n_blocks = (MAX_LOOKUP_DEPTH as u64) + 3;

    let (anchor_state_inner, anchor_signed) = build_anchor_bellatrix(
        pharos_types::phase0::primitives::Slot(0),
        BACKFILL_GENESIS_TIME_SECS,
    );

    let genesis_state =
        pharos_types::state::MinimalBeaconState::Bellatrix(anchor_state_inner.clone());
    let anchor_block = ForkBeaconBlock::Bellatrix(anchor_signed.message.clone());

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(genesis_state, anchor_block);
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );
    // ONLY the anchor is seeded; none of the chain blocks are imported.
    let fc_store = Arc::new(RwLock::new(fc));

    let chain = build_backfill_chain(&anchor_state_inner, n_blocks);
    assert_eq!(chain.len(), n_blocks as usize);

    // Compute roots.
    let block_roots: Vec<pharos_types::phase0::primitives::Root> = chain
        .iter()
        .map(|b| match b {
            MinForkSignedBlock::Bellatrix(inner) => {
                use pharos_ssz::TreeHash as _;
                inner.message.tree_hash_root()
            }
            _ => unreachable!(),
        })
        .collect();

    // Provider serves every block in the chain by root.
    let provider = ChainLookupProvider::new(&chain, &block_roots);

    // Host + storage.
    let tmpdir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );
    let genesis_validators_root = pharos_types::phase0::primitives::Root::default();
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalBeaconSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalBeaconSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: Epoch(0),
        bellatrix_fork_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: Epoch(0),
        capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
        capella_fork_epoch: Epoch(u64::MAX),
        deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
        deneb_fork_epoch: Epoch(u64::MAX),
        electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
        electra_fork_epoch: Epoch(u64::MAX),
        fulu_fork_version: Version::from_array([0x06, 0x00, 0x00, 0x00]),
        fulu_fork_epoch: Epoch(u64::MAX),
        blob_schedule: Vec::new(),
        genesis_validators_root,
    };
    let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
        db,
        Arc::clone(&fc_store),
        genesis_validators_root,
        fork_schedule,
        BACKFILL_GENESIS_TIME_SECS,
        Arc::new(pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
            ..Default::default()
        }),
    ));

    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (lookup_tx, lookup_rx) = mpsc::channel::<LookupRequest>(64);
    let (reinject_tx, _reinject_rx) = mpsc::channel::<ReinjectBlock>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let pending = Arc::new(PendingBlocks::default());
    let notify_backfill = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify_backfill);

    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);
    let exec_engine = Arc::new(NullExecutionEngine);

    tokio::spawn(run_lookup_loop::<
        MinimalBeaconSpec,
        ChainLookupProvider,
        NullExecutionEngine,
        pharos_fork_choice::NoopPowBlockProvider,
    >(
        lookup_rx,
        provider,
        host.clone(),
        Arc::clone(&fc_store),
        exec_engine,
        pow_provider,
        head_tx,
        payload_tx,
        pending,
        notify_backfill,
        reinject_tx,
        shutdown_rx,
        [0u8; 32],
        MinimalBeaconSpec::CUSTODY_REQUIREMENT,
    ));

    // Send the tip block (index n_blocks-1) as an orphan.
    let tip_idx = (n_blocks - 1) as usize;
    let fork_digest = host.fork_digest_for(NetworkFork::Bellatrix);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let tip_ssz = match &chain[tip_idx] {
        MinForkSignedBlock::Bellatrix(inner) => inner.as_ssz_bytes(),
        _ => unreachable!(),
    };

    lookup_tx
        .send(LookupRequest::UnknownParent {
            topic,
            peer: libp2p::PeerId::random(),
            data: tip_ssz,
        })
        .await
        .unwrap();

    // Assert: notify_backfill fires within 5 seconds (depth exhausted).
    tokio::time::timeout(Duration::from_secs(5), notify_clone.notified())
        .await
        .expect("notify_backfill must fire within 5s on depth exhaustion");

    let _ = shutdown_tx.send(true);
}
