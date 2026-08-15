//! Integration test: lookup loop fetches missing ancestors and replays queued orphans.
//!
//! **Scenario**: A 3-block Bellatrix chain (block1→block2→block3). The
//! fork-choice store is seeded with only the genesis anchor (blocks 1-3 absent).
//! The test sends `LookupRequest::UnknownParent` for block3 to `run_lookup_loop`,
//! which then walks backward via the fixture provider (block2_root→block2,
//! block1_root→block1) and imports the full chain in order.
//!
//! **Assertion**: after the walk completes and descendants are replayed,
//! `get_head` returns `block3_root`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{get_forkchoice_store, get_head};
use pharos_network::host::ForkContext as _;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::Fork as NetworkFork;
use pharos_ssz::Encode as _;
use pharos_stf::NullExecutionEngine;
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::primitives::{Root, Version};
use pharos_types::state::BeaconBlock as ForkBeaconBlock;
use pharos_types::{EthSpec, MinimalEthSpec};
use pharos_utils::{Epoch, Hash256};
use tokio::sync::{Notify, mpsc, watch};

use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::lookup::{LookupBlockProvider, LookupError, LookupRequest, run_lookup_loop};
use pharos_node::pending_blocks::PendingBlocks;

mod common;
use common::checkpoint_helpers::{
    BACKFILL_GENESIS_TIME_SECS, MinForkSignedBlock, TERMINAL_BLOCK_HASH_BYTES,
    build_anchor_bellatrix, build_backfill_chain,
};

// ── Fixture LookupBlockProvider ───────────────────────────────────────────────

/// Returns blocks from a pre-built root→block map, one block per request.
#[derive(Clone)]
struct MapLookupProvider {
    map: Arc<HashMap<Root, MinForkSignedBlock>>,
}

impl MapLookupProvider {
    fn new(map: HashMap<Root, MinForkSignedBlock>) -> Self {
        Self { map: Arc::new(map) }
    }
}

impl LookupBlockProvider<MinimalEthSpec> for MapLookupProvider {
    async fn blocks_by_root(
        &self,
        roots: Vec<Root>,
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
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookup_replay_fetches_and_replays_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build genesis anchor at slot 0, genesis_time = BACKFILL_GENESIS_TIME_SECS.
    let (anchor_state_inner, anchor_signed) = build_anchor_bellatrix(
        pharos_types::phase0::primitives::Slot(0),
        BACKFILL_GENESIS_TIME_SECS,
    );

    // Wrap for fork-choice store construction.
    let genesis_state =
        pharos_types::state::MinimalBeaconState::Bellatrix(anchor_state_inner.clone());
    let anchor_block = ForkBeaconBlock::Bellatrix(anchor_signed.message.clone());

    let mut fc = get_forkchoice_store::<MinimalEthSpec>(genesis_state, anchor_block);
    // Advance time so on_block's "future slot" guard doesn't reject blocks.
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );
    let fc_store = Arc::new(RwLock::new(fc));

    // Build a 3-block chain from the anchor state.
    let chain = build_backfill_chain(&anchor_state_inner, 3);
    assert_eq!(chain.len(), 3);

    // Extract block roots by re-hashing each block's inner message.
    let block_roots: Vec<Root> = chain
        .iter()
        .map(|b| match b {
            MinForkSignedBlock::Bellatrix(inner) => {
                use pharos_ssz::TreeHash as _;
                inner.message.tree_hash_root()
            }
            _ => unreachable!("build_backfill_chain always yields Bellatrix blocks"),
        })
        .collect();

    let block3_root = block_roots[2];

    // Provider maps block1 and block2 by root. block3 is the initial orphan — it
    // is sent via LookupRequest::UnknownParent and never fetched by root.
    // The walk from block3.parent_root (= block2_root) fetches block2; block2's
    // parent_root (= block1_root) fetches block1; block1's parent_root (= anchor_root)
    // is already in the fc_store, so the walk terminates.
    let mut provider_map: HashMap<Root, MinForkSignedBlock> = HashMap::new();
    provider_map.insert(block_roots[0], chain[0].clone()); // block1_root → block1
    provider_map.insert(block_roots[1], chain[1].clone()); // block2_root → block2
    let provider = MapLookupProvider::new(provider_map);

    // Build host + RocksDB.
    let tmpdir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );
    let genesis_validators_root = Root::default();
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: Epoch(0),
        bellatrix_fork_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: Epoch(0),
        genesis_validators_root,
    };
    let host = Arc::new(HostImpl::<MinimalEthSpec>::new(
        db,
        Arc::clone(&fc_store),
        genesis_validators_root,
        fork_schedule,
        BACKFILL_GENESIS_TIME_SECS,
        Arc::new(pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            ..Default::default()
        }),
    ));

    // Channels.
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(64);
    let (lookup_tx, lookup_rx) = mpsc::channel::<LookupRequest>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let pending = Arc::new(PendingBlocks::default());
    let notify_backfill = Arc::new(Notify::new());

    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);
    let exec_engine = Arc::new(NullExecutionEngine);

    let fc_for_assert = Arc::clone(&fc_store);

    // Spawn run_lookup_loop.
    let loop_handle = tokio::spawn(run_lookup_loop::<
        MinimalEthSpec,
        MapLookupProvider,
        NullExecutionEngine,
        pharos_fork_choice::NoopPowBlockProvider,
    >(
        lookup_rx,
        provider,
        Arc::clone(&host),
        Arc::clone(&fc_store),
        exec_engine,
        pow_provider,
        head_tx,
        payload_tx,
        Arc::clone(&pending),
        Arc::clone(&notify_backfill),
        shutdown_rx,
    ));

    // Build the gossip topic for block3 (raw inner Bellatrix SSZ).
    let fork_digest = host.fork_digest_for(NetworkFork::Bellatrix);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    // Encode block3 as raw inner SSZ (as real gossip would carry it).
    let block3_ssz = match &chain[2] {
        MinForkSignedBlock::Bellatrix(inner) => inner.as_ssz_bytes(),
        _ => unreachable!(),
    };

    // Send the UnknownParent request for block3.
    lookup_tx
        .send(LookupRequest::UnknownParent {
            topic,
            peer: dummy_peer,
            data: block3_ssz,
        })
        .await
        .unwrap();

    // Poll until head == block3_root or timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let head = {
            let s = fc_for_assert.read();
            get_head::<MinimalEthSpec>(&s)
        };
        if head == block3_root {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let head = {
                let s = fc_for_assert.read();
                get_head::<MinimalEthSpec>(&s)
            };
            panic!("timeout: head={head:?} expected block3_root={block3_root:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Shut down the loop.
    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), loop_handle)
        .await
        .expect("lookup loop must exit after shutdown")
        .expect("loop task must not panic")
        .expect("run_lookup_loop must return Ok");
}
