//! Fulu lookup-path DA gate integration test (M13-Fulu lookup-DA fix, Phase 4).
//!
//! The lookup co-fetch must branch on the block's fork: a Fulu+ block carries
//! its data as `DataColumnSidecar`s (EIP-7594 PeerDAS), NOT blob sidecars, so
//! the lookup path must co-fetch columns via `DataColumnSidecarsByRoot` (not
//! `BlobSidecarsByRoot`) and gate the import on the column DA sub-checker of the
//! `ForkAwareDataAvailabilityChecker`. Before the fix the lookup path always
//! fetched blobs, so Fulu blocks carrying commitments never imported (the blob
//! SSZ decode failed and the DA gate rejected forever).
//!
//! Two assertions:
//!
//! 1. **Negative** (`fulu_lookup_co_fetches_columns_and_da_gate_rejects`): a mock
//!    `LookupBlockProvider` whose `data_columns_by_root` RECORDS it was invoked
//!    and returns `Ok(vec![])` (no columns). The Fulu block carrying a blob
//!    commitment is routed through the Fulu arm, the column DA gate sees no
//!    stored columns → `NotAvailable`, so the block is NOT imported (head stays
//!    at the anchor). The test also asserts `data_columns_by_root` (NOT
//!    `blobs_by_root`) was the provider method invoked — proving the fork-branch.
//!
//! 2. **Positive (persistence)** (`fulu_lookup_persists_fetched_columns`): the
//!    mock returns the node's expected column sidecars; the test asserts every
//!    expected column is persisted to `CF_DATA_COLUMN_SIDECARS` under the block
//!    root after the lookup runs. This proves the Fulu co-fetch + persist path
//!    end-to-end. Full import (which additionally requires KZG-valid columns +
//!    a valid STF crossing) is intentionally NOT asserted here: KZG-valid column
//!    generation needs real blobs + the trusted setup and is impractical in this
//!    unit harness — the full KZG-gated `Available` verdict is covered by
//!    `fulu_pipeline::column_availability_checker_is_custody_gated` and the
//!    `fulu/transition` conformance runner. This test does NOT fake a DA pass.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{NoopPowBlockProvider, get_forkchoice_store, get_head};
use pharos_ssz::{Encode as _, SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::NullExecutionEngine;
use pharos_storage::{RocksStore, RocksStoreConfig, Store as DbStore};
use pharos_types::altair::MinimalSyncCommittee;
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::KZGCommitment;
use pharos_types::fork::ForkSchedule;
use pharos_types::fulu::data_column_sidecar::ColumnIndex;
use pharos_types::fulu::{
    DataColumnsByRootIdentifier, MinimalBeaconBlock as FuluMinimalBeaconBlock,
    MinimalBeaconBlockBody as FuluMinimalBeaconBlockBody,
    MinimalBeaconState as FuluMinimalBeaconState, MinimalDataColumnSidecar,
    MinimalSignedBeaconBlock as FuluMinimalSignedBeaconBlock,
};
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinimalBeaconState,
    SignedBeaconBlock as ForkSignedBeaconBlock,
};
use pharos_types::{BeaconSpec, MinimalBeaconSpec};
use pharos_utils::{BLSPubkey, BLSSignature, Epoch as UtilsEpoch, Hash256};
use tokio::sync::{mpsc, watch};

use pharos_network::host::ForkContext as _;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::Fork as NetworkFork;

use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::lookup::{LookupBlockProvider, LookupError, LookupRequest, run_lookup_loop};
use pharos_node::pending_blocks::PendingBlocks;

mod common;

// ── Constants ───────────────────────────────────────────────────────────────────

const TERMINAL_HASH: [u8; 32] = [0x01u8; 32];

// ── Fork-enum type aliases (minimal preset) ──────────────────────────────────────

type MinForkSignedBlock = ForkSignedBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;

// ── Test pubkey helper ──────────────────────────────────────────────────────────

fn test_pubkey() -> BLSPubkey {
    let sk = blst::min_pk::SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM");
    BLSPubkey::from_array(sk.sk_to_pk().compress())
}

// ── Fixture builders ──────────────────────────────────────────────────────────

/// Build a Fulu genesis anchor state at slot 0 with one active validator.
///
/// Returns `(anchor_signed_inner, fork_enum_state)`; the column DA gate is
/// fork-agnostic, so the anchor only needs to drive `get_forkchoice_store` /
/// `get_head` and provide a parent root for the orphan block.
fn build_fulu_anchor(genesis_time: u64) -> (FuluMinimalSignedBeaconBlock, ForkMinimalBeaconState) {
    let anchor_body = FuluMinimalBeaconBlockBody::default();
    let anchor_body_root: Root = anchor_body.tree_hash_root();

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    let sync_committee = MinimalSyncCommittee {
        pubkeys: SszVector::from_vec(vec![
            test_pubkey();
            MinimalBeaconSpec::SYNC_COMMITTEE_SIZE as usize
        ])
        .unwrap(),
        aggregate_pubkey: test_pubkey(),
    };

    let state_inner = FuluMinimalBeaconState {
        genesis_time,
        slot: Slot(0),
        fork: Fork {
            previous_version: Version::from_array(MinimalBeaconSpec::ELECTRA_FORK_VERSION),
            current_version: Version::from_array(MinimalBeaconSpec::FULU_FORK_VERSION),
            epoch: UtilsEpoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root: anchor_body_root,
        },
        validators: SszList::empty_tree().with_push(validator).unwrap(),
        balances: SszList::with_push(
            &SszList::default(),
            Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
        )
        .unwrap(),
        previous_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
        current_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
        inactivity_scores: SszList::with_push(&SszList::default(), 0u64).unwrap(),
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        ..FuluMinimalBeaconState::default()
    };

    let fork_state = ForkMinimalBeaconState::Fulu(state_inner);
    let state_root: Root = fork_state.tree_hash_root();

    let anchor_block = FuluMinimalSignedBeaconBlock {
        message: FuluMinimalBeaconBlock {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: anchor_body,
        },
        signature: BLSSignature::from_array([0u8; 96]),
    };

    (anchor_block, fork_state)
}

/// Build a single Fulu block at slot 1 extending the anchor, carrying one blob
/// commitment so the import DA gate is genuinely consulted (non-empty
/// commitments → the Fulu column sub-checker runs against the store).
///
/// The state_root is left at default: the column DA gate runs BEFORE the STF in
/// `import_block` (RI-1), so a block whose DA payload is unavailable is rejected
/// before any state-transition is attempted. This keeps the fixture light while
/// still exercising the fork-branch + co-fetch + gate path.
fn build_fulu_block(anchor_root: Root) -> (MinForkSignedBlock, Root) {
    const G2_INFINITY: [u8; 96] = {
        let mut b = [0u8; 96];
        b[0] = 0xc0;
        b
    };

    let blob_kzg_commitments =
        SszList::with_push(&SszList::default(), KZGCommitment::from_array([0x11u8; 48]))
            .expect("push one commitment");

    let mut body = FuluMinimalBeaconBlockBody {
        blob_kzg_commitments,
        ..Default::default()
    };
    body.sync_aggregate.sync_committee_signature = BLSSignature::from_array(G2_INFINITY);

    let block = FuluMinimalBeaconBlock {
        slot: Slot(1),
        proposer_index: ValidatorIndex(0),
        parent_root: anchor_root,
        state_root: Root::default(),
        body,
    };
    let block_root: Root = block.tree_hash_root();

    let signed = MinForkSignedBlock::Fulu(FuluMinimalSignedBeaconBlock {
        message: block,
        signature: BLSSignature::from_array([0u8; 96]),
    });

    (signed, block_root)
}

/// Build a structurally-valid `DataColumnSidecar` keyed to `block_root` at
/// `index`. The cells/proofs are empty (the persistence path only writes the
/// sidecar; KZG validity is exercised elsewhere — see the module doc comment).
/// The sidecar's `signed_block_header.message.body_root` is set to `block_root`
/// so the storage key matches what the gate reads back.
fn build_column_sidecar(block_root: Root, index: ColumnIndex) -> MinimalDataColumnSidecar {
    MinimalDataColumnSidecar {
        index,
        column: SszList::default(),
        kzg_commitments: SszList::default(),
        kzg_proofs: SszList::default(),
        signed_block_header: SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: Slot(1),
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: block_root,
            },
            signature: BLSSignature::from_array([0u8; 96]),
        },
        kzg_commitments_inclusion_proof: SszVector::default(),
    }
}

/// A `ForkSchedule` with every pre-Fulu fork at epoch 0 and Fulu at epoch 0, so
/// the host computes/round-trips the Fulu fork digest for the orphan topic.
fn fulu_fork_schedule(genesis_validators_root: Root) -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalBeaconSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalBeaconSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: UtilsEpoch(0),
        bellatrix_fork_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: UtilsEpoch(0),
        capella_fork_version: Version::from_array(MinimalBeaconSpec::CAPELLA_FORK_VERSION),
        capella_fork_epoch: UtilsEpoch(0),
        deneb_fork_version: Version::from_array(MinimalBeaconSpec::DENEB_FORK_VERSION),
        deneb_fork_epoch: UtilsEpoch(0),
        electra_fork_version: Version::from_array(MinimalBeaconSpec::ELECTRA_FORK_VERSION),
        electra_fork_epoch: UtilsEpoch(0),
        fulu_fork_version: Version::from_array(MinimalBeaconSpec::FULU_FORK_VERSION),
        fulu_fork_epoch: UtilsEpoch(0),
        blob_schedule: Vec::new(),
        genesis_validators_root,
    }
}

/// Runtime config matching `fulu_fork_schedule` (all forks at epoch 0).
fn fulu_runtime_cfg() -> RuntimeConfig {
    RuntimeConfig {
        altair_fork_epoch: 0,
        altair_fork_version: MinimalBeaconSpec::ALTAIR_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        capella_fork_epoch: 0,
        capella_fork_version: MinimalBeaconSpec::CAPELLA_FORK_VERSION,
        deneb_fork_epoch: 0,
        deneb_fork_version: MinimalBeaconSpec::DENEB_FORK_VERSION,
        electra_fork_epoch: 0,
        electra_fork_version: MinimalBeaconSpec::ELECTRA_FORK_VERSION,
        fulu_fork_epoch: 0,
        fulu_fork_version: MinimalBeaconSpec::FULU_FORK_VERSION,
        ..RuntimeConfig::default()
    }
}

// ── Mock provider ─────────────────────────────────────────────────────────────

/// Fixture `LookupBlockProvider` for the Fulu lookup-path DA test.
///
/// `data_columns_by_root` records that it was invoked and returns whatever
/// sidecar set the provider was seeded with. `blobs_by_root` records a separate
/// flag and returns no sidecars — asserting it is NEVER called on the Fulu path.
#[derive(Clone)]
struct ColumnRecordingProvider {
    columns_called: Arc<AtomicBool>,
    blobs_called: Arc<AtomicBool>,
    sidecars: Arc<Vec<MinimalDataColumnSidecar>>,
}

impl LookupBlockProvider<MinimalBeaconSpec> for ColumnRecordingProvider {
    async fn blocks_by_root(
        &self,
        _roots: Vec<Root>,
    ) -> Result<Vec<MinForkSignedBlock>, LookupError> {
        Err(LookupError::NoUsablePeers)
    }

    async fn blobs_by_root(
        &self,
        _ids: Vec<pharos_types::deneb::BlobIdentifier>,
    ) -> Result<Vec<pharos_types::deneb::BlobSidecar>, LookupError> {
        // Fulu path must NOT touch the blob co-fetch.
        self.blobs_called.store(true, Ordering::SeqCst);
        Ok(Vec::new())
    }

    async fn data_columns_by_root(
        &self,
        _ids: Vec<DataColumnsByRootIdentifier<128>>,
    ) -> Result<Vec<pharos_types::fulu::DataColumnSidecar<4096, 4>>, LookupError> {
        self.columns_called.store(true, Ordering::SeqCst);
        Ok((*self.sidecars).clone())
    }
}

// ── Shared host wiring ──────────────────────────────────────────────────────────

struct Harness {
    host: Arc<HostImpl<MinimalBeaconSpec>>,
    fc: Arc<RwLock<pharos_fork_choice::Store<MinimalBeaconSpec>>>,
    store: Arc<RocksStore>,
    anchor_root: Root,
    _tmp: tempfile::TempDir,
}

fn build_harness() -> Harness {
    let genesis_time = 0u64;
    let (anchor_signed, fork_state) = build_fulu_anchor(genesis_time);
    let anchor_block = ForkBeaconBlock::Fulu(anchor_signed.message.clone());
    let anchor_root: Root = anchor_block.tree_hash_root();

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(fork_state, anchor_block);
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::ZERO,
        Hash256::from_array(TERMINAL_HASH),
        0,
    );
    let runtime_cfg = fulu_runtime_cfg();
    fc.runtime_cfg = runtime_cfg.clone();
    fc.set_fork_epochs(
        runtime_cfg.altair_fork_epoch,
        runtime_cfg.bellatrix_fork_epoch,
        runtime_cfg.capella_fork_epoch,
    );
    let fc = Arc::new(RwLock::new(fc));

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmp.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );

    let genesis_validators_root = Root::default();
    let fork_schedule = fulu_fork_schedule(genesis_validators_root);
    let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc),
        genesis_validators_root,
        fork_schedule,
        genesis_time,
        Arc::new(runtime_cfg),
    ));

    Harness {
        host,
        fc,
        store,
        anchor_root,
        _tmp: tmp,
    }
}

/// The node's expected custody+sampling column set for the test node_id + cgc,
/// matching what the lookup co-fetch derives from `expected_columns()`.
fn expected_columns(node_id: [u8; 32], cgc: u64) -> BTreeSet<ColumnIndex> {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmp.path().join("cdb"),
            create_if_missing: true,
        })
        .unwrap(),
    );
    let checker =
        pharos_node::data_availability::ColumnAvailabilityChecker::<MinimalBeaconSpec>::new(
            store,
            Arc::new(pharos_kzg::KzgVerifier::mainnet()),
            Arc::new(RuntimeConfig::default()),
            node_id,
            cgc,
        );
    checker.expected_columns().clone()
}

// ── Test 1: Fulu lookup co-fetches columns + column DA gate rejects ─────────────

/// A Fulu block carrying a blob commitment, imported through the lookup
/// direct-import path, must co-fetch its data-column sidecars via
/// `DataColumnSidecarsByRoot` (NOT `BlobSidecarsByRoot`) and run the column DA
/// sub-checker. With no columns served the gate returns `NotAvailable`, so the
/// block must NOT be imported (head stays at the anchor).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fulu_lookup_co_fetches_columns_and_da_gate_rejects() {
    let _ = tracing_subscriber::fmt::try_init();

    let harness = build_harness();
    let (fulu_signed, fulu_block_root) = build_fulu_block(harness.anchor_root);

    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (lookup_tx, lookup_rx) = mpsc::channel::<LookupRequest>(64);
    let (reinject_tx, _reinject_rx) =
        mpsc::channel::<pharos_node::block_ingestion::ReinjectBlock>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let pending = Arc::new(PendingBlocks::default());
    let notify_backfill = Arc::new(tokio::sync::Notify::new());
    let pow_provider = Arc::new(NoopPowBlockProvider);
    let exec_engine = Arc::new(NullExecutionEngine);

    let columns_called = Arc::new(AtomicBool::new(false));
    let blobs_called = Arc::new(AtomicBool::new(false));
    let provider = ColumnRecordingProvider {
        columns_called: Arc::clone(&columns_called),
        blobs_called: Arc::clone(&blobs_called),
        sidecars: Arc::new(Vec::new()),
    };

    let node_id = [0u8; 32];
    let cgc = MinimalBeaconSpec::CUSTODY_REQUIREMENT;

    let fc_for_assert = Arc::clone(&harness.fc);

    let loop_handle = tokio::spawn(run_lookup_loop::<
        MinimalBeaconSpec,
        ColumnRecordingProvider,
        NullExecutionEngine,
        NoopPowBlockProvider,
    >(
        lookup_rx,
        provider,
        Arc::clone(&harness.host),
        Arc::clone(&harness.fc),
        exec_engine,
        pow_provider,
        head_tx,
        payload_tx,
        Arc::clone(&pending),
        Arc::clone(&notify_backfill),
        reinject_tx,
        shutdown_rx,
        node_id,
        cgc,
    ));

    // Encode the Fulu block as raw inner SSZ (as gossip carries it) and send it
    // as an UnknownParent orphan under the Fulu fork digest.
    let fulu_ssz = match &fulu_signed {
        ForkSignedBeaconBlock::Fulu(inner) => inner.as_ssz_bytes(),
        _ => unreachable!("build_fulu_block always yields a Fulu block"),
    };
    let topic = GossipTopic {
        fork_digest: harness.host.fork_digest_for(NetworkFork::Fulu),
        kind: GossipTopicKind::BeaconBlock,
    };
    lookup_tx
        .send(LookupRequest::UnknownParent {
            topic,
            peer: libp2p::PeerId::random(),
            data: fulu_ssz,
        })
        .await
        .unwrap();

    // Wait until the provider's data_columns_by_root was invoked (Fulu co-fetch).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !columns_called.load(Ordering::SeqCst) {
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout: lookup never co-fetched data-column sidecars for the Fulu block");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // The blob co-fetch must NOT have been used for a Fulu block.
    assert!(
        !blobs_called.load(Ordering::SeqCst),
        "Fulu lookup path must NOT call blobs_by_root"
    );

    // Give the import a moment to (not) complete, then assert head is unchanged:
    // the column DA gate returned NotAvailable, so the Fulu block was NOT imported.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let head = get_head::<MinimalBeaconSpec>(&fc_for_assert.read());
    assert_eq!(
        head, harness.anchor_root,
        "Fulu block with unavailable columns must NOT be imported via lookup"
    );
    assert_ne!(
        head, fulu_block_root,
        "head must not advance to the column-unavailable Fulu block"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle).await;
}

// ── Test 2: Fulu lookup persists every fetched column under the block root ──────

/// When the provider serves the node's expected columns, the lookup Fulu arm
/// must persist each sidecar to `CF_DATA_COLUMN_SIDECARS` keyed by the block
/// root, so the column DA sub-checker can read them back. This proves the
/// co-fetch + persist path end-to-end (full KZG-gated import is covered by the
/// fulu_pipeline DA-gate test and the conformance runners; see the module doc).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fulu_lookup_persists_fetched_columns() {
    let _ = tracing_subscriber::fmt::try_init();

    let harness = build_harness();
    let (fulu_signed, fulu_block_root) = build_fulu_block(harness.anchor_root);

    let node_id = [0u8; 32];
    let cgc = MinimalBeaconSpec::CUSTODY_REQUIREMENT;
    let cols = expected_columns(node_id, cgc);
    assert!(
        !cols.is_empty(),
        "the test node must expect a non-empty custody+sampling column set"
    );

    // Seed the provider with one sidecar per expected column, keyed to the block.
    let sidecars: Vec<MinimalDataColumnSidecar> = cols
        .iter()
        .map(|&idx| build_column_sidecar(fulu_block_root, idx))
        .collect();

    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (lookup_tx, lookup_rx) = mpsc::channel::<LookupRequest>(64);
    let (reinject_tx, _reinject_rx) =
        mpsc::channel::<pharos_node::block_ingestion::ReinjectBlock>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let pending = Arc::new(PendingBlocks::default());
    let notify_backfill = Arc::new(tokio::sync::Notify::new());
    let pow_provider = Arc::new(NoopPowBlockProvider);
    let exec_engine = Arc::new(NullExecutionEngine);

    let columns_called = Arc::new(AtomicBool::new(false));
    let blobs_called = Arc::new(AtomicBool::new(false));
    let provider = ColumnRecordingProvider {
        columns_called: Arc::clone(&columns_called),
        blobs_called: Arc::clone(&blobs_called),
        sidecars: Arc::new(sidecars),
    };

    let loop_handle = tokio::spawn(run_lookup_loop::<
        MinimalBeaconSpec,
        ColumnRecordingProvider,
        NullExecutionEngine,
        NoopPowBlockProvider,
    >(
        lookup_rx,
        provider,
        Arc::clone(&harness.host),
        Arc::clone(&harness.fc),
        exec_engine,
        pow_provider,
        head_tx,
        payload_tx,
        Arc::clone(&pending),
        Arc::clone(&notify_backfill),
        reinject_tx,
        shutdown_rx,
        node_id,
        cgc,
    ));

    let fulu_ssz = match &fulu_signed {
        ForkSignedBeaconBlock::Fulu(inner) => inner.as_ssz_bytes(),
        _ => unreachable!("build_fulu_block always yields a Fulu block"),
    };
    let topic = GossipTopic {
        fork_digest: harness.host.fork_digest_for(NetworkFork::Fulu),
        kind: GossipTopicKind::BeaconBlock,
    };
    lookup_tx
        .send(LookupRequest::UnknownParent {
            topic,
            peer: libp2p::PeerId::random(),
            data: fulu_ssz,
        })
        .await
        .unwrap();

    // Wait until the co-fetch fired.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !columns_called.load(Ordering::SeqCst) {
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout: lookup never co-fetched data-column sidecars for the Fulu block");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !blobs_called.load(Ordering::SeqCst),
        "Fulu lookup path must NOT call blobs_by_root"
    );

    // Wait for the persistence to land: every expected column must be readable
    // back from the store under the block root.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let all_present = cols.iter().all(|&idx| {
            <RocksStore as DbStore<MinimalBeaconSpec>>::get_data_column_sidecar(
                &harness.store,
                &fulu_block_root,
                idx,
            )
            .expect("store read")
            .is_some()
        });
        if all_present {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout: lookup never persisted the co-fetched data-column sidecars");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Confirm each persisted sidecar carries its expected column index.
    for &idx in &cols {
        let stored = <RocksStore as DbStore<MinimalBeaconSpec>>::get_data_column_sidecar(
            &harness.store,
            &fulu_block_root,
            idx,
        )
        .expect("store read")
        .expect("expected column must be persisted");
        assert_eq!(
            stored.index, idx,
            "persisted sidecar index must match the expected column"
        );
    }

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle).await;
}
