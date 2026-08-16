//! Fulu DA pipeline integration test (Task 6.11 of M13-Fulu Phase 6b).
//!
//! Exercises the EIP-7594 PeerDAS column data-availability pipeline that mirrors
//! the M10-DA blob pipeline, plus the fulu-specific custody-gated DA gate:
//!
//! 1. **Column DA park → notify → re-inject** (`column_da_pipeline_reinject`):
//!    a block whose column set is incomplete returns `DataNotAvailable` from
//!    `import_block`; the test parks it in `ColumnAwaitingBlocks`; the fork-choice
//!    head does NOT advance (RI-1); after the toggle checker is unblocked and
//!    `notify_column_arrived` fires, the block bytes are re-injected and the
//!    second import advances the head. Dedup on double-park is asserted.
//!
//! 2. **Column ingestion loop** (`column_ingestion_loop_persists_and_reinjects`):
//!    a `GossipDataColumnSidecar` event drives `run_column_ingestion_loop`, which
//!    SSZ-decodes + persists the sidecar to `CF_DATA_COLUMN_SIDECARS` and notifies
//!    the registry, re-injecting a parked block (the production demux path).
//!
//! 3. **Custody-gated DA gate** (`column_availability_checker_is_custody_gated`):
//!    the real `ColumnAvailabilityChecker` computes the expected-column set as the
//!    custody+sampling union (RI-1), NOT all 128 columns, returns `Irrelevant` for
//!    empty commitments, and `NotAvailable` when an expected column is missing
//!    from the store.
//!
//! Engine note: the import path uses Engine V4 for the (electra-shaped) fulu
//! execution payload; V5 is production-only (`engine_getPayloadV5`). The DA
//! pipeline is engine-agnostic, so a `NullExecutionEngine` mock suffices here —
//! the electra→fulu STF crossing and Engine-V5 production are covered by the
//! `fulu/transition` and engine-yaml conformance runners respectively.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{NoopPowBlockProvider, get_forkchoice_store, get_head};
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::NullExecutionEngine;
use pharos_storage::{RocksStore, RocksStoreConfig, Store as DbStore};
use pharos_types::bellatrix::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayload,
};
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::KZGCommitment;
use pharos_types::fulu::MinimalDataColumnSidecar;
use pharos_types::fulu::data_column_sidecar::ColumnIndex;
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinState,
    SignedBeaconBlock as ForkSignedBlock,
};
use pharos_types::{BeaconSpec, MinimalBeaconSpec};
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
use tokio::sync::mpsc;

use pharos_network::network::NetworkEvent;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::ForkDigest;
use pharos_node::block_ingestion::ReinjectBlock;
use pharos_node::column_ingestion::{ColumnAwaitingBlocks, run_column_ingestion_loop};
use pharos_node::data_availability::{
    ColumnAvailabilityChecker, DataAvailabilityChecker, DataAvailabilityVerdict,
};
use pharos_node::engine_driver::NewPayloadRequest;
use pharos_node::import::ImportError;

// ── Fork-enum type aliases (minimal preset) ────────────────────────────────────

type MinForkSigned = ForkSignedBlock<
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

type MinForkBlock = ForkBeaconBlock<
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

// ── ToggleDAChecker ─────────────────────────────────────────────────────────

/// Test-only DA checker: returns `NotAvailable` while `blocked` is true (the
/// column set is incomplete), then `Irrelevant` once flipped (the expected
/// custody+sampling columns have arrived).
struct ToggleDAChecker {
    blocked: AtomicBool,
}

impl ToggleDAChecker {
    fn new_blocked() -> Self {
        Self {
            blocked: AtomicBool::new(true),
        }
    }
    fn unblock(&self) {
        self.blocked.store(false, Ordering::Relaxed);
    }
}

impl DataAvailabilityChecker<MinimalBeaconSpec> for ToggleDAChecker {
    fn is_data_available(
        &self,
        _block_root: Root,
        _kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        if self.blocked.load(Ordering::Relaxed) {
            DataAvailabilityVerdict::NotAvailable
        } else {
            DataAvailabilityVerdict::Irrelevant
        }
    }
}

const TERMINAL_HASH: [u8; 32] = [0x01u8; 32];

// ── Fixture helpers ───────────────────────────────────────────────────────────

fn test_pubkey() -> BLSPubkey {
    BLSPubkey::from_array([0u8; 48])
}

fn dummy_topic() -> GossipTopic {
    GossipTopic {
        fork_digest: ForkDigest::from_array([0x06u8; 4]),
        kind: GossipTopicKind::BeaconBlock,
    }
}

/// Build a Bellatrix genesis anchor at slot 0 (the column DA gate is fork-agnostic;
/// the anchor only needs to drive `import_block`'s head advance for the RI-1 check).
fn build_anchor() -> (ForkMinState, MinForkBlock, Root) {
    use pharos_types::altair::MinimalSyncCommittee;

    let anchor_body = MinimalBeaconBlockBody::default();
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

    let state_inner = MinimalBeaconState {
        genesis_time: 0,
        slot: Slot(0),
        fork: Fork {
            previous_version: Version::from_array([0x01, 0x00, 0x00, 0x01]),
            current_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
            epoch: Epoch(0),
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
        ..MinimalBeaconState::default()
    };

    let fork_state = ForkMinState::Bellatrix(state_inner.clone());
    let state_root: Root = fork_state.tree_hash_root();

    let anchor_block_inner = MinimalBeaconBlock {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Root::default(),
        state_root,
        body: anchor_body,
    };
    let anchor_root: Root = anchor_block_inner.tree_hash_root();
    let anchor_block = MinForkBlock::Bellatrix(anchor_block_inner);

    (fork_state, anchor_block, anchor_root)
}

/// Build a slot-1 execution block extending the genesis anchor.
fn build_execution_block(genesis_state: ForkMinState, anchor_root: Root) -> MinForkSigned {
    use pharos_stf::{process_slots_fork, state_transition};
    use pharos_types::altair::MinimalSyncAggregate;

    const G2_INFINITY: [u8; 96] = {
        let mut b = [0u8; 96];
        b[0] = 0xc0;
        b
    };

    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        altair_fork_epoch: 0,
        ..Default::default()
    };

    let null_engine = NullExecutionEngine;
    let slot = Slot(1);

    let mut pre_advanced = genesis_state.clone();
    process_slots_fork::<MinimalBeaconSpec>(
        &mut pre_advanced,
        slot,
        pharos_stf::ForkEpochs::never(),
        &runtime_cfg,
    )
    .expect("process_slots_fork");

    let (prev_randao, timestamp) = {
        let s = match &pre_advanced {
            ForkMinState::Bellatrix(s) => s,
            _ => unreachable!(),
        };
        let epoch = slot.0 / MinimalBeaconSpec::SLOTS_PER_EPOCH;
        let idx = (epoch % MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
        let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
        let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
        (randao, ts)
    };

    let payload = MinimalExecutionPayload {
        parent_hash: Hash256::from_array(TERMINAL_HASH),
        prev_randao,
        block_number: 1,
        gas_limit: 0x1c9c380,
        timestamp,
        block_hash: Hash256::from_array([0x01u8; 32]),
        ..Default::default()
    };

    let sync_aggregate = MinimalSyncAggregate {
        sync_committee_signature: BLSSignature::from_array(G2_INFINITY),
        ..Default::default()
    };

    let body = MinimalBeaconBlockBody {
        execution_payload: payload,
        sync_aggregate,
        ..Default::default()
    };

    let draft = MinimalBeaconBlock {
        slot,
        proposer_index: ValidatorIndex(0),
        parent_root: anchor_root,
        state_root: Root::default(),
        body: body.clone(),
    };
    let draft_signed = MinForkSigned::Bellatrix(MinimalSignedBeaconBlock {
        message: draft,
        signature: BLSSignature::from_array([0u8; 96]),
    });

    let (post_state, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
        genesis_state,
        &draft_signed,
        &null_engine,
        false,
        &runtime_cfg,
    )
    .expect("draft STF");

    let state_root: Root = post_state.tree_hash_root();
    let final_block = MinimalBeaconBlock {
        slot,
        proposer_index: ValidatorIndex(0),
        parent_root: anchor_root,
        state_root,
        body,
    };

    MinForkSigned::Bellatrix(MinimalSignedBeaconBlock {
        message: final_block,
        signature: BLSSignature::from_array([0u8; 96]),
    })
}

/// Build a minimal `DataColumnSidecar` for a given block root + column index.
/// The cells/proofs are empty (the column ingestion loop only persists and
/// notifies; KZG verification is exercised by the `pharos-kzg` unit tests and the
/// `verify_data_column_sidecar*` STF tests). The `signed_block_header.message`
/// tree-hash IS the `block_root` used as the storage key, so the header's other
/// fields are derived to make that root match `block_root`.
fn build_column_sidecar(
    block_root: Root,
    index: ColumnIndex,
    slot: Slot,
) -> MinimalDataColumnSidecar {
    MinimalDataColumnSidecar {
        index,
        column: SszList::default(),
        kzg_commitments: SszList::default(),
        kzg_proofs: SszList::default(),
        signed_block_header: SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot,
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

fn open_store() -> (Arc<RocksStore>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
        path: tmp.path().join("chain_db"),
        create_if_missing: true,
    })
    .expect("open store");
    (Arc::new(store), tmp)
}

// ── Test 1: column DA park → notify → re-inject → import → head advances ──────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn column_da_pipeline_reinject() {
    let (genesis_state, anchor_block, anchor_root) = build_anchor();
    let block1 = build_execution_block(genesis_state.clone(), anchor_root);
    let block1_root: Root = match &block1 {
        MinForkSigned::Bellatrix(inner) => inner.message.tree_hash_root(),
        _ => unreachable!(),
    };

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(genesis_state, anchor_block);
    // time = 6s → current_slot = 1 (minimal SECONDS_PER_SLOT = 6) so the slot-1
    // block is not a future block.
    fc.time = 6;
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_HASH),
        0,
    );
    let fc = Arc::new(RwLock::new(fc));

    let (store, _tmp) = open_store();

    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        altair_fork_epoch: 0,
        ..Default::default()
    };

    let da_checker = Arc::new(ToggleDAChecker::new_blocked());
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(16);

    // ── First import: DA blocked → DataNotAvailable, head must NOT advance ─────
    let import1 = pharos_node::import::import_block::<
        MinimalBeaconSpec,
        NullExecutionEngine,
        NoopPowBlockProvider,
        ToggleDAChecker,
    >(
        &block1,
        &fc,
        &Arc::new(NullExecutionEngine),
        &Arc::new(NoopPowBlockProvider),
        &payload_tx,
        false,
        &runtime_cfg,
        &store,
        &da_checker,
    )
    .await;

    assert!(
        matches!(import1, Err(ImportError::DataNotAvailable)),
        "blocked column DA gate must yield DataNotAvailable",
    );
    assert_eq!(
        get_head::<MinimalBeaconSpec>(&fc.read()),
        anchor_root,
        "RI-1: head must NOT advance while the column set is incomplete"
    );

    // ── Park in ColumnAwaitingBlocks ──────────────────────────────────────────
    let column_awaiting = Arc::new(ColumnAwaitingBlocks::new());
    let (reinject_tx, mut reinject_rx) = mpsc::channel::<ReinjectBlock>(16);
    let raw = vec![0xABu8; 8];
    let topic = dummy_topic();

    column_awaiting.park(
        block1_root,
        (topic.clone(), raw.clone()),
        reinject_tx.clone(),
    );
    assert!(
        reinject_rx.try_recv().is_err(),
        "reinject channel must be empty before notify"
    );

    // Dedup: a second park of the same root is a no-op.
    column_awaiting.park(
        block1_root,
        (topic.clone(), vec![0x99u8]),
        reinject_tx.clone(),
    );

    // ── Notify: column set complete → re-inject ───────────────────────────────
    column_awaiting.notify_column_arrived(block1_root).await;
    let reinjected = tokio::time::timeout(Duration::from_secs(2), reinject_rx.recv())
        .await
        .expect("reinject timed out")
        .expect("reinject_rx closed");
    assert_eq!(
        reinjected.0, topic,
        "re-injected topic must match the parked one"
    );
    assert_eq!(
        reinjected.1, raw,
        "re-injected data must be the FIRST park (dedup)"
    );

    // No second re-inject (dedup proven: only one entry existed).
    column_awaiting.notify_column_arrived(block1_root).await;
    assert!(
        reinject_rx.try_recv().is_err(),
        "no second re-inject after dedup"
    );

    // ── Second import: DA unblocked → head advances ───────────────────────────
    da_checker.unblock();
    let import2 = pharos_node::import::import_block::<
        MinimalBeaconSpec,
        NullExecutionEngine,
        NoopPowBlockProvider,
        ToggleDAChecker,
    >(
        &block1,
        &fc,
        &Arc::new(NullExecutionEngine),
        &Arc::new(NoopPowBlockProvider),
        &payload_tx,
        false,
        &runtime_cfg,
        &store,
        &da_checker,
    )
    .await;
    assert!(import2.is_ok(), "unblocked import must succeed");
    assert_eq!(
        get_head::<MinimalBeaconSpec>(&fc.read()),
        block1_root,
        "head must advance to block 1 once the column DA gate is satisfied"
    );
}

// ── Test 2: column ingestion loop persists a sidecar and re-injects ───────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn column_ingestion_loop_persists_and_reinjects() {
    let (store, _tmp) = open_store();
    let column_awaiting = Arc::new(ColumnAwaitingBlocks::new());

    // The DA-pending block is keyed by the sidecar's `signed_block_header.message`
    // tree-hash root (the block root, per `specs/fulu/p2p-interface.md`). Build the
    // sidecar first, derive that root, and park under it.
    let sidecar = build_column_sidecar(Root::default(), 7, Slot(1));
    let header_root = sidecar.signed_block_header.message.tree_hash_root();

    // Park a block awaiting its columns, keyed by the sidecar's header root.
    let (reinject_tx, mut reinject_rx) = mpsc::channel::<ReinjectBlock>(16);
    let raw = vec![0x11u8, 0x22, 0x33];
    let topic = dummy_topic();
    column_awaiting.park(header_root, (topic.clone(), raw.clone()), reinject_tx);

    // Spawn the column ingestion loop.
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);
    let loop_store = Arc::clone(&store);
    let loop_registry = Arc::clone(&column_awaiting);
    let handle = tokio::spawn(async move {
        run_column_ingestion_loop::<MinimalBeaconSpec>(event_rx, loop_store, loop_registry).await;
    });
    let data = {
        use pharos_ssz::Encode as _;
        sidecar.as_ssz_bytes()
    };
    event_tx
        .send(NetworkEvent::GossipDataColumnSidecar {
            subnet: 7u64,
            peer: libp2p::PeerId::random(),
            data,
        })
        .await
        .expect("send gossip event");

    // The parked block (keyed by the sidecar's header root) is re-injected.
    let reinjected = tokio::time::timeout(Duration::from_secs(3), reinject_rx.recv())
        .await
        .expect("reinject timed out")
        .expect("reinject_rx closed");
    assert_eq!(reinjected.0, topic);
    assert_eq!(reinjected.1, raw);

    // The sidecar was persisted to CF_DATA_COLUMN_SIDECARS.
    let stored = <RocksStore as DbStore<MinimalBeaconSpec>>::get_data_column_sidecar(
        &store,
        &header_root,
        7,
    )
    .expect("store read")
    .expect("sidecar must be persisted");
    assert_eq!(stored.index, 7);

    drop(event_tx);
    let _ = handle.await;
}

// ── Test 3: ColumnAvailabilityChecker expected set is custody-gated (RI-1) ────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn column_availability_checker_is_custody_gated() {
    let (store, _tmp) = open_store();
    let verifier = Arc::new(pharos_kzg::KzgVerifier::mainnet());
    let runtime_cfg = Arc::new(RuntimeConfig::default());

    // CUSTODY_REQUIREMENT = 4, SAMPLES_PER_SLOT = 8 → sampling_size = 8 custody
    // groups; NUMBER_OF_CUSTODY_GROUPS == NUMBER_OF_COLUMNS == 128 so each group
    // maps to exactly one column → 8 expected columns, NOT all 128 (RI-1).
    let node_id = [0x11u8; 32];
    let cgc = MinimalBeaconSpec::CUSTODY_REQUIREMENT;
    let checker = ColumnAvailabilityChecker::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&verifier),
        Arc::clone(&runtime_cfg),
        node_id,
        cgc,
    );

    let expected: &BTreeSet<ColumnIndex> = checker.expected_columns();
    assert!(
        !expected.is_empty(),
        "custody+sampling union must be non-empty"
    );
    assert!(
        expected.len() < MinimalBeaconSpec::NUMBER_OF_COLUMNS as usize,
        "RI-1: the DA gate checks the custody+sampling union ({} columns), NOT all {}",
        expected.len(),
        MinimalBeaconSpec::NUMBER_OF_COLUMNS,
    );
    let expected_sampling = MinimalBeaconSpec::SAMPLES_PER_SLOT.max(cgc) as usize;
    assert_eq!(
        expected.len(),
        expected_sampling,
        "with 1 column per custody group, the union size == sampling_size"
    );

    let block_root = Root::from([0x55u8; 32]);

    // Empty commitments → Irrelevant (pre-fulu / no-blob block: no columns).
    assert_eq!(
        checker.is_data_available(block_root, &[]),
        DataAvailabilityVerdict::Irrelevant,
    );

    // Non-empty commitments, no stored columns → NotAvailable (block parks).
    let commitments = vec![KZGCommitment::from_array([0u8; 48])];
    assert_eq!(
        checker.is_data_available(block_root, &commitments),
        DataAvailabilityVerdict::NotAvailable,
        "missing every expected custody column must yield NotAvailable",
    );
}
