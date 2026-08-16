//! Blob DA pipeline integration test (Task 5.9 of M10-DA Phase 5).
//!
//! Exercises the full park → deliver sidecars → re-inject → import → head path:
//!
//! 1. Build a minimal-preset Bellatrix anchor and one execution block at slot 1.
//! 2. Import block 1 with a `ToggleDAChecker` that starts returning `NotAvailable`.
//!    `import_block` returns `DataNotAvailable`; the test parks the block root in
//!    `BlobAwaitingBlocks` via `park`.
//! 3. Assert: fork-choice head has NOT advanced (RI-1 invariant).
//! 4. Flip the checker to `Irrelevant`, call `notify_blob_arrived(block_root)`.
//!    The block bytes are sent on `reinject_tx`.
//! 5. Re-run `import_block` with the checker unblocked.
//!    The import succeeds and the head advances to block 1.
//!
//! Also verifies dedup: parking the same root twice is a no-op (only one
//! re-inject on notify).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{NoopPowBlockProvider, get_forkchoice_store, get_head};
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::NullExecutionEngine;
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::bellatrix::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayload,
};
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::KZGCommitment;
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinState,
    SignedBeaconBlock as ForkSignedBlock,
};
use pharos_types::{EthSpec, MinimalEthSpec};
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
use tokio::sync::mpsc;

use pharos_node::block_ingestion::ReinjectBlock;
use pharos_node::data_availability::{
    BlobAwaitingBlocks, DataAvailabilityChecker, DataAvailabilityVerdict,
};
use pharos_node::engine_driver::NewPayloadRequest;
use pharos_node::import::ImportError;

// ── ForkSignedBlock type alias ────────────────────────────────────────────────

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
>;

// ── ToggleDAChecker ───────────────────────────────────────────────────────────

/// Test-only DA checker: returns `NotAvailable` while `blocked` is true, then
/// `Irrelevant` once flipped.  Thread-safe via `AtomicBool`.
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

impl DataAvailabilityChecker<MinimalEthSpec> for ToggleDAChecker {
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

// ── TERMINAL_HASH ─────────────────────────────────────────────────────────────

const TERMINAL_HASH: [u8; 32] = [0x01u8; 32];

// ── Fixture helpers ───────────────────────────────────────────────────────────

/// Build a test pubkey (zeroed — not used for verification since validate=false).
fn test_pubkey() -> BLSPubkey {
    BLSPubkey::from_array([0u8; 48])
}

/// Build a Bellatrix genesis anchor at slot 0, genesis_time 0.
/// Returns (fork_state, anchor_block) where anchor_block is the unsigned
/// ForkBeaconBlock (for get_forkchoice_store).
fn build_anchor() -> (ForkMinState, MinForkBlock, Root) {
    use pharos_types::altair::MinimalSyncCommittee;

    let anchor_body = MinimalBeaconBlockBody::default();
    let anchor_body_root: Root = anchor_body.tree_hash_root();

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    let sync_committee = MinimalSyncCommittee {
        pubkeys: SszVector::from_vec(vec![
            test_pubkey();
            MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize
        ])
        .unwrap(),
        aggregate_pubkey: test_pubkey(),
    };

    let state_inner = MinimalBeaconState {
        genesis_time: 0,
        slot: Slot(0),
        fork: Fork {
            previous_version: Version::from_array([0x01, 0x00, 0x00, 0x01]),
            current_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
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
            Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
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
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        altair_fork_epoch: 0,
        ..Default::default()
    };

    let null_engine = NullExecutionEngine;
    let slot = Slot(1);

    // Advance a clone to slot 1 to read randao_mix / timestamp.
    let mut pre_advanced = genesis_state.clone();
    process_slots_fork::<MinimalEthSpec>(
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
        let epoch = slot.0 / MinimalEthSpec::SLOTS_PER_EPOCH;
        let idx = (epoch % MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
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

    // Draft pass (state_root = default) to get post-state.
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

    let (post_state, _) = state_transition::<MinimalEthSpec, NullExecutionEngine>(
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

// ── Test ──────────────────────────────────────────────────────────────────────

/// blob_da_pipeline: park → notify → re-inject → import → head advances.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blob_da_pipeline() {
    // ── Build anchor and slot-1 block ─────────────────────────────────────────

    let (genesis_state, anchor_block, anchor_root) = build_anchor();
    let block1 = build_execution_block(genesis_state.clone(), anchor_root);

    let block1_root: Root = match &block1 {
        MinForkSigned::Bellatrix(inner) => inner.message.tree_hash_root(),
        _ => unreachable!(),
    };

    // ── Build fork-choice store ───────────────────────────────────────────────

    let mut fc = get_forkchoice_store::<MinimalEthSpec>(genesis_state, anchor_block);

    // Set time = 6s so current_slot = 1.
    fc.time = 6;
    // Terminal-block-hash override so the merge-transition guard passes.
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_HASH),
        0,
    );

    let fc_store = Arc::new(RwLock::new(fc));

    // ── Open RocksStore ───────────────────────────────────────────────────────

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(
        RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store"),
    );

    // ── Channel setup ─────────────────────────────────────────────────────────

    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(16);
    let (reinject_tx, mut reinject_rx) = mpsc::channel::<ReinjectBlock>(16);

    // ── DA checker + awaiting-blocks registry ─────────────────────────────────

    let da_checker = Arc::new(ToggleDAChecker::new_blocked());
    let blob_awaiting = Arc::new(BlobAwaitingBlocks::new());

    // ── Import block 1 with DA blocked ────────────────────────────────────────

    let cfg = RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        altair_fork_epoch: 0,
        ..Default::default()
    };

    let import_result = pharos_node::import::import_block::<
        MinimalEthSpec,
        NullExecutionEngine,
        NoopPowBlockProvider,
        ToggleDAChecker,
    >(
        &block1,
        &fc_store,
        &Arc::new(NullExecutionEngine),
        &Arc::new(NoopPowBlockProvider),
        &payload_tx,
        false, // validate_result: skip BLS (test blocks have no valid sigs)
        &cfg,
        &store,
        &da_checker,
    )
    .await;

    assert!(
        matches!(import_result, Err(ImportError::DataNotAvailable)),
        "expected DataNotAvailable when DA is blocked, got: {:?}",
        import_result.err()
    );

    // Fork-choice head must NOT have advanced (RI-1 invariant).
    {
        let fc = fc_store.read();
        let head = get_head::<MinimalEthSpec>(&fc);
        assert_ne!(
            head, block1_root,
            "block1 must NOT be head while DA blocked"
        );
    }

    // ── Park the block in BlobAwaitingBlocks ──────────────────────────────────

    use pharos_network::topics::{GossipTopic, GossipTopicKind};
    use pharos_network::types::ForkDigest;

    let fork_digest = ForkDigest::from_array([0u8; 4]);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let raw_data = b"dummy-ssz-bytes".to_vec();

    blob_awaiting.park(
        block1_root,
        (topic.clone(), raw_data.clone()),
        reinject_tx.clone(),
    );

    // Immediately after park, reinject channel should still be empty.
    assert!(
        reinject_rx.try_recv().is_err(),
        "reinject channel should be empty before notify"
    );

    // ── Deliver sidecar → notify re-inject ────────────────────────────────────

    da_checker.unblock();
    blob_awaiting.notify_blob_arrived(block1_root).await;

    // The re-inject channel now has the block.
    let reinjected = tokio::time::timeout(Duration::from_secs(2), reinject_rx.recv())
        .await
        .expect("timeout waiting for re-inject")
        .expect("reinject_rx closed");

    assert_eq!(reinjected.0, topic, "re-injected topic must match");
    assert_eq!(reinjected.1, raw_data, "re-injected data must match");

    // ── Import block 1 again (DA now open) ───────────────────────────────────

    let import_result2 = pharos_node::import::import_block::<
        MinimalEthSpec,
        NullExecutionEngine,
        NoopPowBlockProvider,
        ToggleDAChecker,
    >(
        &block1,
        &fc_store,
        &Arc::new(NullExecutionEngine),
        &Arc::new(NoopPowBlockProvider),
        &payload_tx,
        false,
        &cfg,
        &store,
        &da_checker,
    )
    .await;

    assert!(
        import_result2.is_ok(),
        "expected import success after DA unblocked, got: {:?}",
        import_result2.err()
    );

    // Head must now be block1.
    {
        let fc = fc_store.read();
        let head = get_head::<MinimalEthSpec>(&fc);
        assert_eq!(
            head, block1_root,
            "head must advance to block1 after DA satisfied"
        );
    }

    // ── Dedup: parking the same root twice is a no-op ─────────────────────────

    let dummy_root = Root::from_array([0xaau8; 32]);

    blob_awaiting.park(
        dummy_root,
        (topic.clone(), raw_data.clone()),
        reinject_tx.clone(),
    );
    // Second park for same root: dedup.
    blob_awaiting.park(
        dummy_root,
        (topic.clone(), raw_data.clone()),
        reinject_tx.clone(),
    );

    blob_awaiting.notify_blob_arrived(dummy_root).await;

    // Only one re-inject (first park); second park was dedup'd.
    let _first_reinjected = tokio::time::timeout(Duration::from_secs(1), reinject_rx.recv())
        .await
        .expect("timeout on first reinjected")
        .expect("channel closed");

    // No second re-inject.
    assert!(
        reinject_rx.try_recv().is_err(),
        "dedup: only one re-inject expected for the same block_root"
    );
}
