//! State-replay integration test (Task 2.6 of M-Storage Phase 2).
//!
//! Builds a known minimal-preset Bellatrix chain of `SLOTS_PER_EPOCH + 5` blocks,
//! persists all blocks via `run_backfill_loop` (Phase-1 import path), then
//! exercises `StateRegenService`:
//!
//!   (a) `state_at_slot(s)` for several intermediate (non-epoch-boundary) slots
//!       equals the inline-replayed state's `tree_hash_root`.
//!   (b) `state_at_root(state_root)` round-trips an intermediate state root.
//!
//! Intermediate slots (slot % SLOTS_PER_EPOCH != 0) have no stored state on disk;
//! the regen service must walk backward to the nearest epoch boundary and replay
//! forward.  `SLOTS_PER_EPOCH = 8` for `MinimalEthSpec`, so a chain of 13 blocks
//! (slots 1–13) crosses one epoch boundary at slot 8 and leaves intermediate slots
//! 9–12 (and 1–7) requiring replay.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{get_forkchoice_store, get_head};
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::phase0::accessors::{compute_signing_root, get_current_epoch, get_domain};
use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::{
    EthSpec, MinimalEthSpec,
    altair::{MinimalSyncAggregate, MinimalSyncCommittee},
    bellatrix::{
        MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    },
    fork::ForkSchedule,
    phase0::{Epoch, Gwei, Root, Slot, Validator, ValidatorIndex, Version},
    state::{
        BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinState,
        SignedBeaconBlock as ForkSignedBeaconBlock,
    },
    views::{BeaconBlockView as _, BeaconStateView as _},
};
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
use tokio::sync::{Notify, mpsc, watch};

use pharos_node::backfill::{BackfillBlockProvider, BackfillError, run_backfill_loop};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::state_regen::StateRegenService;

mod common;

// ── Type aliases ──────────────────────────────────────────────────────────────

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
>;
type MinForkState = ForkMinState;

const TERMINAL_BLOCK_HASH_BYTES: [u8; 32] = [0xAA_u8; 32];
const BACKFILL_GENESIS_TIME_SECS: u64 = 1_000_000;

// ── BLS helpers ───────────────────────────────────────────────────────────────

fn test_sk() -> blst::min_pk::SecretKey {
    blst::min_pk::SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM")
}

fn test_pubkey() -> BLSPubkey {
    BLSPubkey::from_array(test_sk().sk_to_pk().compress())
}

fn test_sign(msg: &[u8]) -> BLSSignature {
    use pharos_utils::bls::BLS_DST;
    BLSSignature::from_array(test_sk().sign(msg, BLS_DST, &[]).compress())
}

// ── Genesis + chain builder (reused from live_block_persistence.rs) ───────────

fn build_genesis_for_test() -> (
    MinForkState,
    ForkBeaconBlock<16, 2, 128, 16, 16, 2048, 33, 32, 1_073_741_824, 1_048_576, 256, 32, 4, 16>,
) {
    use pharos_types::phase0::operations::BeaconBlockHeader;

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

    let genesis_bellatrix = MinimalBeaconState {
        genesis_time: 0,
        slot: Slot(0),
        fork: pharos_types::phase0::Fork {
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

    let genesis_state = ForkMinState::Bellatrix(genesis_bellatrix);
    let state_root: Root = genesis_state.tree_hash_root();

    let anchor_block = ForkBeaconBlock::Bellatrix(MinimalBeaconBlock {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Root::default(),
        state_root,
        body: anchor_body,
    });

    (genesis_state, anchor_block)
}

/// Build a chain of `n` Bellatrix blocks starting from `genesis_state`.
/// Returns `(signed_blocks, block_roots, inline_states)` where `inline_states[i]`
/// is the post-state after block `i+1` (slot `i+1`).
fn build_chain(
    genesis_state: MinForkState,
    anchor_root: Root,
    n: u64,
) -> (Vec<MinForkSignedBlock>, Vec<Root>, Vec<MinForkState>) {
    use pharos_types::bellatrix::execution_payload::MinimalExecutionPayload;

    let runtime_cfg = pharos_types::config::RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
        ..Default::default()
    };
    let null_engine = NullExecutionEngine;

    let mut state = genesis_state;
    let mut signed_blocks = Vec::new();
    let mut block_roots = Vec::new();
    let mut inline_states = Vec::new();
    let mut prev_block_root = anchor_root;

    for i in 1..=n {
        let slot = Slot(i);

        let mut pre_state_advanced = state.clone();
        process_slots_fork::<MinimalEthSpec>(
            &mut pre_state_advanced,
            slot,
            ForkEpochs::never(),
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("process_slots failed at slot {i}: {e}"));

        let (prev_randao, expected_timestamp) = {
            let s = match &pre_state_advanced {
                ForkMinState::Bellatrix(s) => s,
                _ => panic!("expected Bellatrix state"),
            };
            let epoch = slot.0 / MinimalEthSpec::SLOTS_PER_EPOCH;
            let idx = (epoch % MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
            let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
            let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
            (randao, ts)
        };

        let payload_parent_hash = if i == 1 {
            Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES)
        } else {
            let mut h = [0u8; 32];
            h[0] = (i - 1) as u8;
            Hash256::from_array(h)
        };
        let mut bh = [0u8; 32];
        bh[0] = i as u8;
        let block_hash = Hash256::from_array(bh);

        let payload = MinimalExecutionPayload {
            parent_hash: payload_parent_hash,
            prev_randao,
            block_number: i,
            gas_limit: 0x1c9c380,
            timestamp: expected_timestamp,
            block_hash,
            ..Default::default()
        };

        let randao_epoch = get_current_epoch::<MinimalEthSpec>(&pre_state_advanced);
        let randao_domain =
            get_domain::<MinimalEthSpec>(&pre_state_advanced, DOMAIN_RANDAO, Some(randao_epoch));
        let randao_signing_root = compute_signing_root(&randao_epoch, randao_domain);
        let randao_reveal = test_sign(randao_signing_root.as_slice());

        const G2_INFINITY: [u8; 96] = {
            let mut b = [0u8; 96];
            b[0] = 0xc0;
            b
        };
        let sync_aggregate = MinimalSyncAggregate {
            sync_committee_signature: BLSSignature::from_array(G2_INFINITY),
            ..Default::default()
        };

        let body = MinimalBeaconBlockBody {
            execution_payload: payload,
            randao_reveal,
            sync_aggregate,
            ..Default::default()
        };

        let draft = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: prev_block_root,
            state_root: Root::default(),
            body: body.clone(),
        };
        let draft_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: draft,
            signature: BLSSignature::from_array([0u8; 96]),
        });
        let (post_draft, _) = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            state.clone(),
            &draft_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("draft STF failed at slot {i}: {e}"));

        let state_root: Root = post_draft.tree_hash_root();
        let final_block = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: prev_block_root,
            state_root,
            body,
        };
        let block_root: Root = final_block.tree_hash_root();

        let domain =
            get_domain::<MinimalEthSpec>(&pre_state_advanced, DOMAIN_BEACON_PROPOSER, None);
        let signing_root = compute_signing_root(&final_block, domain);
        let real_sig = test_sign(signing_root.as_slice());

        let fork_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: final_block,
            signature: real_sig,
        });
        let (post_final, _) = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            state.clone(),
            &fork_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("final STF failed at slot {i}: {e}"));

        state = post_final.clone();
        prev_block_root = block_root;
        signed_blocks.push(fork_signed);
        block_roots.push(block_root);
        inline_states.push(post_final);
    }

    (signed_blocks, block_roots, inline_states)
}

// ── FixtureBlockProvider ──────────────────────────────────────────────────────

#[derive(Clone)]
struct FixtureBlockProvider {
    blocks: Arc<parking_lot::Mutex<Option<Vec<MinForkSignedBlock>>>>,
}

impl FixtureBlockProvider {
    fn new(blocks: Vec<MinForkSignedBlock>) -> Self {
        Self {
            blocks: Arc::new(parking_lot::Mutex::new(Some(blocks))),
        }
    }
}

impl BackfillBlockProvider<MinimalEthSpec> for FixtureBlockProvider {
    async fn blocks_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
    ) -> Result<Vec<MinForkSignedBlock>, BackfillError> {
        let mut guard = self.blocks.lock();
        Ok(guard.take().unwrap_or_default())
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Main test: persist a chain via backfill, then exercise `StateRegenService`.
///
/// `SLOTS_PER_EPOCH = 8` for MinimalEthSpec. We build 13 blocks:
///   - slot 8 → epoch boundary (state stored on disk).
///   - slots 1–7, 9–13 → intermediate (no stored state; regen must replay).
///
/// Assertions:
///   (a) `state_at_slot(s)` for intermediate slots 3, 5, 10, 12 equals the
///       inline-replayed state's `tree_hash_root`.
///   (b) `state_at_root(state_root)` round-trips intermediate slot 11's root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_regen_replay_matches_inline() {
    let _ = tracing_subscriber::fmt::try_init();

    let (genesis_state, anchor_block) = build_genesis_for_test();
    let anchor_root: Root = anchor_block.tree_hash_root();

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open RocksStore"),
    );

    // Wire fork-choice store.
    let mut fc = get_forkchoice_store::<MinimalEthSpec>(genesis_state.clone(), anchor_block);
    fc.runtime_cfg = MinimalEthSpec::default_runtime_config();
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );
    let fc_store = Arc::new(RwLock::new(fc));

    let gvr = Root::default();
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: Epoch(0),
        bellatrix_fork_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: Epoch(0),
        capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
        capella_fork_epoch: Epoch(u64::MAX),
        genesis_validators_root: gvr,
    };
    let runtime_cfg = Arc::new(pharos_types::config::RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
        ..Default::default()
    });
    let host = Arc::new(HostImpl::<MinimalEthSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc_store),
        gvr,
        fork_schedule,
        0,
        Arc::clone(&runtime_cfg),
    ));

    let exec_engine = Arc::new(NullExecutionEngine);
    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

    // Build SLOTS_PER_EPOCH + 5 = 13 blocks.
    let n_blocks: u64 = MinimalEthSpec::SLOTS_PER_EPOCH + 5;
    let (signed_blocks, _block_roots, inline_states) =
        build_chain(genesis_state, anchor_root, n_blocks);

    let provider = FixtureBlockProvider::new(signed_blocks.clone());
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let notify = Arc::new(Notify::new());

    let fc_for_assert = Arc::clone(&fc_store);
    let handle = tokio::spawn(async move {
        run_backfill_loop::<
            MinimalEthSpec,
            _,
            NullExecutionEngine,
            pharos_fork_choice::NoopPowBlockProvider,
        >(
            provider,
            host,
            fc_store,
            exec_engine,
            pow_provider,
            head_tx,
            payload_tx,
            BACKFILL_GENESIS_TIME_SECS,
            shutdown_rx,
            notify,
            None,
        )
        .await
    });

    // Wait until head advances to n_blocks.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let head_slot = {
            let s = fc_for_assert.read();
            let root = get_head::<MinimalEthSpec>(&s);
            s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
        };
        if head_slot.0 >= n_blocks {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout: head_slot={} expected >= {n_blocks}", head_slot.0);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = shutdown_tx.send(true);
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("loop should exit")
        .expect("task must not panic");
    assert!(result.is_ok(), "backfill loop must return Ok: {result:?}");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── Force the disk replay path ────────────────────────────────────────────
    //
    // Without the Phase-3 freezer, the backfill loop leaves ALL post-states in
    // the in-memory `block_states` map, so `nearest_stored_state` would satisfy
    // every query from RAM and `replay_to` would never run. Evict all non-epoch-
    // boundary states so the regen service is forced to load the nearest stored
    // boundary state from disk and replay forward — exactly what Task 2.6 must
    // exercise.
    {
        let mut fc = fc_for_assert.write();
        let evict: Vec<_> = fc
            .block_states
            .iter()
            .filter_map(|(r, s)| (s.slot().0 % MinimalEthSpec::SLOTS_PER_EPOCH != 0).then_some(*r))
            .collect();
        for r in evict {
            fc.block_states.remove(&r);
        }
    }

    // ── Build the StateRegenService ───────────────────────────────────────────

    let regen = StateRegenService::<MinimalEthSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc_for_assert),
        Arc::clone(&runtime_cfg),
    );

    // ── (a) state_at_slot for intermediate slots equals inline replay ─────────
    //
    // Intermediate (non-boundary) slots: 3, 5, 10, 12.
    // `inline_states[i]` is the post-state after slot `i+1`, so slot 3 → index 2.
    let spe = MinimalEthSpec::SLOTS_PER_EPOCH;
    for &target_slot_u64 in &[3u64, 5, 10, 12] {
        // Skip if target slot is an epoch boundary (not intermediate).
        if target_slot_u64 % spe == 0 {
            continue;
        }
        let target_slot = Slot(target_slot_u64);
        let inline_state = &inline_states[(target_slot_u64 - 1) as usize];
        let inline_root = inline_state.tree_hash_root();

        let regen_state = regen
            .state_at_slot(target_slot)
            .unwrap_or_else(|e| panic!("state_at_slot({target_slot_u64}) failed: {e}"));
        let regen_root = regen_state.tree_hash_root();

        assert_eq!(
            regen_root, inline_root,
            "state_at_slot({target_slot_u64}): regen root {regen_root:?} != inline root {inline_root:?}"
        );
    }

    // ── (b) state_at_root round-trips an intermediate state root ─────────────
    //
    // Pick slot 11 (intermediate, post-epoch-boundary).
    let rt_slot = 11u64;
    assert!(
        rt_slot % spe != 0,
        "slot {rt_slot} must be non-boundary for this test"
    );
    let inline_rt_state = &inline_states[(rt_slot - 1) as usize];
    let inline_rt_root = inline_rt_state.tree_hash_root();

    let regen_rt_state = regen
        .state_at_root(inline_rt_root)
        .unwrap_or_else(|e| panic!("state_at_root({inline_rt_root:?}) failed: {e}"));
    let regen_rt_root = regen_rt_state.tree_hash_root();

    assert_eq!(
        regen_rt_root, inline_rt_root,
        "state_at_root round-trip: regen root {regen_rt_root:?} != expected {inline_rt_root:?}"
    );
}
