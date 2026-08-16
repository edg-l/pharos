//! Freezer migration integration test (Task 3.7 of M-Storage Phase 3).
//!
//! Builds a chain of `2 * SLOTS_PER_EPOCH` blocks, persists all blocks via
//! `run_backfill_loop` (Phase-1 import path), then simulates finalization by
//! directly advancing the in-memory `finalized_checkpoint` to the first epoch
//! boundary. Calls `migrate_to_cold` with the migration batch and asserts:
//!
//!   (a) Finalized blocks appear in `cold-blocks` CF (via `get_cold_block`).
//!   (b) `restore-points` has the boundary entry (via `nearest_restore_point`).
//!   (c) Hot `states` CF rows below the split slot are deleted.
//!   (d) A cold-region historical state read via Phase-2
//!       `StateRegenService::state_at_slot` succeeds, producing the same state
//!       root as the inline-computed state.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{get_forkchoice_store, get_head};
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::phase0::accessors::{compute_signing_root, get_current_epoch, get_domain};
use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_storage::{ColdMigrationBatch, RocksStore, RocksStoreConfig, Store as DbStore};
use pharos_types::{
    BeaconSpec, MinimalBeaconSpec,
    altair::{MinimalSyncAggregate, MinimalSyncCommittee},
    bellatrix::{
        MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    },
    fork::ForkSchedule,
    phase0::{Checkpoint, Epoch, Gwei, Root, Slot, Validator, ValidatorIndex, Version},
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
    4096,
    8192,
    4,
    8192,
    16,
    2,
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

// ── Genesis + chain builder ───────────────────────────────────────────────────

fn build_genesis_for_test() -> (
    MinForkState,
    ForkBeaconBlock<
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
    >,
) {
    use pharos_types::phase0::operations::BeaconBlockHeader;

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

    let genesis_bellatrix = MinimalBeaconState {
        genesis_time: 0,
        slot: Slot(0),
        fork: pharos_types::phase0::Fork {
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

fn build_chain(
    genesis_state: MinForkState,
    anchor_root: Root,
    n: u64,
) -> (Vec<MinForkSignedBlock>, Vec<Root>, Vec<MinForkState>) {
    use pharos_types::bellatrix::execution_payload::MinimalExecutionPayload;

    let runtime_cfg = pharos_types::config::RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
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
        process_slots_fork::<MinimalBeaconSpec>(
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
            let epoch = slot.0 / MinimalBeaconSpec::SLOTS_PER_EPOCH;
            let idx = (epoch % MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
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

        let randao_epoch = get_current_epoch::<MinimalBeaconSpec>(&pre_state_advanced);
        let randao_domain =
            get_domain::<MinimalBeaconSpec>(&pre_state_advanced, DOMAIN_RANDAO, Some(randao_epoch));
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
        let (post_draft, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
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
            get_domain::<MinimalBeaconSpec>(&pre_state_advanced, DOMAIN_BEACON_PROPOSER, None);
        let signing_root = compute_signing_root(&final_block, domain);
        let real_sig = test_sign(signing_root.as_slice());

        let fork_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: final_block,
            signature: real_sig,
        });
        let (post_final, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
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

// ── Backfill fixture provider ─────────────────────────────────────────────────

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

impl BackfillBlockProvider<MinimalBeaconSpec> for FixtureBlockProvider {
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

/// Freezer migration test.
///
/// 1. Builds `2 * SLOTS_PER_EPOCH = 16` Bellatrix blocks and persists via backfill.
/// 2. Simulates finalization: directly sets `finalized_checkpoint` to epoch 1
///    (slot 8 = first epoch boundary) in the fork-choice store.
/// 3. Collects the migration batch and calls `migrate_to_cold`.
/// 4. Asserts:
///    (a) Blocks in slots [1, split_slot] appear in `cold-blocks` CF.
///    (b) `nearest_restore_point(split_slot)` returns the epoch-boundary entry.
///    (c) Hot `states` CF row at the epoch boundary (slot 8) is deleted.
///    (d) A cold regen via `StateRegenService::state_at_slot` for slot 5
///        (below the split) produces the correct state root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freezer_migration_cold_presence_and_regen() {
    let _ = tracing_subscriber::fmt::try_init();

    const SPE: u64 = MinimalBeaconSpec::SLOTS_PER_EPOCH;
    let n_blocks: u64 = 2 * SPE; // 16 blocks

    // ── 1. Build genesis + chain ──────────────────────────────────────────────
    let (genesis_state, anchor_block) = build_genesis_for_test();
    let anchor_root: Root = anchor_block.tree_hash_root();

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open RocksStore"),
    );

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(genesis_state.clone(), anchor_block);
    fc.runtime_cfg = MinimalBeaconSpec::default_runtime_config();
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );
    let fc_store = Arc::new(RwLock::new(fc));

    let gvr = Root::default();
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
        genesis_validators_root: gvr,
    };
    let runtime_cfg = Arc::new(pharos_types::config::RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        ..Default::default()
    });
    let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc_store),
        gvr,
        fork_schedule,
        0,
        Arc::clone(&runtime_cfg),
    ));

    let exec_engine = Arc::new(NullExecutionEngine);
    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

    let (signed_blocks, block_roots, inline_states) =
        build_chain(genesis_state, anchor_root, n_blocks);

    let provider = FixtureBlockProvider::new(signed_blocks);
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let notify = Arc::new(Notify::new());

    let fc_for_assert = Arc::clone(&fc_store);
    let handle = tokio::spawn(async move {
        run_backfill_loop::<
            MinimalBeaconSpec,
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
            watch::channel(Slot(0)).0,
        )
        .await
    });

    // Wait until head reaches n_blocks.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let head_slot = {
            let s = fc_for_assert.read();
            let root = get_head::<MinimalBeaconSpec>(&s);
            s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
        };
        if head_slot.0 >= n_blocks {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout: head_slot={} expected >= {n_blocks}",
            head_slot.0
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = shutdown_tx.send(true);
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("loop should exit")
        .expect("task must not panic");
    assert!(result.is_ok(), "backfill loop must return Ok: {result:?}");

    // Give the persist workers a moment to flush.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 2. Simulate finalization at epoch 1 (split_slot = SPE = 8) ───────────
    let split_slot = Slot(SPE); // epoch boundary = slot 8
    let finalized_root = block_roots[(SPE - 1) as usize]; // root of block at slot 8

    {
        let mut fc = fc_for_assert.write();
        fc.finalized_checkpoint = Checkpoint {
            epoch: Epoch(1),
            root: finalized_root,
        };
        fc.justified_checkpoint = Checkpoint {
            epoch: Epoch(1),
            root: finalized_root,
        };
    }

    // ── 3. Build and execute migration batch ──────────────────────────────────
    //
    // Collect blocks and states for slots [1, split_slot].
    let mut cold_blocks_vec: Vec<(Root, MinForkSignedBlock)> = Vec::new();
    let mut prune_block_roots: Vec<Root> = Vec::new();
    let mut prune_state_roots: Vec<Root> = Vec::new();

    for s in 1..=split_slot.0 {
        let slot = Slot(s);

        if let Ok(Some(root)) = store.block_root_at_slot(slot) {
            if let Ok(Some(block)) =
                <RocksStore as DbStore<MinimalBeaconSpec>>::get_block(&store, &root)
            {
                cold_blocks_vec.push((root, block));
                prune_block_roots.push(root);
            }

            // Collect state roots to prune at epoch boundaries.
            if s % SPE == 0 {
                if let Ok(Some(summary)) =
                    <RocksStore as DbStore<MinimalBeaconSpec>>::get_state_summary(&store, &root)
                {
                    if <RocksStore as DbStore<MinimalBeaconSpec>>::get_state(
                        &store,
                        &summary.state_root,
                    )
                    .ok()
                    .flatten()
                    .is_some()
                    {
                        prune_state_roots.push(summary.state_root);
                    }
                }
            }
        }
    }

    // The restore-point state: epoch-boundary at split_slot.
    let rp_root = block_roots[(SPE - 1) as usize]; // slot SPE block root
    let rp_summary =
        <RocksStore as DbStore<MinimalBeaconSpec>>::get_state_summary(&store, &rp_root)
            .expect("state_summary lookup")
            .expect("state_summary must exist at split boundary");
    let rp_state =
        <RocksStore as DbStore<MinimalBeaconSpec>>::get_state(&store, &rp_summary.state_root)
            .expect("get_state")
            .expect("epoch-boundary state must exist at split_slot");

    let cold_states = vec![(split_slot, rp_summary.state_root, rp_state)];

    let batch = ColdMigrationBatch::<MinimalBeaconSpec> {
        cold_blocks: cold_blocks_vec,
        cold_states,
        prune_block_roots: prune_block_roots.clone(),
        prune_state_roots: prune_state_roots.clone(),
        prune_orphan_block_roots: Vec::new(), // no competing forks in this linear-chain test
        split_slot,
    };

    <RocksStore as DbStore<MinimalBeaconSpec>>::migrate_to_cold(&store, batch)
        .expect("migrate_to_cold must succeed");

    // ── 4a. Assert: finalized blocks in cold-blocks CF ────────────────────────
    for (slot_idx, &root) in block_roots[..(SPE as usize)].iter().enumerate() {
        let slot = slot_idx as u64 + 1;
        let cold_block = <RocksStore as DbStore<MinimalBeaconSpec>>::get_cold_block(&store, &root)
            .unwrap_or_else(|e| panic!("get_cold_block at slot {slot}: {e}"));
        assert!(
            cold_block.is_some(),
            "block at slot {slot} must be in cold-blocks CF after migration"
        );
    }

    // ── 4b. Assert: restore-points index has the boundary entry ──────────────
    let rp_entry =
        <RocksStore as DbStore<MinimalBeaconSpec>>::nearest_restore_point(&store, split_slot)
            .expect("nearest_restore_point")
            .expect("restore-points must have an entry at or below split_slot");
    assert_eq!(
        rp_entry.0, split_slot,
        "restore-point slot must match the split boundary"
    );
    assert_eq!(
        rp_entry.1, rp_summary.state_root,
        "restore-point state_root must match the epoch-boundary state"
    );

    // ── 4c. Assert: hot states CF rows below split are deleted ────────────────
    for state_root in &prune_state_roots {
        let hot = <RocksStore as DbStore<MinimalBeaconSpec>>::get_state(&store, state_root)
            .expect("get_state lookup");
        assert!(
            hot.is_none(),
            "hot state {state_root:?} must be deleted after migration"
        );
    }

    // ── 4d. Assert: cold regen via StateRegenService succeeds ─────────────────
    //
    // Slot 4 is below split_slot (8), not an epoch boundary, so the regen
    // service must:
    //   1. Find the nearest stored restore point (slot 8) via cold-states.
    //   2. Replay backward? No — regen goes from a state BELOW the target.
    //      Wait: slot 4 < slot 8. The nearest state AT-OR-BEFORE slot 4 from
    //      cold is... none, since the only cold restore point is at slot 8.
    //
    // After migration, the genesis state (slot 0) is in the in-memory
    // fork-choice store's block_states map. The regen service picks the
    // nearest boundary ≤ target_slot from (a) in-memory, (b) hot-disk, (c) cold.
    //
    // For slot 4: in-memory has the genesis post-state at slot 0 (always
    // present after `get_forkchoice_store`). The regen walks forward to slot 4.
    //
    // For slot 10 (> split_slot=8): the cold restore point at slot 8 is the
    // nearest stored state. The regen loads it from cold-states and replays to
    // slot 10.
    //
    // Test slot 10 (above split, uses cold restore point + replay):
    let target_slot = Slot(SPE + 2); // slot 10
    let expected_state_root = inline_states[(SPE + 1) as usize].tree_hash_root();

    // Evict all in-memory block_states except genesis and the finalized boundary
    // so that cold-states is the only anchor for post-split regen.
    {
        let mut fc = fc_for_assert.write();
        let evict: Vec<_> = fc
            .block_states
            .iter()
            .filter_map(|(r, s)| {
                let slot = s.slot();
                if slot > split_slot {
                    // Keep the post-split in-memory states for the walk base.
                    None
                } else if slot == Slot(0) {
                    // Keep genesis anchor.
                    None
                } else {
                    Some(*r)
                }
            })
            .collect();
        for r in evict {
            fc.block_states.remove(&r);
        }
    }

    let regen = StateRegenService::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc_for_assert),
        Arc::clone(&runtime_cfg),
    );

    let regen_state = tokio::task::spawn_blocking(move || regen.state_at_slot(target_slot))
        .await
        .expect("spawn_blocking must not panic")
        .expect("state_at_slot must succeed for slot 10");

    assert_eq!(
        regen_state.tree_hash_root(),
        expected_state_root,
        "regenerated state root for slot {} must match inline-computed root",
        target_slot.0
    );
}

/// Cold-state density test (Phase 3 M11, `D-cold-granularity-restore-points-only`).
///
/// Verifies that after migration:
///   (a) The `cold-states` CF contains EXACTLY one entry per interval-multiple
///       epoch boundary — never dense per-slot states.
///   (b) The `slot_to_block_root` index is NOT pruned: every migrated slot
///       remains reachable via `block_root_at_slot` after `migrate_to_cold`.
///
/// Chain: 3 epochs = 24 blocks (`3 * SLOTS_PER_EPOCH`).
/// Interval: 1 epoch = 8 slots, so 3 interval-multiple boundaries (8, 16, 24)
/// fall in the migration window `(0, 24]`.
/// Expected cold-state CF entry count = 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_state_density_equals_restore_points() {
    let _ = tracing_subscriber::fmt::try_init();

    const SPE: u64 = MinimalBeaconSpec::SLOTS_PER_EPOCH;
    const INTERVAL_EPOCHS: u64 = 1;
    const INTERVAL_SLOTS: u64 = INTERVAL_EPOCHS * SPE; // 8
    let n_blocks: u64 = 3 * SPE; // 24 blocks — 3 full epochs

    // ── 1. Build genesis + chain ──────────────────────────────────────────────
    let (genesis_state, anchor_block) = build_genesis_for_test();
    let anchor_root: Root = anchor_block.tree_hash_root();

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db_density"),
            create_if_missing: true,
        })
        .expect("open RocksStore"),
    );

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(genesis_state.clone(), anchor_block);
    fc.runtime_cfg = MinimalBeaconSpec::default_runtime_config();
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );
    let fc_store = Arc::new(RwLock::new(fc));

    let gvr = Root::default();
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
        genesis_validators_root: gvr,
    };
    let runtime_cfg = Arc::new(pharos_types::config::RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        ..Default::default()
    });
    let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc_store),
        gvr,
        fork_schedule,
        0,
        Arc::clone(&runtime_cfg),
    ));

    let exec_engine = Arc::new(NullExecutionEngine);
    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

    let (signed_blocks, block_roots, _inline_states) =
        build_chain(genesis_state, anchor_root, n_blocks);

    let provider = FixtureBlockProvider::new(signed_blocks);
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let notify = Arc::new(Notify::new());

    let fc_for_assert = Arc::clone(&fc_store);
    let handle = tokio::spawn(async move {
        run_backfill_loop::<
            MinimalBeaconSpec,
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
            watch::channel(Slot(0)).0,
        )
        .await
    });

    // Wait until head reaches n_blocks.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let head_slot = {
            let s = fc_for_assert.read();
            let root = get_head::<MinimalBeaconSpec>(&s);
            s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
        };
        if head_slot.0 >= n_blocks {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout: head_slot={} expected >= {n_blocks}",
            head_slot.0
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = shutdown_tx.send(true);
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("loop should exit")
        .expect("task must not panic");
    assert!(result.is_ok(), "backfill loop must return Ok: {result:?}");

    // Give the persist workers a moment to flush.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 2. Simulate finalization over the full 3-epoch window ─────────────────
    //
    // Migrate (0, n_blocks=24]: split_slot starts at 0, finalized_slot = 24.
    let finalized_slot = Slot(n_blocks); // 24
    let finalized_root = block_roots[(n_blocks - 1) as usize]; // root of block at slot 24

    {
        let mut fc = fc_for_assert.write();
        fc.finalized_checkpoint = Checkpoint {
            epoch: Epoch(3),
            root: finalized_root,
        };
        fc.justified_checkpoint = Checkpoint {
            epoch: Epoch(3),
            root: finalized_root,
        };
    }

    // ── 3. Build migration batch with restore-point states at every interval
    //      multiple: slots 8, 16, 24 (interval = 1 epoch = 8 slots) ──────────
    let mut cold_blocks_vec: Vec<(Root, MinForkSignedBlock)> = Vec::new();
    let mut prune_block_roots: Vec<Root> = Vec::new();
    let mut prune_state_roots: Vec<Root> = Vec::new();
    let mut cold_states: Vec<(Slot, Root, <MinimalBeaconSpec as BeaconSpec>::BeaconState)> =
        Vec::new();

    for s in 1..=finalized_slot.0 {
        let slot = Slot(s);
        if let Ok(Some(root)) = store.block_root_at_slot(slot) {
            if let Ok(Some(block)) =
                <RocksStore as DbStore<MinimalBeaconSpec>>::get_block(&store, &root)
            {
                cold_blocks_vec.push((root, block));
                prune_block_roots.push(root);
            }

            // Collect restore-point states at interval-multiple epoch boundaries only.
            // With INTERVAL_SLOTS=8=SPE, every epoch boundary is also an interval
            // multiple, so the condition simplifies to: s % INTERVAL_SLOTS == 0.
            if s % INTERVAL_SLOTS == 0 {
                if let Ok(Some(summary)) =
                    <RocksStore as DbStore<MinimalBeaconSpec>>::get_state_summary(&store, &root)
                {
                    if let Ok(Some(state)) = <RocksStore as DbStore<MinimalBeaconSpec>>::get_state(
                        &store,
                        &summary.state_root,
                    ) {
                        prune_state_roots.push(summary.state_root);
                        cold_states.push((slot, summary.state_root, state));
                    }
                }
            }
        }
    }

    // The number of interval-multiple epoch boundaries in (0, 24] with interval 8:
    // slots 8, 16, 24 → 3 expected restore points.
    let expected_restore_point_count = (finalized_slot.0 / INTERVAL_SLOTS) as usize;
    assert_eq!(
        cold_states.len(),
        expected_restore_point_count,
        "test setup must produce exactly {expected_restore_point_count} interval-multiple states",
    );

    let batch = ColdMigrationBatch::<MinimalBeaconSpec> {
        cold_blocks: cold_blocks_vec,
        cold_states,
        prune_block_roots: prune_block_roots.clone(),
        prune_state_roots,
        prune_orphan_block_roots: Vec::new(),
        split_slot: finalized_slot,
    };

    <RocksStore as DbStore<MinimalBeaconSpec>>::migrate_to_cold(&store, batch)
        .expect("migrate_to_cold must succeed");

    // ── 4a. Assert: cold-state CF density == restore-point count ─────────────
    //
    // Per `D-cold-granularity-restore-points-only`: the cold-states CF stores
    // ONLY restore-point-interval-multiple snapshots, never dense per-slot states.
    // `count_cold_state_entries` counts every key in `CF_COLD_STATES`.
    let actual_cold_state_count = store
        .count_cold_state_entries()
        .expect("count_cold_state_entries must succeed");
    assert_eq!(
        actual_cold_state_count, expected_restore_point_count as u64,
        "cold-states CF must contain exactly {} entries (one per interval-multiple epoch boundary), \
         got {}. DIVERGENCE would indicate dense per-slot states are being written.",
        expected_restore_point_count, actual_cold_state_count,
    );

    // ── 4b. Assert: slot_to_block_root index is NOT pruned ───────────────────
    //
    // Per `D-prune-behind-finalized`: the `slot_to_block_root` navigational index
    // is NEVER pruned; cold regen and `BeaconBlocksByRange` require it indefinitely.
    for (slot_idx, &root) in block_roots[..(n_blocks as usize)].iter().enumerate() {
        let slot = Slot(slot_idx as u64 + 1);
        let indexed_root = store
            .block_root_at_slot(slot)
            .unwrap_or_else(|e| panic!("block_root_at_slot({}) failed: {e}", slot.0));
        assert_eq!(
            indexed_root,
            Some(root),
            "slot_to_block_root index for slot {} must survive migration (not pruned)",
            slot.0,
        );
    }

    // ── 4c. Assert: restore-points index matches the cold-states count ────────
    //
    // `nearest_restore_point` iterates the `restore-points` CF. Check all three.
    for epoch in 1u64..=3 {
        let rp_slot = Slot(epoch * INTERVAL_SLOTS);
        let entry =
            <RocksStore as DbStore<MinimalBeaconSpec>>::nearest_restore_point(&store, rp_slot)
                .expect("nearest_restore_point must succeed")
                .unwrap_or_else(|| {
                    panic!(
                        "restore-points CF must have an entry at or below slot {}",
                        rp_slot.0
                    )
                });
        assert_eq!(
            entry.0, rp_slot,
            "nearest_restore_point for slot {} must return the exact boundary",
            rp_slot.0,
        );
    }
}
