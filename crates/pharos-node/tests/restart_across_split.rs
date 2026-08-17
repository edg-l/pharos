//! Restart-across-split integration test (Task 4.5 of M-Storage Phase 4).
//!
//! Builds a chain of `2 * SLOTS_PER_EPOCH` Bellatrix blocks, persists all
//! blocks via `run_backfill_loop`, simulates finalization at epoch 1
//! (slot `SLOTS_PER_EPOCH`), runs `migrate_to_cold` to push data cold, then
//! drops the DB, reopens it, and calls `rehydrate_fork_choice_store`.
//!
//! Asserts:
//!   (a) Head matches: `get_head` after rehydration returns the expected head root.
//!   (b) Pre-split (cold) block is retrievable via `get_cold_block`.
//!   (c) Pre-split historical state regenerates via `StateRegenService::state_at_slot`
//!       for a slot below the split, matching the inline-computed state root.
//!   (d) Post-split hot block is present in the rehydrated `block_states` map.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{get_forkchoice_store, get_head};
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::phase0::accessors::{compute_signing_root, get_current_epoch, get_domain};
use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_storage::{
    ColdMigrationBatch, ForkChoiceSnapshot, RocksStore, RocksStoreConfig, Store as DbStore,
};
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
    views::BeaconBlockView as _,
};
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
use tokio::sync::{Notify, mpsc, watch};

use pharos_node::backfill::{BackfillBlockProvider, BackfillError, run_backfill_loop};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::startup::rehydrate_fork_choice_store;
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

const TERMINAL_BLOCK_HASH_BYTES: [u8; 32] = [0xBB_u8; 32];
const BACKFILL_GENESIS_TIME_SECS: u64 = 1_000_000;

// ── BLS helpers ───────────────────────────────────────────────────────────────

fn test_sk() -> blst::min_pk::SecretKey {
    blst::min_pk::SecretKey::key_gen(&[2u8; 32], &[]).expect("valid IKM")
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

/// Restart-across-split test.
///
/// 1. Builds `2 * SLOTS_PER_EPOCH = 16` Bellatrix blocks and persists via backfill.
/// 2. Simulates finalization at epoch 1 (split_slot = SPE = 8).
/// 3. Runs `migrate_to_cold` (freezer step) to push finalized data cold.
/// 4. Persists the split_slot metadata and a `ForkChoiceSnapshot` that points
///    to the tip (slot 16) as the head.
/// 5. Drops the DB (`Arc` → strong_count = 0) and reopens it.
/// 6. Calls `rehydrate_fork_choice_store` on the fresh `RocksStore`.
/// 7. Asserts:
///    (a) `get_head` returns the expected head root.
///    (b) A pre-split (cold) block is retrievable via `get_cold_block`.
///    (c) A pre-split historical state regenerates via `StateRegenService`.
///    (d) A post-split hot block is present in `rehydrated.block_states`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_across_split_rehydrates_correctly() {
    let _ = tracing_subscriber::fmt::try_init();

    const SPE: u64 = MinimalBeaconSpec::SLOTS_PER_EPOCH;
    let n_blocks: u64 = 2 * SPE; // 16 blocks

    // ── 1. Build genesis + chain ──────────────────────────────────────────────
    let (genesis_state, anchor_block) = build_genesis_for_test();
    let anchor_root: Root = anchor_block.tree_hash_root();

    let tmpdir = tempfile::tempdir().unwrap();
    let db_path = tmpdir.path().join("chain_db");

    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: db_path.clone(),
            create_if_missing: true,
        })
        .expect("open RocksStore"),
    );

    // Persist the genesis state (slot 0) so `StateRegenService` can use it as
    // the replay anchor for pre-split slots (e.g. slot 5 < split_slot = 8).
    // The genesis state is NOT imported via `import_block`, so we persist it
    // manually.  We also store a state-summary and the slot-index entry for
    // the anchor block so `nearest_epoch_boundary_state_on_disk` can find it.
    {
        use pharos_storage::{BlockTransition, StateSummary};
        let genesis_state_root: Root = genesis_state.tree_hash_root();
        let mut bt = BlockTransition::<MinimalBeaconSpec>::new();
        bt.state = Some((genesis_state_root, genesis_state.clone()));
        bt.slot_index = Some((Slot(0), anchor_root));
        bt.state_summary = Some((
            anchor_root,
            StateSummary {
                slot: Slot(0),
                state_root: genesis_state_root,
                parent_root: Root::default(),
            },
        ));
        <RocksStore as DbStore<MinimalBeaconSpec>>::write_block_transition(&store, bt)
            .expect("persist genesis state");
    }

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

    // The expected head root is the last block root in the chain.
    let expected_head_root = block_roots[n_blocks as usize - 1];

    // ── 2. Simulate finalization at epoch 1 (split_slot = SPE = 8) ───────────
    let split_slot = Slot(SPE); // epoch boundary = slot 8
    let finalized_root = block_roots[(SPE - 1) as usize]; // root of block at slot SPE

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

    // Restore-point: epoch-boundary state at split_slot.
    let rp_root = block_roots[(SPE - 1) as usize];
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
        prune_orphan_block_roots: Vec::new(), // linear chain — no orphans
        split_slot,
    };

    <RocksStore as DbStore<MinimalBeaconSpec>>::migrate_to_cold(&store, batch)
        .expect("migrate_to_cold must succeed");

    // ── 4. Persist a ForkChoiceSnapshot pointing at the tip ──────────────────
    //
    // `rehydrate_fork_choice_store` reads the snapshot to know head_slot and
    // the finalized/justified checkpoints.  We write one that accurately
    // reflects the post-migration state: finalized at epoch 1, head at slot 16.
    // Use justified_checkpoint.epoch = 0 (GENESIS_EPOCH) so that
    // `filter_block_tree`'s `correct_justified` shortcut fires unconditionally
    // for all blocks in the chain — without attestations, get_voting_source
    // returns epoch 0 for all blocks (via unrealized_justifications which is
    // empty after restart), and only the GENESIS_EPOCH shortcut keeps them
    // viable as fork-choice heads.  This is the same approach used by
    // `apply_anchor` (see checkpoint_sync.rs comments).
    //
    // Set genesis_time to a value that makes the current slot close to the
    // actual chain tip so `current_epoch` is small and `correct_justified` holds.
    let slot_duration = MinimalBeaconSpec::SLOT_DURATION_MS / 1000;
    let fake_genesis_time = 10_000_000u64 - n_blocks * slot_duration;
    let snap = ForkChoiceSnapshot {
        genesis_time: fake_genesis_time,
        justified_checkpoint: Checkpoint {
            epoch: Epoch(0),
            root: finalized_root,
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch(1),
            root: finalized_root,
        },
        unrealized_justified_checkpoint: Checkpoint {
            epoch: Epoch(0),
            root: finalized_root,
        },
        unrealized_finalized_checkpoint: Checkpoint {
            epoch: Epoch(1),
            root: finalized_root,
        },
        proposer_boost_root: Root::default(),
        head_root: expected_head_root,
        head_slot: Slot(n_blocks),
        last_known_time: 10_000_000,
    };
    <RocksStore as DbStore<MinimalBeaconSpec>>::put_forkchoice_snapshot(&store, &snap)
        .expect("put_forkchoice_snapshot");

    // ── 5. Drop the DB and reopen ─────────────────────────────────────────────
    drop(store);
    drop(fc_for_assert);

    let store2 = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: db_path.clone(),
            create_if_missing: false,
        })
        .expect("reopen RocksStore"),
    );

    // ── 6. Rehydrate fork-choice store ────────────────────────────────────────
    let rehydrated =
        rehydrate_fork_choice_store::<MinimalBeaconSpec>(&store2, &snap, runtime_cfg.as_ref())
            .expect("rehydrate");

    // ── 7a. Assert: head matches ──────────────────────────────────────────────
    let rehydrated_head = get_head::<MinimalBeaconSpec>(&rehydrated);
    assert_eq!(
        rehydrated_head, expected_head_root,
        "rehydrated head root must match the expected tip (slot {n_blocks})"
    );

    // ── 7b. Assert: pre-split (cold) block is retrievable ────────────────────
    //
    // A block at slot 3 (below split_slot = 8) must be in the cold-blocks CF.
    let cold_slot = Slot(3);
    let cold_root = store2
        .block_root_at_slot(cold_slot)
        .expect("slot-index lookup")
        .expect("slot 3 must have a block root");
    let cold_block =
        <RocksStore as DbStore<MinimalBeaconSpec>>::get_cold_block(&store2, &cold_root)
            .expect("get_cold_block")
            .expect("pre-split block at slot 3 must be in cold-blocks CF");
    {
        use pharos_types::views::SignedBeaconBlockView as _;
        let msg_slot =
            if let Some(inner) = MinimalBeaconSpec::unwrap_bellatrix_signed_block(&cold_block) {
                use pharos_types::views::BeaconBlockView as _;
                inner.message().slot()
            } else {
                panic!("expected Bellatrix cold block");
            };
        assert_eq!(
            msg_slot, cold_slot,
            "cold block slot must be {}",
            cold_slot.0
        );
    }

    // ── 7c. Assert: pre-split historical state regenerates ───────────────────
    //
    // Slot 5 (below split_slot = 8, non-epoch-boundary) must be regenerated
    // from the cold restore point (slot 8) via `StateRegenService`.
    // The expected state root is the inline-computed root from `build_chain`.
    let target_slot = Slot(5);
    let expected_state_root = inline_states[(target_slot.0 - 1) as usize].tree_hash_root();

    let fc_for_regen = Arc::new(RwLock::new(rehydrated));
    let regen = StateRegenService::<MinimalBeaconSpec>::new(
        Arc::clone(&store2),
        Arc::clone(&fc_for_regen),
        Arc::clone(&runtime_cfg),
    );

    let regen_state = tokio::task::spawn_blocking(move || regen.state_at_slot(target_slot))
        .await
        .expect("spawn_blocking must not panic")
        .expect("state_at_slot must succeed for slot 5");

    assert_eq!(
        regen_state.tree_hash_root(),
        expected_state_root,
        "regenerated state root for slot {} must match inline-computed root",
        target_slot.0
    );

    // ── 7d. Assert: post-split hot block is present ───────────────────────────
    //
    // A block at slot `SPE + 3` (= 11, above split_slot = 8) must be in the
    // rehydrated `block_states` map.
    let hot_slot = Slot(SPE + 3); // slot 11
    let hot_root = store2
        .block_root_at_slot(hot_slot)
        .expect("slot-index lookup")
        .expect("slot 11 must have a block root");

    assert!(
        fc_for_regen.read().block_states.contains_key(&hot_root),
        "rehydrated block_states must contain post-split block at slot {}",
        hot_slot.0
    );

    // ── 7e. Assert: rehydrated states are Tree-backed (P1 restart fix) ─────────
    //
    // Decode/replay lands `Backend::Flat`; `rehydrate_fork_choice_store` must
    // flip every state entering `block_states` to `Backend::Tree`, or a restarted
    // node runs the live fork-choice/STF loop on the slow full-rehash path
    // forever. Probe a tree-flipped field (`block_roots`) on the post-split entry.
    {
        let fc = fc_for_regen.read();
        let hot_state = fc
            .block_states
            .get(&hot_root)
            .expect("post-split block state present");
        let tree_backed = match hot_state {
            ForkMinState::Bellatrix(s) => s.block_roots.backend_is_tree(),
            _ => panic!("test chain is bellatrix; unexpected fork variant"),
        };
        assert!(
            tree_backed,
            "rehydrated block_states entry must be Tree-backed (P1); got Naive"
        );
    }
}
