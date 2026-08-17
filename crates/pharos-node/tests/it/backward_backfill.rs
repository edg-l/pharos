//! Backward state-backfill integration test.
//!
//! Builds a known minimal-preset Bellatrix chain past two restore-point
//! intervals (`SLOTS_PER_HISTORICAL_ROOT = 64` for `MinimalBeaconSpec`, so a chain
//! to slot 130 covers restore points at slots 64 and 128), persists every block
//! via `run_backfill_loop` (the Phase-1 import path: block + slot-index +
//! state-summary on disk), then:
//!
//!   (a) drives the forward-backfill progress signal to genesis and runs
//!       `run_backward_backfill_loop`; asserts that BOTH restore-point states
//!       (slots 64 and 128) are persisted to the cold `restore-points` /
//!       `cold-states` CFs and that each reconstructed state's `tree_hash_root`
//!       equals the `state_root` field of the block at that slot (
//!       root-equality against a known state, ≥ 2 distinct historical slots);
//!   (b) asserts the loop PARKS (does not error, does not write) when the
//!       progress signal has not yet reached the target restore-point slot
//!       (gate-on-progress behaviour).

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_fork_choice::{get_forkchoice_store, get_head};
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::phase0::accessors::{compute_signing_root, get_current_epoch, get_domain};
use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_storage::{RocksStore, RocksStoreConfig, Store as DbStore};
use pharos_types::{
    BeaconSpec, MinimalBeaconSpec,
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
    views::BeaconBlockView as _,
};
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
use tokio::sync::{Notify, mpsc, watch};

use pharos_node::backfill::{BackfillBlockProvider, BackfillError, run_backfill_loop};
use pharos_node::backward_backfill::run_backward_backfill_loop;
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::state_regen::StateRegenService;

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

// ── Genesis + chain builder (same shape as state_replay.rs) ───────────────────

#[allow(clippy::type_complexity)]
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

/// Build a chain of `n` Bellatrix blocks. Returns `(signed_blocks, block_roots,
/// inline_states)` where `inline_states[i]` is the post-state after slot `i+1`.
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
            h[1] = ((i - 1) >> 8) as u8;
            Hash256::from_array(h)
        };
        let mut bh = [0u8; 32];
        bh[0] = i as u8;
        bh[1] = (i >> 8) as u8;
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

// ── FixtureBlockProvider ──────────────────────────────────────────────────────

#[derive(Clone)]
struct FixtureBlockProvider {
    chunks: Arc<parking_lot::Mutex<std::collections::VecDeque<Vec<MinForkSignedBlock>>>>,
}

impl FixtureBlockProvider {
    /// Serve `blocks` in fixed-size chunks so the forward loop makes multiple
    /// `blocks_by_range` calls (it requests `head_slot+1 ..` each iteration).
    fn chunked(blocks: Vec<MinForkSignedBlock>, chunk: usize) -> Self {
        let mut q = std::collections::VecDeque::new();
        for c in blocks.chunks(chunk) {
            q.push_back(c.to_vec());
        }
        Self {
            chunks: Arc::new(parking_lot::Mutex::new(q)),
        }
    }
}

impl BackfillBlockProvider<MinimalBeaconSpec> for FixtureBlockProvider {
    async fn blocks_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
    ) -> Result<Vec<MinForkSignedBlock>, BackfillError> {
        let mut guard = self.chunks.lock();
        Ok(guard.pop_front().unwrap_or_default())
    }
}

// ── Test harness ──────────────────────────────────────────────────────────────

struct Harness {
    store: Arc<RocksStore>,
    fc_store: Arc<RwLock<pharos_fork_choice::Store<MinimalBeaconSpec>>>,
    runtime_cfg: Arc<pharos_types::config::RuntimeConfig>,
    n_blocks: u64,
}

/// Build a persisted chain of `n_blocks` and return the wired-up store + fc.
async fn seed_persisted_chain(n_blocks: u64) -> Harness {
    let _ = tracing_subscriber::fmt::try_init();

    let (genesis_state, anchor_block) = build_genesis_for_test();
    let anchor_root: Root = anchor_block.tree_hash_root();

    let tmpdir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
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

    let (signed_blocks, _block_roots, _inline_states) =
        build_chain(genesis_state, anchor_root, n_blocks);

    // Serve 64 blocks per chunk so the forward loop drains in several calls.
    let provider = FixtureBlockProvider::chunked(signed_blocks, 64);
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let notify = Arc::new(Notify::new());
    // Discard the forward progress signal here; the test drives the backward loop
    // with its own controlled signal.
    let (lowest_tx, _lowest_rx) = watch::channel(Slot(0));

    let fc_for_loop = Arc::clone(&fc_store);
    let handle = tokio::spawn(async move {
        run_backfill_loop::<
            MinimalBeaconSpec,
            _,
            NullExecutionEngine,
            pharos_fork_choice::NoopPowBlockProvider,
        >(
            provider,
            host,
            fc_for_loop,
            exec_engine,
            pow_provider,
            head_tx,
            payload_tx,
            BACKFILL_GENESIS_TIME_SECS,
            shutdown_rx,
            notify,
            None,
            lowest_tx,
        )
        .await
    });

    // Wait until head advances to n_blocks.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let head_slot = {
            let s = fc_store.read();
            let root = get_head::<MinimalBeaconSpec>(&s);
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

    Harness {
        store,
        fc_store,
        runtime_cfg,
        n_blocks,
    }
}

/// Read the STF-verified `state_root` recorded by the block at `slot`.
fn block_state_root_at(store: &RocksStore, slot: Slot) -> Root {
    let block_root = store
        .block_root_at_slot(slot)
        .expect("slot index read")
        .unwrap_or_else(|| panic!("no block at slot {slot}"));
    <RocksStore as DbStore<MinimalBeaconSpec>>::get_state_summary(store, &block_root)
        .expect("state-summary read")
        .unwrap_or_else(|| panic!("no state-summary for block at slot {slot}"))
        .state_root
}

// ── Test (a): reconstruction + root-equality, ≥ 2 restore points ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backward_backfill_reconstructs_restore_points() {
    // SLOTS_PER_HISTORICAL_ROOT = 64 (minimal). Build to slot 130 so restore
    // points at slots 64 and 128 both have source blocks and a block to validate
    // against.
    let interval = MinimalBeaconSpec::SLOTS_PER_HISTORICAL_ROOT;
    assert_eq!(interval, 64);
    let h = seed_persisted_chain(130).await;

    let regen = Arc::new(StateRegenService::<MinimalBeaconSpec>::new(
        Arc::clone(&h.store),
        Arc::clone(&h.fc_store),
        Arc::clone(&h.runtime_cfg),
    ));

    // Progress signal already at genesis (source blocks present down to slot 0).
    let (lowest_tx, lowest_rx) = watch::channel(Slot(0));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    // Keep the sender alive for the duration of the loop.
    let _lowest_tx = lowest_tx;

    let result = run_backward_backfill_loop::<MinimalBeaconSpec>(
        Arc::clone(&regen),
        Arc::clone(&h.store),
        Arc::clone(&h.fc_store),
        lowest_rx,
        shutdown_rx,
    )
    .await;
    assert!(result.is_ok(), "backward backfill must succeed: {result:?}");

    // Both restore points (64 and 128) must be persisted and root-correct.
    for &slot_u64 in &[64u64, 128] {
        let slot = Slot(slot_u64);
        let cold = <RocksStore as DbStore<MinimalBeaconSpec>>::get_cold_state(&h.store, slot)
            .expect("cold state read")
            .unwrap_or_else(|| panic!("restore point at slot {slot_u64} not persisted"));
        let got = cold.tree_hash_root();
        let expected = block_state_root_at(&h.store, slot);
        assert_eq!(
            got, expected,
            "reconstructed state root at slot {slot_u64} {got:?} != block state_root {expected:?}"
        );

        // The restore-points index must also record the slot → state_root entry.
        let (rp_slot, rp_root) =
            <RocksStore as DbStore<MinimalBeaconSpec>>::nearest_restore_point(&h.store, slot)
                .expect("nearest_restore_point read")
                .unwrap_or_else(|| panic!("no restore-point index at slot {slot_u64}"));
        assert_eq!(rp_slot, slot, "nearest restore point slot mismatch");
        assert_eq!(rp_root, expected, "restore-point index root mismatch");
    }

    let _ = h.n_blocks;
}

// ── Test (b): gate-on-progress — the loop parks, does not error ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backward_backfill_parks_until_progress_signal() {
    let h = seed_persisted_chain(130).await;

    let regen = Arc::new(StateRegenService::<MinimalBeaconSpec>::new(
        Arc::clone(&h.store),
        Arc::clone(&h.fc_store),
        Arc::clone(&h.runtime_cfg),
    ));

    // Progress signal pinned ABOVE the highest restore point (slot 128) so the
    // gate `lowest_block_slot <= target_slot` is FALSE for slot 128 → the loop
    // must park (not error, not write).
    let (lowest_tx, lowest_rx) = watch::channel(Slot(200));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let store_for_loop = Arc::clone(&h.store);
    let mut handle = tokio::spawn(async move {
        run_backward_backfill_loop::<MinimalBeaconSpec>(
            regen,
            store_for_loop,
            Arc::clone(&h.fc_store),
            lowest_rx,
            shutdown_rx,
        )
        .await
    });

    // The loop must NOT complete within 800 ms — it is parked on the signal.
    let timed_out = tokio::time::timeout(Duration::from_millis(800), &mut handle)
        .await
        .is_err();
    assert!(
        timed_out,
        "backward backfill must park while gated, not exit"
    );

    // While parked it must not have written any restore point at slot 128.
    let cold = <RocksStore as DbStore<MinimalBeaconSpec>>::get_cold_state(&h.store, Slot(128))
        .expect("cold state read");
    assert!(
        cold.is_none(),
        "no restore point may be written while parked"
    );

    // Release the gate: signal reaches genesis. The loop must wake, reconstruct,
    // and exit Ok.
    let _ = lowest_tx.send(Slot(0));
    let result = tokio::time::timeout(Duration::from_secs(30), handle)
        .await
        .expect("loop must finish after gate released")
        .expect("task must not panic");
    assert!(
        result.is_ok(),
        "backward backfill must succeed once gated open: {result:?}"
    );

    // Now the restore point at slot 128 must be present.
    let cold = <RocksStore as DbStore<MinimalBeaconSpec>>::get_cold_state(&h.store, Slot(128))
        .expect("cold state read");
    assert!(
        cold.is_some(),
        "restore point at slot 128 must be persisted after the gate opened"
    );

    let _ = shutdown_tx;
}
