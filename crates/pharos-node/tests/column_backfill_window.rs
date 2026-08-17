//! Orchestration test for the Fulu data-column backfill loop.
//!
//! Per the plan's REVIEWER CORRECTIONS (C2/C3/I7): this does NOT assert
//! end-to-end "fetched columns get KZG-verified + persisted" — the available
//! fixture column-sidecar builders set EMPTY `kzg_commitments`, so
//! `verify_and_filter` would drop them. KZG-verify + persist correctness is
//! covered by the Phase 2 `verify_and_filter` unit test plus the existing
//! `fulu_pipeline` / conformance KZG coverage.
//!
//! Instead we test the loop's ORCHESTRATION: which slot ranges it requests over
//! the `data_column_serve_range` window, and that it skips chunks whose custody
//! columns are already present.
//!
//! `FixtureColumnProvider` returns `Ok(Vec::new())` (empty) for every request —
//! keeping the loop advancing while we record exactly which ranges/slots it
//! asked for. An empty response makes the loop retry-after-delay
//! (`COLUMN_BACKFILL_RETRY_DELAY`) up to `COLUMN_BACKFILL_MAX_CHUNK_RETRIES`
//! times, so the test runs on a PAUSED tokio clock (`start_paused = true`):
//! `tokio::time::sleep` auto-advances instantly, making the retries free.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use parking_lot::RwLock;
use tempfile::tempdir;
use tokio::sync::watch;

use pharos_fork_choice::Store as FcStore;
use pharos_node::column_backfill::{
    BackfillColumnProvider, COLUMN_BACKFILL_CHUNK_SLOTS, ColumnBackfillError,
    run_column_backfill_loop,
};
use pharos_node::custody::{CustodyState, custody_columns_for_cgc};
use pharos_storage::transition::BlockTransition;
use pharos_storage::{RocksStore, RocksStoreConfig, Store as DbStore};
use pharos_types::config::RuntimeConfig;
use pharos_types::fulu::DataColumnSidecar;
use pharos_types::phase0::Checkpoint;
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::{BeaconSpec, MinimalBeaconSpec};
use pharos_utils::{Hash256, Uint256};

type E = MinimalBeaconSpec;

/// One recorded `data_columns_by_range` request: `(start_slot, count, columns)`.
type RecordedCall = (Slot, u64, Vec<u64>);

// ── FixtureColumnProvider ────────────────────────────────────────────────────────

/// Records every `(start_slot, count, columns)` the loop requests and returns an
/// empty sidecar set (I7). We only assert WHICH ranges were requested.
#[derive(Clone)]
struct FixtureColumnProvider {
    calls: Arc<Mutex<Vec<RecordedCall>>>,
}

impl FixtureColumnProvider {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Snapshot of the recorded calls (I7 accessor).
    fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("calls mutex").clone()
    }
}

impl BackfillColumnProvider<E> for FixtureColumnProvider {
    async fn data_columns_by_range(
        &self,
        start_slot: Slot,
        count: u64,
        columns: Vec<u64>,
    ) -> Result<Vec<DataColumnSidecar<4096, 4>>, ColumnBackfillError> {
        self.calls
            .lock()
            .expect("calls mutex")
            .push((start_slot, count, columns));
        // Empty: we are testing orchestration, not verify/persist of fetched
        // columns (that path needs KZG-valid fixtures — covered elsewhere).
        Ok(Vec::new())
    }
}

// ── Test fixtures ──────────────────────────────────────────────────────────────

/// Wall-clock current slot used by both tests. The window is
/// `[column_serve_floor_slot(N, 0), N]`; with `fulu_fork_epoch = 0` and the
/// minimal preset (`MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS = 4096`,
/// `SLOTS_PER_EPOCH = 8`) the head-relative subtraction underflows so the floor
/// clamps to `0`. `N = 80` spans three `COLUMN_BACKFILL_CHUNK_SLOTS = 32` chunks:
/// `[0,32)`, `[32,64)`, `[64,81)`.
const CURRENT_SLOT: u64 = 80;

/// `RuntimeConfig` with Fulu (and all prior forks) at epoch 0 and the minimal
/// preset slot duration, so `get_current_slot` derives the slot from the store
/// clock at minimal cadence.
fn fulu_runtime_cfg() -> RuntimeConfig {
    RuntimeConfig {
        altair_fork_epoch: 0,
        bellatrix_fork_epoch: 0,
        capella_fork_epoch: 0,
        deneb_fork_epoch: 0,
        electra_fork_epoch: 0,
        fulu_fork_epoch: 0,
        seconds_per_slot: E::SLOT_DURATION_MS / 1000,
        ..RuntimeConfig::default()
    }
}

/// Build a bare fork-choice `Store` whose `get_current_slot` returns
/// `CURRENT_SLOT`. Only the slot-clock fields (`time`, `genesis_time`,
/// `runtime_cfg.seconds_per_slot`) matter; the loop never touches `blocks` /
/// `get_head` (it walks the window by wall-clock slot, W5). `genesis_time = 0`
/// and `time = CURRENT_SLOT * seconds_per_slot` yields slot `CURRENT_SLOT`.
fn fc_store_at_current_slot() -> Arc<RwLock<FcStore<E>>> {
    let seconds_per_slot = E::SLOT_DURATION_MS / 1000;
    let cp = Checkpoint::default();
    let store = FcStore::<E> {
        time: CURRENT_SLOT * seconds_per_slot,
        genesis_time: 0,
        justified_checkpoint: cp.clone(),
        finalized_checkpoint: cp.clone(),
        unrealized_justified_checkpoint: cp.clone(),
        unrealized_finalized_checkpoint: cp,
        proposer_boost_root: Root::default(),
        equivocating_indices: HashSet::new(),
        blocks: HashMap::new(),
        block_states: HashMap::new(),
        block_timeliness: HashMap::new(),
        checkpoint_states: HashMap::new(),
        latest_messages: HashMap::new(),
        unrealized_justifications: HashMap::new(),
        payload_statuses: HashMap::new(),
        terminal_total_difficulty: Uint256::ZERO,
        terminal_block_hash: Hash256::default(),
        terminal_block_hash_activation_epoch: u64::MAX,
        altair_fork_epoch: 0,
        bellatrix_fork_epoch: 0,
        capella_fork_epoch: 0,
        runtime_cfg: RuntimeConfig {
            seconds_per_slot,
            ..RuntimeConfig::default()
        },
    };
    Arc::new(RwLock::new(store))
}

/// Open an empty `RocksStore` in a fresh tempdir. Returns the store and the
/// `TempDir` guard (kept alive for the test's duration).
fn open_store() -> (Arc<RocksStore>, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open::<E>(RocksStoreConfig {
        path: dir.path().to_path_buf(),
        create_if_missing: true,
    })
    .expect("open store");
    (Arc::new(store), dir)
}

/// A deterministic distinct block root per slot.
fn root_for_slot(slot: u64) -> Root {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&slot.to_le_bytes());
    bytes[31] = 0xAB; // make it non-zero / distinct from defaults
    Root::from(bytes)
}

/// Seed `slot_to_block_root` for `slot` via an otherwise-empty `BlockTransition`
/// (C3): `block_root_at_slot` reads the `slot_to_block_root` CF that
/// `slot_index` writes (`transition.rs:38`).
fn seed_slot_root(store: &RocksStore, slot: u64, root: Root) {
    let mut transition = BlockTransition::<E>::new();
    transition.slot_index = Some((Slot(slot), root));
    <RocksStore as DbStore<E>>::write_block_transition(store, transition)
        .expect("write slot_to_block_root");
}

/// The full window `[floor, CURRENT_SLOT]`; floor is `0` for our config.
fn window_slots() -> std::ops::RangeInclusive<u64> {
    0..=CURRENT_SLOT
}

/// `true` iff some recorded request range `[start, start+count)` covers `slot`.
fn slot_covered_by_calls(calls: &[RecordedCall], slot: u64) -> bool {
    calls
        .iter()
        .any(|(start, count, _)| slot >= start.0 && slot < start.0 + count)
}

// ── 3.2 — window coverage ────────────────────────────────────────────────────────

/// The loop must request the entire `[floor, current_slot]` window (in
/// `COLUMN_BACKFILL_CHUNK_SLOTS` chunks) when no custody columns are present.
#[tokio::test(start_paused = true)]
async fn backfill_requests_window() {
    let (store, _dir) = open_store();
    let fc_store = fc_store_at_current_slot();

    // Seed a canonical block root for every window slot so each chunk has at
    // least one slot worth fetching.
    for slot in window_slots() {
        seed_slot_root(&store, slot, root_for_slot(slot));
    }

    let provider = FixtureColumnProvider::new();
    let custody_state = Arc::new(CustodyState::new(E::CUSTODY_REQUIREMENT));
    let runtime_cfg = fulu_runtime_cfg();
    let node_id = [0u8; 32];
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    run_column_backfill_loop::<E, _>(
        provider.clone(),
        Arc::clone(&store),
        fc_store,
        node_id,
        custody_state,
        runtime_cfg,
        shutdown_rx,
    )
    .await
    .expect("loop runs to completion");

    let calls = provider.calls();
    assert!(!calls.is_empty(), "loop must request at least one chunk");

    // Every requested chunk must carry exactly this node's custody column set.
    let want = custody_columns_for_cgc::<E>(node_id, E::CUSTODY_REQUIREMENT);
    for (_, _, columns) in &calls {
        assert_eq!(*columns, want, "each request must carry the custody set");
    }

    // The union of requested ranges must cover every window slot.
    for slot in window_slots() {
        assert!(
            slot_covered_by_calls(&calls, slot),
            "window slot {slot} was never requested"
        );
    }

    // Sanity: requests are chunked at COLUMN_BACKFILL_CHUNK_SLOTS granularity.
    for (_, count, _) in &calls {
        assert!(
            *count <= COLUMN_BACKFILL_CHUNK_SLOTS,
            "chunk count {count} exceeds COLUMN_BACKFILL_CHUNK_SLOTS"
        );
    }
}

// ── 3.3 — skip already-present chunks ─────────────────────────────────────────────

/// When an entire chunk's custody columns are already persisted, the loop must
/// NOT request that chunk, while still requesting chunks with missing columns.
#[tokio::test(start_paused = true)]
async fn backfill_skips_already_present_slots() {
    let (store, _dir) = open_store();
    let fc_store = fc_store_at_current_slot();

    let node_id = [0u8; 32];
    let custody = custody_columns_for_cgc::<E>(node_id, E::CUSTODY_REQUIREMENT);

    // Seed canonical block roots for every window slot.
    for slot in window_slots() {
        seed_slot_root(&store, slot, root_for_slot(slot));
    }

    // Pre-fill the FIRST chunk entirely ([0, COLUMN_BACKFILL_CHUNK_SLOTS)) with
    // this node's custody columns — direct storage write, no verify needed
    // (`put_data_column_sidecar` keys by the block_root we pass, matching what
    // `slot_columns_present` reads back via `get_all_data_column_sidecars_by_root`).
    let prefilled_chunk_end = COLUMN_BACKFILL_CHUNK_SLOTS; // exclusive
    for slot in 0..prefilled_chunk_end {
        let root = root_for_slot(slot);
        for &index in &custody {
            let sidecar = DataColumnSidecar::<4096, 4> {
                index,
                ..Default::default()
            };
            <RocksStore as DbStore<E>>::put_data_column_sidecar(&store, root, &sidecar)
                .expect("pre-fill custody column");
        }
    }

    let provider = FixtureColumnProvider::new();
    let custody_state = Arc::new(CustodyState::new(E::CUSTODY_REQUIREMENT));
    let runtime_cfg = fulu_runtime_cfg();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    run_column_backfill_loop::<E, _>(
        provider.clone(),
        Arc::clone(&store),
        fc_store,
        node_id,
        custody_state,
        runtime_cfg,
        shutdown_rx,
    )
    .await
    .expect("loop runs to completion");

    let calls = provider.calls();

    // The fully-prefilled first chunk must never be requested.
    for slot in 0..prefilled_chunk_end {
        assert!(
            !slot_covered_by_calls(&calls, slot),
            "pre-filled slot {slot} (in the complete first chunk) must not be requested"
        );
    }

    // The remaining (missing) window slots must still be requested.
    for slot in prefilled_chunk_end..=CURRENT_SLOT {
        assert!(
            slot_covered_by_calls(&calls, slot),
            "missing window slot {slot} must be requested"
        );
    }
}
