//! Backward state backfill — historical state reconstruction (M11 Phase 2).
//!
//! Forward BLOCK backfill (`backfill.rs::run_backfill_loop`, shipped in M4b)
//! walks UP from the anchor toward the wall clock and stops at the tip; it never
//! walks below the anchor. The hot/cold freezer (M-Storage) only writes restore
//! points at-and-above the split slot as finalization advances. Neither produces
//! the genesis-ward restore points a node needs to serve arbitrary historical
//! states below the anchor.
//!
//! `run_backward_backfill_loop` closes that gap. Starting from the lowest forward
//! state the node holds (the anchor / split-point state), it walks BACKWARD by
//! `SLOTS_PER_HISTORICAL_ROOT`-slot restore-point intervals. For each target
//! restore-point slot below the current lowest stored state it:
//!   1. gates on the forward-backfill progress signal — it only attempts a
//!      restore point whose source blocks are already present
//!      (`lowest_block_slot <= target_slot`), parking on the `watch` channel
//!      otherwise (Task 2.2);
//!   2. finds the nearest stored state at-or-below the target and replays the
//!      stored block sequence forward to the restore-point slot, reusing the
//!      M-Storage `StateRegenService` replay primitives (`D-replay-on-read`,
//!      fork-crossing-safe via the real `runtime_cfg` fork schedule);
//!   3. validates `regenerated.tree_hash_root() == stored_block_at(slot).state_root`
//!      (Task 2.4) — a mismatch is a consensus bug and aborts the loop;
//!   4. persists the validated state to the cold `restore-points` /
//!      `cold-states` CFs via the existing `Store` methods (Task 2.5).
//!
//! This is a long-running BACKGROUND process (may take days on mainnet). It MUST
//! NOT block node startup — `main.rs` spawns it detached after the node is live —
//! and emits COARSE progress logging (one INFO line per completed restore-point
//! interval, not per slot; Task 2.3).

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_ssz::TreeHash;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::views::BeaconStateView as _;
use pharos_types::{
    BeaconSpec,
    phase0::primitives::{Root, Slot},
};

use crate::state_regen::{RegenError, ReplayBounds, StateRegenService};

// ── BackwardBackfillError ──────────────────────────────────────────────────────

/// Errors returned by the backward state-backfill loop.
#[derive(Debug, Error)]
pub enum BackwardBackfillError {
    /// A reconstructed state's root did not match the `state_root` field of the
    /// block at that slot. This is a consensus bug — the loop aborts rather than
    /// silently persisting a wrong state (Task 2.4).
    #[error(
        "backfill state mismatch at slot {slot}: regenerated root {got:?} != block state_root {expected:?}"
    )]
    BackfillStateMismatch {
        slot: Slot,
        got: Root,
        expected: Root,
    },

    /// State regeneration failed during replay.
    #[error("regen error during backward backfill: {0}")]
    Regen(#[from] RegenError),

    /// Storage/DB error while reading a block index or persisting a restore point.
    #[error("storage error during backward backfill: {0}")]
    Storage(#[from] pharos_storage::StorageError),
}

// ── run_backward_backfill_loop ─────────────────────────────────────────────────

/// Backward state-backfill loop (Task 2.2/2.3/2.6).
///
/// `regen`: the shared `StateRegenService` (reuses `nearest_stored_state` +
/// `replay_to`; it already carries the real `runtime_cfg` fork schedule, so
/// replay is fork-crossing-safe); `store`: the chain DB for restore-point
/// persistence and the slot/state-summary indexes; `fork_choice`: read for the
/// initial lowest stored state slot; `lowest_block_rx`: the forward-backfill
/// progress signal (`run_backfill_loop`'s `watch::Sender<Slot>`);
/// `shutdown_rx`: graceful exit.
///
/// The loop enumerates restore-point target slots (multiples of
/// `SLOTS_PER_HISTORICAL_ROOT`) strictly below the lowest stored state, from the
/// highest down to genesis. It exits when every restore point from genesis up to
/// the lowest stored state is present, or when shutdown fires (Task 2.6).
pub async fn run_backward_backfill_loop<E>(
    regen: Arc<StateRegenService<E>>,
    store: Arc<RocksStore>,
    fork_choice: Arc<RwLock<FcStore<E>>>,
    mut lowest_block_rx: watch::Receiver<Slot>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), BackwardBackfillError>
where
    E: ReplayBounds,
{
    let interval = E::SLOTS_PER_HISTORICAL_ROOT;

    // The highest restore point we ever need is the boundary just below the lowest
    // forward state we currently hold (the head). The freezer (M-Storage) already
    // writes cold restore points as finalization advances above the split slot;
    // this loop fills the genesis-ward gap below the freezer's archive floor. The
    // per-target `already_present` check (below) skips any restore point the
    // freezer (or a prior run) has already written, so the two never collide.
    let highest_state_slot = {
        let fc = fork_choice.read();
        fc.block_states
            .values()
            .map(|s| s.slot())
            .max()
            .unwrap_or(Slot(0))
    };

    if highest_state_slot.0 < interval {
        // The whole held range is below the first restore-point interval; there is
        // no interval-multiple restore point to reconstruct.
        info!(
            highest_state = %highest_state_slot,
            interval,
            "backward backfill: no restore points within held range; exiting"
        );
        return Ok(());
    }

    info!(
        highest_state = %highest_state_slot,
        interval,
        "backward backfill: starting genesis-ward state reconstruction (background)"
    );

    // Walk restore-point target slots from the highest interval-multiple at-or-below
    // the highest held state down to (and including) genesis-adjacent `interval`.
    // The slot-0 state is the genesis state and is held directly; restore points are
    // the positive multiples.
    let highest_target = (highest_state_slot.0 / interval) * interval;
    let mut target = highest_target;

    loop {
        if *shutdown_rx.borrow() {
            info!("backward backfill: shutdown signal received; exiting");
            return Ok(());
        }

        if target == 0 {
            // Reached genesis-adjacent: the slot-0 state is the genesis state,
            // already held. All genesis-ward restore points are present (Task 2.6).
            info!("backward backfill: reached genesis; all restore points present; exiting");
            return Ok(());
        }

        let target_slot = Slot(target);

        // Skip restore points the freezer (or a prior run of this loop) already
        // wrote — idempotent resume after a restart.
        let already_present =
            <RocksStore as DbStore<E>>::get_cold_state(&store, target_slot)?.is_some();
        if already_present {
            debug!(target = %target_slot, "backward backfill: restore point already present; skipping");
            target = target.saturating_sub(interval);
            continue;
        }

        // ── Gate on the forward-backfill progress signal (Task 2.2) ──────────────
        // We can only reconstruct the state at `target_slot` if the source blocks
        // are present, i.e. block coverage extends to at-or-below `target_slot`.
        // Park on the watch channel until forward backfill lowers its signal.
        loop {
            let lowest_block_slot = *lowest_block_rx.borrow();
            if lowest_block_slot.0 <= target_slot.0 {
                break;
            }
            debug!(
                target = %target_slot,
                lowest_block = %lowest_block_slot,
                "backward backfill: parking until forward backfill supplies source blocks"
            );
            tokio::select! {
                changed = lowest_block_rx.changed() => {
                    if changed.is_err() {
                        // Forward backfill dropped its sender (node teardown).
                        info!("backward backfill: progress signal closed; exiting");
                        return Ok(());
                    }
                }
                _ = shutdown_rx.changed() => {}
            }
            if *shutdown_rx.borrow() {
                info!("backward backfill: shutdown while parked; exiting");
                return Ok(());
            }
        }

        // ── Reconstruct the state at `target_slot` (Task 2.2) ────────────────────
        // `nearest_stored_state` finds the nearest stored state at-or-below the
        // target (genesis, a cold restore point this loop already wrote, or a hot
        // boundary state); `replay_to` replays the stored block sequence forward
        // to the target, fork-crossing-safe via `runtime_cfg`.
        let (_, start_state, start_slot) = regen
            .nearest_stored_state(target_slot)
            .ok_or(RegenError::MissingAnchorState)?;

        let regenerated = if start_slot == target_slot {
            start_state
        } else {
            regen.replay_to(start_state, start_slot, target_slot)?
        };

        // ── Validate against the block's stored state_root (Task 2.4) ────────────
        // The block at `target_slot` records the STF-verified post-state root in
        // its `state_root` field; the `state-summary` CF mirrors it. A mismatch is
        // a consensus bug — abort, never silently persist a wrong state.
        let expected_state_root = expected_state_root_at::<E>(&store, target_slot)?;
        if let Some(expected) = expected_state_root {
            let got = regenerated.tree_hash_root();
            if got != expected {
                warn!(
                    slot = %target_slot,
                    ?got,
                    ?expected,
                    "backward backfill: reconstructed state root mismatch — aborting (consensus bug)"
                );
                return Err(BackwardBackfillError::BackfillStateMismatch {
                    slot: target_slot,
                    got,
                    expected,
                });
            }
        } else {
            // No block at this slot (a skipped slot landing on the interval
            // boundary): persist the empty-slot post-state without a block-root
            // cross-check (there is no block to validate against). The replay
            // itself is deterministic over verified inputs.
            debug!(target = %target_slot, "backward backfill: no block at restore-point slot; persisting empty-slot state");
        }

        // ── Persist to the cold restore-point CFs (Task 2.5) ─────────────────────
        let state_root = regenerated.tree_hash_root();
        <RocksStore as DbStore<E>>::put_cold_state(&store, target_slot, &regenerated)?;
        <RocksStore as DbStore<E>>::put_restore_point(&store, target_slot, state_root)?;

        // Coarse progress logging: one INFO line per completed interval (Task 2.3).
        info!(
            slot = %target_slot,
            ?state_root,
            remaining_intervals = target / interval,
            "backward backfill: reconstructed + persisted restore point"
        );

        target = target.saturating_sub(interval);

        // Yield so a long backward walk never starves other tasks on the runtime.
        tokio::task::yield_now().await;
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Look up the STF-verified `state_root` recorded by the block at `slot`.
///
/// Resolves `slot → block_root` via the `slot_to_block_root` index then
/// `block_root → state_summary.state_root`. Returns `None` when no block exists
/// at `slot` (a skipped slot) — the caller persists the empty-slot state without
/// a block cross-check in that case.
fn expected_state_root_at<E: BeaconSpec>(
    store: &RocksStore,
    slot: Slot,
) -> Result<Option<Root>, BackwardBackfillError> {
    let block_root = match store.block_root_at_slot(slot)? {
        Some(r) => r,
        None => return Ok(None),
    };
    let summary = <RocksStore as DbStore<E>>::get_state_summary(store, &block_root)?;
    Ok(summary.map(|s| s.state_root))
}
