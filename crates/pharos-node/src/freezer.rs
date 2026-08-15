//! Freezer loop — hot→cold migration at finalization.
//!
//! `run_freezer_loop` watches the existing `head_tx` channel for head advances,
//! reads `fork_choice.finalized_checkpoint` on each event, and when finalization
//! has advanced past the current `split_slot` (stored in
//! `metadata[b"split_slot"]`) it:
//!
//!   (a) Selects newly-finalized epoch-boundary states at restore-point cadence.
//!   (b) Collects finalized blocks below the new split slot.
//!   (c) Builds and writes one atomic `ColdMigrationBatch` via `migrate_to_cold`.
//!   (d) Evicts the migrated roots from the in-memory fork-choice maps (under a
//!       short write lock) so RAM is bounded behind finalization.
//!
//! Per `D-freezer-driver-off-head-watch`, `D-freezer-in-rocksdb`,
//! `D-prune-behind-finalized`, and WARNING-9 (Task 3.4).

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_fork_choice::Store as FcStore;
use pharos_storage::{ColdMigrationBatch, RocksStore, Store as DbStore};
use pharos_types::{
    EthSpec,
    phase0::primitives::{Root, Slot},
};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::engine_driver::HeadChange;

// ── Metadata key constants ────────────────────────────────────────────────────

/// `metadata` CF key for the hot/cold boundary slot.
pub const SPLIT_SLOT_KEY: &[u8] = b"split_slot";

// ── run_freezer_loop ──────────────────────────────────────────────────────────

/// Long-lived task: migrate finalized blocks/states to cold storage on each
/// head advance.
///
/// # Arguments
/// - `head_rx`: receiver clone of the existing `watch::Sender<Option<HeadChange>>`;
///   no new channel is created (per `D-freezer-driver-off-head-watch`).
/// - `store`: shared `RocksStore` — all cold writes go through `migrate_to_cold`.
/// - `fork_choice`: in-memory fork-choice store — read for finalized checkpoint
///   and block/state maps; written briefly for eviction.
/// - `restore_point_interval_epochs`: how many epochs between cold state
///   snapshots (default `DEFAULT_RESTORE_POINT_INTERVAL_EPOCHS`).
/// - `shutdown_rx`: set to `true` on Ctrl-C to break the loop.
pub async fn run_freezer_loop<E: EthSpec>(
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    store: Arc<RocksStore>,
    fork_choice: Arc<RwLock<FcStore<E>>>,
    restore_point_interval_epochs: u64,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    E::SignedBeaconBlock: pharos_ssz::Decode + Clone,
    E::BeaconState: pharos_ssz::Decode + Clone,
{
    info!(restore_point_interval_epochs, "freezer loop started");

    loop {
        tokio::select! {
            result = head_rx.changed() => {
                if result.is_err() {
                    // Sender dropped — node is shutting down.
                    break;
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
        }

        // Read the current split_slot from DB (not from memory — stays durable).
        let split_slot = {
            match <RocksStore as DbStore<E>>::get_metadata(&store, SPLIT_SLOT_KEY) {
                Ok(Some(bytes)) => {
                    if bytes.len() == 8 {
                        let arr: [u8; 8] = bytes.try_into().expect("length 8 checked");
                        Slot(u64::from_be_bytes(arr))
                    } else {
                        Slot(0)
                    }
                }
                _ => Slot(0),
            }
        };

        // Read finalized checkpoint under a READ lock (no writes, no contention).
        let (finalized_checkpoint, finalized_slot) = {
            let fc = fork_choice.read();
            let cp = fc.finalized_checkpoint.clone();
            // The finalized slot is at the START of the finalized epoch.
            let epoch_start = cp.epoch.0.saturating_mul(E::SLOTS_PER_EPOCH);
            (cp, Slot(epoch_start))
        };

        // Nothing to do if finalization has not advanced past the split.
        if finalized_slot <= split_slot {
            continue;
        }

        debug!(
            old_split = split_slot.0,
            new_split = finalized_slot.0,
            finalized_epoch = finalized_checkpoint.epoch.0,
            "freezer: finalized past split; building migration batch"
        );

        // ── Collect blocks and states to migrate ──────────────────────────────

        // Collect all block roots in (split_slot, finalized_slot] for cold copy.
        // We use the slot-index (slot_to_block_root) for canonical blocks.
        let mut cold_blocks: Vec<(Root, E::SignedBeaconBlock)> = Vec::new();
        let mut prune_block_roots: Vec<Root> = Vec::new();
        let mut prune_state_roots: Vec<Root> = Vec::new();

        // Collect canonical block roots for slots in (split_slot, finalized_slot].
        // For each canonical block: copy to cold, schedule hot deletion. The
        // slot-index (slot_to_block_root) is NOT pruned — cold regen + network
        // serving navigate migrated history through it.
        let mut canonical_roots_in_range: Vec<(Slot, Root)> = Vec::new();

        for s in (split_slot.0 + 1)..=finalized_slot.0 {
            let slot = Slot(s);
            match store.block_root_at_slot(slot) {
                Ok(Some(root)) => {
                    canonical_roots_in_range.push((slot, root));
                }
                Ok(None) => {
                    // Missed slot — nothing to migrate, but prune the index entry
                    // (it does not exist, so this is a no-op in the batch).
                }
                Err(e) => {
                    warn!(slot = s, error = %e, "freezer: slot-index lookup failed; skipping slot");
                }
            }
        }

        // Load canonical blocks from hot CF and collect cold_blocks + prune lists.
        for (slot, root) in &canonical_roots_in_range {
            // Try to load the signed block from the hot CF.
            match <RocksStore as DbStore<E>>::get_block(&store, root) {
                Ok(Some(block)) => {
                    cold_blocks.push((*root, block));
                    prune_block_roots.push(*root);
                }
                Ok(None) => {
                    // Already migrated or never persisted; skip.
                    debug!(root = ?root, slot = slot.0, "freezer: block not in hot CF; skipping");
                }
                Err(e) => {
                    warn!(root = ?root, slot = slot.0, error = %e,
                          "freezer: block load failed; skipping");
                }
            }

            // Prune the corresponding hot state if stored (epoch-boundary only).
            // Look up the state_root from the state-summary CF.
            if let Ok(Some(summary)) = <RocksStore as DbStore<E>>::get_state_summary(&store, root) {
                // Check if an epoch-boundary state is stored for this slot.
                if slot.0 % E::SLOTS_PER_EPOCH == 0 {
                    // If the state is in the hot CF, schedule it for pruning.
                    if let Ok(Some(_)) =
                        <RocksStore as DbStore<E>>::get_state(&store, &summary.state_root)
                    {
                        prune_state_roots.push(summary.state_root);
                    }
                }
            }
        }

        // ── Select restore-point states ───────────────────────────────────────
        //
        // Write ALL restore-point boundaries in (split_slot, finalized_slot] —
        // every epoch boundary that is a multiple of
        // `restore_point_interval_epochs`, plus a fallback (the finalized slot)
        // when no multiple falls in the range — so cold regen never replays more
        // than the configured interval, even after a long finalization gap.
        let cold_states: Vec<(Slot, Root, E::BeaconState)> = select_restore_point_states::<E>(
            &store,
            split_slot,
            finalized_slot,
            restore_point_interval_epochs,
        );

        // ── Write the atomic migration batch ──────────────────────────────────

        let new_split = finalized_slot;
        let batch = ColdMigrationBatch {
            cold_blocks,
            cold_states,
            prune_block_roots: prune_block_roots.clone(),
            prune_state_roots,
            split_slot: new_split,
        };

        match <RocksStore as DbStore<E>>::migrate_to_cold(&store, batch) {
            Ok(()) => {
                info!(
                    new_split = new_split.0,
                    finalized_epoch = finalized_checkpoint.epoch.0,
                    "freezer: migration complete"
                );
            }
            Err(e) => {
                warn!(error = %e, "freezer: migrate_to_cold failed; will retry on next head");
                continue;
            }
        }

        // ── Evict from in-memory fork-choice maps (Task 3.4) ──────────────────
        //
        // WARNING-9: evicting pre-finalized blocks requires pruning
        // `latest_messages` entries whose `.root` points at an evicted block, to
        // prevent `get_ancestor` from returning a stale root on a missing-blocks
        // entry and silently corrupting LMD-GHOST weights. Also prune
        // `block_timeliness`, `unrealized_justifications`, and `payload_statuses`.
        //
        // Pattern: collect eviction set under READ lock (no contention with import),
        // then take a SHORT WRITE lock only for the HashMap::remove loop.
        evict_finalized_from_fc::<E>(&fork_choice, &prune_block_roots, new_split);
    }

    info!("freezer loop exited");
}

/// Select the restore-point states to write in the current migration batch.
///
/// Scans epoch-boundary slots in (split_slot, finalized_slot] and returns EVERY
/// slot that is a multiple of `interval_epochs * SLOTS_PER_EPOCH` and has a
/// stored state in the hot `states` CF. When no exact interval multiple falls in
/// the range, falls back to the single highest epoch-boundary state in range, so
/// at least one restore point is always written per migration. Returning all
/// multiples (not just the latest) keeps the cold replay-cost bound at
/// `interval_epochs` even after a long non-finalization gap.
fn select_restore_point_states<E: EthSpec>(
    store: &RocksStore,
    split_slot: Slot,
    finalized_slot: Slot,
    interval_epochs: u64,
) -> Vec<(Slot, Root, E::BeaconState)>
where
    E::BeaconState: pharos_ssz::Decode,
    E::SignedBeaconBlock: pharos_ssz::Decode,
{
    let spe = E::SLOTS_PER_EPOCH;
    let interval_slots = interval_epochs.saturating_mul(spe);

    // First epoch boundary strictly after split_slot.
    let first_boundary = {
        let start = split_slot.0 + 1;
        let rem = start % spe;
        if rem == 0 { start } else { start + (spe - rem) }
    };

    let mut rps: Vec<(Slot, Root, E::BeaconState)> = Vec::new();
    let mut best_fallback: Option<(Slot, Root, E::BeaconState)> = None;

    let mut boundary = first_boundary;
    while boundary <= finalized_slot.0 {
        let slot = Slot(boundary);
        boundary += spe;

        let block_root = match store.block_root_at_slot(slot) {
            Ok(Some(r)) => r,
            _ => continue,
        };
        let summary = match <RocksStore as DbStore<E>>::get_state_summary(store, &block_root) {
            Ok(Some(s)) => s,
            _ => continue,
        };
        let state = match <RocksStore as DbStore<E>>::get_state(store, &summary.state_root) {
            Ok(Some(s)) => s,
            _ => continue,
        };

        // Every interval-multiple boundary becomes a restore point.
        if interval_slots > 0 && slot.0 % interval_slots == 0 {
            rps.push((slot, summary.state_root, state));
        } else {
            // Track the latest non-multiple boundary as a fallback.
            let is_newer = best_fallback
                .as_ref()
                .map(|(s, _, _)| slot > *s)
                .unwrap_or(true);
            if is_newer {
                best_fallback = Some((slot, summary.state_root, state));
            }
        }
    }

    // Guarantee at least one restore point per migration window.
    if rps.is_empty() {
        if let Some(fb) = best_fallback {
            rps.push(fb);
        }
    }
    rps
}

/// Evict in-memory fork-choice entries for all roots in `evict_roots` that
/// correspond to slots strictly below `finalized_slot`.
///
/// WARNING-9 compliance:
///  (i)  `get_head`/`filter_block_tree` walk from `justified_checkpoint.root`
///       (≥ finalized_slot) forward — evicted pre-finalized entries are never
///       reached from that base (see `get_head.rs:334`, `get_head.rs:280-296`,
///       `get_head.rs:346-375`).
///  (ii) `latest_messages` entries whose `.root` is in the eviction set MUST be
///       pruned: `get_ancestor(store, msg.root, ...)` returns the root itself
///       on a missing `store.blocks` entry (`get_head.rs:90-92`), which would
///       silently corrupt LMD-GHOST weights.
///  (iii) `block_timeliness`, `unrealized_justifications`, and `payload_statuses`
///        are pruned for the same evicted roots to bound RAM growth.
///
/// Read lock: collect the eviction set while reading.
/// Write lock: held only for the `HashMap::remove` loop (minimal duration).
fn evict_finalized_from_fc<E: EthSpec>(
    fork_choice: &Arc<RwLock<FcStore<E>>>,
    evict_roots: &[Root],
    finalized_slot: Slot,
) {
    use std::collections::HashSet;

    if evict_roots.is_empty() {
        return;
    }

    // Collect the full eviction set: roots supplied by the caller + any
    // in-memory block whose slot is strictly below finalized_slot.
    let additional_evict: Vec<Root> = {
        use pharos_types::views::BeaconBlockView as _;
        let fc = fork_choice.read();
        fc.blocks
            .iter()
            .filter_map(|(root, block)| {
                if block.slot() < finalized_slot {
                    Some(*root)
                } else {
                    None
                }
            })
            .collect()
    };

    let evict_set: HashSet<Root> = evict_roots
        .iter()
        .copied()
        .chain(additional_evict)
        .collect();

    if evict_set.is_empty() {
        return;
    }

    // Take the write lock only for the removal loop.
    let mut fc = fork_choice.write();
    for root in &evict_set {
        fc.blocks.remove(root);
        fc.block_states.remove(root);
        fc.block_timeliness.remove(root);
        fc.unrealized_justifications.remove(root);
        fc.payload_statuses.remove(root);
    }

    // Prune latest_messages: drop entries whose voted root is in the eviction set.
    // Per WARNING-9(ii): a stale .root in latest_messages would be passed to
    // get_ancestor, which returns the root itself on a missing blocks entry,
    // silently mis-scoring forks.
    fc.latest_messages
        .retain(|_validator_idx, msg| !evict_set.contains(&msg.root));

    debug!(
        evicted = evict_set.len(),
        finalized_slot = finalized_slot.0,
        "freezer: evicted pre-finalized entries from fork-choice maps"
    );
}
