//! Data-column sidecar pruning loop (EIP-7594 PeerDAS).
//!
//! `run_column_prune_loop` watches the existing `head_tx` channel for head
//! advances and, on each event, deletes data-column sidecars whose epoch is older
//! than `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` (= 4096) behind the current
//! head epoch.
//!
//! Mirrors `run_blob_prune_loop` (M10-DA Phase 4 / W8): column pruning is a
//! SEPARATE head-watch loop, NOT coupled to finalization or the freezer
//! migration. Sidecars are deleted when:
//!   `head_epoch - epoch_of(column) > MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS`
//! clamped so the prune horizon is never below `fulu_fork_epoch`.
//!
//! The `slot_to_block_root` index is NOT pruned — it is a navigational index
//! required indefinitely by cold regen and `DataColumnSidecarsByRange`.
//!
//! Per `D-data-column-sidecar-storage`, `D-schema-v9-migration`.

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_fork_choice::Store as FcStore;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::{BeaconSpec, phase0::primitives::Slot};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::engine_driver::HeadChange;

/// Long-lived task: prune data-column sidecars older than
/// `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` epochs behind the head.
///
/// # Arguments
/// - `head_rx`: receiver clone of the existing `watch::Sender<Option<HeadChange>>`
///   (no new channel is created — mirrors the blob-prune / freezer pattern per
///   `D-freezer-driver-off-head-watch`).
/// - `store`: shared `RocksStore` — column deletes via
///   `prune_data_column_sidecars_below_slot`.
/// - `fork_choice`: in-memory fork-choice store — read for current head slot.
/// - `fulu_fork_epoch`: the epoch at which Fulu activates; the prune horizon is
///   clamped so columns in the Fulu activation epoch or later are always retained
///   until they are old enough.
/// - `shutdown_rx`: set to `true` on Ctrl-C to break the loop.
pub async fn run_column_prune_loop<E: BeaconSpec>(
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    store: Arc<RocksStore>,
    fork_choice: Arc<RwLock<FcStore<E>>>,
    fulu_fork_epoch: u64,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!("data-column prune loop started");

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

        // Read the current head slot from the fork-choice store.
        let head_slot: Slot = {
            let fc = fork_choice.read();
            pharos_fork_choice::get_current_slot(&fc)
        };

        let head_epoch = head_slot.0 / E::SLOTS_PER_EPOCH;

        // Compute the prune horizon epoch:
        //   prune if head_epoch - epoch_of(column) > MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
        //   i.e. column epoch < head_epoch - MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
        //
        // Clamp so we never prune at or below fulu_fork_epoch (those slots are the
        // first Fulu columns and must be retained until old enough).
        let prune_horizon_epoch =
            head_epoch.saturating_sub(E::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS);

        // If the head hasn't advanced past the retention window beyond the Fulu
        // fork epoch, no column is old enough to prune yet; skip the CF scan.
        if prune_horizon_epoch < fulu_fork_epoch {
            continue;
        }

        // Never prune below fulu_fork_epoch (safety net for fulu_fork_epoch == 0).
        let clamped_epoch = prune_horizon_epoch.max(fulu_fork_epoch);

        if clamped_epoch == 0 {
            // fulu_fork_epoch is 0 and head_epoch < MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS.
            continue;
        }

        let prune_slot = Slot(clamped_epoch.saturating_mul(E::SLOTS_PER_EPOCH));

        debug!(
            head_slot = head_slot.0,
            head_epoch,
            prune_horizon_epoch,
            clamped_epoch,
            prune_slot = prune_slot.0,
            "data-column prune: checking for expired sidecars"
        );

        // Prune sidecars whose block slot falls below the computed prune slot.
        match <RocksStore as DbStore<E>>::prune_data_column_sidecars_below_slot(&store, prune_slot)
        {
            Ok(()) => {
                debug!(prune_slot = prune_slot.0, "data-column prune: completed");
            }
            Err(e) => {
                warn!(
                    prune_slot = prune_slot.0,
                    error = %e,
                    "data-column prune: prune_data_column_sidecars_below_slot failed"
                );
            }
        }
    }

    info!("data-column prune loop stopped");
}
