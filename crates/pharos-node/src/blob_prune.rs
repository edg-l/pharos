//! Blob sidecar pruning loop.
//!
//! `run_blob_prune_loop` watches the existing `head_tx` channel for head
//! advances and, on each event, deletes blob sidecars whose epoch is older
//! than `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` behind the current head epoch.
//!
//! Per W8: blob pruning is a SEPARATE
//! head-watch loop, NOT coupled to finalization or the freezer migration.
//! Sidecars are deleted when:
//!   `head_epoch - epoch_of(blob) > MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`
//! clamped so the prune horizon is never below `deneb_fork_epoch`.
//!
//! The `slot_to_block_root` index is NOT pruned — it is a navigational index
//! required indefinitely by cold regen and `BeaconBlocksByRange`.
//!
//! Per `D-blob-store-cf-keyed-by-root-index`, `D-schema-v4-migration`.

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_fork_choice::Store as FcStore;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::{BeaconSpec, phase0::primitives::Slot};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::engine_driver::HeadChange;

/// Long-lived task: prune blob sidecars older than
/// `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` epochs behind the head.
///
/// # Arguments
/// - `head_rx`: receiver clone of the existing `watch::Sender<Option<HeadChange>>`.
///   No new channel is created (mirrors the freezer pattern per
///   `D-freezer-driver-off-head-watch`).
/// - `store`: shared `RocksStore` — blob deletes via `prune_blob_sidecars_below_slot`.
/// - `fork_choice`: in-memory fork-choice store — read for current head slot.
/// - `deneb_fork_epoch`: the epoch at which Deneb activates; the prune horizon is
///   clamped so blobs in the Deneb activation epoch or later are always retained
///   until they are old enough.
/// - `shutdown_rx`: set to `true` on Ctrl-C to break the loop.
pub async fn run_blob_prune_loop<E: BeaconSpec>(
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    store: Arc<RocksStore>,
    fork_choice: Arc<RwLock<FcStore<E>>>,
    deneb_fork_epoch: u64,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!("blob prune loop started");

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
        //   prune if head_epoch - epoch_of(blob) > MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
        //   i.e. blob epoch < head_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS
        //
        // Clamp so we never prune at or below deneb_fork_epoch (those slots
        // are the first Deneb blobs and must be retained until old enough).
        let prune_horizon_epoch =
            head_epoch.saturating_sub(E::MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS);

        // If the head hasn't advanced past the retention window beyond the Deneb
        // fork epoch, no blob is old enough to prune yet; skip the CF scan entirely.
        if prune_horizon_epoch < deneb_fork_epoch {
            continue;
        }

        // Never prune below deneb_fork_epoch (safety net for deneb_fork_epoch == 0).
        let clamped_epoch = prune_horizon_epoch.max(deneb_fork_epoch);

        if clamped_epoch == 0 {
            // deneb_fork_epoch is 0 and head_epoch < MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS.
            continue;
        }

        let prune_slot = Slot(clamped_epoch.saturating_mul(E::SLOTS_PER_EPOCH));

        debug!(
            head_slot = head_slot.0,
            head_epoch,
            prune_horizon_epoch,
            clamped_epoch,
            prune_slot = prune_slot.0,
            "blob prune: checking for expired sidecars"
        );

        // Prune sidecars whose slot falls below the computed prune slot.
        match <RocksStore as DbStore<E>>::prune_blob_sidecars_below_slot(&store, prune_slot) {
            Ok(()) => {
                debug!(prune_slot = prune_slot.0, "blob prune: completed");
            }
            Err(e) => {
                warn!(
                    prune_slot = prune_slot.0,
                    error = %e,
                    "blob prune: prune_blob_sidecars_below_slot failed"
                );
            }
        }
    }

    info!("blob prune loop stopped");
}
