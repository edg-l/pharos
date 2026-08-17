//! Shared helpers for standard consensus-layer status logging.
//!
//! Pure logic for the sync discriminator, import-log debounce, and root
//! formatting used by the block-import chokepoint, the API event adapter, and
//! the per-slot status heartbeat.
//!
//! The pure helpers (`short_root`, `sync_status`, `should_log_import`,
//! `low_peer_floor`, `peer_log_decision`) have no I/O or logging side effects.
//! [`run_status_heartbeat`] is the one stateful task here: a slot-aligned loop
//! that emits the `Synced`/`Syncing` heartbeat line, peer-count transition
//! logs, and the low-peer warning. The node's justified epoch is reported via
//! the `Synced` heartbeat line (there is no separate per-epoch log).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use pharos_fork_choice::Store as FcStore;
use pharos_fork_choice::get_head::{get_current_slot, get_head};
use pharos_network::NetworkCommandSender;
use pharos_types::BeaconSpec;
use pharos_types::views::BeaconBlockView;
use tracing::{info, warn};

/// Format a 32-byte root as a short `0x`-prefixed hex string (first 4 bytes).
///
/// Output is always 10 characters: `0x` plus 8 hex digits.
pub(crate) fn short_root(root: [u8; 32]) -> String {
    format!("0x{}", hex::encode(&root[..4]))
}

/// Sync distance (in slots) at or below which the node is considered synced.
pub(crate) const SYNCED_DISTANCE_THRESHOLD: u64 = 1;

/// Classification of the node's sync state relative to the current slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncStatus {
    /// Head is within [`SYNCED_DISTANCE_THRESHOLD`] of the current slot.
    Synced,
    /// Head trails the current slot by `distance` slots.
    Syncing { distance: u64 },
}

/// Classify sync state from the head slot and the current (wall-clock) slot.
pub(crate) fn sync_status(head_slot: u64, current_slot: u64) -> SyncStatus {
    let distance = current_slot.saturating_sub(head_slot);
    if distance <= SYNCED_DISTANCE_THRESHOLD {
        SyncStatus::Synced
    } else {
        SyncStatus::Syncing { distance }
    }
}

/// While syncing, only emit an import log every this many slots to avoid
/// flooding during catch-up.
pub(crate) const SYNC_IMPORT_LOG_INTERVAL: u64 = 32;

/// Decide whether to emit an "Imported block" log for `block_slot`.
///
/// When synced, every imported block is logged. While syncing, only blocks on
/// the [`SYNC_IMPORT_LOG_INTERVAL`] boundary are logged.
pub(crate) fn should_log_import(status: &SyncStatus, block_slot: u64) -> bool {
    match status {
        SyncStatus::Synced => true,
        SyncStatus::Syncing { .. } => block_slot.is_multiple_of(SYNC_IMPORT_LOG_INTERVAL),
    }
}

/// Peer count below which the node emits a "Low peer count" warning.
///
/// A quarter of the configured target, floored at 1 so a `target_peers` of 0
/// never yields a 0 floor (which would suppress the warning entirely).
pub(crate) fn low_peer_floor(target_peers: usize) -> usize {
    (target_peers / 4).max(1)
}

/// Minimum absolute peer-count delta that triggers a transition log.
const PEER_LOG_DELTA: usize = 2;

/// Decide whether a peer-count change warrants a "Peer count changed" log.
///
/// Logs on the first observation (`prev` is `None`), when the count moves by at
/// least [`PEER_LOG_DELTA`], or when the `floor` boundary is crossed (one side
/// below `floor`, the other at or above it). Single-peer churn that stays on
/// the same side of the floor is suppressed.
pub(crate) fn peer_log_decision(prev: Option<usize>, cur: usize, floor: usize) -> bool {
    match prev {
        None => true,
        Some(prev) => {
            let crossed_floor = (prev < floor) != (cur < floor);
            cur.abs_diff(prev) >= PEER_LOG_DELTA || crossed_floor
        }
    }
}

/// Slot-aligned per-slot status heartbeat task.
///
/// Sleeps to each slot boundary (derived from `genesis_time_secs` and the
/// wall clock), then reads a fork-choice snapshot under a brief guard and emits:
/// the `Synced`/`Syncing` heartbeat line, a "Peer count changed" transition log
/// (debounced via [`peer_log_decision`]), and a latched "Low peer count"
/// warning. Exits when `shutdown_rx` changes.
///
/// While syncing, the line carries the catch-up speed in blocks/sec (from the
/// head-slot delta since the previous iteration) and, when a network tip is
/// available via [`NetworkCommandSender::highest_head_slot`], an ETA in seconds.
pub async fn run_status_heartbeat<E: BeaconSpec>(
    fork_choice: Arc<RwLock<FcStore<E>>>,
    peers_cmd: NetworkCommandSender<E>,
    genesis_time_secs: u64,
    target_peers: usize,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) where
    E::BeaconBlock: BeaconBlockView,
    E::BeaconState: pharos_types::BeaconStateView,
{
    let mut last_logged_peers: Option<usize> = None;
    let mut low_peer_warned = false;
    // Seed from the current head so the first Syncing tick reports a sane
    // blocks/sec instead of `head_slot / secs_per_slot` (a huge spike when
    // resuming mid-sync). Mirrors the per-iteration head-slot read below.
    let mut last_head_slot: u64 = {
        let fc = fork_choice.read();
        let head_root = get_head(&fc);
        fc.blocks
            .get(&head_root)
            .map(|b| b.slot().into())
            .unwrap_or(0)
    };

    let floor = low_peer_floor(target_peers);
    let slot_ms = E::SLOT_DURATION_MS;
    let secs_per_slot = (E::SLOT_DURATION_MS / 1000).max(1);

    loop {
        // Sleep until the next slot boundary so each line lands at slot start.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let elapsed_ms = now_ms.saturating_sub(genesis_time_secs * 1000);
        let sleep_ms = slot_ms - (elapsed_ms % slot_ms);

        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
        }

        // Read the fork-choice snapshot under a brief guard, then drop it before
        // any await (peer queries below cross await points).
        let (
            head_root_bytes,
            head_slot,
            current_slot,
            finalized_epoch,
            finalized_root,
            justified_epoch,
        ) = {
            let fc = fork_choice.read();
            let head_root = get_head(&fc);
            let head_slot: u64 = fc
                .blocks
                .get(&head_root)
                .map(|b| b.slot().into())
                .unwrap_or(0);
            let current_slot: u64 = get_current_slot(&fc).into();
            let head_root_bytes: [u8; 32] = head_root.into();
            let finalized_epoch: u64 = fc.finalized_checkpoint.epoch.into();
            let finalized_root: [u8; 32] = fc.finalized_checkpoint.root.into();
            let justified_epoch: u64 = fc.justified_checkpoint.epoch.into();
            (
                head_root_bytes,
                head_slot,
                current_slot,
                finalized_epoch,
                finalized_root,
                justified_epoch,
            )
        };

        let peer_count = peers_cmd.peers().await.len();
        let current_epoch = current_slot / E::SLOTS_PER_EPOCH;

        match sync_status(head_slot, current_slot) {
            SyncStatus::Synced => {
                info!(
                    slot = head_slot,
                    head = %short_root(head_root_bytes),
                    epoch = current_epoch,
                    finalized_epoch,
                    finalized_root = %short_root(finalized_root),
                    justified_epoch,
                    peers = peer_count,
                    "Synced"
                );
            }
            SyncStatus::Syncing { distance } => {
                let advanced = head_slot.saturating_sub(last_head_slot);
                let blocks_per_sec = (advanced as f64 / secs_per_slot as f64).max(0.0);
                let tip = peers_cmd.highest_head_slot().await;
                let eta = tip.and_then(|t| {
                    let remaining = t.saturating_sub(head_slot);
                    if blocks_per_sec > 0.0 {
                        Some((remaining as f64 / blocks_per_sec) as u64)
                    } else {
                        None
                    }
                });
                info!(
                    head_slot,
                    target_slot = tip,
                    epoch = current_epoch,
                    distance,
                    blocks_per_sec,
                    eta_secs = eta,
                    peers = peer_count,
                    "Syncing"
                );
            }
        }

        // Peer-count transition log (debounced).
        if peer_log_decision(last_logged_peers, peer_count, floor) {
            info!(peers = peer_count, prev = ?last_logged_peers, "Peer count changed");
            last_logged_peers = Some(peer_count);
        }

        // Low-peer warning latch: warn once on entering the low band, re-arm on
        // recovery.
        if peer_count < floor && !low_peer_warned {
            warn!(peers = peer_count, target = target_peers, "Low peer count");
            low_peer_warned = true;
        } else if peer_count >= floor {
            low_peer_warned = false;
        }

        last_head_slot = head_slot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_status_within_threshold_is_synced() {
        assert_eq!(sync_status(100, 100), SyncStatus::Synced);
        assert_eq!(sync_status(100, 101), SyncStatus::Synced);
    }

    #[test]
    fn sync_status_beyond_threshold_is_syncing() {
        assert_eq!(sync_status(100, 102), SyncStatus::Syncing { distance: 2 });
    }

    #[test]
    fn should_log_import_synced_always_logs() {
        let status = SyncStatus::Synced;
        assert!(should_log_import(&status, 31));
        assert!(should_log_import(&status, 32));
        assert!(should_log_import(&status, 0));
    }

    #[test]
    fn should_log_import_syncing_only_on_interval() {
        let status = SyncStatus::Syncing { distance: 1000 };
        assert!(!should_log_import(&status, 31));
        assert!(should_log_import(&status, 32));
    }

    #[test]
    fn short_root_format() {
        let root = [0xab_u8; 32];
        let s = short_root(root);
        assert_eq!(s.len(), 10);
        assert!(s.starts_with("0x"));
        assert_eq!(s, "0xabababab");
    }

    #[test]
    fn low_peer_floor_quarter_with_min_one() {
        assert_eq!(low_peer_floor(50), 12);
        assert_eq!(low_peer_floor(0), 1);
    }

    #[test]
    fn peer_log_decision_first_observation_logs() {
        assert!(peer_log_decision(None, 30, 12));
    }

    #[test]
    fn peer_log_decision_single_churn_suppressed() {
        assert!(!peer_log_decision(Some(30), 31, 12));
    }

    #[test]
    fn peer_log_decision_large_jump_logs() {
        assert!(peer_log_decision(Some(30), 33, 12));
    }

    #[test]
    fn peer_log_decision_floor_cross_logs() {
        assert!(peer_log_decision(Some(13), 11, 12));
    }
}
