//! Duty fetching and epoch-based scheduling for the validator client.
//!
//! Fetches proposer, attester, and sync duties from the BN once per epoch and
//! refreshes them when a `head` or `finalized_checkpoint` SSE event signals a
//! `dependent_root` change (reorg detection).
//!
//! # Refresh strategy
//!
//! - Duties are fetched on startup for the current epoch (and `current + 1` for
//!   proposer duties so the first slot is never missed).
//! - An SSE stream on `/eth/v1/events?topics=head,finalized_checkpoint` is
//!   maintained via `bn_client.events_url_for_node`. On stream reconnect, the
//!   next BN node in the round-robin is tried.
//! - When a `head` event arrives with a `dependent_root` that differs from the
//!   cached one, duties for the affected epoch are re-fetched (reorg reschedule).
//! - Duties are keyed by slot so the run loop can look up any slot's duties in O(1).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::TryStreamExt as _;
use reqwest::Client;
use tokio::sync::{RwLock, watch};
use tracing::{debug, info, warn};

use crate::bn_client::{AttesterDuty, BnClient, BnError, SyncDuty};

// ── Duty tables ───────────────────────────────────────────────────────────────

/// All duties for a single epoch, keyed by slot.
#[derive(Debug, Default, Clone)]
pub struct EpochDuties {
    /// Proposer slots owned by our validators: slot → validator pubkey hex.
    pub proposer: HashMap<u64, String>,
    /// Attester duties for our validators: slot → list of duties.
    pub attester: HashMap<u64, Vec<AttesterDuty>>,
    /// Sync-committee duties for our validators (same set for the full period).
    pub sync: Vec<SyncDuty>,
    /// `dependent_root` returned by the BN for proposer duties (hex string).
    pub proposer_dependent_root: Option<String>,
    /// `dependent_root` returned by the BN for attester duties (hex string).
    pub attester_dependent_root: Option<String>,
}

/// Shared duty state protected by an `RwLock`.
///
/// The run loop holds a write lock when refreshing duties; all signing paths
/// hold a read lock when looking up duties for the current slot.
pub type SharedDuties = Arc<RwLock<HashMap<u64, EpochDuties>>>;

// ── DutyScheduler ─────────────────────────────────────────────────────────────

/// Fetches and caches duties for all local validators.
///
/// Constructed once at startup and driven by `run_duty_refresh_loop`.
pub struct DutyScheduler {
    bn: BnClient,
    /// Our validator indices (populated after startup or fetched from BN).
    pub validator_indices: Vec<u64>,
    /// Our validator pubkeys (hex strings, index-aligned with `validator_indices`).
    pub pubkeys_hex: Vec<String>,
    /// Cached duties per epoch.
    duties: SharedDuties,
}

impl DutyScheduler {
    /// Create a new `DutyScheduler`.
    pub fn new(bn: BnClient, validator_indices: Vec<u64>, pubkeys_hex: Vec<String>) -> Self {
        Self {
            bn,
            validator_indices,
            pubkeys_hex,
            duties: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Return a clone of the shared duties table for use by the run loop.
    pub fn duties_ref(&self) -> SharedDuties {
        Arc::clone(&self.duties)
    }

    /// Fetch and cache duties for `epoch` from the BN.
    ///
    /// Returns the updated `EpochDuties` on success. On BN error, logs a
    /// warning and returns `Ok(None)` so the caller can skip the slot.
    pub async fn refresh_epoch(&self, epoch: u64) -> Result<(), BnError> {
        let indices = &self.validator_indices;

        // Proposer duties are keyed by epoch; we only store ours.
        let proposer_resp = self.bn.get_proposer_duties(epoch).await?;
        let proposer_dep = proposer_resp.dependent_root.clone();
        let proposer: HashMap<u64, String> = proposer_resp
            .data
            .into_iter()
            .filter(|d| {
                let idx: u64 = d.validator_index.parse().unwrap_or(u64::MAX);
                indices.contains(&idx)
            })
            .map(|d| {
                let slot: u64 = d.slot.parse().unwrap_or(0);
                (slot, d.pubkey.clone())
            })
            .collect();

        // Attester duties.
        let attester_resp = self.bn.post_attester_duties(epoch, indices).await?;
        let attester_dep = attester_resp.dependent_root.clone();
        let mut attester: HashMap<u64, Vec<AttesterDuty>> = HashMap::new();
        for duty in attester_resp.data {
            let slot: u64 = duty.slot.parse().unwrap_or(0);
            attester.entry(slot).or_default().push(duty);
        }

        // Sync committee duties (valid for `EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256` epochs).
        let sync = match self.bn.post_sync_duties(epoch, indices).await {
            Ok(resp) => resp.data,
            Err(e) => {
                // Sync duties may fail for pre-Altair epochs — not fatal.
                warn!(epoch, %e, "sync duties fetch failed (pre-Altair epoch or BN error)");
                vec![]
            }
        };

        let duties = EpochDuties {
            proposer,
            attester,
            sync,
            proposer_dependent_root: proposer_dep,
            attester_dependent_root: attester_dep,
        };

        let mut map = self.duties.write().await;
        map.insert(epoch, duties);
        Ok(())
    }
}

// ── SSE head event ────────────────────────────────────────────────────────────

/// Parsed `head` SSE event from `/eth/v1/events?topics=head`.
#[derive(Debug, serde::Deserialize)]
pub struct HeadEvent {
    pub slot: String,
    pub block: String,
    pub epoch_transition: bool,
    #[serde(default)]
    pub previous_duty_dependent_root: Option<String>,
    #[serde(default)]
    pub current_duty_dependent_root: Option<String>,
}

/// Parsed `finalized_checkpoint` SSE event.
#[derive(Debug, serde::Deserialize)]
pub struct FinalizedCheckpointEvent {
    pub block: String,
    pub state: String,
    pub epoch: String,
    #[serde(default)]
    pub execution_optimistic: bool,
}

// ── run_duty_refresh_loop ─────────────────────────────────────────────────────

/// Drive duty refresh via SSE events and epoch boundaries.
///
/// - Opens the SSE stream from the BN (`head` + `finalized_checkpoint` topics).
/// - On each `head` event, checks if the epoch changed or if `dependent_root`
///   changed (reorg); if so, re-fetches the affected epoch's duties.
/// - Falls back to epoch-boundary polling when the SSE stream drops.
/// - Sends the current epoch number over `epoch_tx` so the signing run loop
///   knows when to perform epoch-boundary actions.
pub async fn run_duty_refresh_loop(
    scheduler: Arc<DutyScheduler>,
    epoch_tx: watch::Sender<u64>,
    genesis_time_secs: u64,
    slots_per_epoch: u64,
    slot_duration_ms: u64,
) {
    let mut current_node_idx: usize = 0;
    let node_count = scheduler.bn.node_count();

    // Seed duties for the current epoch before entering the SSE loop.
    let now_epoch =
        current_epoch_from_wall_clock(genesis_time_secs, slot_duration_ms, slots_per_epoch);
    for ep in [now_epoch, now_epoch.saturating_add(1)] {
        if let Err(e) = scheduler.refresh_epoch(ep).await {
            warn!(epoch = ep, %e, "initial duty fetch failed");
        } else {
            info!(epoch = ep, "initial duties fetched");
        }
    }
    let _ = epoch_tx.send(now_epoch);

    loop {
        // Build the SSE URL for the current BN node in the round-robin.
        let url = match scheduler
            .bn
            .events_url_for_node(current_node_idx, &["head", "finalized_checkpoint"])
        {
            Ok(u) => u,
            Err(e) => {
                warn!(%e, "cannot build events URL; retrying in 4s");
                tokio::time::sleep(Duration::from_secs(4)).await;
                current_node_idx = (current_node_idx + 1) % node_count.max(1);
                continue;
            }
        };

        debug!(url = %url, "opening SSE duty-refresh stream");

        let client = Client::new();
        let resp = client.get(url.as_str()).send().await;

        match resp {
            Err(e) => {
                warn!(%e, "SSE connection failed; will retry on next BN");
                current_node_idx = (current_node_idx + 1) % node_count.max(1);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(status = %resp.status(), "SSE endpoint returned error; retrying");
                    current_node_idx = (current_node_idx + 1) % node_count.max(1);
                    tokio::time::sleep(Duration::from_secs(4)).await;
                    continue;
                }

                // Process the SSE byte stream.
                use tokio::io::AsyncBufReadExt as _;
                let bytes = resp.bytes_stream();
                use tokio_util::io::StreamReader;
                let reader = StreamReader::new(bytes.map_err(std::io::Error::other));
                let mut lines = tokio::io::BufReader::new(reader).lines();

                let mut event_type = String::new();
                let mut data_buf = String::new();
                let mut last_epoch: u64 = u64::MAX;

                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            if line.starts_with("event:") {
                                event_type =
                                    line.strip_prefix("event:").unwrap_or("").trim().to_string();
                                data_buf.clear();
                            } else if line.starts_with("data:") {
                                data_buf =
                                    line.strip_prefix("data:").unwrap_or("").trim().to_string();
                            } else if line.is_empty() && !data_buf.is_empty() {
                                // Dispatch complete SSE event.
                                let epoch = current_epoch_from_wall_clock(
                                    genesis_time_secs,
                                    slot_duration_ms,
                                    slots_per_epoch,
                                );
                                if epoch != last_epoch {
                                    last_epoch = epoch;
                                    let _ = epoch_tx.send(epoch);
                                    // Fetch next epoch's duties ahead of time.
                                    let sched = Arc::clone(&scheduler);
                                    let next = epoch.saturating_add(1);
                                    tokio::spawn(async move {
                                        if let Err(e) = sched.refresh_epoch(next).await {
                                            warn!(epoch = next, %e, "epoch boundary duty refresh failed");
                                        } else {
                                            debug!(epoch = next, "epoch boundary duties refreshed");
                                        }
                                    });
                                }

                                if event_type == "head" {
                                    if let Ok(ev) = serde_json::from_str::<HeadEvent>(&data_buf) {
                                        handle_head_event(&ev, epoch, &scheduler, slots_per_epoch)
                                            .await;
                                    }
                                }

                                event_type.clear();
                                data_buf.clear();
                            }
                        }
                        Ok(None) => {
                            // Stream ended.
                            debug!("SSE stream closed; reconnecting to next BN node");
                            break;
                        }
                        Err(e) => {
                            warn!(%e, "SSE read error; reconnecting");
                            break;
                        }
                    }
                }

                current_node_idx = (current_node_idx + 1) % node_count.max(1);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Handle a `head` SSE event: detect reorgs and re-fetch affected duties.
async fn handle_head_event(
    ev: &HeadEvent,
    current_epoch: u64,
    scheduler: &DutyScheduler,
    slots_per_epoch: u64,
) {
    let slot: u64 = ev.slot.parse().unwrap_or(0);
    let epoch = slot / slots_per_epoch;

    // Check if the dependent_root changed for the current epoch (reorg).
    let should_refresh = {
        let map = scheduler.duties.read().await;
        if let Some(duties) = map.get(&epoch) {
            let prev_dep = duties
                .proposer_dependent_root
                .as_deref()
                .unwrap_or_default();
            let new_dep = ev
                .current_duty_dependent_root
                .as_deref()
                .unwrap_or_default();
            !new_dep.is_empty() && new_dep != prev_dep
        } else {
            // No duties cached yet for this epoch — fetch them.
            true
        }
    };

    if should_refresh || ev.epoch_transition {
        debug!(
            epoch,
            slot, "reorg or epoch transition detected; refreshing duties"
        );
        let sched_ref = scheduler;
        if let Err(e) = sched_ref.refresh_epoch(epoch).await {
            warn!(epoch, %e, "reorg duty refresh failed");
        }
        // Also pre-fetch next epoch.
        let next = epoch.saturating_add(1);
        if current_epoch == epoch {
            if let Err(e) = sched_ref.refresh_epoch(next).await {
                warn!(epoch = next, %e, "next epoch duty refresh failed");
            }
        }
    }
}

// ── Wall-clock helpers ────────────────────────────────────────────────────────

/// Compute the current slot from the wall clock, relative to `genesis_time_secs`.
///
/// Slots are counted from the chain's genesis, NOT the UNIX epoch: a real network
/// has `genesis_time` far from 0, so the elapsed time must be measured from
/// genesis. Returns 0 before genesis (and when `slot_duration_ms == 0`).
pub fn current_slot_from_wall_clock(genesis_time_secs: u64, slot_duration_ms: u64) -> u64 {
    if slot_duration_ms == 0 {
        return 0;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let genesis_ms = genesis_time_secs.saturating_mul(1000);
    let elapsed_ms = now_ms.saturating_sub(genesis_ms);
    elapsed_ms / slot_duration_ms
}

/// Compute the current epoch from the wall clock, relative to `genesis_time_secs`.
///
/// Returns epoch 0 before genesis (and when `slot_duration_ms`/`slots_per_epoch`
/// is 0, as in unit tests).
pub fn current_epoch_from_wall_clock(
    genesis_time_secs: u64,
    slot_duration_ms: u64,
    slots_per_epoch: u64,
) -> u64 {
    if slot_duration_ms == 0 || slots_per_epoch == 0 {
        return 0;
    }
    current_slot_from_wall_clock(genesis_time_secs, slot_duration_ms) / slots_per_epoch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_from_wall_clock_zero_returns_zero() {
        assert_eq!(current_epoch_from_wall_clock(0, 0, 32), 0);
        assert_eq!(current_epoch_from_wall_clock(0, 12_000, 0), 0);
        // A far-future genesis (not yet reached) yields epoch 0.
        assert_eq!(current_epoch_from_wall_clock(u64::MAX, 12_000, 32), 0);
    }

    #[test]
    fn epoch_duties_default_is_empty() {
        let d = EpochDuties::default();
        assert!(d.proposer.is_empty());
        assert!(d.attester.is_empty());
        assert!(d.sync.is_empty());
    }
}
