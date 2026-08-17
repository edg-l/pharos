//! Custody adjustment loop (EIP-7594 PeerDAS validator custody).
//!
//! Per `specs/fulu/validator.md` "Validator custody". A node with validators
//! attached custodies a higher minimum of custody groups per slot, determined
//! by `get_validators_custody_requirement(state, validator_indices)` over the
//! latest finalized `BeaconState`. This loop runs off the head-watch (the same
//! signal the freezer uses, per `D-freezer-driver-off-head-watch`), recomputes
//! the requirement on each finalized state, and:
//!
//! - **On custody INCREASE:** immediately advertises the higher
//!   `custody_group_count` in the ENR `cgc` field, recomputes the custody-group
//!   column set via `get_custody_groups(node_id, cgc)` +
//!   `compute_columns_for_custody_group`, and subscribes to the covering
//!   `data_column_sidecar_{subnet}` gossip topics for the new set.
//! - **On custody DECREASE:** keeps the highest `cgc` seen (sticky-high) and
//!   does NOT unsubscribe or lower the ENR (the spec: the node SHOULD continue
//!   to custody, advertise, and serve the previous highest `cgc`; the highest
//!   `cgc` SHOULD persist across restarts).
//!
//! `last_updated_slot` is internal `cgc` bookkeeping (the slot at which `cgc` was
//! last raised) and does NOT feed the `Status` v2 `earliest_available_slot` field.
//! That value is computed in `HostImpl::earliest_available_slot` from the
//! `lowest_column_slot` watermark clamped to the spec serve window.
//!
//! ## VC → BN validator-indices ingress
//!
//! The lighter-touch option matching the existing BN↔VC pattern is reused: the
//! VC already reports the validator indices attached to it via the existing
//! `POST /eth/v1/validator/prepare_beacon_proposer` REST endpoint (each entry
//! carries a `validator_index`). The BN feeds those indices into the
//! `validator_indices_rx` `watch` channel this loop observes — no new REST
//! endpoint and no new VC→BN wire protocol are introduced.
//!
//! Per `D-cgc-enr-field` (sticky-high ENR `cgc`), `D-eip7594-da-checker-column-impl`
//! (custody column set), and `specs/fulu/validator.md` `get_validators_custody_requirement`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_network::discovery::enr::read_eth2_field;
use pharos_network::topics::{
    GossipTopic, GossipTopicKind, compute_subnet_for_data_column_sidecar,
};
use pharos_network::{DiscoveryHandle, NetworkCommand, NetworkCommandSender};
use pharos_stf::fulu::data_columns::{compute_columns_for_custody_group, get_custody_groups};
use pharos_types::{BeaconSpec, BeaconStateView, phase0::primitives::ValidatorIndex};

use crate::engine_driver::HeadChange;

/// Shared, restart-persistent custody state (`cgc` sticky-high + last-updated
/// slot + lowest-held-column watermark).
///
/// `HostImpl` clones this `Arc` so its `Host::custody_group_count` and
/// `Host::custody_columns` accessors read the live `cgc` the loop maintains, and
/// the network gossip/ENR surfaces reflect dynamic custody adjustment.
///
/// Three shared values:
/// - `cgc`: the sticky-high custody group count (backs `custody_group_count` /
///   `custody_columns` and the ENR `cgc` field).
/// - `last_updated_slot`: internal `cgc` bookkeeping (last raise slot); not wired
///   to any `Status` field.
/// - `lowest_column_slot`: the lowest block slot for which a data-column sidecar
///   is held; `HostImpl::earliest_available_slot` clamps it to the spec serve
///   window for the `Status` v2 `earliest_available_slot` field.
#[derive(Debug)]
pub struct CustodyState {
    /// The current (highest-seen) custody group count. Sticky-high: never
    /// lowered (`D-cgc-enr-field`). Seeded at `CUSTODY_REQUIREMENT` (the
    /// protocol minimum) at startup.
    cgc: AtomicU64,
    /// The slot at which `cgc` was last raised. `cgc` bookkeeping only:
    /// internal record of the last sticky-high raise (`specs/fulu/validator.md`).
    /// It does NOT back the `Status` v2 `earliest_available_slot` field — that is
    /// computed in `HostImpl` from `lowest_column_slot`.
    last_updated_slot: AtomicU64,
    /// The lowest block slot for which this node currently holds a persisted
    /// data-column sidecar. Lowered (`fetch_min`) by the column ingestion loop on
    /// each successful persist. `HostImpl::earliest_available_slot` clamps this to
    /// the spec serve window to produce the `Status` v2 `earliest_available_slot`.
    /// `u64::MAX` is the sentinel meaning "no columns held yet".
    lowest_column_slot: AtomicU64,
}

impl CustodyState {
    /// Construct with the protocol-minimum custody (`CUSTODY_REQUIREMENT`).
    ///
    /// A warm restart that loads a persisted higher `cgc` should pass that value
    /// as `initial_cgc` so the sticky-high invariant survives restarts.
    pub fn new(initial_cgc: u64) -> Self {
        Self {
            cgc: AtomicU64::new(initial_cgc),
            last_updated_slot: AtomicU64::new(0),
            lowest_column_slot: AtomicU64::new(u64::MAX),
        }
    }

    /// The current (highest-seen) custody group count.
    pub fn custody_group_count(&self) -> u64 {
        self.cgc.load(Ordering::Acquire)
    }

    /// The slot at which `cgc` was last raised (`cgc` bookkeeping only).
    pub fn last_updated_slot(&self) -> u64 {
        self.last_updated_slot.load(Ordering::Acquire)
    }

    /// The lowest block slot for which a data-column sidecar is held, or
    /// `u64::MAX` when no columns have been persisted yet.
    pub fn lowest_column_slot(&self) -> u64 {
        self.lowest_column_slot.load(Ordering::Acquire)
    }

    /// Record that a data-column sidecar for block `slot` was persisted, lowering
    /// the watermark when `slot` is below the current minimum (`fetch_min`).
    pub fn observe_column_slot(&self, slot: u64) {
        self.lowest_column_slot.fetch_min(slot, Ordering::AcqRel);
    }

    /// Raise `cgc` to `new_cgc` (sticky-high). Returns `true` when the value
    /// actually increased (the caller then advertises + re-subscribes); returns
    /// `false` when `new_cgc <= current` (decrease or no-op: keep highest).
    fn try_raise(&self, new_cgc: u64, at_slot: u64) -> bool {
        let current = self.cgc.load(Ordering::Acquire);
        if new_cgc > current {
            self.cgc.store(new_cgc, Ordering::Release);
            self.last_updated_slot.store(at_slot, Ordering::Release);
            true
        } else {
            false
        }
    }
}

/// `get_validators_custody_requirement(state, validator_indices)` per
/// `specs/fulu/validator.md`.
///
/// ```text
/// total_node_balance = sum(state.validators[i].effective_balance for i in validator_indices)
/// count = total_node_balance // BALANCE_PER_ADDITIONAL_CUSTODY_GROUP
/// return min(max(count, VALIDATOR_CUSTODY_REQUIREMENT), NUMBER_OF_CUSTODY_GROUPS)
/// ```
///
/// `state` is the latest finalized `BeaconState`. Validator indices outside the
/// registry contribute zero balance (defensive; the VC reports live indices).
pub fn get_validators_custody_requirement<E: BeaconSpec>(
    state: &E::BeaconState,
    validator_indices: &[ValidatorIndex],
) -> u64
where
    E::BeaconState: BeaconStateView,
{
    let total_node_balance: u64 = validator_indices
        .iter()
        .filter_map(|idx| state.validator(idx.0 as usize))
        .map(|v| v.effective_balance.0)
        .sum();
    let count = total_node_balance / E::BALANCE_PER_ADDITIONAL_CUSTODY_GROUP;
    count
        .max(E::VALIDATOR_CUSTODY_REQUIREMENT)
        .min(E::NUMBER_OF_CUSTODY_GROUPS)
}

/// Compute the de-duplicated, sorted column-index set for a custody group count.
///
/// `get_custody_groups(node_id, cgc)` then flatten each group to its columns via
/// `compute_columns_for_custody_group`. Identical to `HostImpl::custody_columns`
/// but parameterised on `cgc` (the loop drives the count dynamically).
pub fn custody_columns_for_cgc<E: BeaconSpec>(node_id: [u8; 32], cgc: u64) -> Vec<u64> {
    let mut columns: Vec<u64> = get_custody_groups::<E>(node_id, cgc)
        .into_iter()
        .flat_map(|group| compute_columns_for_custody_group::<E>(group))
        .collect();
    columns.sort_unstable();
    columns.dedup();
    columns
}

/// Apply a recomputed custody requirement to the shared state + network surface.
///
/// On a genuine increase (`try_raise` returns `true`): re-subscribe to the
/// covering `data_column_sidecar_{subnet}` topics for the new column set and
/// advertise the higher `cgc` in the ENR (preserving the current — possibly
/// BPO-rotated — fork digest, which is owned by the fork-migration loop). On a
/// decrease/no-op: nothing (sticky-high; keep serving the previous set).
///
/// Returns `true` when an increase was applied (for the unit test + logging).
pub async fn apply_custody_requirement<E: BeaconSpec>(
    custody_state: &CustodyState,
    new_cgc: u64,
    at_slot: u64,
    node_id: [u8; 32],
    cmd: &NetworkCommandSender<E>,
    discovery: &DiscoveryHandle,
) -> bool {
    if !custody_state.try_raise(new_cgc, at_slot) {
        // Decrease or no-op: keep the highest `cgc` (sticky-high), keep serving
        // the previous custody set, do NOT unsubscribe (`D-cgc-enr-field`).
        debug!(
            new_cgc,
            current = custody_state.custody_group_count(),
            "custody: requirement did not increase; keeping highest cgc (sticky)"
        );
        return false;
    }

    info!(
        new_cgc,
        at_slot, "custody: requirement increased; advertising higher cgc + re-subscribing"
    );

    // ── Re-subscribe to the covering column subnets for the new set ───────────
    // Read the current fork digest from the live ENR so subscriptions and the
    // ENR stay on the same (possibly BPO-rotated) digest.
    let fork_digest = match discovery.local_enr().await {
        Ok(enr) => match read_eth2_field(&enr) {
            Ok(fork_id) => fork_id.fork_digest,
            Err(e) => {
                warn!(%e, "custody: could not read eth2 fork digest; skipping re-subscribe");
                return true;
            }
        },
        Err(e) => {
            warn!(%e, "custody: could not read local ENR; skipping re-subscribe");
            return true;
        }
    };

    let columns = custody_columns_for_cgc::<E>(node_id, new_cgc);
    // De-duplicate subnets (multiple columns may map to one subnet).
    let mut subscribed = std::collections::HashSet::new();
    for column in columns {
        let subnet =
            compute_subnet_for_data_column_sidecar(column, E::DATA_COLUMN_SIDECAR_SUBNET_COUNT);
        if !subscribed.insert(subnet) {
            continue;
        }
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::DataColumnSidecar(subnet),
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if cmd
            .send(NetworkCommand::Subscribe {
                topic,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            warn!(subnet, "custody: subscribe command channel closed");
            break;
        }
        match reply_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(subnet, %e, "custody: data_column subnet subscribe failed"),
            Err(_) => warn!(subnet, "custody: subscribe reply dropped"),
        }
    }

    // ── Advertise the higher cgc in the ENR (preserve the current digest) ─────
    match discovery.local_enr().await {
        Ok(enr) => match read_eth2_field(&enr) {
            Ok(fork_id) => {
                if let Err(e) = discovery
                    .update_enr_eth2_fulu(fork_id, Some(new_cgc), None)
                    .await
                {
                    warn!(%e, "custody: ENR cgc update failed");
                }
            }
            Err(e) => warn!(%e, "custody: could not read eth2 fork id for ENR cgc update"),
        },
        Err(e) => warn!(%e, "custody: could not read local ENR for cgc update"),
    }

    true
}

/// Long-lived task: re-evaluate validator custody on each finalized state.
///
/// # Arguments
/// - `head_rx`: clone of the existing head-watch `watch::Sender<Option<HeadChange>>`
///   (no new channel; `D-freezer-driver-off-head-watch`).
/// - `fork_choice`: in-memory store — read for the finalized checkpoint + the
///   finalized `BeaconState`.
/// - `validator_indices_rx`: the VC's attached validator indices, fed from the
///   `prepare_beacon_proposer` REST handler (see module docs).
/// - `custody_state`: shared sticky-high `cgc` state read by `HostImpl`.
/// - `node_id`: the local discv5 node id (custody-group derivation input).
/// - `cmd`: network command sender (re-subscribe).
/// - `discovery`: discovery handle (ENR `cgc` update).
/// - `shutdown_rx`: set to `true` on Ctrl-C to break the loop.
#[allow(clippy::too_many_arguments)]
pub async fn run_custody_adjustment_loop<E: BeaconSpec>(
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    fork_choice: Arc<RwLock<FcStore<E>>>,
    validator_indices_rx: watch::Receiver<Vec<ValidatorIndex>>,
    custody_state: Arc<CustodyState>,
    node_id: [u8; 32],
    cmd: NetworkCommandSender<E>,
    discovery: DiscoveryHandle,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    E::BeaconState: BeaconStateView + Clone,
{
    info!(
        seed_cgc = custody_state.custody_group_count(),
        "custody adjustment loop started"
    );

    loop {
        tokio::select! {
            result = head_rx.changed() => {
                if result.is_err() {
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

        // Skip if no validators are attached (a non-validating node keeps the
        // protocol-minimum custody).
        let validator_indices = validator_indices_rx.borrow().clone();
        if validator_indices.is_empty() {
            continue;
        }

        // Read the latest finalized state from the fork-choice store.
        let (finalized_state, finalized_slot) = {
            let fc = fork_choice.read();
            let finalized_root = fc.finalized_checkpoint.root;
            let epoch_start = fc
                .finalized_checkpoint
                .epoch
                .0
                .saturating_mul(E::SLOTS_PER_EPOCH);
            match fc.block_states.get(&finalized_root) {
                Some(s) => (s.clone(), epoch_start),
                None => continue,
            }
        };

        let new_cgc = get_validators_custody_requirement::<E>(&finalized_state, &validator_indices);

        apply_custody_requirement::<E>(
            &custody_state,
            new_cgc,
            finalized_slot,
            node_id,
            &cmd,
            &discovery,
        )
        .await;
    }

    info!("custody adjustment loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::MainnetBeaconSpec;

    type E = MainnetBeaconSpec;

    /// `get_validators_custody_requirement` clamps below by
    /// `VALIDATOR_CUSTODY_REQUIREMENT` and above by `NUMBER_OF_CUSTODY_GROUPS`.
    /// With zero balance the result is the `VALIDATOR_CUSTODY_REQUIREMENT` floor.
    #[test]
    fn requirement_clamps_to_validator_floor() {
        // No state needed for the floor case: an empty index list sums to 0.
        // Build a default mainnet fulu state (no validators) → balance 0.
        let state = default_fulu_state();
        let req = get_validators_custody_requirement::<E>(&state, &[]);
        assert_eq!(req, E::VALIDATOR_CUSTODY_REQUIREMENT);
    }

    /// `CustodyState::try_raise` is sticky-high: an increase raises and reports
    /// `true`; a subsequent decrease keeps the highest value and reports `false`.
    #[test]
    fn custody_state_is_sticky_high() {
        let state = CustodyState::new(E::CUSTODY_REQUIREMENT);
        assert_eq!(state.custody_group_count(), E::CUSTODY_REQUIREMENT);

        // Increase from 4 → 16: raises, returns true, records the slot.
        assert!(state.try_raise(16, 100));
        assert_eq!(state.custody_group_count(), 16);
        assert_eq!(state.last_updated_slot(), 100);

        // Decrease to 8: sticky-high keeps 16, returns false, slot unchanged.
        assert!(!state.try_raise(8, 200));
        assert_eq!(state.custody_group_count(), 16);
        assert_eq!(state.last_updated_slot(), 100);

        // No-op (equal): returns false, no change.
        assert!(!state.try_raise(16, 300));
        assert_eq!(state.custody_group_count(), 16);
        assert_eq!(state.last_updated_slot(), 100);

        // Further increase: raises again, returns true, records the new slot.
        assert!(state.try_raise(32, 400));
        assert_eq!(state.custody_group_count(), 32);
        assert_eq!(state.last_updated_slot(), 400);
    }

    /// `observe_column_slot` is a monotonic minimum: the watermark starts at the
    /// `u64::MAX` "no columns held" sentinel and only ever moves downward.
    #[test]
    fn lowest_column_slot_is_monotonic_min() {
        let state = CustodyState::new(E::CUSTODY_REQUIREMENT);
        assert_eq!(state.lowest_column_slot(), u64::MAX);

        // First observation sets the watermark.
        state.observe_column_slot(100);
        assert_eq!(state.lowest_column_slot(), 100);

        // A lower slot lowers the watermark.
        state.observe_column_slot(50);
        assert_eq!(state.lowest_column_slot(), 50);

        // A higher slot does not raise it.
        state.observe_column_slot(80);
        assert_eq!(state.lowest_column_slot(), 50);
    }

    /// `custody_columns_for_cgc` grows the column set as `cgc` increases (more
    /// custody groups → more covered columns). At `cgc == NUMBER_OF_CUSTODY_GROUPS`
    /// the node custodies every column.
    #[test]
    fn custody_columns_grow_with_cgc() {
        let node_id = {
            let mut id = [0u8; 32];
            id[31] = 0x42;
            id
        };
        let cols_min = custody_columns_for_cgc::<E>(node_id, E::CUSTODY_REQUIREMENT);
        let cols_high = custody_columns_for_cgc::<E>(node_id, 16);
        assert!(
            cols_high.len() >= cols_min.len(),
            "raising cgc must not shrink the custody column set"
        );

        let cols_all = custody_columns_for_cgc::<E>(node_id, E::NUMBER_OF_CUSTODY_GROUPS);
        assert_eq!(cols_all.len(), E::NUMBER_OF_COLUMNS as usize);
    }

    /// Build a default mainnet fulu `BeaconState` for the requirement test.
    fn default_fulu_state() -> <E as BeaconSpec>::BeaconState {
        use pharos_types::state::BeaconState;
        BeaconState::Fulu(<E as BeaconSpec>::FuluBeaconState::default())
    }
}
