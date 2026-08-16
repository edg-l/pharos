//! Weak-subjectivity period math and checkpoint-freshness check.
//!
//! Spec source: `specs/phase0/weak-subjectivity.md` §
//! `compute_weak_subjectivity_period` (lines 94–120) and
//! `is_within_weak_subjectivity_period` (lines 181–191).
//!
//! A checkpoint older than the weak-subjectivity (WS) period before the current
//! slot is unsafe to sync from. Lives next to `EthSpec` (in `pharos-types`, no
//! internal deps beyond `pharos-utils`) so both the node and other callers can
//! reach it without depending on `pharos-stf`. The state-deriving inputs
//! (active validator count, total active balance) are computed by the caller
//! from a `BeaconStateView` and passed in as scalars (the spec function takes a
//! `BeaconState`; `get_validator_churn_limit` and `get_total_active_balance`
//! are pure functions of it, so passing the precomputed scalars is equivalent).

use crate::EthSpec;
use crate::phase0::misc::Validator;
use crate::phase0::primitives::Epoch;

/// `ETH_TO_GWEI` — Gwei per Ether. Spec module constant (`specs/phase0/weak-subjectivity.md`).
const ETH_TO_GWEI: u64 = 1_000_000_000;

/// `SAFETY_DECAY` — `D` in the spec formula (`specs/phase0/weak-subjectivity.md:107`).
const SAFETY_DECAY: u64 = 10;

/// Compute the weak-subjectivity period (in epochs) for a state, given its
/// active validator count and total active balance.
///
/// Implements `compute_weak_subjectivity_period`
/// (`specs/phase0/weak-subjectivity.md:96-118`) exactly, with integer division
/// (`//`) matching the Python reference. `active_validator_count` is `N`;
/// `total_active_balance_gwei` is `get_total_active_balance(state)`.
///
/// Validated against the spec reference table (`weak-subjectivity.md:122-136`):
/// `N=32768, t=28 ETH → 504`; `N=262144, t=32 ETH → 3532` (see unit tests).
///
/// # Panics
///
/// Panics if `active_validator_count == 0` (a state with no active validators
/// is not a valid sync anchor; the spec divides by `N`).
pub fn compute_weak_subjectivity_period<E: EthSpec>(
    active_validator_count: u64,
    total_active_balance_gwei: u64,
) -> u64 {
    assert!(
        active_validator_count > 0,
        "compute_weak_subjectivity_period requires at least one active validator"
    );

    let n = active_validator_count;
    // t = get_total_active_balance(state) // N // ETH_TO_GWEI  (avg balance in Ether)
    let t = total_active_balance_gwei / n / ETH_TO_GWEI;
    // T = MAX_EFFECTIVE_BALANCE // ETH_TO_GWEI  (= 32 Ether on both presets)
    let t_max = E::MAX_EFFECTIVE_BALANCE / ETH_TO_GWEI;
    // delta = get_validator_churn_limit(state)
    //       = max(MIN_PER_EPOCH_CHURN_LIMIT, N // CHURN_LIMIT_QUOTIENT)
    let delta = E::MIN_PER_EPOCH_CHURN_LIMIT.max(n / E::CHURN_LIMIT_QUOTIENT);
    // Delta = MAX_DEPOSITS * SLOTS_PER_EPOCH
    let delta_cap = E::MAX_DEPOSITS * E::SLOTS_PER_EPOCH;
    let d = SAFETY_DECAY;

    let mut ws_period = E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

    if t_max * (200 + 3 * d) < t * (200 + 12 * d) {
        let epochs_for_validator_set_churn =
            n * (t * (200 + 12 * d) - t_max * (200 + 3 * d)) / (600 * delta * (2 * t + t_max));
        let epochs_for_balance_top_ups = n * (200 + 3 * d) / (600 * delta_cap);
        ws_period += epochs_for_validator_set_churn.max(epochs_for_balance_top_ups);
    } else {
        ws_period += 3 * n * d * t / (200 * delta_cap * (t_max - t));
    }

    ws_period
}

/// Return `true` if the WS checkpoint is still within the weak-subjectivity
/// period at `current_slot`.
///
/// Implements `is_within_weak_subjectivity_period`
/// (`specs/phase0/weak-subjectivity.md:183-191`):
/// `current_epoch <= ws_state_epoch + ws_period`, where `ws_state_epoch =
/// compute_epoch_at_slot(ws_state.slot)`. The caller passes the WS-state slot
/// (the anchor state slot) and the state-derived `active_validator_count` /
/// `total_active_balance_gwei` used to compute the period.
///
/// The spec's two `assert`s (`get_block_root(ws_state, ws_checkpoint.epoch) ==
/// ws_checkpoint.root` and `compute_epoch_at_slot(ws_state.slot) ==
/// ws_checkpoint.epoch`) are enforced upstream: the checkpoint-sync fetch
/// already binds the anchor block to the anchor state, and the anchor epoch is
/// derived from `ws_state.slot`, so they hold by construction here.
pub fn is_within_weak_subjectivity_period<E: EthSpec>(
    ws_state_slot: u64,
    current_slot: u64,
    active_validator_count: u64,
    total_active_balance_gwei: u64,
) -> bool {
    let ws_period =
        compute_weak_subjectivity_period::<E>(active_validator_count, total_active_balance_gwei);
    let ws_state_epoch = ws_state_slot / E::SLOTS_PER_EPOCH;
    let current_epoch = current_slot / E::SLOTS_PER_EPOCH;
    current_epoch <= ws_state_epoch + ws_period
}

/// Sum the active-validator stats `(active_count, total_active_balance_gwei)`
/// for a validator iterator at `epoch`.
///
/// `is_active_validator(v, epoch)` is `v.activation_epoch <= epoch <
/// v.exit_epoch` (`specs/phase0/beacon-chain.md:699-703`);
/// `get_total_active_balance` sums `effective_balance` over the active set
/// (`specs/phase0/beacon-chain.md`). Lives here (not in `pharos-stf`) so the
/// `pharos-types`-resident WS math can be driven directly from a state view
/// without an `stf` dependency edge.
pub fn active_validator_stats<'a>(
    validators: impl Iterator<Item = &'a Validator>,
    epoch: Epoch,
) -> (u64, u64) {
    let mut count: u64 = 0;
    let mut total_balance: u64 = 0;
    for v in validators {
        if v.activation_epoch.0 <= epoch.0 && epoch.0 < v.exit_epoch.0 {
            count += 1;
            total_balance += v.effective_balance.0;
        }
    }
    (count, total_balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MainnetEthSpec, MinimalEthSpec};

    /// `t` Ether per validator → total active balance in Gwei for `n` validators.
    fn total_balance_gwei(n: u64, t_eth: u64) -> u64 {
        // The spec computes t = total // N // 1e9; choose total so that the
        // floor divisions recover exactly `t_eth`.
        n * t_eth * ETH_TO_GWEI
    }

    // ── Spec reference table (`weak-subjectivity.md:122-136`) ─────────────────
    //
    // | D | Avg Bal (ETH) | Val Count | WS Period (Epochs) |
    // | 10 | 28 | 32768  | 504  |
    // | 10 | 28 | 65536  | 752  |
    // | 10 | 28 | 131072 | 1248 |
    // | 10 | 28 | 262144 | 2241 |
    // | 10 | 32 | 32768  | 665  |
    // | 10 | 32 | 262144 | 3532 |
    //
    // Mainnet preset (MIN_VALIDATOR_WITHDRAWABILITY_DELAY=256, MIN_PER_EPOCH_
    // CHURN_LIMIT=4, CHURN_LIMIT_QUOTIENT=65536, MAX_DEPOSITS=16, SLOTS_PER_
    // EPOCH=32, MAX_EFFECTIVE_BALANCE=32e9).

    #[test]
    fn ws_period_matches_spec_reference_table_mainnet() {
        let cases = [
            (32768u64, 28u64, 504u64),
            (65536, 28, 752),
            (131072, 28, 1248),
            (262144, 28, 2241),
            (32768, 32, 665),
            (65536, 32, 1075),
            (131072, 32, 1894),
            (262144, 32, 3532),
        ];
        for (n, t_eth, expected) in cases {
            let total = total_balance_gwei(n, t_eth);
            let got = compute_weak_subjectivity_period::<MainnetEthSpec>(n, total);
            assert_eq!(
                got, expected,
                "mainnet WS period mismatch for N={n}, t={t_eth} ETH: got {got}, want {expected}"
            );
        }
    }

    #[test]
    fn ws_period_small_validator_set() {
        // A tiny validator set with average balance == MAX_EFFECTIVE_BALANCE
        // (32 ETH). `T * 230 < t * 320` is false when t == T (`32*230=7360`,
        // `32*320=10240` → 7360 < 10240 is TRUE), so the churn branch is used.
        // With N well below CHURN_LIMIT_QUOTIENT the churn term floors to 0, so
        // the period equals MIN_VALIDATOR_WITHDRAWABILITY_DELAY (256) exactly.
        // For N=64, t=32 both the churn and top-up terms floor to 0 (verified by
        // hand: N*(t*320 - T*230)//(600*delta*(2t+T)) = 64*2880//(600*4*96) = 0).
        let n = 64u64;
        let total = total_balance_gwei(n, 32);
        let got = compute_weak_subjectivity_period::<MainnetEthSpec>(n, total);
        assert_eq!(
            got,
            MainnetEthSpec::MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
            "tiny set should floor to MIN_VALIDATOR_WITHDRAWABILITY_DELAY"
        );
    }

    #[test]
    fn ws_period_large_validator_set() {
        // Period must grow monotonically with validator count at fixed avg
        // balance (more validators → longer safe window).
        let t_eth = 32u64;
        let p1 = compute_weak_subjectivity_period::<MainnetEthSpec>(
            65536,
            total_balance_gwei(65536, t_eth),
        );
        let p2 = compute_weak_subjectivity_period::<MainnetEthSpec>(
            131072,
            total_balance_gwei(131072, t_eth),
        );
        assert!(
            p2 > p1,
            "WS period must grow with validator count: {p1} -> {p2}"
        );
    }

    #[test]
    fn ws_period_minimal_preset_floor() {
        // Minimal preset: MIN_VALIDATOR_WITHDRAWABILITY_DELAY=256,
        // MIN_PER_EPOCH_CHURN_LIMIT=2, CHURN_LIMIT_QUOTIENT=32,
        // SLOTS_PER_EPOCH=8, MAX_DEPOSITS=16, MAX_EFFECTIVE_BALANCE=32e9.
        // A small set at avg balance well below 32 ETH uses the deficit branch
        // and must still be >= the withdrawability floor.
        let n = 64u64;
        let total = total_balance_gwei(n, 20);
        let got = compute_weak_subjectivity_period::<MinimalEthSpec>(n, total);
        assert!(
            got >= MinimalEthSpec::MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
            "minimal WS period must be >= MIN_VALIDATOR_WITHDRAWABILITY_DELAY, got {got}"
        );
    }

    #[test]
    fn within_period_accepts_fresh_checkpoint() {
        // Anchor at epoch 100 (slot 3200 on mainnet), current slot just one
        // epoch later → well within any positive WS period.
        let n = 262144u64;
        let total = total_balance_gwei(n, 32);
        let ws_state_slot = 100 * MainnetEthSpec::SLOTS_PER_EPOCH;
        let current_slot = 101 * MainnetEthSpec::SLOTS_PER_EPOCH;
        assert!(is_within_weak_subjectivity_period::<MainnetEthSpec>(
            ws_state_slot,
            current_slot,
            n,
            total
        ));
    }

    #[test]
    fn within_period_rejects_stale_checkpoint() {
        // N=262144, t=32 → period 3532 epochs. Anchor at epoch 100; current at
        // epoch 100 + 3532 + 1 = 3633 → past the period → not within.
        let n = 262144u64;
        let total = total_balance_gwei(n, 32);
        let period = compute_weak_subjectivity_period::<MainnetEthSpec>(n, total);
        assert_eq!(period, 3532);
        let ws_epoch = 100u64;
        let ws_state_slot = ws_epoch * MainnetEthSpec::SLOTS_PER_EPOCH;
        let current_slot = (ws_epoch + period + 1) * MainnetEthSpec::SLOTS_PER_EPOCH;
        assert!(!is_within_weak_subjectivity_period::<MainnetEthSpec>(
            ws_state_slot,
            current_slot,
            n,
            total
        ));
        // Exactly at the boundary (current_epoch == ws_epoch + period) is within.
        let boundary_slot = (ws_epoch + period) * MainnetEthSpec::SLOTS_PER_EPOCH;
        assert!(is_within_weak_subjectivity_period::<MainnetEthSpec>(
            ws_state_slot,
            boundary_slot,
            n,
            total
        ));
    }

    #[test]
    fn active_validator_stats_counts_active_set() {
        use crate::phase0::primitives::Epoch;
        use pharos_utils::Gwei;

        let mut validators = Vec::new();
        // Active at epoch 50: activation <= 50 < exit.
        let mut active = Validator {
            activation_epoch: Epoch(10),
            exit_epoch: Epoch(100),
            effective_balance: Gwei(32_000_000_000),
            ..Validator::default()
        };
        active.cached_root = std::sync::OnceLock::new();
        validators.push(active);
        // Not yet activated.
        validators.push(Validator {
            activation_epoch: Epoch(60),
            exit_epoch: Epoch(100),
            effective_balance: Gwei(32_000_000_000),
            ..Validator::default()
        });
        // Already exited.
        validators.push(Validator {
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(40),
            effective_balance: Gwei(32_000_000_000),
            ..Validator::default()
        });

        let (count, total) = active_validator_stats(validators.iter(), Epoch(50));
        assert_eq!(count, 1, "only one validator active at epoch 50");
        assert_eq!(total, 32_000_000_000);
    }
}
