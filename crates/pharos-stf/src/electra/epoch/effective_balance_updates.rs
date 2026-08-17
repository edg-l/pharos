//! `process_effective_balance_updates` for Electra (EIP-7251).
//!
//! Per `specs/electra/beacon-chain.md:1090-1107`.
//!
//! Identical to phase0/altair hysteresis EXCEPT the ceiling is the
//! compounding-aware `get_max_effective_balance(validator)` instead of the flat
//! `MAX_EFFECTIVE_BALANCE`: `MAX_EFFECTIVE_BALANCE_ELECTRA` for `0x02`
//! (compounding) validators, `MIN_ACTIVATION_BALANCE` otherwise.

use rayon::prelude::*;

use pharos_ssz::SszSequence;
use pharos_types::{BeaconSpec, electra::BeaconState};
use pharos_utils::Gwei;

use crate::electra::helpers::get_max_effective_balance;
use crate::error::EpochProcessingError;

/// `process_effective_balance_updates` per `specs/electra/beacon-chain.md:1090-1107`.
#[allow(clippy::type_complexity)]
pub fn process_effective_balance_updates<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: BeaconSpec,
>(
    state: &mut BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
) -> Result<(), EpochProcessingError> {
    let hysteresis_increment = E::EFFECTIVE_BALANCE_INCREMENT / E::HYSTERESIS_QUOTIENT;
    let downward_threshold = hysteresis_increment * E::HYSTERESIS_DOWNWARD_MULTIPLIER;
    let upward_threshold = hysteresis_increment * E::HYSTERESIS_UPWARD_MULTIPLIER;

    let n = state.validators.len();

    // Snapshot (balance, eff_balance, max_effective_balance) for parallel
    // computation. The ceiling is per-validator (compounding-aware) in Electra.
    let snapshot: Vec<(u64, u64, u64)> = (0..n)
        .map(|i| {
            let balance = state.balances.get(i).copied().unwrap_or(Gwei(0)).0;
            let (eff_bal, max_eff) = state
                .validators
                .get(i)
                .map(|v| (v.effective_balance.0, get_max_effective_balance::<E>(v).0))
                .unwrap_or((0, 0));
            (balance, eff_bal, max_eff)
        })
        .collect();

    // Compute new effective balances in parallel.
    let updates: Vec<Option<u64>> = snapshot
        .into_par_iter()
        .map(|(balance, eff_bal, max_eff)| {
            if balance + downward_threshold < eff_bal || eff_bal + upward_threshold < balance {
                let new_eff = (balance - balance % E::EFFECTIVE_BALANCE_INCREMENT).min(max_eff);
                Some(new_eff)
            } else {
                None
            }
        })
        .collect();

    // Apply sequentially.
    for (i, maybe_new) in updates.into_iter().enumerate() {
        if let Some(new_eff) = maybe_new {
            let mut v = state
                .validators
                .get(i)
                .ok_or(EpochProcessingError::ValidatorIndexOutOfRange { index: i })?
                .clone();
            v.effective_balance = Gwei(new_eff);
            v.invalidate_cache();
            state.validators = state
                .validators
                .with_set(i, v)
                .map_err(EpochProcessingError::Ssz)?;
        }
    }

    Ok(())
}
