//! `process_effective_balance_updates` for Altair.
//!
//! Identical to phase0; operates on the concrete altair `BeaconState`.
//! Uses `rayon` for parallel delta computation per D5.
//!
//! spec: specs/phase0/beacon-chain.md:1814-1831 (unchanged in Altair)

use rayon::prelude::*;

use pharos_ssz::SszSequence;
use pharos_types::{EthSpec, altair::BeaconState};
use pharos_utils::Gwei;

use crate::error::EpochProcessingError;

/// `process_effective_balance_updates` per `specs/phase0/beacon-chain.md:1814-1831`.
///
/// Altair: identical to phase0. Updates effective balances with hysteresis
/// to prevent thrashing. Uses `rayon` for the parallel read pass.
pub fn process_effective_balance_updates<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
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
    >,
) -> Result<(), EpochProcessingError>
where
    E: EthSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let hysteresis_increment = E::EFFECTIVE_BALANCE_INCREMENT / E::HYSTERESIS_QUOTIENT;
    let downward_threshold = hysteresis_increment * E::HYSTERESIS_DOWNWARD_MULTIPLIER;
    let upward_threshold = hysteresis_increment * E::HYSTERESIS_UPWARD_MULTIPLIER;

    let n = state.validators.len();

    // Snapshot (balance, eff_balance) pairs for parallel computation.
    let snapshot: Vec<(u64, u64)> = (0..n)
        .map(|i| {
            let balance = state
                .balances
                .as_slice()
                .get(i)
                .copied()
                .unwrap_or(Gwei(0))
                .0;
            let eff_bal = state
                .validators
                .as_slice()
                .get(i)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0);
            (balance, eff_bal)
        })
        .collect();

    // Compute new effective balances in parallel.
    let updates: Vec<Option<u64>> = snapshot
        .into_par_iter()
        .map(|(balance, eff_bal)| {
            if balance + downward_threshold < eff_bal || eff_bal + upward_threshold < balance {
                let new_eff = (balance - balance % E::EFFECTIVE_BALANCE_INCREMENT)
                    .min(E::MAX_EFFECTIVE_BALANCE);
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
                .as_slice()
                .get(i)
                .ok_or(EpochProcessingError::ValidatorIndexOutOfRange { index: i })?
                .clone();
            v.effective_balance = Gwei(new_eff);
            state.validators = state
                .validators
                .with_set(i, v)
                .map_err(EpochProcessingError::Ssz)?;
        }
    }

    Ok(())
}
