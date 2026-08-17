//! `process_slashings` for Electra (EIP-7251).
//!
//! Per `specs/electra/beacon-chain.md:934-955`.
//!
//! Delta vs. Deneb: the correlation penalty is computed per-increment up front
//! rather than per-validator. Deneb computes, per slashed validator,
//! `penalty = effective_balance / increment * adjusted / total_balance * increment`.
//! Electra factors `total_balance // increment` out once into
//! `penalty_per_effective_balance_increment = adjusted // (total_balance // increment)`
//! and then multiplies by the validator's `effective_balance // increment`. This
//! changes the integer-division rounding and is a genuine algorithmic difference,
//! not merely a constant change. `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` is
//! unchanged.

use pharos_ssz::SszSequence;
use pharos_types::{BeaconSpec, electra::BeaconState, phase0::ValidatorIndex};
use pharos_utils::Gwei;

use crate::electra::helpers::{
    decrease_balance_electra, get_current_epoch_electra, get_total_active_balance_electra,
};
use crate::error::EpochProcessingError;

/// `process_slashings` per `specs/electra/beacon-chain.md:934-955`.
#[allow(clippy::type_complexity)]
pub fn process_slashings<
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
    let epoch = get_current_epoch_electra::<
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
        E,
    >(state);

    let total_balance = get_total_active_balance_electra::<
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
        E,
    >(state)
    .0;

    let total_slashings: u64 = state.slashings.iter().map(|g| g.0).sum();
    let adjusted_total_slashing_balance =
        (total_slashings * E::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX).min(total_balance);

    let increment = E::EFFECTIVE_BALANCE_INCREMENT;
    // [Modified in Electra:EIP7251] per-increment correlation penalty.
    let penalty_per_effective_balance_increment =
        adjusted_total_slashing_balance / (total_balance / increment);

    let slashing_epoch_mid = epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR / 2;
    let n = state.validators.len();

    let slashable: Vec<(usize, u64)> = (0..n)
        .filter_map(|i| {
            let v = state.validators.get(i)?;
            if v.slashed && slashing_epoch_mid == v.withdrawable_epoch.0 {
                Some((i, v.effective_balance.0))
            } else {
                None
            }
        })
        .collect();

    for (i, effective_balance) in slashable {
        let effective_balance_increments = effective_balance / increment;
        let penalty = penalty_per_effective_balance_increment * effective_balance_increments;
        decrease_balance_electra::<
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
        >(state, ValidatorIndex(i as u64), Gwei(penalty))?;
    }

    Ok(())
}
