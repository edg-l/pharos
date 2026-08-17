//! `process_slashings` for Altair.
//!
//! Modified from phase0: uses `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR`
//! instead of `PROPORTIONAL_SLASHING_MULTIPLIER`.
//!
//! spec: specs/altair/beacon-chain.md:741-763

use pharos_ssz::SszSequence;
use pharos_types::{BeaconSpec, altair::BeaconState, phase0::ValidatorIndex};
use pharos_utils::Gwei;

use crate::altair::helpers::{decrease_balance_altair, get_total_active_balance_altair};
use crate::error::EpochProcessingError;

use super::helpers::get_current_epoch_altair;

/// `process_slashings` per `specs/altair/beacon-chain.md:741-763`.
///
/// Modified in Altair: uses `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR`
/// (value 2) instead of phase0's `PROPORTIONAL_SLASHING_MULTIPLIER` (1).
pub fn process_slashings<
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
    E: BeaconSpec<
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
    let epoch = get_current_epoch_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);

    let total_balance = get_total_active_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state)
    .0;

    let total_slashings: u64 = state.slashings.iter().map(|g| g.0).sum();
    // Altair: use PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR.
    let adjusted =
        (total_slashings * E::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR).min(total_balance);

    let slashing_epoch_mid = epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR / 2;
    let n = state.validators.len();

    // Collect slashable (index, effective_balance) pairs.
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

    let increment = E::EFFECTIVE_BALANCE_INCREMENT;
    for (i, effective_balance) in slashable {
        let penalty_numerator = effective_balance / increment * adjusted;
        let penalty = penalty_numerator / total_balance * increment;
        decrease_balance_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >(state, ValidatorIndex(i as u64), Gwei(penalty))?;
    }

    Ok(())
}
