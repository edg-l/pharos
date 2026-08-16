//! `process_slashings` per `specs/phase0/beacon-chain.md:1782-1802`.
//!
//! Penalises slashed validators at the midpoint of their `EPOCHS_PER_SLASHINGS_VECTOR`
//! withdrawal delay, proportional to `sum(state.slashings) * PROPORTIONAL_SLASHING_MULTIPLIER`
//! relative to `total_balance`.

use pharos_types::{BeaconStateView, EthSpec, phase0::ValidatorIndex};

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::{get_current_epoch, get_total_active_balance},
    mutators::decrease_balance,
    state_write::BeaconStateWrite,
};
use pharos_utils::Gwei;

/// `process_slashings` per `specs/phase0/beacon-chain.md:1782-1802`.
pub fn process_slashings<E: EthSpec>(state: &mut E::BeaconState) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let epoch = get_current_epoch::<E>(state);
    let total_balance = get_total_active_balance::<E>(state).0;

    let total_slashings: u64 = state.slashings().iter().map(|g| g.0).sum();
    let adjusted = (total_slashings * E::PROPORTIONAL_SLASHING_MULTIPLIER).min(total_balance);

    let slashing_epoch_mid = epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR / 2;
    let slashable: Vec<(usize, u64)> = state
        .validators_iter()
        .enumerate()
        .filter_map(|(i, v)| {
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
        decrease_balance::<E>(state, ValidatorIndex(i as u64), Gwei(penalty))?;
    }

    Ok(())
}
