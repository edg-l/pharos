//! Beacon state mutator helpers.
//!
//! Per `specs/phase0/beacon-chain.md:1205-1296` "Beacon state mutators".
//!
//! # Threading convention
//!
//! `SszList` / `SszVector` fields are mutated via the copy-on-write
//! `with_set` / `with_push` API on `BeaconStateWrite`, which returns a new
//! collection immediately rebound to the state field:
//!
//! ```text
//! state.set_balance(idx, Gwei(new));
//! state.set_slashing(slot, Gwei(cur + delta))?;
//! ```
//!
//! Scalar fields are set via `BeaconStateWrite` setters.  No `unsafe` code;
//! no direct field access on the opaque `E::BeaconState` associated type.

use pharos_types::{
    BeaconStateView, EthSpec,
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::error::StateTransitionError;
use crate::phase0::{
    accessors::{
        compute_activation_exit_epoch, get_beacon_proposer_index, get_current_epoch,
        get_validator_churn_limit,
    },
    helpers::FAR_FUTURE_EPOCH,
    state_write::BeaconStateWrite,
};

/// `increase_balance` per `specs/phase0/beacon-chain.md:1205-1210`.
pub fn increase_balance<E: EthSpec>(state: &mut E::BeaconState, index: ValidatorIndex, delta: Gwei)
where
    E::BeaconState: BeaconStateWrite,
{
    let cur = state
        .balances()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    state.set_balance(index.0 as usize, Gwei(cur.0.saturating_add(delta.0)));
}

/// `decrease_balance` per `specs/phase0/beacon-chain.md:1215-1221`.
///
/// Underflow-protected: clamps to 0.
pub fn decrease_balance<E: EthSpec>(state: &mut E::BeaconState, index: ValidatorIndex, delta: Gwei)
where
    E::BeaconState: BeaconStateWrite,
{
    let cur = state
        .balances()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    let new_val = if delta.0 > cur.0 {
        Gwei(0)
    } else {
        Gwei(cur.0 - delta.0)
    };
    state.set_balance(index.0 as usize, new_val);
}

/// `initiate_validator_exit` per `specs/phase0/beacon-chain.md:1225-1245`.
pub fn initiate_validator_exit<E: EthSpec>(
    state: &mut E::BeaconState,
    index: ValidatorIndex,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    {
        let validator = state
            .validator(index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
        if validator.exit_epoch.0 != FAR_FUTURE_EPOCH {
            return Ok(());
        }
    }

    let activation_exit_epoch =
        compute_activation_exit_epoch(get_current_epoch::<E>(state), E::MAX_SEED_LOOKAHEAD);

    let exit_queue_epoch = {
        let max_existing = state
            .validators_iter()
            .filter(|v| v.exit_epoch.0 != FAR_FUTURE_EPOCH)
            .map(|v| v.exit_epoch.0)
            .max()
            .unwrap_or(0)
            .max(activation_exit_epoch.0);
        Epoch(max_existing)
    };

    let churn_limit = get_validator_churn_limit::<E>(state);
    let exit_queue_churn = state
        .validators_iter()
        .filter(|v| v.exit_epoch == exit_queue_epoch)
        .count() as u64;

    let final_exit_epoch = if exit_queue_churn >= churn_limit {
        let next = exit_queue_epoch
            .0
            .checked_add(1)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
        Epoch(next)
    } else {
        exit_queue_epoch
    };

    let withdrawable_epoch_raw = final_exit_epoch
        .0
        .checked_add(E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
        .ok_or(StateTransitionError::SlotOutOfRange)?;
    let withdrawable_epoch = Epoch(withdrawable_epoch_raw);

    let mut validator = state
        .validator(index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();
    validator.exit_epoch = final_exit_epoch;
    validator.withdrawable_epoch = withdrawable_epoch;
    state.set_validator(index.0 as usize, validator)?;

    Ok(())
}

/// `slash_validator` per `specs/phase0/beacon-chain.md:1249-1286`.
pub fn slash_validator<E: EthSpec>(
    state: &mut E::BeaconState,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    let epoch = get_current_epoch::<E>(state);

    initiate_validator_exit::<E>(state, slashed_index)?;

    let (effective_balance, current_withdrawable_epoch) = {
        let v = state
            .validator(slashed_index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
        (v.effective_balance, v.withdrawable_epoch)
    };

    let new_withdrawable_epoch = Epoch(
        current_withdrawable_epoch
            .0
            .max(epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR),
    );

    {
        let mut v = state
            .validator(slashed_index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?
            .clone();
        v.slashed = true;
        v.withdrawable_epoch = new_withdrawable_epoch;
        state.set_validator(slashed_index.0 as usize, v)?;
    }

    let slashing_slot = (epoch.0 % E::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
    let cur_slashing = state
        .slashings()
        .get(slashing_slot)
        .copied()
        .unwrap_or(Gwei(0));
    state.set_slashing(
        slashing_slot,
        Gwei(cur_slashing.0.saturating_add(effective_balance.0)),
    )?;

    let penalty = Gwei(effective_balance.0 / E::MIN_SLASHING_PENALTY_QUOTIENT);
    decrease_balance::<E>(state, slashed_index, penalty);

    let proposer_index = get_beacon_proposer_index::<E>(state);
    let whistleblower_idx = whistleblower_index.unwrap_or(proposer_index);

    let whistleblower_reward = Gwei(effective_balance.0 / E::WHISTLEBLOWER_REWARD_QUOTIENT);
    let proposer_reward = Gwei(whistleblower_reward.0 / E::PROPOSER_REWARD_QUOTIENT);

    increase_balance::<E>(state, proposer_index, proposer_reward);
    increase_balance::<E>(
        state,
        whistleblower_idx,
        Gwei(whistleblower_reward.0 - proposer_reward.0),
    );

    Ok(())
}
