//! `process_registry_updates` per `specs/phase0/beacon-chain.md:1751-1780`.
//!
//! Queues activation eligibility, ejects validators below `EJECTION_BALANCE`,
//! then activates up to `churn_limit` validators sorted by
//! `(activation_eligibility_epoch, index)`.
//!
//! # Spec note
//! The spec mutates validators in-place during the eligibility/ejection loop,
//! which means the `validators` list reflects updates mid-iteration. This
//! implementation matches that by applying mutations index-by-index and
//! reading the updated list for the activation queue sort.

use pharos_types::{BeaconStateView, EthSpec, phase0::ValidatorIndex};

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::{compute_activation_exit_epoch, get_current_epoch, get_validator_churn_limit},
    mutators::initiate_validator_exit,
    predicates::{
        is_active_validator, is_eligible_for_activation, is_eligible_for_activation_queue,
    },
    state_write::BeaconStateWrite,
};

/// `EJECTION_BALANCE` per `specs/phase0/beacon-chain.md:347`.
///
/// Validators with effective balance at or below this value are ejected.
/// Value: `2^4 * 10^9 = 16_000_000_000` Gwei.
const EJECTION_BALANCE: u64 = 16_000_000_000;

/// `process_registry_updates` per `specs/phase0/beacon-chain.md:1751-1780`.
pub fn process_registry_updates<E: EthSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let current_epoch = get_current_epoch::<E>(state);

    // Process activation eligibility and ejections.
    // Iterate by index to allow in-place mutation of each validator.
    let n = state.validators().len();
    for index in 0..n {
        let (is_queue_eligible, should_eject) = {
            let vs = state.validators();
            let v = &vs[index];
            let queue_eligible = is_eligible_for_activation_queue::<E>(v);
            let eject = is_active_validator(v, current_epoch.0)
                && v.effective_balance.0 <= EJECTION_BALANCE;
            (queue_eligible, eject)
        };

        if is_queue_eligible {
            let mut v = state.validators()[index].clone();
            v.activation_eligibility_epoch = pharos_types::phase0::Epoch(current_epoch.0 + 1);
            state
                .set_validator(index, v)
                .map_err(EpochProcessingError::from)?;
        }

        if should_eject {
            initiate_validator_exit::<E>(state, ValidatorIndex(index as u64))
                .map_err(|_| EpochProcessingError::ValidatorIndexOutOfRange { index })?;
        }
    }

    // Build activation queue: validators eligible for activation, not yet activated,
    // sorted by (activation_eligibility_epoch, index) per spec.
    let finalized_epoch = state.finalized_checkpoint().epoch;
    let validators_snap = state.validators();
    let mut activation_queue: Vec<usize> = (0..validators_snap.len())
        .filter(|&i| is_eligible_for_activation(finalized_epoch, &validators_snap[i]))
        .collect();

    activation_queue.sort_by_key(|&i| (validators_snap[i].activation_eligibility_epoch, i));

    let churn_limit = get_validator_churn_limit::<E>(state) as usize;
    for &index in activation_queue.iter().take(churn_limit) {
        let mut v = state.validators()[index].clone();
        v.activation_epoch = compute_activation_exit_epoch(current_epoch, E::MAX_SEED_LOOKAHEAD);
        state
            .set_validator(index, v)
            .map_err(EpochProcessingError::from)?;
    }

    Ok(())
}
