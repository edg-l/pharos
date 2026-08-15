//! `process_registry_updates` for Altair.
//!
//! Unchanged from phase0 in logic; re-implemented to operate on the concrete
//! altair `BeaconState` (which does not implement `BeaconStateWrite`).
//!
//! spec: specs/phase0/beacon-chain.md:1751-1780 (identical in Altair)

use pharos_ssz::SszSequence;
use pharos_types::{EthSpec, altair::BeaconState, phase0::ValidatorIndex};

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::compute_activation_exit_epoch,
    predicates::{
        is_active_validator, is_eligible_for_activation, is_eligible_for_activation_queue,
    },
};
use crate::altair::helpers::initiate_validator_exit_altair_pub;

use super::helpers::get_current_epoch_altair;

/// `EJECTION_BALANCE` per `specs/phase0/beacon-chain.md:347`.
const EJECTION_BALANCE: u64 = 16_000_000_000;

/// `process_registry_updates` per `specs/phase0/beacon-chain.md:1751-1780`.
///
/// Altair: logic is identical to phase0; operates on the concrete altair state.
pub fn process_registry_updates<
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
    let current_epoch = get_current_epoch_altair::<
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

    let n = state.validators.len();

    // Process activation eligibility and ejections.
    for index in 0..n {
        let v = state
            .validators
            .as_slice()
            .get(index)
            .ok_or(EpochProcessingError::ValidatorIndexOutOfRange { index })?
            .clone();

        if is_eligible_for_activation_queue::<E>(&v) {
            let mut updated = v.clone();
            updated.activation_eligibility_epoch =
                pharos_types::phase0::Epoch(current_epoch.0 + 1);
            state.validators = state
                .validators
                .with_set(index, updated)
                .map_err(EpochProcessingError::Ssz)?;
        }

        if is_active_validator(&v, current_epoch.0) && v.effective_balance.0 <= EJECTION_BALANCE {
            initiate_validator_exit_altair_pub::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                E,
            >(state, ValidatorIndex(index as u64))
            .map_err(|_| EpochProcessingError::ValidatorIndexOutOfRange { index })?;
        }
    }

    // Build activation queue: validators eligible, not yet activated,
    // sorted by (activation_eligibility_epoch, index).
    let finalized_epoch = state.finalized_checkpoint.epoch;
    let mut activation_queue: Vec<usize> = (0..state.validators.len())
        .filter(|&i| {
            is_eligible_for_activation(
                finalized_epoch,
                state.validators.as_slice().get(i).expect("in range"),
            )
        })
        .collect();

    activation_queue.sort_by_key(|&i| {
        (
            state
                .validators
                .as_slice()
                .get(i)
                .expect("in range")
                .activation_eligibility_epoch,
            i,
        )
    });

    // churn_limit via a BeaconStateView-free path.
    let active_count = state
        .validators
        .as_slice()
        .iter()
        .filter(|v| is_active_validator(v, current_epoch.0))
        .count() as u64;
    let churn_limit = (active_count / E::CHURN_LIMIT_QUOTIENT)
        .max(E::MIN_PER_EPOCH_CHURN_LIMIT) as usize;

    for &index in activation_queue.iter().take(churn_limit) {
        let mut v = state
            .validators
            .as_slice()
            .get(index)
            .ok_or(EpochProcessingError::ValidatorIndexOutOfRange { index })?
            .clone();
        v.activation_epoch = compute_activation_exit_epoch(current_epoch, E::MAX_SEED_LOOKAHEAD);
        state.validators = state
            .validators
            .with_set(index, v)
            .map_err(EpochProcessingError::Ssz)?;
    }

    Ok(())
}
