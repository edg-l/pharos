//! `process_registry_updates` for Electra (EIP-7251).
//!
//! Per `specs/electra/beacon-chain.md:909-926`.
//!
//! Electra reshapes the registry-update loop vs. Deneb in three ways:
//! 1. `is_eligible_for_activation_queue` uses `MIN_ACTIVATION_BALANCE` with a
//!    `>=` comparison (not `== MAX_EFFECTIVE_BALANCE`).
//! 2. Ejections call the electra `initiate_validator_exit` (churn-as-balance
//!    accounting via `compute_exit_epoch_and_update_churn`).
//! 3. Activations happen in the SAME loop as eligibility + ejections and the
//!    EIP-7514 activation-queue churn cap is REMOVED — every
//!    `is_eligible_for_activation` validator is activated unconditionally.

use pharos_ssz::SszSequence;
use pharos_types::{BeaconSpec, electra::BeaconState, phase0::Validator, phase0::ValidatorIndex};
use pharos_utils::BLSPubkey;

use crate::electra::helpers::{get_current_epoch_electra, initiate_validator_exit_electra};
use crate::error::EpochProcessingError;
use crate::phase0::accessors::compute_activation_exit_epoch;
use crate::phase0::helpers::FAR_FUTURE_EPOCH;
use crate::phase0::predicates::{is_active_validator, is_eligible_for_activation};

/// `EJECTION_BALANCE` per `specs/phase0/beacon-chain.md:347`.
const EJECTION_BALANCE: u64 = 16_000_000_000;

/// Electra `is_eligible_for_activation_queue` per `specs/electra/beacon-chain.md:480-488`.
///
/// `MIN_ACTIVATION_BALANCE` with `>=` replaces the phase0 `MAX_EFFECTIVE_BALANCE`
/// equality check.
fn is_eligible_for_activation_queue_electra<E: BeaconSpec>(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch.0 == FAR_FUTURE_EPOCH
        && validator.effective_balance.0 >= E::MIN_ACTIVATION_BALANCE
}

/// `process_registry_updates` per `specs/electra/beacon-chain.md:909-926`.
#[allow(clippy::type_complexity)]
pub fn process_registry_updates<
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
) -> Result<(), EpochProcessingError>
where
    BLSPubkey: Default + Clone,
{
    let current_epoch = get_current_epoch_electra::<
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

    let activation_epoch = compute_activation_exit_epoch(current_epoch, E::MAX_SEED_LOOKAHEAD);
    let finalized_epoch = state.finalized_checkpoint.epoch;
    let n = state.validators.len();

    // Process activation eligibility, ejections, and activations in one pass.
    for index in 0..n {
        let v = state
            .validators
            .get(index)
            .ok_or(EpochProcessingError::ValidatorIndexOutOfRange { index })?
            .clone();

        if is_eligible_for_activation_queue_electra::<E>(&v) {
            let mut updated = v.clone();
            updated.activation_eligibility_epoch = pharos_types::phase0::Epoch(current_epoch.0 + 1);
            updated.invalidate_cache();
            state.validators = state
                .validators
                .with_set(index, updated)
                .map_err(EpochProcessingError::Ssz)?;
        } else if is_active_validator(&v, current_epoch.0)
            && v.effective_balance.0 <= EJECTION_BALANCE
        {
            initiate_validator_exit_electra::<
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
            >(state, ValidatorIndex(index as u64))
            .map_err(|_| EpochProcessingError::ValidatorIndexOutOfRange { index })?;
        } else if is_eligible_for_activation(finalized_epoch, &v) {
            let mut activated = v.clone();
            activated.activation_epoch = activation_epoch;
            activated.invalidate_cache();
            state.validators = state
                .validators
                .with_set(index, activated)
                .map_err(EpochProcessingError::Ssz)?;
        }
    }

    Ok(())
}
