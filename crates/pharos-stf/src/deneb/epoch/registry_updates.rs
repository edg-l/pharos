//! `process_registry_updates` for Deneb (EIP-7514).
//!
//! Per `specs/deneb/beacon-chain.md` Epoch processing → Modified
//! `process_registry_updates`.
//!
//! EIP-7514: the validator activation churn is capped at
//! `min(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, get_validator_churn_limit(state))`.
//! This prevents a sudden massive validator activation burst.

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    config::RuntimeConfig,
    deneb::BeaconState,
    phase0::ValidatorIndex,
};

use crate::deneb::helpers::{get_current_epoch_deneb, initiate_validator_exit_deneb};
use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::compute_activation_exit_epoch,
    predicates::{
        is_active_validator, is_eligible_for_activation, is_eligible_for_activation_queue,
    },
};

/// `EJECTION_BALANCE` per `specs/phase0/beacon-chain.md:347`.
const EJECTION_BALANCE: u64 = 16_000_000_000;

/// `process_registry_updates` per `specs/deneb/beacon-chain.md` (EIP-7514).
///
/// Identical to Altair/Capella except the activation churn is capped at
/// `min(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, get_validator_churn_limit(state))`.
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    runtime_cfg: &RuntimeConfig,
) -> Result<(), EpochProcessingError>
where
    E: EthSpec<
        DenebBeaconState = BeaconState<
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
        >,
    >,
{
    let current_epoch = get_current_epoch_deneb::<
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
        E,
    >(state);

    let n = state.validators.len();

    // Process activation eligibility and ejections.
    for index in 0..n {
        let v = state
            .validators
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
            initiate_validator_exit_deneb::<
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
                E,
            >(state, ValidatorIndex(index as u64))
            .map_err(|_| EpochProcessingError::ValidatorIndexOutOfRange { index })?;
        }
    }

    // Build activation queue.
    let finalized_epoch = state.finalized_checkpoint.epoch;
    let mut activation_queue: Vec<usize> = (0..state.validators.len())
        .filter(|&i| {
            is_eligible_for_activation(finalized_epoch, state.validators.get(i).expect("in range"))
        })
        .collect();

    activation_queue.sort_by_key(|&i| {
        (
            state
                .validators
                .get(i)
                .expect("in range")
                .activation_eligibility_epoch,
            i,
        )
    });

    // EIP-7514: churn limit = min(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, validator_churn_limit).
    let active_count = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, current_epoch.0))
        .count() as u64;
    let validator_churn_limit =
        (active_count / E::CHURN_LIMIT_QUOTIENT).max(E::MIN_PER_EPOCH_CHURN_LIMIT);
    let churn_limit =
        runtime_cfg.max_per_epoch_activation_churn_limit.min(validator_churn_limit) as usize;

    for &index in activation_queue.iter().take(churn_limit) {
        let mut v = state
            .validators
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
