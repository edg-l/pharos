//! `process_consolidation_request` (EIP-7251) per
//! `specs/electra/beacon-chain.md:1869-1942`, with the
//! `is_valid_switch_to_compounding_request` predicate at `:1831-1864`.
//!
//! An EL-triggered consolidation request has two distinct outcomes:
//!
//! 1. **Switch-to-compounding** (checked FIRST): a self-request
//!    (`source_pubkey == target_pubkey`) by a `0x01` validator whose
//!    `source_address` matches, that is active and not exiting, switches the
//!    source to a `0x02` compounding credential via
//!    `switch_to_compounding_validator` and returns immediately.
//! 2. **Consolidation**: enqueues a `PendingConsolidation { source, target }`
//!    and initiates the source validator's exit (with churn-derived
//!    `exit_epoch` / `withdrawable_epoch`).
//!
//! Every precondition that fails is a SILENT no-op (`return` in the spec), NOT
//! an error: the op succeeds with the state unchanged. The spec gates must
//! short-circuit in exact order — a wrong order passes some fixtures and fails
//! others — so they are kept 1:1 with the spec.
//!
//! Churn / credential / compounding logic is reused from `electra::helpers`
//! (Phase 2a); none of it is reimplemented here.

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    electra::{BeaconState, requests::ConsolidationRequest, requests::PendingConsolidation},
    phase0::{Epoch, ValidatorIndex},
};

use crate::electra::helpers::{
    compute_consolidation_epoch_and_update_churn_electra, get_consolidation_churn_limit_electra,
    get_pending_balance_to_withdraw_electra, has_compounding_withdrawal_credential,
    has_execution_withdrawal_credential, switch_to_compounding_validator_electra,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;
use crate::phase0::helpers::FAR_FUTURE_EPOCH;
use crate::phase0::predicates::is_active_validator;

/// `is_valid_switch_to_compounding_request` per
/// `specs/electra/beacon-chain.md:1831-1864`.
///
/// Returns `true` when the request is a self-targeting switch by an active,
/// non-exiting `0x01` validator whose authorized `source_address` matches.
pub fn is_valid_switch_to_compounding_request<
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
    E: EthSpec,
>(
    state: &BeaconState<
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
    consolidation_request: &ConsolidationRequest,
) -> bool {
    // Switch to compounding requires source and target be equal.
    if consolidation_request.source_pubkey.as_slice()
        != consolidation_request.target_pubkey.as_slice()
    {
        return false;
    }

    // Verify pubkey exists.
    let source_pubkey = consolidation_request.source_pubkey.as_slice();
    let source_index = match state
        .validators
        .iter()
        .position(|v| v.pubkey.as_slice() == source_pubkey)
    {
        Some(i) => i,
        None => return false,
    };
    let source_validator = match state.validators.get(source_index) {
        Some(v) => v,
        None => return false,
    };

    // Verify request has been authorized.
    if source_validator.withdrawal_credentials.as_slice()[12..]
        != consolidation_request.source_address[..]
    {
        return false;
    }

    // Verify source withdrawal credentials (0x01 eth1 credential).
    if !crate::capella::helpers::has_eth1_withdrawal_credential(source_validator) {
        return false;
    }

    // Verify the source is active.
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    if !is_active_validator(source_validator, current_epoch.0) {
        return false;
    }

    // Verify exit for source has not been initiated.
    if source_validator.exit_epoch.0 != FAR_FUTURE_EPOCH {
        return false;
    }

    true
}

/// `process_consolidation_request` per `specs/electra/beacon-chain.md:1869-1942`.
#[allow(clippy::too_many_arguments)]
pub fn process_consolidation_request<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    consolidation_request: &ConsolidationRequest,
    _verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
        ElectraBeaconState = BeaconState<
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
    >,
{
    // Switch-to-compounding path is checked FIRST: a valid self-request switches
    // the source to a 0x02 credential and returns immediately.
    if is_valid_switch_to_compounding_request::<
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
    >(state, consolidation_request)
    {
        let source_pubkey = consolidation_request.source_pubkey.as_slice();
        let source_index = state
            .validators
            .iter()
            .position(|v| v.pubkey.as_slice() == source_pubkey)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
        switch_to_compounding_validator_electra::<
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
        >(state, ValidatorIndex(source_index as u64))?;
        return Ok(());
    }

    // Verify that source != target, so a consolidation cannot be used as an exit.
    if consolidation_request.source_pubkey.as_slice()
        == consolidation_request.target_pubkey.as_slice()
    {
        return Ok(());
    }
    // If the pending consolidations queue is full, requests are ignored.
    if state.pending_consolidations.len() as u64 == PENDING_CONSOLIDATIONS_LIMIT {
        return Ok(());
    }
    // If there is too little available consolidation churn limit, ignore.
    let consolidation_churn_limit = get_consolidation_churn_limit_electra::<
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
    if consolidation_churn_limit.0 <= E::MIN_ACTIVATION_BALANCE {
        return Ok(());
    }

    // Verify pubkeys exist.
    let source_pubkey = consolidation_request.source_pubkey.as_slice();
    let target_pubkey = consolidation_request.target_pubkey.as_slice();
    let source_index = match state
        .validators
        .iter()
        .position(|v| v.pubkey.as_slice() == source_pubkey)
    {
        Some(i) => ValidatorIndex(i as u64),
        None => return Ok(()),
    };
    let target_index = match state
        .validators
        .iter()
        .position(|v| v.pubkey.as_slice() == target_pubkey)
    {
        Some(i) => ValidatorIndex(i as u64),
        None => return Ok(()),
    };
    let source_validator = state
        .validators
        .get(source_index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();
    let target_validator = state
        .validators
        .get(target_index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();

    // Verify source withdrawal credentials.
    let has_correct_credential = has_execution_withdrawal_credential::<E>(&source_validator);
    let is_correct_source_address = source_validator.withdrawal_credentials.as_slice()[12..]
        == consolidation_request.source_address[..];
    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }

    // Verify that target has compounding withdrawal credentials.
    if !has_compounding_withdrawal_credential::<E>(&target_validator) {
        return Ok(());
    }

    // Verify the source and the target are active.
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    if !is_active_validator(&source_validator, current_epoch.0) {
        return Ok(());
    }
    if !is_active_validator(&target_validator, current_epoch.0) {
        return Ok(());
    }
    // Verify exits for source and target have not been initiated.
    if source_validator.exit_epoch.0 != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    if target_validator.exit_epoch.0 != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    // Verify the source has been active long enough.
    if current_epoch.0 < source_validator.activation_epoch.0 + E::SHARD_COMMITTEE_PERIOD {
        return Ok(());
    }
    // Verify the source has no pending withdrawals in the queue.
    let pending_balance_to_withdraw = get_pending_balance_to_withdraw_electra::<
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
    >(state, source_index);
    if pending_balance_to_withdraw.0 > 0 {
        return Ok(());
    }

    // Initiate source validator exit and append pending consolidation.
    let exit_epoch = compute_consolidation_epoch_and_update_churn_electra::<
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
    >(state, source_validator.effective_balance);
    let withdrawable_epoch = Epoch(exit_epoch.0 + E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY);

    let mut source = state
        .validators
        .get(source_index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();
    source.exit_epoch = exit_epoch;
    source.withdrawable_epoch = withdrawable_epoch;
    source.invalidate_cache();
    state.validators = state
        .validators
        .with_set(source_index.0 as usize, source)
        .map_err(StateTransitionError::Ssz)?;

    let pending = PendingConsolidation {
        source_index,
        target_index,
    };
    state.pending_consolidations = state
        .pending_consolidations
        .with_push(pending)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}
