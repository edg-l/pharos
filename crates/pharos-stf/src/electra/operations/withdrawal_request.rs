//! `process_withdrawal_request` (EIP-7002) per
//! `specs/electra/beacon-chain.md:1735-1802`.
//!
//! An EL-triggered withdrawal request is either a FULL exit
//! (`amount == FULL_EXIT_REQUEST_AMOUNT == 0`) or a PARTIAL withdrawal.
//!
//! Every precondition that fails is a SILENT no-op (`return` in the spec), NOT
//! an error: the op succeeds with the state unchanged. The spec gates must
//! short-circuit in exact order — a wrong order passes some fixtures and fails
//! others — so they are kept 1:1 with `:1735-1802`:
//!
//! 1. partial-queue-full guard (only full exits proceed once the partial queue
//!    is at `PENDING_PARTIAL_WITHDRAWALS_LIMIT`),
//! 2. pubkey must exist in the registry,
//! 3. execution (`0x01`/`0x02`) credential whose address matches the request
//!    `source_address`,
//! 4. validator active in the current epoch,
//! 5. exit not already initiated,
//! 6. active long enough (`activation_epoch + SHARD_COMMITTEE_PERIOD`),
//! 7. then read `pending_balance_to_withdraw` and branch full vs partial.
//!
//! Churn/credential logic is reused from `electra::helpers` (Phase 2a).

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    electra::{BeaconState, requests::PendingPartialWithdrawal, requests::WithdrawalRequest},
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::electra::helpers::{
    compute_exit_epoch_and_update_churn_electra, get_pending_balance_to_withdraw_electra,
    has_compounding_withdrawal_credential, has_execution_withdrawal_credential,
    initiate_validator_exit_electra,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;
use crate::phase0::helpers::FAR_FUTURE_EPOCH;
use crate::phase0::predicates::is_active_validator;

/// `process_withdrawal_request` per `specs/electra/beacon-chain.md:1735-1802`.
#[allow(clippy::too_many_arguments)]
pub fn process_withdrawal_request<
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
    withdrawal_request: &WithdrawalRequest,
    _verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
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
    let amount = withdrawal_request.amount;
    let is_full_exit_request = amount.0 == E::FULL_EXIT_REQUEST_AMOUNT;

    // If partial withdrawal queue is full, only full exits are processed.
    if state.pending_partial_withdrawals.len() as u64 == PENDING_PARTIAL_WITHDRAWALS_LIMIT
        && !is_full_exit_request
    {
        return Ok(());
    }

    // Verify pubkey exists.
    let request_pubkey = withdrawal_request.validator_pubkey.as_slice();
    let index = match state
        .validators
        .iter()
        .position(|v| v.pubkey.as_slice() == request_pubkey)
    {
        Some(i) => ValidatorIndex(i as u64),
        None => return Ok(()),
    };
    let validator = state
        .validators
        .get(index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();

    // Verify withdrawal credentials.
    let has_correct_credential = has_execution_withdrawal_credential::<E>(&validator);
    let is_correct_source_address =
        validator.withdrawal_credentials.as_slice()[12..] == withdrawal_request.source_address[..];
    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // Verify the validator is active.
    if !is_active_validator(&validator, current_epoch.0) {
        return Ok(());
    }
    // Verify exit has not been initiated.
    if validator.exit_epoch.0 != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    // Verify the validator has been active long enough.
    if current_epoch.0 < validator.activation_epoch.0 + E::SHARD_COMMITTEE_PERIOD {
        return Ok(());
    }

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
    >(state, index);

    if is_full_exit_request {
        // Only exit validator if it has no pending withdrawals in the queue.
        if pending_balance_to_withdraw.0 == 0 {
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
            >(state, index)?;
        }
        return Ok(());
    }

    let balance = state
        .balances
        .as_slice()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    let has_sufficient_effective_balance =
        validator.effective_balance.0 >= E::MIN_ACTIVATION_BALANCE;
    let has_excess_balance = balance.0 > E::MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw.0;

    // Only allow partial withdrawals with compounding withdrawal credentials.
    if has_compounding_withdrawal_credential::<E>(&validator)
        && has_sufficient_effective_balance
        && has_excess_balance
    {
        let to_withdraw =
            (balance.0 - E::MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw.0).min(amount.0);
        let exit_queue_epoch = compute_exit_epoch_and_update_churn_electra::<
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
        >(state, Gwei(to_withdraw));
        let withdrawable_epoch = Epoch(exit_queue_epoch.0 + E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY);
        let pending = PendingPartialWithdrawal {
            validator_index: index,
            amount: Gwei(to_withdraw),
            withdrawable_epoch,
        };
        state.pending_partial_withdrawals = state
            .pending_partial_withdrawals
            .with_push(pending)
            .map_err(StateTransitionError::Ssz)?;
    }

    Ok(())
}
