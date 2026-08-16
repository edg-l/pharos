//! `process_execution_payload` for Bellatrix.
//!
//! Per `specs/bellatrix/beacon-chain.md:380-416`.

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    BeaconSpec,
    bellatrix::{BeaconBlockBody, BeaconState, ExecutionPayloadHeader},
};

use crate::bellatrix::execution_engine::{
    ExecutionEngine, NewPayloadRequest, PayloadVerificationStatus,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_execution_payload` per `specs/bellatrix/beacon-chain.md:380-416`.
///
/// Returns `PayloadVerificationStatus` from the EL on success, or `Err` if a
/// pre-check or EL `Invalid` verdict rejects the payload.
///
/// Checks:
/// - spec line 389-390: parent-hash must match `state.latest_execution_payload_header.block_hash`
///   when the merge transition is complete (i.e. the header is non-default).
/// - spec line 392: `payload.prev_randao == get_randao_mix(state, get_current_epoch(state))`.
/// - spec line 394: `payload.timestamp == compute_time_at_slot(state, state.slot)`.
/// - spec line 396-398: `execution_engine.verify_and_notify_new_payload`:
///   `Invalid` → `Err(InvalidExecutionPayload)`; `Valid`/`NotValidated` → returned to caller.
/// - spec line 400-415: cache `latest_execution_payload_header` with `transactions_root` computed
///   via `hash_tree_root(payload.transactions)`.
pub fn process_execution_payload<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    E,
    EE,
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    execution_engine: &EE,
    runtime_cfg: &pharos_types::config::RuntimeConfig,
) -> Result<PayloadVerificationStatus, StateTransitionError>
where
    E: BeaconSpec<
        BellatrixBeaconState = BeaconState<
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
    EE: ExecutionEngine,
{
    let payload = &body.execution_payload;

    // spec line 389-390: verify parent_hash when merge transition is complete.
    // `is_merge_transition_complete` per `specs/bellatrix/beacon-chain.md:202-203`:
    //   state.latest_execution_payload_header != ExecutionPayloadHeader()
    let header_default =
        ExecutionPayloadHeader::<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>::default();
    let merge_complete = state.latest_execution_payload_header != header_default;
    if merge_complete {
        // spec line 390: `assert payload.parent_hash == state.latest_execution_payload_header.block_hash`
        if payload.parent_hash != state.latest_execution_payload_header.block_hash {
            return Err(StateTransitionError::InvalidExecutionPayload(
                "parent_hash mismatch",
            ));
        }
    }

    // spec line 392: `assert payload.prev_randao == get_randao_mix(state, get_current_epoch(state))`
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let expected_randao = {
        let idx = (current_epoch.0 % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
        state.randao_mixes.get(idx).copied().unwrap_or_default()
    };
    if payload.prev_randao != expected_randao {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "prev_randao mismatch",
        ));
    }

    // spec line 394: `assert payload.timestamp == compute_time_at_slot(state, state.slot)`
    // `compute_time_at_slot` per `specs/phase0/beacon-chain.md` (and bellatrix):
    //   state.genesis_time + state.slot * SECONDS_PER_SLOT
    let expected_timestamp = state.genesis_time + state.slot.0 * runtime_cfg.seconds_per_slot;
    if payload.timestamp != expected_timestamp {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "timestamp mismatch",
        ));
    }

    // spec lines 396-398: `assert execution_engine.verify_and_notify_new_payload(NewPayloadRequest(...))`
    // `Invalid` → reject; `Valid`/`NotValidated` → proceed and return the status.
    let el_status = execution_engine.verify_and_notify_new_payload(NewPayloadRequest {
        execution_payload: payload,
    });
    if el_status == PayloadVerificationStatus::Invalid {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "execution engine rejected payload",
        ));
    }

    // spec lines 400-415: cache execution payload header.
    // `transactions_root` is `hash_tree_root(payload.transactions)`.
    let transactions_root = payload.transactions.tree_hash_root();

    state.latest_execution_payload_header = ExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions_root,
    };

    Ok(el_status)
}

/// `is_execution_enabled` per `specs/bellatrix/beacon-chain.md:216-217`.
///
/// Returns `true` when execution should run for the given block body against the
/// given state. Used by `process_block` to gate `process_execution_payload`.
pub fn is_execution_enabled<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
    >,
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
) -> bool {
    use pharos_types::bellatrix::ExecutionPayload;

    // spec line 202-203: `is_merge_transition_complete`
    let header_default =
        ExecutionPayloadHeader::<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>::default();
    let merge_complete = state.latest_execution_payload_header != header_default;

    // spec line 209-210: `is_merge_transition_block`
    let empty_payload = ExecutionPayload::<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >::default();
    let is_merge_block = !merge_complete && body.execution_payload != empty_payload;

    // spec line 216-217: `is_execution_enabled`
    is_merge_block || merge_complete
}
