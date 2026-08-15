//! `process_execution_payload` for Capella.
//!
//! Per `specs/capella/beacon-chain.md` Block processing → Modified
//! `process_execution_payload`.
//!
//! Changes from Bellatrix:
//! - `is_merge_transition_complete` check REMOVED (always runs in Capella).
//! - `parent_hash` check is always enforced (no conditional on merge transition).
//! - `withdrawals_root` added to the cached `ExecutionPayloadHeader`.

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    capella::{
        BeaconBlockBody, BeaconState, execution_payload::ExecutionPayloadHeader as CapellaHeader,
    },
};

use crate::bellatrix::execution_engine::ExecutionEngine;
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_execution_payload` per `specs/capella/beacon-chain.md`.
///
/// Checks (in order):
/// - spec: parent_hash == `state.latest_execution_payload_header.block_hash`
///   (no merge-transition-complete guard — always enforced in Capella).
/// - spec: `payload.prev_randao == get_randao_mix(state, get_current_epoch(state))`.
/// - spec: `payload.timestamp == compute_time_at_slot(state, state.slot)`.
/// - spec: `execution_engine.verify_and_notify_new_payload(...)`.
/// - Cache `latest_execution_payload_header` with `withdrawals_root`.
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >,
    execution_engine: &EE,
    runtime_cfg: &pharos_types::config::RuntimeConfig,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
        CapellaBeaconState = BeaconState<
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

    // spec: parent_hash check (always enforced — no is_merge_transition_complete guard).
    if payload.parent_hash != state.latest_execution_payload_header.block_hash {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "parent_hash mismatch",
        ));
    }

    // spec: prev_randao check.
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

    // spec: timestamp check.
    let expected_timestamp = state.genesis_time + state.slot.0 * runtime_cfg.seconds_per_slot;
    if payload.timestamp != expected_timestamp {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "timestamp mismatch",
        ));
    }

    // spec: execution engine verification.
    // Call notify_new_payload_capella so the EL receives the full Capella payload
    // including withdrawals (engine_newPayloadV2). The default fallback strips
    // withdrawals for implementations that have not been upgraded to V2.
    let valid = execution_engine.notify_new_payload_capella(payload);
    if !valid {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "execution engine rejected payload",
        ));
    }

    // spec: cache execution payload header (with withdrawals_root — [New in Capella]).
    let transactions_root = payload.transactions.tree_hash_root();
    let withdrawals_root = payload.withdrawals.tree_hash_root();

    state.latest_execution_payload_header = CapellaHeader {
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
        withdrawals_root,
    };

    Ok(())
}
