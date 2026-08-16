//! `process_execution_payload` for Electra.
//!
//! Per `specs/electra/beacon-chain.md` Block processing → Modified
//! `process_execution_payload` (`:1411-1461`).
//!
//! Changes from Deneb:
//! - [Modified in Electra:EIP7691] blob-count cap uses `MAX_BLOBS_PER_BLOCK_ELECTRA`
//!   (`runtime_cfg.max_blobs_per_block_electra`) instead of the Deneb per-block limit.
//! - [New in Electra:EIP7685] `execution_requests` from the BODY threaded to the
//!   engine `notify_new_payload_electra` call. The requests live in `body.execution_requests`,
//!   not in the `ExecutionPayload` itself (payload/header are byte-identical to Deneb).
//! - `versioned_hashes` and `parent_beacon_block_root` — same as Deneb.

use pharos_kzg::kzg_commitment_to_versioned_hash;
use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    deneb::execution_payload::ExecutionPayloadHeader as DenebHeader,
    electra::{BeaconBlockBody, BeaconState},
};

use crate::bellatrix::execution_engine::{ExecutionEngine, PayloadVerificationStatus};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_execution_payload` per `specs/electra/beacon-chain.md:1411-1461`.
///
/// Extends the Deneb version with:
/// - EIP-7691: blob commitment count bounded by `runtime.max_blobs_per_block_electra`.
/// - EIP-7685: `execution_requests` from the body passed to `notify_new_payload_electra`.
#[allow(clippy::too_many_arguments)]
pub fn process_execution_payload<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS_ELECTRA: u64,
    const MAX_ATTESTATIONS_ELECTRA: u64,
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
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_ATTESTATIONS_ELECTRA,
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
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >,
    execution_engine: &EE,
    runtime_cfg: &pharos_types::config::RuntimeConfig,
) -> Result<PayloadVerificationStatus, StateTransitionError>
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
    EE: ExecutionEngine,
{
    let payload = &body.execution_payload;

    // spec: parent_hash check.
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

    // [Modified in Electra:EIP7691] blob commitment count check — uses the
    // electra limit (9) rather than the deneb limit (6).
    let blob_count = body.blob_kzg_commitments.len();
    if blob_count as u64 > runtime_cfg.max_blobs_per_block_electra {
        return Err(StateTransitionError::TooManyBlobCommitments {
            count: blob_count,
            max: runtime_cfg.max_blobs_per_block_electra,
        });
    }

    // EIP-4844: compute versioned hashes from blob_kzg_commitments.
    let versioned_hashes: Vec<[u8; 32]> = body
        .blob_kzg_commitments
        .as_slice()
        .iter()
        .map(|c| kzg_commitment_to_versioned_hash(&(*c).into_inner()))
        .collect();

    // parent_beacon_block_root = state.latest_block_header.parent_root.
    // Must be read BEFORE process_block_header mutates latest_block_header.
    let parent_beacon_block_root = state.latest_block_header.parent_root;

    // [New in Electra:EIP7685] engine verification includes execution_requests.
    let el_status = execution_engine.notify_new_payload_electra(
        payload,
        &versioned_hashes,
        parent_beacon_block_root,
        &body.execution_requests,
    );
    if el_status == PayloadVerificationStatus::Invalid {
        return Err(StateTransitionError::InvalidExecutionPayload(
            "execution engine rejected payload",
        ));
    }

    // Cache execution payload header (byte-identical to Deneb header).
    let transactions_root = payload.transactions.tree_hash_root();
    let withdrawals_root = payload.withdrawals.tree_hash_root();

    state.latest_execution_payload_header = DenebHeader {
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
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    };

    Ok(el_status)
}
