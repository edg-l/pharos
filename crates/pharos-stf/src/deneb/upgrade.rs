//! `upgrade_to_deneb` fork transition.
//!
//! Per `specs/deneb/fork.md` → `upgrade_to_deneb`.
//!
//! Converts a capella `BeaconState` into a deneb `BeaconState` by:
//!
//! 1. Setting the fork field with
//!    `previous_version = capella fork.current_version`,
//!    `current_version = DENEB_FORK_VERSION`,
//!    `epoch = get_current_epoch(pre)`.
//! 2. Copying all shared fields verbatim (identical layout).
//! 3. Re-typing `latest_execution_payload_header` from capella to deneb by
//!    adding zeroed `blob_gas_used = 0` and `excess_blob_gas = 0`.

use pharos_types::{
    BeaconSpec,
    capella::BeaconState as CapellaBeaconState,
    config::RuntimeConfig,
    deneb::{BeaconState as DenebBeaconState, ExecutionPayloadHeader as DenebHeader},
    phase0::Fork,
};

use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `upgrade_to_deneb` per `specs/deneb/fork.md`.
///
/// Converts a capella beacon state into a deneb beacon state.
pub fn upgrade_to_deneb<
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
    pre: CapellaBeaconState<
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
) -> Result<
    DenebBeaconState<
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
    StateTransitionError,
>
where
    E: BeaconSpec<
            CapellaBeaconState = CapellaBeaconState<
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
            DenebBeaconState = DenebBeaconState<
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
    let epoch = compute_epoch_at_slot(pre.slot, E::SLOTS_PER_EPOCH);

    // spec fork.md: set fork field.
    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: pharos_utils::Bytes4::from_array(runtime_cfg.deneb_fork_version),
        epoch,
    };

    // spec fork.md: build deneb ExecutionPayloadHeader from capella header.
    // blob_gas_used = 0, excess_blob_gas = 0 [New in Deneb].
    let latest_execution_payload_header = DenebHeader {
        parent_hash: pre.latest_execution_payload_header.parent_hash,
        fee_recipient: pre.latest_execution_payload_header.fee_recipient,
        state_root: pre.latest_execution_payload_header.state_root,
        receipts_root: pre.latest_execution_payload_header.receipts_root,
        logs_bloom: pre.latest_execution_payload_header.logs_bloom.clone(),
        prev_randao: pre.latest_execution_payload_header.prev_randao,
        block_number: pre.latest_execution_payload_header.block_number,
        gas_limit: pre.latest_execution_payload_header.gas_limit,
        gas_used: pre.latest_execution_payload_header.gas_used,
        timestamp: pre.latest_execution_payload_header.timestamp,
        extra_data: pre.latest_execution_payload_header.extra_data.clone(),
        base_fee_per_gas: pre.latest_execution_payload_header.base_fee_per_gas,
        block_hash: pre.latest_execution_payload_header.block_hash,
        transactions_root: pre.latest_execution_payload_header.transactions_root,
        withdrawals_root: pre.latest_execution_payload_header.withdrawals_root,
        // [New in Deneb]: zero-filled.
        blob_gas_used: 0,
        excess_blob_gas: 0,
    };

    Ok(DenebBeaconState {
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork,
        latest_block_header: pre.latest_block_header,
        block_roots: pre.block_roots,
        state_roots: pre.state_roots,
        historical_roots: pre.historical_roots,
        eth1_data: pre.eth1_data,
        eth1_data_votes: pre.eth1_data_votes,
        eth1_deposit_index: pre.eth1_deposit_index,
        validators: pre.validators,
        balances: pre.balances,
        randao_mixes: pre.randao_mixes,
        slashings: pre.slashings,
        previous_epoch_participation: pre.previous_epoch_participation,
        current_epoch_participation: pre.current_epoch_participation,
        justification_bits: pre.justification_bits,
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: pre.inactivity_scores,
        current_sync_committee: pre.current_sync_committee,
        next_sync_committee: pre.next_sync_committee,
        latest_execution_payload_header,
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries,
        cached_root: pharos_utils::CachedRoot::default(),
    })
}
