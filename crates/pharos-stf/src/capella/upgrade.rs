//! `upgrade_to_capella` fork transition.
//!
//! Per `specs/capella/fork.md` → `upgrade_to_capella`.
//!
//! Converts a bellatrix `BeaconState` into a capella `BeaconState` by:
//!
//! 1. Setting the fork field with
//!    `previous_version = bellatrix fork.current_version`,
//!    `current_version = CAPELLA_FORK_VERSION`,
//!    `epoch = get_current_epoch(pre)`.
//! 2. Copying all shared fields verbatim.
//! 3. Building a `capella::ExecutionPayloadHeader` from the bellatrix one,
//!    adding `withdrawals_root = Root::default()` (`[New in Capella]`).
//! 4. Initialising `next_withdrawal_index = 0`, `next_withdrawal_validator_index = 0`,
//!    `historical_summaries = []`.

use pharos_ssz::SszList;
use pharos_types::{
    EthSpec,
    bellatrix::BeaconState as BellatrixBeaconState,
    capella::{
        BeaconState as CapellaBeaconState,
        execution_payload::ExecutionPayloadHeader as CapellaHeader, operations::HistoricalSummary,
    },
    config::RuntimeConfig,
    phase0::{Fork, ValidatorIndex},
};

use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `upgrade_to_capella` per `specs/capella/fork.md`.
///
/// Converts a bellatrix beacon state into a capella beacon state.
pub fn upgrade_to_capella<
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
    pre: BellatrixBeaconState<
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
    CapellaBeaconState<
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
    E: EthSpec<
            BellatrixBeaconState = BellatrixBeaconState<
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
        >,
{
    let epoch = compute_epoch_at_slot(pre.slot, E::SLOTS_PER_EPOCH);

    // spec fork.md: set fork field.
    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: pharos_utils::Bytes4::from_array(runtime_cfg.capella_fork_version),
        epoch,
    };

    // spec fork.md: build capella ExecutionPayloadHeader from bellatrix header.
    // withdrawals_root is Root::default() [New in Capella].
    let latest_execution_payload_header = CapellaHeader {
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
        // [New in Capella]: zero-filled.
        withdrawals_root: pharos_utils::Hash256::default(),
    };

    Ok(CapellaBeaconState {
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
        // [New in Capella]: zero-initialised.
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: ValidatorIndex(0),
        historical_summaries: SszList::<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>::default(),
        cached_root: pharos_utils::CachedRoot::default(),
    })
}
