//! `upgrade_to_bellatrix` fork transition.
//!
//! Per `specs/bellatrix/fork.md:54-90`.
//!
//! Converts an altair `BeaconState` into a bellatrix `BeaconState` by:
//!
//! 1. Setting the fork field with `previous_version = altair fork.current_version`,
//!    `current_version = BELLATRIX_FORK_VERSION`, `epoch = get_current_epoch(pre)`.
//! 2. Copying all other shared fields verbatim.
//! 3. Initialising `latest_execution_payload_header` to a zero-filled
//!    `ExecutionPayloadHeader`.
//!
//! No validator-registry mutation.

use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    bellatrix::{BeaconState as BellatrixBeaconState, ExecutionPayloadHeader},
    config::RuntimeConfig,
    phase0::Fork,
};

use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `upgrade_to_bellatrix` per `specs/bellatrix/fork.md:54-90`.
///
/// Converts an altair beacon state into a bellatrix beacon state.
pub fn upgrade_to_bellatrix<
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
    pre: AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    runtime_cfg: &RuntimeConfig,
) -> Result<
    BellatrixBeaconState<
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
            AltairBeaconState = AltairBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
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
        >,
{
    let epoch = compute_epoch_at_slot(pre.slot, E::SLOTS_PER_EPOCH);

    // spec fork.md:61-65: set fork field.
    // previous_version = pre.fork.current_version  (was altair version)
    // current_version  = BELLATRIX_FORK_VERSION    ([New in Bellatrix])
    // epoch            = get_current_epoch(pre)
    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: pharos_utils::Bytes4::from_array(runtime_cfg.bellatrix_fork_version),
        epoch,
    };

    // spec fork.md:56-90: copy all shared fields; initialise new field.
    Ok(BellatrixBeaconState {
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
        // spec fork.md:87: [New in Bellatrix] — zero-filled ExecutionPayloadHeader.
        latest_execution_payload_header: ExecutionPayloadHeader::default(),
    })
}
