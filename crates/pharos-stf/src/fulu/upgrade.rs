//! `upgrade_to_fulu` fork transition.
//!
//! Per `specs/fulu/fork.md` → `upgrade_to_fulu`.
//!
//! Converts an electra `BeaconState` into a fulu `BeaconState`:
//! 1. Copy all shared fields verbatim (all electra fields are preserved).
//! 2. Set `fork.current_version = FULU_FORK_VERSION` (EIP-7917).
//! 3. Initialize `proposer_lookahead` by calling `initialize_proposer_lookahead`
//!    which seeds the window via `compute_proposer_indices(state,
//!    state.current_epoch() + MIN_SEED_LOOKAHEAD + 1)`.
//!
//! `proposer_lookahead` is the ONLY new state field added in Fulu; everything
//! else carries over from electra without modification.

use pharos_ssz::SszVector;
use pharos_types::{
    BeaconSpec,
    config::RuntimeConfig,
    electra::BeaconState as ElectraBeaconState,
    fulu::BeaconState as FuluBeaconState,
    phase0::{Epoch, Fork, ValidatorIndex},
};

use crate::error::StateTransitionError;
use crate::fulu::helpers::get_beacon_proposer_indices;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `upgrade_to_fulu` per `specs/fulu/fork.md`.
///
/// Converts an electra `BeaconState` into a fulu `BeaconState`. The only
/// difference between the two states is the addition of `proposer_lookahead`.
#[allow(clippy::type_complexity)]
pub fn upgrade_to_fulu<
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
    const LOOKAHEAD_WINDOW: u64,
    E,
>(
    pre: ElectraBeaconState<
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
    runtime_cfg: &RuntimeConfig,
) -> Result<
    FuluBeaconState<
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
        LOOKAHEAD_WINDOW,
    >,
    StateTransitionError,
>
where
    E: BeaconSpec<
            ElectraBeaconState = ElectraBeaconState<
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
            FuluBeaconState = FuluBeaconState<
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
                LOOKAHEAD_WINDOW,
            >,
        >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    let epoch = compute_epoch_at_slot(pre.slot, E::SLOTS_PER_EPOCH);

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: pharos_utils::Bytes4::from_array(runtime_cfg.fulu_fork_version),
        epoch,
    };

    let mut post = FuluBeaconState {
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
        latest_execution_payload_header: pre.latest_execution_payload_header,
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries,
        deposit_requests_start_index: pre.deposit_requests_start_index,
        deposit_balance_to_consume: pre.deposit_balance_to_consume,
        exit_balance_to_consume: pre.exit_balance_to_consume,
        earliest_exit_epoch: pre.earliest_exit_epoch,
        consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
        earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
        pending_deposits: pre.pending_deposits,
        pending_partial_withdrawals: pre.pending_partial_withdrawals,
        pending_consolidations: pre.pending_consolidations,
        // [New in Fulu:EIP7917] seed the proposer lookahead below.
        proposer_lookahead: SszVector::from_vec(vec![
            ValidatorIndex::default();
            LOOKAHEAD_WINDOW as usize
        ])
        .map_err(StateTransitionError::Ssz)?,
        cached_root: pharos_utils::CachedRoot::default(),
    };

    // Initialize the proposer lookahead window.
    initialize_proposer_lookahead::<
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
        LOOKAHEAD_WINDOW,
        E,
    >(&mut post)?;

    Ok(post)
}

/// `initialize_proposer_lookahead` per `specs/fulu/fork.md`.
///
/// Seeds `state.proposer_lookahead` with the proposer indices for the epoch
/// `current_epoch + MIN_SEED_LOOKAHEAD + 1` (the first determinable window).
/// The window spans `LOOKAHEAD_WINDOW` slots covering `(MIN_SEED_LOOKAHEAD + 1)`
/// epochs starting from the next slot.
#[allow(clippy::type_complexity)]
pub fn initialize_proposer_lookahead<
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
    const LOOKAHEAD_WINDOW: u64,
    E,
>(
    state: &mut FuluBeaconState<
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
        LOOKAHEAD_WINDOW,
    >,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
        FuluBeaconState = FuluBeaconState<
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
            LOOKAHEAD_WINDOW,
        >,
    >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // The initial window spans (MIN_SEED_LOOKAHEAD + 1) epochs starting from the
    // epoch that is already determinable at the start of `current_epoch`.
    // `process_proposer_lookahead` fills one epoch at a time; here we fill the
    // full (MIN_SEED_LOOKAHEAD + 1) epochs in one shot.
    let mut window: Vec<ValidatorIndex> = Vec::with_capacity(LOOKAHEAD_WINDOW as usize);
    for offset in 0..=(E::MIN_SEED_LOOKAHEAD as i64) {
        let target_epoch = Epoch(current_epoch.0.saturating_add_signed(offset));
        let view = E::fulu_into_state(state.clone());
        let epoch_proposers = get_beacon_proposer_indices::<E>(&view, target_epoch);
        window.extend(epoch_proposers);
    }

    // Truncate or pad to exactly LOOKAHEAD_WINDOW entries.
    window.truncate(LOOKAHEAD_WINDOW as usize);
    while window.len() < LOOKAHEAD_WINDOW as usize {
        window.push(ValidatorIndex::default());
    }

    state.proposer_lookahead = SszVector::from_vec(window).map_err(StateTransitionError::Ssz)?;
    Ok(())
}
