//! Fulu state transition function.
//!
//! Per `specs/fulu/beacon-chain.md`, `specs/fulu/fork.md`.
//!
//! Fulu is an Electra sibling (EIP-7594 PeerDAS + EIP-7917 deterministic
//! proposer lookahead + EIP-7892 blob-parameter-only forks). The only reshaped
//! container is `BeaconState` (it adds `proposer_lookahead`); everything else is
//! structurally identical to electra and the fulu STF delegates to the electra
//! per-operation impls under a fulu→electra state projection.
//!
//! The Fulu deltas are:
//! - `helpers::{compute_proposer_indices, get_beacon_proposer_indices,
//!   get_beacon_proposer_index}` — EIP-7917 deterministic proposer lookahead.
//! - `epoch::process_proposer_lookahead` — shifts the lookahead window each epoch.
//! - `operations::process_execution_payload` — EIP-7892 epoch-dependent blob limit.
//! - `operations::process_operations` / `operations::process_deposit_request` /
//!   `epoch::process_pending_deposits` — verified identical to electra at
//!   consensus-specs v1.7.0-alpha.8 (the deposit mechanism is unchanged from
//!   electra; legacy `body.deposits` are still processed); re-exported.
//! - `upgrade::upgrade_to_fulu` + `upgrade::initialize_proposer_lookahead` —
//!   electra→fulu fork transition (seeds `proposer_lookahead`, EIP-7917).
//! - `block::process_block` / `epoch::process_epoch` / `state_transition` —
//!   electra block/epoch schedule + the fulu `process_execution_payload` and
//!   `process_proposer_lookahead` deltas, run over the fulu→electra projection.
//! - `light_client` — fulu LC types ARE the electra LC types (re-exported).

pub mod block;
pub mod data_columns;
pub mod epoch;
pub mod helpers;
pub mod light_client;
pub mod operations;
pub mod state_transition;
pub mod upgrade;

#[cfg(test)]
pub(crate) mod test_support;

use pharos_types::{
    electra::BeaconState as ElectraBeaconState, fulu::BeaconState as FuluBeaconState,
};

/// Project a `fulu::BeaconState` into an `electra::BeaconState`.
///
/// The fulu state is structurally an electra state plus the EIP-7917
/// `proposer_lookahead` field; every other field is byte-identical. Dropping
/// `proposer_lookahead` yields a valid electra state, letting the electra
/// per-operation impls run unchanged. The companion `update_fulu_from_electra`
/// copies the electra-shared fields back; `proposer_lookahead` is preserved.
#[allow(clippy::type_complexity)]
pub fn fulu_state_to_electra<
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
>(
    state: &FuluBeaconState<
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
) -> ElectraBeaconState<
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
> {
    ElectraBeaconState {
        genesis_time: state.genesis_time,
        genesis_validators_root: state.genesis_validators_root,
        slot: state.slot,
        fork: state.fork.clone(),
        latest_block_header: state.latest_block_header.clone(),
        block_roots: state.block_roots.clone(),
        state_roots: state.state_roots.clone(),
        historical_roots: state.historical_roots.clone(),
        eth1_data: state.eth1_data.clone(),
        eth1_data_votes: state.eth1_data_votes.clone(),
        eth1_deposit_index: state.eth1_deposit_index,
        validators: state.validators.clone(),
        balances: state.balances.clone(),
        randao_mixes: state.randao_mixes.clone(),
        slashings: state.slashings.clone(),
        previous_epoch_participation: state.previous_epoch_participation.clone(),
        current_epoch_participation: state.current_epoch_participation.clone(),
        justification_bits: state.justification_bits.clone(),
        previous_justified_checkpoint: state.previous_justified_checkpoint.clone(),
        current_justified_checkpoint: state.current_justified_checkpoint.clone(),
        finalized_checkpoint: state.finalized_checkpoint.clone(),
        inactivity_scores: state.inactivity_scores.clone(),
        current_sync_committee: state.current_sync_committee.clone(),
        next_sync_committee: state.next_sync_committee.clone(),
        latest_execution_payload_header: state.latest_execution_payload_header.clone(),
        next_withdrawal_index: state.next_withdrawal_index,
        next_withdrawal_validator_index: state.next_withdrawal_validator_index,
        historical_summaries: state.historical_summaries.clone(),
        deposit_requests_start_index: state.deposit_requests_start_index,
        deposit_balance_to_consume: state.deposit_balance_to_consume,
        exit_balance_to_consume: state.exit_balance_to_consume,
        earliest_exit_epoch: state.earliest_exit_epoch,
        consolidation_balance_to_consume: state.consolidation_balance_to_consume,
        earliest_consolidation_epoch: state.earliest_consolidation_epoch,
        pending_deposits: state.pending_deposits.clone(),
        pending_partial_withdrawals: state.pending_partial_withdrawals.clone(),
        pending_consolidations: state.pending_consolidations.clone(),
        cached_root: pharos_utils::CachedRoot::default(),
    }
}

/// Copy the electra-shared fields from an `electra::BeaconState` back into a
/// `fulu::BeaconState`. The fulu-only `proposer_lookahead` field is preserved.
#[allow(clippy::type_complexity)]
pub fn update_fulu_from_electra<
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
    electra: ElectraBeaconState<
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
) {
    state.genesis_time = electra.genesis_time;
    state.genesis_validators_root = electra.genesis_validators_root;
    state.slot = electra.slot;
    state.fork = electra.fork;
    state.latest_block_header = electra.latest_block_header;
    state.block_roots = electra.block_roots;
    state.state_roots = electra.state_roots;
    state.historical_roots = electra.historical_roots;
    state.eth1_data = electra.eth1_data;
    state.eth1_data_votes = electra.eth1_data_votes;
    state.eth1_deposit_index = electra.eth1_deposit_index;
    state.validators = electra.validators;
    state.balances = electra.balances;
    state.randao_mixes = electra.randao_mixes;
    state.slashings = electra.slashings;
    state.previous_epoch_participation = electra.previous_epoch_participation;
    state.current_epoch_participation = electra.current_epoch_participation;
    state.justification_bits = electra.justification_bits;
    state.previous_justified_checkpoint = electra.previous_justified_checkpoint;
    state.current_justified_checkpoint = electra.current_justified_checkpoint;
    state.finalized_checkpoint = electra.finalized_checkpoint;
    state.inactivity_scores = electra.inactivity_scores;
    state.current_sync_committee = electra.current_sync_committee;
    state.next_sync_committee = electra.next_sync_committee;
    state.latest_execution_payload_header = electra.latest_execution_payload_header;
    state.next_withdrawal_index = electra.next_withdrawal_index;
    state.next_withdrawal_validator_index = electra.next_withdrawal_validator_index;
    state.historical_summaries = electra.historical_summaries;
    state.deposit_requests_start_index = electra.deposit_requests_start_index;
    state.deposit_balance_to_consume = electra.deposit_balance_to_consume;
    state.exit_balance_to_consume = electra.exit_balance_to_consume;
    state.earliest_exit_epoch = electra.earliest_exit_epoch;
    state.consolidation_balance_to_consume = electra.consolidation_balance_to_consume;
    state.earliest_consolidation_epoch = electra.earliest_consolidation_epoch;
    state.pending_deposits = electra.pending_deposits;
    state.pending_partial_withdrawals = electra.pending_partial_withdrawals;
    state.pending_consolidations = electra.pending_consolidations;
    // fulu-only: proposer_lookahead intentionally NOT overwritten.
}
