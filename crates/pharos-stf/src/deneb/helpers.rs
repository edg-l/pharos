//! Deneb beacon-state helper functions.
//!
//! Per `specs/deneb/beacon-chain.md` — Helpers section.
//!
//! Deneb adds no new helpers beyond what Capella provides. This module provides
//! state projection helpers that convert between the deneb and capella inner
//! state types (deneb state is a strict superset of capella state: same fields
//! except `latest_execution_payload_header` is re-typed to the Deneb header).

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    capella::BeaconState as CapellaBeaconState,
    deneb::BeaconState,
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::phase0::{accessors::compute_epoch_at_slot, predicates::is_active_validator};

// ── State-projection helpers ──────────────────────────────────────────────────

/// Project a `deneb::BeaconState` into an `altair::BeaconState` by cloning
/// the shared fields.
///
/// `latest_execution_payload_header`, withdrawal fields, and
/// `historical_summaries` are deneb/capella-only and not present in altair.
pub fn deneb_state_to_altair<
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
) -> AltairBeaconState<
    SLOTS_PER_HISTORICAL_ROOT,
    HISTORICAL_ROOTS_LIMIT,
    ETH1_DATA_VOTES_LIMIT,
    VALIDATOR_REGISTRY_LIMIT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    JUSTIFICATION_BITS_LENGTH,
    SYNC_COMMITTEE_SIZE,
> {
    AltairBeaconState {
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
        cached_root: pharos_utils::CachedRoot::default(),
    }
}

/// Copy the shared fields from an `altair::BeaconState` back into a
/// `deneb::BeaconState`. The deneb-only fields are preserved.
pub fn update_deneb_from_altair<
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
    altair: AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) {
    state.genesis_time = altair.genesis_time;
    state.genesis_validators_root = altair.genesis_validators_root;
    state.slot = altair.slot;
    state.fork = altair.fork;
    state.latest_block_header = altair.latest_block_header;
    state.block_roots = altair.block_roots;
    state.state_roots = altair.state_roots;
    state.historical_roots = altair.historical_roots;
    state.eth1_data = altair.eth1_data;
    state.eth1_data_votes = altair.eth1_data_votes;
    state.eth1_deposit_index = altair.eth1_deposit_index;
    state.validators = altair.validators;
    state.balances = altair.balances;
    state.randao_mixes = altair.randao_mixes;
    state.slashings = altair.slashings;
    state.previous_epoch_participation = altair.previous_epoch_participation;
    state.current_epoch_participation = altair.current_epoch_participation;
    state.justification_bits = altair.justification_bits;
    state.previous_justified_checkpoint = altair.previous_justified_checkpoint;
    state.current_justified_checkpoint = altair.current_justified_checkpoint;
    state.finalized_checkpoint = altair.finalized_checkpoint;
    state.inactivity_scores = altair.inactivity_scores;
    state.current_sync_committee = altair.current_sync_committee;
    state.next_sync_committee = altair.next_sync_committee;
}

/// Partial update: copy from altair reference into deneb state.
pub(crate) fn update_deneb_from_altair_ref<
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
    altair: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) {
    state.genesis_time = altair.genesis_time;
    state.genesis_validators_root = altair.genesis_validators_root;
    state.slot = altair.slot;
    state.fork = altair.fork.clone();
    state.latest_block_header = altair.latest_block_header.clone();
    state.block_roots = altair.block_roots.clone();
    state.state_roots = altair.state_roots.clone();
    state.historical_roots = altair.historical_roots.clone();
    state.eth1_data = altair.eth1_data.clone();
    state.eth1_data_votes = altair.eth1_data_votes.clone();
    state.eth1_deposit_index = altair.eth1_deposit_index;
    state.validators = altair.validators.clone();
    state.balances = altair.balances.clone();
    state.randao_mixes = altair.randao_mixes.clone();
    state.slashings = altair.slashings.clone();
    state.previous_epoch_participation = altair.previous_epoch_participation.clone();
    state.current_epoch_participation = altair.current_epoch_participation.clone();
    state.justification_bits = altair.justification_bits.clone();
    state.previous_justified_checkpoint = altair.previous_justified_checkpoint.clone();
    state.current_justified_checkpoint = altair.current_justified_checkpoint.clone();
    state.finalized_checkpoint = altair.finalized_checkpoint.clone();
    state.inactivity_scores = altair.inactivity_scores.clone();
    state.current_sync_committee = altair.current_sync_committee.clone();
    state.next_sync_committee = altair.next_sync_committee.clone();
}

/// Project a `deneb::BeaconState` into a `capella::BeaconState`.
///
/// The `latest_execution_payload_header` is converted from Deneb to Capella
/// type by copying all shared sub-fields (drops `blob_gas_used`/`excess_blob_gas`).
/// Used to reuse capella helpers that operate on the capella state type.
pub fn deneb_state_to_capella<
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
) -> CapellaBeaconState<
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
> {
    use pharos_types::capella::execution_payload::ExecutionPayloadHeader as CapellaHeader;

    let capella_header = CapellaHeader {
        parent_hash: state.latest_execution_payload_header.parent_hash,
        fee_recipient: state.latest_execution_payload_header.fee_recipient,
        state_root: state.latest_execution_payload_header.state_root,
        receipts_root: state.latest_execution_payload_header.receipts_root,
        logs_bloom: state.latest_execution_payload_header.logs_bloom.clone(),
        prev_randao: state.latest_execution_payload_header.prev_randao,
        block_number: state.latest_execution_payload_header.block_number,
        gas_limit: state.latest_execution_payload_header.gas_limit,
        gas_used: state.latest_execution_payload_header.gas_used,
        timestamp: state.latest_execution_payload_header.timestamp,
        extra_data: state.latest_execution_payload_header.extra_data.clone(),
        base_fee_per_gas: state.latest_execution_payload_header.base_fee_per_gas,
        block_hash: state.latest_execution_payload_header.block_hash,
        transactions_root: state.latest_execution_payload_header.transactions_root,
        withdrawals_root: state.latest_execution_payload_header.withdrawals_root,
    };

    CapellaBeaconState {
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
        latest_execution_payload_header: capella_header,
        next_withdrawal_index: state.next_withdrawal_index,
        next_withdrawal_validator_index: state.next_withdrawal_validator_index,
        historical_summaries: state.historical_summaries.clone(),
        cached_root: pharos_utils::CachedRoot::default(),
    }
}

/// Copy the shared fields from a `capella::BeaconState` back into a
/// `deneb::BeaconState`. The deneb-specific `latest_execution_payload_header`
/// is NOT overwritten; call sites that mutate it via capella projection must
/// explicitly update the deneb header after this call.
///
/// Used to sync capella-projected epoch-processing results back.
pub fn update_deneb_from_capella<
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
    capella: CapellaBeaconState<
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
) {
    state.genesis_time = capella.genesis_time;
    state.genesis_validators_root = capella.genesis_validators_root;
    state.slot = capella.slot;
    state.fork = capella.fork;
    state.latest_block_header = capella.latest_block_header;
    state.block_roots = capella.block_roots;
    state.state_roots = capella.state_roots;
    state.historical_roots = capella.historical_roots;
    state.eth1_data = capella.eth1_data;
    state.eth1_data_votes = capella.eth1_data_votes;
    state.eth1_deposit_index = capella.eth1_deposit_index;
    state.validators = capella.validators;
    state.balances = capella.balances;
    state.randao_mixes = capella.randao_mixes;
    state.slashings = capella.slashings;
    state.previous_epoch_participation = capella.previous_epoch_participation;
    state.current_epoch_participation = capella.current_epoch_participation;
    state.justification_bits = capella.justification_bits;
    state.previous_justified_checkpoint = capella.previous_justified_checkpoint;
    state.current_justified_checkpoint = capella.current_justified_checkpoint;
    state.finalized_checkpoint = capella.finalized_checkpoint;
    state.inactivity_scores = capella.inactivity_scores;
    state.current_sync_committee = capella.current_sync_committee;
    state.next_sync_committee = capella.next_sync_committee;
    // capella-shared fields
    state.next_withdrawal_index = capella.next_withdrawal_index;
    state.next_withdrawal_validator_index = capella.next_withdrawal_validator_index;
    state.historical_summaries = capella.historical_summaries;
    // deneb-only: latest_execution_payload_header intentionally NOT overwritten.
}

// ── Epoch helpers ─────────────────────────────────────────────────────────────

/// Return the current epoch for a deneb `BeaconState`.
pub(crate) fn get_current_epoch_deneb<
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
    >,
) -> Epoch {
    compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH)
}

/// `get_total_active_balance` for a deneb `BeaconState`.
pub(crate) fn get_total_active_balance_deneb<
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
    >,
) -> Gwei {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let sum: u64 = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, current_epoch.0))
        .map(|v| v.effective_balance.0)
        .sum();
    Gwei(sum.max(E::EFFECTIVE_BALANCE_INCREMENT))
}

/// `decrease_balance` for a deneb `BeaconState`.
pub(crate) fn decrease_balance_deneb<
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
    index: ValidatorIndex,
    delta: Gwei,
) {
    let cur = state
        .balances
        .as_slice()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    let new_val = if delta.0 > cur.0 {
        Gwei(0)
    } else {
        Gwei(cur.0 - delta.0)
    };
    state.balances = state
        .balances
        .with_set(index.0 as usize, new_val)
        .expect("balance index in range");
}

/// `increase_balance` for a deneb `BeaconState`.
pub(crate) fn increase_balance_deneb<
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
    index: ValidatorIndex,
    delta: Gwei,
) {
    let cur = state
        .balances
        .as_slice()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    state.balances = state
        .balances
        .with_set(index.0 as usize, Gwei(cur.0.saturating_add(delta.0)))
        .expect("balance index in range");
}

// ── initiate_validator_exit (deneb) ───────────────────────────────────────────

/// `initiate_validator_exit` for a deneb `BeaconState`.
///
/// Identical to capella: operates directly on the validator registry fields.
pub(crate) fn initiate_validator_exit_deneb<
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
    E: EthSpec,
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
    index: ValidatorIndex,
) -> Result<(), crate::error::StateTransitionError> {
    use crate::phase0::helpers::FAR_FUTURE_EPOCH;

    {
        let exit_epoch_val = state
            .validators
            .get(index.0 as usize)
            .map(|v| v.exit_epoch.0);
        match exit_epoch_val {
            None => return Err(crate::error::StateTransitionError::SlotOutOfRange),
            Some(ep) if ep != FAR_FUTURE_EPOCH => return Ok(()),
            _ => {}
        }
    }

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let activation_exit_epoch =
        pharos_types::phase0::Epoch(current_epoch.0 + 1 + E::MAX_SEED_LOOKAHEAD);

    let exit_queue_epoch = {
        let max_existing = state
            .validators
            .iter()
            .filter(|v| v.exit_epoch.0 != FAR_FUTURE_EPOCH)
            .map(|v| v.exit_epoch.0)
            .max()
            .unwrap_or(0)
            .max(activation_exit_epoch.0);
        pharos_types::phase0::Epoch(max_existing)
    };

    let churn_limit = {
        let active_count = state
            .validators
            .iter()
            .filter(|v| is_active_validator(v, current_epoch.0))
            .count() as u64;
        (active_count / E::CHURN_LIMIT_QUOTIENT).max(E::MIN_PER_EPOCH_CHURN_LIMIT)
    };

    let exit_queue_churn = state
        .validators
        .iter()
        .filter(|v| v.exit_epoch == exit_queue_epoch)
        .count() as u64;

    let final_exit_epoch = if exit_queue_churn >= churn_limit {
        pharos_types::phase0::Epoch(exit_queue_epoch.0 + 1)
    } else {
        exit_queue_epoch
    };

    let withdrawable_epoch_raw = final_exit_epoch
        .0
        .checked_add(E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
        .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?;

    let mut v = state
        .validators
        .get(index.0 as usize)
        .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?
        .clone();
    v.exit_epoch = final_exit_epoch;
    v.withdrawable_epoch = pharos_types::phase0::Epoch(withdrawable_epoch_raw);
    v.invalidate_cache();
    state.validators = state
        .validators
        .with_set(index.0 as usize, v)
        .map_err(crate::error::StateTransitionError::Ssz)?;

    Ok(())
}

// ── get_inactivity_penalty_deltas (deneb) ─────────────────────────────────────

/// `get_inactivity_penalty_deltas` for Deneb.
///
/// Deneb uses `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` (unchanged from Capella).
pub fn get_inactivity_penalty_deltas_deneb<
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
) -> (Vec<Gwei>, Vec<Gwei>)
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
            DenebBeaconState = BeaconState<
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
    use pharos_types::altair::constants::TIMELY_TARGET_FLAG_INDEX;

    use crate::altair::helpers::{
        get_eligible_validator_indices, get_unslashed_participating_indices,
    };

    let altair = deneb_state_to_altair(state);
    let n = state.validators.len();
    let rewards = vec![Gwei(0); n];
    let mut penalties = vec![Gwei(0); n];

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let previous_epoch = if current_epoch.0 == 0 {
        Epoch(0)
    } else {
        Epoch(current_epoch.0 - 1)
    };

    let matching_target = get_unslashed_participating_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair, TIMELY_TARGET_FLAG_INDEX, previous_epoch);

    let matching_set: std::collections::HashSet<u64> =
        matching_target.iter().map(|v| v.0).collect();

    let eligible = get_eligible_validator_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair);

    for index in &eligible {
        if !matching_set.contains(&index.0) {
            let effective_balance = state
                .validators
                .get(index.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0);
            let inactivity_score = state
                .inactivity_scores
                .as_slice()
                .get(index.0 as usize)
                .copied()
                .unwrap_or(0);
            let penalty_numerator = effective_balance * inactivity_score;
            let penalty_denominator =
                E::INACTIVITY_SCORE_BIAS * E::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
            penalties[index.0 as usize].0 += penalty_numerator / penalty_denominator;
        }
    }

    (rewards, penalties)
}
