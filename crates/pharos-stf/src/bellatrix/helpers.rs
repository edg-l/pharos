//! Bellatrix beacon-state helper functions.
//!
//! Per `specs/bellatrix/beacon-chain.md:288-338`.
//!
//! Bellatrix does not introduce new helper functions beyond Altair. This
//! module provides bellatrix-state-typed wrappers for helpers needed by
//! block and epoch processing, plus projection helpers that convert between
//! bellatrix and altair state (the bellatrix state is a strict superset of
//! altair state: same fields plus `latest_execution_payload_header`).

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::BeaconState as AltairBeaconState,
    bellatrix::BeaconState,
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::error::StateTransitionError;
use crate::phase0::{accessors::compute_epoch_at_slot, predicates::is_active_validator};

// ── Epoch helpers ─────────────────────────────────────────────────────────────

/// Return the current epoch for a bellatrix `BeaconState`.
pub(crate) fn get_current_epoch_bellatrix<
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
    E: BeaconSpec,
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

/// `get_total_active_balance` for a bellatrix `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:661-669`.
pub(crate) fn get_total_active_balance_bellatrix<
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
    E: BeaconSpec,
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

/// `decrease_balance` for a bellatrix `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:679-681`.
pub(crate) fn decrease_balance_bellatrix<
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
) -> Result<(), StateTransitionError> {
    let cur = state
        .balances
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
        .map_err(|_| StateTransitionError::IndexOutOfRange(index.0 as usize))?;
    Ok(())
}

// ── State-projection helpers ──────────────────────────────────────────────────

/// Project a `bellatrix::BeaconState` into an `altair::BeaconState` by
/// cloning the shared fields. `latest_execution_payload_header` is not present
/// in the altair state and is preserved in the caller's bellatrix state.
pub fn bellatrix_state_to_altair<
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
/// `bellatrix::BeaconState`. `latest_execution_payload_header` is preserved.
pub fn update_bellatrix_from_altair<
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

/// Partial update: copy by reference (for cases where we need intermediate
/// snapshots without taking ownership of the altair state).
pub(crate) fn update_bellatrix_from_altair_ref<
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

// ── Balance mutator (increase) for bellatrix state ────────────────────────────

/// `increase_balance` for a bellatrix `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:677-678`.
pub(crate) fn increase_balance_bellatrix<
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
) -> Result<(), StateTransitionError> {
    let cur = state
        .balances
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    state.balances = state
        .balances
        .with_set(index.0 as usize, Gwei(cur.0.saturating_add(delta.0)))
        .map_err(|_| StateTransitionError::IndexOutOfRange(index.0 as usize))?;
    Ok(())
}

// ── initiate_validator_exit for bellatrix state ───────────────────────────────

/// `initiate_validator_exit` for a bellatrix `BeaconState`.
///
/// Mirrors the altair implementation (`altair::helpers::initiate_validator_exit_altair_pub`)
/// but operates directly on the bellatrix state. The logic is identical since
/// Bellatrix adds no validator-registry changes; the bellatrix state shares all
/// relevant fields with the altair state.
///
/// Per `specs/phase0/beacon-chain.md:693-717`.
pub(crate) fn initiate_validator_exit_bellatrix<
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
    E: BeaconSpec,
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

// ── slash_validator for bellatrix state ───────────────────────────────────────

/// `slash_validator` for Bellatrix.
///
/// Per `specs/bellatrix/beacon-chain.md:257-276` `[Modified in Bellatrix]`.
///
/// Uses `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX` (= 32) instead of the Altair
/// value (= 64). All other logic (proposer reward, whistleblower reward,
/// slashing accumulator update) is identical to the Altair version.
///
/// spec line 273-274: `# [Modified in Bellatrix]`
///   `slashing_penalty = validator.effective_balance // MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`
pub(crate) fn slash_validator_bellatrix<
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
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
) -> Result<(), crate::error::StateTransitionError>
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
{
    use crate::altair::helpers::{PROPOSER_WEIGHT, get_proposer_index_altair};

    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    initiate_validator_exit_bellatrix::<
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
        E,
    >(state, slashed_index)?;

    let (effective_balance, current_withdrawable_epoch) = {
        let v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?;
        (v.effective_balance, v.withdrawable_epoch)
    };

    let new_withdrawable_epoch = pharos_types::phase0::Epoch(
        current_withdrawable_epoch
            .0
            .max(epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR),
    );

    {
        let mut v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?
            .clone();
        v.slashed = true;
        v.withdrawable_epoch = new_withdrawable_epoch;
        v.invalidate_cache();
        state.validators = state
            .validators
            .with_set(slashed_index.0 as usize, v)
            .map_err(crate::error::StateTransitionError::Ssz)?;
    }

    let slashing_slot = (epoch.0 % E::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
    let cur_slashing = state
        .slashings
        .get(slashing_slot)
        .copied()
        .unwrap_or(Gwei(0));
    state.slashings = state
        .slashings
        .with_set(
            slashing_slot,
            Gwei(cur_slashing.0.saturating_add(effective_balance.0)),
        )
        .map_err(crate::error::StateTransitionError::Ssz)?;

    // spec line 273-274: [Modified in Bellatrix] — use MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX.
    let penalty = Gwei(effective_balance.0 / E::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX);
    decrease_balance_bellatrix::<
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
    >(state, slashed_index, penalty)?;

    // Proposer reward: PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT).
    // Derive proposer index via projection to altair state (reads only shared fields).
    let altair_state = bellatrix_state_to_altair(state);
    let proposer_index = get_proposer_index_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair_state);

    let whistleblower_idx = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = Gwei(effective_balance.0 / E::WHISTLEBLOWER_REWARD_QUOTIENT);
    let proposer_reward = Gwei(whistleblower_reward.0 * PROPOSER_WEIGHT / E::WEIGHT_DENOMINATOR);

    increase_balance_bellatrix::<
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
    >(state, proposer_index, proposer_reward)?;
    increase_balance_bellatrix::<
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
    >(
        state,
        whistleblower_idx,
        Gwei(whistleblower_reward.0 - proposer_reward.0),
    )?;

    Ok(())
}

// ── get_inactivity_penalty_deltas for bellatrix state ─────────────────────────

/// `get_inactivity_penalty_deltas` for Bellatrix.
///
/// Per `specs/bellatrix/beacon-chain.md:222-246` `[Modified in Bellatrix]`.
///
/// Note: this function uses `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX`
/// (= 16,777,216; `2**24`) instead of `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`
/// (= 50,331,648; `3 * 2**24`), a 3× difference that lowers inactivity
/// penalties relative to Altair.
///
/// spec line 243-244: `# [Modified in Bellatrix]`
///   `penalty_denominator = INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX`
///
/// The function operates on the projected altair state (all required fields are
/// shared); it is called from `process_rewards_and_penalties_bellatrix`.
pub fn get_inactivity_penalty_deltas_bellatrix<
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
    E: BeaconSpec<
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
{
    use pharos_types::altair::constants::TIMELY_TARGET_FLAG_INDEX;

    use crate::altair::helpers::{
        get_eligible_validator_indices, get_unslashed_participating_indices,
    };

    // Project to altair state for helpers that require `AltairBeaconState`.
    let altair = bellatrix_state_to_altair(state);

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
                .get(index.0 as usize)
                .copied()
                .unwrap_or(0);
            let penalty_numerator = effective_balance * inactivity_score;
            // spec line 243-244: [Modified in Bellatrix] — use INACTIVITY_PENALTY_QUOTIENT_BELLATRIX.
            let penalty_denominator =
                E::INACTIVITY_SCORE_BIAS * E::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
            penalties[index.0 as usize].0 += penalty_numerator / penalty_denominator;
        }
    }

    (rewards, penalties)
}
