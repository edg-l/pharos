//! Altair beacon-state helpers and mutators.
//!
//! Implements all helper functions from `specs/altair/beacon-chain.md` that do
//! not belong to a specific operation file.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::{
        BeaconState, SyncCommittee,
        constants::{ParticipationFlags, TIMELY_TARGET_FLAG_INDEX},
    },
    phase0::{AttestationData, Epoch, ValidatorIndex},
};
use pharos_utils::{BLSPubkey, Gwei};

use crate::error::StateTransitionError;
use crate::phase0::{
    accessors::compute_epoch_at_slot,
    helpers::{FAR_FUTURE_EPOCH, integer_squareroot, uint_to_bytes},
    predicates::is_active_validator,
    shuffling::compute_shuffled_index,
};

// ── Domain constants ──────────────────────────────────────────────────────────

/// `DOMAIN_SYNC_COMMITTEE` per `specs/altair/beacon-chain.md:97`.
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

/// `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` per `specs/altair/beacon-chain.md`.
///
/// Used to sign sync-committee selection proofs. Value `0x08000000`.
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: [u8; 4] = [0x08, 0x00, 0x00, 0x00];

/// `DOMAIN_CONTRIBUTION_AND_PROOF` per `specs/altair/beacon-chain.md`.
///
/// Used to sign `ContributionAndProof` messages. Value `0x09000000`.
pub const DOMAIN_CONTRIBUTION_AND_PROOF: [u8; 4] = [0x09, 0x00, 0x00, 0x00];

/// `SYNC_REWARD_WEIGHT` per `specs/altair/beacon-chain.md:87`.
pub const SYNC_REWARD_WEIGHT: u64 = 2;

/// `PROPOSER_WEIGHT` per `specs/altair/beacon-chain.md:88`.
pub const PROPOSER_WEIGHT: u64 = 8;

// ── Flag helpers ──────────────────────────────────────────────────────────────

/// `add_flag` per `specs/altair/beacon-chain.md:224-229`.
///
/// Returns a new `ParticipationFlags` with `flag_index` set.
pub fn add_flag(flags: ParticipationFlags, flag_index: usize) -> ParticipationFlags {
    let flag: ParticipationFlags = 1 << flag_index;
    flags | flag
}

/// `has_flag` per `specs/altair/beacon-chain.md:235-240`.
///
/// Returns `true` when `flag_index` is set in `flags`.
pub fn has_flag(flags: ParticipationFlags, flag_index: usize) -> bool {
    let flag: ParticipationFlags = 1 << flag_index;
    flags & flag == flag
}

// ── Participation flag index helpers ─────────────────────────────────────────

/// `get_attestation_participation_flag_indices` per
/// `specs/altair/beacon-chain.md:358-393`.
///
/// Returns the list of flag indices satisfied by the attestation given its
/// `inclusion_delay` (= `state.slot - data.slot`).
pub fn get_attestation_participation_flag_indices<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    data: &AttestationData,
    inclusion_delay: u64,
    // EIP-7045 (Deneb): when `true`, the `TIMELY_TARGET_FLAG_INDEX` condition
    // drops its `inclusion_delay <= SLOTS_PER_EPOCH` gate (the target flag is
    // set for any matching target regardless of inclusion distance). Altair /
    // Bellatrix / Capella pass `false`.
    eip7045_target_flag: bool,
) -> Result<Vec<usize>, StateTransitionError>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    // Matching source
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    let justified_checkpoint = if data.target.epoch == current_epoch {
        &state.current_justified_checkpoint
    } else {
        &state.previous_justified_checkpoint
    };
    let is_matching_source = &data.source == justified_checkpoint;

    // Matching target
    let target_root = get_block_root_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, data.target.epoch)?;
    let is_matching_target = is_matching_source && data.target.root == target_root;

    // Matching head
    let head_root = get_block_root_at_slot_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, data.slot)?;
    let is_matching_head = is_matching_target && data.beacon_block_root == head_root;

    if !is_matching_source {
        return Err(StateTransitionError::InvalidAttestation {
            reason: crate::error::AttestationInvalidReason::InvalidSourceCheckpoint,
        });
    }

    let mut flag_indices = Vec::new();
    // TIMELY_SOURCE_FLAG_INDEX = 0
    if is_matching_source && inclusion_delay <= integer_squareroot(E::SLOTS_PER_EPOCH) {
        flag_indices.push(pharos_types::altair::constants::TIMELY_SOURCE_FLAG_INDEX);
    }
    // TIMELY_TARGET_FLAG_INDEX = 1
    // [Modified in Deneb:EIP7045] the inclusion-delay gate is dropped for the
    // target flag when `eip7045_target_flag` is set.
    if is_matching_target && (eip7045_target_flag || inclusion_delay <= E::SLOTS_PER_EPOCH) {
        flag_indices.push(pharos_types::altair::constants::TIMELY_TARGET_FLAG_INDEX);
    }
    // TIMELY_HEAD_FLAG_INDEX = 2
    if is_matching_head && inclusion_delay == E::MIN_ATTESTATION_INCLUSION_DELAY {
        flag_indices.push(pharos_types::altair::constants::TIMELY_HEAD_FLAG_INDEX);
    }

    Ok(flag_indices)
}

// ── Altair-local block-root helpers ──────────────────────────────────────────
//
// These mirror `get_block_root` / `get_block_root_at_slot` from phase0 but
// operate on the concrete altair `BeaconState` (which does not implement
// `E::BeaconState` for `E: BeaconSpec`; the accessors from phase0 take
// `&E::BeaconState`). Rather than threading new trait bounds everywhere,
// we inline the trivial index lookups here.

fn get_block_root_at_slot_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    slot: pharos_types::phase0::Slot,
) -> Result<pharos_types::phase0::Root, StateTransitionError> {
    if !(slot < state.slot && state.slot.0 <= slot.0 + E::SLOTS_PER_HISTORICAL_ROOT) {
        return Err(StateTransitionError::SlotOutOfRange);
    }
    let idx = (slot.0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
    state
        .block_roots
        .get(idx)
        .copied()
        .ok_or(StateTransitionError::SlotOutOfRange)
}

fn get_block_root_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    epoch: Epoch,
) -> Result<pharos_types::phase0::Root, StateTransitionError> {
    let slot = pharos_types::phase0::Slot(epoch.0 * E::SLOTS_PER_EPOCH);
    get_block_root_at_slot_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, slot)
}

// ── Participating indices ─────────────────────────────────────────────────────

/// `get_unslashed_participating_indices` per
/// `specs/altair/beacon-chain.md:338-353`.
///
/// Returns validators that are active, not slashed, and have `flag_index` set
/// in their epoch participation for the given `epoch` (current or previous).
pub fn get_unslashed_participating_indices<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    flag_index: usize,
    epoch: Epoch,
) -> Vec<ValidatorIndex>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // Reference the SszList directly (not a slice) so `.get(i)` works on both
    // the Naive and Tree backends — `as_slice()` panics on the tree backend.
    let epoch_participation = if epoch == current_epoch {
        &state.current_epoch_participation
    } else {
        &state.previous_epoch_participation
    };

    state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if is_active_validator(v, epoch.0)
                && has_flag(epoch_participation.get(i).copied().unwrap_or(0), flag_index)
                && !v.slashed
            {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect()
}

// ── Base reward ───────────────────────────────────────────────────────────────

/// `get_base_reward_per_increment` per `specs/altair/beacon-chain.md:307-315`.
pub fn get_base_reward_per_increment<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> Gwei
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let total_active = get_total_active_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);
    let sqrt_total = integer_squareroot(total_active.0);
    Gwei(E::EFFECTIVE_BALANCE_INCREMENT * E::BASE_REWARD_FACTOR / sqrt_total)
}

/// `get_base_reward` per `specs/altair/beacon-chain.md:319-333`.
pub fn get_base_reward<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    index: ValidatorIndex,
) -> Gwei
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let increments = state
        .validators
        .get(index.0 as usize)
        .map(|v| v.effective_balance.0 / E::EFFECTIVE_BALANCE_INCREMENT)
        .unwrap_or(0);
    let brpi = get_base_reward_per_increment::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);
    Gwei(increments * brpi.0)
}

// ── Eligible validator indices (for epoch processing) ────────────────────────

/// `get_eligible_validator_indices` per `specs/altair/beacon-chain.md`.
///
/// Active in the previous epoch OR slashed and between exit epoch and
/// withdrawable epoch.
pub fn get_eligible_validator_indices<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> Vec<ValidatorIndex>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let previous_epoch = if current_epoch.0 == 0 {
        Epoch(0)
    } else {
        Epoch(current_epoch.0 - 1)
    };

    state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            let active_prev = is_active_validator(v, previous_epoch.0);
            let slashed_in_window = v.slashed && previous_epoch.0 + 1 < v.withdrawable_epoch.0;
            if active_prev || slashed_in_window {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect()
}

/// `is_in_inactivity_leak` per `specs/phase0/beacon-chain.md:1578-1580`.
///
/// Inherited unchanged in Altair. True when the finality delay (previous epoch
/// minus finalized checkpoint epoch) exceeds `MIN_EPOCHS_TO_INACTIVITY_PENALTY`.
///
/// `get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY`
/// where `get_finality_delay(state) = get_previous_epoch(state) - state.finalized_checkpoint.epoch`
pub fn is_in_inactivity_leak<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> bool
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let previous_epoch = if current_epoch.0 == 0 {
        Epoch(0)
    } else {
        Epoch(current_epoch.0 - 1)
    };
    let finality_delay = previous_epoch
        .0
        .saturating_sub(state.finalized_checkpoint.epoch.0);
    finality_delay > E::MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

// ── Altair-local balance helpers ──────────────────────────────────────────────

pub(crate) fn get_total_balance_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    indices: &[ValidatorIndex],
) -> Gwei {
    let sum: u64 = indices
        .iter()
        .map(|i| {
            state
                .validators
                .get(i.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0)
        })
        .sum();
    Gwei(sum.max(E::EFFECTIVE_BALANCE_INCREMENT))
}

pub(crate) fn get_total_active_balance_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> Gwei {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    // Fused active-filter + balance-sum in a single index-ordered pass: avoids
    // collecting an intermediate `Vec<ValidatorIndex>` and the per-index tree
    // re-descent in `get_total_balance_altair`. Identical addends in identical
    // (ascending index) order, so the sum is bit-identical.
    let sum: u64 = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, current_epoch.0))
        .map(|v| v.effective_balance.0)
        .sum();
    Gwei(sum.max(E::EFFECTIVE_BALANCE_INCREMENT))
}

// ── Epoch deltas ──────────────────────────────────────────────────────────────

/// `get_flag_index_deltas` per `specs/altair/beacon-chain.md:396-424`.
pub fn get_flag_index_deltas<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    flag_index: usize,
) -> (Vec<Gwei>, Vec<Gwei>)
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let n = state.validators.len();
    let mut rewards = vec![Gwei(0); n];
    let mut penalties = vec![Gwei(0); n];

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let previous_epoch = if current_epoch.0 == 0 {
        Epoch(0)
    } else {
        Epoch(current_epoch.0 - 1)
    };

    let unslashed = get_unslashed_participating_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, flag_index, previous_epoch);

    let weight = E::PARTICIPATION_FLAG_WEIGHTS[flag_index];

    let unslashed_balance = get_total_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, &unslashed);

    let unslashed_increments = unslashed_balance.0 / E::EFFECTIVE_BALANCE_INCREMENT;

    let total_active = get_total_active_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);
    let active_increments = total_active.0 / E::EFFECTIVE_BALANCE_INCREMENT;

    // `base_reward_per_increment` is loop-invariant within this delta
    // computation (state is not mutated), so derive it from the already-computed
    // `total_active` instead of having `get_base_reward` rescan all validators
    // per index. `brpi = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR /
    // isqrt(total_active)` matches `get_base_reward_per_increment` exactly.
    let brpi =
        E::EFFECTIVE_BALANCE_INCREMENT * E::BASE_REWARD_FACTOR / integer_squareroot(total_active.0);

    let in_leak = is_in_inactivity_leak::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);

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
    >(state);

    let unslashed_set: std::collections::HashSet<u64> = unslashed.iter().map(|v| v.0).collect();

    for index in &eligible {
        let i = index.0 as usize;
        // Inline `get_base_reward` using the hoisted `brpi`: identical to
        // `Gwei(effective_balance_increments * brpi)`.
        let effective_balance_increments = state
            .validators
            .get(i)
            .map(|v| v.effective_balance.0 / E::EFFECTIVE_BALANCE_INCREMENT)
            .unwrap_or(0);
        let base_reward = Gwei(effective_balance_increments * brpi);
        if unslashed_set.contains(&index.0) {
            if !in_leak {
                let reward_numerator = base_reward.0 * weight * unslashed_increments;
                rewards[i].0 += reward_numerator / (active_increments * E::WEIGHT_DENOMINATOR);
            }
        } else if flag_index != pharos_types::altair::constants::TIMELY_HEAD_FLAG_INDEX {
            penalties[i].0 += base_reward.0 * weight / E::WEIGHT_DENOMINATOR;
        }
    }

    (rewards, penalties)
}

/// `get_inactivity_penalty_deltas` per `specs/altair/beacon-chain.md:430-447`.
pub fn get_inactivity_penalty_deltas<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> (Vec<Gwei>, Vec<Gwei>)
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
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
    >(state, TIMELY_TARGET_FLAG_INDEX, previous_epoch);

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
    >(state);

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
            let penalty_denominator =
                E::INACTIVITY_SCORE_BIAS * E::INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
            penalties[index.0 as usize].0 += penalty_numerator / penalty_denominator;
        }
    }

    (rewards, penalties)
}

// ── Sync committee selection ──────────────────────────────────────────────────

/// `get_next_sync_committee_indices` per `specs/altair/beacon-chain.md:263-287`.
pub fn get_next_sync_committee_indices<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> Vec<ValidatorIndex>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let epoch = Epoch(current_epoch.0 + 1);

    let active_indices: Vec<ValidatorIndex> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if is_active_validator(v, epoch.0) {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect();

    let active_count = active_indices.len() as u64;
    if active_count == 0 {
        return Vec::new();
    }

    // Use DOMAIN_SYNC_COMMITTEE for seed.
    let seed = get_seed_altair_pub::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, epoch, DOMAIN_SYNC_COMMITTEE);

    let max_random_byte: u64 = 255;
    let mut sync_committee_indices: Vec<ValidatorIndex> = Vec::new();
    let mut i: u64 = 0;

    while (sync_committee_indices.len() as u64) < E::SYNC_COMMITTEE_SIZE {
        let shuffled_index = compute_shuffled_index(
            i % active_count,
            active_count,
            &seed,
            E::SHUFFLE_ROUND_COUNT,
        );
        let candidate_index = active_indices[shuffled_index as usize];
        let random_byte = {
            let mut hash_input = seed.as_slice().to_vec();
            hash_input.extend_from_slice(&uint_to_bytes(i / 32));
            let h = pharos_utils::hash::hash(&hash_input);
            h.as_slice()[(i % 32) as usize] as u64
        };
        let effective_balance = state
            .validators
            .get(candidate_index.0 as usize)
            .map(|v| v.effective_balance.0)
            .unwrap_or(0);
        if effective_balance * max_random_byte >= E::MAX_EFFECTIVE_BALANCE * random_byte {
            sync_committee_indices.push(candidate_index);
        }
        i += 1;
    }

    sync_committee_indices
}

/// `get_next_sync_committee` per `specs/altair/beacon-chain.md:297-304`.
pub fn get_next_sync_committee<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> Result<SyncCommittee<SYNC_COMMITTEE_SIZE>, StateTransitionError>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
    BLSPubkey: Default + Clone,
{
    let indices = get_next_sync_committee_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);

    let pubkeys: Vec<BLSPubkey> = indices
        .iter()
        .map(|idx| {
            state
                .validators
                .get(idx.0 as usize)
                .map(|v| v.pubkey)
                .unwrap_or_default()
        })
        .collect();

    let aggregate_pubkey = pharos_utils::bls::aggregate_pubkeys(&pubkeys)
        .map_err(|_| StateTransitionError::InvalidBlockSignature)?;

    let pubkeys_vec: pharos_ssz::SszVector<BLSPubkey, SYNC_COMMITTEE_SIZE> =
        pharos_ssz::SszVector::from_vec(pubkeys).map_err(StateTransitionError::Ssz)?;

    Ok(SyncCommittee {
        pubkeys: pubkeys_vec,
        aggregate_pubkey,
    })
}

// ── get_seed for altair state ─────────────────────────────────────────────────
//
// Mirrors `get_seed` from phase0 accessors but operates on the concrete altair
// `BeaconState` fields directly (no `BeaconStateView` bound on altair state).

pub(crate) fn get_seed_altair_pub<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    epoch: Epoch,
    domain_type: [u8; 4],
) -> pharos_utils::Hash256 {
    let mix_epoch_raw = epoch
        .0
        .wrapping_add(E::EPOCHS_PER_HISTORICAL_VECTOR)
        .wrapping_sub(E::MIN_SEED_LOOKAHEAD)
        .wrapping_sub(1);
    let mix_idx = (mix_epoch_raw % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    let mix = state.randao_mixes.get(mix_idx).copied().unwrap_or_default();
    let epoch_bytes = uint_to_bytes(epoch.0);
    let mut input = [0u8; 4 + 8 + 32];
    input[..4].copy_from_slice(&domain_type);
    input[4..12].copy_from_slice(&epoch_bytes);
    input[12..].copy_from_slice(mix.as_slice());
    pharos_utils::hash::hash(&input)
}

// ── slash_validator (altair version) ─────────────────────────────────────────

/// `slash_validator` (modified in Altair) per `specs/altair/beacon-chain.md:459-487`.
///
/// Uses `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR` and `PROPOSER_WEIGHT` for
/// the proposer reward fraction (instead of phase0's `PROPOSER_REWARD_QUOTIENT`).
pub fn slash_validator<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // initiate_validator_exit operates on the altair state via direct field access.
    initiate_validator_exit_altair_pub::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, slashed_index)?;

    let (effective_balance, current_withdrawable_epoch) = {
        let v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
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
            .ok_or(StateTransitionError::SlotOutOfRange)?
            .clone();
        v.slashed = true;
        v.withdrawable_epoch = new_withdrawable_epoch;
        v.invalidate_cache();
        state.validators = state
            .validators
            .with_set(slashed_index.0 as usize, v)
            .map_err(StateTransitionError::Ssz)?;
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
        .map_err(StateTransitionError::Ssz)?;

    // Altair: penalty uses MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR.
    let penalty = Gwei(effective_balance.0 / E::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR);
    decrease_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >(state, slashed_index, penalty)?;

    // Proposer reward: PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT).
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
    >(state);

    let whistleblower_idx = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = Gwei(effective_balance.0 / E::WHISTLEBLOWER_REWARD_QUOTIENT);
    let proposer_reward = Gwei(whistleblower_reward.0 * PROPOSER_WEIGHT / E::WEIGHT_DENOMINATOR);

    increase_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >(state, proposer_index, proposer_reward)?;
    increase_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >(
        state,
        whistleblower_idx,
        Gwei(whistleblower_reward.0 - proposer_reward.0),
    )?;

    Ok(())
}

// ── Balance mutators for altair state ────────────────────────────────────────
//
// The phase0 `increase_balance` / `decrease_balance` are generic over
// `E::BeaconState: BeaconStateWrite`. The altair inner `BeaconState` does not
// implement `BeaconStateWrite` (that trait is phase0-specific). We provide
// direct-field versions here.

pub(crate) fn increase_balance_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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

pub(crate) fn decrease_balance_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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

// ── Altair-local proposer index ───────────────────────────────────────────────

/// `get_beacon_proposer_index` for Altair state.
///
/// Promoted from `pub(crate)` to `pub` so Bellatrix `slash_validator_bellatrix`
/// can derive the proposer index from a projected altair state without
/// duplicating the computation.
pub fn get_proposer_index_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
) -> ValidatorIndex {
    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let seed_base = get_seed_altair_pub::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, epoch, crate::phase0::helpers::DOMAIN_BEACON_PROPOSER);
    let slot_bytes = uint_to_bytes(state.slot.0);
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed_base.as_slice());
    input[32..].copy_from_slice(&slot_bytes);
    let seed = pharos_utils::hash::hash(&input);

    let active_indices: Vec<ValidatorIndex> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if is_active_validator(v, epoch.0) {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect();

    let max_random_byte: u64 = 255;
    let total = active_indices.len() as u64;
    let mut i: u64 = 0;
    loop {
        let shuffled = compute_shuffled_index(i % total, total, &seed, E::SHUFFLE_ROUND_COUNT);
        let candidate = active_indices[shuffled as usize];
        let mut hash_input = seed.as_slice().to_vec();
        hash_input.extend_from_slice(&uint_to_bytes(i / 32));
        let random_byte =
            pharos_utils::hash::hash(&hash_input).as_slice()[(i % 32) as usize] as u64;
        let effective_balance = state
            .validators
            .get(candidate.0 as usize)
            .map(|v| v.effective_balance.0)
            .unwrap_or(0);
        if effective_balance * max_random_byte >= E::MAX_EFFECTIVE_BALANCE * random_byte {
            return candidate;
        }
        i += 1;
    }
}

// ── initiate_validator_exit for altair state ──────────────────────────────────

pub(crate) fn initiate_validator_exit_altair_pub<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    index: ValidatorIndex,
) -> Result<(), StateTransitionError> {
    {
        let exit_epoch_val = state
            .validators
            .get(index.0 as usize)
            .map(|v| v.exit_epoch.0);
        match exit_epoch_val {
            None => return Err(StateTransitionError::SlotOutOfRange),
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
        .ok_or(StateTransitionError::SlotOutOfRange)?;
    let withdrawable_epoch = pharos_types::phase0::Epoch(withdrawable_epoch_raw);

    let mut v = state
        .validators
        .get(index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();
    v.exit_epoch = final_exit_epoch;
    v.withdrawable_epoch = withdrawable_epoch;
    v.invalidate_cache();
    state.validators = state
        .validators
        .with_set(index.0 as usize, v)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// ── Sync-committee aggregator / subnet helpers ────────────────────────────────

/// `is_sync_committee_aggregator` per `specs/altair/validator.md:438-443`.
///
/// A validator is selected as a sync-committee aggregator when
/// `SHA256(selection_proof)[0:8] as uint64 % modulo == 0`
/// with `modulo = max(1, SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT //
/// TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)`.
///
/// The constants reduce to `modulo = max(1, subcommittee_size // 16)` where
/// `subcommittee_size = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT`.
/// For mainnet (512/4/16 = 8) and minimal (32/4/16 = 0 → 1) the modulo is
/// well-defined.
///
/// Only the selection-proof *bytes* are needed; the caller holds them as a
/// `BLSSignature` and can pass `sig.as_slice()` (or `sig.0.as_ref()`).
pub fn is_sync_committee_aggregator<E: pharos_types::BeaconSpec>(
    selection_proof_bytes: &[u8],
) -> bool {
    let modulo = std::cmp::max(
        1,
        E::SYNC_COMMITTEE_SIZE
            / E::SYNC_COMMITTEE_SUBNET_COUNT
            / E::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    );
    let hash = pharos_utils::hash::hash(selection_proof_bytes);
    let first8 = u64::from_le_bytes(hash.as_slice()[..8].try_into().unwrap_or([0u8; 8]));
    first8 % modulo == 0
}

/// `compute_subnets_for_sync_committee` per `specs/altair/validator.md:378-395`.
///
/// Returns the set of subnet IDs on which `validator_index` should broadcast
/// `SyncCommitteeMessage`s during the current slot.
///
/// Uses the *current* sync committee unless the next slot crosses a sync
/// committee period boundary, in which case the *next* committee is used.
///
/// Parameters:
/// - `current_pubkeys` / `next_pubkeys`: the full ordered pubkey slices from
///   `state.current_sync_committee.pubkeys` and `state.next_sync_committee.pubkeys`
///   respectively — available from `BeaconStateView::sync_committee_pubkeys()`.
/// - `state_slot`: `state.slot`.
/// - `validator_pubkey`: the 48-byte pubkey of the target validator.
///
/// Returns an ordered, deduplicated `Vec<u64>` of subnet indices.
pub fn compute_subnets_for_sync_committee<E: pharos_types::BeaconSpec>(
    current_pubkeys: &[[u8; 48]],
    next_pubkeys: &[[u8; 48]],
    state_slot: u64,
    validator_pubkey: &[u8; 48],
) -> Vec<u64> {
    use crate::phase0::accessors::compute_epoch_at_slot;
    use pharos_types::phase0::Slot;

    // Determine whether to use current or next sync committee per spec:
    // "if compute_sync_committee_period(get_current_epoch(state)) ==
    //     compute_sync_committee_period(compute_epoch_at_slot(Slot(state.slot + 1)))"
    let current_epoch = compute_epoch_at_slot(Slot(state_slot), E::SLOTS_PER_EPOCH);
    let next_slot_epoch = compute_epoch_at_slot(Slot(state_slot + 1), E::SLOTS_PER_EPOCH);
    let current_period = current_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    let next_period = next_slot_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    let sync_pubkeys = if current_period == next_period {
        current_pubkeys
    } else {
        next_pubkeys
    };

    let subcommittee_size = E::SYNC_COMMITTEE_SIZE / E::SYNC_COMMITTEE_SUBNET_COUNT;

    let mut subnets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for (index, pk) in sync_pubkeys.iter().enumerate() {
        if pk == validator_pubkey {
            subnets.insert(index as u64 / subcommittee_size);
        }
    }
    subnets.into_iter().collect()
}

/// `get_sync_subcommittee_pubkeys` per `specs/altair/p2p-interface.md:98-114`.
///
/// Returns the ordered pubkeys in subcommittee `subcommittee_index` for the
/// current slot (using current or next sync committee per the same period
/// transition logic as `compute_subnets_for_sync_committee`).
///
/// Parameters are the same as in `compute_subnets_for_sync_committee`.
/// Returns an empty vec for an out-of-range `subcommittee_index`.
pub fn get_sync_subcommittee_pubkeys<E: pharos_types::BeaconSpec>(
    current_pubkeys: &[[u8; 48]],
    next_pubkeys: &[[u8; 48]],
    state_slot: u64,
    subcommittee_index: u64,
) -> Vec<[u8; 48]> {
    use crate::phase0::accessors::compute_epoch_at_slot;
    use pharos_types::phase0::Slot;

    let current_epoch = compute_epoch_at_slot(Slot(state_slot), E::SLOTS_PER_EPOCH);
    let next_slot_epoch = compute_epoch_at_slot(Slot(state_slot + 1), E::SLOTS_PER_EPOCH);
    let current_period = current_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    let next_period = next_slot_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    let sync_pubkeys = if current_period == next_period {
        current_pubkeys
    } else {
        next_pubkeys
    };

    if subcommittee_index >= E::SYNC_COMMITTEE_SUBNET_COUNT {
        return vec![];
    }
    let subcommittee_size = E::SYNC_COMMITTEE_SIZE / E::SYNC_COMMITTEE_SUBNET_COUNT;
    let start = (subcommittee_index * subcommittee_size) as usize;
    let end = (start as u64 + subcommittee_size) as usize;
    sync_pubkeys.get(start..end).unwrap_or(&[]).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_flag_sets_correct_bit() {
        // TIMELY_SOURCE_FLAG_INDEX = 0
        assert_eq!(add_flag(0u8, 0), 0b0000_0001);
        // TIMELY_TARGET_FLAG_INDEX = 1
        assert_eq!(add_flag(0u8, 1), 0b0000_0010);
        // TIMELY_HEAD_FLAG_INDEX = 2
        assert_eq!(add_flag(0u8, 2), 0b0000_0100);
        // Set multiple flags
        let f = add_flag(add_flag(add_flag(0u8, 0), 1), 2);
        assert_eq!(f, 0b0000_0111);
    }

    #[test]
    fn add_flag_idempotent() {
        // Setting a flag twice produces the same result.
        let f1 = add_flag(0u8, 1);
        let f2 = add_flag(f1, 1);
        assert_eq!(f1, f2);
    }

    #[test]
    fn has_flag_reads_correct_bit() {
        // 0b0000_0011 has bits 0 and 1 set, not 2.
        let flags: u8 = 0b0000_0011;
        assert!(has_flag(flags, 0));
        assert!(has_flag(flags, 1));
        assert!(!has_flag(flags, 2));
    }

    #[test]
    fn has_flag_zero_flags() {
        assert!(!has_flag(0u8, 0));
        assert!(!has_flag(0u8, 1));
        assert!(!has_flag(0u8, 2));
    }

    #[test]
    fn add_flag_has_flag_roundtrip() {
        for flag_index in 0usize..3 {
            let flags = add_flag(0u8, flag_index);
            assert!(has_flag(flags, flag_index));
            // Other bits unset
            for other in 0usize..3 {
                if other != flag_index {
                    assert!(!has_flag(flags, other));
                }
            }
        }
    }
}
