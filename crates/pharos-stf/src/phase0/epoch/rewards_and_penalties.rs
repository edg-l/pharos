//! `process_rewards_and_penalties` and delta helpers.
//!
//! Per `specs/phase0/beacon-chain.md:1577-1735`.
//!
//! All five `get_*_deltas` functions are `pub` so the rewards conformance
//! harness (Phase 7 Task 7.4) can call each individually.

use rayon::prelude::*;

use pharos_ssz::{SszList, SszSequence};
use pharos_types::{
    BeaconStateView, EthSpec,
    phase0::{Attestation, Deltas, PendingAttestation, ValidatorIndex},
    views::BeaconBlockBodyView,
};
use pharos_utils::Gwei;

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::{
        get_attesting_indices, get_current_epoch, get_previous_epoch, get_total_active_balance,
        get_total_balance,
    },
    helpers::{GENESIS_EPOCH, integer_squareroot},
    mutators::{decrease_balance, increase_balance},
    predicates::is_active_validator,
    state_write::BeaconStateWrite,
};

use super::helpers::{
    get_matching_head_attestations, get_matching_source_attestations,
    get_matching_target_attestations, get_unslashed_attesting_indices,
};

// ── Small spec helpers ─────────────────────────────────────────────────────────

/// `get_base_reward` per `specs/phase0/beacon-chain.md:1577-1584`.
fn get_base_reward<E: EthSpec>(state: &E::BeaconState, index: ValidatorIndex) -> u64 {
    let total_balance = get_total_active_balance::<E>(state).0;
    let effective_balance = state
        .validators()
        .get(index.0 as usize)
        .map(|v| v.effective_balance.0)
        .unwrap_or(0);
    effective_balance * E::BASE_REWARD_FACTOR
        / integer_squareroot(total_balance)
        / E::BASE_REWARDS_PER_EPOCH
}

/// `get_proposer_reward` per `specs/phase0/beacon-chain.md:1587-1589`.
fn get_proposer_reward<E: EthSpec>(state: &E::BeaconState, attesting_index: ValidatorIndex) -> u64 {
    get_base_reward::<E>(state, attesting_index) / E::PROPOSER_REWARD_QUOTIENT
}

/// `get_finality_delay` per `specs/phase0/beacon-chain.md:1593-1594`.
fn get_finality_delay<E: EthSpec>(state: &E::BeaconState) -> u64 {
    let prev = get_previous_epoch::<E>(state).0;
    let finalized = state.finalized_checkpoint().epoch.0;
    prev.saturating_sub(finalized)
}

/// `is_in_inactivity_leak` per `specs/phase0/beacon-chain.md:1597-1598`.
fn is_in_inactivity_leak<E: EthSpec>(state: &E::BeaconState) -> bool {
    get_finality_delay::<E>(state) > E::MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

/// `get_eligible_validator_indices` per `specs/phase0/beacon-chain.md:1601-1609`.
fn get_eligible_validator_indices<E: EthSpec>(state: &E::BeaconState) -> Vec<ValidatorIndex> {
    let previous_epoch = get_previous_epoch::<E>(state);
    state
        .validators()
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            let is_active = is_active_validator(v, previous_epoch.0);
            let is_slashed_not_withdrawn =
                v.slashed && previous_epoch.0 + 1 < v.withdrawable_epoch.0;
            if is_active || is_slashed_not_withdrawn {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect()
}

// ── attestation component deltas ──────────────────────────────────────────────

/// `get_attestation_component_deltas` per `specs/phase0/beacon-chain.md:1611-1625`.
///
/// Shared logic for source, target, and head deltas.
fn get_attestation_component_deltas<E: EthSpec>(
    state: &E::BeaconState,
    attestations: &[PendingAttestation<2048>],
) -> Result<(Vec<u64>, Vec<u64>), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let n = state.num_validators();
    let mut rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];

    let total_balance = get_total_active_balance::<E>(state);
    let unslashed: std::collections::HashSet<ValidatorIndex> =
        get_unslashed_attesting_indices::<E>(state, attestations);
    let attesting_balance = {
        let v: Vec<ValidatorIndex> = unslashed.iter().copied().collect();
        get_total_balance::<E>(state, &v)
    };

    let increment = E::EFFECTIVE_BALANCE_INCREMENT;
    let inactivity_leak = is_in_inactivity_leak::<E>(state);

    for index in get_eligible_validator_indices::<E>(state) {
        let i = index.0 as usize;
        if unslashed.contains(&index) {
            let base_reward = get_base_reward::<E>(state, index);
            if inactivity_leak {
                // In a leak: give full base reward to optimal participants.
                rewards[i] += base_reward;
            } else {
                let reward_numerator = base_reward * (attesting_balance.0 / increment);
                rewards[i] += reward_numerator / (total_balance.0 / increment);
            }
        } else {
            penalties[i] += get_base_reward::<E>(state, index);
        }
    }

    Ok((rewards, penalties))
}

// ── Public delta functions ─────────────────────────────────────────────────────

/// `get_source_deltas` per `specs/phase0/beacon-chain.md:1627-1634`.
pub fn get_source_deltas<E: EthSpec>(
    state: &E::BeaconState,
) -> Result<Deltas<1_099_511_627_776u64>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let prev_epoch = get_previous_epoch::<E>(state);
    let atts = get_matching_source_attestations::<E>(state, prev_epoch)?;
    let (rewards, penalties) = get_attestation_component_deltas::<E>(state, &atts)?;
    build_deltas(rewards, penalties)
}

/// `get_target_deltas` per `specs/phase0/beacon-chain.md:1636-1643`.
pub fn get_target_deltas<E: EthSpec>(
    state: &E::BeaconState,
) -> Result<Deltas<1_099_511_627_776u64>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let prev_epoch = get_previous_epoch::<E>(state);
    let atts = get_matching_target_attestations::<E>(state, prev_epoch)?;
    let (rewards, penalties) = get_attestation_component_deltas::<E>(state, &atts)?;
    build_deltas(rewards, penalties)
}

/// `get_head_deltas` per `specs/phase0/beacon-chain.md:1645-1652`.
pub fn get_head_deltas<E: EthSpec>(
    state: &E::BeaconState,
) -> Result<Deltas<1_099_511_627_776u64>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let prev_epoch = get_previous_epoch::<E>(state);
    let atts = get_matching_head_attestations::<E>(state, prev_epoch)?;
    let (rewards, penalties) = get_attestation_component_deltas::<E>(state, &atts)?;
    build_deltas(rewards, penalties)
}

/// `get_inclusion_delay_deltas` per `specs/phase0/beacon-chain.md:1654-1675`.
pub fn get_inclusion_delay_deltas<E: EthSpec>(
    state: &E::BeaconState,
) -> Result<Deltas<1_099_511_627_776u64>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let n = state.num_validators();
    let mut rewards = vec![0u64; n];
    let penalties = vec![0u64; n];

    let prev_epoch = get_previous_epoch::<E>(state);
    let matching_source = get_matching_source_attestations::<E>(state, prev_epoch)?;

    let unslashed = get_unslashed_attesting_indices::<E>(state, &matching_source);

    for index in unslashed {
        // Find the attestation with the smallest inclusion_delay for this validator.
        let best_att = matching_source
            .iter()
            .filter(|a| {
                get_attesting_indices::<E>(state, &a.data, &a.aggregation_bits).contains(&index)
            })
            .min_by_key(|a| a.inclusion_delay.0);

        if let Some(att) = best_att {
            let proposer_reward = get_proposer_reward::<E>(state, index);
            let proposer_i = att.proposer_index.0 as usize;
            if proposer_i < n {
                rewards[proposer_i] += proposer_reward;
            }
            let base_reward = get_base_reward::<E>(state, index);
            let max_attester_reward = base_reward.saturating_sub(proposer_reward);
            let delay = att.inclusion_delay.0.max(1);
            let i = index.0 as usize;
            if i < n {
                rewards[i] += max_attester_reward / delay;
            }
        }
    }

    build_deltas(rewards, penalties)
}

/// `get_inactivity_penalty_deltas` per `specs/phase0/beacon-chain.md:1677-1700`.
pub fn get_inactivity_penalty_deltas<E: EthSpec>(
    state: &E::BeaconState,
) -> Result<Deltas<1_099_511_627_776u64>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let n = state.num_validators();
    let rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];

    if is_in_inactivity_leak::<E>(state) {
        let prev_epoch = get_previous_epoch::<E>(state);
        let matching_target = get_matching_target_attestations::<E>(state, prev_epoch)?;
        let matching_target_attesting =
            get_unslashed_attesting_indices::<E>(state, &matching_target);

        let finality_delay = get_finality_delay::<E>(state);

        for index in get_eligible_validator_indices::<E>(state) {
            let i = index.0 as usize;
            let base_reward = get_base_reward::<E>(state, index);
            let proposer_reward = get_proposer_reward::<E>(state, index);
            // Every eligible validator loses: BASE_REWARDS_PER_EPOCH * base_reward - proposer_reward.
            penalties[i] += E::BASE_REWARDS_PER_EPOCH * base_reward - proposer_reward;
            if !matching_target_attesting.contains(&index) {
                let effective_balance = state
                    .validators()
                    .get(i)
                    .map(|v| v.effective_balance.0)
                    .unwrap_or(0);
                penalties[i] += effective_balance * finality_delay / E::INACTIVITY_PENALTY_QUOTIENT;
            }
        }
    }

    build_deltas(rewards, penalties)
}

// ── Internal combiner ─────────────────────────────────────────────────────────

fn build_deltas(
    rewards: Vec<u64>,
    penalties: Vec<u64>,
) -> Result<Deltas<1_099_511_627_776u64>, EpochProcessingError> {
    let rewards_list = SszList::from_vec(rewards.into_iter().map(Gwei).collect())
        .map_err(EpochProcessingError::Ssz)?;
    let penalties_list = SszList::from_vec(penalties.into_iter().map(Gwei).collect())
        .map_err(EpochProcessingError::Ssz)?;
    Ok(Deltas {
        rewards: rewards_list,
        penalties: penalties_list,
    })
}

// ── get_attestation_deltas ────────────────────────────────────────────────────

fn get_attestation_deltas<E: EthSpec>(
    state: &E::BeaconState,
) -> Result<(Vec<u64>, Vec<u64>), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let n = state.num_validators();

    let source = get_source_deltas::<E>(state)?;
    let target = get_target_deltas::<E>(state)?;
    let head = get_head_deltas::<E>(state)?;
    let inclusion = get_inclusion_delay_deltas::<E>(state)?;
    let inactivity = get_inactivity_penalty_deltas::<E>(state)?;

    // Compute per-validator (reward, penalty) in parallel, then collect.
    let deltas: Vec<(u64, u64)> = (0..n)
        .into_par_iter()
        .map(|i| {
            let reward = source.rewards.get(i).copied().unwrap_or(Gwei(0)).0
                + target.rewards.get(i).copied().unwrap_or(Gwei(0)).0
                + head.rewards.get(i).copied().unwrap_or(Gwei(0)).0
                + inclusion.rewards.get(i).copied().unwrap_or(Gwei(0)).0;
            let penalty = source.penalties.get(i).copied().unwrap_or(Gwei(0)).0
                + target.penalties.get(i).copied().unwrap_or(Gwei(0)).0
                + head.penalties.get(i).copied().unwrap_or(Gwei(0)).0
                + inactivity.penalties.get(i).copied().unwrap_or(Gwei(0)).0;
            (reward, penalty)
        })
        .collect();

    let mut rewards = vec![0u64; n];
    let mut penalties = vec![0u64; n];
    for (i, (r, p)) in deltas.into_iter().enumerate() {
        rewards[i] = r;
        penalties[i] = p;
    }

    Ok((rewards, penalties))
}

// ── process_rewards_and_penalties ────────────────────────────────────────────

/// `process_rewards_and_penalties` per `specs/phase0/beacon-chain.md:1737-1749`.
///
/// Sequential implementation (Phase 4). Phase 5 will add rayon parallelism.
pub fn process_rewards_and_penalties<E: EthSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    // No rewards for work done in GENESIS_EPOCH (no previous epoch existed).
    if get_current_epoch::<E>(state).0 == GENESIS_EPOCH {
        return Ok(());
    }

    let (rewards, penalties) = get_attestation_deltas::<E>(state)?;
    let n = state.num_validators();
    for i in 0..n {
        increase_balance::<E>(state, ValidatorIndex(i as u64), Gwei(rewards[i]));
        decrease_balance::<E>(state, ValidatorIndex(i as u64), Gwei(penalties[i]));
    }

    Ok(())
}
