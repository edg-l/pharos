//! `process_inactivity_updates` for Altair.
//!
//! New in Altair: bumps `inactivity_scores` for non-participating validators
//! and decays them for participants and during non-leak epochs.
//!
//! spec: specs/altair/beacon-chain.md:693-717

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    altair::{BeaconState, constants::TIMELY_TARGET_FLAG_INDEX},
};

use crate::error::EpochProcessingError;
use crate::phase0::helpers::GENESIS_EPOCH;

use super::helpers::{get_current_epoch_altair, get_previous_epoch_altair};
use crate::altair::helpers::{
    get_eligible_validator_indices, get_unslashed_participating_indices, is_in_inactivity_leak,
};

/// `process_inactivity_updates` per `specs/altair/beacon-chain.md:693-717`.
///
/// New in Altair. Maintains per-validator `inactivity_scores`:
/// - Decrements by min(1, score) for validators with `TIMELY_TARGET_FLAG_INDEX`
///   in the previous epoch.
/// - Increments by `INACTIVITY_SCORE_BIAS` for non-participants.
/// - During non-leak epochs, decrements by min(`INACTIVITY_SCORE_RECOVERY_RATE`,
///   score) for all eligible validators.
pub fn process_inactivity_updates<
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
) -> Result<(), EpochProcessingError>
where
    E: EthSpec<
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
    let current_epoch = get_current_epoch_altair::<
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

    // Skip genesis epoch: score updates are based on previous epoch participation.
    if current_epoch.0 == GENESIS_EPOCH {
        return Ok(());
    }

    let previous_epoch = get_previous_epoch_altair::<
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

    let unslashed_prev_target = get_unslashed_participating_indices::<
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

    let participating_set: std::collections::HashSet<u64> =
        unslashed_prev_target.iter().map(|v| v.0).collect();

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

    // Compute new scores from snapshot, then apply.
    let new_scores: Vec<u64> = eligible
        .iter()
        .map(|vi| {
            let i = vi.0 as usize;
            let score = state
                .inactivity_scores
                .as_slice()
                .get(i)
                .copied()
                .unwrap_or(0);
            let mut new_score = score;
            if participating_set.contains(&vi.0) {
                // Decrease by min(1, score) for active timely-target participants.
                new_score -= new_score.min(1);
            } else {
                // Increase by INACTIVITY_SCORE_BIAS for non-participants.
                new_score += E::INACTIVITY_SCORE_BIAS;
            }
            // During non-leak epochs, recover by INACTIVITY_SCORE_RECOVERY_RATE.
            if !in_leak {
                new_score -= new_score.min(E::INACTIVITY_SCORE_RECOVERY_RATE);
            }
            new_score
        })
        .collect();

    // Apply updated scores back to state.
    for (vi, new_score) in eligible.iter().zip(new_scores.iter()) {
        let i = vi.0 as usize;
        let old_score = state
            .inactivity_scores
            .as_slice()
            .get(i)
            .copied()
            .unwrap_or(0);
        if *new_score != old_score {
            state.inactivity_scores = state
                .inactivity_scores
                .with_set(i, *new_score)
                .map_err(EpochProcessingError::Ssz)?;
        }
    }

    Ok(())
}
