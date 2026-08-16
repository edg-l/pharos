//! `process_rewards_and_penalties` for Altair.
//!
//! Modified from phase0: uses `get_flag_index_deltas` and
//! `get_inactivity_penalty_deltas` (participation-flag based).
//!
//! spec: specs/altair/beacon-chain.md:719-739

use rayon::prelude::*;

use pharos_ssz::SszSequence;
use pharos_types::{EthSpec, altair::BeaconState};
use pharos_utils::Gwei;

use crate::error::EpochProcessingError;
use crate::phase0::helpers::GENESIS_EPOCH;

use super::helpers::get_current_epoch_altair;
use crate::altair::helpers::{
    decrease_balance_altair, get_flag_index_deltas, get_inactivity_penalty_deltas,
    increase_balance_altair,
};

/// `process_rewards_and_penalties` per `specs/altair/beacon-chain.md:719-739`.
///
/// Modified in Altair. Iterates the three participation flags, accumulates
/// `get_flag_index_deltas` for each, then `get_inactivity_penalty_deltas`.
/// Uses `rayon` for parallel delta accumulation per D5.
pub fn process_rewards_and_penalties<
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
    // No rewards are applied at the end of GENESIS_EPOCH because rewards are
    // for work done in the previous epoch (spec note at line 722).
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
    if current_epoch.0 == GENESIS_EPOCH {
        return Ok(());
    }

    let n = state.validators.len();

    // Compute per-flag deltas for the three participation flags (D5: rayon).
    // Each `get_flag_index_deltas` call is independent; run them in parallel.
    let flag_deltas: Vec<(Vec<Gwei>, Vec<Gwei>)> = (0..E::PARTICIPATION_FLAG_WEIGHTS.len())
        .into_par_iter()
        .map(|flag_index| {
            get_flag_index_deltas::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                E,
            >(state, flag_index)
        })
        .collect();

    // Inactivity penalty deltas.
    let inactivity_deltas = get_inactivity_penalty_deltas::<
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

    // Aggregate rewards and penalties across all delta sources.
    let mut total_rewards = vec![Gwei(0); n];
    let mut total_penalties = vec![Gwei(0); n];

    for (rewards, penalties) in flag_deltas {
        for i in 0..n {
            total_rewards[i].0 += rewards[i].0;
            total_penalties[i].0 += penalties[i].0;
        }
    }
    {
        let (rewards, penalties) = inactivity_deltas;
        for i in 0..n {
            total_rewards[i].0 += rewards[i].0;
            total_penalties[i].0 += penalties[i].0;
        }
    }

    // Apply aggregated deltas sequentially (state mutation is not thread-safe).
    for i in 0..n {
        if total_rewards[i].0 > 0 {
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
                pharos_types::phase0::ValidatorIndex(i as u64),
                total_rewards[i],
            )?;
        }
        if total_penalties[i].0 > 0 {
            decrease_balance_altair::<
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
                pharos_types::phase0::ValidatorIndex(i as u64),
                total_penalties[i],
            )?;
        }
    }

    Ok(())
}
