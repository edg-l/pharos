//! Bellatrix epoch processing.
//!
//! Per `specs/bellatrix/beacon-chain.md:419-466`.
//!
//! Bellatrix epoch processing is identical to Altair except for
//! `process_slashings`, which uses `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX`
//! (value 3) instead of `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR` (value 2).
//! All other epoch sub-routines delegate to the altair implementations via the
//! altair-state projection helpers in `helpers.rs`.

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec, altair::BeaconState as AltairBeaconState, bellatrix::BeaconState,
    phase0::ValidatorIndex,
};
use pharos_utils::{BLSPubkey, Gwei};

use crate::altair::epoch;
use crate::bellatrix::helpers::{
    bellatrix_state_to_altair, decrease_balance_bellatrix, get_current_epoch_bellatrix,
    get_inactivity_penalty_deltas_bellatrix, get_total_active_balance_bellatrix,
    increase_balance_bellatrix, update_bellatrix_from_altair, update_bellatrix_from_altair_ref,
};
use crate::error::EpochProcessingError;

/// `process_epoch` for Bellatrix.
///
/// Per `specs/bellatrix/beacon-chain.md:419-451` (identical to Altair except
/// `process_slashings` uses `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX`).
///
/// All sub-routines except `process_slashings` delegate to the altair
/// implementations via altair-state projection.
pub fn process_epoch<
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
) -> Result<(), EpochProcessingError>
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
    BLSPubkey: Default + Clone,
{
    // Project bellatrix state into altair state for shared epoch sub-routines.
    let mut altair = bellatrix_state_to_altair(state);

    // spec bellatrix/beacon-chain.md:421: process_justification_and_finalization
    epoch::process_justification_and_finalization::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:422: process_inactivity_updates
    epoch::process_inactivity_updates::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:423: process_rewards_and_penalties
    // [Modified in Bellatrix] — uses INACTIVITY_PENALTY_QUOTIENT_BELLATRIX per
    // beacon-chain.md:222-246. Operates on the bellatrix state directly.
    // Sync altair-mutated fields (justification, inactivity scores) into the
    // bellatrix state first so the rewards computation sees the updated values.
    update_bellatrix_from_altair_ref(state, &altair);
    process_rewards_and_penalties_bellatrix::<
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
    >(state)?;
    // Re-sync altair from the updated bellatrix state (rewards mutated balances).
    altair = bellatrix_state_to_altair(state);

    // spec bellatrix/beacon-chain.md:424: process_registry_updates
    epoch::process_registry_updates::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // Copy altair-mutated fields back so bellatrix slashings sees updated balances.
    update_bellatrix_from_altair_ref(state, &altair);

    // spec bellatrix/beacon-chain.md:426-445: [Modified in Bellatrix]
    // process_slashings uses PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX.
    process_slashings_bellatrix::<
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
    >(state)?;

    // Re-sync altair from bellatrix state (slashings mutated balances).
    let mut altair = bellatrix_state_to_altair(state);

    // spec bellatrix/beacon-chain.md:447: process_eth1_data_reset
    epoch::process_eth1_data_reset::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:448: process_effective_balance_updates
    epoch::process_effective_balance_updates::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:449: process_slashings_reset
    epoch::process_slashings_reset::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:450: process_randao_mixes_reset
    epoch::process_randao_mixes_reset::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:451: process_historical_roots_update
    epoch::process_historical_roots_update::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:452: process_participation_flag_updates
    epoch::process_participation_flag_updates::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // spec bellatrix/beacon-chain.md:453: process_sync_committee_updates
    epoch::process_sync_committee_updates::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut altair)?;

    // Final sync: copy all altair-mutated fields back to bellatrix state.
    update_bellatrix_from_altair(state, altair);

    Ok(())
}

/// `process_slashings` for Bellatrix.
///
/// Per `specs/bellatrix/beacon-chain.md:426-445`.
///
/// Modified from Altair: uses `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX`
/// (value 3) instead of `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR` (value 2).
/// spec line 432: `* PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` `[Modified in Bellatrix]`
pub fn process_slashings_bellatrix<
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
) -> Result<(), EpochProcessingError>
where
    E: EthSpec<
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
    let epoch = get_current_epoch_bellatrix::<
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
    >(state);

    let total_balance = get_total_active_balance_bellatrix::<
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
    >(state)
    .0;

    let total_slashings: u64 = state.slashings.as_slice().iter().map(|g| g.0).sum();

    // spec line 432: [Modified in Bellatrix] — use PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX.
    let adjusted =
        (total_slashings * E::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX).min(total_balance);

    let slashing_epoch_mid = epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR / 2;
    let n = state.validators.len();

    let slashable: Vec<(usize, u64)> = (0..n)
        .filter_map(|i| {
            let v = state.validators.as_slice().get(i)?;
            if v.slashed && slashing_epoch_mid == v.withdrawable_epoch.0 {
                Some((i, v.effective_balance.0))
            } else {
                None
            }
        })
        .collect();

    let increment = E::EFFECTIVE_BALANCE_INCREMENT;
    for (i, effective_balance) in slashable {
        let penalty_numerator = effective_balance / increment * adjusted;
        let penalty = penalty_numerator / total_balance * increment;
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
        >(state, ValidatorIndex(i as u64), Gwei(penalty));
    }

    Ok(())
}

/// `process_rewards_and_penalties` for Bellatrix.
///
/// Per `specs/bellatrix/beacon-chain.md:222-246` `[Modified in Bellatrix]`.
///
/// Identical to the Altair version except `get_inactivity_penalty_deltas` uses
/// `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` (= 16,777,216) instead of
/// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR` (= 50,331,648). The flag-index deltas
/// are unchanged.
///
/// spec line 243-244: `# [Modified in Bellatrix]`
///   `penalty_denominator = INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX`
pub fn process_rewards_and_penalties_bellatrix<
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
) -> Result<(), EpochProcessingError>
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
    BLSPubkey: Default + Clone,
{
    use rayon::prelude::*;

    use crate::altair::helpers::get_flag_index_deltas;
    use crate::phase0::helpers::GENESIS_EPOCH;

    let current_epoch = get_current_epoch_bellatrix::<
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
    >(state);

    // No rewards are applied at GENESIS_EPOCH (spec note from altair).
    if current_epoch.0 == GENESIS_EPOCH {
        return Ok(());
    }

    let n = state.validators.len();

    // Project to altair state for get_flag_index_deltas (operates on altair inner type).
    let altair = bellatrix_state_to_altair(state);

    // Compute per-flag deltas (identical to altair; flag weights are unchanged).
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
            >(&altair, flag_index)
        })
        .collect();

    // Inactivity penalty deltas — [Modified in Bellatrix]: uses
    // INACTIVITY_PENALTY_QUOTIENT_BELLATRIX per beacon-chain.md:243-244.
    let inactivity_deltas = get_inactivity_penalty_deltas_bellatrix::<
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
    >(state);

    // Aggregate all delta sources.
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

    // Apply deltas.
    for i in 0..n {
        if total_rewards[i].0 > 0 {
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
                pharos_types::phase0::ValidatorIndex(i as u64),
                total_rewards[i],
            );
        }
        if total_penalties[i].0 > 0 {
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
            >(
                state,
                pharos_types::phase0::ValidatorIndex(i as u64),
                total_penalties[i],
            );
        }
    }

    Ok(())
}
