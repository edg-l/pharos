//! Capella epoch processing.
//!
//! Per `specs/capella/beacon-chain.md` Epoch processing.
//!
//! Capella epoch processing is identical to Bellatrix except:
//! - `process_historical_summaries_update` replaces `process_historical_roots_update`.
//!
//! All other sub-routines delegate to the bellatrix / altair implementations.

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    bellatrix::BeaconState as BellatrixBeaconState,
    capella::{BeaconState, operations::HistoricalSummary},
    phase0::ValidatorIndex,
};
use pharos_utils::{BLSPubkey, Gwei};

use crate::altair::epoch;
use crate::capella::helpers::{
    capella_state_to_altair, decrease_balance_capella, get_current_epoch_capella,
    get_inactivity_penalty_deltas_capella, get_total_active_balance_capella,
    increase_balance_capella, update_capella_from_altair, update_capella_from_altair_ref,
};
use crate::error::EpochProcessingError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_epoch` for Capella.
///
/// Per `specs/capella/beacon-chain.md` Epoch processing.
///
/// Identical to Bellatrix except `process_historical_summaries_update`
/// replaces `process_historical_roots_update`.
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
            CapellaBeaconState = BeaconState<
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
    // Project capella state into altair state for shared epoch sub-routines.
    let mut altair = capella_state_to_altair(state);

    // spec capella/beacon-chain.md:316: process_justification_and_finalization
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

    // spec capella/beacon-chain.md:317: process_inactivity_updates
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

    // spec capella/beacon-chain.md:318: process_rewards_and_penalties
    // [Inherited from Bellatrix] — uses INACTIVITY_PENALTY_QUOTIENT_BELLATRIX.
    update_capella_from_altair_ref(state, &altair);
    process_rewards_and_penalties_capella::<
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
    // Re-sync altair from the updated capella state.
    altair = capella_state_to_altair(state);

    // spec capella/beacon-chain.md:319: process_registry_updates
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

    // Copy altair-mutated fields back.
    update_capella_from_altair_ref(state, &altair);

    // spec capella/beacon-chain.md:320: process_slashings
    // [Inherited from Bellatrix] — uses PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX.
    process_slashings_capella::<
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
    let mut altair = capella_state_to_altair(state);

    // spec capella/beacon-chain.md:321: process_eth1_data_reset
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

    // spec capella/beacon-chain.md:322: process_effective_balance_updates
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

    // spec capella/beacon-chain.md:323: process_slashings_reset
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

    // spec capella/beacon-chain.md:324: process_randao_mixes_reset
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

    // Sync altair back into capella before process_historical_summaries_update.
    update_capella_from_altair(state, altair);

    // spec capella/beacon-chain.md:326-328: process_historical_summaries_update
    // [New in Capella] — replaces process_historical_roots_update.
    process_historical_summaries_update::<
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

    // Re-project to altair for participation and sync committee updates.
    let mut altair = capella_state_to_altair(state);

    // spec capella/beacon-chain.md:329: process_participation_flag_updates
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

    // spec capella/beacon-chain.md:330: process_sync_committee_updates
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

    // Final sync.
    update_capella_from_altair(state, altair);

    Ok(())
}

// ── process_historical_summaries_update ───────────────────────────────────────

/// `process_historical_summaries_update` per `specs/capella/beacon-chain.md`.
///
/// Appends a `HistoricalSummary` to `state.historical_summaries` when
/// `(get_current_epoch(state) + 1) % (SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH) == 0`.
///
/// Note: `historical_roots` is frozen in Capella — this function does NOT
/// append to it.
pub fn process_historical_summaries_update<
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
) -> Result<(), EpochProcessingError> {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let next_epoch = current_epoch.0 + 1;
    let period = SLOTS_PER_HISTORICAL_ROOT / E::SLOTS_PER_EPOCH;

    if next_epoch % period == 0 {
        let historical_summary = HistoricalSummary {
            block_summary_root: state.block_roots.tree_hash_root(),
            state_summary_root: state.state_roots.tree_hash_root(),
        };
        state.historical_summaries = state
            .historical_summaries
            .with_push(historical_summary)
            .map_err(EpochProcessingError::Ssz)?;
    }

    Ok(())
}

// ── process_slashings (capella) ───────────────────────────────────────────────

/// `process_slashings` for Capella.
///
/// Inherits Bellatrix's `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX`.
fn process_slashings_capella<
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
        CapellaBeaconState = BeaconState<
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
    let epoch = get_current_epoch_capella::<
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

    let total_balance = get_total_active_balance_capella::<
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

    let adjusted =
        (total_slashings * E::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX).min(total_balance);

    let slashing_epoch_mid = epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR / 2;
    let n = state.validators.len();

    let slashable: Vec<(usize, u64)> = (0..n)
        .filter_map(|i| {
            let v = state.validators.get(i)?;
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
        decrease_balance_capella::<
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

// ── process_rewards_and_penalties (capella) ───────────────────────────────────

/// `process_rewards_and_penalties` for Capella.
///
/// Identical to Bellatrix.
fn process_rewards_and_penalties_capella<
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
            CapellaBeaconState = BeaconState<
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

    let current_epoch = get_current_epoch_capella::<
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

    if current_epoch.0 == GENESIS_EPOCH {
        return Ok(());
    }

    let n = state.validators.len();
    let altair = capella_state_to_altair(state);

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

    let inactivity_deltas = get_inactivity_penalty_deltas_capella::<
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

    for i in 0..n {
        if total_rewards[i].0 > 0 {
            increase_balance_capella::<
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
            decrease_balance_capella::<
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
