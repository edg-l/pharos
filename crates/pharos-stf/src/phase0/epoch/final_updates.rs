//! Final updates sub-routines for Phase 0 epoch processing.
//!
//! Six trailing sub-routines per `specs/phase0/beacon-chain.md:1804-1872`:
//! 1. `process_eth1_data_reset`
//! 2. `process_effective_balance_updates`
//! 3. `process_slashings_reset`
//! 4. `process_randao_mixes_reset`
//! 5. `process_historical_roots_update`
//! 6. `process_participation_record_updates`

use rayon::prelude::*;

use pharos_ssz::TreeHash;
use pharos_types::{BeaconSpec, BeaconStateView, phase0::HistoricalBatch};
use pharos_utils::Gwei;

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::{get_current_epoch, get_randao_mix},
    state_write::BeaconStateWrite,
};

/// `process_eth1_data_reset` per `specs/phase0/beacon-chain.md:1804-1812`.
///
/// Resets `eth1_data_votes` at the end of each `EPOCHS_PER_ETH1_VOTING_PERIOD`.
pub fn process_eth1_data_reset<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let next_epoch = get_current_epoch::<E>(state).0 + 1;
    if next_epoch % E::EPOCHS_PER_ETH1_VOTING_PERIOD == 0 {
        state.clear_eth1_data_votes();
    }
    Ok(())
}

/// `process_effective_balance_updates` per `specs/phase0/beacon-chain.md:1814-1831`.
///
/// Updates effective balances with hysteresis to prevent thrashing.
pub fn process_effective_balance_updates<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let hysteresis_increment = E::EFFECTIVE_BALANCE_INCREMENT / E::HYSTERESIS_QUOTIENT;
    let downward_threshold = hysteresis_increment * E::HYSTERESIS_DOWNWARD_MULTIPLIER;
    let upward_threshold = hysteresis_increment * E::HYSTERESIS_UPWARD_MULTIPLIER;

    let n = state.num_validators();

    // Snapshot the per-validator (balance, effective_balance) pairs so the
    // parallel map below has no shared mutable access.
    let snapshot: Vec<(u64, u64)> = (0..n)
        .map(|i| {
            let balance = state.balances().get(i).copied().unwrap_or(Gwei(0)).0;
            let eff_bal = state
                .validator(i)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0);
            (balance, eff_bal)
        })
        .collect();

    // Compute new effective balances in parallel, then apply sequentially via
    // `set_validator` (BeaconStateWrite is not thread-safe).
    let updates: Vec<Option<u64>> = snapshot
        .into_par_iter()
        .map(|(balance, eff_bal)| {
            if balance + downward_threshold < eff_bal || eff_bal + upward_threshold < balance {
                let new_eff = (balance - balance % E::EFFECTIVE_BALANCE_INCREMENT)
                    .min(E::MAX_EFFECTIVE_BALANCE);
                Some(new_eff)
            } else {
                None
            }
        })
        .collect();

    for (i, maybe_new) in updates.into_iter().enumerate() {
        if let Some(new_eff) = maybe_new {
            let mut v = state
                .validator(i)
                .ok_or(EpochProcessingError::ValidatorIndexOutOfRange { index: i })?
                .clone();
            v.effective_balance = Gwei(new_eff);
            state
                .set_validator(i, v)
                .map_err(EpochProcessingError::from)?;
        }
    }

    Ok(())
}

/// `process_slashings_reset` per `specs/phase0/beacon-chain.md:1833-1841`.
///
/// Zeros the slashings entry for the next epoch's slot in the rolling vector.
pub fn process_slashings_reset<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let next_epoch = get_current_epoch::<E>(state).0 + 1;
    let idx = (next_epoch % E::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
    state
        .set_slashing(idx, Gwei(0))
        .map_err(EpochProcessingError::from)
}

/// `process_randao_mixes_reset` per `specs/phase0/beacon-chain.md:1842-1851`.
///
/// Copies the current epoch's randao mix into the next epoch's slot.
pub fn process_randao_mixes_reset<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let current_epoch = get_current_epoch::<E>(state);
    let next_epoch = current_epoch.0 + 1;
    let mix = get_randao_mix::<E>(state, current_epoch);
    let idx = (next_epoch % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    state
        .set_randao_mix(idx, mix)
        .map_err(EpochProcessingError::from)
}

/// `process_historical_roots_update` per `specs/phase0/beacon-chain.md:1854-1865`.
///
/// Appends the Merkle root of a `HistoricalBatch` every
/// `SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH` epochs.
pub fn process_historical_roots_update<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let next_epoch = get_current_epoch::<E>(state).0 + 1;
    let epochs_per_period = E::SLOTS_PER_HISTORICAL_ROOT / E::SLOTS_PER_EPOCH;
    if next_epoch % epochs_per_period == 0 {
        // Build HistoricalBatch from current block_roots and state_roots.
        // Both mainnet and minimal have the same SLOTS_PER_HISTORICAL_ROOT
        // associated with the preset, so we dispatch through E's associated type.
        // We do this by tree-hashing the sub-components, since we cannot
        // construct HistoricalBatch<E::SLOTS_PER_HISTORICAL_ROOT> in a generic
        // context without `generic_const_exprs`. Instead, compute the root
        // directly per the SSZ struct merkleization.
        //
        // HistoricalBatch has exactly two vector fields: block_roots and state_roots.
        // Its tree_hash_root = merkle_mix_in_length(hash([block_root_hash, state_root_hash])).
        // But since we have access to the full state vectors, delegate to the
        // blanket impl of HistoricalBatch by routing through the preset's concrete type.
        //
        // Mainnet: SLOTS_PER_HISTORICAL_ROOT = 8192
        // Minimal: SLOTS_PER_HISTORICAL_ROOT = 64
        //
        // Use the preset's SLOTS_PER_HISTORICAL_ROOT to choose the right variant.
        let historical_root = compute_historical_batch_root::<E>(state);
        state
            .push_historical_root(historical_root)
            .map_err(|e| match e {
                crate::error::StateTransitionError::Ssz(err) => EpochProcessingError::Ssz(err),
                _ => EpochProcessingError::ValidatorIndexOutOfRange { index: 0 },
            })?;
    }
    Ok(())
}

/// Compute the `hash_tree_root(HistoricalBatch)` from the current state.
///
/// `HistoricalBatch` is generic over `SLOTS_PER_HISTORICAL_ROOT`.
/// We construct it from the two vectors in the state, which already carry
/// the right const-generic parameter. The hack: we clone the raw slices into
/// a `HistoricalBatch` typed at the correct concrete length by reading the
/// const from `E::SLOTS_PER_HISTORICAL_ROOT` and dispatching to a pair of
/// concrete branches (8192 for mainnet, 64 for minimal). This avoids
/// `generic_const_exprs` while remaining correct.
///
/// If future presets add a new `SLOTS_PER_HISTORICAL_ROOT` value, add a new
/// branch here.
fn compute_historical_batch_root<E: BeaconSpec>(
    state: &E::BeaconState,
) -> pharos_types::phase0::Root {
    use pharos_ssz::SszVector;
    use pharos_types::phase0::Root;

    let block_roots_slice = state.block_roots();
    let state_roots_slice = state.state_roots();

    match E::SLOTS_PER_HISTORICAL_ROOT {
        8192 => {
            let block_roots: SszVector<Root, 8192> =
                SszVector::from_vec(block_roots_slice.to_vec())
                    .expect("block_roots length matches");
            let state_roots: SszVector<Root, 8192> =
                SszVector::from_vec(state_roots_slice.to_vec())
                    .expect("state_roots length matches");
            HistoricalBatch::<8192> {
                block_roots,
                state_roots,
            }
            .tree_hash_root()
        }
        64 => {
            let block_roots: SszVector<Root, 64> = SszVector::from_vec(block_roots_slice.to_vec())
                .expect("block_roots length matches");
            let state_roots: SszVector<Root, 64> = SszVector::from_vec(state_roots_slice.to_vec())
                .expect("state_roots length matches");
            HistoricalBatch::<64> {
                block_roots,
                state_roots,
            }
            .tree_hash_root()
        }
        n => unreachable!(
            "SLOTS_PER_HISTORICAL_ROOT={n}: no HistoricalBatch branch; add one to compute_historical_batch_root"
        ),
    }
}

/// `process_participation_record_updates` per
/// `specs/phase0/beacon-chain.md:1867-1872`.
///
/// Rotates current → previous; clears current.
pub fn process_participation_record_updates<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let current = state.current_epoch_attestations();
    state
        .set_previous_epoch_attestations(current)
        .map_err(EpochProcessingError::from)?;
    state.clear_current_epoch_attestations();
    Ok(())
}
