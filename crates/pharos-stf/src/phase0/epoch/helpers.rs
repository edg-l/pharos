//! Shared helpers for epoch processing sub-routines.
//!
//! `get_matching_*`, `get_unslashed_attesting_indices`, `get_attesting_balance`
//! per `specs/phase0/beacon-chain.md:1438-1487`.

use std::collections::HashSet;

use pharos_types::{
    BeaconStateView, EthSpec,
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::{
        get_attesting_indices, get_block_root, get_block_root_at_slot, get_current_epoch,
        get_previous_epoch, get_total_balance,
    },
    state_write::BeaconStateWrite,
};
use pharos_types::phase0::Attestation;
use pharos_types::views::BeaconBlockBodyView;

/// `get_matching_source_attestations` per
/// `specs/phase0/beacon-chain.md:1438-1448`.
pub fn get_matching_source_attestations<E: EthSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
) -> Result<Vec<pharos_types::phase0::PendingAttestation<2048>>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let current_epoch = get_current_epoch::<E>(state);
    let previous_epoch = get_previous_epoch::<E>(state);

    if epoch == current_epoch {
        Ok(state.current_epoch_attestations())
    } else if epoch == previous_epoch {
        Ok(state.previous_epoch_attestations())
    } else {
        Err(EpochProcessingError::InvalidEpochForAttestation)
    }
}

/// `get_matching_target_attestations` per
/// `specs/phase0/beacon-chain.md:1450-1459`.
///
/// The Python spec evaluates `get_block_root` inside the list-comprehension
/// filter, so it is only called if `source` is non-empty. We match that
/// semantics: return an empty list immediately when there are no source
/// attestations rather than calling `get_block_root` unconditionally (which
/// would fail at slot 0 where no prior block root exists).
pub fn get_matching_target_attestations<E: EthSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
) -> Result<Vec<pharos_types::phase0::PendingAttestation<2048>>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let source = get_matching_source_attestations::<E>(state, epoch)?;
    if source.is_empty() {
        return Ok(vec![]);
    }
    let block_root = get_block_root::<E>(state, epoch)
        .map_err(|_| EpochProcessingError::BlockRootUnavailable)?;
    Ok(source
        .into_iter()
        .filter(|a| a.data.target.root == block_root)
        .collect())
}

/// `get_matching_head_attestations` per
/// `specs/phase0/beacon-chain.md:1461-1470`.
pub fn get_matching_head_attestations<E: EthSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
) -> Result<Vec<pharos_types::phase0::PendingAttestation<2048>>, EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let target = get_matching_target_attestations::<E>(state, epoch)?;
    let mut result = Vec::new();
    for a in target {
        let slot_root = get_block_root_at_slot::<E>(state, a.data.slot)
            .map_err(|_| EpochProcessingError::BlockRootUnavailable)?;
        if a.data.beacon_block_root == slot_root {
            result.push(a);
        }
    }
    Ok(result)
}

/// `get_unslashed_attesting_indices` per
/// `specs/phase0/beacon-chain.md:1472-1481`.
pub fn get_unslashed_attesting_indices<E: EthSpec>(
    state: &E::BeaconState,
    attestations: &[pharos_types::phase0::PendingAttestation<2048>],
) -> HashSet<ValidatorIndex>
where
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let mut output: HashSet<ValidatorIndex> = HashSet::new();
    for a in attestations {
        let indices = get_attesting_indices::<E>(state, &a.data, &a.aggregation_bits);
        for idx in indices {
            output.insert(idx);
        }
    }
    output
        .into_iter()
        .filter(|idx| {
            state
                .validators()
                .get(idx.0 as usize)
                .map(|v| !v.slashed)
                .unwrap_or(false)
        })
        .collect()
}

/// `get_attesting_balance` per `specs/phase0/beacon-chain.md:1482-1487`.
pub fn get_attesting_balance<E: EthSpec>(
    state: &E::BeaconState,
    attestations: &[pharos_types::phase0::PendingAttestation<2048>],
) -> Gwei
where
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let indices: Vec<ValidatorIndex> = get_unslashed_attesting_indices::<E>(state, attestations)
        .into_iter()
        .collect();
    get_total_balance::<E>(state, &indices)
}
