//! `process_slashings_reset` for Altair.
//!
//! Identical to phase0; operates on the concrete altair `BeaconState`.
//!
//! spec: specs/phase0/beacon-chain.md:1833-1841 (unchanged in Altair)

use pharos_ssz::SszSequence;
use pharos_types::{BeaconSpec, altair::BeaconState};
use pharos_utils::Gwei;

use crate::error::EpochProcessingError;

use super::helpers::get_current_epoch_altair;

/// `process_slashings_reset` per `specs/phase0/beacon-chain.md:1833-1841`.
///
/// Altair: identical to phase0. Zeros the slashings entry for the next
/// epoch's slot in the rolling vector.
pub fn process_slashings_reset<
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
    let next_epoch = get_current_epoch_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state)
    .0 + 1;
    let idx = (next_epoch % E::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
    state.slashings = state
        .slashings
        .with_set(idx, Gwei(0))
        .map_err(EpochProcessingError::Ssz)?;
    Ok(())
}
