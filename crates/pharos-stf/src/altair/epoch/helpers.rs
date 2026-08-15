//! Local helpers for altair epoch processing.
//!
//! These mirror the phase0 `get_current_epoch` / `get_previous_epoch` /
//! `get_block_root` accessors but operate directly on the concrete altair
//! `BeaconState` fields without the `BeaconStateView` abstraction.

use pharos_types::{EthSpec, altair::BeaconState, phase0::Epoch};

use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// Return the current epoch from an altair `BeaconState`.
pub(super) fn get_current_epoch_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: EthSpec,
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
) -> Epoch {
    compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH)
}

/// Return the previous epoch from an altair `BeaconState`.
pub(super) fn get_previous_epoch_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: EthSpec,
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
) -> Epoch {
    let current = get_current_epoch_altair::<
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
    if current.0 == 0 { Epoch(0) } else { Epoch(current.0 - 1) }
}

/// `get_block_root` for an epoch in an altair `BeaconState`.
///
/// Returns the block root at the first slot of `epoch`.
pub(super) fn get_block_root_for_epoch<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: EthSpec,
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
    if !(slot < state.slot && state.slot.0 <= slot.0 + E::SLOTS_PER_HISTORICAL_ROOT) {
        return Err(StateTransitionError::SlotOutOfRange);
    }
    let idx = (slot.0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
    Ok(state.block_roots.as_slice()[idx])
}

/// `get_randao_mix` for an epoch in an altair `BeaconState`.
///
/// Returns the randao mix at `epoch % EPOCHS_PER_HISTORICAL_VECTOR`.
pub(super) fn get_randao_mix_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: EthSpec,
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
) -> pharos_utils::Hash256 {
    let idx = (epoch.0 % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    state.randao_mixes.as_slice()[idx]
}
