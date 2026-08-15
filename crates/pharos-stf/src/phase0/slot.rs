//! `process_slot` and `process_slots` per
//! `specs/phase0/beacon-chain.md:1396-1425`.

use pharos_ssz::TreeHash;
use pharos_types::{BeaconStateView, EthSpec, phase0::Slot, views::BeaconBlockBodyView};

use crate::error::{EpochProcessingError, StateTransitionError};
use crate::phase0::{epoch::process_epoch, state_write::BeaconStateWrite};

/// `process_slot` per `specs/phase0/beacon-chain.md:1407-1425`.
///
/// Caches state root and block root for the current slot into the circular
/// `state_roots` and `block_roots` vectors, and patches the latest block
/// header's `state_root` field when it is still zeroed (it is zeroed by
/// `process_block_header` and filled in here on the next call).
pub fn process_slot<E: EthSpec>(state: &mut E::BeaconState) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
{
    // Cache state root.
    let previous_state_root = state.tree_hash_root();
    let slot_idx = (state.slot().0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
    state.set_state_root(slot_idx, previous_state_root)?;

    // Patch latest block header if state_root is still zeroed.
    let previous_block_root =
        if state.latest_block_header().state_root == pharos_types::phase0::Root::default() {
            let mut updated = state.latest_block_header().clone();
            updated.state_root = previous_state_root;
            state.set_latest_block_header(updated.clone());
            updated.tree_hash_root()
        } else {
            state.latest_block_header().tree_hash_root()
        };

    // Cache block root.
    state.set_block_root(slot_idx, previous_block_root)?;

    Ok(())
}

/// `process_slots` per `specs/phase0/beacon-chain.md:1396-1406`.
///
/// Advances state from its current slot up to and including `target_slot`,
/// calling `process_slot` at every step and `process_epoch` at each epoch
/// boundary. After return, `state.slot() == target_slot`.
pub fn process_slots<E: EthSpec>(
    state: &mut E::BeaconState,
    target_slot: Slot,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::Phase0BeaconBlockBody:
        BeaconBlockBodyView<Attestation = pharos_types::phase0::Attestation<2048>>,
{
    if target_slot < state.slot() {
        return Err(StateTransitionError::TargetSlotNotAfterCurrent {
            current: state.slot(),
            target: target_slot,
        });
    }

    while state.slot() < target_slot {
        process_slot::<E>(state)?;
        // Process epoch on the start slot of the next epoch.
        if (state.slot().0 + 1) % E::SLOTS_PER_EPOCH == 0 {
            process_epoch::<E>(state).map_err(|e: EpochProcessingError| match e {
                EpochProcessingError::Ssz(s) => StateTransitionError::Ssz(s),
                other => StateTransitionError::EpochProcessing { reason: other },
            })?;
        }
        state.set_slot(Slot(state.slot().0 + 1));
    }

    Ok(())
}
