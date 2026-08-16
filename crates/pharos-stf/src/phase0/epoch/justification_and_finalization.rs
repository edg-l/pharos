//! `process_justification_and_finalization` per
//! `specs/phase0/beacon-chain.md:1493-1537`.
//!
//! Called by `process_epoch` and externally by `pharos-fork-choice`'s
//! `compute_pulled_up_tip` (Phase 8); hence `pub`.

use pharos_types::{
    BeaconSpec, BeaconStateView,
    phase0::{Attestation, Checkpoint},
    views::BeaconBlockBodyView,
};

use crate::error::EpochProcessingError;
use crate::phase0::{
    accessors::{get_block_root, get_current_epoch, get_previous_epoch, get_total_balance},
    helpers::GENESIS_EPOCH,
    state_write::BeaconStateWrite,
};

use super::helpers::{get_attesting_balance, get_matching_target_attestations};

/// `process_justification_and_finalization` per
/// `specs/phase0/beacon-chain.md:1493-1537`.
///
/// Skip in the first two epochs (genesis and epoch 1) to avoid modifying the
/// `0x00` stub root in the initial checkpoints.
///
/// **Must be `pub`**: Phase 8 (`compute_pulled_up_tip`) calls this directly
/// from `pharos-fork-choice` to compute unrealized justification.
pub fn process_justification_and_finalization<E: BeaconSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let current_epoch = get_current_epoch::<E>(state);
    if current_epoch.0 <= GENESIS_EPOCH + 1 {
        return Ok(());
    }

    let previous_epoch = get_previous_epoch::<E>(state);

    let previous_target_attestations =
        get_matching_target_attestations::<E>(state, previous_epoch)?;
    let current_target_attestations = get_matching_target_attestations::<E>(state, current_epoch)?;

    let active_indices =
        crate::phase0::accessors::get_active_validator_indices::<E>(state, current_epoch);
    let total_active_balance = get_total_balance::<E>(state, &active_indices);
    let previous_target_balance = get_attesting_balance::<E>(state, &previous_target_attestations);
    let current_target_balance = get_attesting_balance::<E>(state, &current_target_attestations);

    weigh_justification_and_finalization::<E>(
        state,
        total_active_balance.0,
        previous_target_balance.0,
        current_target_balance.0,
    )
}

/// `weigh_justification_and_finalization` per
/// `specs/phase0/beacon-chain.md:1513-1537`.
fn weigh_justification_and_finalization<E: BeaconSpec>(
    state: &mut E::BeaconState,
    total_active_balance: u64,
    previous_epoch_target_balance: u64,
    current_epoch_target_balance: u64,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
{
    let previous_epoch = get_previous_epoch::<E>(state);
    let current_epoch = get_current_epoch::<E>(state);

    let old_previous_justified_checkpoint = state.previous_justified_checkpoint().clone();
    let old_current_justified_checkpoint = state.current_justified_checkpoint().clone();

    // Shift: previous <- current, then shift bits left by 1.
    state.set_previous_justified_checkpoint(state.current_justified_checkpoint().clone());

    // justification_bits[1:] = justification_bits[:JUSTIFICATION_BITS_LENGTH - 1]
    // justification_bits[0] = 0b0
    // (shift right by 1 in the "bit 0 = most recent" encoding used by the spec)
    let mut bits = state.justification_bits();
    // Shift: bit[i] <- bit[i-1] for i in 1..4, then bit[0] = 0.
    // The spec's bit layout: bit index 0 = current epoch, bit index 1 = prev, etc.
    // Python: bits[1:] = bits[:3]  means bits[3]=bits[2], bits[2]=bits[1], bits[1]=bits[0].
    let b0 = bits.get(0).unwrap_or(false);
    let b1 = bits.get(1).unwrap_or(false);
    let b2 = bits.get(2).unwrap_or(false);
    bits.set(3, b2);
    bits.set(2, b1);
    bits.set(1, b0);
    bits.set(0, false);

    // Previous epoch: 2/3 supermajority?
    if previous_epoch_target_balance * 3 >= total_active_balance * 2 {
        let root = get_block_root::<E>(state, previous_epoch)
            .map_err(|_| EpochProcessingError::BlockRootUnavailable)?;
        state.set_current_justified_checkpoint(Checkpoint {
            epoch: previous_epoch,
            root,
        });
        bits.set(1, true);
    }

    // Current epoch: 2/3 supermajority?
    if current_epoch_target_balance * 3 >= total_active_balance * 2 {
        let root = get_block_root::<E>(state, current_epoch)
            .map_err(|_| EpochProcessingError::BlockRootUnavailable)?;
        state.set_current_justified_checkpoint(Checkpoint {
            epoch: current_epoch,
            root,
        });
        bits.set(0, true);
    }

    state.set_justification_bits(bits);

    // Re-read bits after write for finalization logic.
    let bits = state.justification_bits();

    // ── Finalization rules (four rules, highest-priority last) ────────────────
    //
    // Rule 1: bits[1:4] all set AND old_prev.epoch + 3 == current_epoch
    let b1 = bits.get(1).unwrap_or(false);
    let b2 = bits.get(2).unwrap_or(false);
    let b3 = bits.get(3).unwrap_or(false);
    let b0 = bits.get(0).unwrap_or(false);

    if b1 && b2 && b3 && old_previous_justified_checkpoint.epoch.0 + 3 == current_epoch.0 {
        state.set_finalized_checkpoint(old_previous_justified_checkpoint.clone());
    }
    // Rule 2: bits[1:3] all set AND old_prev.epoch + 2 == current_epoch
    if b1 && b2 && old_previous_justified_checkpoint.epoch.0 + 2 == current_epoch.0 {
        state.set_finalized_checkpoint(old_previous_justified_checkpoint);
    }
    // Rule 3: bits[0:3] all set AND old_curr.epoch + 2 == current_epoch
    if b0 && b1 && b2 && old_current_justified_checkpoint.epoch.0 + 2 == current_epoch.0 {
        state.set_finalized_checkpoint(old_current_justified_checkpoint.clone());
    }
    // Rule 4: bits[0:2] all set AND old_curr.epoch + 1 == current_epoch
    if b0 && b1 && old_current_justified_checkpoint.epoch.0 + 1 == current_epoch.0 {
        state.set_finalized_checkpoint(old_current_justified_checkpoint);
    }

    Ok(())
}
