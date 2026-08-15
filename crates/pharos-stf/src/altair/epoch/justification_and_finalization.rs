//! `process_justification_and_finalization` for Altair.
//!
//! Modified from phase0: uses participation flags instead of pending attestations
//! to compute previous- and current-epoch target balances.
//!
//! spec: specs/altair/beacon-chain.md:669-691

use pharos_types::{
    EthSpec,
    altair::{BeaconState, constants::TIMELY_TARGET_FLAG_INDEX},
    phase0::Checkpoint,
};

use crate::error::EpochProcessingError;
use crate::phase0::helpers::GENESIS_EPOCH;

use super::helpers::{
    get_block_root_for_epoch, get_current_epoch_altair, get_previous_epoch_altair,
};
use crate::altair::helpers::{
    get_total_active_balance_altair, get_total_balance_altair,
    get_unslashed_participating_indices,
};

/// `process_justification_and_finalization` per
/// `specs/altair/beacon-chain.md:669-691`.
///
/// Modified: replaces pending-attestation look-ups with participation-flag
/// look-ups (`TIMELY_TARGET_FLAG_INDEX`) on the altair `BeaconState`.
/// `weigh_justification_and_finalization` logic is identical to phase0.
pub fn process_justification_and_finalization<
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

    // Skip in the first two epochs (genesis and epoch 1).
    if current_epoch.0 <= GENESIS_EPOCH + 1 {
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

    let previous_indices = get_unslashed_participating_indices::<
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

    let current_indices = get_unslashed_participating_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, TIMELY_TARGET_FLAG_INDEX, current_epoch);

    let total_active_balance = get_total_active_balance_altair::<
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

    let previous_target_balance = get_total_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, &previous_indices);

    let current_target_balance = get_total_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, &current_indices);

    weigh_justification_and_finalization::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(
        state,
        total_active_balance.0,
        previous_target_balance.0,
        current_target_balance.0,
    )
}

/// `weigh_justification_and_finalization` per
/// `specs/phase0/beacon-chain.md:1513-1537` (identical logic in altair).
///
/// Mutates `justification_bits`, checkpoints, and finalized checkpoint
/// directly on the concrete altair `BeaconState`.
fn weigh_justification_and_finalization<
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
    total_active_balance: u64,
    previous_epoch_target_balance: u64,
    current_epoch_target_balance: u64,
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

    let old_previous_justified_checkpoint = state.previous_justified_checkpoint.clone();
    let old_current_justified_checkpoint = state.current_justified_checkpoint.clone();

    // Shift: previous <- current.
    state.previous_justified_checkpoint = state.current_justified_checkpoint.clone();

    // justification_bits[1:] = justification_bits[:JUSTIFICATION_BITS_LENGTH - 1]
    // justification_bits[0] = 0b0
    // (shift right by 1; bit 0 = most-recent-epoch)
    let b0 = state.justification_bits.get(0).unwrap_or(false);
    let b1 = state.justification_bits.get(1).unwrap_or(false);
    let b2 = state.justification_bits.get(2).unwrap_or(false);
    state.justification_bits.set(3, b2);
    state.justification_bits.set(2, b1);
    state.justification_bits.set(1, b0);
    state.justification_bits.set(0, false);

    // Previous epoch: 2/3 supermajority?
    if previous_epoch_target_balance * 3 >= total_active_balance * 2 {
        let root = get_block_root_for_epoch::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, previous_epoch)
        .map_err(|_| EpochProcessingError::BlockRootUnavailable)?;
        state.current_justified_checkpoint = Checkpoint {
            epoch: previous_epoch,
            root,
        };
        state.justification_bits.set(1, true);
    }

    // Current epoch: 2/3 supermajority?
    if current_epoch_target_balance * 3 >= total_active_balance * 2 {
        let root = get_block_root_for_epoch::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, current_epoch)
        .map_err(|_| EpochProcessingError::BlockRootUnavailable)?;
        state.current_justified_checkpoint = Checkpoint {
            epoch: current_epoch,
            root,
        };
        state.justification_bits.set(0, true);
    }

    // Re-read bits after write for finalization logic.
    let b0 = state.justification_bits.get(0).unwrap_or(false);
    let b1 = state.justification_bits.get(1).unwrap_or(false);
    let b2 = state.justification_bits.get(2).unwrap_or(false);
    let b3 = state.justification_bits.get(3).unwrap_or(false);

    // Rule 1: bits[1:4] all set AND old_prev.epoch + 3 == current_epoch.
    if b1 && b2 && b3 && old_previous_justified_checkpoint.epoch.0 + 3 == current_epoch.0 {
        state.finalized_checkpoint = old_previous_justified_checkpoint.clone();
    }
    // Rule 2: bits[1:3] all set AND old_prev.epoch + 2 == current_epoch.
    if b1 && b2 && old_previous_justified_checkpoint.epoch.0 + 2 == current_epoch.0 {
        state.finalized_checkpoint = old_previous_justified_checkpoint;
    }
    // Rule 3: bits[0:3] all set AND old_curr.epoch + 2 == current_epoch.
    if b0 && b1 && b2 && old_current_justified_checkpoint.epoch.0 + 2 == current_epoch.0 {
        state.finalized_checkpoint = old_current_justified_checkpoint.clone();
    }
    // Rule 4: bits[0:2] all set AND old_curr.epoch + 1 == current_epoch.
    if b0 && b1 && old_current_justified_checkpoint.epoch.0 + 1 == current_epoch.0 {
        state.finalized_checkpoint = old_current_justified_checkpoint;
    }

    Ok(())
}
