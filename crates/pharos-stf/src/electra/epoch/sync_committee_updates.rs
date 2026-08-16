//! `process_sync_committee_updates` for Electra (EIP-7251).
//!
//! Per `specs/altair/beacon-chain.md:777-790` (call site unmodified) but using
//! the electra `get_next_sync_committee` (`[Modified in Electra:EIP7251]`
//! 16-bit random value + `MAX_EFFECTIVE_BALANCE_ELECTRA` weighting). The altair
//! delegation would produce the wrong next-sync-committee, so this operates on
//! the concrete electra state directly.

use pharos_types::{EthSpec, electra::BeaconState};
use pharos_utils::BLSPubkey;

use crate::electra::helpers::{get_current_epoch_electra, get_next_sync_committee_electra};
use crate::error::EpochProcessingError;

/// `process_sync_committee_updates` for Electra.
///
/// At the start of a new sync-committee period
/// (`(epoch + 1) % EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0`):
/// - `state.current_sync_committee = state.next_sync_committee`
/// - `state.next_sync_committee = get_next_sync_committee(state)` (electra).
#[allow(clippy::type_complexity)]
pub fn process_sync_committee_updates<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
) -> Result<(), EpochProcessingError>
where
    BLSPubkey: Default + Clone,
{
    let current_epoch = get_current_epoch_electra::<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        E,
    >(state);

    let next_epoch = current_epoch.0 + 1;

    if next_epoch % E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0 {
        state.current_sync_committee = state.next_sync_committee.clone();
        let new_next = get_next_sync_committee_electra::<
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
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
            E,
        >(state)
        .map_err(|e| match e {
            crate::error::StateTransitionError::Ssz(s) => EpochProcessingError::Ssz(s),
            _ => EpochProcessingError::ValidatorIndexOutOfRange { index: 0 },
        })?;
        state.next_sync_committee = new_next;
    }

    Ok(())
}
