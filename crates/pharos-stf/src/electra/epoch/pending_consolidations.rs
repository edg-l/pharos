//! `process_pending_consolidations` for Electra (EIP-7251).
//!
//! Per `specs/electra/beacon-chain.md:1060-1082`.
//!
//! Drains `state.pending_consolidations` from the front. For each entry:
//! - If the source validator is slashed, skip it (advance the cursor, leave
//!   balances untouched) — a slashed source forfeits the consolidation.
//! - Otherwise, if the source is not yet withdrawable
//!   (`withdrawable_epoch > next_epoch`, with `next_epoch = current_epoch + 1`),
//!   STOP: the queue is processed in order and later entries cannot jump ahead.
//! - Otherwise, move the source's active balance
//!   (`min(balance, effective_balance)`, compounding-aware) to the target via
//!   `decrease_balance` / `increase_balance`; the excess source balance stays
//!   put and becomes withdrawable.
//!
//! The processed prefix is truncated off `state.pending_consolidations`.

use pharos_ssz::{SszList, SszSequence};
use pharos_types::{EthSpec, electra::BeaconState};
use pharos_utils::Gwei;

use crate::electra::helpers::{decrease_balance_electra, increase_balance_electra};
use crate::error::EpochProcessingError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_pending_consolidations` per `specs/electra/beacon-chain.md:1060-1082`.
#[allow(clippy::type_complexity)]
pub fn process_pending_consolidations<
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
) -> Result<(), EpochProcessingError> {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let next_epoch = current_epoch.0 + 1;

    // Snapshot the queue so we can mutate `state.balances` inside the loop
    // without aliasing the iterated list.
    let pending = state
        .pending_consolidations
        .iter()
        .cloned()
        .collect::<Vec<_>>();

    let mut next_pending_consolidation: usize = 0;
    for pending_consolidation in &pending {
        let source_index = pending_consolidation.source_index;
        let target_index = pending_consolidation.target_index;

        let source_validator = state.validators.get(source_index.0 as usize).ok_or(
            EpochProcessingError::ValidatorIndexOutOfRange {
                index: source_index.0 as usize,
            },
        )?;

        if source_validator.slashed {
            next_pending_consolidation += 1;
            continue;
        }
        if source_validator.withdrawable_epoch.0 > next_epoch {
            break;
        }

        // Calculate the consolidated balance: the active (compounding-aware)
        // balance is `min(balance, effective_balance)`. Excess is withdrawable.
        let source_balance = state
            .balances
            .as_slice()
            .get(source_index.0 as usize)
            .copied()
            .unwrap_or(Gwei(0))
            .0;
        let source_effective_balance = source_balance.min(source_validator.effective_balance.0);

        decrease_balance_electra::<
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
        >(state, source_index, Gwei(source_effective_balance));
        increase_balance_electra::<
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
        >(state, target_index, Gwei(source_effective_balance));
        next_pending_consolidation += 1;
    }

    // `state.pending_consolidations = state.pending_consolidations[next_pending_consolidation:]`
    let remaining = pending[next_pending_consolidation..].to_vec();
    state.pending_consolidations =
        SszList::from_vec(remaining).map_err(EpochProcessingError::Ssz)?;

    Ok(())
}
