//! `process_pending_deposits` for Electra (EIP-7251 / EIP-6110).
//!
//! Per `specs/electra/beacon-chain.md:960-1055`.
//!
//! Drains `state.pending_deposits` at the epoch boundary, applying each deposit
//! that clears four gates in order (eth1-bridge ordering, finalization,
//! `MAX_PENDING_DEPOSITS_PER_EPOCH` cap, activation-exit churn), postponing the
//! deposits of exiting validators, and crediting balance immediately (without
//! consuming churn) for validators whose withdrawable epoch has already passed.
//!
//! `next_deposit_index` advances for applied, postponed, AND
//! withdrawn-credit deposits; the surviving queue is
//! `pending_deposits[next_deposit_index:] + deposits_to_postpone` (postponed
//! entries are reattached at the END). `deposit_balance_to_consume` carries the
//! leftover churn forward only when the churn break fired, else resets to 0.

use std::collections::HashMap;

use pharos_ssz::{SszList, SszSequence, SszVector};
use pharos_types::{
    BeaconSpec,
    electra::{BeaconState, requests::PendingDeposit},
    phase0::{Epoch, Slot, ValidatorIndex},
};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32, Gwei};

use crate::electra::helpers::{
    get_activation_exit_churn_limit_electra, increase_balance_electra, is_valid_deposit_signature,
};
use crate::electra::operations::deposit::add_validator_to_registry_electra;
use crate::error::EpochProcessingError;
use crate::phase0::accessors::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use crate::phase0::helpers::FAR_FUTURE_EPOCH;

/// `GENESIS_SLOT` per `specs/phase0/beacon-chain.md`. A `PendingDeposit` with
/// `slot == GENESIS_SLOT` is an Eth1-bridge deposit (not an EIP-6110 request).
const GENESIS_SLOT: Slot = Slot(0);

/// `apply_pending_deposit` per `specs/electra/beacon-chain.md:960-976`.
///
/// Top-up path (pubkey already in the registry): credit the balance. New-validator
/// path: gate on `is_valid_deposit_signature` (proof of possession, not checked by
/// the deposit contract); an invalid signature silently skips registration.
#[allow(clippy::type_complexity)]
pub fn apply_pending_deposit<
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
    E: BeaconSpec,
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
    deposit: &PendingDeposit,
) -> Result<(), EpochProcessingError> {
    let pubkey = pubkey_from_vector(&deposit.pubkey);

    let existing_index = state
        .validators
        .iter()
        .position(|v| v.pubkey == pubkey)
        .map(|i| ValidatorIndex(i as u64));

    match existing_index {
        None => {
            // Verify the deposit signature (proof of possession) which is not
            // checked by the deposit contract.
            let withdrawal_credentials = Bytes32::from_array(deposit.withdrawal_credentials);
            let signature = signature_from_vector(&deposit.signature);
            if is_valid_deposit_signature::<E>(
                &pubkey,
                &withdrawal_credentials,
                deposit.amount.0,
                &signature,
            ) {
                add_validator_to_registry_electra::<
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
                >(state, &pubkey, &withdrawal_credentials, deposit.amount.0)
                .map_err(|_| EpochProcessingError::ValidatorIndexOutOfRange {
                    index: state.validators.len(),
                })?;
            }
        }
        Some(validator_index) => {
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
            >(state, validator_index, deposit.amount)?;
        }
    }

    Ok(())
}

/// `process_pending_deposits` per `specs/electra/beacon-chain.md:990-1055`.
#[allow(clippy::type_complexity)]
pub fn process_pending_deposits<
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
    E: BeaconSpec,
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
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let next_epoch = Epoch(current_epoch.0 + 1);

    let available_for_processing = state.deposit_balance_to_consume.0
        + get_activation_exit_churn_limit_electra::<
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
        .0;

    let mut processed_amount: u64 = 0;
    let mut next_deposit_index: usize = 0;
    let mut deposits_to_postpone: Vec<PendingDeposit> = Vec::new();
    let mut is_churn_limit_reached = false;
    let finalized_slot =
        compute_start_slot_at_epoch(state.finalized_checkpoint.epoch, E::SLOTS_PER_EPOCH);

    // Snapshot the queue so we can mutate `state.validators` / `state.balances`
    // inside the loop without aliasing the iterated list.
    let pending_deposits: Vec<PendingDeposit> = state.pending_deposits.iter().cloned().collect();

    // Build a pubkey -> validator-index map ONCE to replace the per-deposit O(N)
    // `validators.iter().find(...)` status read below. Keyed by an OWNED
    // `BLSPubkey` (not a borrowed slice) because the registry GROWS during this
    // loop — `apply_pending_deposit` appends a new validator on the new-pubkey
    // path — and a slice-keyed map would alias `state.validators` across the
    // `&mut state` call. First-write-wins (`or_insert`) reproduces the
    // first-match result of `position()`/`find()`. After each deposit that grew
    // the registry we register the freshly-appended validator (always at the new
    // last index, and always a previously-absent pubkey) so a later same-pubkey
    // deposit in this same loop is NOT served a stale "absent" answer.
    let mut pubkey_to_index: HashMap<BLSPubkey, usize> =
        HashMap::with_capacity(state.validators.len());
    for (i, v) in state.validators.iter().enumerate() {
        pubkey_to_index.entry(v.pubkey).or_insert(i);
    }

    for deposit in &pending_deposits {
        // Do not process deposit requests if Eth1 bridge deposits are not yet
        // applied.
        if deposit.slot.0 > GENESIS_SLOT.0
            && state.eth1_deposit_index < state.deposit_requests_start_index
        {
            break;
        }

        // Check if deposit has been finalized, otherwise, stop processing.
        if deposit.slot.0 > finalized_slot.0 {
            break;
        }

        // Check if number of processed deposits has not reached the limit,
        // otherwise, stop processing.
        if next_deposit_index as u64 >= E::MAX_PENDING_DEPOSITS_PER_EPOCH {
            break;
        }

        // Read validator state.
        let pubkey = pubkey_from_vector(&deposit.pubkey);
        let mut is_validator_exited = false;
        let mut is_validator_withdrawn = false;
        if let Some(validator) = pubkey_to_index
            .get(&pubkey)
            .and_then(|&i| state.validators.get(i))
        {
            is_validator_exited = validator.exit_epoch.0 < FAR_FUTURE_EPOCH;
            is_validator_withdrawn = validator.withdrawable_epoch.0 < next_epoch.0;
        }

        if is_validator_withdrawn {
            // Deposited balance will never become active. Increase balance but do
            // not consume churn.
            apply_pending_deposit::<
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
            >(state, deposit)?;
        } else if is_validator_exited {
            // Validator is exiting, postpone the deposit until after withdrawable
            // epoch.
            deposits_to_postpone.push(deposit.clone());
        } else {
            // Check if deposit fits in the churn, otherwise, do no more deposit
            // processing in this epoch.
            is_churn_limit_reached = processed_amount + deposit.amount.0 > available_for_processing;
            if is_churn_limit_reached {
                break;
            }

            // Consume churn and apply deposit. This is the ONLY branch that can
            // append a new validator (the withdrawn branch is always a top-up of
            // an already-present validator). Snapshot the length so we can keep
            // `pubkey_to_index` consistent if a new validator was registered.
            processed_amount += deposit.amount.0;
            let len_before = state.validators.len();
            apply_pending_deposit::<
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
            >(state, deposit)?;
            // A freshly-appended validator lands at `len_before` and its pubkey
            // was previously absent, so `or_insert` keeps first-match semantics
            // and prevents a later same-pubkey deposit from reading a stale miss.
            if state.validators.len() > len_before {
                pubkey_to_index.entry(pubkey).or_insert(len_before);
            }
        }

        // Regardless of how the deposit was handled, we move on in the queue.
        next_deposit_index += 1;
    }

    // `pending_deposits[next_deposit_index:] + deposits_to_postpone` (postponed
    // entries are reattached at the END — order is load-bearing).
    let mut remaining: Vec<PendingDeposit> = pending_deposits[next_deposit_index..].to_vec();
    remaining.extend(deposits_to_postpone);
    state.pending_deposits = SszList::from_vec(remaining).map_err(EpochProcessingError::Ssz)?;

    // Accumulate churn only if the churn limit has been hit.
    if is_churn_limit_reached {
        state.deposit_balance_to_consume = Gwei(available_for_processing - processed_amount);
    } else {
        state.deposit_balance_to_consume = Gwei(0);
    }

    Ok(())
}

/// Reconstruct a `BLSPubkey` from a `PendingDeposit`'s 48-byte vector.
fn pubkey_from_vector(vector: &SszVector<u8, 48>) -> BLSPubkey {
    let mut bytes = [0u8; 48];
    bytes.copy_from_slice(vector.as_slice());
    BLSPubkey::from_array(bytes)
}

/// Reconstruct a `BLSSignature` from a `PendingDeposit`'s 96-byte vector.
fn signature_from_vector(vector: &SszVector<u8, 96>) -> BLSSignature {
    let mut bytes = [0u8; 96];
    bytes.copy_from_slice(vector.as_slice());
    BLSSignature::from_array(bytes)
}
