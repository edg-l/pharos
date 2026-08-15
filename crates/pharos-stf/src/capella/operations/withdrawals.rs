//! `process_withdrawals` for Capella.
//!
//! Per `specs/capella/beacon-chain.md` Block processing → New `process_withdrawals`.

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    capella::{
        BeaconState,
        execution_payload::{Withdrawal, WithdrawalIndex},
    },
    phase0::ValidatorIndex,
};
use pharos_utils::Gwei;

use crate::capella::helpers::{
    decrease_balance_capella, is_fully_withdrawable_validator, is_partially_withdrawable_validator,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

// ── get_balance_after_withdrawals ─────────────────────────────────────────────

/// `get_balance_after_withdrawals` per `specs/capella/beacon-chain.md`.
///
/// Returns `state.balances[validator_index]` minus all withdrawals that target
/// the given validator index from the `withdrawals` slice.
pub fn get_balance_after_withdrawals<
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    validator_index: ValidatorIndex,
    withdrawals: &[Withdrawal],
) -> Gwei {
    let balance = state
        .balances
        .as_slice()
        .get(validator_index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));

    let withdrawn: u64 = withdrawals
        .iter()
        .filter(|w| w.validator_index == validator_index)
        .map(|w| w.amount.0)
        .sum();

    Gwei(balance.0.saturating_sub(withdrawn))
}

// ── get_validators_sweep_withdrawals ──────────────────────────────────────────

/// Return value of `get_validators_sweep_withdrawals`.
pub struct SweepResult {
    /// New withdrawals from the sweep.
    pub withdrawals: Vec<Withdrawal>,
    /// Updated withdrawal index after the sweep.
    pub withdrawal_index: WithdrawalIndex,
    /// Number of validators processed in this sweep pass.
    pub processed_count: u64,
}

/// `get_validators_sweep_withdrawals` per `specs/capella/beacon-chain.md`.
///
/// Iterates up to `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` validators starting
/// from `state.next_withdrawal_validator_index`, appending full and partial
/// withdrawals until `MAX_WITHDRAWALS_PER_PAYLOAD` is reached.
///
/// The spec asserts `len(prior_withdrawals) < withdrawals_limit`.
pub fn get_validators_sweep_withdrawals<
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> SweepResult {
    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let num_validators = state.validators.len();
    let validators_limit = (num_validators as u64).min(E::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    let withdrawals_limit = E::MAX_WITHDRAWALS_PER_PAYLOAD;

    // spec: assert len(prior_withdrawals) < withdrawals_limit
    assert!(
        (prior_withdrawals.len() as u64) < withdrawals_limit,
        "prior_withdrawals must be less than withdrawals_limit"
    );

    let mut new_withdrawals: Vec<Withdrawal> = Vec::new();
    let mut current_withdrawal_index = withdrawal_index;
    let mut validator_index = state.next_withdrawal_validator_index.0 as usize;
    let mut processed_count: u64 = 0;

    for _ in 0..validators_limit {
        // Combine prior and new for limit check.
        let all_len = prior_withdrawals.len() + new_withdrawals.len();
        if all_len as u64 >= withdrawals_limit {
            break;
        }

        if let Some(validator) = state.validators.get(validator_index) {
            // Build a combined view for get_balance_after_withdrawals.
            let combined: Vec<Withdrawal> = prior_withdrawals
                .iter()
                .chain(new_withdrawals.iter())
                .cloned()
                .collect();
            let balance = get_balance_after_withdrawals::<
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
            >(state, ValidatorIndex(validator_index as u64), &combined);

            if is_fully_withdrawable_validator(validator, balance, epoch) {
                // address = withdrawal_credentials[12:]
                let creds = validator.withdrawal_credentials.as_slice();
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&creds[12..32]);
                new_withdrawals.push(Withdrawal {
                    index: current_withdrawal_index,
                    validator_index: ValidatorIndex(validator_index as u64),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            addr,
                        ),
                    amount: balance,
                });
                current_withdrawal_index += 1;
            } else if is_partially_withdrawable_validator::<E>(validator, balance) {
                let creds = validator.withdrawal_credentials.as_slice();
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&creds[12..32]);
                new_withdrawals.push(Withdrawal {
                    index: current_withdrawal_index,
                    validator_index: ValidatorIndex(validator_index as u64),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            addr,
                        ),
                    amount: Gwei(balance.0 - E::MAX_EFFECTIVE_BALANCE),
                });
                current_withdrawal_index += 1;
            }
        }

        validator_index = (validator_index + 1) % num_validators;
        processed_count += 1;
    }

    SweepResult {
        withdrawals: new_withdrawals,
        withdrawal_index: current_withdrawal_index,
        processed_count,
    }
}

// ── get_expected_withdrawals ──────────────────────────────────────────────────

/// `get_expected_withdrawals` per `specs/capella/beacon-chain.md`.
pub fn get_expected_withdrawals<
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
) -> Vec<Withdrawal> {
    let withdrawal_index = state.next_withdrawal_index;

    let sweep_result = get_validators_sweep_withdrawals::<
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
        E,
    >(state, withdrawal_index, &[]);

    sweep_result.withdrawals
}

// ── apply_withdrawals ─────────────────────────────────────────────────────────

/// `apply_withdrawals` per `specs/capella/beacon-chain.md`.
///
/// Decreases each validator's balance by the withdrawal amount.
pub fn apply_withdrawals<
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
    >,
    withdrawals: &[Withdrawal],
) {
    for withdrawal in withdrawals {
        decrease_balance_capella::<
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
        >(state, withdrawal.validator_index, withdrawal.amount);
    }
}

// ── update_next_withdrawal_index ──────────────────────────────────────────────

/// `update_next_withdrawal_index` per `specs/capella/beacon-chain.md`.
///
/// If `withdrawals` is non-empty, advances `state.next_withdrawal_index`
/// to `last_withdrawal.index + 1`.
pub fn update_next_withdrawal_index<
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
    >,
    withdrawals: &[Withdrawal],
) {
    if let Some(latest) = withdrawals.last() {
        state.next_withdrawal_index = latest.index + 1;
    }
}

// ── update_next_withdrawal_validator_index ────────────────────────────────────

/// `update_next_withdrawal_validator_index` per `specs/capella/beacon-chain.md`.
///
/// If `len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD`, the next sweep
/// starts after the last withdrawal's validator index.  Otherwise it advances
/// by `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`.
pub fn update_next_withdrawal_validator_index<
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
    >,
    withdrawals: &[Withdrawal],
) {
    let num_validators = state.validators.len() as u64;
    if num_validators == 0 {
        return;
    }

    if withdrawals.len() as u64 == E::MAX_WITHDRAWALS_PER_PAYLOAD {
        let last = withdrawals.last().expect("non-empty");
        let next_index = (last.validator_index.0 + 1) % num_validators;
        state.next_withdrawal_validator_index = ValidatorIndex(next_index);
    } else {
        let next_index =
            state.next_withdrawal_validator_index.0 + E::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;
        state.next_withdrawal_validator_index = ValidatorIndex(next_index % num_validators);
    }
}

// ── process_withdrawals ───────────────────────────────────────────────────────

/// `process_withdrawals` per `specs/capella/beacon-chain.md`.
///
/// 1. Compute expected withdrawals.
/// 2. Assert `payload.withdrawals == expected.withdrawals` (consensus check →
///    `WithdrawalsMismatch`).
/// 3. Apply withdrawals (decrease balances).
/// 4. Update `next_withdrawal_index`.
/// 5. Update `next_withdrawal_validator_index`.
pub fn process_withdrawals<
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
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
    >,
    payload: &pharos_types::capella::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >,
) -> Result<(), StateTransitionError> {
    let expected = get_expected_withdrawals::<
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
        E,
    >(state);

    // spec: assert payload.withdrawals == expected.withdrawals
    let payload_withdrawals: Vec<Withdrawal> = payload.withdrawals.as_slice().to_vec();
    if payload_withdrawals != expected {
        return Err(StateTransitionError::WithdrawalsMismatch);
    }

    apply_withdrawals::<
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
    >(state, &expected);

    update_next_withdrawal_index::<
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
    >(state, &expected);

    update_next_withdrawal_validator_index::<
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
        E,
    >(state, &expected);

    Ok(())
}
