//! `process_withdrawals` for Electra.
//!
//! Per `specs/electra/beacon-chain.md` Block processing → Withdrawals
//! (`:1219-1380`). EIP-7251 adds the pending-partial-withdrawal queue sweep
//! that runs BEFORE the regular validator sweep.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    capella::execution_payload::WithdrawalIndex,
    deneb::execution_payload::Withdrawal,
    electra::{BeaconState, requests::PendingPartialWithdrawal},
    phase0::ValidatorIndex,
};
use pharos_utils::Gwei;

use crate::electra::helpers::{
    decrease_balance_electra, get_max_effective_balance,
    is_eligible_for_partial_withdrawals_electra, is_fully_withdrawable_validator_electra,
    is_partially_withdrawable_validator_electra,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

// ── get_balance_after_withdrawals ─────────────────────────────────────────────

/// `get_balance_after_withdrawals` for an electra `BeaconState`.
///
/// Returns `state.balances[validator_index]` minus any withdrawals in `withdrawals`
/// that target `validator_index`.
fn get_balance_after_withdrawals_electra<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    validator_index: ValidatorIndex,
    withdrawals: &[Withdrawal],
) -> Gwei {
    let balance = state
        .balances
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

// ── get_pending_partial_withdrawals ──────────────────────────────────────────

/// `get_pending_partial_withdrawals` per `specs/electra/beacon-chain.md:1222-1267`.
///
/// Drains up to `MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP` entries from
/// `state.pending_partial_withdrawals` (only those whose `withdrawable_epoch <=
/// current_epoch` and for which the validator is eligible), stopping when the
/// combined withdrawal limit is reached or a non-withdrawable entry is hit.
///
/// Returns `(withdrawals, updated_withdrawal_index, processed_count)`.
/// `processed_count` is the number of queue entries examined (not just emitted);
/// the caller must slice off this many entries from `pending_partial_withdrawals`.
pub fn get_pending_partial_withdrawals<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> (Vec<Withdrawal>, WithdrawalIndex, u64) {
    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // Reserve at least one slot for the validator sweep (MAX_WITHDRAWALS_PER_PAYLOAD - 1).
    let withdrawals_limit = (prior_withdrawals.len() as u64)
        .saturating_add(E::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP)
        .min(E::MAX_WITHDRAWALS_PER_PAYLOAD.saturating_sub(1));

    // spec: assert len(prior_withdrawals) <= withdrawals_limit
    debug_assert!(
        (prior_withdrawals.len() as u64) <= withdrawals_limit,
        "prior_withdrawals must be <= withdrawals_limit"
    );

    let mut withdrawals: Vec<Withdrawal> = Vec::new();
    let mut current_withdrawal_index = withdrawal_index;
    let mut processed_count: u64 = 0;

    for pending in state.pending_partial_withdrawals.iter() {
        let all_len = (prior_withdrawals.len() + withdrawals.len()) as u64;
        let is_withdrawable = pending.withdrawable_epoch.0 <= epoch.0;
        let has_reached_limit = all_len >= withdrawals_limit;

        // spec: stop immediately if not withdrawable OR limit reached
        if !is_withdrawable || has_reached_limit {
            break;
        }

        let validator_index = pending.validator_index;
        let validator = match state.validators.get(validator_index.0 as usize) {
            Some(v) => v,
            None => {
                processed_count += 1;
                continue;
            }
        };

        // Build the combined view for balance accounting.
        let combined: Vec<Withdrawal> = prior_withdrawals
            .iter()
            .chain(withdrawals.iter())
            .cloned()
            .collect();
        let balance = get_balance_after_withdrawals_electra::<
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
        >(state, validator_index, &combined);

        if is_eligible_for_partial_withdrawals_electra::<E>(validator, balance) {
            let withdrawal_amount =
                Gwei((balance.0 - E::MIN_ACTIVATION_BALANCE).min(pending.amount.0));
            let creds = validator.withdrawal_credentials.as_slice();
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&creds[12..32]);
            withdrawals.push(Withdrawal {
                index: current_withdrawal_index,
                validator_index,
                address: pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                    addr,
                ),
                amount: withdrawal_amount,
            });
            current_withdrawal_index += 1;
        }

        processed_count += 1;
    }

    (withdrawals, current_withdrawal_index, processed_count)
}

// ── get_validators_sweep_withdrawals ─────────────────────────────────────────

/// Return value of `get_validators_sweep_withdrawals` for Electra.
pub struct ElectraSweepResult {
    pub withdrawals: Vec<Withdrawal>,
    pub withdrawal_index: WithdrawalIndex,
    pub processed_count: u64,
}

/// `get_validators_sweep_withdrawals` for Electra per `specs/electra/beacon-chain.md:1269-1314`.
///
/// Modified from Capella/Deneb: partial withdrawals use `get_max_effective_balance`
/// (compounding-aware) instead of `MAX_EFFECTIVE_BALANCE`, and withdrawal
/// predicates are the electra variants.
///
/// spec: assert `len(prior_withdrawals) < MAX_WITHDRAWALS_PER_PAYLOAD`
/// (at least one slot reserved; the partial sweep already consumed up to
/// `MAX_WITHDRAWALS_PER_PAYLOAD - 1`).
pub fn get_validators_sweep_withdrawals_electra<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> ElectraSweepResult {
    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let num_validators = state.validators.len();
    let validators_limit = (num_validators as u64).min(E::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    let withdrawals_limit = E::MAX_WITHDRAWALS_PER_PAYLOAD;

    // spec: assert len(prior_withdrawals) < withdrawals_limit
    debug_assert!(
        (prior_withdrawals.len() as u64) < withdrawals_limit,
        "prior_withdrawals must be < MAX_WITHDRAWALS_PER_PAYLOAD"
    );

    let mut new_withdrawals: Vec<Withdrawal> = Vec::new();
    let mut current_withdrawal_index = withdrawal_index;
    let mut validator_index = state.next_withdrawal_validator_index.0 as usize;
    let mut processed_count: u64 = 0;

    for _ in 0..validators_limit {
        let all_len = prior_withdrawals.len() + new_withdrawals.len();
        if all_len as u64 >= withdrawals_limit {
            break;
        }

        if let Some(validator) = state.validators.get(validator_index) {
            let combined: Vec<Withdrawal> = prior_withdrawals
                .iter()
                .chain(new_withdrawals.iter())
                .cloned()
                .collect();
            let balance = get_balance_after_withdrawals_electra::<
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
            >(state, ValidatorIndex(validator_index as u64), &combined);

            let creds = validator.withdrawal_credentials.as_slice();
            let mut addr = [0u8; 20];
            if creds.len() >= 32 {
                addr.copy_from_slice(&creds[12..32]);
            }

            if is_fully_withdrawable_validator_electra::<E>(validator, balance, epoch) {
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
            } else if is_partially_withdrawable_validator_electra::<E>(validator, balance) {
                // [Modified in Electra:EIP7251] use get_max_effective_balance
                let max_effective_balance = get_max_effective_balance::<E>(validator);
                new_withdrawals.push(Withdrawal {
                    index: current_withdrawal_index,
                    validator_index: ValidatorIndex(validator_index as u64),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            addr,
                        ),
                    amount: Gwei(balance.0 - max_effective_balance.0),
                });
                current_withdrawal_index += 1;
            }
        }

        validator_index = (validator_index + 1) % num_validators.max(1);
        processed_count += 1;
    }

    ElectraSweepResult {
        withdrawals: new_withdrawals,
        withdrawal_index: current_withdrawal_index,
        processed_count,
    }
}

// ── get_expected_withdrawals ──────────────────────────────────────────────────

/// Return value of `get_expected_withdrawals` for Electra.
pub struct ElectraExpectedWithdrawals {
    pub withdrawals: Vec<Withdrawal>,
    /// Number of `pending_partial_withdrawals` entries examined (to be sliced off).
    pub processed_partial_withdrawals_count: u64,
}

/// `get_expected_withdrawals` for Electra per `specs/electra/beacon-chain.md:1316-1342`.
///
/// FIRST drains `pending_partial_withdrawals` (up to
/// `MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP`), THEN runs the regular
/// validator sweep using the electra withdrawal predicates.
pub fn get_expected_withdrawals_electra<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
) -> ElectraExpectedWithdrawals {
    let withdrawal_index = state.next_withdrawal_index;

    // [New in Electra:EIP7251] partial-withdrawal queue sweep runs FIRST.
    let (partial_withdrawals, withdrawal_index, processed_partial_withdrawals_count) =
        get_pending_partial_withdrawals::<
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
        >(state, withdrawal_index, &[]);

    // Regular validator sweep (electra variants).
    let sweep_result = get_validators_sweep_withdrawals_electra::<
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
    >(state, withdrawal_index, &partial_withdrawals);

    let mut withdrawals = partial_withdrawals;
    withdrawals.extend(sweep_result.withdrawals);

    ElectraExpectedWithdrawals {
        withdrawals,
        processed_partial_withdrawals_count,
    }
}

// ── apply_withdrawals ─────────────────────────────────────────────────────────

/// Apply withdrawals by decreasing each validator's balance.
fn apply_withdrawals_electra<
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
    withdrawals: &[Withdrawal],
) -> Result<(), crate::error::StateTransitionError> {
    for w in withdrawals {
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
        >(state, w.validator_index, w.amount)?;
    }
    Ok(())
}

// ── update_next_withdrawal_index ─────────────────────────────────────────────

fn update_next_withdrawal_index_electra<
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
    withdrawals: &[Withdrawal],
) {
    if let Some(latest) = withdrawals.last() {
        state.next_withdrawal_index = latest.index + 1;
    }
}

// ── update_pending_partial_withdrawals ────────────────────────────────────────

/// `update_pending_partial_withdrawals` per `specs/electra/beacon-chain.md:1344-1348`.
///
/// Slices off the first `processed_partial_withdrawals_count` entries from
/// `state.pending_partial_withdrawals`.
fn update_pending_partial_withdrawals<
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
    processed_partial_withdrawals_count: u64,
) -> Result<(), StateTransitionError> {
    let count = processed_partial_withdrawals_count as usize;
    if count == 0 {
        return Ok(());
    }
    let remaining: Vec<PendingPartialWithdrawal> = state
        .pending_partial_withdrawals
        .iter()
        .skip(count)
        .cloned()
        .collect();
    state.pending_partial_withdrawals =
        pharos_ssz::SszList::from_vec(remaining).map_err(StateTransitionError::Ssz)?;
    Ok(())
}

// ── update_next_withdrawal_validator_index ────────────────────────────────────

fn update_next_withdrawal_validator_index_electra<
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

/// `process_withdrawals` for Electra per `specs/electra/beacon-chain.md:1350-1380`.
///
/// 1. Compute expected withdrawals (partial queue first, then validator sweep).
/// 2. Assert `payload.withdrawals == expected.withdrawals`.
/// 3. Apply withdrawals (decrease balances).
/// 4. Update `next_withdrawal_index`.
/// 5. [New in Electra:EIP7251] Slice off `processed_partial_withdrawals_count`
///    entries from `state.pending_partial_withdrawals`.
/// 6. Update `next_withdrawal_validator_index`.
pub fn process_withdrawals_electra<
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
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
    payload: &pharos_types::deneb::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >,
) -> Result<(), StateTransitionError> {
    let expected = get_expected_withdrawals_electra::<
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

    // spec: assert payload.withdrawals == expected.withdrawals
    let payload_withdrawals: Vec<Withdrawal> = payload.withdrawals.as_slice().to_vec();
    if payload_withdrawals != expected.withdrawals {
        return Err(StateTransitionError::WithdrawalsMismatch);
    }

    apply_withdrawals_electra::<
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
    >(state, &expected.withdrawals)?;

    update_next_withdrawal_index_electra::<
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
    >(state, &expected.withdrawals);

    // [New in Electra:EIP7251] drain processed partials from the queue.
    update_pending_partial_withdrawals::<
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
    >(state, expected.processed_partial_withdrawals_count)?;

    update_next_withdrawal_validator_index_electra::<
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
    >(state, &expected.withdrawals);

    Ok(())
}
