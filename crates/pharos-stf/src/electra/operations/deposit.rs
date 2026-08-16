//! `process_deposit` (modified in Electra:EIP7251) per
//! `specs/electra/beacon-chain.md:1568-1696`.
//!
//! Electra changes vs. Altair/Deneb `apply_deposit`:
//! - Deposits no longer credit balance immediately. Instead a `PendingDeposit`
//!   is appended to `state.pending_deposits` (with `slot = GENESIS_SLOT` to
//!   distinguish it from a 6110 deposit-request) and processed at epoch
//!   boundary by `process_pending_deposits`.
//! - A new validator is created via `add_validator_to_registry` with a balance
//!   of `Gwei(0)`; its `effective_balance` is gated by `get_max_effective_balance`
//!   in the modified `get_validator_from_deposit`.

use pharos_ssz::{SszSequence, SszVector, TreeHash};
use pharos_types::{
    EthSpec,
    electra::{BeaconState, requests::PendingDeposit},
    phase0::{Deposit, Epoch, Slot, Validator},
};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32, Gwei, Hash256};

use crate::electra::helpers::{get_max_effective_balance, is_valid_deposit_signature};
use crate::error::{DepositInvalidReason, StateTransitionError};
use crate::phase0::{helpers::FAR_FUTURE_EPOCH, operations::deposit::is_valid_merkle_branch};

/// `GENESIS_SLOT` placeholder used to mark deposits applied via the deposit tree
/// (distinct from EIP-6110 deposit requests). Per `specs/electra/beacon-chain.md`.
const GENESIS_SLOT: Slot = Slot(0);

/// `process_deposit` (modified in Electra:EIP7251) per
/// `specs/electra/beacon-chain.md:1684-1696`.
pub fn process_deposit_electra<
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    deposit: &Deposit<33>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
        ElectraBeaconState = BeaconState<
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
    >,
{
    // Verify Merkle proof.
    let leaf = deposit.data.tree_hash_root();
    let index = state.eth1_deposit_index;
    let deposit_root = state.eth1_data.deposit_root;
    let depth = E::DEPOSIT_CONTRACT_TREE_DEPTH + 1;
    let branch: Vec<Hash256> = deposit.proof.as_slice().to_vec();

    if !is_valid_merkle_branch(&leaf, &branch, depth, index, &deposit_root) {
        return Err(StateTransitionError::InvalidDeposit {
            reason: DepositInvalidReason::InvalidMerkleProof,
        });
    }

    // Deposits must be processed in order.
    state.eth1_deposit_index += 1;

    apply_deposit_electra::<
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
    >(
        state,
        &deposit.data.pubkey,
        &deposit.data.withdrawal_credentials,
        deposit.data.amount.0,
        &deposit.data.signature,
        verify_signatures,
    )
}

/// `apply_deposit` (modified in Electra:EIP7251) per
/// `specs/electra/beacon-chain.md:1640-1660`.
///
/// A new validator (whose pubkey is absent) is registered with a zero balance
/// when the proof-of-possession signature is valid; an invalid signature for a
/// new pubkey silently returns. In all cases the deposit amount is enqueued as a
/// `PendingDeposit` (slot = `GENESIS_SLOT`) rather than credited directly.
#[allow(clippy::too_many_arguments)]
fn apply_deposit_electra<
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
    pubkey: &BLSPubkey,
    withdrawal_credentials: &Bytes32,
    amount: u64,
    signature: &BLSSignature,
    verify_signatures: bool,
) -> Result<(), StateTransitionError> {
    let is_new_validator = !state.validators.iter().any(|v| &v.pubkey == pubkey);

    if is_new_validator {
        // Verify the proof of possession before registering a new validator.
        // When signature verification is disabled the deposit is treated as
        // valid (consistent with the rest of the STF's `verify_signatures` gate).
        let sig_ok = !verify_signatures
            || is_valid_deposit_signature::<E>(pubkey, withdrawal_credentials, amount, signature);
        if sig_ok {
            // [Modified in Electra:EIP7251] register with a zero balance.
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
            >(state, pubkey, withdrawal_credentials, 0)?;
        } else {
            // Invalid proof of possession for a new pubkey: silently skip.
            return Ok(());
        }
    }

    // [Modified in Electra:EIP7251] enqueue the deposit amount.
    let pending = PendingDeposit {
        pubkey: SszVector::from_vec(pubkey.as_slice().to_vec()).expect("pubkey is 48 bytes"),
        withdrawal_credentials: withdrawal_credentials.into_inner(),
        amount: Gwei(amount),
        signature: SszVector::from_vec(signature.as_slice().to_vec())
            .expect("signature is 96 bytes"),
        slot: GENESIS_SLOT,
    };
    state.pending_deposits = state
        .pending_deposits
        .with_push(pending)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}

/// `add_validator_to_registry` (modified in Electra:EIP7251) per
/// `specs/electra/beacon-chain.md:1617-1628`.
///
/// Appends the validator (via the modified `get_validator_from_deposit`), its
/// balance, participation flags, and inactivity score.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_validator_to_registry_electra<
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
    pubkey: &BLSPubkey,
    withdrawal_credentials: &Bytes32,
    amount: u64,
) -> Result<(), StateTransitionError> {
    let validator = get_validator_from_deposit_electra::<E>(pubkey, withdrawal_credentials, amount);
    state.validators = state
        .validators
        .with_push(validator)
        .map_err(StateTransitionError::Ssz)?;
    state.balances = state
        .balances
        .with_push(Gwei(amount))
        .map_err(StateTransitionError::Ssz)?;
    state.previous_epoch_participation = state
        .previous_epoch_participation
        .with_push(0u8)
        .map_err(StateTransitionError::Ssz)?;
    state.current_epoch_participation = state
        .current_epoch_participation
        .with_push(0u8)
        .map_err(StateTransitionError::Ssz)?;
    state.inactivity_scores = state
        .inactivity_scores
        .with_push(0u64)
        .map_err(StateTransitionError::Ssz)?;
    Ok(())
}

/// `get_validator_from_deposit` (modified in Electra:EIP7251) per
/// `specs/electra/beacon-chain.md:1596-1612`.
///
/// `effective_balance` is gated by `get_max_effective_balance`, which uses
/// `MAX_EFFECTIVE_BALANCE_ELECTRA` for compounding-credential validators.
fn get_validator_from_deposit_electra<E: EthSpec>(
    pubkey: &BLSPubkey,
    withdrawal_credentials: &Bytes32,
    amount: u64,
) -> Validator {
    let mut validator = Validator {
        pubkey: *pubkey,
        withdrawal_credentials: *withdrawal_credentials,
        effective_balance: Gwei(0),
        slashed: false,
        activation_eligibility_epoch: Epoch(FAR_FUTURE_EPOCH),
        activation_epoch: Epoch(FAR_FUTURE_EPOCH),
        exit_epoch: Epoch(FAR_FUTURE_EPOCH),
        withdrawable_epoch: Epoch(FAR_FUTURE_EPOCH),
        ..Validator::default()
    };

    // [Modified in Electra:EIP7251]
    let max_effective_balance = get_max_effective_balance::<E>(&validator);
    validator.effective_balance =
        Gwei((amount - amount % E::EFFECTIVE_BALANCE_INCREMENT).min(max_effective_balance.0));

    validator
}
