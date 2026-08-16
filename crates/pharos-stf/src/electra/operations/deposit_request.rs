//! `process_deposit_request` (EIP-6110) per
//! `specs/electra/beacon-chain.md:1809-1824`.
//!
//! A deposit request from the EL (EIP-6110) is enqueued as a `PendingDeposit`
//! with `slot = state.slot`.  Unlike the deposit-tree `process_deposit` (which
//! uses `slot = GENESIS_SLOT`), deposit requests carry the actual CL slot so
//! that `process_pending_deposits` at epoch boundary can distinguish them.
//!
//! No signature verification occurs here; the BLS proof-of-possession is
//! checked lazily by `process_pending_deposits`.

use pharos_ssz::{SszSequence, SszVector};
use pharos_types::{
    EthSpec,
    electra::{
        BeaconState,
        requests::{DepositRequest, PendingDeposit},
    },
};
use pharos_utils::Gwei;

use crate::error::StateTransitionError;

/// `UNSET_DEPOSIT_REQUESTS_START_INDEX` sentinel value per
/// `specs/electra/beacon-chain.md` (`2**64 - 1`).
pub const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;

/// `process_deposit_request` per `specs/electra/beacon-chain.md:1809-1824`.
pub fn process_deposit_request<
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
    deposit_request: &DepositRequest,
    _verify_signatures: bool,
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
    // Set deposit request start index on first EIP-6110 deposit request seen.
    if state.deposit_requests_start_index == UNSET_DEPOSIT_REQUESTS_START_INDEX {
        state.deposit_requests_start_index = deposit_request.index;
    }

    // Enqueue as a PendingDeposit with slot = state.slot (EIP-6110, distinct
    // from deposit-tree deposits which use GENESIS_SLOT).
    let pending = PendingDeposit {
        pubkey: SszVector::from_vec(deposit_request.pubkey.as_slice().to_vec())
            .expect("pubkey is 48 bytes"),
        withdrawal_credentials: deposit_request.withdrawal_credentials,
        amount: Gwei(deposit_request.amount.0),
        signature: SszVector::from_vec(deposit_request.signature.as_slice().to_vec())
            .expect("signature is 96 bytes"),
        slot: state.slot,
    };
    state.pending_deposits = state
        .pending_deposits
        .with_push(pending)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}
