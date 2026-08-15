//! Bellatrix block-processing operations.
//!
//! Per `specs/bellatrix/beacon-chain.md:378-416`.

pub mod attester_slashing;
pub mod execution_payload;
pub mod proposer_slashing;

pub use attester_slashing::process_attester_slashing_bellatrix;
pub use execution_payload::{is_execution_enabled, process_execution_payload};
pub use proposer_slashing::process_proposer_slashing_bellatrix;

use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    bellatrix::BeaconState,
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::BeaconBlockBodyView,
};

use crate::altair::operations::{process_attestation, process_deposit, process_voluntary_exit};
use crate::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
use crate::error::StateTransitionError;

/// `process_operations` for Bellatrix.
///
/// Per `specs/bellatrix/beacon-chain.md:374` and the same structure as Altair
/// operations, except proposer and attester slashings call
/// `slash_validator_bellatrix` (which uses
/// `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`) per
/// `specs/bellatrix/beacon-chain.md:253-276`.
///
/// Sequence:
/// 1. Proposer slashings — Bellatrix-specific handler.
/// 2. Attester slashings — Bellatrix-specific handler.
/// 3. Attestations — Altair handler via state projection.
/// 4. Deposits — Altair handler via state projection.
/// 5. Voluntary exits — Altair handler via state projection.
#[allow(clippy::too_many_arguments)]
pub fn process_operations_bellatrix<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
    >,
    body: &pharos_types::bellatrix::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
            AltairBeaconState = AltairBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            BellatrixBeaconState = BeaconState<
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
        >,
    // process_attestation / process_deposit / process_voluntary_exit require
    // the AltairBeaconState bound (they operate on the altair inner type).
    // The bound above already satisfies this; the compiler needs it spelled out.
    pharos_types::bellatrix::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    use BeaconBlockBodyView as _;

    // Verify deposit count.
    let expected_deposits = E::MAX_DEPOSITS.min(
        state
            .eth1_data
            .deposit_count
            .saturating_sub(state.eth1_deposit_index),
    );
    if body.deposits().len() as u64 != expected_deposits {
        return Err(StateTransitionError::InvalidDepositCount);
    }

    // Step 1: Proposer slashings — use Bellatrix handler (MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX).
    for slashing in body.proposer_slashings() {
        process_proposer_slashing_bellatrix::<
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
        >(state, slashing, verify_signatures)?;
    }

    // Step 2: Attester slashings — use Bellatrix handler (MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX).
    for slashing in body.attester_slashings() {
        process_attester_slashing_bellatrix::<
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
        >(state, slashing, verify_signatures)?;
    }

    // Steps 3–5: attestations, deposits, voluntary exits — delegate to Altair
    // handlers via state projection (identical logic; only slashings differ).
    let mut altair_state = bellatrix_state_to_altair(state);

    for attestation in body.attestations() {
        process_attestation::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(&mut altair_state, attestation, verify_signatures)?;
    }
    for deposit in body.deposits() {
        process_deposit::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(&mut altair_state, deposit, verify_signatures)?;
    }
    for exit in body.voluntary_exits() {
        process_voluntary_exit::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(&mut altair_state, exit, verify_signatures)?;
    }

    update_bellatrix_from_altair(state, altair_state);

    Ok(())
}
