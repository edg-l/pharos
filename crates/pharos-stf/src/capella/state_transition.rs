//! Capella state-transition entry point.
//!
//! Per `specs/phase0/beacon-chain.md:1370-1393` (identical interface in Capella).

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    capella::{BeaconBlock, BeaconState, SignedBeaconBlock},
    config::RuntimeConfig,
    phase0::Slot,
    views::{BeaconBlockView, SignedBeaconBlockView},
};
use pharos_utils::BLSPubkey;

use pharos_types::capella::execution_payload::Withdrawal;

use crate::altair::epoch::process_justification_and_finalization;
use crate::bellatrix::execution_engine::{ExecutionEngine, PayloadVerificationStatus};
use crate::capella::block::process_block;
use crate::capella::epoch::process_epoch;
use crate::capella::operations::withdrawals::get_expected_withdrawals;
use crate::error::{EpochProcessingError, StateTransitionError};
use crate::phase0::helpers::DOMAIN_BEACON_PROPOSER;

// ── process_slots (capella) ───────────────────────────────────────────────────

/// `process_slots` for the capella `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:1396-1406` (identical in Capella).
pub fn process_slots_capella<
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
    target_slot: Slot,
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
            BellatrixBeaconState = pharos_types::bellatrix::BeaconState<
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
            CapellaBeaconState = BeaconState<
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
    BLSPubkey: Default + Clone,
{
    if target_slot < state.slot {
        return Err(StateTransitionError::TargetSlotNotAfterCurrent {
            current: state.slot,
            target: target_slot,
        });
    }

    while state.slot < target_slot {
        process_slot_capella::<
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
        >(state)?;

        if (state.slot.0 + 1) % E::SLOTS_PER_EPOCH == 0 {
            process_epoch::<
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
            >(state)
            .map_err(|e: EpochProcessingError| match e {
                EpochProcessingError::Ssz(s) => StateTransitionError::Ssz(s),
                other => StateTransitionError::EpochProcessing { reason: other },
            })?;
        }

        state.slot = Slot(state.slot.0 + 1);
    }

    Ok(())
}

/// `process_slot` for the capella `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:1407-1425` (identical in Capella).
fn process_slot_capella<
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
) -> Result<(), StateTransitionError> {
    // Cache state root.
    let previous_state_root = state.tree_hash_root();
    let slot_idx = (state.slot.0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
    state.state_roots = state
        .state_roots
        .with_set(slot_idx, previous_state_root)
        .map_err(StateTransitionError::Ssz)?;

    // Patch latest block header if state_root is still zeroed.
    let previous_block_root =
        if state.latest_block_header.state_root == pharos_types::phase0::Root::default() {
            let mut updated = state.latest_block_header.clone();
            updated.state_root = previous_state_root;
            state.latest_block_header = updated.clone();
            updated.tree_hash_root()
        } else {
            state.latest_block_header.tree_hash_root()
        };

    // Cache block root.
    state.block_roots = state
        .block_roots
        .with_set(slot_idx, previous_block_root)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}

// ── state_transition (capella) ────────────────────────────────────────────────

/// `state_transition` for the capella `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:1370-1393` (identical interface in Capella).
pub fn state_transition<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    E,
    EE,
>(
    mut state: BeaconState<
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
    signed_block: &SignedBeaconBlock<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >,
    execution_engine: &EE,
    validate_result: bool,
    runtime_cfg: &RuntimeConfig,
) -> Result<
    (
        BeaconState<
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
        Option<PayloadVerificationStatus>,
    ),
    StateTransitionError,
>
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
            BellatrixBeaconState = pharos_types::bellatrix::BeaconState<
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
            CapellaBeaconState = BeaconState<
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
            CapellaBeaconBlock = BeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
            CapellaSignedBeaconBlock = SignedBeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
            AltairBeaconBlock = pharos_types::altair::BeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
        >,
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    pharos_types::capella::BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState: TreeHash,
    E::AltairBeaconBlock: BeaconBlockView,
    E::CapellaBeaconState: TreeHash,
    BLSPubkey: Default + Clone,
    EE: ExecutionEngine,
{
    let block = signed_block.message();

    // Step 1: process slots up to block.slot.
    process_slots_capella::<
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
    >(&mut state, block.slot())?;

    // Step 2: verify block signature when validate_result is true.
    if validate_result {
        let proposer_index = block.proposer_index();
        let proposer_pubkey = state
            .validators
            .get(proposer_index.0 as usize)
            .ok_or(StateTransitionError::InvalidBlockSignature)?
            .pubkey;

        let domain = {
            use crate::phase0::accessors::{compute_domain, compute_epoch_at_slot};
            let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
            let fork_version = if epoch < state.fork.epoch {
                state.fork.previous_version.into_inner()
            } else {
                state.fork.current_version.into_inner()
            };
            compute_domain(
                DOMAIN_BEACON_PROPOSER,
                fork_version,
                &state.genesis_validators_root,
            )
        };

        let signing_root = {
            use pharos_types::phase0::SigningData;
            SigningData {
                object_root: block.tree_hash_root(),
                domain,
            }
            .tree_hash_root()
        };

        let valid = pharos_utils::bls::verify(
            &proposer_pubkey,
            signing_root.as_slice(),
            signed_block.signature(),
        )
        .unwrap_or(false);
        if !valid {
            return Err(StateTransitionError::InvalidBlockSignature);
        }
    }

    // Step 3: process block.
    let payload_status = process_block::<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        E,
        EE,
    >(
        &mut state,
        &signed_block.message,
        execution_engine,
        validate_result,
        runtime_cfg,
    )?;

    // Step 4: verify state root when validate_result is true.
    if validate_result {
        let actual = state.tree_hash_root();
        let expected = block.state_root();
        if actual != expected {
            return Err(StateTransitionError::StateRootMismatch { expected, actual });
        }
    }

    Ok((state, payload_status))
}

// ── CapellaDispatch trait ─────────────────────────────────────────────────────

/// Dispatch trait for the capella state transition.
///
/// Implemented via blanket impl on `capella::BeaconState<...>`. Used by the
/// fork-dispatch in `lib.rs::state_transition`.
pub trait CapellaDispatch<E: EthSpec, EE: ExecutionEngine>: Sized {
    fn apply_signed_block(
        self,
        signed_block: &E::CapellaSignedBeaconBlock,
        execution_engine: &EE,
        validate_result: bool,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<(Self, Option<PayloadVerificationStatus>), StateTransitionError>;
}

impl<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    E,
    EE,
> CapellaDispatch<E, EE>
    for BeaconState<
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
    >
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
            BellatrixBeaconState = pharos_types::bellatrix::BeaconState<
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
            CapellaBeaconState = BeaconState<
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
            CapellaBeaconBlock = BeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
            CapellaSignedBeaconBlock = SignedBeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
            AltairBeaconBlock = pharos_types::altair::BeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
        >,
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    pharos_types::capella::BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState: TreeHash,
    E::AltairBeaconBlock: BeaconBlockView,
    E::CapellaBeaconState: TreeHash,
    BLSPubkey: Default + Clone,
    EE: ExecutionEngine,
{
    fn apply_signed_block(
        self,
        signed_block: &E::CapellaSignedBeaconBlock,
        execution_engine: &EE,
        validate_result: bool,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<(Self, Option<PayloadVerificationStatus>), StateTransitionError> {
        state_transition::<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            E,
            EE,
        >(
            self,
            signed_block,
            execution_engine,
            validate_result,
            runtime_cfg,
        )
    }
}

/// Dispatch trait for `process_slots` on capella states.
pub trait CapellaProcessSlotsDispatch<E: EthSpec>: Sized {
    fn process_slots_capella(
        &mut self,
        target_slot: pharos_types::phase0::Slot,
    ) -> Result<(), StateTransitionError>;
}

impl<
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
    E,
> CapellaProcessSlotsDispatch<E>
    for BeaconState<
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
    >
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
            BellatrixBeaconState = pharos_types::bellatrix::BeaconState<
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
            CapellaBeaconState = BeaconState<
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
    BLSPubkey: Default + Clone,
{
    fn process_slots_capella(
        &mut self,
        target_slot: pharos_types::phase0::Slot,
    ) -> Result<(), StateTransitionError> {
        process_slots_capella::<
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
        >(self, target_slot)
    }
}

// ── CapellaJaFDispatch trait ──────────────────────────────────────────────────

/// Dispatch trait for `process_justification_and_finalization` on capella states.
pub trait CapellaJaFDispatch<E: EthSpec>: Sized {
    fn process_jaf_capella(&mut self) -> Result<(), crate::error::EpochProcessingError>;
}

impl<
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
    E,
> CapellaJaFDispatch<E>
    for BeaconState<
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
    >
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
            CapellaBeaconState = BeaconState<
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
{
    fn process_jaf_capella(&mut self) -> Result<(), crate::error::EpochProcessingError> {
        use crate::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        let mut altair = capella_state_to_altair(self);
        process_justification_and_finalization::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(&mut altair)?;
        update_capella_from_altair(self, altair);
        Ok(())
    }
}

// ── GetExpectedWithdrawalsDispatch trait ──────────────────────────────────────

/// Dispatch trait for `get_expected_withdrawals` on capella states.
///
/// Allows `build_payload_attributes_v2` in `pharos-node` to call
/// `get_expected_withdrawals` through the opaque `E::CapellaBeaconState` associated
/// type. Implemented via blanket impl on `capella::BeaconState<...>`.
pub trait GetExpectedWithdrawalsDispatch<E: EthSpec> {
    /// Compute the list of expected withdrawals for the next block on this state.
    ///
    /// Per `specs/capella/beacon-chain.md` `get_expected_withdrawals`.
    fn get_expected_withdrawals_dispatch(&self) -> Vec<Withdrawal>;
}

impl<
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
    E,
> GetExpectedWithdrawalsDispatch<E>
    for BeaconState<
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
    >
where
    E: EthSpec<
        CapellaBeaconState = BeaconState<
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
{
    fn get_expected_withdrawals_dispatch(&self) -> Vec<Withdrawal> {
        get_expected_withdrawals::<
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
        >(self)
    }
}
