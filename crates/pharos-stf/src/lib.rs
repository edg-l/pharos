//! Beacon-chain state transition function.
//!
//! `process_block`, `process_epoch`, per-operation processors, BLS batch
//! verification. Sync core; callers wrap in `spawn_blocking` from async
//! contexts.
//!
//! Conformance: `consensus-specs/tests/formats/{operations,epoch_processing,
//! sanity,finality,random,rewards}`.
//!
//! # Cross-crate re-exports (Phases 4 and 8)
//!
//! When Phase 4 lands `process_justification_and_finalization`, add:
//!   pub use phase0::epoch::justification_and_finalization::process_justification_and_finalization;
//!
//! Called from `pharos_fork_choice::handlers::compute_pulled_up_tip` (Task 8.3).
//! Any additional epoch sub-routines consumed by pharos-fork-choice should be
//! re-exported here at the same time.

pub mod altair;
pub mod bellatrix;
pub mod error;
pub mod phase0;

pub use altair::state_transition::{AltairDispatch, AltairJaFDispatch, AltairProcessSlotsDispatch};
pub use bellatrix::execution_engine::{ExecutionEngine, FixedExecutionEngine, NullExecutionEngine};
pub use bellatrix::state_transition::{BellatrixDispatch, BellatrixProcessSlotsDispatch};
pub use phase0::block::process_block;
pub use phase0::epoch::justification_and_finalization::process_justification_and_finalization;
pub use phase0::epoch::process_epoch;
pub use phase0::genesis::{initialize_beacon_state_from_eth1, is_valid_genesis_state};
pub use phase0::slot::process_slots;

pub use error::{
    AttestationInvalidReason, AttesterSlashingInvalidReason, BlockHeaderInvalidReason,
    DepositInvalidReason, EpochProcessingError, ProposerSlashingInvalidReason,
    StateTransitionError, VoluntaryExitInvalidReason,
};

use pharos_ssz::TreeHash;
use pharos_types::{
    BeaconStateView, EthSpec,
    config::RuntimeConfig,
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::{BeaconBlockBodyView, BeaconBlockView, ForkVariant, SignedBeaconBlockView},
};

use phase0::{
    accessors::{compute_signing_root, get_domain},
    helpers::DOMAIN_BEACON_PROPOSER,
    state_write::BeaconStateWrite,
};

/// `state_transition` per `specs/phase0/beacon-chain.md:1370-1393`.
///
/// Dispatches on the `BeaconState` fork variant:
/// - `Phase0` → unwraps the block to the concrete phase0 signed block, then
///   calls the phase0 STF (`process_slots`, `process_block`).
/// - `Altair` → unwraps state and block to altair inner types, calls the altair
///   STF via `AltairDispatch`, wraps result back into the fork-enum.
/// - `Bellatrix` → unwraps state and block to bellatrix inner types, calls the
///   bellatrix STF via `BellatrixDispatch`, wraps result back into the fork-enum.
///
/// Advances `state` to `signed_block.message.slot` via `process_slots`,
/// optionally verifies the block signature and final state root, then
/// applies the block. Returns the updated state.
///
/// When `validate_result` is `false`, the BLS block-signature check and the
/// `block.state_root == hash_tree_root(state)` post-condition are both skipped
/// (per Q3 resolution); `verify_signatures` is also set to `false` so every
/// per-operation BLS check is skipped.
///
/// `execution_engine` is used only for the Bellatrix arm; phase0 and altair
/// arms ignore it. Pass `&NullExecutionEngine` for non-EL contexts (spec tests).
pub fn state_transition<E: EthSpec, EE: ExecutionEngine>(
    mut state: E::BeaconState,
    signed_block: &E::SignedBeaconBlock,
    execution_engine: &EE,
    validate_result: bool,
    runtime_cfg: &RuntimeConfig,
) -> Result<E::BeaconState, StateTransitionError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairBeaconState: AltairDispatch<E>,
    E::BellatrixBeaconState: BellatrixDispatch<E, EE> + TreeHash,
{
    // Fork dispatch via `fork_variant()`. Cannot pattern-match on a concrete
    // enum variant through the opaque `E::BeaconState` associated type;
    // `fork_variant()` provides the required discriminant.
    match state.fork_variant() {
        ForkVariant::Phase0 => {
            // Unwrap the fork-enum signed block to the concrete phase0 inner type.
            // The block must be a Phase0 variant; if it isn't, return an error rather
            // than panic.
            let phase0_signed = E::unwrap_phase0_signed_block(signed_block)
                .ok_or(StateTransitionError::UnsupportedFork)?;
            phase0_state_transition::<E>(&mut state, phase0_signed, validate_result)?;
        }
        ForkVariant::Altair => {
            // Unwrap fork-enum state and block to their inner altair types.
            let altair_signed = E::unwrap_altair_signed_block(signed_block)
                .ok_or(StateTransitionError::UnsupportedFork)?;
            let altair_inner =
                E::into_altair_state(state).ok_or(StateTransitionError::UnsupportedFork)?;
            // Apply the altair state transition via the `AltairDispatch` blanket impl.
            let updated = altair_inner.apply_signed_block(altair_signed, validate_result)?;
            // Wrap the result back into the fork-enum.
            return Ok(E::altair_into_state(updated));
        }
        ForkVariant::Bellatrix => {
            // Unwrap fork-enum state and block to their inner bellatrix types.
            let bellatrix_signed = E::unwrap_bellatrix_signed_block(signed_block)
                .ok_or(StateTransitionError::UnsupportedFork)?;
            let bellatrix_inner =
                E::into_bellatrix_state(state).ok_or(StateTransitionError::UnsupportedFork)?;
            // Apply the bellatrix state transition via the `BellatrixDispatch` blanket impl.
            let updated = bellatrix_inner.apply_signed_block(
                bellatrix_signed,
                execution_engine,
                validate_result,
                runtime_cfg,
            )?;
            // Wrap the result back into the fork-enum.
            return Ok(E::bellatrix_into_state(updated));
        }
    }
    Ok(state)
}

/// Phase0 inner state transition.
///
/// Called from `state_transition` after variant dispatch. Takes the concrete
/// phase0 signed block (already unwrapped from the fork-enum by the caller).
fn phase0_state_transition<E: EthSpec>(
    state: &mut E::BeaconState,
    signed_block: &E::Phase0SignedBeaconBlock,
    validate_result: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
{
    let block = signed_block.message();

    // Process slots (including those with no blocks) since block.
    process_slots::<E>(state, block.slot())?;

    // Verify block signature when validate_result is true.
    // Per `specs/phase0/beacon-chain.md:1387-1392`, the proposer pubkey is
    // looked up using the block's claimed `proposer_index`, not the slot-derived
    // proposer. `process_block_header` separately checks that the two agree.
    if validate_result {
        let proposer_index = block.proposer_index();
        let proposer_pubkey = state
            .validator(proposer_index.0 as usize)
            .ok_or(StateTransitionError::InvalidBlockSignature)?
            .pubkey;

        let domain = get_domain::<E>(state, DOMAIN_BEACON_PROPOSER, None);
        let signing_root = compute_signing_root(block, domain);

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

    // Process block, threading verify_signatures from validate_result.
    process_block::<E>(state, block, validate_result)?;

    // Verify state root when validate_result is true.
    if validate_result {
        let actual = state.tree_hash_root();
        let expected = block.state_root();
        if actual != expected {
            return Err(StateTransitionError::StateRootMismatch { expected, actual });
        }
    }

    Ok(())
}

/// Fork-aware `process_justification_and_finalization`.
///
/// Dispatches to the phase0, altair, or bellatrix implementation depending on
/// the fork variant of `state`. Called from
/// `pharos_fork_choice::compute_pulled_up_tip` which holds a fork-enum
/// `BeaconState` that may be any fork variant.
pub fn process_justification_and_finalization_fork<E: EthSpec>(
    state: &mut E::BeaconState,
) -> Result<(), EpochProcessingError>
where
    E::BeaconState: phase0::state_write::BeaconStateWrite,
    E::AltairBeaconState: AltairJaFDispatch<E>,
    E::BellatrixBeaconState: BellatrixJaFDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
{
    use pharos_types::views::ForkVariant;
    match state.fork_variant() {
        ForkVariant::Phase0 => process_justification_and_finalization::<E>(state),
        ForkVariant::Altair => {
            let mut inner = E::into_altair_state(state.clone()).expect("fork_variant is Altair");
            inner.process_jaf()?;
            *state = E::altair_into_state(inner);
            Ok(())
        }
        ForkVariant::Bellatrix => {
            let mut inner =
                E::into_bellatrix_state(state.clone()).expect("fork_variant is Bellatrix");
            inner.process_jaf_bellatrix()?;
            *state = E::bellatrix_into_state(inner);
            Ok(())
        }
    }
}

/// Fork-aware `process_slots`.
///
/// Dispatches to the phase0, altair, or bellatrix implementation depending on
/// the fork variant of `state`. Called from `pharos_fork_choice` helpers that
/// advance an opaque fork-enum `BeaconState` by one or more slots.
pub fn process_slots_fork<E: EthSpec>(
    state: &mut E::BeaconState,
    target_slot: pharos_types::phase0::Slot,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: phase0::state_write::BeaconStateWrite + TreeHash,
    E::AltairBeaconState: AltairProcessSlotsDispatch<E>,
    E::BellatrixBeaconState: BellatrixProcessSlotsDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
{
    use pharos_types::views::ForkVariant;
    match state.fork_variant() {
        ForkVariant::Phase0 => process_slots::<E>(state, target_slot),
        ForkVariant::Altair => {
            let mut inner = E::into_altair_state(state.clone()).expect("fork_variant is Altair");
            inner.process_slots_altair(target_slot)?;
            *state = E::altair_into_state(inner);
            Ok(())
        }
        ForkVariant::Bellatrix => {
            let mut inner =
                E::into_bellatrix_state(state.clone()).expect("fork_variant is Bellatrix");
            inner.process_slots_bellatrix(target_slot)?;
            *state = E::bellatrix_into_state(inner);
            Ok(())
        }
    }
}

// ── BellatrixJaFDispatch trait ────────────────────────────────────────────────

/// Dispatch trait for `process_justification_and_finalization` on bellatrix states.
///
/// Bellatrix J&F is identical to Altair J&F; this trait allows
/// `process_justification_and_finalization_fork` to call it through the opaque
/// `E::BellatrixBeaconState` associated type without knowing concrete const params.
pub trait BellatrixJaFDispatch<E: EthSpec>: Sized {
    /// Run `process_justification_and_finalization` on `self` (in place).
    fn process_jaf_bellatrix(&mut self) -> Result<(), EpochProcessingError>;
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
> BellatrixJaFDispatch<E>
    for pharos_types::bellatrix::BeaconState<
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
            AltairBeaconState = pharos_types::altair::BeaconState<
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
        >,
{
    fn process_jaf_bellatrix(&mut self) -> Result<(), EpochProcessingError> {
        // Bellatrix J&F is identical to Altair J&F.
        // Project to altair, run J&F, copy back.
        let mut altair = bellatrix::helpers::bellatrix_state_to_altair(self);
        crate::altair::epoch::process_justification_and_finalization::<
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
        bellatrix::helpers::update_bellatrix_from_altair(self, altair);
        Ok(())
    }
}
