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
pub mod capella;
pub mod error;
pub mod phase0;

pub use altair::light_client_dispatch::{
    AltairDispatchBounds, BellatrixDispatchBounds, CapellaDispatchBounds,
};
pub use altair::state_transition::{AltairDispatch, AltairJaFDispatch, AltairProcessSlotsDispatch};
pub use bellatrix::execution_engine::{ExecutionEngine, FixedExecutionEngine, NullExecutionEngine};
pub use bellatrix::state_transition::{BellatrixDispatch, BellatrixProcessSlotsDispatch};
pub use capella::state_transition::{
    CapellaDispatch, CapellaJaFDispatch, CapellaProcessSlotsDispatch,
};
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

// ── ForkEpochs ────────────────────────────────────────────────────────────────

/// Runtime fork epochs threaded into `process_slots_fork` so the live path can
/// trigger irregular fork transitions without knowing compile-time const params.
///
/// All fields are epoch numbers (`u64`). `u64::MAX` is the conventional
/// "never upgrade" sentinel (matching `FAR_FUTURE_EPOCH` in the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkEpochs {
    /// Epoch at which phase0 upgrades to Altair (`ALTAIR_FORK_EPOCH`).
    pub altair: u64,
    /// Epoch at which Altair upgrades to Bellatrix (`BELLATRIX_FORK_EPOCH`).
    pub bellatrix: u64,
    /// Epoch at which Bellatrix upgrades to Capella (`CAPELLA_FORK_EPOCH`).
    pub capella: u64,
}

impl ForkEpochs {
    /// All fork epochs set to `u64::MAX` — no upgrade ever triggers.
    ///
    /// Used by single-fork test helpers, benches, and conformance helpers
    /// that construct single-fork chains and must not cross a fork boundary.
    pub fn never() -> Self {
        Self {
            altair: u64::MAX,
            bellatrix: u64::MAX,
            capella: u64::MAX,
        }
    }
}

// ── Upgrade dispatch traits ───────────────────────────────────────────────────
//
// These traits mirror the `*ProcessSlotsDispatch` pattern: a single method on
// the concrete inner state type that delegates to the existing concrete
// `upgrade_to_*` free functions. They allow `process_slots_fork` — which is
// generic over `E: EthSpec` and cannot call const-generic fns directly — to
// invoke the upgrade through the opaque associated type.

/// Dispatch trait for upgrading a phase0 state to Altair.
///
/// Implemented via blanket impl on `phase0::BeaconState<...>`. Called from
/// `process_slots_fork` when it reaches the Altair fork epoch boundary.
pub trait Phase0UpgradeDispatch<E: EthSpec>: Sized {
    /// Upgrade `self` (phase0 inner state) to an Altair inner state.
    fn upgrade_to_altair_dispatch(
        self,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<E::AltairBeaconState, StateTransitionError>;
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
> Phase0UpgradeDispatch<E>
    for pharos_types::phase0::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
    >
where
    E: EthSpec<
            Phase0BeaconState = pharos_types::phase0::BeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                MAX_PENDING_ATTESTATIONS,
                JUSTIFICATION_BITS_LENGTH,
                MAX_VALIDATORS_PER_COMMITTEE,
            >,
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
        >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    fn upgrade_to_altair_dispatch(
        self,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<E::AltairBeaconState, StateTransitionError> {
        altair::upgrade::upgrade_to_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_PENDING_ATTESTATIONS,
            JUSTIFICATION_BITS_LENGTH,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            E,
        >(self, runtime_cfg)
    }
}

/// Dispatch trait for upgrading an Altair state to Bellatrix.
///
/// Implemented via blanket impl on `altair::BeaconState<...>`. Called from
/// `process_slots_fork` when it reaches the Bellatrix fork epoch boundary.
pub trait AltairUpgradeDispatch<E: EthSpec>: Sized {
    /// Upgrade `self` (Altair inner state) to a Bellatrix inner state.
    fn upgrade_to_bellatrix_dispatch(
        self,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<E::BellatrixBeaconState, StateTransitionError>;
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
> AltairUpgradeDispatch<E>
    for pharos_types::altair::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
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
    fn upgrade_to_bellatrix_dispatch(
        self,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<E::BellatrixBeaconState, StateTransitionError> {
        bellatrix::upgrade::upgrade_to_bellatrix::<
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
        >(self, runtime_cfg)
    }
}

/// Dispatch trait for upgrading a Bellatrix state to Capella.
///
/// Implemented via blanket impl on `bellatrix::BeaconState<...>`. Called from
/// `process_slots_fork` when it reaches the Capella fork epoch boundary.
pub trait BellatrixUpgradeDispatch<E: EthSpec>: Sized {
    /// Upgrade `self` (Bellatrix inner state) to a Capella inner state.
    fn upgrade_to_capella_dispatch(
        self,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<E::CapellaBeaconState, StateTransitionError>;
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
> BellatrixUpgradeDispatch<E>
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
            CapellaBeaconState = pharos_types::capella::BeaconState<
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
    fn upgrade_to_capella_dispatch(
        self,
        runtime_cfg: &RuntimeConfig,
    ) -> Result<E::CapellaBeaconState, StateTransitionError> {
        capella::upgrade::upgrade_to_capella::<
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
        >(self, runtime_cfg)
    }
}

/// `state_transition` per `specs/phase0/beacon-chain.md:1370-1393`.
///
/// Dispatches on the `BeaconState` fork variant:
/// - `Phase0` → unwraps the block to the concrete phase0 signed block, then
///   calls the phase0 STF (`process_slots`, `process_block`).
/// - `Altair` → unwraps state and block to altair inner types, calls the altair
///   STF via `AltairDispatch`, wraps result back into the fork-enum.
/// - `Bellatrix` → unwraps state and block to bellatrix inner types, calls the
///   bellatrix STF via `BellatrixDispatch`, wraps result back into the fork-enum.
/// - `Capella` → unwraps state and block to capella inner types, calls the
///   capella STF via `CapellaDispatch`, wraps result back into the fork-enum.
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
/// `execution_engine` is used for Bellatrix and Capella arms; phase0 and altair
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
    E::CapellaBeaconState: CapellaDispatch<E, EE> + TreeHash,
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
            // Wrap the result back into the fork-enum + invalidate the root cache.
            let mut wrapped = E::bellatrix_into_state(updated);
            wrapped.invalidate_root_cache();
            return Ok(wrapped);
        }
        ForkVariant::Capella => {
            // Unwrap fork-enum state and block to their inner capella types.
            let capella_signed = E::unwrap_capella_signed_block(signed_block)
                .ok_or(StateTransitionError::UnsupportedFork)?;
            let capella_inner =
                E::into_capella_state(state).ok_or(StateTransitionError::UnsupportedFork)?;
            // Apply the capella state transition via the `CapellaDispatch` blanket impl.
            let updated = capella_inner.apply_signed_block(
                capella_signed,
                execution_engine,
                validate_result,
                runtime_cfg,
            )?;
            // Wrap the result back into the fork-enum + invalidate the root cache.
            let mut wrapped = E::capella_into_state(updated);
            wrapped.invalidate_root_cache();
            return Ok(wrapped);
        }
    }
    // STF mutated `state` (phase0 + altair arms operate on `&mut state`); reset
    // the cached top-level root so the next `cached_tree_hash_root` call
    // recomputes from the post-STF state.
    state.invalidate_root_cache();
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
    E::CapellaBeaconState: CapellaJaFDispatch<E>,
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
        ForkVariant::Capella => {
            let mut inner = E::into_capella_state(state.clone()).expect("fork_variant is Capella");
            inner.process_jaf_capella()?;
            *state = E::capella_into_state(inner);
            Ok(())
        }
    }
}

/// Fork-aware `process_slots`, upgrade-aware.
///
/// Advances `state` to `target_slot` through any fork boundaries encountered.
/// When the advance reaches the first slot of a fork epoch (the boundary at
/// which the spec performs the irregular fork transition), the state is
/// upgraded to the next fork variant in-place and the advance continues.
///
/// `fork_epochs` carries the three fork epoch numbers for the current network.
/// Pass `ForkEpochs::never()` from single-fork tests and benches to suppress
/// any upgrade trigger and preserve byte-identical behaviour.
///
/// # Spec ordering
///
/// Per `specs/*/fork.md`, `process_slots` runs up to the boundary slot first
/// (so `process_epoch` for the last pre-fork epoch executes), then the upgrade
/// is applied. The loop guard `state.slot() < boundary_slot` enforces this.
///
/// # Multi-fork advance
///
/// A phase0 state can be advanced past both the Altair and Bellatrix (and
/// Capella) boundaries in one call. The loop re-evaluates after each upgrade
/// so every fork is crossed in order.
///
/// # Coincident fork epochs
///
/// Fork-at-genesis (epoch 0) is handled by the genesis builder, not here.
/// Coincident non-genesis fork epochs (two forks at the same epoch) are not
/// supported; real networks use distinct epochs. The strict `<` guard in
/// `boundary_slot_if` is intentional.
pub fn process_slots_fork<E: EthSpec>(
    state: &mut E::BeaconState,
    target_slot: pharos_types::phase0::Slot,
    fork_epochs: ForkEpochs,
    runtime_cfg: &RuntimeConfig,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: phase0::state_write::BeaconStateWrite + TreeHash,
    E::AltairBeaconState: AltairProcessSlotsDispatch<E>,
    E::BellatrixBeaconState: BellatrixProcessSlotsDispatch<E>,
    E::CapellaBeaconState: CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
    E::AltairBeaconState: AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixUpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
{
    use pharos_types::views::ForkVariant;

    // Returns the boundary slot for `fork_epoch` if there is a fork boundary
    // strictly after `current_slot` and at or before `target_slot`.
    // `epoch * SLOTS_PER_EPOCH` is the first slot of the fork epoch.
    // Takes `current_slot` explicitly so the closure does not borrow `state`.
    let boundary_slot_if = |fork_epoch: u64,
                            current_slot: pharos_types::phase0::Slot|
     -> Option<pharos_types::phase0::Slot> {
        if fork_epoch == u64::MAX {
            return None;
        }
        let boundary = pharos_types::phase0::Slot(fork_epoch.saturating_mul(E::SLOTS_PER_EPOCH));
        if current_slot < boundary && boundary <= target_slot {
            Some(boundary)
        } else {
            None
        }
    };

    loop {
        let current_slot = state.slot();
        if current_slot >= target_slot {
            break;
        }

        let cur = state.fork_variant();

        // Determine the next fork boundary strictly after current slot and ≤ target_slot.
        let next_boundary: Option<pharos_types::phase0::Slot> = match cur {
            ForkVariant::Phase0 => boundary_slot_if(fork_epochs.altair, current_slot),
            ForkVariant::Altair => boundary_slot_if(fork_epochs.bellatrix, current_slot),
            ForkVariant::Bellatrix => boundary_slot_if(fork_epochs.capella, current_slot),
            ForkVariant::Capella => None,
        };

        let step_target = next_boundary.unwrap_or(target_slot);

        // Advance the current fork to `step_target`.
        match cur {
            ForkVariant::Phase0 => process_slots::<E>(state, step_target)?,
            ForkVariant::Altair => {
                let mut inner =
                    E::into_altair_state(state.clone()).expect("fork_variant is Altair");
                inner.process_slots_altair(step_target)?;
                *state = E::altair_into_state(inner);
            }
            ForkVariant::Bellatrix => {
                let mut inner =
                    E::into_bellatrix_state(state.clone()).expect("fork_variant is Bellatrix");
                inner.process_slots_bellatrix(step_target)?;
                *state = E::bellatrix_into_state(inner);
            }
            ForkVariant::Capella => {
                let mut inner =
                    E::into_capella_state(state.clone()).expect("fork_variant is Capella");
                inner.process_slots_capella(step_target)?;
                *state = E::capella_into_state(inner);
            }
        }

        // If we stopped at a fork boundary, perform the upgrade.
        match next_boundary {
            Some(boundary) if boundary == step_target => {
                // Advance to boundary has completed; now apply the irregular fork upgrade.
                match state.fork_variant() {
                    ForkVariant::Phase0 => {
                        let inner =
                            E::into_phase0_state(state.clone()).expect("fork_variant is Phase0");
                        let upgraded = inner.upgrade_to_altair_dispatch(runtime_cfg)?;
                        *state = E::altair_into_state(upgraded);
                    }
                    ForkVariant::Altair => {
                        let inner =
                            E::into_altair_state(state.clone()).expect("fork_variant is Altair");
                        let upgraded = inner.upgrade_to_bellatrix_dispatch(runtime_cfg)?;
                        *state = E::bellatrix_into_state(upgraded);
                    }
                    ForkVariant::Bellatrix => {
                        let inner = E::into_bellatrix_state(state.clone())
                            .expect("fork_variant is Bellatrix");
                        let upgraded = inner.upgrade_to_capella_dispatch(runtime_cfg)?;
                        *state = E::capella_into_state(upgraded);
                    }
                    ForkVariant::Capella => {
                        // Capella is the last supported fork; no successor boundary.
                        break;
                    }
                }
                // Loop continues: re-evaluate with the upgraded fork variant.
            }
            _ => break,
        }
    }

    Ok(())
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

// ── process_slots_fork upgrade-trigger tests ──────────────────────────────────

#[cfg(test)]
mod fork_upgrade_tests {
    use pharos_types::{
        BeaconStateView as _, EthSpec, MinimalEthSpec, config::RuntimeConfig, phase0::Slot,
        views::ForkVariant,
    };

    use super::{ForkEpochs, process_slots_fork};

    /// Build a minimal Bellatrix fork-enum state at `slot` for upgrade tests.
    ///
    /// Uses `Default::default()` for the inner bellatrix state (zero validators,
    /// all fields zero). This is sufficient for epoch processing in the tests
    /// because zero-validator epoch processing is a no-op for all iteration steps.
    ///
    /// The `randao_mixes` vector must be non-empty per the spec (length =
    /// EPOCHS_PER_HISTORICAL_VECTOR). `Default` fills it correctly.
    fn make_bellatrix_state_at_slot(slot: Slot) -> <MinimalEthSpec as EthSpec>::BeaconState {
        use pharos_types::MinimalEthSpec as E;

        // Build a default inner state then set the slot; the clippy lint
        // "field assignment outside of initializer" is suppressed here because
        // `E::BellatrixBeaconState` is an opaque associated type — struct literal
        // syntax requires a concrete type path which is not available generically.
        #[allow(clippy::field_reassign_with_default)]
        let inner = {
            let mut s = <E as EthSpec>::BellatrixBeaconState::default();
            s.slot = slot;
            s
        };
        <E as EthSpec>::bellatrix_into_state(inner)
    }

    /// `process_slots_fork` with a real `capella_fork_epoch` upgrades the state
    /// from Bellatrix to Capella when it advances through the fork boundary.
    ///
    /// Scenario: bellatrix state at slot `capella_epoch * SPE - 1`, advance to
    /// `capella_epoch * SPE + 1`. The loop: advances to the boundary (crossing
    /// one epoch), applies `upgrade_to_capella`, then advances one more slot.
    #[test]
    fn process_slots_fork_upgrades_bellatrix_to_capella() {
        type E = MinimalEthSpec;
        let spe = E::SLOTS_PER_EPOCH;
        // Use epoch 2 as the capella epoch so there is a clear boundary.
        let capella_epoch = 2u64;
        let boundary_slot = Slot(capella_epoch * spe);
        // Start one slot before the boundary.
        let start_slot = Slot(capella_epoch * spe - 1);

        let mut state = make_bellatrix_state_at_slot(start_slot);
        assert_eq!(state.fork_variant(), ForkVariant::Bellatrix);

        let runtime_cfg = RuntimeConfig {
            capella_fork_version: MinimalEthSpec::CAPELLA_FORK_VERSION,
            capella_fork_epoch: capella_epoch,
            // Other fork epochs far in the future so only capella fires.
            altair_fork_epoch: u64::MAX,
            bellatrix_fork_epoch: u64::MAX,
            ..RuntimeConfig::default()
        };
        let fork_epochs = ForkEpochs {
            altair: u64::MAX,
            bellatrix: u64::MAX,
            capella: capella_epoch,
        };

        // Advance to one slot past the boundary — triggers the upgrade.
        let target = Slot(boundary_slot.0 + 1);
        process_slots_fork::<E>(&mut state, target, fork_epochs, &runtime_cfg)
            .expect("process_slots_fork should succeed");

        assert_eq!(
            state.fork_variant(),
            ForkVariant::Capella,
            "state must be Capella after crossing capella_fork_epoch boundary"
        );
        assert_eq!(state.slot(), target, "state.slot must equal target_slot");
    }

    /// Regression: with `ForkEpochs::never()`, advancing a Bellatrix state
    /// does NOT trigger any upgrade — it stays Bellatrix.
    #[test]
    fn process_slots_fork_never_stays_bellatrix() {
        type E = MinimalEthSpec;
        let spe = E::SLOTS_PER_EPOCH;
        // Even though `capella_fork_epoch` in the runtime_cfg says epoch 2,
        // ForkEpochs::never() suppresses all upgrade triggers.
        let start_slot = Slot(spe * 2 - 1);
        let mut state = make_bellatrix_state_at_slot(start_slot);

        assert_eq!(state.fork_variant(), ForkVariant::Bellatrix);

        let runtime_cfg = RuntimeConfig::default();
        let target = Slot(spe * 2 + 1);
        process_slots_fork::<E>(&mut state, target, ForkEpochs::never(), &runtime_cfg)
            .expect("process_slots_fork should succeed");

        assert_eq!(
            state.fork_variant(),
            ForkVariant::Bellatrix,
            "ForkEpochs::never() must not trigger any upgrade"
        );
    }

    /// Build a minimal Altair fork-enum state at `slot` for upgrade tests.
    fn make_altair_state_at_slot(slot: Slot) -> <MinimalEthSpec as EthSpec>::BeaconState {
        use pharos_types::MinimalEthSpec as E;
        #[allow(clippy::field_reassign_with_default)]
        let inner = {
            let mut s = <E as EthSpec>::AltairBeaconState::default();
            s.slot = slot;
            s
        };
        <E as EthSpec>::altair_into_state(inner)
    }

    /// Multi-fork jump: an Altair state advanced in a SINGLE `process_slots_fork`
    /// call across BOTH the bellatrix and capella fork-epoch boundaries must
    /// upgrade through each fork in order (the checkpoint-catch-up path).
    ///
    /// This exercises the loop's multi-hop iteration plus the altair→bellatrix
    /// and bellatrix→capella dispatch legs. We start at Altair (not Phase0)
    /// because `upgrade_to_altair` computes the initial sync committee via
    /// `get_next_sync_committee`, which requires a populated validator set —
    /// out of scope for a zero-validator unit test. The phase0→altair leg's
    /// upgrade correctness is covered by the `altair/transition` conformance
    /// category; the altair→bellatrix / bellatrix→capella upgrades only COPY the
    /// sync committee forward, so they work with zero validators (and
    /// `process_sync_committee_updates` does not recompute at the epochs crossed
    /// here — the sync-committee period is not hit).
    #[test]
    fn process_slots_fork_multi_hop_altair_to_capella() {
        type E = MinimalEthSpec;
        let spe = E::SLOTS_PER_EPOCH;
        // Altair already active (epoch 0); bellatrix at epoch 1, capella at epoch 2.
        let (bellatrix_epoch, capella_epoch) = (1u64, 2u64);

        let mut state = make_altair_state_at_slot(Slot(0));
        assert_eq!(state.fork_variant(), ForkVariant::Altair);

        let runtime_cfg = RuntimeConfig {
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            capella_fork_version: MinimalEthSpec::CAPELLA_FORK_VERSION,
            altair_fork_epoch: 0,
            bellatrix_fork_epoch: bellatrix_epoch,
            capella_fork_epoch: capella_epoch,
            ..RuntimeConfig::default()
        };
        let fork_epochs = ForkEpochs {
            altair: 0,
            bellatrix: bellatrix_epoch,
            capella: capella_epoch,
        };

        // One slot into the capella epoch: crosses bellatrix (slot spe) and
        // capella (2*spe) boundaries in a single call.
        let target = Slot(capella_epoch * spe + 1);
        process_slots_fork::<E>(&mut state, target, fork_epochs, &runtime_cfg)
            .expect("multi-hop process_slots_fork should succeed");

        assert_eq!(
            state.fork_variant(),
            ForkVariant::Capella,
            "state must upgrade altair→bellatrix→capella across both boundaries"
        );
        assert_eq!(state.slot(), target);
    }
}
