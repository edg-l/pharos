//! Altair state-transition entry point.
//!
//! Implements `state_transition` and `process_slots` for the concrete altair
//! `BeaconState`.
//!
//! spec: specs/phase0/beacon-chain.md:1370-1393 (identical interface in Altair)

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    altair::{BeaconBlock, BeaconState, SignedBeaconBlock},
    phase0::Slot,
    views::{BeaconBlockView, SignedBeaconBlockView},
};
use pharos_utils::BLSPubkey;

use crate::altair::block::process_block;
use crate::altair::epoch::process_epoch;
use crate::error::{EpochProcessingError, StateTransitionError};
use crate::phase0::helpers::DOMAIN_BEACON_PROPOSER;

// ── process_slots (altair) ────────────────────────────────────────────────────

/// `process_slots` for the altair `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:1396-1406` (identical in Altair).
///
/// Advances the state from its current slot up to `target_slot`, calling
/// `process_slot` at every step and the altair `process_epoch` at each epoch
/// boundary.
pub fn process_slots_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    target_slot: Slot,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
        AltairBeaconState = BeaconState<
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
    BLSPubkey: Default + Clone,
{
    if target_slot < state.slot {
        return Err(StateTransitionError::TargetSlotNotAfterCurrent {
            current: state.slot,
            target: target_slot,
        });
    }

    while state.slot < target_slot {
        process_slot_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state)?;

        // Process epoch on the start slot of the next epoch.
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

/// `process_slot` for the altair `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:1407-1425` (identical in Altair).
/// Caches state root and block root into the circular vectors and patches the
/// latest block header's `state_root` when still zeroed.
fn process_slot_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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

// ── state_transition (altair) ─────────────────────────────────────────────────

/// `state_transition` for the altair `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:1370-1393` (identical interface in Altair).
///
/// Sequence:
/// 1. `process_slots` (altair)
/// 2. Verify block signature (when `validate_result`)
/// 3. `process_block` (altair)
/// 4. Verify state root (when `validate_result`)
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
    E,
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
    >,
    validate_result: bool,
) -> Result<
    BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    StateTransitionError,
>
where
    E: EthSpec<
            AltairBeaconState = BeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            AltairBeaconBlock = BeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            AltairSignedBeaconBlock = SignedBeaconBlock<
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
    E::AltairBeaconState: TreeHash,
    E::AltairBeaconBlock: BeaconBlockView,
    BLSPubkey: Default + Clone,
{
    let block = signed_block.message();

    // Step 1: process slots (including those with no blocks) up to block.slot.
    process_slots_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&mut state, block.slot())?;

    // Step 2: verify block signature when validate_result is true.
    if validate_result {
        let proposer_index = block.proposer_index();
        let proposer_pubkey = state
            .validators
            .as_slice()
            .get(proposer_index.0 as usize)
            .ok_or(StateTransitionError::InvalidBlockSignature)?
            .pubkey;

        let domain = get_domain_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(&state, DOMAIN_BEACON_PROPOSER, None);

        let signing_root = compute_signing_root_altair(block, domain);

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
    process_block::<
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
        E,
    >(&mut state, &signed_block.message, validate_result)?;

    // Step 4: verify state root when validate_result is true.
    if validate_result {
        let actual = state.tree_hash_root();
        let expected = block.state_root();
        if actual != expected {
            return Err(StateTransitionError::StateRootMismatch { expected, actual });
        }
    }

    Ok(state)
}

// ── Altair-local domain / signing-root helpers ────────────────────────────────
//
// `get_domain` from phase0 is generic over `E::BeaconState: BeaconStateView`.
// The altair inner `BeaconState` does not implement that trait.
// We inline the trivial computation here.

fn get_domain_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    domain_type: [u8; 4],
    message_epoch: Option<pharos_types::phase0::Epoch>,
) -> pharos_utils::Hash256 {
    use crate::phase0::accessors::{compute_domain, compute_epoch_at_slot};

    let epoch =
        message_epoch.unwrap_or_else(|| compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH));
    let fork_version = if epoch < state.fork.epoch {
        state.fork.previous_version.into_inner()
    } else {
        state.fork.current_version.into_inner()
    };
    compute_domain(domain_type, fork_version, &state.genesis_validators_root)
}

/// Compute the signing root for any SSZ-hashable object (block).
fn compute_signing_root_altair<T: TreeHash>(
    object: &T,
    domain: pharos_utils::Hash256,
) -> pharos_types::phase0::Root {
    use pharos_types::phase0::SigningData;
    SigningData {
        object_root: object.tree_hash_root(),
        domain,
    }
    .tree_hash_root()
}

// ── AltairJaFDispatch trait ───────────────────────────────────────────────────
//
// Mirrors `AltairDispatch` but for `process_justification_and_finalization`.
// Needed by `compute_pulled_up_tip` in `pharos-fork-choice`, which must call
// the altair version of J&F on altair states (the phase0 version panics because
// it writes through `BeaconStateWrite` which guards against altair states).

/// Dispatch trait for `process_justification_and_finalization` on altair states.
///
/// Implemented via blanket impl on `altair::BeaconState<...>`. Allows
/// code generic over `E: EthSpec` to call the altair J&F routine through
/// the opaque `E::AltairBeaconState` associated type.
pub trait AltairJaFDispatch<E: EthSpec>: Sized {
    /// Run `process_justification_and_finalization` on `self` (in place).
    fn process_jaf(&mut self) -> Result<(), EpochProcessingError>;
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
    E,
> AltairJaFDispatch<E>
    for BeaconState<
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
        AltairBeaconState = BeaconState<
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
{
    fn process_jaf(&mut self) -> Result<(), EpochProcessingError> {
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
        >(self)
    }
}

// ── AltairProcessSlotsDispatch trait ─────────────────────────────────────────
//
// Mirrors `AltairJaFDispatch` but for `process_slots`.
// Needed by `update_proposer_boost_root` and `store_target_checkpoint_state`
// in `pharos-fork-choice`, which must call the altair version of `process_slots`
// on altair states (the phase0 version panics via `BeaconStateWrite` guards).

/// Dispatch trait for `process_slots` on altair states.
///
/// Implemented via blanket impl on `altair::BeaconState<...>`. Allows
/// code generic over `E: EthSpec` to call the altair `process_slots` through
/// the opaque `E::AltairBeaconState` associated type.
pub trait AltairProcessSlotsDispatch<E: EthSpec>: Sized {
    /// Advance `self` to `target_slot` (altair `process_slots`).
    fn process_slots_altair(
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
    E,
> AltairProcessSlotsDispatch<E>
    for BeaconState<
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
        AltairBeaconState = BeaconState<
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
    BLSPubkey: Default + Clone,
{
    fn process_slots_altair(
        &mut self,
        target_slot: pharos_types::phase0::Slot,
    ) -> Result<(), StateTransitionError> {
        process_slots_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(self, target_slot)
    }
}

// ── AltairDispatch trait ──────────────────────────────────────────────────────
//
// This trait provides a single-method interface so that `lib.rs::state_transition`
// can dispatch to the altair STF without knowing the concrete const-generic
// params of the altair `BeaconState`. Each `altair::BeaconState<...>` gets a
// blanket impl that calls `state_transition` with the right parameters.

/// Dispatch trait for the altair state transition.
///
/// Implemented via blanket impl on `altair::BeaconState<...>`. Used by the
/// fork-dispatch in `lib.rs::state_transition` so that code generic over
/// `E: EthSpec` can invoke the altair STF without knowing concrete const params.
pub trait AltairDispatch<E: EthSpec>: Sized {
    /// Apply `signed_block` to `self` and return the updated state.
    fn apply_signed_block(
        self,
        signed_block: &E::AltairSignedBeaconBlock,
        validate_result: bool,
    ) -> Result<Self, StateTransitionError>;
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
    E,
> AltairDispatch<E>
    for BeaconState<
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
            AltairBeaconState = BeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            AltairBeaconBlock = BeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            AltairSignedBeaconBlock = SignedBeaconBlock<
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
    E::AltairBeaconState: TreeHash,
    E::AltairBeaconBlock: BeaconBlockView,
    BLSPubkey: Default + Clone,
{
    fn apply_signed_block(
        self,
        signed_block: &E::AltairSignedBeaconBlock,
        validate_result: bool,
    ) -> Result<Self, StateTransitionError> {
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
            E,
        >(self, signed_block, validate_result)
    }
}
