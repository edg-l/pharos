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

pub mod error;
pub mod phase0;

pub use phase0::block::process_block;
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
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use phase0::{
    accessors::{compute_signing_root, get_domain},
    helpers::DOMAIN_BEACON_PROPOSER,
    state_write::BeaconStateWrite,
};

/// `state_transition` per `specs/phase0/beacon-chain.md:1370-1393`.
///
/// Advances `state` to `signed_block.message.slot` via `process_slots`,
/// optionally verifies the block signature and final state root, then
/// applies the block. Returns the updated state.
///
/// When `validate_result` is `false`, the BLS block-signature check and the
/// `block.state_root == hash_tree_root(state)` post-condition are both skipped
/// (per Q3 resolution); `verify_signatures` is also set to `false` so every
/// per-operation BLS check is skipped.
pub fn state_transition<E: EthSpec>(
    mut state: E::BeaconState,
    signed_block: &E::SignedBeaconBlock,
    validate_result: bool,
) -> Result<E::BeaconState, StateTransitionError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::BeaconBlock: BeaconBlockView<Body = E::BeaconBlockBody>,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
    E::BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
{
    let block = signed_block.message();

    // Process slots (including those with no blocks) since block.
    process_slots::<E>(&mut state, block.slot())?;

    // Verify block signature when validate_result is true.
    // Per `specs/phase0/beacon-chain.md:1387-1392`, the proposer pubkey is
    // looked up using the block's claimed `proposer_index`, not the slot-derived
    // proposer. `process_block_header` separately checks that the two agree.
    if validate_result {
        let proposer_index = block.proposer_index();
        let proposer_pubkey = state
            .validators()
            .get(proposer_index.0 as usize)
            .ok_or(StateTransitionError::InvalidBlockSignature)?
            .pubkey;

        let domain = get_domain::<E>(&state, DOMAIN_BEACON_PROPOSER, None);
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
    process_block::<E>(&mut state, block, validate_result)?;

    // Verify state root when validate_result is true.
    if validate_result {
        let actual = state.tree_hash_root();
        let expected = block.state_root();
        if actual != expected {
            return Err(StateTransitionError::StateRootMismatch { expected, actual });
        }
    }

    Ok(state)
}
