//! Fork-choice error type.
//!
//! `ForkChoiceError` is the single error type returned by all handlers in this
//! crate.  Sub-error types from `pharos-stf` convert in automatically via
//! `#[from]`.

use pharos_types::phase0::{Root, Slot};
use thiserror::Error;

/// Errors returned by fork-choice handlers.
///
/// Per `specs/phase0/fork-choice.md` — the spec uses Python `assert` to signal
/// all invalid conditions; each variant here corresponds to one such assertion.
#[derive(Error, Debug)]
pub enum ForkChoiceError {
    /// A block or attestation contained an invalid block structure.
    #[error("invalid block: {reason}")]
    InvalidBlock { reason: String },

    /// An attestation failed validation (see `validate_on_attestation`).
    #[error("invalid attestation: {reason}")]
    InvalidAttestation { reason: String },

    /// A lookup into `store.blocks` or `store.block_states` found no entry.
    ///
    /// Per `specs/phase0/fork-choice.md:849` (`assert block.parent_root in store.block_states`).
    #[error("missing block: root {root:?}")]
    MissingBlock { root: Root },

    /// `block.slot` is not strictly greater than the finalized slot.
    ///
    /// Per `specs/phase0/fork-choice.md:857-858`
    /// (`assert block.slot > finalized_slot`).
    #[error("block slot {slot} is not after finalized slot {finalized_slot}")]
    BeforeFinalized { slot: Slot, finalized_slot: Slot },

    /// The block's slot does not match the expected value.
    #[error("slot mismatch: expected {expected}, actual {actual}")]
    SlotMismatch { expected: Slot, actual: Slot },

    /// The block's slot is in the future relative to the store's current slot.
    ///
    /// Per `specs/phase0/fork-choice.md:853`
    /// (`assert get_current_slot(store) >= block.slot`).
    #[error("future block: current slot {current}, block slot {block_slot}")]
    FutureSlot { current: Slot, block_slot: Slot },

    /// Error returned by `pharos_stf::state_transition`.
    #[error("state transition failed: {0}")]
    StateTransition(#[from] pharos_stf::StateTransitionError),

    /// Error returned by epoch-processing sub-routines called from
    /// `compute_pulled_up_tip`.
    #[error("epoch processing failed: {0}")]
    EpochProcessing(#[from] pharos_stf::EpochProcessingError),
}
