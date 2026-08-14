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

pub use error::{
    AttestationInvalidReason, AttesterSlashingInvalidReason, BlockHeaderInvalidReason,
    DepositInvalidReason, EpochProcessingError, ProposerSlashingInvalidReason,
    StateTransitionError, VoluntaryExitInvalidReason,
};
