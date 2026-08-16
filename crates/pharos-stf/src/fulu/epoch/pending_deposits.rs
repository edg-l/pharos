//! `process_pending_deposits` for Fulu.
//!
//! Verified against `specs/fulu/beacon-chain.md` (consensus-specs
//! v1.7.0-alpha.8): fulu does NOT override `process_pending_deposits`. The
//! modified `process_epoch` (`:300-318`) still calls the electra
//! `process_pending_deposits` unchanged; the only fulu addition to the epoch
//! schedule is `process_proposer_lookahead` at the very end.
//!
//! The electra `process_pending_deposits` (`specs/electra/beacon-chain.md:990-1055`)
//! already implements the EIP-7251/6110 queue drain (eth1-bridge ordering,
//! finalization gate, `MAX_PENDING_DEPOSITS_PER_EPOCH` cap, activation-exit
//! churn, exiting-validator postponement, withdrawn-credit fast path); there is
//! no fulu-specific legacy-branch removal at this spec version. The fulu
//! `process_pending_deposits` IS the electra impl, re-exported (no fabricated
//! delta).

pub use crate::electra::epoch::pending_deposits::{
    apply_pending_deposit, process_pending_deposits,
};
