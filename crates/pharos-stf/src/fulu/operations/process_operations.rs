//! `process_operations` for Fulu.
//!
//! Verified against `specs/fulu/beacon-chain.md` (consensus-specs
//! v1.7.0-alpha.8): fulu does NOT override `process_operations`. The electra
//! `process_operations` (`specs/electra/beacon-chain.md:1472-1503`) is the fulu
//! `process_operations`: it retains the EIP-6110 modified deposit-count assert
//! (`for_ops(body.deposits, process_deposit)` over the eth1-bridge limit) plus
//! the proposer/attester slashings, attestations, deposits, voluntary exits,
//! BLS-to-execution changes, and the EIP-6110/7002/7251 execution-request
//! routing (`process_deposit_request` / `process_withdrawal_request` /
//! `process_consolidation_request`).
//!
//! There is NO fulu-specific `assert len(body.deposits) == 0` and NO removal of
//! the legacy `process_deposit` call at this spec version; the deposit mechanism
//! is unchanged from electra. The fulu body is the electra `BeaconBlockBody`
//! type, so the electra impl accepts fulu blocks directly — the fulu
//! `process_operations` IS the electra impl, re-exported (no fabricated delta).

pub use crate::electra::operations::process_operations_electra as process_operations_fulu;
