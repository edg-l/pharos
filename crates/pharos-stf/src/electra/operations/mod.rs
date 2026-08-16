//! Electra block-processing operations.
//!
//! Per `specs/electra/beacon-chain.md` Block processing.

pub mod attestation;

pub use attestation::{process_attestation_electra, process_attester_slashing_electra};
