//! Deneb state transition function utilities.
//!
//! Per `specs/deneb/beacon-chain.md` and `specs/deneb/p2p-interface.md`.

pub mod blob;

pub use blob::verify_blob_sidecar_inclusion_proof;
