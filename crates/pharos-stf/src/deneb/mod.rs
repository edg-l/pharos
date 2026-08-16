//! Deneb state transition function.
//!
//! Per `specs/deneb/beacon-chain.md`, `specs/deneb/fork.md`,
//! and `specs/deneb/p2p-interface.md`.

pub mod blob;
pub mod block;
pub mod epoch;
pub mod helpers;
pub mod light_client;
pub mod operations;
pub mod state_transition;
pub mod upgrade;

pub use blob::{
    build_blob_sidecar_inclusion_proof, build_blob_sidecar_inclusion_proof_electra,
    verify_blob_sidecar_inclusion_proof,
};
pub use state_transition::{DenebDispatch, DenebJaFDispatch, DenebProcessSlotsDispatch};
pub use upgrade::upgrade_to_deneb;
