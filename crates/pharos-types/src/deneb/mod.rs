//! Deneb beacon-chain type containers.
//!
//! Contains blob-related primitives introduced in the Deneb fork.
//! Full Deneb fork containers (BeaconBlock, BeaconState, ExecutionPayload
//! with `blob_gas_used`/`excess_blob_gas`) are added in Phase 2.

pub mod blob;
pub mod blob_sidecar;

pub use blob::{BYTES_PER_BLOB, Blob, BlobIndex, KZGCommitment, KZGProof};
pub use blob_sidecar::{BlobIdentifier, BlobSidecar, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH};
