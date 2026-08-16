//! Deneb beacon-chain type containers.
//!
//! Contains blob-related primitives and full Deneb fork containers.

pub mod blob;
pub mod blob_sidecar;
pub mod block;
pub mod body;
pub mod execution_payload;
pub mod state;

pub use blob::{BYTES_PER_BLOB, Blob, BlobIndex, KZGCommitment, KZGProof};
pub use blob_sidecar::{BlobIdentifier, BlobSidecar, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH};
pub use block::{
    BeaconBlock, MainnetBeaconBlock, MainnetSignedBeaconBlock, MinimalBeaconBlock,
    MinimalSignedBeaconBlock, SignedBeaconBlock,
};
pub use body::{BeaconBlockBody, MainnetBeaconBlockBody, MinimalBeaconBlockBody};
pub use execution_payload::{
    ExecutionPayload, ExecutionPayloadHeader, MainnetExecutionPayload,
    MainnetExecutionPayloadHeader, MinimalExecutionPayload, MinimalExecutionPayloadHeader,
};
pub use state::{BeaconState, MainnetBeaconState, MinimalBeaconState};
