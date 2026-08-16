//! Engine API client.
//!
//! Talks to an execution-layer node (ethrex, reth, geth, ...) over JSON-RPC.
//! In-house implementation: `reqwest` + `serde_json` + JWT auth, our own
//! request/response types. HTTP first; IPC later.
//!
//! Spec: `execution-apis/src/engine/`.

pub mod client;
pub mod error;
pub mod handle;
pub mod jwt;
pub mod types;

pub use client::{
    DEFAULT_ENGINE_CAPABILITIES, EngineClient, ForkchoiceUpdatedVersion, GetPayloadVersion,
    NewPayloadVersion, NewPayloadWire,
};
pub use error::EngineError;
pub use handle::{EngineHandle, EngineRequest, run_engine_actor, spawn_engine_actor};
pub use jwt::{JwtSecret, load_jwt_secret};
pub use types::{
    BlobAndProofV1, BlobsBundleV1, BlobsBundleV2, BlockHeader, ExecutionPayloadV1,
    ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceStateV1, ForkchoiceUpdatedV1Response,
    GetPayloadV2Response, GetPayloadV3Response, GetPayloadV4Response, GetPayloadV5Response,
    PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, PayloadIdV1,
    PayloadStatusStatus, PayloadStatusV1, SyncingStatus, TransitionConfigurationV1, WithdrawalV1,
};
