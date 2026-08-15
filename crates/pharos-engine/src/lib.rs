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

pub use client::{EngineClient, ForkchoiceUpdatedVersion, GetPayloadVersion, NewPayloadVersion};
pub use error::EngineError;
pub use handle::{EngineHandle, EngineRequest, run_engine_actor, spawn_engine_actor};
pub use jwt::{JwtSecret, load_jwt_secret};
pub use types::{
    BlockHeader, ExecutionPayloadV1, ForkchoiceStateV1, ForkchoiceUpdatedV1Response,
    PayloadAttributesV1, PayloadIdV1, PayloadStatusStatus, PayloadStatusV1, SyncingStatus,
    TransitionConfigurationV1,
};
