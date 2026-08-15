//! Beacon API HTTP server.
//!
//! Implements the OpenAPI surface defined in `beacon-APIs/`. Built on
//! `axum`. Endpoints under `/eth/v1`, `/eth/v2`, ... including SSE streams.

pub mod auth;
pub mod dto;
pub mod error;
pub mod events;
pub mod fork_tag;
pub mod handlers;
pub mod resolve;
pub mod respond;
pub mod router;
pub mod serde_helpers;
pub mod server;
pub mod state;

pub use error::ApiError;
pub use events::{ApiEvent, EventBus, KnownTopic};
pub use router::{build_router, build_router_with_auth};
pub use server::{serve, serve_with_auth};
pub use state::{
    ApiState, ChainStateApi, NodeChainState, NodeIdentityCache, PeersFn, ProduceAttDataFn,
    ProduceFn, PublishFn, RegenFn, RegenTarget, beacon_state_to_json_full,
};
