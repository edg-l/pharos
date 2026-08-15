//! Beacon API HTTP server.
//!
//! Implements the OpenAPI surface defined in `beacon-APIs/`. Built on
//! `axum`. Endpoints under `/eth/v1`, `/eth/v2`, ... including SSE streams.

pub mod error;
pub mod handlers;
pub mod resolve;
pub mod respond;
pub mod router;
pub mod serde_helpers;
pub mod server;
pub mod state;

pub use error::ApiError;
pub use router::build_router;
pub use server::serve;
pub use state::{ApiState, ChainStateApi, NodeChainState, NodeIdentityCache};
