//! Engine API client error types.

use thiserror::Error;

/// Errors produced by the Engine API client.
#[derive(Debug, Error)]
pub enum EngineError {
    /// HTTP transport failure (connect, send, receive, TLS, etc.).
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON (de)serialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// JWT issuance or verification failure.
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// EL returned a JSON-RPC `error` envelope.
    #[error("json-rpc error {code}: {message}")]
    JsonRpc { code: i64, message: String },

    /// The response envelope was structurally unexpected (e.g. missing
    /// both `result` and `error`, or a wire-shape mismatch on a typed field).
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),

    /// Request exceeded the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// EL rejected the bearer token (HTTP 401).
    #[error("unauthenticated: EL rejected JWT")]
    Unauthenticated,
}
