//! `ApiError` — Beacon API error envelope.
//!
//! All error responses use the shape `{ "code": <int>, "message": <string> }`
//! with a matching HTTP status code, per the OpenAPI spec.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// Top-level Beacon API errors.
#[derive(Debug, Error)]
pub enum ApiError {
    /// 400 — malformed block/state id or query parameter.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// 404 — block/state/validator not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// 406 — client sent an `Accept` header we cannot satisfy.
    #[error("Not acceptable: {0}")]
    NotAcceptable(String),

    /// 500 — unexpected internal error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// 503 — node not yet initialized or not synced.
    #[error("Service unavailable: {0}")]
    NotSynced(String),
}

/// Wire JSON shape: `{ "code": <int>, "message": <string> }`.
#[derive(Serialize)]
struct ErrorBody<'a> {
    code: u16,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.as_str()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.as_str()),
            ApiError::NotAcceptable(m) => (StatusCode::NOT_ACCEPTABLE, m.as_str()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.as_str()),
            ApiError::NotSynced(m) => (StatusCode::SERVICE_UNAVAILABLE, m.as_str()),
        };
        let body = serde_json::to_vec(&ErrorBody {
            code: status.as_u16(),
            message: msg,
        })
        .unwrap_or_else(|_| br#"{"code":500,"message":"serialization error"}"#.to_vec());
        (status, [("content-type", "application/json")], body).into_response()
    }
}
