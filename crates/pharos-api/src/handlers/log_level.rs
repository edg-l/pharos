//! Vendor namespace — runtime log-level endpoint.
//!
//! `POST /pharos/v1/log-level` — change the active `EnvFilter` at runtime.
//!
//! This is a Pharos-specific (non-spec) endpoint. It is auth-gated via the
//! validator Bearer token so that operator credentials control access.
//! The body accepts any valid RUST_LOG directive string (e.g. `"debug"`,
//! `"info,pharos_network=trace"`).
//!
//! Returns 503 when the node was started without a reload handle
//! (`ApiState::new` / `ApiState::new_with_bus`), 400 on a bad directive,
//! 500 if the reload itself fails, 200 with the applied filter on success.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use pharos_types::BeaconSpec;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::error::ApiError;
use crate::state::ApiState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetLogLevelRequest {
    pub filter: String,
}

#[derive(Serialize)]
pub struct SetLogLevelResponse {
    pub filter: String,
}

// ── Handler ───────────────────────────────────────────────────────────────────

pub async fn post_log_level<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(req): Json<SetLogLevelRequest>,
) -> Result<Json<SetLogLevelResponse>, ApiError> {
    let handle = state
        .log_reload
        .as_ref()
        .ok_or_else(|| ApiError::NotSynced("log-level reload handle not configured".to_string()))?;
    let new_filter = EnvFilter::try_new(&req.filter)
        .map_err(|e| ApiError::BadRequest(format!("invalid log filter directive: {e}")))?;
    handle
        .reload(new_filter)
        .map_err(|e| ApiError::Internal(format!("failed to apply log filter: {e}")))?;
    Ok(Json(SetLogLevelResponse { filter: req.filter }))
}
