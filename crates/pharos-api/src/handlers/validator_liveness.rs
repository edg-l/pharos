//! Validator liveness endpoint (Task 5.4).
//!
//! `POST /eth/v1/validator/liveness/{epoch}`
//!
//! Resolves OQ4 via `D-doppelganger-bn-liveness-endpoint`. The pharos-vc
//! doppelganger path calls this endpoint to check whether any of its
//! managed validators appear to be live on the network (i.e. had an
//! attestation in a recently imported block or the attestation pool).
//!
//! Request body: JSON array of validator index strings.
//! Response: `{ "data": [{ "index": "N", "epoch": "E", "is_live": bool }] }`
//!
//! Spec shape from `~/dev/beacon-APIs/apis/validator/liveness.yaml`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use pharos_types::BeaconSpec;
use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::state::ApiState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// One liveness record for a validator in the requested epoch.
///
/// Spec `liveness.yaml` requires only `index` and `is_live` (no `epoch`).
#[derive(Serialize)]
pub struct LivenessEntry {
    pub index: String,
    pub is_live: bool,
}

/// Response envelope for the liveness endpoint.
#[derive(Serialize)]
pub struct LivenessResponse {
    pub data: Vec<LivenessEntry>,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// `POST /eth/v1/validator/liveness/{epoch}`
///
/// Body: JSON array of validator index strings, e.g. `["0","1","42"]`.
///
/// Per `D-doppelganger-bn-liveness-endpoint` (M9 Phase 5.4).
pub async fn post_validator_liveness<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(epoch): Path<u64>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        // Parse validator indices from the body array.
        let indices: Vec<ValidatorIndex> = body
            .iter()
            .filter_map(|v| {
                let idx: u64 = match v {
                    JsonValue::String(s) => s.parse().ok()?,
                    JsonValue::Number(n) => n.as_u64()?,
                    _ => return None,
                };
                Some(ValidatorIndex(idx))
            })
            .collect();

        if indices.is_empty() {
            return Err(ApiError::BadRequest(
                "validator indices array must not be empty".into(),
            ));
        }

        let results = chain.validator_liveness(Epoch(epoch), indices)?;

        let data: Vec<LivenessEntry> = results
            .into_iter()
            .map(|(idx, is_live)| LivenessEntry {
                index: idx.0.to_string(),
                is_live,
            })
            .collect();

        Ok::<_, ApiError>(LivenessResponse { data })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(resp)) => Json(resp).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
