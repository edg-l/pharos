//! Beacon block publish handlers.
//!
//! - `POST /eth/v1/beacon/blocks`
//! - `POST /eth/v2/beacon/blocks`
//!
//! Both routes accept a `SignedBeaconBlock` (JSON or SSZ) and:
//!   - Import the block locally via `chain.publish_block` (which calls `import_block`).
//!   - Gossip-broadcast it to the network.
//!
//! Response codes per spec:
//! - `200` — block imported AND broadcast.
//! - `202` — block broadcast-only (could not import locally, e.g. it is
//!   ahead of the current head by >1 slot).
//! - `400` — block could not be decoded or is obviously invalid.
//! - `503` — node is syncing or optimistic (`D-503-on-optimistic-or-syncing`).
//!
//! The `Eth-Consensus-Version` request header is used by v2 to choose the
//! fork for SSZ decode; for JSON both v1 and v2 rely on the `version`
//! field in the envelope.
//!
//! Spec shapes from `~/dev/beacon-APIs/apis/beacon/blocks/publishBlock.yaml`
//! and `publishBlockV2.yaml`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use pharos_types::BeaconSpec;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::state::ApiState;

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /eth/v1/beacon/blocks`
///
/// Accepts a `SignedBeaconBlock` JSON object. Imports and broadcasts.
pub async fn post_beacon_block_v1<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<JsonValue>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced(
                "node is syncing or optimistic; block publish unavailable".into(),
            ));
        }
        chain.publish_block(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(true)) => StatusCode::OK.into_response(),
        Ok(Ok(false)) => StatusCode::ACCEPTED.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v2/beacon/blocks`
///
/// Accepts a fork-tagged `SignedBeaconBlock`. The `Eth-Consensus-Version`
/// header indicates the fork; `Content-Type: application/octet-stream`
/// triggers SSZ decode; JSON envelopes carry `version` in the body.
pub async fn post_beacon_block_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    request: Request,
) -> Response {
    // Extract relevant headers before consuming the body.
    let fork_hint = request
        .headers()
        .get("eth-consensus-version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());

    let is_ssz = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/octet-stream"))
        .unwrap_or(false);

    let body_bytes = match axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return ApiError::BadRequest(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    // SSZ path: decode bytes by fork hint, publish.
    if is_ssz {
        let fork = match fork_hint {
            Some(f) => f,
            None => {
                return ApiError::BadRequest(
                    "Eth-Consensus-Version header required for SSZ block".into(),
                )
                .into_response();
            }
        };
        let chain = Arc::clone(&state.chain);
        let bytes = body_bytes.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            if chain.is_syncing() || chain.is_optimistic_node() {
                return Err(ApiError::NotSynced(
                    "node is syncing or optimistic; block publish unavailable".into(),
                ));
            }
            chain.publish_block_ssz(bytes, &fork)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

        return match result {
            Ok(Ok(true)) => StatusCode::OK.into_response(),
            Ok(Ok(false)) => StatusCode::ACCEPTED.into_response(),
            Ok(Err(e)) => e.into_response(),
            Err(e) => e.into_response(),
        };
    }

    // JSON path.
    let body_json: JsonValue = match serde_json::from_slice(&body_bytes) {
        Ok(j) => j,
        Err(e) => {
            return ApiError::BadRequest(format!("invalid JSON: {e}")).into_response();
        }
    };

    // If fork hint provided, annotate the JSON with the version.
    let annotated = if let Some(fork) = fork_hint {
        if body_json.get("version").is_none() {
            let mut map = body_json.as_object().cloned().unwrap_or_default();
            map.insert("version".into(), JsonValue::String(fork));
            JsonValue::Object(map)
        } else {
            body_json
        }
    } else {
        body_json
    };

    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced(
                "node is syncing or optimistic; block publish unavailable".into(),
            ));
        }
        chain.publish_block(annotated)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(true)) => StatusCode::OK.into_response(),
        Ok(Ok(false)) => StatusCode::ACCEPTED.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
