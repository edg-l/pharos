//! Basic beacon namespace handlers (Phase 1 Tier-1 subset).
//!
//! - `GET /eth/v1/beacon/genesis`
//!
//! (`/eth/v1/beacon/headers/head` is served by the Phase-3
//! `/eth/v1/beacon/headers/{block_id}` handler in `blocks.rs` — block_id "head"
//! — which returns a single header object per the spec.)
//!
//! Spec shapes from `~/dev/beacon-APIs/apis/beacon/genesis.yaml`.
//!
//! `genesis` is JSON-only in the spec (no SSZ form). Since Phase 2 it routes
//! through `ApiResponse` so the `Accept` header is validated uniformly: a
//! missing / `*/*` / `application/json` Accept yields JSON, any other explicit
//! Accept (including `application/octet-stream`, which the endpoint cannot
//! satisfy) yields 406.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_types::BeaconSpec;
use serde::Serialize;

use crate::error::ApiError;
use crate::respond::{ApiResponse, parse_accept};
use crate::serde_helpers::{quoted_u64, serialize_hex4, serialize_hex32};
use crate::state::ApiState;

// ── genesis DTOs ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct GenesisData {
    #[serde(with = "quoted_u64")]
    genesis_time: u64,
    #[serde(serialize_with = "serialize_hex32")]
    genesis_validators_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex4")]
    genesis_fork_version: [u8; 4],
}

#[derive(Serialize)]
pub struct GenesisResponse {
    data: GenesisData,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/genesis`
pub async fn get_genesis<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let (genesis_time, genesis_validators_root, genesis_fork_version) = chain.genesis();
        GenesisResponse {
            data: GenesisData {
                genesis_time,
                genesis_validators_root: genesis_validators_root.into(),
                genesis_fork_version,
            },
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(dto) => ApiResponse::json(dto).render(format),
        Err(e) => e.into_response(),
    }
}
