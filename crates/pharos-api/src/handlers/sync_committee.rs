//! Sync-committee validator namespace handlers (Task 5.3).
//!
//! Routes implemented:
//! - `GET  /eth/v1/validator/sync_committee_contribution`
//! - `POST /eth/v1/validator/contribution_and_proofs`
//! - `POST /eth/v1/validator/beacon_committee_selections`
//! - `POST /eth/v1/validator/sync_committee_selections`
//!
//! All endpoints return HTTP 503 when the node is syncing or optimistic
//! (`D-503-on-optimistic-or-syncing`).
//!
//! `beacon_committee_selections` and `sync_committee_selections` are non-DVT
//! identity pass-through endpoints (OQ2 resolved). They echo the input
//! unchanged with a 200, as no selection aggregation is needed for a
//! single-instance (non-DVT) setup.
//!
//! Spec shapes from `~/dev/beacon-APIs/`:
//! - `apis/validator/sync_committee_contribution.yaml`
//! - `apis/validator/contribution_and_proofs.yaml`
//! - `apis/validator/beacon_committee_selections.yaml`
//! - `apis/validator/sync_committee_selections.yaml`

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use pharos_types::EthSpec;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::serde_helpers::quoted_u64;
use crate::state::ApiState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Query parameters for `GET /eth/v1/validator/sync_committee_contribution`.
#[derive(Deserialize)]
pub struct SyncContributionQuery {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    pub beacon_block_root: String,
    #[serde(with = "quoted_u64")]
    pub subcommittee_index: u64,
}

// ── Helpers ─────────────────────────────────────────────────────────────────--

/// Parse a 0x-prefixed 32-byte root from a hex string.
fn parse_root32(s: &str) -> Result<pharos_types::phase0::primitives::Root, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(s).map_err(|_| ApiError::BadRequest("invalid beacon_block_root hex".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("beacon_block_root must be 32 bytes".into()))?;
    Ok(pharos_types::phase0::primitives::Root::from(arr))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/validator/sync_committee_contribution`
///
/// Returns the best `SyncCommitteeContribution` from the pool matching the
/// given `(slot, beacon_block_root, subcommittee_index)`. Returns 404 when
/// no matching contribution is available.
pub async fn get_sync_committee_contribution<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Query(params): Query<SyncContributionQuery>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced(
                "node is syncing or optimistic; sync contribution unavailable".into(),
            ));
        }
        let block_root = parse_root32(&params.beacon_block_root)?;
        chain
            .sync_committee_contribution(params.slot, block_root, params.subcommittee_index)
            .ok_or_else(|| {
                ApiError::NotFound("no matching sync committee contribution in pool".into())
            })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(json)) => Json(serde_json::json!({ "data": json })).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/contribution_and_proofs`
///
/// Accepts signed `ContributionAndProof` objects and routes them to the pool
/// and gossip. Always 200.
pub async fn post_contribution_and_proofs<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        // Routes to submit_contribution_and_proofs (not submit_aggregate_and_proofs).
        chain.submit_contribution_and_proofs(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/beacon_committee_selections`
///
/// Non-DVT identity pass-through (OQ2 resolved).
/// Echoes the input array unchanged with a 200.
pub async fn post_beacon_committee_selections<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        Ok::<_, ApiError>(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(data)) => Json(serde_json::json!({ "data": data })).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/sync_committee_selections`
///
/// Non-DVT identity pass-through (OQ2 resolved).
/// Echoes the input array unchanged with a 200.
pub async fn post_sync_committee_selections<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        Ok::<_, ApiError>(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(data)) => Json(serde_json::json!({ "data": data })).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
