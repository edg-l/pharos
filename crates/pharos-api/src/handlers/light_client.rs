//! Light-client REST endpoint handlers.
//!
//! Endpoints per `beacon-APIs/apis/beacon/light_client/`:
//! - `GET /eth/v1/beacon/light_client/bootstrap/{block_root}`
//! - `GET /eth/v1/beacon/light_client/updates`
//! - `GET /eth/v1/beacon/light_client/finality_update`
//! - `GET /eth/v1/beacon/light_client/optimistic_update`
//!
//! Response shape (per beacon-APIs spec):
//! - JSON: `{"version":"<fork>","data":{...}}` — NO `execution_optimistic` or `finalized`.
//! - SSZ single: raw (unframed) inner bytes + `Eth-Consensus-Version` header.
//! - SSZ updates: each item length-framed as `u64_le(4 + ssz_len) || fork_digest[..4] || ssz_bytes`.
//!
//! Per `D-api-lc-gvr-from-head-state`: the genesis validators root (gvr) used for
//! `compute_fork_digest` in SSZ updates framing is sourced from `chain.genesis()`,
//! not from `runtime_cfg` (which may be zeroed on checkpoint-sync nodes).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use pharos_types::{
    BeaconSpec,
    fork::compute_fork_digest,
    phase0::primitives::{Root, Version},
};
use serde::Deserialize;

use crate::dto::light_client::MAX_REQUEST_LC_UPDATES;
use crate::error::ApiError;
use crate::fork_tag::{fork_variant_str, render_lc_envelope};
use crate::respond::parse_accept;
use crate::state::ApiState;

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdatesQuery {
    pub start_period: u64,
    pub count: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a hex block-root string (with or without `0x` prefix) into a `Root`.
fn parse_block_root(s: &str) -> Result<Root, ApiError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped)
        .map_err(|_| ApiError::BadRequest(format!("invalid hex block_root: {s}")))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(format!(
            "block_root must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Root::from(arr))
}

/// Return the fork version bytes for a `ForkVariant` given the `RuntimeConfig`.
fn fork_version_for_variant(
    variant: pharos_types::views::ForkVariant,
    cfg: &pharos_types::config::RuntimeConfig,
) -> [u8; 4] {
    use pharos_types::views::ForkVariant;
    match variant {
        ForkVariant::Phase0 => cfg.genesis_fork_version,
        ForkVariant::Altair => cfg.altair_fork_version,
        ForkVariant::Bellatrix => cfg.bellatrix_fork_version,
        ForkVariant::Capella => cfg.capella_fork_version,
        ForkVariant::Deneb => cfg.deneb_fork_version,
        ForkVariant::Electra => cfg.electra_fork_version,
        ForkVariant::Fulu => cfg.fulu_fork_version,
    }
}

// ── GET /eth/v1/beacon/light_client/bootstrap/{block_root} ───────────────────

/// `GET /eth/v1/beacon/light_client/bootstrap/{block_root}`
///
/// Per `beacon-APIs/apis/beacon/light_client/bootstrap.yaml`.
pub async fn get_bootstrap<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_root_str): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let root = parse_block_root(&block_root_str)?;
        chain.light_client_bootstrap(root)
    })
    .await;

    match result {
        Ok(Ok(Some(env))) => render_lc_envelope(env, format),
        Ok(Ok(None)) => ApiError::NotFound("bootstrap not found".into()).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => ApiError::Internal("spawn_blocking panicked".into()).into_response(),
    }
}

// ── GET /eth/v1/beacon/light_client/updates ───────────────────────────────────

/// `GET /eth/v1/beacon/light_client/updates?start_period=N&count=K`
///
/// Per `beacon-APIs/apis/beacon/light_client/updates.yaml`.
///
/// SSZ format for each item: `u64_le(4 + ssz_len) || fork_digest[..4] || ssz_bytes`.
/// Empty range returns 200 with an empty body.
///
/// Per `beacon-APIs/apis/beacon/light_client/updates.yaml` and
/// `specs/altair/light-client/p2p-interface.md:29-35`.
pub async fn get_updates<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Query(params): Query<UpdatesQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    // Clamp count per spec.
    let count = params.count.min(MAX_REQUEST_LC_UPDATES);
    let start_period = params.start_period;

    let chain = Arc::clone(&state.chain);
    let result =
        tokio::task::spawn_blocking(move || chain.light_client_updates(start_period, count)).await;

    match result {
        Ok(Ok(envelopes)) => {
            use crate::respond::AcceptFormat;
            match format {
                AcceptFormat::Json => {
                    if envelopes.is_empty() {
                        return (
                            StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            b"[]".to_vec(),
                        )
                            .into_response();
                    }
                    let arr: Vec<serde_json::Value> = envelopes
                        .into_iter()
                        .map(|env| {
                            serde_json::json!({
                                "version": fork_variant_str(env.variant),
                                "data": env.json,
                            })
                        })
                        .collect();
                    let body = match serde_json::to_vec(&arr) {
                        Ok(b) => b,
                        Err(e) => {
                            return ApiError::Internal(format!("JSON serialization error: {e}"))
                                .into_response();
                        }
                    };
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response()
                }
                AcceptFormat::Ssz => {
                    let cfg = state.chain.runtime_cfg();
                    let (_, gvr, _) = state.chain.genesis();
                    // SSZ encoding: concatenation of length-framed items.
                    // Per `beacon-APIs`: each item = u64_le(4 + ssz_len) || fork_digest[4] || ssz_bytes.
                    let mut out: Vec<u8> = Vec::new();
                    for env in envelopes {
                        let fork_version = fork_version_for_variant(env.variant, &cfg);
                        let digest = compute_fork_digest(Version::from_array(fork_version), &gvr);
                        let ssz_len = env.ssz_bytes.len() as u64;
                        let frame_len = 4u64 + ssz_len;
                        out.extend_from_slice(&frame_len.to_le_bytes());
                        out.extend_from_slice(&digest.as_slice()[..4]);
                        out.extend_from_slice(&env.ssz_bytes);
                    }
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        out,
                    )
                        .into_response()
                }
            }
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => ApiError::Internal("spawn_blocking panicked".into()).into_response(),
    }
}

// ── GET /eth/v1/beacon/light_client/finality_update ──────────────────────────

/// `GET /eth/v1/beacon/light_client/finality_update`
///
/// Per `beacon-APIs/apis/beacon/light_client/finality_update.yaml`.
pub async fn get_finality_update<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.light_client_finality_update()).await;

    match result {
        Ok(Ok(Some(env))) => render_lc_envelope(env, format),
        Ok(Ok(None)) => ApiError::NotFound("finality update not available".into()).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => ApiError::Internal("spawn_blocking panicked".into()).into_response(),
    }
}

// ── GET /eth/v1/beacon/light_client/optimistic_update ────────────────────────

/// `GET /eth/v1/beacon/light_client/optimistic_update`
///
/// Per `beacon-APIs/apis/beacon/light_client/optimistic_update.yaml`.
pub async fn get_optimistic_update<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.light_client_optimistic_update()).await;

    match result {
        Ok(Ok(Some(env))) => render_lc_envelope(env, format),
        Ok(Ok(None)) => {
            ApiError::NotFound("optimistic update not available".into()).into_response()
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => ApiError::Internal("spawn_blocking panicked".into()).into_response(),
    }
}
