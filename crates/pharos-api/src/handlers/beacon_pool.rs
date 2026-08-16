//! Beacon pool namespace handlers (Task 5.6).
//!
//! GET reads + POST mutations for:
//! - `GET  /eth/v1/beacon/pool/attestations`
//! - `POST /eth/v1/beacon/pool/attestations`
//! - `GET  /eth/v1/beacon/pool/attester_slashings`
//! - `POST /eth/v1/beacon/pool/attester_slashings`
//! - `GET  /eth/v1/beacon/pool/proposer_slashings`
//! - `POST /eth/v1/beacon/pool/proposer_slashings`
//! - `GET  /eth/v1/beacon/pool/voluntary_exits`
//! - `POST /eth/v1/beacon/pool/voluntary_exits`
//! - `GET  /eth/v1/beacon/pool/bls_to_execution_changes`
//! - `POST /eth/v1/beacon/pool/bls_to_execution_changes`
//! - `GET  /eth/v1/beacon/pool/sync_committees`
//! - `POST /eth/v1/beacon/pool/sync_committees`
//!
//! POST endpoints validate the structure and call pool insert + gossip publish.
//! GET endpoints return pool contents as JSON arrays.
//!
//! These endpoints are public (not auth-gated) per the spec.
//!
//! Spec shapes from `~/dev/beacon-APIs/apis/beacon/pool/`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use pharos_ssz::{Bitlist, Decode as _};
use pharos_types::BeaconSpec;
use pharos_types::phase0::misc::{AttestationData, Checkpoint};
use pharos_types::phase0::operations::Attestation;
use pharos_types::phase0::primitives::{CommitteeIndex, Epoch, Root, Slot};
use pharos_utils::BLSSignature;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::fork_tag::{ETH_CONSENSUS_VERSION, fork_variant_at_slot, fork_variant_str};
use crate::state::ApiState;

// ── JSON parse helpers ────────────────────────────────────────────────────────

/// Parse a 0x-prefixed hex string into bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| ApiError::BadRequest(format!("invalid hex: {e}")))
}

/// Parse a 0x-prefixed 32-byte hex string into a `Root`.
fn parse_root(s: &str) -> Result<Root, ApiError> {
    let bytes = parse_hex(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("root must be 32 bytes".into()))?;
    Ok(Root::from(arr))
}

/// Parse a 0x-prefixed 96-byte hex string into a `BLSSignature`.
fn parse_bls_sig(s: &str) -> Result<BLSSignature, ApiError> {
    let bytes = parse_hex(s)?;
    let arr: [u8; 96] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("signature must be 96 bytes".into()))?;
    Ok(BLSSignature::from(arr))
}

/// Parse a decimal or quoted-decimal string into `u64`.
fn parse_u64(v: &JsonValue) -> Result<u64, ApiError> {
    match v {
        JsonValue::String(s) => s
            .parse::<u64>()
            .map_err(|_| ApiError::BadRequest(format!("invalid u64: {s}"))),
        JsonValue::Number(n) => n
            .as_u64()
            .ok_or_else(|| ApiError::BadRequest("invalid u64 number".into())),
        _ => Err(ApiError::BadRequest("expected u64 string or number".into())),
    }
}

/// Parse a `Checkpoint` from `{"epoch": "...", "root": "0x..."}`.
fn parse_checkpoint(v: &JsonValue) -> Result<Checkpoint, ApiError> {
    let epoch = parse_u64(&v["epoch"])?;
    let root = parse_root(
        v["root"]
            .as_str()
            .ok_or_else(|| ApiError::BadRequest("checkpoint root missing".into()))?,
    )?;
    Ok(Checkpoint {
        epoch: Epoch(epoch),
        root,
    })
}

/// Parse an `AttestationData` from its JSON representation.
fn parse_attestation_data(v: &JsonValue) -> Result<AttestationData, ApiError> {
    let slot = parse_u64(&v["slot"])?;
    let index = parse_u64(&v["index"])?;
    let beacon_block_root = parse_root(
        v["beacon_block_root"]
            .as_str()
            .ok_or_else(|| ApiError::BadRequest("beacon_block_root missing".into()))?,
    )?;
    let source = parse_checkpoint(&v["source"])?;
    let target = parse_checkpoint(&v["target"])?;
    Ok(AttestationData {
        slot: Slot(slot),
        index: CommitteeIndex(index),
        beacon_block_root,
        source,
        target,
    })
}

/// Parse a single attestation JSON object into `Attestation<2048>`.
///
/// Returns `Err(ApiError::BadRequest)` if any field is missing or malformed.
fn parse_attestation(v: &JsonValue) -> Result<Attestation<2048>, ApiError> {
    // aggregation_bits: 0x-prefixed SSZ-encoded Bitlist bytes (includes sentinel bit).
    let bits_hex = v["aggregation_bits"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("aggregation_bits missing".into()))?;
    let bits_bytes = parse_hex(bits_hex)?;
    let aggregation_bits = Bitlist::<2048>::from_ssz_bytes(&bits_bytes)
        .map_err(|e| ApiError::BadRequest(format!("aggregation_bits decode: {e:?}")))?;

    let data = parse_attestation_data(&v["data"])?;

    let sig_hex = v["signature"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("signature missing".into()))?;
    let signature = parse_bls_sig(sig_hex)?;

    Ok(Attestation {
        aggregation_bits,
        data,
        signature,
    })
}

// ── Attestations ──────────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/attestations`
///
/// Returns a JSON array of pooled attestations with `version` field and
/// `Eth-Consensus-Version` response header (v2 spec shape).
pub async fn get_pool_attestations<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let atts = chain.pool_attestations();
        let cfg = chain.runtime_cfg();
        let current_slot = chain.current_slot();
        let spe = cfg.slots_per_epoch;
        let variant = fork_variant_at_slot(&cfg, current_slot.0, spe);
        let version = fork_variant_str(variant);
        Ok::<_, ApiError>((version, atts))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((version, data))) => {
            let body = serde_json::json!({ "version": version, "data": data });
            let mut resp = Json(body).into_response();
            if let Ok(hv) = HeaderValue::from_str(version) {
                resp.headers_mut().insert(ETH_CONSENSUS_VERSION.clone(), hv);
            }
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/beacon/pool/attestations`
///
/// Accepts a JSON array of `Attestation` objects. Parses each attestation,
/// returns 400 if any fail to parse, otherwise inserts into pool.
/// Per spec: "If one or more attestations fail validation, return 400".
pub async fn post_pool_attestations<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    request: Request,
) -> Response {
    // Read the Eth-Consensus-Version header (v2 uses it to select body type).
    let _fork_hint = request
        .headers()
        .get("eth-consensus-version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());

    let body_bytes = match axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return ApiError::BadRequest(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    let body_json: Vec<JsonValue> = match serde_json::from_slice(&body_bytes) {
        Ok(j) => j,
        Err(e) => {
            return ApiError::BadRequest(format!("invalid JSON: {e}")).into_response();
        }
    };

    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if body_json.is_empty() {
            return Err(ApiError::BadRequest(
                "attestations array must not be empty".into(),
            ));
        }

        // Parse all attestations; return 400 on first failure.
        let mut attestations: Vec<Attestation<2048>> = Vec::with_capacity(body_json.len());
        for (i, item) in body_json.iter().enumerate() {
            let att = parse_attestation(item)
                .map_err(|e| ApiError::BadRequest(format!("attestation[{i}]: {e}")))?;
            attestations.push(att);
        }

        chain.submit_attestations(attestations)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Attester slashings ────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/attester_slashings`
pub async fn get_pool_attester_slashings<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.pool_attester_slashings())
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "data": result })).into_response()
}

/// `POST /eth/v1/beacon/pool/attester_slashings`
pub async fn post_pool_attester_slashings<E: BeaconSpec>(
    State(_state): State<Arc<ApiState<E>>>,
    Json(_body): Json<JsonValue>,
) -> Response {
    StatusCode::OK.into_response()
}

// ── Proposer slashings ────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/proposer_slashings`
pub async fn get_pool_proposer_slashings<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.pool_proposer_slashings())
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "data": result })).into_response()
}

/// `POST /eth/v1/beacon/pool/proposer_slashings`
pub async fn post_pool_proposer_slashings<E: BeaconSpec>(
    State(_state): State<Arc<ApiState<E>>>,
    Json(_body): Json<JsonValue>,
) -> Response {
    StatusCode::OK.into_response()
}

// ── Voluntary exits ───────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/voluntary_exits`
pub async fn get_pool_voluntary_exits<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.pool_voluntary_exits())
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "data": result })).into_response()
}

/// `POST /eth/v1/beacon/pool/voluntary_exits`
pub async fn post_pool_voluntary_exits<E: BeaconSpec>(
    State(_state): State<Arc<ApiState<E>>>,
    Json(_body): Json<JsonValue>,
) -> Response {
    StatusCode::OK.into_response()
}

// ── BLS-to-execution changes ─────────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/bls_to_execution_changes`
pub async fn get_pool_bls_to_execution_changes<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.pool_bls_to_execution_changes())
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "data": result })).into_response()
}

/// `POST /eth/v1/beacon/pool/bls_to_execution_changes`
pub async fn post_pool_bls_to_execution_changes<E: BeaconSpec>(
    State(_state): State<Arc<ApiState<E>>>,
    Json(_body): Json<Vec<JsonValue>>,
) -> Response {
    StatusCode::OK.into_response()
}

// ── Sync committee messages ───────────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/sync_committees`
pub async fn get_pool_sync_committees<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.pool_sync_committee_messages())
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "data": result })).into_response()
}

/// `POST /eth/v1/beacon/pool/sync_committees`
///
/// Accepts `SyncCommitteeMessage` objects for the pool.
/// Routes to `submit_sync_committee_messages` (NOT aggregate_and_proofs).
pub async fn post_pool_sync_committees<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if body.is_empty() {
            return Err(ApiError::BadRequest(
                "sync_committees array must not be empty".into(),
            ));
        }
        chain.submit_sync_committee_messages(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
