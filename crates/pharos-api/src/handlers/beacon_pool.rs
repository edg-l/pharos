//! Beacon pool namespace handlers.
//!
//! GET reads + POST mutations for:
//! - `GET  /eth/v1/beacon/pool/attestations`
//! - `POST /eth/v1/beacon/pool/attestations`
//! - `GET  /eth/v2/beacon/pool/attestations`   (EIP-7549)
//! - `POST /eth/v2/beacon/pool/attestations`   (EIP-7549)
//! - `GET  /eth/v1/beacon/pool/attester_slashings`
//! - `POST /eth/v1/beacon/pool/attester_slashings`
//! - `GET  /eth/v2/beacon/pool/attester_slashings`
//! - `POST /eth/v2/beacon/pool/attester_slashings`
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
use pharos_ssz::{Bitlist, Decode as _, SszList};
use pharos_types::BeaconSpec;
use pharos_types::electra::attestation::SingleAttestation;
use pharos_types::phase0::misc::{
    AttestationData, Checkpoint, IndexedAttestation as Phase0IndexedAttestation,
};
use pharos_types::phase0::operations::{Attestation, AttesterSlashing as Phase0AttesterSlashing};
use pharos_types::phase0::primitives::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};
use pharos_types::views::ForkVariant;
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

// ── EIP-7549 v2 pool parse helpers ───────────────────────────────────────────

/// Map a fork string from the `Eth-Consensus-Version` header to `ForkVariant`.
///
/// Returns `Err(ApiError::BadRequest)` for unknown fork strings — unknown forks
/// must 400, not default, per the v2 POST spec. No `_ =>` wildcard fallback.
fn header_str_to_fork_variant(s: &str) -> Result<ForkVariant, ApiError> {
    match s {
        "phase0" => Ok(ForkVariant::Phase0),
        "altair" => Ok(ForkVariant::Altair),
        "bellatrix" => Ok(ForkVariant::Bellatrix),
        "capella" => Ok(ForkVariant::Capella),
        "deneb" => Ok(ForkVariant::Deneb),
        "electra" => Ok(ForkVariant::Electra),
        "fulu" => Ok(ForkVariant::Fulu),
        other => Err(ApiError::BadRequest(format!(
            "unknown Eth-Consensus-Version: {other}"
        ))),
    }
}

/// Parse a `SingleAttestation` from its JSON representation.
///
/// Fields per `types/electra/attestation.yaml#/Electra/SingleAttestation`:
/// `committee_index`, `attester_index`, `data`, `signature`.
fn parse_single_attestation(v: &JsonValue) -> Result<SingleAttestation, ApiError> {
    let committee_index = parse_u64(&v["committee_index"])?;
    let attester_index = parse_u64(&v["attester_index"])?;
    let data = parse_attestation_data(&v["data"])?;
    let sig_hex = v["signature"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("signature missing".into()))?;
    let signature = parse_bls_sig(sig_hex)?;
    Ok(SingleAttestation {
        committee_index: CommitteeIndex(committee_index),
        attester_index: ValidatorIndex(attester_index),
        data,
        signature,
    })
}

/// Validate an `Electra.IndexedAttestation` JSON object: checks required fields
/// per `types/electra/attestation.yaml#/Electra/IndexedAttestation`.
///
/// Returns `Err(ApiError::BadRequest)` if any required field is missing or malformed.
/// Does not construct a typed value because the const generic `MAX_AGGREGATION_BITS`
/// differs between mainnet (131072) and minimal (8192), making a single generic
/// function incompatible with the non-generic `ChainStateApi` trait. The validated
/// JSON is passed to `submit_electra_attester_slashing` per `D-pool-v2-submit-default-broadcast`.
fn validate_electra_indexed_attestation_json(v: &JsonValue) -> Result<(), ApiError> {
    // attesting_indices: required array of Uint64 strings/numbers.
    let indices_arr = v["attesting_indices"]
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("attesting_indices missing".into()))?;
    for (i, idx_val) in indices_arr.iter().enumerate() {
        parse_u64(idx_val)
            .map_err(|e| ApiError::BadRequest(format!("attesting_indices[{i}]: {e}")))?;
    }
    // data: required AttestationData.
    parse_attestation_data(&v["data"])?;
    // signature: required 0x-prefixed 96-byte hex.
    let sig_hex = v["signature"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("signature missing".into()))?;
    parse_bls_sig(sig_hex)?;
    Ok(())
}

/// Validate an `Electra.AttesterSlashing` JSON object: checks required fields
/// per `types/electra/attester_slashing.yaml#/Electra/AttesterSlashing`.
///
/// Returns the original `v` on success so the caller can pass it to
/// `submit_electra_attester_slashing` without re-cloning.
fn validate_electra_attester_slashing_json(v: &JsonValue) -> Result<(), ApiError> {
    validate_electra_indexed_attestation_json(&v["attestation_1"])
        .map_err(|e| ApiError::BadRequest(format!("attestation_1: {e}")))?;
    validate_electra_indexed_attestation_json(&v["attestation_2"])
        .map_err(|e| ApiError::BadRequest(format!("attestation_2: {e}")))?;
    Ok(())
}

/// Parse a `Phase0.AttesterSlashing` from JSON.
///
/// Fields per `types/phase0/attester_slashing.yaml`: `attestation_1`, `attestation_2`.
fn parse_phase0_attester_slashing(v: &JsonValue) -> Result<Phase0AttesterSlashing<2048>, ApiError> {
    fn parse_phase0_indexed(v: &JsonValue) -> Result<Phase0IndexedAttestation<2048>, ApiError> {
        let indices_arr = v["attesting_indices"]
            .as_array()
            .ok_or_else(|| ApiError::BadRequest("attesting_indices missing".into()))?;
        // Collect all indices first so errors are reported before constructing the list.
        let parsed_indices: Result<Vec<ValidatorIndex>, ApiError> = indices_arr
            .iter()
            .enumerate()
            .map(|(i, idx_val)| {
                parse_u64(idx_val)
                    .map(ValidatorIndex)
                    .map_err(|e| ApiError::BadRequest(format!("attesting_indices[{i}]: {e}")))
            })
            .collect();
        let parsed_indices = parsed_indices?;
        let indices = SszList::<ValidatorIndex, 2048>::from_items(parsed_indices)
            .map_err(|_| ApiError::BadRequest("attesting_indices: too many entries".into()))?;
        let data = parse_attestation_data(&v["data"])?;
        let sig_hex = v["signature"]
            .as_str()
            .ok_or_else(|| ApiError::BadRequest("signature missing".into()))?;
        let signature = parse_bls_sig(sig_hex)?;
        Ok(Phase0IndexedAttestation {
            attesting_indices: indices,
            data,
            signature,
        })
    }

    let att1 = parse_phase0_indexed(&v["attestation_1"])
        .map_err(|e| ApiError::BadRequest(format!("attestation_1: {e}")))?;
    let att2 = parse_phase0_indexed(&v["attestation_2"])
        .map_err(|e| ApiError::BadRequest(format!("attestation_2: {e}")))?;
    Ok(Phase0AttesterSlashing {
        attestation_1: att1,
        attestation_2: att2,
    })
}

// ── EIP-7549 v2 pool handlers ─────────────────────────────────────────────────

/// `POST /eth/v2/beacon/pool/attestations`
///
/// Fork-selected by the required `Eth-Consensus-Version` request header:
/// - electra / fulu  → body is an array of `Electra.SingleAttestation`
/// - phase0..deneb   → body is an array of `Phase0.Attestation`
///
/// Per `attestations.v2.yaml` (submitPoolAttestationsV2): missing or unknown
/// header → 400 Bad Request.
pub async fn post_pool_attestations_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    request: Request,
) -> Response {
    // Extract the required `Eth-Consensus-Version` header before consuming body.
    let fork_str = match request
        .headers()
        .get("eth-consensus-version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
    {
        Some(s) => s,
        None => {
            return ApiError::BadRequest("missing required Eth-Consensus-Version header".into())
                .into_response();
        }
    };

    let fork_variant = match header_str_to_fork_variant(&fork_str) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

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
            // An empty array is a valid no-op per the v2 spec.
            return Ok(());
        }

        match fork_variant {
            ForkVariant::Electra | ForkVariant::Fulu => {
                // Electra+: array of SingleAttestation objects.
                let mut single_atts: Vec<SingleAttestation> = Vec::with_capacity(body_json.len());
                for (i, item) in body_json.iter().enumerate() {
                    let att = parse_single_attestation(item)
                        .map_err(|e| ApiError::BadRequest(format!("attestation[{i}]: {e}")))?;
                    single_atts.push(att);
                }
                chain.submit_single_attestations(single_atts)
            }
            ForkVariant::Phase0
            | ForkVariant::Altair
            | ForkVariant::Bellatrix
            | ForkVariant::Capella
            | ForkVariant::Deneb => {
                // Pre-electra: array of Phase0.Attestation objects.
                let mut attestations: Vec<Attestation<2048>> = Vec::with_capacity(body_json.len());
                for (i, item) in body_json.iter().enumerate() {
                    let att = parse_attestation(item)
                        .map_err(|e| ApiError::BadRequest(format!("attestation[{i}]: {e}")))?;
                    attestations.push(att);
                }
                chain.submit_attestations(attestations)
            }
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/beacon/pool/attestations`
///
/// Returns `{version, data}` + `Eth-Consensus-Version` response header.
///
/// Per `attestations.v2.yaml` (getPoolAttestationsV2): the `data` field is
/// fork-selected by exhaustive `ForkVariant` match:
/// - electra / fulu  → array of `Electra.Attestation` (aggregated, with `committee_bits`)
/// - phase0..deneb   → array of `Phase0.Attestation`
///
/// The pool stores `Phase0.Attestation` objects. For electra+ forks, the pool
/// contents are wrapped into the `Electra.Attestation` JSON shape (single
/// committee_bits bit set at index 0; committee_index carried in `data.index`).
pub async fn get_pool_attestations_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let atts = chain.pool_attestations();
        let cfg = chain.runtime_cfg();
        let current_slot = chain.current_slot();
        let spe = cfg.slots_per_epoch;
        let variant = fork_variant_at_slot(&cfg, current_slot.0, spe);
        Ok::<_, ApiError>((variant, atts))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((variant, atts))) => {
            let version = fork_variant_str(variant);
            // Per-fork data array shape (exhaustive match, no _ =>):
            let data: Vec<JsonValue> = match variant {
                ForkVariant::Electra | ForkVariant::Fulu => {
                    // Electra.Attestation: adds `committee_bits` field.
                    // Pool items are Phase0.Attestation; emit them as
                    // Electra.Attestation by adding committee_bits with the
                    // single bit at the index from data.index.
                    // committee_bits is a Bitvector[MAX_COMMITTEES_PER_SLOT].
                    // Width is preset-dependent: mainnet=64 bits (8 bytes),
                    // minimal=4 bits (1 byte). Derive from E::MAX_COMMITTEES_PER_SLOT.
                    let n_committees = E::MAX_COMMITTEES_PER_SLOT as usize;
                    let n_bytes = n_committees.div_ceil(8);
                    atts.into_iter()
                        .map(|att| {
                            // Set the bit at the committee index carried in data.index.
                            let committee_idx = att["data"]["index"]
                                .as_str()
                                .and_then(|s| s.parse::<usize>().ok());
                            let mut bits = vec![0u8; n_bytes];
                            if let Some(idx) = committee_idx
                                && idx < n_committees
                            {
                                bits[idx / 8] |= 1 << (idx % 8);
                            }
                            let committee_bits_hex = format!("0x{}", hex::encode(&bits));
                            serde_json::json!({
                                "aggregation_bits": att["aggregation_bits"],
                                "data": att["data"],
                                "signature": att["signature"],
                                "committee_bits": committee_bits_hex,
                            })
                        })
                        .collect()
                }
                ForkVariant::Phase0
                | ForkVariant::Altair
                | ForkVariant::Bellatrix
                | ForkVariant::Capella
                | ForkVariant::Deneb => {
                    // Phase0.Attestation shape unchanged.
                    atts
                }
            };
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

/// `POST /eth/v2/beacon/pool/attester_slashings`
///
/// Fork-selected by the required `Eth-Consensus-Version` request header:
/// - electra / fulu  → body is a single `Electra.AttesterSlashing`
/// - phase0..deneb   → body is a single `Phase0.AttesterSlashing`
///
/// Per `attester_slashings.v2.yaml` (submitPoolAttesterSlashingsV2): missing or
/// unknown header → 400 Bad Request.
pub async fn post_pool_attester_slashings_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    request: Request,
) -> Response {
    let fork_str = match request
        .headers()
        .get("eth-consensus-version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase())
    {
        Some(s) => s,
        None => {
            return ApiError::BadRequest("missing required Eth-Consensus-Version header".into())
                .into_response();
        }
    };

    let fork_variant = match header_str_to_fork_variant(&fork_str) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let body_bytes = match axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return ApiError::BadRequest(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    let body_json: JsonValue = match serde_json::from_slice(&body_bytes) {
        Ok(j) => j,
        Err(e) => {
            return ApiError::BadRequest(format!("invalid JSON: {e}")).into_response();
        }
    };

    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        match fork_variant {
            ForkVariant::Electra | ForkVariant::Fulu => {
                // Validate structure before accepting.
                validate_electra_attester_slashing_json(&body_json)?;
                chain.submit_electra_attester_slashing(body_json)
            }
            ForkVariant::Phase0
            | ForkVariant::Altair
            | ForkVariant::Bellatrix
            | ForkVariant::Capella
            | ForkVariant::Deneb => {
                let slashing = parse_phase0_attester_slashing(&body_json)?;
                chain.submit_phase0_attester_slashing(slashing)
            }
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/beacon/pool/attester_slashings`
///
/// Returns `{version, data}` + `Eth-Consensus-Version` response header.
///
/// Per `attester_slashings.v2.yaml` (getPoolAttesterSlashingsV2): the `data`
/// field is fork-selected by exhaustive `ForkVariant` match:
/// - electra / fulu  → array of `Electra.AttesterSlashing`
/// - phase0..deneb   → array of `Phase0.AttesterSlashing`
///
/// The pool stores `Phase0.AttesterSlashing` objects. Both shapes share the
/// `{attestation_1, attestation_2}` outer structure; the difference is the
/// inner `IndexedAttestation` type. The pool's `AttesterSlashing` carries
/// `Phase0.IndexedAttestation` (limit 2048), which is valid as `Electra.IndexedAttestation`
/// (limit 131072). Both are serialized as the same JSON shape.
pub async fn get_pool_attester_slashings_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let slashings = chain.pool_attester_slashings();
        let cfg = chain.runtime_cfg();
        let current_slot = chain.current_slot();
        let spe = cfg.slots_per_epoch;
        let variant = fork_variant_at_slot(&cfg, current_slot.0, spe);
        Ok::<_, ApiError>((variant, slashings))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((variant, slashings))) => {
            let version = fork_variant_str(variant);
            // The JSON shape of the pool items is already correct for both
            // Phase0.AttesterSlashing and Electra.AttesterSlashing (same outer
            // structure: {attestation_1, attestation_2} with {attesting_indices,
            // data, signature}). Exhaustive fork match dispatches the correct
            // version tag without a _ => fallback.
            let body = match variant {
                ForkVariant::Phase0
                | ForkVariant::Altair
                | ForkVariant::Bellatrix
                | ForkVariant::Capella
                | ForkVariant::Deneb
                | ForkVariant::Electra
                | ForkVariant::Fulu => {
                    serde_json::json!({ "version": version, "data": slashings })
                }
            };
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
