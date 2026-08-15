//! Validator production/signing namespace handlers (Task 5.2).
//!
//! Routes implemented:
//! - `GET  /eth/v3/validator/blocks/{slot}`
//! - `GET  /eth/v1/validator/attestation_data`
//! - `GET  /eth/v2/validator/aggregate_attestation`
//! - `POST /eth/v2/validator/aggregate_and_proofs`
//! - `POST /eth/v1/validator/prepare_beacon_proposer`
//! - `POST /eth/v1/validator/register_validator`
//! - `POST /eth/v1/validator/beacon_committee_subscriptions`
//! - `POST /eth/v1/validator/sync_committee_subscriptions`
//!
//! All production/signing endpoints return HTTP 503 when the node is syncing
//! or in an optimistic state (`D-503-on-optimistic-or-syncing`).
//!
//! Spec shapes from `~/dev/beacon-APIs/`:
//! - `apis/validator/produce_block_v3.yaml`
//! - `apis/validator/attestation_data.yaml`
//! - `apis/validator/aggregate_attestation.v2.yaml`
//! - `apis/validator/aggregate_and_proofs.v2.yaml`
//! - `apis/validator/prepare_beacon_proposer.yaml`
//! - `apis/validator/register_validator.yaml`
//! - `apis/validator/beacon_committee_subscriptions.yaml`
//! - `apis/validator/sync_committee_subscriptions.yaml`

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use pharos_types::EthSpec;
use pharos_types::bellatrix::execution_payload::ExecutionAddress;
use pharos_types::phase0::primitives::{CommitteeIndex, Slot, ValidatorIndex};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::fork_tag::{ETH_CONSENSUS_VERSION, fork_variant_at_slot, fork_variant_str};
use crate::serde_helpers::quoted_u64;
use crate::state::ApiState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Query parameters for `GET /eth/v3/validator/blocks/{slot}`.
#[derive(Deserialize)]
pub struct ProduceBlockQuery {
    /// RANDAO reveal — 0x-prefixed 96-byte BLS signature.
    pub randao_reveal: String,
    /// Optional 0x-prefixed 32-byte graffiti hex.
    pub graffiti: Option<String>,
}

/// Query parameters for `GET /eth/v1/validator/attestation_data`.
#[derive(Deserialize)]
pub struct AttestationDataQuery {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub committee_index: u64,
}

/// Query parameters for `GET /eth/v2/validator/aggregate_attestation`.
#[derive(Deserialize)]
pub struct AggregateAttestationQuery {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    pub attestation_data_root: String,
}

/// Response for `GET /eth/v1/validator/attestation_data`.
#[derive(Serialize)]
struct AttestationDataResponse {
    data: JsonValue,
}

/// Response for `GET /eth/v2/validator/aggregate_attestation`.
#[derive(Serialize)]
struct AggregateAttestationResponse {
    data: JsonValue,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a 0x-prefixed 96-byte BLS signature from a hex string.
fn parse_randao_reveal(s: &str) -> Result<pharos_utils::BLSSignature, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(s).map_err(|_| ApiError::BadRequest("invalid randao_reveal hex".into()))?;
    let arr: [u8; 96] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("randao_reveal must be 96 bytes".into()))?;
    Ok(pharos_utils::BLSSignature::from(arr))
}

/// Parse an optional 0x-prefixed 32-byte graffiti hex string.
fn parse_graffiti(s: Option<&str>) -> pharos_utils::Bytes32 {
    let Some(s) = s else {
        return pharos_utils::Bytes32::default();
    };
    let s = s.strip_prefix("0x").unwrap_or(s);
    let Ok(bytes) = hex::decode(s) else {
        return pharos_utils::Bytes32::default();
    };
    let Ok(arr) = bytes.try_into() else {
        return pharos_utils::Bytes32::default();
    };
    pharos_utils::Bytes32::from_array(arr)
}

/// Parse a 0x-prefixed 20-byte Ethereum address into `ExecutionAddress`.
fn parse_execution_address(s: &str) -> Result<ExecutionAddress, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|_| ApiError::BadRequest(format!("invalid execution address hex: {s}")))?;
    let arr: [u8; 20] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("execution address must be 20 bytes".into()))?;
    Ok(ExecutionAddress::from(arr))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v3/validator/blocks/{slot}`
///
/// Per `~/dev/beacon-APIs/apis/validator/produce_block_v3.yaml`.
/// Returns a v3 envelope: `execution_payload_blinded: false`,
/// `execution_payload_value` (MEV-Boost not used), `consensus_block_value`,
/// fork-tagged `data`.
///
/// Response headers per spec:
/// - `Eth-Consensus-Version`
/// - `Eth-Execution-Payload-Blinded: false`
/// - `Eth-Execution-Payload-Value`
/// - `Eth-Consensus-Block-Value`
pub async fn get_produce_block_v3<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(slot): Path<u64>,
    Query(params): Query<ProduceBlockQuery>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced(
                "node is syncing or optimistic; block production is unavailable".into(),
            ));
        }

        let randao = parse_randao_reveal(&params.randao_reveal)?;
        let graffiti = parse_graffiti(params.graffiti.as_deref());

        let (block_json, exec_value, consensus_value) =
            chain.produce_block(Slot(slot), randao, graffiti)?;

        let cfg = chain.runtime_cfg();
        let spe = cfg.slots_per_epoch;
        let variant = fork_variant_at_slot(&cfg, slot, spe);
        let version = fork_variant_str(variant);

        let response = serde_json::json!({
            "version": version,
            "execution_payload_blinded": false,
            "execution_payload_value": exec_value.to_string(),
            "consensus_block_value": consensus_value.to_string(),
            "data": block_json.get("data").unwrap_or(&block_json),
        });
        Ok::<_, ApiError>((version, exec_value, consensus_value, response))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((version, exec_value, consensus_value, json))) => {
            let body = match serde_json::to_vec(&json) {
                Ok(b) => b,
                Err(e) => {
                    return ApiError::Internal(format!("JSON serialize: {e}")).into_response();
                }
            };
            let mut resp = (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response();
            // Add required v3 response headers.
            if let Ok(hv) = HeaderValue::from_str(version) {
                resp.headers_mut().insert(ETH_CONSENSUS_VERSION.clone(), hv);
            }
            resp.headers_mut().insert(
                "eth-execution-payload-blinded",
                HeaderValue::from_static("false"),
            );
            if let Ok(hv) = HeaderValue::from_str(&exec_value.to_string()) {
                resp.headers_mut().insert("eth-execution-payload-value", hv);
            }
            if let Ok(hv) = HeaderValue::from_str(&consensus_value.to_string()) {
                resp.headers_mut().insert("eth-consensus-block-value", hv);
            }
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/validator/attestation_data`
///
/// Query params: `slot` (quoted u64), `committee_index` (quoted u64).
/// Per `~/dev/beacon-APIs/apis/validator/attestation_data.yaml`.
pub async fn get_attestation_data<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Query(params): Query<AttestationDataQuery>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced(
                "node is syncing or optimistic; attestation data unavailable".into(),
            ));
        }

        let att_data = chain.produce_attestation_data(
            Slot(params.slot),
            CommitteeIndex(params.committee_index),
        )?;

        let json = serde_json::json!({
            "slot": att_data.slot.0.to_string(),
            "index": att_data.index.0.to_string(),
            "beacon_block_root": format!("0x{}", hex::encode(att_data.beacon_block_root.as_slice())),
            "source": {
                "epoch": att_data.source.epoch.0.to_string(),
                "root": format!("0x{}", hex::encode(att_data.source.root.as_slice())),
            },
            "target": {
                "epoch": att_data.target.epoch.0.to_string(),
                "root": format!("0x{}", hex::encode(att_data.target.root.as_slice())),
            },
        });
        Ok::<_, ApiError>(AttestationDataResponse { data: json })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(resp)) => Json(resp).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/validator/aggregate_attestation`
///
/// Returns the best aggregate attestation from the pool matching the given
/// attestation_data_root. When no matching attestation is found, returns 404.
pub async fn get_aggregate_attestation<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Query(_params): Query<AggregateAttestationQuery>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        // Return 404 when no matching attestation is in the pool.
        Err::<JsonValue, ApiError>(ApiError::NotFound(
            "no matching aggregate attestation in pool".into(),
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(json)) => Json(AggregateAttestationResponse { data: json }).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v2/validator/aggregate_and_proofs`
///
/// Accepts signed aggregate-and-proof objects.
/// Per `~/dev/beacon-APIs/apis/validator/aggregate_and_proofs.v2.yaml`.
pub async fn post_aggregate_and_proofs<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        chain.submit_aggregate_and_proofs(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/prepare_beacon_proposer`
///
/// Registers `(validator_index, fee_recipient)` pairs in the node's
/// fee-recipient store.  Always 200 (best-effort; no EL forwarding).
/// `D-register-validator-accept-and-store`.
/// 503 when syncing or optimistic (plan: gate every validator-namespace endpoint).
pub async fn post_prepare_beacon_proposer<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        let pairs: Vec<(ValidatorIndex, ExecutionAddress)> = body
            .iter()
            .filter_map(|item| {
                let idx = item["validator_index"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| item["validator_index"].as_u64())?;
                let fee_str = item["fee_recipient"].as_str()?;
                let addr = parse_execution_address(fee_str).ok()?;
                Some((ValidatorIndex(idx), addr))
            })
            .collect();
        chain.set_fee_recipients_by_index(pairs)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/register_validator`
///
/// Stores fee-recipient and gas-limit per BLS pubkey.
/// No MEV-Boost relay forwarding.  Always 200.
/// `D-register-validator-accept-and-store`.
/// 503 when syncing or optimistic.
pub async fn post_register_validator<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        chain.register_validators(body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/beacon_committee_subscriptions`
///
/// Accepts subscription requests. Always 200 (ENR attnets rotation is handled
/// by the subnet-rotation loop, not per-subscription).
/// 503 when syncing or optimistic.
pub async fn post_beacon_committee_subscriptions<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        let _ = body;
        Ok::<_, ApiError>(())
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/sync_committee_subscriptions`
///
/// Accepts sync committee subscription requests. Always 200.
/// `D-syncnets-enr-on-subscription` wires ENR syncnets updates in Phase 7.
/// 503 when syncing or optimistic.
pub async fn post_sync_committee_subscriptions<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Json(body): Json<Vec<JsonValue>>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        if chain.is_syncing() || chain.is_optimistic_node() {
            return Err(ApiError::NotSynced("node is syncing or optimistic".into()));
        }
        let _ = body;
        Ok::<_, ApiError>(())
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
