//! Integration test: `prepare_execution_payload` round-trip via a mock EL.
//!
//! Asserts that the Capella V2 payload-production path:
//!   FCU V2 with attrs → payloadId → `engine_getPayloadV2` → in-house
//!   `capella::ExecutionPayload` (mainnet preset)
//! round-trips correctly against a canned `engine_getPayloadV2` response
//! shaped as `{executionPayload, blockValue}` per shanghai.md.
//!

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use parking_lot::Mutex;
use pharos_engine::types::ForkchoiceStateV1;
use pharos_engine::{EngineClient, JwtSecret, spawn_engine_actor};
use pharos_node::engine_driver::{PreparePayloadError, prepare_execution_payload};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ── Mock EL server ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MockState {
    secret: Arc<JwtSecret>,
    responses: Arc<Mutex<HashMap<String, Value>>>,
}

#[derive(Deserialize)]
struct RpcEnvelope {
    method: String,
    #[allow(dead_code)]
    params: Value,
    id: u64,
}

async fn mock_handler(
    State(s): State<MockState>,
    headers: HeaderMap,
    Json(req): Json<RpcEnvelope>,
) -> impl IntoResponse {
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(token) = bearer else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "no token"}))).into_response();
    };
    let mut val = Validation::new(Algorithm::HS256);
    val.required_spec_claims.clear();
    val.required_spec_claims.insert("iat".into());
    val.validate_exp = false;
    if decode::<Value>(token, &DecodingKey::from_secret(s.secret.as_bytes()), &val).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "bad token"})),
        )
            .into_response();
    }
    let result = s
        .responses
        .lock()
        .get(&req.method)
        .cloned()
        .unwrap_or(json!(null));
    (
        StatusCode::OK,
        Json(json!({"jsonrpc": "2.0", "id": req.id, "result": result})),
    )
        .into_response()
}

struct MockServer {
    url: reqwest::Url,
    secret: JwtSecret,
    responses: Arc<Mutex<HashMap<String, Value>>>,
}

impl MockServer {
    fn set(&self, method: &str, value: Value) {
        self.responses.lock().insert(method.into(), value);
    }
}

async fn spawn_mock() -> MockServer {
    let secret = JwtSecret::from_bytes([0xAB; 32]);
    let responses: Arc<Mutex<HashMap<String, Value>>> = Arc::new(Mutex::new(HashMap::new()));
    let state = MockState {
        secret: Arc::new(secret.clone()),
        responses: responses.clone(),
    };
    let app = Router::new()
        .route("/", post(mock_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = format!("http://{addr}/").parse().unwrap();
    MockServer {
        url,
        secret,
        responses,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Round-trip: FCU V2 with attrs → payloadId → getPayloadV2 → in-house capella payload.
///
/// The mock returns a `payloadId` from `engine_forkchoiceUpdatedV2` and
/// a canned `{executionPayload, blockValue}` from `engine_getPayloadV2`.
/// Asserts:
/// - `prepare_execution_payload` succeeds (no `PayloadNotReady`).
/// - The returned `ExecutionPayloadV2` matches the mock payload fields.
/// - `TryFrom<ExecutionPayloadV2>` converts to in-house
///   `capella::ExecutionPayload<.., 16>` without error.
/// - Field values survive the round-trip (block_number, gas_limit, timestamp,
///   withdrawal index).
#[tokio::test]
async fn prepare_execution_payload_round_trip() {
    let mock = spawn_mock().await;

    // Program mock: engine_forkchoiceUpdatedV2 returns VALID + payloadId.
    mock.set(
        "engine_forkchoiceUpdatedV2",
        json!({
            "payloadStatus": {
                "status": "VALID",
                "latestValidHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "validationError": null
            },
            "payloadId": "0x0102030405060708"
        }),
    );

    // Program mock: engine_getPayloadV2 returns {executionPayload, blockValue}
    // per execution-apis/src/engine/shanghai.md.
    mock.set(
        "engine_getPayloadV2",
        json!({
            "executionPayload": {
                "parentHash":    "0x0000000000000000000000000000000000000000000000000000000000000001",
                "feeRecipient":  "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                "stateRoot":     "0x0000000000000000000000000000000000000000000000000000000000000002",
                "receiptsRoot":  "0x0000000000000000000000000000000000000000000000000000000000000003",
                "logsBloom":     &format!("0x{}", "00".repeat(256)),
                "prevRandao":    "0x0000000000000000000000000000000000000000000000000000000000000004",
                "blockNumber":   "0x10",
                "gasLimit":      "0x1c9c380",
                "gasUsed":       "0x0",
                "timestamp":     "0x64e7785b",
                "extraData":     "0x",
                "baseFeePerGas": "0x7",
                "blockHash":     "0x0000000000000000000000000000000000000000000000000000000000000005",
                "transactions":  ["0xdeadbeef"],
                "withdrawals": [
                    {
                        "index":          "0x1",
                        "validatorIndex": "0x2",
                        "address":        "0x0000000000000000000000000000000000000001",
                        "amount":         "0x3e8"
                    }
                ]
            },
            "blockValue": "0x0"
        }),
    );

    let primary = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let handle = spawn_engine_actor(primary, None);

    let fcu_state = ForkchoiceStateV1 {
        head_block_hash: "0x0000000000000000000000000000000000000000000000000000000000000001"
            .into(),
        safe_block_hash: "0x0000000000000000000000000000000000000000000000000000000000000001"
            .into(),
        finalized_block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
    };

    // Build minimal PayloadAttributesV2 (contents ignored by the mock, but must
    // serialize correctly).
    let attrs = pharos_engine::types::PayloadAttributesV2 {
        timestamp: "0x64e7785b".into(),
        prev_randao: "0x0000000000000000000000000000000000000000000000000000000000000004".into(),
        suggested_fee_recipient: "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b".into(),
        withdrawals: vec![],
    };

    // Run prepare_execution_payload in a spawn_blocking (it uses blocking EngineHandle calls).
    let result =
        tokio::task::spawn_blocking(move || prepare_execution_payload(&handle, fcu_state, attrs))
            .await
            .expect("spawn_blocking join");

    // Must succeed (not PayloadNotReady).
    let wire_payload = match result {
        Ok(p) => p,
        Err(PreparePayloadError::PayloadNotReady) => panic!("EL returned no payloadId"),
        Err(PreparePayloadError::Engine(e)) => panic!("engine error: {e}"),
    };

    // Assert wire payload fields match what the mock returned.
    assert_eq!(wire_payload.block_number, "0x10");
    assert_eq!(wire_payload.gas_limit, "0x1c9c380");
    assert_eq!(wire_payload.timestamp, "0x64e7785b");
    assert_eq!(wire_payload.withdrawals.len(), 1);
    assert_eq!(wire_payload.withdrawals[0].index, "0x1");
    assert_eq!(wire_payload.withdrawals[0].validator_index, "0x2");
    assert_eq!(wire_payload.withdrawals[0].amount, "0x3e8");
    assert_eq!(wire_payload.transactions.len(), 1);

    // TryFrom: convert wire → in-house capella::ExecutionPayload (mainnet, 16 withdrawals).
    use pharos_types::capella::ExecutionPayload as CapellaPayload;
    let in_house: CapellaPayload<1_073_741_824, 1_048_576, 256, 32, 16> =
        wire_payload.try_into().expect("TryFrom must succeed");

    use pharos_ssz::SszSequence as _;
    assert_eq!(in_house.block_number, 0x10u64);
    assert_eq!(in_house.gas_limit, 0x1c9c380u64);
    assert_eq!(in_house.timestamp, 0x64e7785bu64);
    assert_eq!(in_house.withdrawals.len(), 1);
    assert_eq!(in_house.withdrawals.as_slice()[0].index, 1u64);
    assert_eq!(in_house.withdrawals.as_slice()[0].validator_index.0, 2u64);
    assert_eq!(in_house.withdrawals.as_slice()[0].amount.0, 0x3e8u64);
    assert_eq!(in_house.transactions.len(), 1);
}

/// Verify that `prepare_execution_payload` returns `PayloadNotReady` when
/// `engine_forkchoiceUpdatedV2` returns `payloadId: null`.
#[tokio::test]
async fn prepare_execution_payload_no_payload_id_returns_not_ready() {
    let mock = spawn_mock().await;

    // FCU returns SYNCING with no payloadId.
    mock.set(
        "engine_forkchoiceUpdatedV2",
        json!({
            "payloadStatus": {
                "status": "SYNCING",
                "latestValidHash": null,
                "validationError": null
            },
            "payloadId": null
        }),
    );

    let primary = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let handle = spawn_engine_actor(primary, None);

    let fcu_state = ForkchoiceStateV1 {
        head_block_hash: "0x00".into(),
        safe_block_hash: "0x00".into(),
        finalized_block_hash: "0x00".into(),
    };
    let attrs = pharos_engine::types::PayloadAttributesV2 {
        timestamp: "0x0".into(),
        prev_randao: "0x00".into(),
        suggested_fee_recipient: "0x00".into(),
        withdrawals: vec![],
    };

    let result =
        tokio::task::spawn_blocking(move || prepare_execution_payload(&handle, fcu_state, attrs))
            .await
            .expect("spawn_blocking join");

    assert!(
        matches!(result, Err(PreparePayloadError::PayloadNotReady)),
        "expected PayloadNotReady, got {result:?}"
    );
}
