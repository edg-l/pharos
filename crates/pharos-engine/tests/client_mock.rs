//! Integration tests against an in-process axum mock EL.
//!
//! Covers:
//! 1. JWT round-trip (issue + verify with the same secret).
//! 2. `engine_exchangeCapabilities` request/response.
//! 3. `engine_forkchoiceUpdatedV1` happy path + JSON-RPC error path.
//! 4. `engine_newPayloadV1` for `VALID` / `INVALID` / `SYNCING`.

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
use pharos_engine::jwt::sign_token;
use pharos_engine::{
    EngineClient, ExecutionPayloadV1, ForkchoiceStateV1, ForkchoiceUpdatedV1Response,
    ForkchoiceUpdatedVersion, JwtSecret, NewPayloadVersion, PayloadStatusStatus,
};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ── Mock server ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MockState {
    secret: Arc<JwtSecret>,
    responses: Arc<Mutex<HashMap<String, Value>>>,
}

#[derive(Deserialize)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    #[allow(dead_code)]
    params: Value,
    id: u64,
}

async fn rpc_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let Some(token) = bearer else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "no token" })),
        )
            .into_response();
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.required_spec_claims.insert("iat".into());
    validation.validate_exp = false;
    let key = DecodingKey::from_secret(state.secret.as_bytes());
    if decode::<Value>(token, &key, &validation).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "bad token" })),
        )
            .into_response();
    }

    let result = state
        .responses
        .lock()
        .get(&req.method)
        .cloned()
        .unwrap_or(json!(null));
    let envelope = if let Some(err) = result.get("__error__") {
        json!({"jsonrpc": "2.0", "id": req.id, "error": err.clone()})
    } else {
        json!({"jsonrpc": "2.0", "id": req.id, "result": result})
    };
    (StatusCode::OK, Json(envelope)).into_response()
}

struct Mock {
    url: Url,
    secret: JwtSecret,
    responses: Arc<Mutex<HashMap<String, Value>>>,
}

async fn spawn_mock() -> Mock {
    let secret = JwtSecret::from_bytes([0xAB; 32]);
    let responses = Arc::new(Mutex::new(HashMap::new()));
    let state = MockState {
        secret: Arc::new(secret.clone()),
        responses: responses.clone(),
    };
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url: Url = format!("http://{addr}/").parse().unwrap();
    Mock {
        url,
        secret,
        responses,
    }
}

// We need a clone for sharing the secret with the mock; provide it as a
// helper since `JwtSecret` doesn't derive Clone outside the crate.
impl Mock {
    fn set(&self, method: &str, value: Value) {
        self.responses.lock().insert(method.into(), value);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn jwt_round_trip() {
    let secret = JwtSecret::from_bytes([7u8; 32]);
    let token = sign_token(&secret).unwrap();
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.required_spec_claims.insert("iat".into());
    validation.validate_exp = false;
    let decoded = decode::<Value>(&token, &key, &validation).unwrap();
    assert!(decoded.claims.get("iat").and_then(Value::as_u64).is_some());
}

#[tokio::test]
async fn exchange_capabilities_round_trip() {
    let mock = spawn_mock().await;
    mock.set(
        "engine_exchangeCapabilities",
        json!([
            "engine_newPayloadV1",
            "engine_forkchoiceUpdatedV1",
            "engine_getPayloadV1",
            "engine_exchangeCapabilities"
        ]),
    );
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let caps = client
        .exchange_capabilities(&["engine_newPayloadV1", "engine_forkchoiceUpdatedV1"])
        .await
        .unwrap();
    assert!(caps.contains("engine_newPayloadV1"));
    assert!(caps.contains("engine_forkchoiceUpdatedV1"));
    // Second call serves from cache; mutate mock to confirm.
    mock.set("engine_exchangeCapabilities", json!([]));
    let cached = client.exchange_capabilities(&[]).await.unwrap();
    assert!(cached.contains("engine_newPayloadV1"));
}

#[tokio::test]
async fn forkchoice_updated_happy_path() {
    let mock = spawn_mock().await;
    mock.set(
        "engine_forkchoiceUpdatedV1",
        json!({
            "payloadStatus": {
                "status": "VALID",
                "latestValidHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "validationError": null,
            },
            "payloadId": null,
        }),
    );
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let state = ForkchoiceStateV1 {
        head_block_hash: "0x01".into(),
        safe_block_hash: "0x01".into(),
        finalized_block_hash: "0x01".into(),
    };
    let resp: ForkchoiceUpdatedV1Response = client
        .forkchoice_updated(ForkchoiceUpdatedVersion::V1, state, None)
        .await
        .unwrap();
    assert_eq!(resp.payload_status.status, PayloadStatusStatus::Valid);
    assert!(resp.payload_id.is_none());
}

#[tokio::test]
async fn forkchoice_updated_error_path() {
    let mock = spawn_mock().await;
    mock.set(
        "engine_forkchoiceUpdatedV1",
        json!({"__error__": {"code": -32602, "message": "invalid params"}}),
    );
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let state = ForkchoiceStateV1 {
        head_block_hash: "0x01".into(),
        safe_block_hash: "0x01".into(),
        finalized_block_hash: "0x01".into(),
    };
    let err = client
        .forkchoice_updated(ForkchoiceUpdatedVersion::V1, state, None)
        .await
        .unwrap_err();
    match err {
        pharos_engine::EngineError::JsonRpc { code, message } => {
            assert_eq!(code, -32602);
            assert_eq!(message, "invalid params");
        }
        other => panic!("expected JsonRpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn new_payload_valid_invalid_syncing() {
    let mock = spawn_mock().await;
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();

    for (status_str, expected) in [
        ("VALID", PayloadStatusStatus::Valid),
        ("INVALID", PayloadStatusStatus::Invalid),
        ("SYNCING", PayloadStatusStatus::Syncing),
    ] {
        mock.set(
            "engine_newPayloadV1",
            json!({"status": status_str, "latestValidHash": null, "validationError": null}),
        );
        let resp = client
            .new_payload(NewPayloadVersion::V1, dummy_payload())
            .await
            .unwrap();
        assert_eq!(resp.status, expected, "status `{status_str}` round-trip");
    }
}

fn dummy_payload() -> ExecutionPayloadV1 {
    ExecutionPayloadV1 {
        parent_hash: "0x00".into(),
        fee_recipient: "0x00".into(),
        state_root: "0x00".into(),
        receipts_root: "0x00".into(),
        logs_bloom: "0x00".into(),
        prev_randao: "0x00".into(),
        block_number: "0x0".into(),
        gas_limit: "0x0".into(),
        gas_used: "0x0".into(),
        timestamp: "0x0".into(),
        extra_data: "0x".into(),
        base_fee_per_gas: "0x0".into(),
        block_hash: "0x00".into(),
        transactions: vec![],
    }
}
