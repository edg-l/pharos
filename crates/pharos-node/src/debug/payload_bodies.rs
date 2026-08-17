//! `pharos debug payload-bodies` — `engine_getPayloadBodies{ByHash,ByRange}`
//! consumer.
//!
//! Unlike `debug das` (a pure offline calculator), this tool drives the live
//! Engine API: it spins up an [`EngineClient`] + [`spawn_engine_actor`] exactly
//! like the node does, then calls the Phase-1 [`EngineHandle`] blocking
//! payload-bodies methods from inside `tokio::task::spawn_blocking` (calling a
//! blocking method directly on the async runtime thread panics — M3a
//! invariant). It exists as the reference call site for
//! `engine_getPayloadBodiesByHashV1`/`ByRangeV1` so `DEFAULT_ENGINE_CAPABILITIES`
//! advertises methods pharos actually calls, not merely implements.

use std::path::Path;

use anyhow::Context as _;
use pharos_engine::{EngineClient, spawn_engine_actor};
use serde_json::Value as JsonValue;

use crate::jwt_autogen::ensure_jwt_secret;

/// Selects which `engine_getPayloadBodies*` query to issue.
pub enum Mode {
    ByHash(Vec<String>),
    ByRange { start: u64, count: u64 },
}

/// Resolve the JWT secret, connect to the EL, issue the requested
/// `engine_getPayloadBodiesBy{Hash,Range}{V1,V2}` call, and print the result.
///
/// `v2` selects the Amsterdam-era V2 variant (implemented on `EngineClient` but
/// not advertised in `DEFAULT_ENGINE_CAPABILITIES` — pharos has no Amsterdam
/// fork); `v1` (the default) is the advertised, driven method.
pub async fn run(
    execution_endpoint: &str,
    jwt_secret: Option<&Path>,
    data_dir: &Path,
    mode: Mode,
    v2: bool,
    json_out: bool,
) -> anyhow::Result<()> {
    let jwt = ensure_jwt_secret(data_dir, jwt_secret).context("ensuring JWT secret")?;
    let url: reqwest::Url = execution_endpoint.parse().with_context(|| {
        format!("--execution-endpoint is not a valid URL: {execution_endpoint}")
    })?;
    let client = EngineClient::new(url, jwt).context("constructing EngineClient")?;
    let handle = spawn_engine_actor(client, None);

    // The blocking `EngineHandle` methods must not run on the async runtime
    // thread; hop to a blocking-pool thread for the round-trip.
    let bodies: Vec<JsonValue> = tokio::task::spawn_blocking(move || match (mode, v2) {
        (Mode::ByHash(block_hashes), false) => handle
            .get_payload_bodies_by_hash_v1_blocking(block_hashes)
            .map(|bodies| {
                bodies
                    .into_iter()
                    .map(|b| serde_json::to_value(b).unwrap_or(JsonValue::Null))
                    .collect::<Vec<_>>()
            }),
        (Mode::ByHash(block_hashes), true) => handle
            .get_payload_bodies_by_hash_v2_blocking(block_hashes)
            .map(|bodies| {
                bodies
                    .into_iter()
                    .map(|b| serde_json::to_value(b).unwrap_or(JsonValue::Null))
                    .collect::<Vec<_>>()
            }),
        (Mode::ByRange { start, count }, false) => handle
            .get_payload_bodies_by_range_v1_blocking(format!("0x{start:x}"), format!("0x{count:x}"))
            .map(|bodies| {
                bodies
                    .into_iter()
                    .map(|b| serde_json::to_value(b).unwrap_or(JsonValue::Null))
                    .collect::<Vec<_>>()
            }),
        (Mode::ByRange { start, count }, true) => handle
            .get_payload_bodies_by_range_v2_blocking(format!("0x{start:x}"), format!("0x{count:x}"))
            .map(|bodies| {
                bodies
                    .into_iter()
                    .map(|b| serde_json::to_value(b).unwrap_or(JsonValue::Null))
                    .collect::<Vec<_>>()
            }),
    })
    .await
    .context("spawn_blocking must not panic")?
    .context("engine_getPayloadBodies* call failed")?;

    if json_out {
        println!("{}", serde_json::to_string_pretty(&bodies)?);
        return Ok(());
    }

    for (i, body) in bodies.iter().enumerate() {
        if body.is_null() {
            println!("[{i}] null");
        } else {
            println!("[{i}] {}", serde_json::to_string_pretty(body)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::{
        Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post,
    };
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use parking_lot::Mutex;
    use pharos_engine::JwtSecret;
    use serde::Deserialize;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    use super::*;

    // ── Minimal mock EL (mirrors engine_keepalive.rs's harness) ─────────────────

    #[derive(Clone)]
    struct MockState {
        secret: Arc<JwtSecret>,
        responses: Arc<Mutex<HashMap<String, JsonValue>>>,
    }

    #[derive(Deserialize)]
    struct RpcEnvelope {
        method: String,
        #[allow(dead_code)]
        params: JsonValue,
        id: u64,
    }

    async fn mock_handler(
        State(s): State<MockState>,
        headers: axum::http::HeaderMap,
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
        if decode::<JsonValue>(token, &DecodingKey::from_secret(s.secret.as_bytes()), &val).is_err()
        {
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
        responses: Arc<Mutex<HashMap<String, JsonValue>>>,
    }

    impl MockServer {
        fn set(&self, method: &str, value: JsonValue) {
            self.responses.lock().insert(method.into(), value);
        }
    }

    async fn spawn_mock() -> MockServer {
        let secret = JwtSecret::from_bytes([0xAB; 32]);
        let responses: Arc<Mutex<HashMap<String, JsonValue>>> =
            Arc::new(Mutex::new(HashMap::new()));
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

    /// `run` end-to-end against a mock EL (both output modes) must not error,
    /// covering `engine_getPayloadBodiesByRangeV1`.
    #[tokio::test]
    async fn run_smoke_both_output_modes() {
        let mock = spawn_mock().await;
        mock.set(
            "engine_getPayloadBodiesByRangeV1",
            json!([
                {
                    "transactions": ["0xdeadbeef"],
                    "withdrawals": null,
                },
                null,
            ]),
        );

        let dir = TempDir::new().unwrap();
        let jwt_path = dir.path().join("jwt.hex");
        std::fs::write(&jwt_path, hex::encode(mock.secret.as_bytes())).unwrap();

        run(
            mock.url.as_str(),
            Some(jwt_path.as_path()),
            dir.path(),
            Mode::ByRange { start: 1, count: 2 },
            false,
            false,
        )
        .await
        .expect("run (human output) must succeed");

        run(
            mock.url.as_str(),
            Some(jwt_path.as_path()),
            dir.path(),
            Mode::ByRange { start: 1, count: 2 },
            false,
            true,
        )
        .await
        .expect("run (json output) must succeed");
    }
}
