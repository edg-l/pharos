//! Transition-configuration keepalive task.
//!
//! `run_transition_config_keepalive` ticks every 60 seconds and calls
//! `engine_exchangeTransitionConfigurationV1` to confirm the EL agrees with
//! the CL's terminal total difficulty.  A mismatch is logged at WARN level,
//! rate-limited to one warning per distinct EL-reported TTD value.
//!
//! The keepalive is spawned from `main.rs` immediately after `spawn_engine_actor`
//! and runs until the node receives a shutdown signal.

use std::collections::HashSet;
use std::time::Duration;

use pharos_engine::{EngineError, EngineHandle, TransitionConfigurationV1};
use pharos_utils::Uint256;
use thiserror::Error;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeepaliveError {
    #[error("hex conversion: {0}")]
    Hex(String),
    #[error("engine error: {0}")]
    Engine(#[from] EngineError),
}

// ── Hex helpers (pub for use in main.rs cold-start check) ────────────────────

/// Encode a `Uint256` as a `0x`-prefixed hex string (no leading zeros, except
/// `0x0` for the zero value).
///
/// `Uint256` is stored in little-endian order; we reverse to big-endian before
/// hex-encoding so the string matches the JSON-RPC `QUANTITY` format.
pub fn u256_to_hex(v: Uint256) -> String {
    let mut be = v.to_le_bytes();
    be.reverse(); // LE → BE
    let hex = hex::encode(be);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{trimmed}")
    }
}

/// Parse a `0x`-prefixed hex string into a `Uint256`.
///
/// Strips `0x`, pads to 64 hex chars (32 bytes big-endian), decodes, then
/// stores as little-endian.
pub fn hex_to_u256(s: &str) -> Result<Uint256, KeepaliveError> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex.len() > 64 {
        return Err(KeepaliveError::Hex(format!(
            "hex value too long for U256 (max 64 hex chars): `{s}`"
        )));
    }
    // Pad to 64 chars (32 bytes).
    let padded = format!("{:0>64}", hex);
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&padded[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| KeepaliveError::Hex(format!("invalid hex in U256: `{s}`")))?;
    // `bytes` is big-endian; Uint256 is LE — reverse before storing.
    let mut le = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        le[31 - i] = *b;
    }
    Ok(Uint256::from_le_bytes(le))
}

// ── Inner tick (pub(crate) for unit-testing without running the full loop) ────

/// Execute one keepalive tick: call the EL, compare TTDs, warn on new mismatch.
///
/// Returns `Ok(true)` if a WARN was emitted (new mismatch), `Ok(false)` otherwise.
pub(crate) async fn tick_once(
    engine: &EngineHandle,
    runtime_cfg_ttd: Uint256,
    warned_ttds: &mut HashSet<Uint256>,
) -> Result<bool, KeepaliveError> {
    let cl_cfg = TransitionConfigurationV1 {
        terminal_total_difficulty: u256_to_hex(runtime_cfg_ttd),
        terminal_block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        terminal_block_number: "0x0".into(),
    };
    match engine.exchange_transition_configuration_async(cl_cfg).await {
        Ok(el_cfg) => {
            let el_ttd = hex_to_u256(&el_cfg.terminal_total_difficulty)?;
            if el_ttd != runtime_cfg_ttd && warned_ttds.insert(el_ttd) {
                warn!(
                    cl_ttd = %runtime_cfg_ttd,
                    el_ttd = %el_ttd,
                    "TTD mismatch with execution layer",
                );
                return Ok(true);
            }
            Ok(false)
        }
        Err(e) => {
            warn!(error = %e, "transition config keepalive call failed");
            Ok(false)
        }
    }
}

// ── Public keepalive entry point ──────────────────────────────────────────────

/// Long-lived task that calls `engine_exchangeTransitionConfigurationV1` every
/// 60 seconds to verify the EL's TTD matches `runtime_cfg_ttd`.
///
/// Shuts down cleanly when `shutdown_rx` receives `true`.
pub async fn run_transition_config_keepalive(
    engine: EngineHandle,
    runtime_cfg_ttd: Uint256,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    // TODO(M5): remove keepalive — exchange_transition_configuration is deprecated post-Capella
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await; // consume immediate first tick — cold-start check in main.rs covers t=0
    let mut warned_ttds: HashSet<Uint256> = HashSet::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let _ = tick_once(&engine, runtime_cfg_ttd, &mut warned_ttds).await;
            }
            result = shutdown_rx.changed() => {
                if result.is_ok() && *shutdown_rx.borrow() {
                    info!("transition_config_keepalive shutting down");
                    return;
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::{
        Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post,
    };
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use parking_lot::Mutex;
    use pharos_engine::{EngineClient, EngineHandle, run_engine_actor};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use tokio::runtime::Runtime;

    use super::*;
    use pharos_engine::JwtSecret;

    // ── Minimal mock EL ───────────────────────────────────────────────────────

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

    fn make_engine_handle(mock: &MockServer) -> EngineHandle {
        let primary = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(8);

        let actor_rt: Arc<Runtime> = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let placeholder_rt: Arc<Runtime> = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let rt_for_actor = actor_rt.clone();
        tokio::spawn(async move {
            run_engine_actor(rt_for_actor, primary, None, rx).await;
        });
        std::mem::forget(actor_rt);
        let handle = EngineHandle::new(placeholder_rt.clone(), tx);
        std::mem::forget(placeholder_rt);
        handle
    }

    // ── Hex helpers ───────────────────────────────────────────────────────────

    #[test]
    fn u256_to_hex_zero() {
        assert_eq!(u256_to_hex(Uint256::ZERO), "0x0");
    }

    #[test]
    fn u256_to_hex_small() {
        assert_eq!(u256_to_hex(Uint256::from(0x123u64)), "0x123");
    }

    #[test]
    fn hex_to_u256_roundtrip() {
        let v = Uint256::from(0x5678u64);
        let hex = u256_to_hex(v);
        let back = hex_to_u256(&hex).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn hex_to_u256_zero() {
        assert_eq!(hex_to_u256("0x0").unwrap(), Uint256::ZERO);
    }

    // ── tick_once tests ───────────────────────────────────────────────────────

    /// `tick_once` must return `Ok(false)` when EL TTD matches CL TTD.
    #[tokio::test]
    async fn tick_once_no_mismatch() {
        let mock = spawn_mock().await;
        let ttd = Uint256::from(0x1234u64);
        mock.set(
            "engine_exchangeTransitionConfigurationV1",
            json!({
                "terminalTotalDifficulty": u256_to_hex(ttd),
                "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "terminalBlockNumber": "0x0",
            }),
        );
        let handle = make_engine_handle(&mock);
        let mut warned = HashSet::new();
        let warned_flag = tick_once(&handle, ttd, &mut warned).await.unwrap();
        assert!(!warned_flag);
        assert!(warned.is_empty());
    }

    /// `tick_once` must return `Ok(true)` and insert into `warned_ttds` when
    /// the EL TTD differs from the CL TTD (first occurrence).
    #[tokio::test]
    async fn keepalive_ticks_and_warns_on_mismatch() {
        let mock = spawn_mock().await;
        let cl_ttd = Uint256::from(0x5678u64);
        let el_ttd = Uint256::from(0x1234u64);
        mock.set(
            "engine_exchangeTransitionConfigurationV1",
            json!({
                "terminalTotalDifficulty": u256_to_hex(el_ttd),
                "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "terminalBlockNumber": "0x0",
            }),
        );
        let handle = make_engine_handle(&mock);
        let mut warned = HashSet::new();
        let warned_flag = tick_once(&handle, cl_ttd, &mut warned).await.unwrap();
        assert!(warned_flag, "should have warned on first mismatch");
        assert!(warned.contains(&el_ttd), "el_ttd should be in warned set");

        // Second call with same mismatch: must NOT warn again (rate-limited).
        let warned_flag2 = tick_once(&handle, cl_ttd, &mut warned).await.unwrap();
        assert!(!warned_flag2, "should NOT warn again for same EL TTD");
    }
}
