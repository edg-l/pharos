//! Sync-callable engine handle and async actor.
//!
//! The STF runs on a `tokio::task::spawn_blocking` worker (M3a invariant) and
//! must reach the EL through an async HTTP client. We bridge the boundary
//! with an actor: `EngineHandle` sends typed requests over an mpsc channel
//! and blocks on a `oneshot::Receiver` via a dedicated multi-thread tokio
//! runtime. The actor task drives the underlying `EngineClient` and replies.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};

use crate::client::{EngineClient, ForkchoiceUpdatedVersion, GetPayloadVersion, NewPayloadVersion};
use crate::error::EngineError;
use crate::types::{
    ExecutionPayloadV1, ForkchoiceStateV1, ForkchoiceUpdatedV1Response, PayloadAttributesV1,
    PayloadIdV1, PayloadStatusV1, SyncingStatus, TransitionConfigurationV1,
};

/// Capacity of the EngineHandle → actor request channel.
///
/// Engine API requests are rare relative to block-processing rate; 64 lets
/// short bursts (a sync handful of blocks) queue without backpressure.
const ENGINE_REQUEST_CAPACITY: usize = 64;

/// Health-check interval for the primary EL.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(12);

/// Consecutive health-check failures before failing over to the secondary.
const MAX_HEALTH_FAILURES: u8 = 3;

// ── EngineRequest ────────────────────────────────────────────────────────────

/// Typed request envelope handled by the engine actor.
pub enum EngineRequest {
    NewPayload {
        version: NewPayloadVersion,
        payload: ExecutionPayloadV1,
        reply: oneshot::Sender<Result<PayloadStatusV1, EngineError>>,
    },
    ForkchoiceUpdated {
        version: ForkchoiceUpdatedVersion,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV1>,
        reply: oneshot::Sender<Result<ForkchoiceUpdatedV1Response, EngineError>>,
    },
    GetPayload {
        version: GetPayloadVersion,
        id: PayloadIdV1,
        reply: oneshot::Sender<Result<ExecutionPayloadV1, EngineError>>,
    },
    GetBlockByHash {
        hash: String,
        reply: oneshot::Sender<Result<Option<crate::types::BlockHeader>, EngineError>>,
    },
    ChainId {
        reply: oneshot::Sender<Result<u64, EngineError>>,
    },
    Syncing {
        reply: oneshot::Sender<Result<SyncingStatus, EngineError>>,
    },
    ExchangeTransitionConfiguration {
        config: TransitionConfigurationV1,
        reply: oneshot::Sender<Result<TransitionConfigurationV1, EngineError>>,
    },
}

// ── EngineHandle ─────────────────────────────────────────────────────────────

/// Sync-callable handle to the engine actor. Cheap to clone.
#[derive(Clone)]
pub struct EngineHandle {
    tx: mpsc::Sender<EngineRequest>,
    runtime: Arc<Runtime>,
}

impl EngineHandle {
    /// Wrap an existing actor channel + tokio runtime. The async-context
    /// constructor (`spawn_engine_actor` below) is the usual entry point.
    pub fn new(runtime: Arc<Runtime>, tx: mpsc::Sender<EngineRequest>) -> Self {
        Self { runtime, tx }
    }

    fn dispatch_blocking<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, EngineError>>) -> EngineRequest,
    ) -> Result<T, EngineError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let req = build(reply_tx);
        self.tx
            .blocking_send(req)
            .map_err(|_| EngineError::UnexpectedResponse("engine actor dropped".into()))?;
        self.runtime
            .block_on(reply_rx)
            .map_err(|_| EngineError::UnexpectedResponse("engine actor dropped reply".into()))?
    }

    /// Sync `engine_newPayload*`.
    pub fn new_payload_blocking(
        &self,
        version: NewPayloadVersion,
        payload: ExecutionPayloadV1,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::NewPayload {
            version,
            payload,
            reply,
        })
    }

    /// Sync `engine_forkchoiceUpdated*`.
    pub fn forkchoice_updated_blocking(
        &self,
        version: ForkchoiceUpdatedVersion,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV1>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::ForkchoiceUpdated {
            version,
            state,
            attrs,
            reply,
        })
    }

    /// Sync `engine_getPayload*`.
    pub fn get_payload_blocking(
        &self,
        version: GetPayloadVersion,
        id: PayloadIdV1,
    ) -> Result<ExecutionPayloadV1, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetPayload { version, id, reply })
    }

    /// Sync `eth_chainId`.
    pub fn chain_id_blocking(&self) -> Result<u64, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::ChainId { reply })
    }

    /// Sync `eth_syncing`.
    pub fn syncing_blocking(&self) -> Result<SyncingStatus, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::Syncing { reply })
    }

    /// Sync `eth_getBlockByHash`.
    pub fn get_block_by_hash_blocking(
        &self,
        hash: String,
    ) -> Result<Option<crate::types::BlockHeader>, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetBlockByHash { hash, reply })
    }

    /// Async `engine_exchangeTransitionConfigurationV1`.
    ///
    /// Sends the CL's transition configuration to the EL and returns the EL's
    /// configuration.  Used by the keepalive task in `pharos-node`.
    pub async fn exchange_transition_configuration_async(
        &self,
        config: TransitionConfigurationV1,
    ) -> Result<TransitionConfigurationV1, EngineError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(EngineRequest::ExchangeTransitionConfiguration { config, reply })
            .await
            .map_err(|_| EngineError::UnexpectedResponse("engine actor dropped".into()))?;
        rx.await
            .map_err(|_| EngineError::UnexpectedResponse("engine actor dropped reply".into()))?
    }
}

// ── Actor loop + failover ────────────────────────────────────────────────────

/// Spawn the engine actor on `runtime` driving `primary` (with optional
/// `secondary` for hot failover). Returns the `EngineHandle` used by the
/// node and the STF.
pub fn spawn_engine_actor(
    runtime: Arc<Runtime>,
    primary: EngineClient,
    secondary: Option<EngineClient>,
) -> EngineHandle {
    let (tx, rx) = mpsc::channel(ENGINE_REQUEST_CAPACITY);
    let actor_runtime = runtime.clone();
    runtime.spawn(async move {
        run_engine_actor(actor_runtime, primary, secondary, rx).await;
    });
    EngineHandle::new(runtime, tx)
}

/// Run the engine actor: dispatch incoming requests to the active client and
/// flip to the secondary after `MAX_HEALTH_FAILURES` consecutive health-check
/// failures.
pub async fn run_engine_actor(
    runtime: Arc<Runtime>,
    primary: EngineClient,
    mut secondary: Option<EngineClient>,
    mut rx: mpsc::Receiver<EngineRequest>,
) {
    let active = Arc::new(primary);
    let failures = Arc::new(AtomicU8::new(0));
    let active_for_monitor = active.clone();
    let failures_for_monitor = failures.clone();

    let _monitor = runtime.spawn(async move {
        let mut ticker = tokio::time::interval(HEALTH_CHECK_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match active_for_monitor.syncing().await {
                Ok(_) => failures_for_monitor.store(0, Ordering::Relaxed),
                Err(e) => {
                    let prev = failures_for_monitor.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        target: "engine",
                        consecutive_failures = prev + 1,
                        error = %e,
                        endpoint = %active_for_monitor.endpoint(),
                        "engine health-check failed",
                    );
                }
            }
        }
    });

    let mut active = active;
    while let Some(req) = rx.recv().await {
        if failures.load(Ordering::Relaxed) >= MAX_HEALTH_FAILURES
            && let Some(sec) = secondary.take()
        {
            tracing::error!(
                target: "engine",
                from = %active.endpoint(),
                to = %sec.endpoint(),
                "engine primary unhealthy, failing over to secondary",
            );
            active = Arc::new(sec);
            failures.store(0, Ordering::Relaxed);
        }
        dispatch(&active, req).await;
    }
}

async fn dispatch(client: &EngineClient, req: EngineRequest) {
    match req {
        EngineRequest::NewPayload {
            version,
            payload,
            reply,
        } => {
            let _ = reply.send(client.new_payload(version, payload).await);
        }
        EngineRequest::ForkchoiceUpdated {
            version,
            state,
            attrs,
            reply,
        } => {
            let _ = reply.send(client.forkchoice_updated(version, state, attrs).await);
        }
        EngineRequest::GetPayload { version, id, reply } => {
            let _ = reply.send(client.get_payload(version, id).await);
        }
        EngineRequest::GetBlockByHash { hash, reply } => {
            let _ = reply.send(client.get_block_by_hash(&hash).await);
        }
        EngineRequest::ChainId { reply } => {
            let _ = reply.send(client.chain_id().await);
        }
        EngineRequest::Syncing { reply } => {
            let _ = reply.send(client.syncing().await);
        }
        EngineRequest::ExchangeTransitionConfiguration { config, reply } => {
            let _ = reply.send(client.exchange_transition_configuration(config).await);
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
    use serde::Deserialize;
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::*;
    use crate::jwt::JwtSecret;

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

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exchange_transition_configuration_async_dispatch() {
        let mock = spawn_mock().await;
        // The mock echoes back the same TTD/hash/number the caller sends.
        mock.set(
            "engine_exchangeTransitionConfigurationV1",
            json!({
                "terminalTotalDifficulty": "0x123",
                "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "terminalBlockNumber": "0x0",
            }),
        );

        let primary = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();

        // Wire actor directly on the current test tokio runtime to avoid
        // nesting a new runtime inside an async context (which panics on drop).
        let (tx, rx) = mpsc::channel(8);

        // Build two runtimes we need to supply but must not drop in async context.
        // `std::mem::forget` prevents the drop-in-async-context panic; this is
        // acceptable in tests (the OS reclaims memory at process exit).
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

        let config = TransitionConfigurationV1 {
            terminal_total_difficulty: "0x123".into(),
            terminal_block_hash:
                "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
            terminal_block_number: "0x0".into(),
        };
        let result = handle
            .exchange_transition_configuration_async(config)
            .await
            .expect("exchange_transition_configuration_async must succeed");
        assert_eq!(result.terminal_total_difficulty, "0x123");
        assert_eq!(result.terminal_block_number, "0x0");
    }
}
