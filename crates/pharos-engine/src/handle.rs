//! Sync-callable engine handle and async actor.
//!
//! The STF runs on a `tokio::task::spawn_blocking` worker (M3a invariant) and
//! must reach the EL through an async HTTP client. We bridge the boundary
//! with an actor: `EngineHandle` sends typed requests over an mpsc channel
//! and blocks on a `oneshot::Receiver` via a dedicated multi-thread tokio
//! runtime. The actor task drives the underlying `EngineClient` and replies.
//!
//! ## Runtime ownership
//!
//! The engine runtime is *owned by a dedicated OS thread* (`spawn_engine_actor`
//! spawns it). That thread builds the `Runtime`, hands a cheap `Handle` to the
//! `EngineHandle`, runs the actor loop via `Runtime::block_on`, and only then
//! lets the `Runtime` drop — on that thread, in a *synchronous* context. This
//! is required: dropping a `tokio::runtime::Runtime` from inside an async
//! context (e.g. from a task running on that same runtime) panics with
//! "Cannot drop a runtime in a context where blocking is not allowed". The old
//! design captured an `Arc<Runtime>` inside the actor task itself, so the last
//! `Arc` ref dropped on an engine worker thread → panic on shutdown. Holding a
//! `Handle` (not the `Runtime`) in `EngineHandle` keeps `dispatch_blocking`
//! working from any thread while making the runtime impossible to drop in an
//! async context.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use tokio::runtime::{Builder, Handle};
use tokio::sync::{mpsc, oneshot};

use crate::client::{
    EngineClient, ForkchoiceUpdatedVersion, GetPayloadVersion, NewPayloadVersion, NewPayloadWire,
};
use crate::error::EngineError;
use crate::types::{
    BlobAndProofV1, ExecutionPayloadV1, ExecutionPayloadV2, ForkchoiceStateV1,
    ForkchoiceUpdatedV1Response, GetPayloadV2Response, GetPayloadV3Response, GetPayloadV4Response,
    PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, PayloadIdV1, PayloadStatusV1,
    SyncingStatus, TransitionConfigurationV1,
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
    /// `engine_newPayload*` — fork-discriminated via `NewPayloadWire`.
    NewPayload {
        version: NewPayloadVersion,
        // Boxed: `NewPayloadWire::V3` carries a full `ExecutionPayloadV3`, which
        // would otherwise make this the dominant `EngineRequest` variant
        // (clippy::large_enum_variant). Boxing keeps the channelled enum small.
        payload: Box<NewPayloadWire>,
        reply: oneshot::Sender<Result<PayloadStatusV1, EngineError>>,
    },
    /// `engine_forkchoiceUpdatedV1` — Bellatrix (no payload attributes on follow path).
    ForkchoiceUpdated {
        version: ForkchoiceUpdatedVersion,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV1>,
        reply: oneshot::Sender<Result<ForkchoiceUpdatedV1Response, EngineError>>,
    },
    /// `engine_forkchoiceUpdatedV2` — Capella (no payload attributes on follow path).
    ForkchoiceUpdatedV2 {
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV2>,
        reply: oneshot::Sender<Result<ForkchoiceUpdatedV1Response, EngineError>>,
    },
    /// `engine_getPayloadV1` — Bellatrix block production.
    GetPayload {
        version: GetPayloadVersion,
        id: PayloadIdV1,
        reply: oneshot::Sender<Result<ExecutionPayloadV1, EngineError>>,
    },
    /// `engine_getPayloadV2` — Capella block production. Returns `{executionPayload, blockValue}`.
    GetPayloadV2 {
        id: PayloadIdV1,
        reply: oneshot::Sender<Result<GetPayloadV2Response, EngineError>>,
    },
    /// `engine_forkchoiceUpdatedV3` — Deneb (optional V3 payload attributes).
    ForkchoiceUpdatedV3 {
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV3>,
        reply: oneshot::Sender<Result<ForkchoiceUpdatedV1Response, EngineError>>,
    },
    /// `engine_getPayloadV3` — Deneb block production.
    /// Returns `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder}`.
    GetPayloadV3 {
        id: PayloadIdV1,
        reply: oneshot::Sender<Result<GetPayloadV3Response, EngineError>>,
    },
    /// `engine_getPayloadV4` — Electra / Prague block production.
    /// Returns `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder, executionRequests}`.
    GetPayloadV4 {
        id: PayloadIdV1,
        reply: oneshot::Sender<Result<GetPayloadV4Response, EngineError>>,
    },
    /// `engine_getBlobsV1` — retrieve blobs from the local EL blob pool.
    GetBlobsV1 {
        versioned_hashes: Vec<String>,
        reply: oneshot::Sender<Result<Vec<Option<BlobAndProofV1>>, EngineError>>,
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
    /// Handle to the engine runtime. A `Handle` is a cheap, cloneable, NON-owning
    /// reference; dropping it never tears down the runtime, so it can be dropped
    /// from any context (including an async one) without panicking. The owning
    /// `Runtime` lives on the dedicated thread spawned by `spawn_engine_actor`.
    runtime: Handle,
    /// Liveness flag for the EL endpoint, observed from every blocking engine
    /// call. `true` while the last call reached the EL (any JSON-RPC reply,
    /// including SYNCING); set `false` on a transport/timeout error. Backs the
    /// `el_offline` field of `/eth/v1/node/syncing`.
    el_online: Arc<AtomicBool>,
}

impl EngineHandle {
    /// Wrap an existing actor channel + runtime `Handle`. `spawn_engine_actor`
    /// below is the usual entry point and owns the runtime correctly.
    pub fn new(runtime: Handle, tx: mpsc::Sender<EngineRequest>) -> Self {
        Self {
            runtime,
            tx,
            el_online: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Whether the EL endpoint is currently believed unreachable, based on the
    /// most recent blocking engine round-trip. Backs `/eth/v1/node/syncing`'s
    /// `el_offline`. A transport or timeout error flips this to `true`; any
    /// reply from the EL (even SYNCING) flips it back to `false`.
    pub fn el_offline(&self) -> bool {
        !self.el_online.load(Ordering::Acquire)
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
        let result = self
            .runtime
            .block_on(reply_rx)
            .map_err(|_| EngineError::UnexpectedResponse("engine actor dropped reply".into()))?;
        // Observe EL liveness: a transport/timeout error means the endpoint is
        // unreachable; any other outcome (including a JSON-RPC error reply or a
        // SYNCING status) proves the EL answered.
        let online = !matches!(
            result,
            Err(EngineError::Transport(_) | EngineError::Timeout)
        );
        self.el_online.store(online, Ordering::Release);
        result
    }

    /// Sync `engine_newPayloadV1` — Bellatrix.
    pub fn new_payload_v1_blocking(
        &self,
        payload: ExecutionPayloadV1,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::NewPayload {
            version: NewPayloadVersion::V1,
            payload: Box::new(NewPayloadWire::V1(payload)),
            reply,
        })
    }

    /// Sync `engine_newPayloadV2` — Capella (with withdrawals).
    pub fn new_payload_v2_blocking(
        &self,
        payload: ExecutionPayloadV2,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::NewPayload {
            version: NewPayloadVersion::V2,
            payload: Box::new(NewPayloadWire::V2(payload)),
            reply,
        })
    }

    /// Sync `engine_newPayload*` dispatch — fork-discriminated.
    pub fn new_payload_blocking(
        &self,
        version: NewPayloadVersion,
        payload: NewPayloadWire,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::NewPayload {
            version,
            payload: Box::new(payload),
            reply,
        })
    }

    /// Sync `engine_forkchoiceUpdatedV1` — Bellatrix.
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

    /// Sync `engine_forkchoiceUpdatedV2` — Capella (optional V2 payload attributes).
    pub fn forkchoice_updated_v2_blocking(
        &self,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV2>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::ForkchoiceUpdatedV2 {
            state,
            attrs,
            reply,
        })
    }

    /// Sync `engine_getPayloadV1` — Bellatrix block production.
    pub fn get_payload_blocking(
        &self,
        version: GetPayloadVersion,
        id: PayloadIdV1,
    ) -> Result<ExecutionPayloadV1, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetPayload { version, id, reply })
    }

    /// Sync `engine_getPayloadV2` — Capella block production.
    ///
    /// Returns `{executionPayload, blockValue}` per shanghai.md.
    pub fn get_payload_v2_blocking(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV2Response, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetPayloadV2 { id, reply })
    }

    /// Sync `engine_forkchoiceUpdatedV3` — Deneb (optional V3 payload attributes).
    pub fn forkchoice_updated_v3_blocking(
        &self,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV3>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::ForkchoiceUpdatedV3 {
            state,
            attrs,
            reply,
        })
    }

    /// Sync `engine_getPayloadV3` — Deneb block production.
    ///
    /// Returns `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder}`
    /// per cancun.md.
    pub fn get_payload_v3_blocking(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV3Response, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetPayloadV3 { id, reply })
    }

    /// Sync `engine_getPayloadV4` — Electra / Prague block production.
    ///
    /// Returns `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder, executionRequests}`
    /// per prague.md.
    pub fn get_payload_v4_blocking(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV4Response, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetPayloadV4 { id, reply })
    }

    /// Sync `engine_getBlobsV1` — retrieve blobs from the local EL blob pool.
    ///
    /// Returns a `Vec<Option<BlobAndProofV1>>` preserving the request order.
    /// Missing blobs are represented as `None` per cancun.md.
    pub fn get_blobs_v1_blocking(
        &self,
        versioned_hashes: Vec<String>,
    ) -> Result<Vec<Option<BlobAndProofV1>>, EngineError> {
        self.dispatch_blocking(|reply| EngineRequest::GetBlobsV1 {
            versioned_hashes,
            reply,
        })
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

/// Spawn the engine actor on a freshly built multi-thread runtime owned by a
/// dedicated OS thread, driving `primary` (with optional `secondary` for hot
/// failover). Returns the `EngineHandle` used by the node and the STF.
///
/// The dedicated thread builds the `Runtime`, runs the actor loop to completion
/// via `Runtime::block_on`, and drops the `Runtime` *on that thread in a sync
/// context*. This is the only correct place to drop it: dropping a `Runtime`
/// from within an async context panics. See the module-level docs.
///
/// The returned `EngineHandle` holds only a `Handle` (non-owning), so all of
/// its clones — and the actor task itself — can be dropped from any context
/// without tearing down or panicking the runtime.
pub fn spawn_engine_actor(primary: EngineClient, secondary: Option<EngineClient>) -> EngineHandle {
    let (tx, rx) = mpsc::channel(ENGINE_REQUEST_CAPACITY);
    // Hand the runtime `Handle` back out of the spawned thread via a oneshot.
    let (handle_tx, handle_rx) = std::sync::mpsc::channel::<Handle>();

    std::thread::Builder::new()
        .name("pharos-engine".into())
        .spawn(move || {
            let runtime = Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("pharos-engine-worker")
                .enable_all()
                .build()
                .expect("building engine tokio runtime");
            // Publish the Handle so `spawn_engine_actor` can return the
            // EngineHandle. If the receiver is gone the node is already
            // shutting down; nothing to do.
            let handle = runtime.handle().clone();
            if handle_tx.send(handle.clone()).is_err() {
                return;
            }
            // Run the actor loop to completion. When every `EngineRequest`
            // sender (every EngineHandle clone) drops, `rx.recv()` yields
            // `None`, the loop ends, `block_on` returns, and `runtime` drops
            // HERE — on this OS thread, outside any async context. No panic.
            runtime.block_on(run_engine_actor(handle, primary, secondary, rx));
        })
        .expect("spawning engine runtime thread");

    let runtime = handle_rx
        .recv()
        .expect("engine runtime thread failed to start");
    EngineHandle::new(runtime, tx)
}

/// Run the engine actor: dispatch incoming requests to the active client and
/// flip to the secondary after `MAX_HEALTH_FAILURES` consecutive health-check
/// failures.
pub async fn run_engine_actor(
    runtime: Handle,
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
            let _ = reply.send(client.new_payload(version, *payload).await);
        }
        EngineRequest::ForkchoiceUpdated {
            version,
            state,
            attrs,
            reply,
        } => {
            let _ = reply.send(client.forkchoice_updated(version, state, attrs).await);
        }
        EngineRequest::ForkchoiceUpdatedV2 {
            state,
            attrs,
            reply,
        } => {
            let _ = reply.send(client.forkchoice_updated_v2(state, attrs).await);
        }
        EngineRequest::GetPayload { version, id, reply } => {
            let _ = reply.send(client.get_payload(version, id).await);
        }
        EngineRequest::GetPayloadV2 { id, reply } => {
            let _ = reply.send(client.get_payload_v2(id).await);
        }
        EngineRequest::ForkchoiceUpdatedV3 {
            state,
            attrs,
            reply,
        } => {
            let _ = reply.send(client.forkchoice_updated_v3(state, attrs).await);
        }
        EngineRequest::GetPayloadV3 { id, reply } => {
            let _ = reply.send(client.get_payload_v3(id).await);
        }
        EngineRequest::GetPayloadV4 { id, reply } => {
            let _ = reply.send(client.get_payload_v4(id).await);
        }
        EngineRequest::GetBlobsV1 {
            versioned_hashes,
            reply,
        } => {
            let _ = reply.send(client.get_blobs_v1(versioned_hashes).await);
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

        // Mirror production: own the engine runtime on a dedicated OS thread so
        // it drops in a sync context. The `EngineHandle` holds only a `Handle`.
        let handle = spawn_engine_actor(primary, None);

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
