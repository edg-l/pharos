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
    PayloadIdV1, PayloadStatusV1, SyncingStatus,
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
    }
}
