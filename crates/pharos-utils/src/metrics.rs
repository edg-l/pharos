//! Prometheus metrics registry initialisation.
//!
//! Call [`init_metrics`] once at startup (when `--metrics` is set) to install
//! the global `metrics` recorder and start the Prometheus HTTP exporter on the
//! configured address.  Metric-name constants and `describe_*` declarations for
//! every metric live here; the call sites that emit them live with the code
//! they measure.
//!
//! The HTTP server serves two routes on the same port:
//! - `GET /metrics` — Prometheus text format.
//! - `GET /health`  — 200 when [`SyncState::Synced`], 503 otherwise.
//!
//! # Histogram bucket set
//!
//! The roadmap specifies `[0.5, 1, 5, 25, 100, 500, 2500] ms`.  Since the
//! `metrics` crate records values as `f64` seconds, those translate to:
//! `[0.0005, 0.001, 0.005, 0.025, 0.1, 0.5, 2.5]` seconds.  Call sites should
//! use `duration.as_secs_f64()` to emit values in seconds.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use metrics_exporter_prometheus::PrometheusBuilder;
pub use metrics_exporter_prometheus::{BuildError, PrometheusHandle};

// ── Histogram bucket set (roadmap § Metrics layer) ───────────────────────────
// [0.5, 1, 5, 25, 100, 500, 2500] ms expressed in seconds.
const LATENCY_BUCKETS: &[f64] = &[0.0005, 0.001, 0.005, 0.025, 0.1, 0.5, 2.5];

// ── Metric-name constants ─────────────────────────────────────────────────────

/// Gossip message counter (label: `topic`).
pub const METRIC_GOSSIP_MSG_TOTAL: &str = "pharos_gossip_messages_total";

/// Req-resp method latency histogram (label: `method`).
pub const METRIC_RPC_LATENCY_SECONDS: &str = "pharos_rpc_latency_seconds";

/// Peer score distribution gauge (label: `bucket`).
pub const METRIC_PEER_SCORE: &str = "pharos_peer_score";

/// STF `process_block` duration histogram.
pub const METRIC_STF_PROCESS_BLOCK_SECONDS: &str = "pharos_stf_process_block_seconds";

/// STF `process_epoch` duration histogram.
pub const METRIC_STF_PROCESS_EPOCH_SECONDS: &str = "pharos_stf_process_epoch_seconds";

/// Fork-choice `get_head` duration histogram.
pub const METRIC_FORK_CHOICE_GET_HEAD_SECONDS: &str = "pharos_fork_choice_get_head_seconds";

/// Engine API call latency histogram (label: `method`).
pub const METRIC_ENGINE_CALL_LATENCY_SECONDS: &str = "pharos_engine_call_latency_seconds";

/// Slasher detection counter (label: `kind` = `double_vote` | `surround_vote`).
pub const METRIC_SLASHER_DETECTIONS_TOTAL: &str = "pharos_slasher_detections_total";

// ── Sync state ────────────────────────────────────────────────────────────────

/// Node sync state reported by the `/health` probe on the metrics port.
///
/// `Synced` → HTTP 200; `Syncing` → HTTP 503.  The same source as
/// `/eth/v1/node/health` is used (fork-choice head vs wall-clock + optimistic
/// flag); the probe is threaded from `pharos-node` via [`init_metrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Node is fully synced and not optimistic.
    Synced,
    /// Node is syncing, optimistic, or not yet initialised.
    Syncing,
}

// ── Registry init ─────────────────────────────────────────────────────────────

/// Install the global Prometheus recorder and start a two-route HTTP server on
/// `addr` serving:
/// - `GET /metrics` — Prometheus text output.
/// - `GET /health`  — 200 when `probe()` returns [`SyncState::Synced`], 503
///   otherwise.
///
/// `probe` is an optional sync-state callback threaded from the node.  Pass
/// `None` to serve `/health` as 503 unconditionally (useful in contexts where
/// the sync state is unavailable, e.g. test harnesses that only exercise
/// `/metrics`).
///
/// Must be called from within a Tokio runtime; the HTTP listener is spawned as
/// a background task.
///
/// # Errors
///
/// Returns [`BuildError`] if the recorder is already installed or the bucket
/// configuration is invalid.  Bind errors surface asynchronously (the spawned
/// task will log and exit).
pub fn init_metrics(
    addr: SocketAddr,
    probe: Option<Arc<dyn Fn() -> SyncState + Send + Sync>>,
) -> Result<(), BuildError> {
    let handle = PrometheusBuilder::new()
        .set_buckets(LATENCY_BUCKETS)?
        .install_recorder()?;

    describe_metrics();
    register_metrics();

    // Spawn a small axum server on the metrics port serving /metrics and /health.
    tokio::spawn(async move {
        let app = build_router(handle, probe);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| {
                panic!("metrics server: failed to bind {addr}: {e}");
            });
        axum::serve(listener, app).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "metrics HTTP server exited");
        });
    });

    Ok(())
}

/// Build the axum router serving `/metrics` and `/health`.
///
/// Exposed publicly so integration tests can spin up the server directly with
/// a `PrometheusHandle` obtained from [`init_metrics_with_handle`], without
/// calling [`init_metrics`] (which installs the global recorder and can only
/// succeed once per process).
pub fn build_router_for_test(
    handle: PrometheusHandle,
    probe: Option<Arc<dyn Fn() -> SyncState + Send + Sync>>,
) -> axum::Router {
    build_router(handle, probe)
}

/// Internal router builder.
fn build_router(
    handle: PrometheusHandle,
    probe: Option<Arc<dyn Fn() -> SyncState + Send + Sync>>,
) -> axum::Router {
    let handle = Arc::new(handle);

    let metrics_handle = Arc::clone(&handle);
    let metrics_route = get(move || {
        let h = Arc::clone(&metrics_handle);
        async move { h.render() }
    });

    let health_route = get(move || {
        let p = probe.clone();
        async move {
            let synced = p.as_ref().is_some_and(|f| f() == SyncState::Synced);
            if synced {
                StatusCode::OK.into_response()
            } else {
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    });

    axum::Router::new()
        .route("/metrics", metrics_route)
        .route("/health", health_route)
}

/// Install the global Prometheus recorder without binding an HTTP listener.
///
/// Returns a [`PrometheusHandle`] that can be used in tests to call
/// [`PrometheusHandle::render`] and inspect metric values without needing a
/// running HTTP server.
///
/// # Errors
///
/// Returns [`BuildError`] if the recorder is already installed or the bucket
/// configuration is invalid.
pub fn init_metrics_with_handle() -> Result<PrometheusHandle, BuildError> {
    let handle = PrometheusBuilder::new()
        .set_buckets(LATENCY_BUCKETS)?
        .install_recorder()?;

    describe_metrics();
    register_metrics();
    Ok(handle)
}

/// Register human-readable descriptions for every declared metric.
///
/// This function is called once by [`init_metrics`]; it may also be called in
/// tests that install the recorder without a listening address.
pub fn describe_metrics() {
    use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};

    describe_counter!(
        METRIC_GOSSIP_MSG_TOTAL,
        Unit::Count,
        "Number of gossip messages received, by topic"
    );
    describe_histogram!(
        METRIC_RPC_LATENCY_SECONDS,
        Unit::Seconds,
        "Req-resp method latency in seconds, by method"
    );
    describe_gauge!(
        METRIC_PEER_SCORE,
        Unit::Count,
        "Peer score distribution by bucket"
    );
    describe_histogram!(
        METRIC_STF_PROCESS_BLOCK_SECONDS,
        Unit::Seconds,
        "STF process_block duration in seconds"
    );
    describe_histogram!(
        METRIC_STF_PROCESS_EPOCH_SECONDS,
        Unit::Seconds,
        "STF process_epoch duration in seconds"
    );
    describe_histogram!(
        METRIC_FORK_CHOICE_GET_HEAD_SECONDS,
        Unit::Seconds,
        "Fork-choice get_head duration in seconds"
    );
    describe_histogram!(
        METRIC_ENGINE_CALL_LATENCY_SECONDS,
        Unit::Seconds,
        "Engine API call latency in seconds, by method"
    );
    describe_counter!(
        METRIC_SLASHER_DETECTIONS_TOTAL,
        Unit::Count,
        "Number of slashings detected, by kind (double_vote, surround_vote, or proposer_double_block)"
    );
}

/// Force each declared metric to appear in Prometheus output by recording an
/// initial zero-value observation.
///
/// The Prometheus exporter only emits `# HELP` / `# TYPE` lines for metrics
/// that have at least one registered value in the current snapshot; calling
/// `describe_*` alone is not sufficient.  This function is called once by
/// [`init_metrics`] immediately after [`describe_metrics`].
pub fn register_metrics() {
    use metrics::{counter, gauge, histogram};

    counter!(METRIC_GOSSIP_MSG_TOTAL).absolute(0);
    histogram!(METRIC_RPC_LATENCY_SECONDS).record(0.0);
    gauge!(METRIC_PEER_SCORE).set(0.0);
    histogram!(METRIC_STF_PROCESS_BLOCK_SECONDS).record(0.0);
    histogram!(METRIC_STF_PROCESS_EPOCH_SECONDS).record(0.0);
    histogram!(METRIC_FORK_CHOICE_GET_HEAD_SECONDS).record(0.0);
    histogram!(METRIC_ENGINE_CALL_LATENCY_SECONDS).record(0.0);
    counter!(METRIC_SLASHER_DETECTIONS_TOTAL).absolute(0);
}
