//! Prometheus metrics registry initialisation.
//!
//! Call [`init_metrics`] once at startup (when `--metrics` is set) to install
//! the global `metrics` recorder and start the Prometheus HTTP exporter on the
//! configured address.  Metric-name constants and `describe_*` declarations for
//! every metric in the roadmap list live here; Phase 6 wires the actual emission
//! call sites.
//!
//! # Histogram bucket set
//!
//! The roadmap specifies `[0.5, 1, 5, 25, 100, 500, 2500] ms`.  Since the
//! `metrics` crate records values as `f64` seconds, those translate to:
//! `[0.0005, 0.001, 0.005, 0.025, 0.1, 0.5, 2.5]` seconds.  Call sites should
//! use `duration.as_secs_f64()` to emit values in seconds.

use std::net::SocketAddr;

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

// ── Registry init ─────────────────────────────────────────────────────────────

/// Install the global Prometheus recorder and start the HTTP exporter on
/// `addr` (the `/metrics` path is served automatically by the exporter).
///
/// Must be called from within a Tokio runtime; `install()` internally calls
/// `tokio::spawn` to drive the HTTP listener when a runtime is active.
///
/// # Errors
///
/// Returns [`BuildError`] if the recorder is already installed, the address
/// cannot be bound, or the bucket configuration is invalid.
pub fn init_metrics(addr: SocketAddr) -> Result<(), BuildError> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets(LATENCY_BUCKETS)?
        .install()?;

    describe_metrics();
    register_metrics();
    Ok(())
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
}
