//! Smoke test for [`pharos_utils::metrics::init_metrics`].
//!
//! Binds an ephemeral port, installs the Prometheus recorder, and asserts that
//! `GET /metrics` returns HTTP 200 with the expected `# HELP` lines for the
//! STF and req-resp metrics declared in `pharos_utils::metrics`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use pharos_utils::metrics::{
    METRIC_ENGINE_CALL_LATENCY_SECONDS, METRIC_FORK_CHOICE_GET_HEAD_SECONDS,
    METRIC_GOSSIP_MSG_TOTAL, METRIC_RPC_LATENCY_SECONDS, METRIC_STF_PROCESS_BLOCK_SECONDS,
    METRIC_STF_PROCESS_EPOCH_SECONDS,
};

/// Pick a free port by binding and immediately releasing a `TcpListener`.
fn free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

#[tokio::test]
async fn metrics_init_serves_help_lines() {
    let port = free_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    pharos_utils::metrics::init_metrics(addr)
        .expect("init_metrics should succeed on a fresh process");

    // Give the Prometheus HTTP server a moment to bind and start accepting.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let url = format!("http://{}:{}/metrics", Ipv4Addr::LOCALHOST, port);
    let resp = reqwest::get(&url).await.expect("HTTP GET /metrics failed");

    assert_eq!(resp.status(), 200, "/metrics should return HTTP 200");

    let body = resp.text().await.expect("reading /metrics body");

    // Assert that all declared metric names appear as `# HELP` lines.
    let expected_metrics = [
        METRIC_GOSSIP_MSG_TOTAL,
        METRIC_RPC_LATENCY_SECONDS,
        METRIC_STF_PROCESS_BLOCK_SECONDS,
        METRIC_STF_PROCESS_EPOCH_SECONDS,
        METRIC_FORK_CHOICE_GET_HEAD_SECONDS,
        METRIC_ENGINE_CALL_LATENCY_SECONDS,
    ];

    for name in expected_metrics {
        let help_line = format!("# HELP {name}");
        assert!(
            body.contains(&help_line),
            "/metrics body missing expected help line: {help_line}\nbody:\n{body}",
        );
    }
}
