//! Oracle for Phase 18: `/health` probe on the metrics port.
//!
//! Verifies that the combined metrics + health HTTP server returns:
//! - HTTP 200 when the sync-state probe reports [`SyncState::Synced`].
//! - HTTP 503 when the probe reports [`SyncState::Syncing`].
//!
//! The two cases run as two independent HTTP servers, each on its own
//! ephemeral port, backed by the binary-wide recorder handle from `common` but
//! with different sync-state probes.
//!
//! Per `D-health-probe-on-metrics-port` (M11 Phase 18).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use pharos_utils::metrics::SyncState;

/// Bind a free ephemeral port, immediately release it, and return its number.
fn free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// Spin up the metrics+health axum server on `port` with `probe`, wait for it
/// to bind, and return the base URL.
async fn start_server(port: u16, probe: Arc<dyn Fn() -> SyncState + Send + Sync>) -> String {
    let handle = crate::common::metrics_handle().clone();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    // Spawn the server.
    tokio::spawn(async move {
        let app = pharos_utils::metrics::build_router_for_test(handle, Some(probe));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind test server");
        axum::serve(listener, app).await.ok();
    });

    // Give the server a moment to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;
    format!("http://{}:{}", Ipv4Addr::LOCALHOST, port)
}

#[tokio::test]
async fn health_probe_returns_503_when_syncing() {
    let port = free_port();
    let probe: Arc<dyn Fn() -> SyncState + Send + Sync> = Arc::new(|| SyncState::Syncing);
    let base = start_server(port, probe).await;

    let resp = reqwest::get(format!("{base}/health"))
        .await
        .expect("GET /health failed");

    assert_eq!(resp.status(), 503, "/health should return 503 when syncing");
}

#[tokio::test]
async fn health_probe_returns_200_when_synced() {
    let port = free_port();
    let probe: Arc<dyn Fn() -> SyncState + Send + Sync> = Arc::new(|| SyncState::Synced);
    let base = start_server(port, probe).await;

    let resp = reqwest::get(format!("{base}/health"))
        .await
        .expect("GET /health failed");

    assert_eq!(resp.status(), 200, "/health should return 200 when synced");
}
