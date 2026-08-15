//! Beacon API server: bind + serve via `axum::serve`.

use std::net::SocketAddr;
use std::sync::Arc;

use pharos_types::EthSpec;
use tracing::info;

use crate::router::build_router;
use crate::state::ApiState;

/// Bind `addr` and serve the Beacon API router.
///
/// This future runs indefinitely; `tokio::spawn` it in `main.rs`.
pub async fn serve<E: EthSpec>(addr: SocketAddr, state: Arc<ApiState<E>>) {
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("Beacon API: failed to bind {addr}: {e}"));
    info!(%addr, "Beacon API server listening");
    axum::serve(listener, router)
        .await
        .unwrap_or_else(|e| panic!("Beacon API server exited: {e}"));
}
