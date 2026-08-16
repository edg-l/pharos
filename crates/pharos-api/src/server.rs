//! Beacon API server: bind + serve via `axum::serve`.

use std::net::SocketAddr;
use std::sync::Arc;

use pharos_types::BeaconSpec;
use tracing::info;

use crate::router::{build_router, build_router_with_auth};
use crate::state::ApiState;

/// Bind `addr` and serve the Beacon API router (no validator-API auth).
///
/// This future runs indefinitely; `tokio::spawn` it in `main.rs`.
pub async fn serve<E: BeaconSpec>(addr: SocketAddr, state: Arc<ApiState<E>>) {
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("Beacon API: failed to bind {addr}: {e}"));
    info!(%addr, "Beacon API server listening");
    axum::serve(listener, router)
        .await
        .unwrap_or_else(|e| panic!("Beacon API server exited: {e}"));
}

/// Bind `addr` and serve the Beacon API router with an optional validator-API token.
///
/// When `validator_token` is `Some(t)`, requests to `/eth/v1/validator/*` require
/// `Authorization: Bearer <t>`.  When `None`, no auth is applied.
pub async fn serve_with_auth<E: BeaconSpec>(
    addr: SocketAddr,
    state: Arc<ApiState<E>>,
    validator_token: Option<String>,
) {
    let router = build_router_with_auth(state, validator_token);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("Beacon API: failed to bind {addr}: {e}"));
    info!(%addr, "Beacon API server listening");
    axum::serve(listener, router)
        .await
        .unwrap_or_else(|e| panic!("Beacon API server exited: {e}"));
}
