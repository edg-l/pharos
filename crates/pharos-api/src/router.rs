//! Beacon API router: wires all Phase-1 routes into an `axum::Router`.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use pharos_types::EthSpec;

use crate::handlers::beacon_basic;
use crate::handlers::config as config_handlers;
use crate::handlers::node;
use crate::state::ApiState;

/// Build the Beacon API router for Phase 1.
///
/// Routes wired:
/// - `GET /eth/v1/node/identity`
/// - `GET /eth/v1/node/version`
/// - `GET /eth/v1/node/syncing`
/// - `GET /eth/v1/node/health`
/// - `GET /eth/v1/beacon/genesis`
/// - `GET /eth/v1/beacon/headers/head`
/// - `GET /eth/v1/config/spec`
pub fn build_router<E: EthSpec>(state: Arc<ApiState<E>>) -> Router {
    Router::new()
        // Node namespace
        .route("/eth/v1/node/identity", get(node::get_identity::<E>))
        .route("/eth/v1/node/version", get(node::get_version::<E>))
        .route("/eth/v1/node/syncing", get(node::get_syncing::<E>))
        .route("/eth/v1/node/health", get(node::get_health::<E>))
        // Beacon namespace
        .route(
            "/eth/v1/beacon/genesis",
            get(beacon_basic::get_genesis::<E>),
        )
        .route(
            "/eth/v1/beacon/headers/head",
            get(beacon_basic::get_head_header::<E>),
        )
        // Config namespace
        .route("/eth/v1/config/spec", get(config_handlers::get_spec::<E>))
        .with_state(state)
}
