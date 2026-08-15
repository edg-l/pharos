//! Beacon API router: wires all Phase-1 and Phase-2 routes.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use pharos_types::EthSpec;

use crate::handlers::beacon_basic;
use crate::handlers::config as config_handlers;
use crate::handlers::node;
use crate::handlers::states;
use crate::state::ApiState;

/// Build the Beacon API router (Phase 1 + Phase 2).
///
/// Routes wired:
/// **Phase 1 — Tier-1 probes**
/// - `GET /eth/v1/node/identity`
/// - `GET /eth/v1/node/version`
/// - `GET /eth/v1/node/syncing`
/// - `GET /eth/v1/node/health`
/// - `GET /eth/v1/beacon/genesis`
/// - `GET /eth/v1/beacon/headers/head`
/// - `GET /eth/v1/config/spec`
///
/// **Phase 2 — State reads**
/// - `GET /eth/v1/beacon/states/{state_id}/root`
/// - `GET /eth/v1/beacon/states/{state_id}/fork`
/// - `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints`
/// - `GET /eth/v1/beacon/states/{state_id}/validators`
/// - `GET /eth/v1/beacon/states/{state_id}/validators/{validator_id}`
/// - `GET /eth/v1/beacon/states/{state_id}/validator_balances`
/// - `GET /eth/v1/beacon/states/{state_id}/committees`
/// - `GET /eth/v1/beacon/states/{state_id}/randao`
/// - `GET /eth/v1/beacon/states/{state_id}/sync_committees`
pub fn build_router<E: EthSpec>(state: Arc<ApiState<E>>) -> Router {
    Router::new()
        // Node namespace (Phase 1)
        .route("/eth/v1/node/identity", get(node::get_identity::<E>))
        .route("/eth/v1/node/version", get(node::get_version::<E>))
        .route("/eth/v1/node/syncing", get(node::get_syncing::<E>))
        .route("/eth/v1/node/health", get(node::get_health::<E>))
        // Beacon basic namespace (Phase 1; migrated to ApiResponse in Phase 2)
        .route(
            "/eth/v1/beacon/genesis",
            get(beacon_basic::get_genesis::<E>),
        )
        .route(
            "/eth/v1/beacon/headers/head",
            get(beacon_basic::get_head_header::<E>),
        )
        // Config namespace (Phase 1)
        .route("/eth/v1/config/spec", get(config_handlers::get_spec::<E>))
        // States namespace (Phase 2)
        .route(
            "/eth/v1/beacon/states/{state_id}/root",
            get(states::get_state_root::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/fork",
            get(states::get_state_fork::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            get(states::get_finality_checkpoints::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators",
            get(states::get_validators::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
            get(states::get_validator::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validator_balances",
            get(states::get_validator_balances::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/committees",
            get(states::get_committees::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/randao",
            get(states::get_randao::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/sync_committees",
            get(states::get_sync_committees::<E>),
        )
        .with_state(state)
}
