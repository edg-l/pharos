//! Beacon API router: wires all Phase-1 through Phase-5 routes.

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use pharos_types::EthSpec;

use crate::auth::validator_auth_layer;
use crate::handlers::beacon_basic;
use crate::handlers::blocks as blocks_handlers;
use crate::handlers::config as config_handlers;
use crate::handlers::config_extra;
use crate::handlers::debug as debug_handlers;
use crate::handlers::events as events_handlers;
use crate::handlers::node;
use crate::handlers::states;
use crate::handlers::validator_duties;
use crate::state::ApiState;

/// Build the Beacon API router (Phase 1 through Phase 5).
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
///
/// **Phase 3 — Blocks, headers, fork-tagging, config extras**
/// - `GET /eth/v1/beacon/blocks/{block_id}/root`
/// - `GET /eth/v1/beacon/headers`
/// - `GET /eth/v1/beacon/headers/{block_id}`
/// - `GET /eth/v2/beacon/blocks/{block_id}`
/// - `GET /eth/v2/beacon/blocks/{block_id}/attestations`
/// - `GET /eth/v1/config/fork_schedule`
/// - `GET /eth/v1/config/deposit_contract`
///
/// **Phase 4 — SSE event stream**
/// - `GET /eth/v1/events`
///
/// **Phase 5 — Validator-read endpoints + debug namespace**
/// - `GET  /eth/v1/validator/duties/proposer/{epoch}`   (auth-gated)
/// - `POST /eth/v1/validator/duties/attester/{epoch}`   (auth-gated)
/// - `POST /eth/v1/validator/duties/sync/{epoch}`       (auth-gated)
/// - `GET  /eth/v1/debug/fork_choice`
/// - `GET  /eth/v2/debug/beacon/heads`
/// - `GET  /eth/v2/debug/beacon/states/{state_id}`
///
/// The validator sub-router has `validator_auth_layer` applied; `None` means
/// no auth (default).  The debug routes are unauthenticated.
pub fn build_router<E: EthSpec>(state: Arc<ApiState<E>>) -> Router {
    build_router_with_auth::<E>(state, None)
}

/// Build the router with an optional validator-API bearer token.
///
/// When `validator_token` is `Some(t)`, requests to `/eth/v1/validator/*`
/// must carry `Authorization: Bearer <t>`; missing/wrong token → 401/403.
/// When `None`, the validator routes are unauthenticated (default).
pub fn build_router_with_auth<E: EthSpec>(
    state: Arc<ApiState<E>>,
    validator_token: Option<String>,
) -> Router {
    // ── Validator sub-router (auth-gated) ─────────────────────────────────
    let validator_router = Router::new()
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(validator_duties::get_proposer_duties::<E>),
        )
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            post(validator_duties::post_attester_duties::<E>),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            post(validator_duties::post_sync_duties::<E>),
        )
        .layer(validator_auth_layer(validator_token))
        .with_state(Arc::clone(&state));

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
        // Blocks namespace (Phase 3)
        .route(
            "/eth/v1/beacon/blocks/{block_id}/root",
            get(blocks_handlers::get_block_root::<E>),
        )
        .route(
            "/eth/v1/beacon/headers",
            get(blocks_handlers::get_headers::<E>),
        )
        .route(
            "/eth/v1/beacon/headers/{block_id}",
            get(blocks_handlers::get_header::<E>),
        )
        .route(
            "/eth/v2/beacon/blocks/{block_id}",
            get(blocks_handlers::get_block_v2::<E>),
        )
        .route(
            "/eth/v2/beacon/blocks/{block_id}/attestations",
            get(blocks_handlers::get_block_attestations_v2::<E>),
        )
        // Config extras (Phase 3)
        .route(
            "/eth/v1/config/fork_schedule",
            get(config_extra::get_fork_schedule::<E>),
        )
        .route(
            "/eth/v1/config/deposit_contract",
            get(config_extra::get_deposit_contract::<E>),
        )
        // SSE event stream (Phase 4)
        .route("/eth/v1/events", get(events_handlers::get_events::<E>))
        // Debug namespace (Phase 5)
        .route(
            "/eth/v1/debug/fork_choice",
            get(debug_handlers::get_fork_choice::<E>),
        )
        .route(
            "/eth/v2/debug/beacon/heads",
            get(debug_handlers::get_beacon_heads::<E>),
        )
        .route(
            "/eth/v2/debug/beacon/states/{state_id}",
            get(debug_handlers::get_debug_state::<E>),
        )
        .with_state(Arc::clone(&state))
        // Merge validator sub-router (has its own auth layer + state)
        .merge(validator_router)
}
