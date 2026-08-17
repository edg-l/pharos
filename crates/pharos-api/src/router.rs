//! Beacon API router: wires all Phase-1 through M9-Phase-5 routes.

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use pharos_types::BeaconSpec;

use crate::auth::validator_auth_layer;
use crate::handlers::beacon_basic;
use crate::handlers::beacon_blocks_publish;
use crate::handlers::beacon_pool;
use crate::handlers::blocks as blocks_handlers;
use crate::handlers::config as config_handlers;
use crate::handlers::config_extra;
use crate::handlers::debug as debug_handlers;
use crate::handlers::events as events_handlers;
use crate::handlers::light_client as lc_handlers;
use crate::handlers::node;
use crate::handlers::states;
use crate::handlers::sync_committee as sync_committee_handlers;
use crate::handlers::validator_duties;
use crate::handlers::validator_liveness;
use crate::handlers::validator_production;
use crate::state::ApiState;

/// Build the Beacon API router (Phase 1 through M9-Phase-5).
///
/// Routes wired:
/// **Phase 1 — Tier-1 probes**
/// - `GET /eth/v1/node/identity`
/// - `GET /eth/v1/node/version`
/// - `GET /eth/v2/node/version`
/// - `GET /eth/v1/node/syncing`
/// - `GET /eth/v1/node/health`
/// - `GET /eth/v1/node/peers`
/// - `GET /eth/v1/node/peer_count`
/// - `GET /eth/v1/node/peers/{peer_id}`
/// - `GET /eth/v1/beacon/genesis`
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
/// - `GET  /eth/v2/validator/duties/proposer/{epoch}`   (auth-gated)
/// - `POST /eth/v1/validator/duties/attester/{epoch}`   (auth-gated)
/// - `POST /eth/v1/validator/duties/sync/{epoch}`       (auth-gated)
/// - `GET  /eth/v1/debug/fork_choice`
/// - `GET  /eth/v2/debug/beacon/heads`
/// - `GET  /eth/v2/debug/beacon/states/{state_id}`
///
/// **M9 Phase 5 — Validator production + beacon pool + publish**
/// - `GET  /eth/v3/validator/blocks/{slot}`             (auth-gated)
/// - `GET  /eth/v1/validator/attestation_data`          (auth-gated)
/// - `GET  /eth/v2/validator/aggregate_attestation`     (auth-gated)
/// - `POST /eth/v2/validator/aggregate_and_proofs`      (auth-gated)
/// - `POST /eth/v1/validator/prepare_beacon_proposer`   (auth-gated)
/// - `POST /eth/v1/validator/register_validator`        (auth-gated)
/// - `POST /eth/v1/validator/beacon_committee_subscriptions`   (auth-gated)
/// - `POST /eth/v1/validator/sync_committee_subscriptions`     (auth-gated)
/// - `GET  /eth/v1/validator/sync_committee_contribution`      (auth-gated)
/// - `POST /eth/v1/validator/contribution_and_proofs`          (auth-gated)
/// - `POST /eth/v1/validator/beacon_committee_selections`      (auth-gated)
/// - `POST /eth/v1/validator/sync_committee_selections`        (auth-gated)
/// - `POST /eth/v1/validator/liveness/{epoch}`                 (auth-gated)
/// - `POST /eth/v1/beacon/blocks`                    (public)
/// - `POST /eth/v2/beacon/blocks`                    (public)
/// - `GET  /eth/v1/beacon/pool/attestations`         (public)
/// - `POST /eth/v1/beacon/pool/attestations`         (public)
/// - `GET  /eth/v2/beacon/pool/attestations`         (public, M15 Phase 3)
/// - `POST /eth/v2/beacon/pool/attestations`         (public, M15 Phase 3)
/// - `GET  /eth/v1/beacon/pool/attester_slashings`   (public)
/// - `POST /eth/v1/beacon/pool/attester_slashings`   (public)
/// - `GET  /eth/v2/beacon/pool/attester_slashings`   (public, M15 Phase 3)
/// - `POST /eth/v2/beacon/pool/attester_slashings`   (public, M15 Phase 3)
/// - `GET  /eth/v1/beacon/pool/proposer_slashings`   (public)
/// - `POST /eth/v1/beacon/pool/proposer_slashings`   (public)
/// - `GET  /eth/v1/beacon/pool/voluntary_exits`      (public)
/// - `POST /eth/v1/beacon/pool/voluntary_exits`      (public)
/// - `GET  /eth/v1/beacon/pool/bls_to_execution_changes`  (public)
/// - `POST /eth/v1/beacon/pool/bls_to_execution_changes`  (public)
/// - `GET  /eth/v1/beacon/pool/sync_committees`      (public)
/// - `POST /eth/v1/beacon/pool/sync_committees`      (public)
///
/// The validator sub-router has `validator_auth_layer` applied; `None` means
/// no auth (default).  The debug and pool routes are unauthenticated.
pub fn build_router<E: BeaconSpec>(state: Arc<ApiState<E>>) -> Router {
    build_router_with_auth::<E>(state, None)
}

/// Build the router with an optional validator-API bearer token.
///
/// When `validator_token` is `Some(t)`, requests to `/eth/v1/validator/*`
/// must carry `Authorization: Bearer <t>`; missing/wrong token → 401/403.
/// When `None`, the validator routes are unauthenticated (default).
pub fn build_router_with_auth<E: BeaconSpec>(
    state: Arc<ApiState<E>>,
    validator_token: Option<String>,
) -> Router {
    // ── Validator sub-router (auth-gated) ─────────────────────────────────
    let validator_router = Router::new()
        // Duties (Phase 5 + M15-Phase2)
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(validator_duties::get_proposer_duties::<E>),
        )
        .route(
            "/eth/v2/validator/duties/proposer/{epoch}",
            get(validator_duties::get_proposer_duties_v2::<E>),
        )
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            post(validator_duties::post_attester_duties::<E>),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            post(validator_duties::post_sync_duties::<E>),
        )
        // M9 Phase 5 — production + signing (Task 5.2)
        .route(
            "/eth/v3/validator/blocks/{slot}",
            get(validator_production::get_produce_block_v3::<E>),
        )
        .route(
            "/eth/v1/validator/attestation_data",
            get(validator_production::get_attestation_data::<E>),
        )
        .route(
            "/eth/v2/validator/aggregate_attestation",
            get(validator_production::get_aggregate_attestation::<E>),
        )
        .route(
            "/eth/v2/validator/aggregate_and_proofs",
            post(validator_production::post_aggregate_and_proofs::<E>),
        )
        .route(
            "/eth/v1/validator/prepare_beacon_proposer",
            post(validator_production::post_prepare_beacon_proposer::<E>),
        )
        .route(
            "/eth/v1/validator/register_validator",
            post(validator_production::post_register_validator::<E>),
        )
        .route(
            "/eth/v1/validator/beacon_committee_subscriptions",
            post(validator_production::post_beacon_committee_subscriptions::<E>),
        )
        .route(
            "/eth/v1/validator/sync_committee_subscriptions",
            post(validator_production::post_sync_committee_subscriptions::<E>),
        )
        // M9 Phase 5 — sync-committee (Task 5.3)
        .route(
            "/eth/v1/validator/sync_committee_contribution",
            get(sync_committee_handlers::get_sync_committee_contribution::<E>),
        )
        .route(
            "/eth/v1/validator/contribution_and_proofs",
            post(sync_committee_handlers::post_contribution_and_proofs::<E>),
        )
        .route(
            "/eth/v1/validator/beacon_committee_selections",
            post(sync_committee_handlers::post_beacon_committee_selections::<E>),
        )
        .route(
            "/eth/v1/validator/sync_committee_selections",
            post(sync_committee_handlers::post_sync_committee_selections::<E>),
        )
        // M9 Phase 5 — liveness (Task 5.4)
        .route(
            "/eth/v1/validator/liveness/{epoch}",
            post(validator_liveness::post_validator_liveness::<E>),
        )
        .layer(validator_auth_layer(validator_token))
        .with_state(Arc::clone(&state));

    Router::new()
        // Node namespace (Phase 1 + M9 Phase 5 peers + M15 Phase 1)
        .route("/eth/v1/node/identity", get(node::get_identity::<E>))
        .route("/eth/v1/node/version", get(node::get_version::<E>))
        .route("/eth/v2/node/version", get(node::get_version_v2::<E>))
        .route("/eth/v1/node/syncing", get(node::get_syncing::<E>))
        .route("/eth/v1/node/health", get(node::get_health::<E>))
        .route("/eth/v1/node/peers", get(node::get_peers::<E>))
        .route("/eth/v1/node/peer_count", get(node::get_peer_count::<E>))
        .route("/eth/v1/node/peers/{peer_id}", get(node::get_peer::<E>))
        // Beacon basic namespace (Phase 1; migrated to ApiResponse in Phase 2)
        .route(
            "/eth/v1/beacon/genesis",
            get(beacon_basic::get_genesis::<E>),
        )
        // NOTE: `/eth/v1/beacon/headers/head` is served by the
        // `/eth/v1/beacon/headers/{block_id}` route below (block_id = "head"),
        // which returns a single header object per the beacon-API spec. A
        // dedicated head-header route returned a `data` ARRAY and shadowed the
        // {block_id} route for "head", so it was removed.
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
        // Electra-only state endpoints (Phase 6e)
        .route(
            "/eth/v1/beacon/states/{state_id}/pending_deposits",
            get(states::get_pending_deposits::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/pending_partial_withdrawals",
            get(states::get_pending_partial_withdrawals::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/pending_consolidations",
            get(states::get_pending_consolidations::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validator_identities",
            post(states::post_validator_identities::<E>),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/proposer_lookahead",
            get(states::get_proposer_lookahead::<E>),
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
        // Light-client namespace (M7-followup)
        .route(
            "/eth/v1/beacon/light_client/bootstrap/{block_root}",
            get(lc_handlers::get_bootstrap::<E>),
        )
        .route(
            "/eth/v1/beacon/light_client/updates",
            get(lc_handlers::get_updates::<E>),
        )
        .route(
            "/eth/v1/beacon/light_client/finality_update",
            get(lc_handlers::get_finality_update::<E>),
        )
        .route(
            "/eth/v1/beacon/light_client/optimistic_update",
            get(lc_handlers::get_optimistic_update::<E>),
        )
        // M9 Phase 5 — beacon block publish (Task 5.5, public)
        .route(
            "/eth/v1/beacon/blocks",
            post(beacon_blocks_publish::post_beacon_block_v1::<E>),
        )
        .route(
            "/eth/v2/beacon/blocks",
            post(beacon_blocks_publish::post_beacon_block_v2::<E>),
        )
        // M9 Phase 5 — beacon pool (Task 5.6, public)
        .route(
            "/eth/v1/beacon/pool/attestations",
            get(beacon_pool::get_pool_attestations::<E>)
                .post(beacon_pool::post_pool_attestations::<E>),
        )
        // M15 Phase 3 — EIP-7549 versioned pool (public)
        .route(
            "/eth/v2/beacon/pool/attestations",
            get(beacon_pool::get_pool_attestations_v2::<E>)
                .post(beacon_pool::post_pool_attestations_v2::<E>),
        )
        .route(
            "/eth/v1/beacon/pool/attester_slashings",
            get(beacon_pool::get_pool_attester_slashings::<E>)
                .post(beacon_pool::post_pool_attester_slashings::<E>),
        )
        .route(
            "/eth/v2/beacon/pool/attester_slashings",
            get(beacon_pool::get_pool_attester_slashings_v2::<E>)
                .post(beacon_pool::post_pool_attester_slashings_v2::<E>),
        )
        .route(
            "/eth/v1/beacon/pool/proposer_slashings",
            get(beacon_pool::get_pool_proposer_slashings::<E>)
                .post(beacon_pool::post_pool_proposer_slashings::<E>),
        )
        .route(
            "/eth/v1/beacon/pool/voluntary_exits",
            get(beacon_pool::get_pool_voluntary_exits::<E>)
                .post(beacon_pool::post_pool_voluntary_exits::<E>),
        )
        .route(
            "/eth/v1/beacon/pool/bls_to_execution_changes",
            get(beacon_pool::get_pool_bls_to_execution_changes::<E>)
                .post(beacon_pool::post_pool_bls_to_execution_changes::<E>),
        )
        .route(
            "/eth/v1/beacon/pool/sync_committees",
            get(beacon_pool::get_pool_sync_committees::<E>)
                .post(beacon_pool::post_pool_sync_committees::<E>),
        )
        .with_state(Arc::clone(&state))
        // Merge validator sub-router (has its own auth layer + state)
        .merge(validator_router)
}
