//! Debug namespace handlers (Task 5.4).
//!
//! - `GET /eth/v1/debug/fork_choice`     — fork-choice node dump
//! - `GET /eth/v2/debug/beacon/heads`    — fork-choice leaf nodes
//! - `GET /eth/v2/debug/beacon/states/{state_id}` — full BeaconState (fork-tagged, JSON + SSZ)
//!
//! Spec shapes from:
//! `~/dev/beacon-APIs/apis/debug/{fork_choice,heads.v2,state.v2}.yaml`
//! `~/dev/beacon-APIs/types/fork_choice.yaml`
//!
//! The state endpoint reuses `resolve_state_id` + `ForkTagged<T>` from Phase 3
//! (Tasks 2.2 / 3.1) — no new resolution path.  The JSON serialization is
//! handled by `ChainStateApi::state_to_json`, whose default implementation uses
//! `BeaconStateView` accessors common to all forks; `NodeChainState` provides
//! the full per-fork field access where the concrete types are available.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_ssz::Encode;
use pharos_types::{BeaconSpec, BeaconStateView};

use crate::error::ApiError;
use crate::fork_tag::ForkTagged;
use crate::resolve::resolve_state_id;
use crate::respond::{AcceptFormat, ApiResponse, parse_accept};
use crate::state::ApiState;

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/debug/fork_choice`
///
/// Dumps all in-memory fork-choice blocks.  Sources from
/// `ChainStateApi::fork_choice_dump`.
pub async fn get_fork_choice<E: BeaconSpec>(State(state): State<Arc<ApiState<E>>>) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.fork_choice_dump())
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(v)) => ApiResponse::json(v).render(AcceptFormat::Json),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/debug/beacon/heads`
///
/// Returns the set of leaf nodes in the in-memory fork-choice tree.
pub async fn get_beacon_heads<E: BeaconSpec>(State(state): State<Arc<ApiState<E>>>) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.fork_choice_heads())
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(v)) => ApiResponse::json(v).render(AcceptFormat::Json),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/debug/beacon/states/{state_id}`
///
/// Returns the full `BeaconState` for the resolved id, fork-tagged.
/// Reuses `resolve_state_id` + `ForkTagged<T>` from Phase 3.
///
/// JSON: `ChainStateApi::state_to_json` — required method, produces complete
/// fork-tagged fields via `beacon_state_to_json_full`.
/// SSZ: raw `Encode::as_ssz_bytes`.
pub async fn get_debug_state<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        let variant = beacon_state.fork_variant();
        let ssz_bytes = beacon_state.as_ssz_bytes();
        let json_val = chain.state_to_json(beacon_state)?;

        Ok::<_, ApiError>((
            variant,
            resolved.execution_optimistic,
            resolved.finalized,
            json_val,
            ssz_bytes,
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((variant, eo, finalized, json_val, ssz_bytes))) => {
            ForkTagged::new(variant, eo, finalized, json_val).render(format, Some(ssz_bytes))
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
