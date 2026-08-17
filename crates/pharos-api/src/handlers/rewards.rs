//! Rewards endpoints (M15-BeaconAPIGaps Phase 6).
//!
//! - `POST /eth/v1/beacon/rewards/attestations/{epoch}` — per-validator
//!   attestation rewards for a completed epoch.
//! - `GET  /eth/v1/beacon/rewards/blocks/{block_id}` — proposer-reward
//!   components of a single block.
//! - `POST /eth/v1/beacon/rewards/sync_committee/{block_id}` — per-member
//!   sync-committee rewards for a single block.
//!
//! Spec: `~/dev/beacon-APIs/apis/beacon/rewards/{attestations,blocks,sync_committee}.yaml`
//! and `~/dev/beacon-APIs/types/rewards.yaml` (`AttestationsRewards`,
//! `BlockRewards`, `SyncCommitteeRewards`).
//!
//! All reward math runs in `pharos_stf::rewards_api` (FACTORED STF helpers, no
//! duplication), reached via the bound-heavy `ChainStateApi::*_rewards_data`
//! methods so these handlers stay generic over plain `E: BeaconSpec`. The
//! handlers resolve the block/epoch, parse the optional validator-id filter
//! body, call the chain method, and serialize the per-endpoint JSON shape.
//!
//! ADRs: `D-rewards-stf-factoring-not-duplication`,
//! `D-rewards-attestation-regen-epoch-plus-one`,
//! `D-rewards-block-recompute-not-balance-diff`,
//! `D-rewards-no-test-vectors-shape-only`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use pharos_stf::rewards_api::{AttestationRewardsData, BlockRewardComponents, SyncCommitteeReward};
use pharos_types::BeaconSpec;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::resolve::resolve_block_id;
use crate::state::ApiState;

// ── filter parsing ────────────────────────────────────────────────────────────

/// Parse the optional POST body — a JSON array of validator id strings (decimal
/// index or `0x`-prefixed pubkey hex) — into the raw string list. `None`/empty
/// body → `None` ("all validators"). The chain method resolves pubkeys against
/// the regenerated state.
fn parse_filter_body(body: &[u8]) -> Result<Option<Vec<String>>, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let v: JsonValue = serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("invalid request body: {e}")))?;
    let JsonValue::Array(items) = v else {
        return Err(ApiError::BadRequest(
            "request body must be a JSON array of validator id/pubkey strings".into(),
        ));
    };
    if items.is_empty() {
        return Ok(None);
    }
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let s = item
            .as_str()
            .ok_or_else(|| ApiError::BadRequest("each id must be a string".into()))?;
        ids.push(s.to_string());
    }
    Ok(Some(ids))
}

// ── POST /eth/v1/beacon/rewards/attestations/{epoch} ────────────────────────────

/// Per `~/dev/beacon-APIs/apis/beacon/rewards/attestations.yaml`.
///
/// Response: `{execution_optimistic, finalized, data: {ideal_rewards,
/// total_rewards}}`. `head`/`target`/`source`/`inactivity` are signed `Int64`;
/// `inclusion_delay` (phase0 only) is `Uint64`.
///
/// **phase0 `ideal_rewards` note**: phase0 has no closed-form ideal reward
/// formula (the per-validator delta fns depend on the full attestation set, not
/// just effective balance). For phase0 states the `ideal_rewards` array
/// enumerates effective-balance buckets `[INCREMENT..=MAX_EFFECTIVE_BALANCE]`
/// with zero component values. The real per-validator values (including
/// `inclusion_delay`) are in `total_rewards` and ARE non-zero.
pub async fn post_attestation_rewards<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(epoch): Path<u64>,
    body: axum::body::Bytes,
) -> Response {
    let ids = match parse_filter_body(&body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let data = chain.attestation_rewards_data(epoch, ids)?;
        // Finalized iff `epoch + 1` boundary is at/behind the finalized cp.
        let finalized = (epoch + 1) <= chain.finalized_checkpoint().epoch.0;
        // The regenerated epoch boundary is a finalized historical state; mark
        // execution_optimistic = false (it is not the optimistic head).
        Ok::<_, ApiError>(attestation_rewards_json(&data, false, finalized))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => json_ok(dto),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

fn attestation_rewards_json(
    data: &AttestationRewardsData,
    execution_optimistic: bool,
    finalized: bool,
) -> JsonValue {
    let ideal: Vec<JsonValue> = data
        .ideal_rewards
        .iter()
        .map(|r| {
            let mut o = serde_json::json!({
                "effective_balance": r.effective_balance.to_string(),
                "head": r.head.to_string(),
                "target": r.target.to_string(),
                "source": r.source.to_string(),
                "inactivity": r.inactivity.to_string(),
            });
            if let Some(id) = r.inclusion_delay {
                o["inclusion_delay"] = id.to_string().into();
            }
            o
        })
        .collect();
    let total: Vec<JsonValue> = data
        .total_rewards
        .iter()
        .map(|r| {
            let mut o = serde_json::json!({
                "validator_index": r.validator_index.to_string(),
                "head": r.head.to_string(),
                "target": r.target.to_string(),
                "source": r.source.to_string(),
                "inactivity": r.inactivity.to_string(),
            });
            if let Some(id) = r.inclusion_delay {
                o["inclusion_delay"] = id.to_string().into();
            }
            o
        })
        .collect();
    serde_json::json!({
        "execution_optimistic": execution_optimistic,
        "finalized": finalized,
        "data": { "ideal_rewards": ideal, "total_rewards": total },
    })
}

// ── GET /eth/v1/beacon/rewards/blocks/{block_id} ────────────────────────────────

/// Per `~/dev/beacon-APIs/apis/beacon/rewards/blocks.yaml`.
///
/// Response: `{execution_optimistic, finalized, data: BlockRewards}` where
/// `BlockRewards = {proposer_index, total, attestations, sync_aggregate,
/// proposer_slashings, attester_slashings}` (all `Uint64`).
pub async fn get_block_rewards<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;
        let components: BlockRewardComponents = chain.block_rewards_data(resolved.block_root)?;
        let dto = serde_json::json!({
            "execution_optimistic": resolved.execution_optimistic,
            "finalized": resolved.finalized,
            "data": {
                "proposer_index": components.proposer_index.to_string(),
                "total": components.total().to_string(),
                "attestations": components.attestations.to_string(),
                "sync_aggregate": components.sync_aggregate.to_string(),
                "proposer_slashings": components.proposer_slashings.to_string(),
                "attester_slashings": components.attester_slashings.to_string(),
            },
        });
        Ok::<_, ApiError>(dto)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => json_ok(dto),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── POST /eth/v1/beacon/rewards/sync_committee/{block_id} ────────────────────────

/// Per `~/dev/beacon-APIs/apis/beacon/rewards/sync_committee.yaml`.
///
/// Response: `{execution_optimistic, finalized, data: [{validator_index,
/// reward}]}` where `reward` is signed `Int64`. Pre-altair → 400.
pub async fn post_sync_committee_rewards<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let ids = match parse_filter_body(&body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;
        let rewards: Vec<SyncCommitteeReward> =
            chain.sync_committee_rewards_data(resolved.block_root, ids)?;
        let data: Vec<JsonValue> = rewards
            .iter()
            .map(|r| {
                serde_json::json!({
                    "validator_index": r.validator_index.to_string(),
                    "reward": r.reward.to_string(),
                })
            })
            .collect();
        let dto = serde_json::json!({
            "execution_optimistic": resolved.execution_optimistic,
            "finalized": resolved.finalized,
            "data": data,
        });
        Ok::<_, ApiError>(dto)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => json_ok(dto),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── shared response helper ──────────────────────────────────────────────────────

fn json_ok(dto: JsonValue) -> Response {
    match serde_json::to_vec(&dto) {
        Ok(body) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => ApiError::Internal(format!("JSON serialization: {e}")).into_response(),
    }
}
