//! Beacon blocks namespace handlers.
//!
//! - `GET /eth/v1/beacon/blocks/{block_id}/root`
//! - `GET /eth/v1/beacon/headers`  (query: slot, parent_root)
//! - `GET /eth/v1/beacon/headers/{block_id}`
//! - `GET /eth/v2/beacon/blocks/{block_id}`  (fork-tagged, JSON + SSZ)
//! - `GET /eth/v2/beacon/blocks/{block_id}/attestations`  (fork-tagged)
//!
//! Spec shapes from:
//! - `~/dev/beacon-APIs/apis/beacon/blocks/{root,headers,header,block.v2,attestations.v2}.yaml`

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_types::BeaconSpec;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::fork_tag::ForkTagged;
use crate::resolve::resolve_block_id;
use crate::respond::{ApiResponse, parse_accept};
use crate::serde_helpers::{quoted_u64, serialize_hex32, serialize_hex96};
use crate::state::ApiState;

// ── Block root ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct BlockRootData {
    #[serde(serialize_with = "serialize_hex32")]
    root: [u8; 32],
}

#[derive(Serialize)]
struct BlockRootResponse {
    execution_optimistic: bool,
    finalized: bool,
    data: BlockRootData,
}

/// `GET /eth/v1/beacon/blocks/{block_id}/root`
///
/// Per `~/dev/beacon-APIs/apis/beacon/blocks/root.yaml`.
pub async fn get_block_root<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;
        Ok::<_, ApiError>(BlockRootResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: BlockRootData {
                root: resolved.block_root.into(),
            },
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => {
            let root_bytes: Vec<u8> = dto.data.root.to_vec();
            ApiResponse::both(dto, root_bytes).render(format)
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Headers ───────────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct HeadersQuery {
    slot: Option<u64>,
    parent_root: Option<String>,
}

#[derive(Serialize)]
struct BeaconBlockHeaderDto {
    #[serde(with = "quoted_u64")]
    slot: u64,
    #[serde(with = "quoted_u64")]
    proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    state_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    body_root: [u8; 32],
}

#[derive(Serialize)]
struct SignedHeaderDto {
    message: BeaconBlockHeaderDto,
    #[serde(serialize_with = "serialize_hex96")]
    signature: [u8; 96],
}

#[derive(Serialize)]
struct HeaderItem {
    #[serde(serialize_with = "serialize_hex32")]
    root: [u8; 32],
    canonical: bool,
    header: SignedHeaderDto,
}

#[derive(Serialize)]
struct HeadersResponse {
    execution_optimistic: bool,
    finalized: bool,
    data: Vec<HeaderItem>,
}

/// Response for `GET /eth/v1/beacon/headers/{block_id}` — per `header.yaml`,
/// `data` is a single object (not an array, unlike the list endpoint).
#[derive(Serialize)]
struct SingleHeaderResponse {
    execution_optimistic: bool,
    finalized: bool,
    data: HeaderItem,
}

/// Build a `HeaderItem` from a block root using the stored signed block.
///
/// Sources the REAL proposer signature from `signed_block_header_at` (which
/// reads the `SignedBeaconBlock` from `RocksStore`). Falls back to the
/// in-memory header with a zeroed signature only when the signed block is
/// absent from storage (e.g. pre-schema-v3 anchor blocks imported before live
/// block persistence existed).
fn build_header_item<E: BeaconSpec>(
    chain: &dyn crate::state::ChainStateApi<E>,
    root: pharos_types::phase0::Root,
    _execution_optimistic: bool,
) -> Result<HeaderItem, ApiError> {
    // Prefer the real signature sourced from the stored SignedBeaconBlock.
    if let Some((hdr, sig)) = chain.signed_block_header_at(root) {
        return Ok(HeaderItem {
            root: root.into(),
            canonical: true,
            header: SignedHeaderDto {
                message: BeaconBlockHeaderDto {
                    slot: u64::from(hdr.slot),
                    proposer_index: hdr.proposer_index.into(),
                    parent_root: hdr.parent_root.into(),
                    state_root: hdr.state_root.into(),
                    body_root: hdr.body_root.into(),
                },
                signature: sig.into_inner(),
            },
        });
    }

    // Fall back: block not yet in storage — use in-memory header with zeroed sig.
    let hdr = chain
        .block_header_at(root)
        .ok_or_else(|| ApiError::NotFound(format!("block not found for root {root:?}")))?;
    Ok(HeaderItem {
        root: root.into(),
        canonical: true,
        header: SignedHeaderDto {
            message: BeaconBlockHeaderDto {
                slot: u64::from(hdr.slot),
                proposer_index: hdr.proposer_index.into(),
                parent_root: hdr.parent_root.into(),
                state_root: hdr.state_root.into(),
                body_root: hdr.body_root.into(),
            },
            signature: [0u8; 96],
        },
    })
}

/// `GET /eth/v1/beacon/headers`
///
/// Returns block headers matching the given query. When no query parameters are
/// supplied, returns the current head slot headers. Per
/// `~/dev/beacon-APIs/apis/beacon/blocks/headers.yaml`.
pub async fn get_headers<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Query(q): Query<HeadersQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let finalized_cp = chain.finalized_checkpoint();

        // If slot query: look up blocks at that slot.
        if let Some(slot_num) = q.slot {
            use pharos_types::phase0::Slot;
            let slot = Slot(slot_num);
            match chain.block_root_for_slot(slot) {
                None => {
                    // No block at this slot; head-level optimism as fallback
                    // (empty data array — the optimism flag is advisory).
                    let is_optimistic = chain.is_optimistic();
                    return Ok::<_, ApiError>(HeadersResponse {
                        execution_optimistic: is_optimistic,
                        finalized: false,
                        data: vec![],
                    });
                }
                Some(root) => {
                    // Per-root derivation: response is about THIS specific block.
                    let is_optimistic = chain.is_optimistic_for_root(root);
                    let item = build_header_item(chain.as_ref(), root, is_optimistic)?;
                    let fin = slot.epoch(E::SLOTS_PER_EPOCH) <= finalized_cp.epoch;
                    return Ok(HeadersResponse {
                        execution_optimistic: is_optimistic,
                        finalized: fin,
                        data: vec![item],
                    });
                }
            }
        }

        // If parent_root query: not currently indexed; return empty list.
        if q.parent_root.is_some() {
            let is_optimistic = chain.is_optimistic();
            return Ok(HeadersResponse {
                execution_optimistic: is_optimistic,
                finalized: false,
                data: vec![],
            });
        }

        // Default: head block — per-root derivation.
        let head_root = chain.head_root();
        let is_optimistic = chain.is_optimistic_for_root(head_root);
        let item = build_header_item(chain.as_ref(), head_root, is_optimistic)?;
        let head_slot = item.header.message.slot;
        let fin =
            pharos_types::phase0::Slot(head_slot).epoch(E::SLOTS_PER_EPOCH) <= finalized_cp.epoch;
        Ok(HeadersResponse {
            execution_optimistic: is_optimistic,
            finalized: fin,
            data: vec![item],
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/headers/{block_id}`
///
/// Returns the block header for the given block id. Per
/// `~/dev/beacon-APIs/apis/beacon/blocks/header.yaml`.
pub async fn get_header<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;
        let item = build_header_item(
            chain.as_ref(),
            resolved.block_root,
            resolved.execution_optimistic,
        )?;
        Ok::<_, ApiError>(SingleHeaderResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: item,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── v2 full block ─────────────────────────────────────────────────────────────

/// `GET /eth/v2/beacon/blocks/{block_id}`
///
/// Returns the full `SignedBeaconBlock` fork-tagged with the `version` field and
/// the `Eth-Consensus-Version` response header. Supports both JSON
/// (`Accept: application/json`) and SSZ (`Accept: application/octet-stream`).
///
/// Per `~/dev/beacon-APIs/apis/beacon/blocks/block.v2.yaml`.
pub async fn get_block_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;
        let block_data = chain
            .block_by_root_for_api(resolved.block_root)?
            .ok_or_else(|| ApiError::NotFound(format!("block not found: {block_id}")))?;
        Ok::<_, ApiError>((resolved, block_data))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((resolved, block_data))) => {
            let tagged = ForkTagged::new(
                block_data.variant,
                resolved.execution_optimistic,
                resolved.finalized,
                block_data.json,
            );
            tagged.render(format, Some(block_data.ssz_bytes))
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── v2 block attestations ─────────────────────────────────────────────────────

/// `GET /eth/v2/beacon/blocks/{block_id}/attestations`
///
/// Returns the attestations included in the block for the given block id, fork-tagged.
/// Per `~/dev/beacon-APIs/apis/beacon/blocks/attestations.v2.yaml`.
pub async fn get_block_attestations_v2<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;
        let block_data = chain
            .block_by_root_for_api(resolved.block_root)?
            .ok_or_else(|| ApiError::NotFound(format!("block not found: {block_id}")))?;
        Ok::<_, ApiError>((resolved, block_data))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((resolved, block_data))) => {
            // Attestations are JSON-only (no SSZ form for an array of attestations).
            let tagged = ForkTagged::new(
                block_data.variant,
                resolved.execution_optimistic,
                resolved.finalized,
                block_data.attestations_json,
            );
            tagged.render(format, None)
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
