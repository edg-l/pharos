//! Basic beacon namespace handlers (Phase 1 Tier-1 subset).
//!
//! - `GET /eth/v1/beacon/genesis`
//! - `GET /eth/v1/beacon/headers/head`
//!
//! Spec shapes from:
//! - `~/dev/beacon-APIs/apis/beacon/genesis.yaml`
//! - `~/dev/beacon-APIs/apis/beacon/blocks/headers.yaml`
//!
//! NOTE (Phase 1): responses are JSON-only. Content-negotiation (SSZ via
//! `Accept: application/octet-stream`) lands in Phase 2 (Task 2.6).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use pharos_types::EthSpec;
use serde::Serialize;

use crate::error::ApiError;
use crate::serde_helpers::{quoted_u64, serialize_hex4, serialize_hex32};
use crate::state::ApiState;

// ── genesis DTOs ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct GenesisData {
    #[serde(with = "quoted_u64")]
    genesis_time: u64,
    #[serde(serialize_with = "serialize_hex32")]
    genesis_validators_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex4")]
    genesis_fork_version: [u8; 4],
}

#[derive(Serialize)]
pub struct GenesisResponse {
    data: GenesisData,
}

// ── headers DTOs ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BeaconBlockHeaderDto {
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
pub struct SignedBeaconBlockHeaderDto {
    message: BeaconBlockHeaderDto,
    // Signature is not tracked in the in-memory block-header view;
    // the `latest_block_header` in the state stores a zeroed signature
    // (per STF process_block_header). For Phase 1, we emit a zero
    // signature. Phase 3 will add full block decoding.
    #[serde(serialize_with = "crate::serde_helpers::serialize_hex96")]
    signature: [u8; 96],
}

#[derive(Serialize)]
pub struct BlockHeaderItem {
    #[serde(serialize_with = "serialize_hex32")]
    root: [u8; 32],
    canonical: bool,
    header: SignedBeaconBlockHeaderDto,
}

#[derive(Serialize)]
pub struct BlockHeadersResponse {
    execution_optimistic: bool,
    finalized: bool,
    data: Vec<BlockHeaderItem>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/genesis`
pub async fn get_genesis<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<GenesisResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let (genesis_time, genesis_validators_root, genesis_fork_version) = chain.genesis();
        GenesisResponse {
            data: GenesisData {
                genesis_time,
                genesis_validators_root: genesis_validators_root.into(),
                genesis_fork_version,
            },
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;

    Ok(Json(result))
}

/// `GET /eth/v1/beacon/headers/head`
///
/// Returns the head block header. Per the spec (`headers.yaml`), the endpoint
/// accepts optional `slot` / `parent_root` query parameters; Phase 1 returns
/// only the head without query filtering (Phase 3 adds full query support).
pub async fn get_head_header<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<BlockHeadersResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let head_root = chain.head_root();
        let is_optimistic = chain.is_optimistic();
        let finalized = chain.finalized_checkpoint();

        let header = chain
            .block_header_at(head_root)
            .ok_or_else(|| ApiError::Internal("head block not in fork-choice store".to_string()))?;

        let head_slot = u64::from(header.slot);
        let finalized_block = chain.block_header_at(finalized.root);
        let is_finalized = finalized_block
            .map(|h| u64::from(h.slot) >= head_slot)
            .unwrap_or(false);

        Ok(BlockHeadersResponse {
            execution_optimistic: is_optimistic,
            finalized: is_finalized,
            data: vec![BlockHeaderItem {
                root: head_root.into(),
                canonical: true,
                header: SignedBeaconBlockHeaderDto {
                    message: BeaconBlockHeaderDto {
                        slot: u64::from(header.slot),
                        proposer_index: header.proposer_index.into(),
                        parent_root: header.parent_root.into(),
                        state_root: header.state_root.into(),
                        body_root: header.body_root.into(),
                    },
                    signature: [0u8; 96],
                },
            }],
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))??;

    Ok(Json(result))
}
