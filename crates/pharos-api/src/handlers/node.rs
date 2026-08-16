//! Node namespace handlers.
//!
//! - `GET /eth/v1/node/identity`
//! - `GET /eth/v1/node/version`
//! - `GET /eth/v1/node/syncing`
//! - `GET /eth/v1/node/health`
//!
//! Spec shapes from `~/dev/beacon-APIs/apis/node/{identity,version,syncing,health}.yaml`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use libp2p::Multiaddr;
use pharos_types::EthSpec;
use serde::Serialize;

use crate::error::ApiError;
use crate::serde_helpers::quoted_u64;
use crate::state::ApiState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MetaDataDto {
    #[serde(with = "quoted_u64")]
    seq_number: u64,
    attnets: String,
    syncnets: String,
}

#[derive(Serialize)]
pub struct IdentityData {
    peer_id: String,
    enr: String,
    p2p_addresses: Vec<String>,
    discovery_addresses: Vec<String>,
    metadata: MetaDataDto,
}

#[derive(Serialize)]
pub struct IdentityResponse {
    data: IdentityData,
}

#[derive(Serialize)]
pub struct VersionData {
    version: String,
}

#[derive(Serialize)]
pub struct VersionResponse {
    data: VersionData,
}

#[derive(Serialize)]
pub struct SyncingData {
    #[serde(with = "quoted_u64")]
    head_slot: u64,
    #[serde(with = "quoted_u64")]
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
    el_offline: bool,
}

#[derive(Serialize)]
pub struct SyncingResponse {
    data: SyncingData,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/node/identity`
pub async fn get_identity<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<IdentityResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let identity = chain.node_identity();

        let meta_load = identity.metadata.load();
        let seq_number = meta_load.seq_number;

        // Encode attnets / syncnets as 0x-prefixed hex.
        let attnets_bytes = pharos_ssz::Encode::as_ssz_bytes(&meta_load.attnets);
        let attnets = format!(
            "0x{}",
            attnets_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let syncnets_bytes = pharos_ssz::Encode::as_ssz_bytes(&meta_load.syncnets);
        let syncnets = format!(
            "0x{}",
            syncnets_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );

        let p2p_addresses: Vec<String> = identity
            .listen_addrs
            .iter()
            .map(|a| format!("{a}/p2p/{}", identity.peer_id))
            .collect();
        let discovery_addresses: Vec<String> = identity
            .discovery_addrs
            .iter()
            .map(|a: &Multiaddr| a.to_string())
            .collect();

        IdentityResponse {
            data: IdentityData {
                peer_id: identity.peer_id.to_string(),
                enr: identity.enr.to_base64(),
                p2p_addresses,
                discovery_addresses,
                metadata: MetaDataDto {
                    seq_number,
                    attnets,
                    syncnets,
                },
            },
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;

    Ok(Json(result))
}

/// `GET /eth/v1/node/version`
pub async fn get_version<E: EthSpec>(
    State(_state): State<Arc<ApiState<E>>>,
) -> Json<VersionResponse> {
    Json(VersionResponse {
        data: VersionData {
            version: format!(
                "Pharos/{}/{}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS
            ),
        },
    })
}

/// `GET /eth/v1/node/syncing`
pub async fn get_syncing<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<SyncingResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        // head_slot is the slot of the node's CURRENT HEAD BLOCK (not the wall
        // clock); sync_distance = wall_slot - head_slot. A lighthouse VC reads
        // all three and refuses to drive a BN whose head_slot / sync_distance
        // disagree with is_syncing, so they must derive from the same source.
        let current = u64::from(chain.current_slot());
        let head_root = chain.head_root();
        let head_slot = chain
            .block_header_at(head_root)
            .map(|h| u64::from(h.slot))
            .unwrap_or(0);
        let sync_distance = current.saturating_sub(head_slot);
        let is_syncing = chain.is_syncing();
        let is_optimistic = chain.is_optimistic();
        let el_offline = chain.el_offline();
        SyncingData {
            head_slot,
            sync_distance,
            is_syncing,
            is_optimistic,
            el_offline,
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;

    Ok(Json(SyncingResponse { data: result }))
}

/// `GET /eth/v1/node/health`
///
/// Returns bare HTTP status codes (no body):
/// - `200` — node synced, not optimistic, and ready.
/// - `206` — node is syncing OR execution node is optimistic/offline.
/// - `503` — node not initialized.
pub async fn get_health<E: EthSpec>(State(state): State<Arc<ApiState<E>>>) -> Response {
    let chain = Arc::clone(&state.chain);
    let probe = tokio::task::spawn_blocking(move || {
        chain.is_syncing() || chain.is_optimistic() || chain.el_offline()
    })
    .await;
    match probe {
        Ok(false) => StatusCode::OK.into_response(),
        Ok(true) => StatusCode::from_u16(206).unwrap().into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

// ── Peer DTOs ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PeerCountData {
    #[serde(with = "crate::serde_helpers::quoted_u64")]
    pub connected: u64,
    #[serde(with = "crate::serde_helpers::quoted_u64")]
    pub disconnecting: u64,
    #[serde(with = "crate::serde_helpers::quoted_u64")]
    pub disconnected: u64,
    #[serde(with = "crate::serde_helpers::quoted_u64")]
    pub connecting: u64,
}

#[derive(Serialize)]
pub struct PeerCountResponse {
    pub data: PeerCountData,
}

#[derive(Serialize)]
pub struct PeersResponse {
    pub data: Vec<serde_json::Value>,
}

// ── Peer handlers ──────────────────────────────────────────────────────────────

/// `GET /eth/v1/node/peers`
///
/// Returns a list of connected peers.
/// Per `~/dev/beacon-APIs/apis/node/peers.yaml`.
pub async fn get_peers<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<PeersResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let peers = tokio::task::spawn_blocking(move || chain.peers())
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;
    Ok(Json(PeersResponse { data: peers }))
}

/// `GET /eth/v1/node/peer_count`
///
/// Returns counts of peers in each state.
/// Per `~/dev/beacon-APIs/apis/node/peer_count.yaml`.
pub async fn get_peer_count<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<PeerCountResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let peers = tokio::task::spawn_blocking(move || chain.peers())
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;

    // Count peers by state field (per beacon-API `peer_count.yaml` buckets).
    let (mut connected, mut connecting, mut disconnecting, mut disconnected) = (0, 0, 0, 0);
    for peer in &peers {
        match peer.get("state").and_then(|s| s.as_str()) {
            Some("connected") => connected += 1,
            Some("connecting") => connecting += 1,
            Some("disconnecting") => disconnecting += 1,
            Some("disconnected") => disconnected += 1,
            _ => {}
        }
    }

    Ok(Json(PeerCountResponse {
        data: PeerCountData {
            connected,
            disconnecting,
            disconnected,
            connecting,
        },
    }))
}
