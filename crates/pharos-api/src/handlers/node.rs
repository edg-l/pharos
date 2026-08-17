//! Node namespace handlers.
//!
//! - `GET /eth/v1/node/identity`
//! - `GET /eth/v1/node/version`
//! - `GET /eth/v2/node/version`
//! - `GET /eth/v1/node/syncing`
//! - `GET /eth/v1/node/health`
//! - `GET /eth/v1/node/peers`
//! - `GET /eth/v1/node/peer_count`
//! - `GET /eth/v1/node/peers/{peer_id}`
//!
//! Spec shapes from `~/dev/beacon-APIs/apis/node/{identity,version,version.v2,syncing,health,peers,peer_count,peer}.yaml`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use libp2p::Multiaddr;
use pharos_types::BeaconSpec;
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

/// `ClientVersionV1` per `~/dev/beacon-APIs/types/node.yaml#ClientVersionV1`.
///
/// Fields: `code` (2-letter client code), `name`, `version`, `commit`
/// (0x-prefixed 4-byte hex string). All four are required by the schema.
#[derive(Serialize)]
pub struct ClientVersionV1 {
    /// Two-character client code (e.g. "LH", "PH").
    pub code: String,
    /// Human-readable client name.
    pub name: String,
    /// Version string (e.g. "v0.21.0").
    pub version: String,
    /// First 4 bytes of the latest commit hash, `0x`-prefixed.
    /// Pharos does not bake the git commit at build time, so this is
    /// `"0x00000000"`. See ADR `D-node-version-v2-commit-placeholder`.
    pub commit: String,
}

#[derive(Serialize)]
pub struct VersionV2Data {
    pub beacon_node: ClientVersionV1,
    // `execution_client` is optional per the spec; omitted because pharos
    // does not call `engine_getClientVersionV1` today (see
    // `Q-node-version-v2-execution-client` in the plan).
}

#[derive(Serialize)]
pub struct VersionV2Response {
    pub data: VersionV2Data,
}

/// `GetPeerResponse` per `~/dev/beacon-APIs/apis/node/peer.yaml`.
#[derive(Serialize)]
pub struct PeerResponse {
    pub data: serde_json::Value,
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
pub async fn get_identity<E: BeaconSpec>(
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
pub async fn get_version<E: BeaconSpec>(
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

/// `GET /eth/v2/node/version`
///
/// Returns `{ "data": { "beacon_node": ClientVersionV1 } }`.
/// The `execution_client` sub-object is optional per the spec and is omitted
/// because pharos does not call `engine_getClientVersionV1` today.
///
/// The `commit` field is `"0x00000000"` because pharos does not bake a git
/// commit hash at build time (ADR `D-node-version-v2-commit-placeholder`).
///
/// Per `~/dev/beacon-APIs/apis/node/version.v2.yaml`.
pub async fn get_version_v2<E: BeaconSpec>(
    State(_state): State<Arc<ApiState<E>>>,
) -> Json<VersionV2Response> {
    Json(VersionV2Response {
        data: VersionV2Data {
            beacon_node: ClientVersionV1 {
                code: "PH".to_string(),
                name: "Pharos".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                commit: "0x00000000".to_string(),
            },
        },
    })
}

/// `GET /eth/v1/node/peers/{peer_id}`
///
/// Returns `{ "data": Peer }` on hit, 404 `{code,message}` when not found,
/// 400 when the `peer_id` is unparseable (empty string or not a valid
/// libp2p base58-encoded peer id).
///
/// Per `~/dev/beacon-APIs/apis/node/peer.yaml`.
///
/// The `Peer` object fields are sourced from the per-peer JSON values already
/// emitted by `chain.peers()`: `peer_id`, `enr`, `last_seen_p2p_address`,
/// `state`, `direction`.  Matching is a linear scan via `peer_by_id` whose
/// default impl is on `ChainStateApi` in `state.rs`.
pub async fn get_peer<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(peer_id): Path<String>,
) -> Result<Json<PeerResponse>, ApiError> {
    // Reject obviously invalid peer ids before touching the peer list.
    if peer_id.is_empty() {
        return Err(ApiError::BadRequest(format!("Invalid peer ID: {peer_id}")));
    }
    // Validate that the peer_id parses as a libp2p PeerId (base58 / base32
    // multihash).  An unparseable id should return 400 per the spec.
    if peer_id.parse::<libp2p::PeerId>().is_err() {
        return Err(ApiError::BadRequest(format!("Invalid peer ID: {peer_id}")));
    }

    let chain = Arc::clone(&state.chain);
    let peer_id_clone = peer_id.clone();
    let found = tokio::task::spawn_blocking(move || chain.peer_by_id(&peer_id_clone))
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;

    match found {
        Some(peer) => Ok(Json(PeerResponse { data: peer })),
        None => Err(ApiError::NotFound(format!("Peer not found: {peer_id}"))),
    }
}

/// `GET /eth/v1/node/syncing`
pub async fn get_syncing<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<SyncingResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        // head_slot is the slot of the node's CURRENT HEAD BLOCK (not the wall
        // clock); sync_distance = wall_slot - head_slot. A reference CL VC reads
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
pub async fn get_health<E: BeaconSpec>(State(state): State<Arc<ApiState<E>>>) -> Response {
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
pub async fn get_peers<E: BeaconSpec>(
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
pub async fn get_peer_count<E: BeaconSpec>(
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
