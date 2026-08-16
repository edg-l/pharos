//! Req-resp request and response type enums.
//!
//! Per `specs/phase0/p2p-interface.md:1303-1310`.

use pharos_types::EthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::deneb::{BlobSidecar, BlobSidecarsByRangeRequest, BlobSidecarsByRootRequest};
use pharos_types::phase0::{
    BeaconBlocksByRangeRequest, BeaconBlocksByRootRequest, ErrorMessage, MetaData, Status,
};

pub use crate::codec::MAX_PAYLOAD_SIZE;

/// Maximum number of blocks returnable in a single `BlocksByRange` or
/// `BlocksByRoot` response.
///
/// Per `specs/phase0/p2p-interface.md:228`.
pub const MAX_REQUEST_BLOCKS: u64 = 1024;

/// Maximum number of `LightClientUpdate` objects per range request.
///
/// Per `specs/altair/light-client/p2p-interface.md:35`.
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

/// Maximum number of blocks in a `BeaconBlocksByRange` / `BeaconBlocksByRoot`
/// request in Deneb and later.
///
/// Per `specs/deneb/p2p-interface.md` (`MAX_REQUEST_BLOCKS_DENEB = 128`).
pub const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;

/// Maximum number of blob sidecars returnable in a single request.
///
/// `compute_max_request_blob_sidecars() = MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK`
/// = 128 * 6 = 768.
///
/// Per `specs/deneb/p2p-interface.md`.
pub const MAX_REQUEST_BLOB_SIDECARS: u64 = 768;

// ── MetaDataResponse ──────────────────────────────────────────────────────────

/// A `MetaData` response carrying either v1 (Phase-0) or v2 (Altair) metadata.
///
/// Dual-handle per `D-metadata-v2-dual-handle`: inbound v1 streams receive
/// `V1`; inbound v2 streams receive `V2`. The handler selects by the protocol
/// ID that multistream-select negotiated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetaDataResponse {
    /// Phase-0 metadata — served when the inbound stream negotiated
    /// `/eth2/beacon_chain/req/metadata/1/ssz_snappy`.
    V1(MetaData),
    /// Altair metadata (adds `syncnets`) — served when the inbound stream
    /// negotiated `/eth2/beacon_chain/req/metadata/2/ssz_snappy`.
    V2(AltairMetaData),
}

// ── LightClient request types ─────────────────────────────────────────────────

/// Request body for `LightClientBootstrap`.
///
/// Carries the trusted block root.  Per
/// `specs/altair/light-client/p2p-interface.md:56-68`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientBootstrapRequest(pub pharos_types::phase0::primitives::Root);

/// Request body for `LightClientUpdatesByRange`.
///
/// Per `specs/altair/light-client/p2p-interface.md:70-86`.
/// `count` is clamped to `MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128` on receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientUpdatesByRangeRequest {
    /// First sync-committee period to return.
    pub start_period: u64,
    /// Number of periods to return (clamped to `MAX_REQUEST_LIGHT_CLIENT_UPDATES`).
    pub count: u64,
}

// ── RpcRequest ────────────────────────────────────────────────────────────────

/// An inbound or outbound Ethereum CL req-resp request.
#[derive(Debug, Clone)]
pub enum RpcRequest {
    /// Status handshake — `p2p-interface.md:1321`.
    Status(Status),
    /// Goodbye notification — `p2p-interface.md:1380`. Carries the reason code.
    Goodbye(u64),
    /// Ping — `p2p-interface.md:1408`. Carries the local `seq_number`.
    Ping(u64),
    /// MetaData request (v2) — `p2p-interface.md:1494`. No body on the wire.
    MetaData,
    /// MetaData request (v1) — legacy protocol. No body on the wire.
    MetaDataV1,
    /// Beacon blocks by slot range — `p2p-interface.md:1545`.
    BlocksByRange(BeaconBlocksByRangeRequest),
    /// Beacon blocks by block root — `p2p-interface.md:1579`.
    BlocksByRoot(BeaconBlocksByRootRequest<MAX_REQUEST_BLOCKS>),
    /// Request a `LightClientBootstrap` for a trusted block root.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:56-68`.
    LightClientBootstrap(LightClientBootstrapRequest),
    /// Request a range of `LightClientUpdate` objects.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:70-86`.
    LightClientUpdatesByRange(LightClientUpdatesByRangeRequest),
    /// Request the latest `LightClientFinalityUpdate`.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:88-101`. No body.
    LightClientFinalityUpdate,
    /// Request the latest `LightClientOptimisticUpdate`.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:103-116`. No body.
    LightClientOptimisticUpdate,
    /// Blob sidecars by slot range.
    ///
    /// Per `specs/deneb/p2p-interface.md` (`BlobSidecarsByRange v1`).
    BlobSidecarsByRange(BlobSidecarsByRangeRequest),
    /// Blob sidecars by block root and blob index.
    ///
    /// Request body is a bare `List[BlobIdentifier, MAX_REQUEST_BLOB_SIDECARS]`
    /// (single-field rule, no container offset — identical trap to `D-blocksbyroot-bare-list`).
    ///
    /// Per `specs/deneb/p2p-interface.md` (`BlobSidecarsByRoot v1`).
    BlobSidecarsByRoot(BlobSidecarsByRootRequest<MAX_REQUEST_BLOB_SIDECARS>),
}

// ── RpcResponse ───────────────────────────────────────────────────────────────

/// An inbound or outbound Ethereum CL req-resp response.
///
/// Generic over `EthSpec` because `BlocksByRange` / `BlocksByRoot` / light-client
/// responses carry preset-stamped types.
pub enum RpcResponse<E: EthSpec> {
    /// Status response.
    Status(Status),
    /// Goodbye acknowledgement — carries the echoed reason code.
    Goodbye(u64),
    /// Ping response — carries the responder's `seq_number`.
    Ping(u64),
    /// MetaData response — v1 or v2 depending on negotiated protocol.
    MetaData(MetaDataResponse),
    /// Beacon blocks by range — zero or more blocks.
    BlocksByRange(Vec<E::SignedBeaconBlock>),
    /// Beacon blocks by root — zero or more blocks.
    BlocksByRoot(Vec<E::SignedBeaconBlock>),
    /// `LightClientBootstrap` response.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:56-68`.
    LightClientBootstrap(E::AltairLightClientBootstrap),
    /// Zero or more `LightClientUpdate` objects for a period range.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:70-86`.
    LightClientUpdatesByRange(Vec<E::AltairLightClientUpdate>),
    /// Latest `LightClientFinalityUpdate`.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:88-101`.
    LightClientFinalityUpdate(E::AltairLightClientFinalityUpdate),
    /// Latest `LightClientOptimisticUpdate`.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:103-116`.
    LightClientOptimisticUpdate(E::AltairLightClientOptimisticUpdate),
    /// Blob sidecars by range or by root — zero or more `BlobSidecar` objects.
    ///
    /// Per `specs/deneb/p2p-interface.md`.
    BlobSidecars(Vec<BlobSidecar>),
    /// Error chunk (result code 1/2/3) with an `ErrorMessage` payload.
    Error { code: u8, message: ErrorMessage },
}

// Manual Clone; derive cannot express `E::SignedBeaconBlock: Clone` without
// the bound living on the impl, not the struct.
impl<E: EthSpec> Clone for RpcResponse<E>
where
    E::SignedBeaconBlock: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Status(s) => Self::Status(s.clone()),
            Self::Goodbye(v) => Self::Goodbye(*v),
            Self::Ping(v) => Self::Ping(*v),
            Self::MetaData(m) => Self::MetaData(m.clone()),
            Self::BlocksByRange(v) => Self::BlocksByRange(v.clone()),
            Self::BlocksByRoot(v) => Self::BlocksByRoot(v.clone()),
            Self::LightClientBootstrap(b) => Self::LightClientBootstrap(b.clone()),
            Self::LightClientUpdatesByRange(v) => Self::LightClientUpdatesByRange(v.clone()),
            Self::LightClientFinalityUpdate(u) => Self::LightClientFinalityUpdate(u.clone()),
            Self::LightClientOptimisticUpdate(u) => Self::LightClientOptimisticUpdate(u.clone()),
            Self::BlobSidecars(v) => Self::BlobSidecars(v.clone()),
            Self::Error { code, message } => Self::Error {
                code: *code,
                message: message.clone(),
            },
        }
    }
}

impl<E: EthSpec> std::fmt::Debug for RpcResponse<E>
where
    E::SignedBeaconBlock: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(s) => f.debug_tuple("Status").field(s).finish(),
            Self::Goodbye(v) => f.debug_tuple("Goodbye").field(v).finish(),
            Self::Ping(v) => f.debug_tuple("Ping").field(v).finish(),
            Self::MetaData(m) => f.debug_tuple("MetaData").field(m).finish(),
            Self::BlocksByRange(v) => f.debug_tuple("BlocksByRange").field(v).finish(),
            Self::BlocksByRoot(v) => f.debug_tuple("BlocksByRoot").field(v).finish(),
            Self::LightClientBootstrap(_) => f.debug_tuple("LightClientBootstrap").finish(),
            Self::LightClientUpdatesByRange(_) => {
                f.debug_tuple("LightClientUpdatesByRange").finish()
            }
            Self::LightClientFinalityUpdate(_) => {
                f.debug_tuple("LightClientFinalityUpdate").finish()
            }
            Self::LightClientOptimisticUpdate(_) => {
                f.debug_tuple("LightClientOptimisticUpdate").finish()
            }
            Self::BlobSidecars(v) => f
                .debug_tuple("BlobSidecars")
                .field(&format!("[{} sidecars]", v.len()))
                .finish(),
            Self::Error { code, message } => f
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}
