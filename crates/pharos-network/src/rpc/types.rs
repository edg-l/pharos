//! Req-resp request and response type enums.
//!
//! Per `specs/phase0/p2p-interface.md:1303-1310`.

use pharos_types::EthSpec;
use pharos_types::phase0::{
    BeaconBlocksByRangeRequest, BeaconBlocksByRootRequest, ErrorMessage, MetaData, Status,
};

pub use crate::codec::MAX_PAYLOAD_SIZE;

/// Maximum number of blocks returnable in a single `BlocksByRange` or
/// `BlocksByRoot` response.
///
/// Per `specs/phase0/p2p-interface.md:228`.
pub const MAX_REQUEST_BLOCKS: u64 = 1024;

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
    /// MetaData request — `p2p-interface.md:1494`. No body on the wire.
    MetaData,
    /// Beacon blocks by slot range — `p2p-interface.md:1545`.
    BlocksByRange(BeaconBlocksByRangeRequest),
    /// Beacon blocks by block root — `p2p-interface.md:1579`.
    BlocksByRoot(BeaconBlocksByRootRequest<MAX_REQUEST_BLOCKS>),
}

// ── RpcResponse ───────────────────────────────────────────────────────────────

/// An inbound or outbound Ethereum CL req-resp response.
///
/// Generic over `EthSpec` because `BlocksByRange` / `BlocksByRoot` responses
/// carry `E::SignedBeaconBlock` values.
pub enum RpcResponse<E: EthSpec> {
    /// Status response.
    Status(Status),
    /// Goodbye acknowledgement — carries the echoed reason code.
    Goodbye(u64),
    /// Ping response — carries the responder's `seq_number`.
    Ping(u64),
    /// MetaData response.
    MetaData(MetaData),
    /// Beacon blocks by range — zero or more blocks.
    BlocksByRange(Vec<E::SignedBeaconBlock>),
    /// Beacon blocks by root — zero or more blocks.
    BlocksByRoot(Vec<E::SignedBeaconBlock>),
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
            Self::Error { code, message } => f
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}
