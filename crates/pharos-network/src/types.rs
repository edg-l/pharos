//! Shared network types.
//!
//! Phase 0 declares the minimum shape needed by `scoring::ScoreEvent`. Phase 1
//! (Task 1.2) expands `DisconnectReason` and adds `PeerInfo` /
//! `ConnectionDirection` with the full set of fields.

use std::time::Instant;

use libp2p::{Multiaddr, PeerId};

use pharos_types::phase0::Status;

// ── SubnetId ──────────────────────────────────────────────────────────────────

/// Attestation subnet identifier (0..ATTESTATION_SUBNET_COUNT).
///
/// The u64 type matches the `SubnetID` type alias used throughout the p2p spec.
pub type SubnetId = u64;

// ── ForkDigest ────────────────────────────────────────────────────────────────

/// Re-export of `pharos_types::phase0::primitives::ForkDigest`.
///
/// A 4-byte fork digest computed per `specs/phase0/p2p-interface.md:269-285`.
/// Aliased here so network-layer code can use `crate::types::ForkDigest`
/// without depending on `pharos-types` paths directly.
pub use pharos_types::phase0::primitives::ForkDigest;

// ── ConnectionDirection ───────────────────────────────────────────────────────

/// Whether a connection was initiated by the local node or a remote peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// The local node dialled the remote peer.
    Outbound,
    /// The remote peer dialled the local node.
    Inbound,
}

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// Aggregated state for a connected peer.
///
/// Held in the peer manager's `HashMap<PeerId, PeerInfo>` (Task 2.4).
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The libp2p peer identifier.
    pub peer_id: PeerId,
    /// Known listen addresses for this peer.
    pub addrs: Vec<Multiaddr>,
    /// The peer's ENR, if obtained via discv5.
    pub enr: Option<discv5::Enr>,
    /// When the connection was established.
    pub connected_since: Option<Instant>,
    /// The last `Status` message received from this peer.
    pub last_status: Option<Status>,
    /// Whether the local or remote side initiated the connection.
    pub direction: ConnectionDirection,
}

// ── DisconnectReason ──────────────────────────────────────────────────────────

/// Reason a peer connection was terminated.
///
/// Phase 0 carries only the variants needed by `ScoreEvent::PeerDisconnected`.
/// Phase 1 (Task 1.2) extends this with the full per-spec set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Peer sent a `Goodbye` message with the given reason code.
    Goodbye(u64),
    /// Local timeout waiting on the peer.
    Timeout,
    /// Peer's fork digest did not match ours.
    IrrelevantNetwork,
    /// Peer was pruned by the scorer.
    ScorerLow,
    /// Local node is shutting down.
    Shutdown,
    /// Other / unclassified reason.
    Other(String),
}
