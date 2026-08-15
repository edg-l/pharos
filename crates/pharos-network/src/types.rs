//! Shared network types.
//!
//! Phase 0 declares the minimum shape needed by `scoring::ScoreEvent`. Phase 1
//! (Task 1.2) expands `DisconnectReason` and adds `PeerInfo` /
//! `ConnectionDirection` with the full set of fields.

use std::time::Instant;

use libp2p::{Multiaddr, PeerId};

use pharos_types::phase0::Status;

// ── Fork ──────────────────────────────────────────────────────────────────────

/// Ethereum consensus fork identifier used by the network layer.
///
/// Distinct from `pharos_types::phase0::misc::Fork` (which is a beacon-chain
/// container with `previous_version`, `current_version`, `epoch`). This enum
/// is used to tag RPC response chunks with the fork that produced them,
/// enabling the context-bytes codec dispatch per
/// `specs/altair/p2p-interface.md:445-461` and
/// `specs/bellatrix/p2p-interface.md` and
/// `specs/capella/p2p-interface.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fork {
    /// Phase 0 fork.
    Phase0,
    /// Altair fork.
    Altair,
    /// Bellatrix (merge) fork.
    Bellatrix,
    /// Capella fork.
    Capella,
}

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

// ── PeerState ─────────────────────────────────────────────────────────────────

/// Handshake and connection lifecycle state for a peer.
///
/// Transitions follow `p2p-interface.md:1352`: the dialing side MUST send
/// `Status` immediately on connection, so outbound connections move through
/// `Connecting → Handshaking → Connected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// TCP connection established; no messages exchanged yet.
    Connecting,
    /// `Status` request sent (outbound) or received (inbound); awaiting reply.
    Handshaking,
    /// `Status` exchange complete; peer is ready for use.
    Connected,
    /// Local node is closing the connection gracefully (sent `Goodbye`).
    Disconnecting,
    /// Peer is banned; all new connections will be rejected.
    Banned,
}

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// Aggregated state for a connected peer.
///
/// Held in the peer manager's `HashMap<PeerId, PeerInfo>` (Task 2.4).
/// Fields `agent_string`, `protocols`, and `observed_addr` are populated from
/// the libp2p `identify` protocol exchange per D-peer-info-shape (M3a Phase 3).
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
    /// Handshake and connection lifecycle state.
    pub state: PeerState,
    /// The peer's last known `MetaData` (populated after GetMetaData exchange).
    pub metadata: Option<pharos_types::phase0::MetaData>,
    /// Agent version string from the identify protocol (e.g. `"Lighthouse/v4.0.0"`).
    ///
    /// Populated on `NetworkEvent::PeerIdentified`; `None` before identify completes.
    pub agent_string: Option<String>,
    /// Protocol IDs advertised by the peer via the identify protocol.
    ///
    /// Each entry is a string like `"/eth2/beacon_chain/req/status/1/ssz_snappy"`.
    /// Empty before identify completes.
    pub protocols: Vec<String>,
    /// The address the peer observed for our local node, reported via identify.
    ///
    /// Useful for external address discovery. `None` before identify completes.
    pub observed_addr: Option<Multiaddr>,
}

// ── Goodbye reason codes ──────────────────────────────────────────────────────

/// Goodbye reason code: client is shutting down gracefully.
///
/// Per `p2p-interface.md:1393` Goodbye reason codes table: value 1 = ClientShutdown.
pub const GOODBYE_CLIENT_SHUTDOWN: u64 = 1;

/// Goodbye reason code: peer is on an irrelevant network (different fork).
///
/// Per `p2p-interface.md` Goodbye reason codes table: value 2 = IrrelevantNetwork.
pub const GOODBYE_IRRELEVANT_NETWORK: u64 = 2;

/// Goodbye reason code: fault/error in the peer's behaviour.
///
/// Per `p2p-interface.md` Goodbye reason codes table: value 3 = Fault/Error.
pub const GOODBYE_FAULT_ERROR: u64 = 3;

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
