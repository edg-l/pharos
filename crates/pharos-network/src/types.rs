//! Shared network types.
//!
//! Phase 0 declares the minimum shape needed by `scoring::ScoreEvent`. Phase 1
//! (Task 1.2) expands `DisconnectReason` and adds `PeerInfo` /
//! `ConnectionDirection` with the full set of fields.

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
