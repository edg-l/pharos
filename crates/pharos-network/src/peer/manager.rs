//! Peer connection tracking, status state machine, and ban list.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId};
use tracing::warn;

use pharos_types::phase0::Status;

use crate::scoring::{PeerScorer, ScoreEvent};
use crate::types::{ConnectionDirection, DisconnectReason, PeerInfo};

// ── PeerManager ───────────────────────────────────────────────────────────────

/// Tracks connected peers, records score events, and enforces ban decisions.
pub struct PeerManager<S: PeerScorer> {
    /// Currently connected peers and their state.
    peers: HashMap<PeerId, PeerInfo>,
    /// Banned peers and the `Instant` at which the ban expires.
    banned: HashMap<PeerId, Instant>,
    /// Pluggable peer scorer.
    scorer: S,
    /// Hard cap on connected peers.
    max_peers: usize,
    /// Desired steady-state connected peer count.
    target_peers: usize,
}

impl<S: PeerScorer> PeerManager<S> {
    /// Create a new `PeerManager` with the given scorer and peer limits.
    pub fn new(scorer: S, max_peers: usize, target_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            banned: HashMap::new(),
            scorer,
            max_peers,
            target_peers,
        }
    }

    // ── Connection lifecycle ──────────────────────────────────────────────────

    /// Record a new connection for `peer_id`.
    ///
    /// Inserts a fresh `PeerInfo` with `connected_since = Some(Instant::now())`,
    /// `last_status = None`, and `enr = None`, then records a
    /// `ScoreEvent::PeerConnected` with the scorer.
    pub fn on_connected(
        &mut self,
        peer_id: PeerId,
        dir: ConnectionDirection,
        addrs: Vec<Multiaddr>,
    ) {
        let info = PeerInfo {
            peer_id,
            addrs,
            enr: None,
            connected_since: Some(Instant::now()),
            last_status: None,
            direction: dir,
        };
        self.peers.insert(peer_id, info);
        self.scorer.record(peer_id, ScoreEvent::PeerConnected);
    }

    /// Record a peer disconnection.
    ///
    /// Removes `peer_id` from the connected-peer map and records a
    /// `ScoreEvent::PeerDisconnected` with the scorer.
    pub fn on_disconnected(&mut self, peer_id: PeerId, reason: DisconnectReason) {
        self.peers.remove(&peer_id);
        self.scorer
            .record(peer_id, ScoreEvent::PeerDisconnected { reason });
    }

    /// Update the cached `Status` for `peer_id`.
    ///
    /// Logs a warning and returns early if the peer is not in the connected
    /// map (e.g., the status message arrived after the connection was dropped).
    pub fn on_status(&mut self, peer_id: PeerId, status: Status) {
        match self.peers.get_mut(&peer_id) {
            Some(info) => info.last_status = Some(status),
            None => {
                warn!(%peer_id, "on_status called for unknown peer");
            }
        }
    }

    // ── Scoring ───────────────────────────────────────────────────────────────

    /// Forward a score-affecting event to the scorer.
    pub fn record_event(&mut self, peer_id: PeerId, event: ScoreEvent) {
        self.scorer.record(peer_id, event);
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /// Return the `PeerId`s that should be pruned to reach `target_peers`.
    ///
    /// Delegates to `scorer.worst_peers(excess)` where
    /// `excess = peers.len().saturating_sub(target_peers)`.
    pub fn should_prune(&self) -> Vec<PeerId> {
        let excess = self.peers.len().saturating_sub(self.target_peers);
        self.scorer.worst_peers(excess)
    }

    // ── Ban list ──────────────────────────────────────────────────────────────

    /// Returns `true` if `peer_id` has an active (non-expired) ban.
    ///
    /// Expired bans are not cleaned up in this method; they will remain in
    /// the map until `ban` is called again or the manager is restarted.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        match self.banned.get(peer_id) {
            Some(expires_at) => *expires_at > Instant::now(),
            None => false,
        }
    }

    /// Ban `peer_id` for `duration`, removing them from connected peers if present.
    pub fn ban(&mut self, peer_id: PeerId, duration: Duration) {
        let expires_at = Instant::now() + duration;
        self.banned.insert(peer_id, expires_at);
        self.peers.remove(&peer_id);
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Returns the number of currently connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the maximum peer cap.
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::NoopScorer;

    fn make_manager() -> PeerManager<NoopScorer> {
        PeerManager::new(NoopScorer, 10, 2)
    }

    /// Register 5 peers, ban one, then verify:
    /// - `is_banned` returns true for the banned peer, false for all others.
    /// - `peer_count` equals 4 (the banned peer was removed from `peers`).
    /// - `should_prune()` with `NoopScorer` always returns an empty Vec,
    ///   because `NoopScorer::worst_peers` is a no-op stub.
    ///   This test verifies the wiring, not pruning semantics; real pruning
    ///   semantics arrive with the real scorer in M11.
    #[test]
    fn peer_manager_ban_and_prune_wiring() {
        let mut mgr = make_manager();

        // Connect 5 peers.
        let peers: Vec<PeerId> = (0..5).map(|_| PeerId::random()).collect();
        for &peer_id in &peers {
            mgr.on_connected(peer_id, ConnectionDirection::Outbound, Vec::new());
        }
        assert_eq!(mgr.peer_count(), 5);

        // Ban the first peer for 60 seconds.
        let banned_peer = peers[0];
        mgr.ban(banned_peer, Duration::from_secs(60));

        // Banned peer is removed from connected peers.
        assert_eq!(
            mgr.peer_count(),
            4,
            "banned peer must be removed from peers map"
        );

        // is_banned returns true for the banned peer.
        assert!(mgr.is_banned(&banned_peer), "banned_peer should be banned");

        // is_banned returns false for all other peers.
        for peer_id in &peers[1..] {
            assert!(
                !mgr.is_banned(peer_id),
                "non-banned peer should not be banned"
            );
        }

        // should_prune: peers.len()=4, target_peers=2, so excess=2.
        // NoopScorer::worst_peers always returns Vec::new(), so should_prune is empty.
        let prune = mgr.should_prune();
        assert!(
            prune.is_empty(),
            "NoopScorer never produces prune candidates; wiring test only"
        );
    }
}
