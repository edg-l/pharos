//! Peer connection tracking, status state machine, and ban list.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId};
use tracing::warn;

use pharos_types::phase0::Status;

use crate::scoring::{PeerScorer, ScoreEvent};
use crate::types::{ConnectionDirection, DisconnectReason, PeerInfo, PeerState};

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
            state: PeerState::Connecting,
            metadata: None,
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

    /// Transition `peer_id` from `Connecting` → `Handshaking`.
    ///
    /// Called immediately before sending (outbound) or after receiving
    /// (inbound) the initial `Status` request.
    pub fn on_handshaking(&mut self, peer_id: PeerId) {
        if let Some(info) = self.peers.get_mut(&peer_id) {
            info.state = PeerState::Handshaking;
        } else {
            warn!(%peer_id, "on_handshaking called for unknown peer");
        }
    }

    /// Transition `peer_id` to `Connected` after a successful handshake.
    pub fn on_handshake_complete(&mut self, peer_id: PeerId) {
        if let Some(info) = self.peers.get_mut(&peer_id) {
            info.state = PeerState::Connected;
        } else {
            warn!(%peer_id, "on_handshake_complete called for unknown peer");
        }
    }

    /// Transition `peer_id` to `Disconnecting` (e.g., mismatched fork digest).
    pub fn on_disconnecting(&mut self, peer_id: PeerId) {
        if let Some(info) = self.peers.get_mut(&peer_id) {
            info.state = PeerState::Disconnecting;
        } else {
            warn!(%peer_id, "on_disconnecting called for unknown peer");
        }
    }

    /// Handle an inbound `Status` request when the fork digest matches.
    ///
    /// Atomically advances state: `Connecting → Handshaking → Connected`
    /// and records the peer's status. Called by `handle_request` in
    /// `rpc/handler.rs` for inbound Status exchanges per
    /// `p2p-interface.md:1352` (both sides MUST send Status).
    pub fn on_inbound_status(&mut self, peer_id: PeerId, status: Status) {
        self.on_handshaking(peer_id);
        self.on_status(peer_id, status);
        self.on_handshake_complete(peer_id);
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

    /// Update the cached `MetaData` for `peer_id`.
    pub fn on_metadata(&mut self, peer_id: PeerId, metadata: pharos_types::phase0::MetaData) {
        match self.peers.get_mut(&peer_id) {
            Some(info) => info.metadata = Some(metadata),
            None => {
                warn!(%peer_id, "on_metadata called for unknown peer");
            }
        }
    }

    /// Returns the stored `MetaData` seq_number for `peer_id`, or `None`.
    pub fn peer_metadata_seq(&self, peer_id: &PeerId) -> Option<u64> {
        self.peers
            .get(peer_id)
            .and_then(|info| info.metadata.as_ref())
            .map(|m| m.seq_number)
    }

    /// Returns an iterator over `PeerId`s that are in `Connected` state.
    pub fn connected_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers
            .values()
            .filter(|info| info.state == PeerState::Connected)
            .map(|info| info.peer_id)
    }

    /// Returns the current `PeerState` for `peer_id`, or `None` if unknown.
    pub fn peer_state(&self, peer_id: &PeerId) -> Option<PeerState> {
        self.peers.get(peer_id).map(|info| info.state)
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

    /// Verify the happy-path handshake: Connecting → Handshaking → Connected.
    ///
    /// This mirrors what `Network::on_swarm_connection_established` does for
    /// outbound connections: the peer starts in `Connecting`, moves to
    /// `Handshaking` when the Status request is sent, then to `Connected`
    /// after a successful fork-digest match.
    #[test]
    fn handshake_connecting_to_connected() {
        let mut mgr = make_manager();
        let peer = PeerId::random();

        mgr.on_connected(peer, ConnectionDirection::Outbound, Vec::new());
        assert_eq!(
            mgr.peers[&peer].state,
            PeerState::Connecting,
            "fresh connection must start in Connecting"
        );

        mgr.on_handshaking(peer);
        assert_eq!(
            mgr.peers[&peer].state,
            PeerState::Handshaking,
            "after sending Status must be Handshaking"
        );

        mgr.on_handshake_complete(peer);
        assert_eq!(
            mgr.peers[&peer].state,
            PeerState::Connected,
            "after successful Status exchange must be Connected"
        );
    }

    /// Verify the inbound handshake path: `Connecting → Handshaking → Connected`
    /// via the atomic `on_inbound_status` helper.
    ///
    /// This covers `p2p-interface.md:1352`: when a peer dials us and sends a
    /// `Status` request with a matching fork digest, we must advance from
    /// `Connecting` to `Connected` and record the peer's status.
    #[test]
    fn inbound_handshake_connecting_to_connected() {
        let mut mgr = make_manager();
        let peer = PeerId::random();

        mgr.on_connected(peer, ConnectionDirection::Inbound, Vec::new());
        assert_eq!(mgr.peers[&peer].state, PeerState::Connecting);

        let status = Status::default();
        mgr.on_inbound_status(peer, status.clone());

        assert_eq!(
            mgr.peers[&peer].state,
            PeerState::Connected,
            "on_inbound_status must advance inbound peer to Connected"
        );
        assert_eq!(
            mgr.peers[&peer].last_status.as_ref(),
            Some(&status),
            "on_inbound_status must record the peer's status"
        );
    }

    /// Verify the fork-digest-mismatch path: Connecting → Handshaking → Disconnecting.
    ///
    /// When the peer replies with a different fork digest, the peer manager
    /// transitions to `Disconnecting` and the network layer sends Goodbye(2).
    #[test]
    fn handshake_disconnecting_on_fork_digest_mismatch() {
        let mut mgr = make_manager();
        let peer = PeerId::random();

        mgr.on_connected(peer, ConnectionDirection::Outbound, Vec::new());
        assert_eq!(mgr.peers[&peer].state, PeerState::Connecting);

        mgr.on_handshaking(peer);
        assert_eq!(mgr.peers[&peer].state, PeerState::Handshaking);

        // Fork digest mismatch detected — move to Disconnecting.
        mgr.on_disconnecting(peer);
        assert_eq!(
            mgr.peers[&peer].state,
            PeerState::Disconnecting,
            "fork-digest mismatch must transition peer to Disconnecting"
        );
    }
}
