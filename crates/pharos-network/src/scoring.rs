//! Peer scoring: `PeerScorer` trait, `ScoreEvent` enum, `NoopScorer`, and the
//! real `RealScorer`.
//!
//! Per M2 plan D-peer-scoring: the trait + event enum lock in the API surface
//! at Phase 0 so every later phase can emit events without later renames.
//! The real scoring algorithm lands in M11 (`RealScorer`, this file).
//!
//! ## Score model (M11 Phase 10)
//!
//! Each peer carries three additive score components, mirroring the gossipsub
//! v1.1 score-decomposition (cite: libp2p gossipsub v1.1 spec, "Peer Scoring"):
//!
//! - **gossip** — mesh behaviour (accepts reward, rejects/ignores/slow penalise).
//! - **req_resp** — request/response behaviour (success rewards, error/timeout/
//!   rate-limit-exceeded penalise).
//! - **app** — application-specific long-term component (handshake failures,
//!   subnet non-propagation, banned reconnects). This is the durable component
//!   the Phase 14 persistence layer will save.
//!
//! `score(peer) = gossip + req_resp + app`, with each component lazily decayed
//! toward 0 on read.
//!
//! ## Decay model (M11 Phase 10 task 1 decision)
//!
//! **Lazy decay on `score()`** (plan option (a), preferred per
//! `docs/m11-phase0-findings.md`). Each peer stores a `last_decay: Instant`.
//! On every `score()` / `record()` we apply exponential decay
//! `component *= DECAY_PER_SECOND.powf(elapsed_secs)` before using or mutating
//! the value, then reset `last_decay` to now. No `tick` method is added to the
//! `PeerScorer` trait, so the swarm loop (Phase 11) carries no decay-driver
//! dependency. The trait stays unchanged and `NoopScorer` keeps working.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use libp2p::gossipsub::TopicHash;

use crate::types::DisconnectReason;

/// An event that affects a peer's score.
///
/// Plan reference: D-peer-scoring in `docs/m2-plan.md`, extended for the M11
/// Phase 10/11 signals (`SlowPeer`, `RateLimitExceeded`, `SubnetNonPropagation`,
/// `UnsubscribedFromExpectedSubnet`). Every variant carries the context a real
/// scoring implementation needs; do not strip fields when stubbing.
#[derive(Debug, Clone)]
pub enum ScoreEvent {
    /// A gossip message from this peer was accepted by the validator.
    GossipAccept { topic: TopicHash },
    /// A gossip message from this peer was rejected by the validator.
    GossipReject { topic: TopicHash, reason: String },
    /// A gossip message from this peer was ignored (validator returned Ignore).
    GossipIgnore { topic: TopicHash, reason: String },
    /// A successful RPC exchange with this peer.
    RpcSuccess { method: RpcMethod },
    /// An RPC call returned an error from this peer.
    RpcError {
        method: RpcMethod,
        kind: RpcErrorKind,
    },
    /// An RPC call to this peer timed out.
    RpcTimeout { method: RpcMethod },
    /// A handshake with this peer failed.
    HandshakeFail { kind: HandshakeFailKind },
    /// The peer was newly connected.
    PeerConnected,
    /// The peer disconnected.
    PeerDisconnected { reason: DisconnectReason },
    /// A connection was rejected because the peer is banned.
    BannedPeerConnected,
    /// gossipsub reported the peer cannot download messages in time
    /// (`gossipsub::Event::SlowPeer`). `failed_messages` is the total count of
    /// failed deliveries, used as penalty severity (M11 Phase 0 finding).
    SlowPeer { failed_messages: usize },
    /// The peer issued more req-resp requests than its per-method token bucket
    /// allows (M11 Phase 10/11). Carries the offending method.
    RateLimitExceeded { method: RpcMethod },
    /// The peer is subscribed to an expected subnet but never propagated a
    /// message on it within the coverage window (M11 Phase 10 task 5).
    SubnetNonPropagation { topic: TopicHash },
    /// The peer left the mesh for a subnet we expected it to serve
    /// (`gossipsub::Event::Unsubscribed` on an expected subnet, M11 Phase 0).
    UnsubscribedFromExpectedSubnet { topic: TopicHash },
}

/// RPC methods tracked for scoring purposes.
///
/// Light-client variants added per `specs/altair/p2p-interface.md:445-461`.
/// Handlers land in Phase 6; variant declarations are here so Phase 5 compiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcMethod {
    Status,
    Goodbye,
    Ping,
    MetaData,
    /// `metadata/1/ssz_snappy` — phase-0 MetaData (v1 fallback per D-metadata-v2-dual-handle).
    MetaDataV1,
    BlocksByRange,
    BlocksByRoot,
    /// `light_client_bootstrap/1/ssz_snappy` — `specs/altair/light-client/p2p-interface.md`.
    LightClientBootstrap,
    /// `light_client_updates_by_range/1/ssz_snappy` — `specs/altair/light-client/p2p-interface.md`.
    LightClientUpdatesByRange,
    /// `light_client_finality_update/1/ssz_snappy` — `specs/altair/light-client/p2p-interface.md`.
    LightClientFinalityUpdate,
    /// `light_client_optimistic_update/1/ssz_snappy` — `specs/altair/light-client/p2p-interface.md`.
    LightClientOptimisticUpdate,
    /// `blob_sidecars_by_range/1/ssz_snappy` — `specs/deneb/p2p-interface.md`.
    BlobSidecarsByRange,
    /// `blob_sidecars_by_root/1/ssz_snappy` — `specs/deneb/p2p-interface.md`.
    BlobSidecarsByRoot,
}

/// Kinds of RPC error that affect scoring.
///
/// Timeout is modelled as the top-level [`ScoreEvent::RpcTimeout`] variant,
/// not as a `Timeout` kind here, deviating from the M2 plan. Do not add a
/// `Timeout` variant; emit `RpcTimeout` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcErrorKind {
    InvalidRequest,
    ServerError,
    ResourceUnavailable,
    Decode,
    StreamReset,
}

/// Reasons a handshake can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFailKind {
    ForkDigestMismatch,
    IrrelevantNetwork,
    Timeout,
    Decode,
}

/// Trait implemented by peer scorers.
///
/// The network layer records `ScoreEvent`s via this trait; the scorer decides
/// how to translate them into a numeric score. Peer-manager consumers use
/// `score()` to rank peers for eviction.
///
/// `Send + Sync + 'static` so a single scorer can be shared across the Swarm
/// task and any peer-manager helper tasks (M11 work will likely wrap it in
/// `Arc<RwLock<_>>`).
///
/// Decay is lazy-on-read (M11 Phase 10 task 1 decision); the trait carries no
/// `tick`/time method so consumers never have to drive a decay cadence.
pub trait PeerScorer: Send + Sync + 'static {
    /// Records a score-affecting event for the given peer.
    fn record(&mut self, peer: PeerId, event: ScoreEvent);

    /// Returns the current score for the given peer (higher is better).
    fn score(&self, peer: &PeerId) -> f64;

    /// Returns the `count` lowest-scoring peer IDs.
    fn worst_peers(&self, count: usize) -> Vec<PeerId>;

    /// True if the peer's current score is at or below the ban threshold.
    ///
    /// The default returns `false` (a no-op scorer never bans). `RealScorer`
    /// overrides this to compare against [`BAN_THRESHOLD`] (M11 Phase 11).
    fn is_banned(&self, _peer: &PeerId) -> bool {
        false
    }

    /// True if the peer's current score is at or below the disconnect threshold
    /// (but not necessarily a ban candidate).
    ///
    /// The default returns `false`. `RealScorer` overrides this to compare
    /// against [`DISCONNECT_THRESHOLD`] (M11 Phase 11).
    fn should_disconnect(&self, _peer: &PeerId) -> bool {
        false
    }

    /// Per-peer/per-method req-resp rate limiting (M11 Phase 11 task 2).
    ///
    /// Consumes one token from the peer's bucket for `method`; returns `false`
    /// when the bucket is empty (the caller should reject / penalise the
    /// request). The default always allows (a no-op scorer imposes no limit).
    fn allow_request(&mut self, _peer: PeerId, _method: RpcMethod) -> bool {
        true
    }

    /// The earliest [`Instant`] at which a (re)dial of this peer is allowed
    /// (M11 Phase 11 task 3 dial backoff). The default returns [`Instant::now`]
    /// (dial always allowed).
    fn next_dial_allowed(&self, _peer: &PeerId) -> Instant {
        Instant::now()
    }

    /// Records a failed dial attempt, advancing exponential backoff. The
    /// default is a no-op (a no-op scorer tracks no backoff).
    fn record_dial_failure(&mut self, _peer: PeerId) {}

    /// Clears dial-backoff state after a successful dial. Default no-op.
    fn record_dial_success(&mut self, _peer: PeerId) {}
}

/// A no-op scorer that returns 0.0 for all peers and never prunes.
///
/// Useful in tests and as a placeholder until a real scorer is wired.
pub struct NoopScorer;

impl PeerScorer for NoopScorer {
    fn record(&mut self, _peer: PeerId, _event: ScoreEvent) {}

    fn score(&self, _peer: &PeerId) -> f64 {
        0.0
    }

    fn worst_peers(&self, _count: usize) -> Vec<PeerId> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// RealScorer
// ---------------------------------------------------------------------------

/// Per-second multiplicative decay applied to every score component. A value
/// of 0.99 means roughly 1% of the magnitude bleeds off per second, so a single
/// penalty halves in ~69 s and is effectively gone after a few minutes. Mirrors
/// the gossipsub v1.1 `DecayInterval`-style exponential decay.
pub const DECAY_PER_SECOND: f64 = 0.99;

/// Below this total score a peer is a ban candidate (graylist threshold in
/// gossipsub v1.1 terms). The peer-manager prunes/bans peers below this.
pub const BAN_THRESHOLD: f64 = -100.0;

/// Below this total score a peer should be disconnected but not banned
/// (gossip/publish-threshold region in gossipsub v1.1).
pub const DISCONNECT_THRESHOLD: f64 = -50.0;

// --- gossip-component event weights ---
const W_GOSSIP_ACCEPT: f64 = 1.0;
const W_GOSSIP_IGNORE: f64 = -1.0;
const W_GOSSIP_REJECT: f64 = -10.0;
/// Per failed message reported by `SlowPeer`.
const W_SLOW_PEER_PER_MSG: f64 = -1.0;

// --- req-resp-component event weights ---
const W_RPC_SUCCESS: f64 = 1.0;
const W_RPC_ERROR: f64 = -5.0;
const W_RPC_TIMEOUT: f64 = -5.0;
const W_RATE_LIMIT_EXCEEDED: f64 = -10.0;

// --- app-component event weights ---
const W_HANDSHAKE_FAIL: f64 = -20.0;
const W_BANNED_RECONNECT: f64 = -50.0;
const W_SUBNET_NON_PROPAGATION: f64 = -20.0;
const W_UNSUBSCRIBED_EXPECTED_SUBNET: f64 = -10.0;

/// Per-peer token-bucket capacity per req-resp method, derived from the
/// p2p-interface "two-level token/leaky bucket" guidance
/// (`specs/phase0/p2p-interface.md` §"What is a typical rate limiting
/// strategy?"). Capacity is the burst allowance; `refill_per_second` is the
/// steady-state rate. Values are conservative per-peer defaults.
const fn rate_limit_for(method: RpcMethod) -> (f64, f64) {
    // (capacity, refill_per_second)
    match method {
        // Cheap control-plane messages: small steady allowance.
        RpcMethod::Status
        | RpcMethod::Goodbye
        | RpcMethod::Ping
        | RpcMethod::MetaData
        | RpcMethod::MetaDataV1 => (5.0, 1.0),
        // Bulk data requests are expensive; tighter buckets.
        RpcMethod::BlocksByRange
        | RpcMethod::BlocksByRoot
        | RpcMethod::BlobSidecarsByRange
        | RpcMethod::BlobSidecarsByRoot => (10.0, 2.0),
        // Light-client requests: moderate allowance.
        RpcMethod::LightClientBootstrap
        | RpcMethod::LightClientUpdatesByRange
        | RpcMethod::LightClientFinalityUpdate
        | RpcMethod::LightClientOptimisticUpdate => (8.0, 1.0),
    }
}

/// Base dial-backoff interval; the backoff for failure `n` is
/// `DIAL_BACKOFF_BASE * 2^(n-1)`, capped at [`DIAL_BACKOFF_MAX`].
const DIAL_BACKOFF_BASE: Duration = Duration::from_secs(2);
/// Maximum exponential dial backoff.
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(512);

/// A single token bucket for per-peer/per-method req-resp rate limiting.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_second: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: now,
        }
    }

    /// Refills the bucket for the elapsed interval, then attempts to consume one
    /// token. Returns true if a token was available (request allowed).
    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Dial-backoff state for a single peer.
#[derive(Debug, Clone)]
struct DialBackoff {
    failures: u32,
    next_allowed: Instant,
}

/// Per-peer mutable scoring state.
#[derive(Debug, Clone)]
struct PeerState {
    gossip: f64,
    req_resp: f64,
    app: f64,
    last_decay: Instant,
    buckets: HashMap<RpcMethod, TokenBucket>,
    backoff: DialBackoff,
}

impl PeerState {
    fn new(now: Instant) -> Self {
        Self {
            gossip: 0.0,
            req_resp: 0.0,
            app: 0.0,
            last_decay: now,
            buckets: HashMap::new(),
            backoff: DialBackoff {
                failures: 0,
                next_allowed: now,
            },
        }
    }

    /// Applies lazy exponential decay for the elapsed interval since the last
    /// touch, then advances `last_decay` to `now`.
    fn decay(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_decay).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let factor = DECAY_PER_SECOND.powf(elapsed);
        self.gossip *= factor;
        self.req_resp *= factor;
        self.app *= factor;
        self.last_decay = now;
    }

    fn total(&self) -> f64 {
        self.gossip + self.req_resp + self.app
    }
}

/// The real peer scorer (M11 Phase 10).
///
/// Maintains a per-peer additive score with lazy exponential decay on read,
/// plus per-peer/per-method req-resp token buckets and exponential dial
/// backoff. Drop-in for [`NoopScorer`] behind the [`PeerScorer`] trait.
pub struct RealScorer {
    peers: HashMap<PeerId, PeerState>,
}

impl Default for RealScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl RealScorer {
    /// Creates an empty scorer.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    fn entry(&mut self, peer: PeerId, now: Instant) -> &mut PeerState {
        self.peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(now))
    }

    /// Records an event for the peer at an explicit time. Public test seam; the
    /// trait method [`PeerScorer::record`] delegates here with `Instant::now()`.
    pub fn record_at(&mut self, peer: PeerId, event: ScoreEvent, now: Instant) {
        let state = self.entry(peer, now);
        state.decay(now);
        match event {
            ScoreEvent::GossipAccept { .. } => state.gossip += W_GOSSIP_ACCEPT,
            ScoreEvent::GossipIgnore { .. } => state.gossip += W_GOSSIP_IGNORE,
            ScoreEvent::GossipReject { .. } => state.gossip += W_GOSSIP_REJECT,
            ScoreEvent::SlowPeer { failed_messages } => {
                state.gossip += W_SLOW_PEER_PER_MSG * failed_messages as f64;
            }
            ScoreEvent::RpcSuccess { .. } => state.req_resp += W_RPC_SUCCESS,
            ScoreEvent::RpcError { .. } => state.req_resp += W_RPC_ERROR,
            ScoreEvent::RpcTimeout { .. } => state.req_resp += W_RPC_TIMEOUT,
            ScoreEvent::RateLimitExceeded { .. } => state.req_resp += W_RATE_LIMIT_EXCEEDED,
            ScoreEvent::HandshakeFail { .. } => state.app += W_HANDSHAKE_FAIL,
            ScoreEvent::BannedPeerConnected => state.app += W_BANNED_RECONNECT,
            ScoreEvent::SubnetNonPropagation { .. } => state.app += W_SUBNET_NON_PROPAGATION,
            ScoreEvent::UnsubscribedFromExpectedSubnet { .. } => {
                state.app += W_UNSUBSCRIBED_EXPECTED_SUBNET;
            }
            // Connection lifecycle events are score-neutral; they exist so the
            // peer-manager can register/forget a peer.
            ScoreEvent::PeerConnected | ScoreEvent::PeerDisconnected { .. } => {}
        }
    }

    /// Returns the decayed score for a peer at an explicit time. Public test
    /// seam; [`PeerScorer::score`] delegates here with `Instant::now()`.
    pub fn score_at(&self, peer: &PeerId, now: Instant) -> f64 {
        match self.peers.get(peer) {
            None => 0.0,
            Some(state) => {
                let mut tmp = state.clone();
                tmp.decay(now);
                tmp.total()
            }
        }
    }

    /// True if the peer's current score is at or below the ban threshold.
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.score(peer) <= BAN_THRESHOLD
    }

    /// True if the peer's current score is at or below the disconnect threshold
    /// (but not necessarily a ban candidate).
    pub fn should_disconnect(&self, peer: &PeerId) -> bool {
        self.score(peer) <= DISCONNECT_THRESHOLD
    }

    /// Per-peer/per-method req-resp rate limiting (Phase 10 task 3). Consumes
    /// one token from the peer's bucket for `method`; returns false when the
    /// bucket is empty (request should be rejected / penalised by the caller).
    pub fn allow_request(&mut self, peer: PeerId, method: RpcMethod) -> bool {
        self.allow_request_at(peer, method, Instant::now())
    }

    /// [`allow_request`](Self::allow_request) at an explicit time (test seam).
    pub fn allow_request_at(&mut self, peer: PeerId, method: RpcMethod, now: Instant) -> bool {
        let state = self.entry(peer, now);
        let bucket = state.buckets.entry(method).or_insert_with(|| {
            let (capacity, refill) = rate_limit_for(method);
            TokenBucket::new(capacity, refill, now)
        });
        bucket.try_consume(now)
    }

    /// Records a failed dial attempt, advancing exponential backoff
    /// (Phase 10 task 4).
    pub fn record_dial_failure(&mut self, peer: PeerId) {
        self.record_dial_failure_at(peer, Instant::now());
    }

    /// [`record_dial_failure`](Self::record_dial_failure) at an explicit time.
    pub fn record_dial_failure_at(&mut self, peer: PeerId, now: Instant) {
        let state = self.entry(peer, now);
        state.backoff.failures = state.backoff.failures.saturating_add(1);
        let shift = state.backoff.failures - 1;
        let backoff = DIAL_BACKOFF_BASE
            .checked_mul(1u32.checked_shl(shift.min(31)).unwrap_or(u32::MAX))
            .unwrap_or(DIAL_BACKOFF_MAX)
            .min(DIAL_BACKOFF_MAX);
        state.backoff.next_allowed = now + backoff;
    }

    /// Clears dial-backoff state after a successful dial.
    pub fn record_dial_success(&mut self, peer: PeerId) {
        let now = Instant::now();
        let state = self.entry(peer, now);
        state.backoff.failures = 0;
        state.backoff.next_allowed = now;
    }

    /// The earliest `Instant` at which a (re)dial of this peer is allowed
    /// (Phase 10 task 4). For an unknown peer this is `now` (dial allowed).
    pub fn next_dial_allowed(&self, peer: &PeerId) -> Instant {
        match self.peers.get(peer) {
            Some(state) => state.backoff.next_allowed,
            None => Instant::now(),
        }
    }

    /// Forgets all state for a peer (e.g. on permanent removal).
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }
}

impl PeerScorer for RealScorer {
    fn record(&mut self, peer: PeerId, event: ScoreEvent) {
        self.record_at(peer, event, Instant::now());
    }

    fn score(&self, peer: &PeerId) -> f64 {
        self.score_at(peer, Instant::now())
    }

    fn worst_peers(&self, count: usize) -> Vec<PeerId> {
        let now = Instant::now();
        let mut scored: Vec<(PeerId, f64)> = self
            .peers
            .keys()
            .map(|p| (*p, self.score_at(p, now)))
            .collect();
        scored.sort_by(|a, b| a.1.total_cmp(&b.1));
        scored.into_iter().take(count).map(|(p, _)| p).collect()
    }

    fn is_banned(&self, peer: &PeerId) -> bool {
        RealScorer::is_banned(self, peer)
    }

    fn should_disconnect(&self, peer: &PeerId) -> bool {
        RealScorer::should_disconnect(self, peer)
    }

    fn allow_request(&mut self, peer: PeerId, method: RpcMethod) -> bool {
        RealScorer::allow_request(self, peer, method)
    }

    fn next_dial_allowed(&self, peer: &PeerId) -> Instant {
        RealScorer::next_dial_allowed(self, peer)
    }

    fn record_dial_failure(&mut self, peer: PeerId) {
        RealScorer::record_dial_failure(self, peer)
    }

    fn record_dial_success(&mut self, peer: PeerId) {
        RealScorer::record_dial_success(self, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        // Deterministic distinct PeerIds for ordering tests.
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        let kp = libp2p::identity::Keypair::ed25519_from_bytes(bytes).unwrap();
        PeerId::from(kp.public())
    }

    fn topic() -> TopicHash {
        TopicHash::from_raw("test_topic")
    }

    #[test]
    fn score_decays_over_time() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(1);
        // A strong negative event.
        scorer.record_at(
            p,
            ScoreEvent::GossipReject {
                topic: topic(),
                reason: "x".into(),
            },
            t0,
        );
        let immediate = scorer.score_at(&p, t0);
        assert!(immediate < 0.0, "reject should produce a negative score");
        // After 60 s the magnitude must have shrunk toward 0.
        let later = scorer.score_at(&p, t0 + Duration::from_secs(60));
        assert!(
            later > immediate,
            "score must decay toward 0: later {later} should exceed immediate {immediate}"
        );
        assert!(
            later < 0.0,
            "60 s is not enough to fully recover from a reject"
        );
        // After a long time it is effectively gone.
        let much_later = scorer.score_at(&p, t0 + Duration::from_secs(3600));
        assert!(
            much_later.abs() < 0.1,
            "score should decay to ~0 after an hour, got {much_later}"
        );
    }

    #[test]
    fn crosses_ban_threshold_after_n_negative_events() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(2);
        assert!(!scorer.is_banned(&p), "fresh peer is not banned");
        // Each reject is -10; need > 10 to cross -100. Apply at the same instant
        // so decay does not interfere.
        for _ in 0..11 {
            scorer.record_at(
                p,
                ScoreEvent::GossipReject {
                    topic: topic(),
                    reason: "bad".into(),
                },
                t0,
            );
        }
        assert!(
            scorer.score_at(&p, t0) <= BAN_THRESHOLD,
            "11 rejects (-110) must cross the ban threshold"
        );
    }

    #[test]
    fn positive_events_recover_score() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(3);
        scorer.record_at(
            p,
            ScoreEvent::RpcTimeout {
                method: RpcMethod::Status,
            },
            t0,
        );
        let after_penalty = scorer.score_at(&p, t0);
        assert!(after_penalty < 0.0);
        for _ in 0..10 {
            scorer.record_at(
                p,
                ScoreEvent::RpcSuccess {
                    method: RpcMethod::Status,
                },
                t0,
            );
        }
        let recovered = scorer.score_at(&p, t0);
        assert!(
            recovered > after_penalty,
            "successes must raise the score back up"
        );
        assert!(
            recovered >= 0.0,
            "10 successes (+10) should outweigh one timeout (-5)"
        );
    }

    #[test]
    fn worst_peers_orders_ascending() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let good = peer(10);
        let mid = peer(11);
        let bad = peer(12);
        scorer.record_at(good, ScoreEvent::GossipAccept { topic: topic() }, t0);
        scorer.record_at(good, ScoreEvent::GossipAccept { topic: topic() }, t0);
        scorer.record_at(
            mid,
            ScoreEvent::GossipIgnore {
                topic: topic(),
                reason: "m".into(),
            },
            t0,
        );
        scorer.record_at(
            bad,
            ScoreEvent::GossipReject {
                topic: topic(),
                reason: "b".into(),
            },
            t0,
        );
        let worst = scorer.worst_peers(3);
        assert_eq!(worst.len(), 3);
        assert_eq!(worst[0], bad, "lowest score first");
        assert_eq!(worst[2], good, "highest score last");
        // Subset request returns just the worst.
        let worst1 = scorer.worst_peers(1);
        assert_eq!(worst1, vec![bad]);
    }

    #[test]
    fn rate_limit_token_bucket_refills() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(20);
        let m = RpcMethod::BlocksByRange; // capacity 10, refill 2/s
        // Drain the full burst capacity.
        for i in 0..10 {
            assert!(
                scorer.allow_request_at(p, m, t0),
                "burst request {i} within capacity must be allowed"
            );
        }
        // Bucket now empty.
        assert!(
            !scorer.allow_request_at(p, m, t0),
            "11th request exhausts the bucket"
        );
        // After 1 s at 2 tokens/s, two more are allowed.
        let t1 = t0 + Duration::from_secs(1);
        assert!(scorer.allow_request_at(p, m, t1), "first refilled token");
        assert!(scorer.allow_request_at(p, m, t1), "second refilled token");
        assert!(
            !scorer.allow_request_at(p, m, t1),
            "only 2 tokens refilled in 1 s"
        );
    }

    #[test]
    fn dial_backoff_exponential() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(30);
        // Unknown peer: dial allowed now.
        assert!(scorer.next_dial_allowed(&p) <= Instant::now());
        scorer.record_dial_failure_at(p, t0);
        let b1 = scorer.next_dial_allowed(&p).saturating_duration_since(t0);
        assert_eq!(b1, DIAL_BACKOFF_BASE, "first failure = base backoff");
        scorer.record_dial_failure_at(p, t0);
        let b2 = scorer.next_dial_allowed(&p).saturating_duration_since(t0);
        assert_eq!(b2, DIAL_BACKOFF_BASE * 2, "second failure doubles");
        scorer.record_dial_failure_at(p, t0);
        let b3 = scorer.next_dial_allowed(&p).saturating_duration_since(t0);
        assert_eq!(b3, DIAL_BACKOFF_BASE * 4, "third failure quadruples");
        // Backoff is capped.
        for _ in 0..20 {
            scorer.record_dial_failure_at(p, t0);
        }
        let capped = scorer.next_dial_allowed(&p).saturating_duration_since(t0);
        assert_eq!(capped, DIAL_BACKOFF_MAX, "backoff saturates at the cap");
    }

    #[test]
    fn subnet_non_propagation_penalised() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(40);
        let baseline = scorer.score_at(&p, t0);
        scorer.record_at(p, ScoreEvent::SubnetNonPropagation { topic: topic() }, t0);
        let after = scorer.score_at(&p, t0);
        assert!(
            after < baseline,
            "subnet non-propagation must lower the score"
        );
        assert_eq!(
            after, W_SUBNET_NON_PROPAGATION,
            "app-component penalty applied"
        );
    }

    #[test]
    fn unsubscribed_from_expected_subnet_penalised() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(41);
        scorer.record_at(
            p,
            ScoreEvent::UnsubscribedFromExpectedSubnet { topic: topic() },
            t0,
        );
        assert_eq!(scorer.score_at(&p, t0), W_UNSUBSCRIBED_EXPECTED_SUBNET);
    }

    #[test]
    fn slow_peer_penalty_scales_with_failed_messages() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(42);
        scorer.record_at(p, ScoreEvent::SlowPeer { failed_messages: 5 }, t0);
        assert_eq!(scorer.score_at(&p, t0), W_SLOW_PEER_PER_MSG * 5.0);
    }

    #[test]
    fn rate_limit_exceeded_penalises_req_resp() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(43);
        scorer.record_at(
            p,
            ScoreEvent::RateLimitExceeded {
                method: RpcMethod::BlocksByRoot,
            },
            t0,
        );
        assert_eq!(scorer.score_at(&p, t0), W_RATE_LIMIT_EXCEEDED);
    }

    #[test]
    fn realscorer_is_drop_in_for_noopscorer() {
        // Compile-time/behavioural check that RealScorer satisfies PeerScorer.
        fn use_scorer<S: PeerScorer>(mut s: S, p: PeerId) -> f64 {
            s.record(p, ScoreEvent::PeerConnected);
            s.score(&p)
        }
        let p = peer(50);
        assert_eq!(use_scorer(RealScorer::new(), p), 0.0);
        assert_eq!(use_scorer(NoopScorer, p), 0.0);
    }

    #[test]
    fn dial_success_resets_backoff() {
        let mut scorer = RealScorer::new();
        let t0 = Instant::now();
        let p = peer(60);
        scorer.record_dial_failure_at(p, t0);
        scorer.record_dial_failure_at(p, t0);
        assert!(scorer.next_dial_allowed(&p) > t0);
        scorer.record_dial_success(p);
        // Next failure restarts at the base interval.
        let t1 = Instant::now();
        scorer.record_dial_failure_at(p, t1);
        let b = scorer.next_dial_allowed(&p).saturating_duration_since(t1);
        assert_eq!(b, DIAL_BACKOFF_BASE, "success resets the failure count");
    }
}
