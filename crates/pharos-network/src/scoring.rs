//! Peer scoring: `PeerScorer` trait, `ScoreEvent` enum, and `NoopScorer`.
//!
//! Per M2 plan D-peer-scoring: the trait + event enum lock in the API surface
//! at Phase 0 so every later phase can emit events without later renames.
//! The real scoring algorithm lands in M11; M2 ships `NoopScorer`.

use libp2p::PeerId;
use libp2p::gossipsub::TopicHash;

use crate::types::DisconnectReason;

/// An event that affects a peer's score.
///
/// Plan reference: D-peer-scoring in `docs/m2-plan.md`. Every variant carries
/// the context a real scoring implementation will need; do not strip fields
/// when stubbing.
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
pub trait PeerScorer: Send + Sync + 'static {
    /// Records a score-affecting event for the given peer.
    fn record(&mut self, peer: PeerId, event: ScoreEvent);

    /// Returns the current score for the given peer (higher is better).
    fn score(&self, peer: &PeerId) -> f64;

    /// Returns the `count` lowest-scoring peer IDs.
    fn worst_peers(&self, count: usize) -> Vec<PeerId>;
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
