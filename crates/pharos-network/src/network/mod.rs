//! Core network task: `Network` struct and `NetworkBuilder`.
//!
//! `Network` owns the libp2p `Swarm`, the discv5 `DiscoveryService`, and the
//! `PeerManager`. `NetworkBuilder` constructs the full stack.
//!
//! Transport construction follows the libp2p 0.56 `SwarmBuilder` typed
//! pipeline (see `transport` module).  Cite:
//! <https://docs.rs/libp2p/0.56.0/libp2p/struct.SwarmBuilder.html>

pub mod behaviour;
pub mod transport;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use futures::StreamExt as _;
use libp2p::core::ConnectedPoint;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance, TopicHash};
use libp2p::identify;
use libp2p::identity::Keypair;
use libp2p::noise;
use libp2p::ping;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::ConnectionError;
use libp2p::{PeerId, Swarm, SwarmBuilder};
use pharos_ssz::Bitvector;
use pharos_types::EthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::phase0::Status as BeaconStatus;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, interval, timeout};

use discv5::enr::EnrKey as _;

use crate::codec::snappy_block::{decode_snappy_block, encode_snappy_block};
use crate::discovery::enr::{Enr, enr_to_dial_multiaddr};
use crate::discovery::handle::{DiscoveryCommand, DiscoveryHandle, discovery_channel};
use crate::discovery::service::{DiscoveryConfig, DiscoveryService, query_interval};
use crate::discovery::subnets::compute_subscribed_subnets;
use crate::error::NetworkError;
use crate::gossip::config::gossipsub_behaviour;
use crate::gossip::{
    dispatch_gossip_message, subscribe_altair_extra_topics, subscribe_base_topics,
    subscribe_deneb_blob_topics,
};
use crate::handle::NetworkHandle;
use crate::host::{
    BlobProvider, GOSSIP_REASON_PARENT_UNSEEN, GossipVerdict, Host, LightClientProvider,
};
use crate::peer::manager::PeerManager;
use crate::rpc::handler::handle_request;
use crate::rpc::types::{RpcRequest, RpcResponse};
use crate::scoring::{HandshakeFailKind, PeerScorer, RpcErrorKind, RpcMethod, ScoreEvent};
use crate::topics::{GossipTopic, GossipTopicKind, is_subnet_topic, topic_kind_name};
use crate::types::{
    ConnectionDirection, GOODBYE_CLIENT_SHUTDOWN, GOODBYE_FAULT_ERROR, GOODBYE_IRRELEVANT_NETWORK,
    PeerState,
};
use pharos_utils::metrics::{
    METRIC_GOSSIP_MSG_TOTAL, METRIC_PEER_SCORE, METRIC_RPC_LATENCY_SECONDS,
};

use behaviour::{PharosBehaviour, PharosBehaviourEvent};

// ── Scoring enforcement constants (M11 Phase 11) ──────────────────────────────

/// How long a peer banned for crossing the scorer ban threshold stays blocked
/// from reconnecting. Mirrors the gossipsub-v1.1 graylist-recovery horizon.
const SCORE_BAN_DURATION: std::time::Duration = std::time::Duration::from_secs(600);

/// Upper bound of each peer-score gauge bucket (M11 Phase 11 task 4). Scores at
/// or below a bound fall in that bucket; scores above the last bound fall in the
/// overflow bucket (`ALL_SCORE_BUCKET_LABELS` last entry).
const SCORE_BUCKETS: [f64; 4] = [
    crate::scoring::BAN_THRESHOLD,        // <= -100 : ban region
    crate::scoring::DISCONNECT_THRESHOLD, // <= -50  : disconnect region
    0.0,                                  // <= 0    : negative-but-tolerated
    50.0,                                 // <= 50   : healthy
];

/// Gauge bucket labels, one per `SCORE_BUCKETS` bound plus a trailing overflow
/// bucket for scores above the last bound.
const ALL_SCORE_BUCKET_LABELS: [&str; SCORE_BUCKETS.len() + 1] =
    ["banned", "disconnect", "negative", "healthy", "excellent"];

/// Index of the bucket a `score` falls into, for `ALL_SCORE_BUCKET_LABELS`.
fn score_bucket_index(score: f64) -> usize {
    for (idx, &bound) in SCORE_BUCKETS.iter().enumerate() {
        if score <= bound {
            return idx;
        }
    }
    SCORE_BUCKETS.len()
}

/// Bucket label a `score` falls into (M11 Phase 11 task 4 gauge label).
fn score_bucket_label(score: f64) -> &'static str {
    ALL_SCORE_BUCKET_LABELS[score_bucket_index(score)]
}

// ── Commands and Events ───────────────────────────────────────────────────────

/// Commands sent from `NetworkHandle` to the `Network` event loop.
pub enum NetworkCommand<E: EthSpec> {
    /// Publish an SSZ+snappy-encoded payload to the given gossipsub topic.
    Publish {
        topic: GossipTopic,
        /// Raw SSZ bytes; the network task snappy-frames before publishing.
        ssz_payload: Vec<u8>,
        /// Resolves with the assigned `MessageId` or an error.
        reply: oneshot::Sender<Result<gossipsub::MessageId, NetworkError>>,
    },
    /// Subscribe to an additional gossipsub topic at runtime.
    Subscribe {
        topic: GossipTopic,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Unsubscribe from a gossipsub topic at runtime.
    ///
    /// Used by the fork-migration loop to drop phase-0 topics after crossing
    /// `ALTAIR_FORK_EPOCH`. Per `specs/phase0/p2p-interface.md:1670-1672`.
    Unsubscribe {
        topic: GossipTopic,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Update the local node's `MetaData` (Altair v2).
    ///
    /// Swaps the cached `AltairMetaData` in `Network::host_metadata` and
    /// increments `seq_number` if the `attnets` or `syncnets` fields changed.
    /// Used by the subnet-rotation driver (Task 7.1) and the fork-migration
    /// loop (Task 7.3).
    UpdateMetaData(AltairMetaData),
    /// Dial a remote peer by multiaddr.
    Dial {
        addr: libp2p::Multiaddr,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Disconnect from a peer.
    Disconnect { peer_id: PeerId },
    /// Send an outbound RPC request; resolves via `reply`.
    OutgoingRequest {
        peer: PeerId,
        req: RpcRequest,
        reply: oneshot::Sender<Result<RpcResponse<E>, NetworkError>>,
    },
    /// Request a clean shutdown of the network task.
    Shutdown,
    /// Return the `PeerId` with the highest `head_slot` among connected peers
    /// that have completed the Status handshake.  Returns `None` when no such
    /// peers exist.  Used by the backfill driver to pick the best peer for a
    /// `BeaconBlocksByRange` request.
    PickHighestHeadPeer {
        reply: oneshot::Sender<Option<PeerId>>,
    },
    /// Return a cloned snapshot of every known peer's `PeerInfo`.
    ///
    /// Serves the Beacon API `/eth/v1/node/peers` and `/eth/v1/node/peer_count`
    /// endpoints. The consumer maps `PeerInfo` to the beacon-API peer JSON.
    ListPeers {
        reply: oneshot::Sender<Vec<crate::types::PeerInfo>>,
    },
}

/// Events emitted from the `Network` event loop to external consumers.
///
/// Note: inbound RPC requests are NOT forwarded as events. The `Host<E>` trait
/// owns inbound RPC dispatch (see `rpc::handler::handle_request`). Forwarding
/// inbound requests as events would couple the network task to a consumer queue
/// and require reworking the Phase 5/6/8 architecture. Amendment recorded in
/// `docs/m2-plan.md` (Amendment 2026-05-22).
pub enum NetworkEvent {
    /// A peer connected and completed the handshake.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId, crate::types::DisconnectReason),
    /// A gossip message was received and accepted.
    GossipMessage {
        topic: GossipTopic,
        peer: PeerId,
        data: Vec<u8>,
    },
    /// The swarm successfully bound a new listener address.
    ///
    /// Emitted once per `listen_on` call when the OS assigns the actual port.
    /// Consumers waiting on the real bound address (e.g. integration tests
    /// using OS-assigned port 0) should wait for this event before dialling.
    NewListenAddr(libp2p::Multiaddr),
    /// The local node's signed ENR.
    ///
    /// Emitted once at startup, immediately before the main event loop begins.
    /// Integration tests that need the real discv5 ENR (e.g. to pass as a
    /// bootnode to another test node) wait for this event.
    LocalEnr(crate::discovery::enr::Enr),
    /// The network task has shut down.
    Shutdown,

    // ── M3a Phase 3 events (deferred from M2 audit, D-network-event-surface) ──
    /// A remote peer subscribed to one of our known gossipsub topics.
    ///
    /// Deferred from M2 audit (D-network-event-surface); implemented in M3a
    /// Phase 3. Only emitted when the topic hash resolves against the local
    /// `topic_map`; unknown-topic subscriptions are silently dropped.
    PeerSubscribed { peer: PeerId, topic: GossipTopic },

    /// A remote peer unsubscribed from one of our known gossipsub topics.
    ///
    /// Deferred from M2 audit (D-network-event-surface); implemented in M3a
    /// Phase 3. Only emitted when the topic hash resolves against the local
    /// `topic_map`; unknown-topic unsubscriptions are silently dropped.
    PeerUnsubscribed { peer: PeerId, topic: GossipTopic },

    /// The identify protocol completed for a peer; `info` contains the updated
    /// peer metadata (agent version, protocol list, observed address).
    ///
    /// Deferred from M2 audit (D-network-event-surface); implemented in M3a
    /// Phase 3. Only emitted when the peer is already in the connected-peer map;
    /// identify events for unknown peers are dropped (D-peer-info-shape:
    /// identify-flood mitigation by per-peer overwrite).
    ///
    /// `info` is boxed to keep the `NetworkEvent` enum size reasonable
    /// (`PeerInfo` is large relative to the other variants).
    PeerIdentified {
        peer: PeerId,
        info: Box<crate::types::PeerInfo>,
    },

    /// An outbound dial attempt failed.
    ///
    /// Deferred from M2 audit (D-network-event-surface); implemented in M3a
    /// Phase 3. `peer` is `None` when the peer identity was not yet known at
    /// dial time (dial-failed-pre-identity case per D-network-event-surface).
    DialFailed { peer: Option<PeerId>, error: String },

    /// The swarm confirmed a new external address for the local node.
    ///
    /// Deferred from M2 audit (D-network-event-surface); implemented in M3a
    /// Phase 3. ENR update is deferred to M3b (cross-fork ENR migration).
    ExternalAddrConfirmed { address: libp2p::Multiaddr },

    /// A `beacon_block` gossip message was IGNOREd because its parent has not
    /// been seen (RB6).
    ///
    /// `data` is the snappy-decompressed SSZ bytes of the signed beacon block.
    /// `topic` carries the fork-digest so the consumer can select the correct
    /// fork variant when decoding via `decode_block_by_topic`.  `peer` is the
    /// forwarding (propagation-source) peer.
    ///
    /// Emitted by the network dispatcher so the lookup loop (Phase 4) can fetch
    /// the missing parent by root and replay the orphaned block on import.
    UnknownParentBlock {
        topic: GossipTopic,
        peer: PeerId,
        data: Vec<u8>,
    },

    /// A validated `blob_sidecar_{subnet_id}` gossip message.
    ///
    /// Emitted after `validate_blob_sidecar` returns `Accept`.  The consumer
    /// (Phase 5 `run_blob_ingestion_loop`) persists the sidecar and re-injects
    /// the parent block when all sidecars for a slot are complete.
    ///
    /// `subnet` is the gossip subnet the message arrived on.
    /// `data` is the snappy-decompressed SSZ bytes of the `BlobSidecar`.
    GossipBlobSidecar {
        subnet: crate::types::SubnetId,
        peer: PeerId,
        data: Vec<u8>,
    },
}

impl NetworkEvent {
    /// Returns the variant name as a static string.
    ///
    /// Used in structured warn logs (D-network-backpressure) to identify which
    /// event was dropped when the consumer is stalled, without allocating.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::PeerConnected(_) => "PeerConnected",
            Self::PeerDisconnected(_, _) => "PeerDisconnected",
            Self::GossipMessage { .. } => "GossipMessage",
            Self::NewListenAddr(_) => "NewListenAddr",
            Self::LocalEnr(_) => "LocalEnr",
            Self::Shutdown => "Shutdown",
            Self::PeerSubscribed { .. } => "PeerSubscribed",
            Self::PeerUnsubscribed { .. } => "PeerUnsubscribed",
            Self::PeerIdentified { .. } => "PeerIdentified",
            Self::DialFailed { .. } => "DialFailed",
            Self::ExternalAddrConfirmed { .. } => "ExternalAddrConfirmed",
            Self::UnknownParentBlock { .. } => "UnknownParentBlock",
            Self::GossipBlobSidecar { .. } => "GossipBlobSidecar",
        }
    }
}

// ── Network ───────────────────────────────────────────────────────────────────

/// TTL for entries in `Network::pending_dials`.
///
/// When an addr-only bootnode dial fails, `OutgoingConnectionError.peer_id` is
/// `None`, so the `OutgoingConnectionError` arm cannot clear the entry by
/// `PeerId`.  The sweep in `discovery_tick` removes any entry older than this
/// duration so a peer is never permanently blocked from re-dial.  30 s matches
/// the discovery tick interval, so every peer gets at most one extra tick of
/// suppression beyond the actual dial timeout.
const DIAL_PENDING_TTL: Duration = Duration::from_secs(30);

/// The running network task.
///
/// Constructed via `NetworkBuilder::build`.  Call `run()` to drive the
/// event loop.  Shut down by sending `NetworkCommand::Shutdown` via the
/// `NetworkHandle` or by dropping the handle's `shutdown_tx`.
pub struct Network<E: EthSpec, H: Host<E> + LightClientProvider<E> + BlobProvider<E>, S: PeerScorer>
{
    swarm: Swarm<PharosBehaviour<E>>,
    discovery: DiscoveryService,
    peer_manager: PeerManager<S>,
    host: Arc<H>,
    /// Cached local `MetaData` (Altair v2) for lock-free reads by RPC handlers.
    ///
    /// Initialised from `host.local_metadata()` at build time. Updated via
    /// `NetworkCommand::UpdateMetaData` which is issued by the subnet-rotation
    /// driver whenever the `attnets` or `syncnets` bitvectors change.
    host_metadata: Arc<ArcSwap<AltairMetaData>>,
    /// Maps subscribed topic hashes to their parsed `GossipTopic` for dispatch.
    topic_map: HashMap<TopicHash, GossipTopic>,
    command_rx: mpsc::Receiver<NetworkCommand<E>>,
    /// Inbound commands from `DiscoveryHandle`.
    ///
    /// Polled in the main select loop alongside `command_rx`. Commands are
    /// forwarded to `DiscoveryService::handle_discovery_command`.
    discovery_cmd_rx: mpsc::Receiver<DiscoveryCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    /// Configured capacity of the `event_tx` channel.
    ///
    /// Stored here so `emit_event` can include it in the drop-warning log
    /// per D-network-backpressure.
    event_channel_capacity: usize,
    discovery_tick: Interval,
    shutdown_signal: oneshot::Receiver<()>,
    /// Pending outbound RPC requests: maps `(method, OutboundRequestId)` to the
    /// originating method and the oneshot channel to resolve.
    ///
    /// The key MUST include `RpcMethod`: each per-method `request_response::Behaviour`
    /// has an INDEPENDENT `OutboundRequestId` counter, so a `BlocksByRange` request
    /// and a `BlocksByRoot` request both receive `OutboundRequestId(1)`. Keying by
    /// the id alone collides them, cross-delivering responses (a ByRoot response
    /// resolving a ByRange caller). Keying by `(method, id)` is globally unique.
    #[allow(clippy::type_complexity)]
    pending_rpc: HashMap<
        (RpcMethod, OutboundRequestId),
        (
            RpcMethod,
            oneshot::Sender<Result<RpcResponse<E>, NetworkError>>,
        ),
    >,
    /// Outbound Status requests sent as part of the connection handshake.
    ///
    /// Maps `OutboundRequestId` → `PeerId`.  When the Status response arrives
    /// in `on_request_response_event`, if the request id is in this map we
    /// perform the fork-digest check and complete (or abort) the handshake.
    pending_status_checks: HashMap<OutboundRequestId, PeerId>,
    /// Outbound Ping requests sent for keepalive purposes.
    ///
    /// Maps `OutboundRequestId` → `PeerId`.  On response, if the peer's
    /// seq_number is newer than our stored value, a follow-up `GetMetaData`
    /// is sent.
    pending_ping_checks: HashMap<OutboundRequestId, PeerId>,
    /// Outbound GetMetaData requests sent after a Ping seq-number mismatch.
    ///
    /// Maps `OutboundRequestId` → `PeerId`.  On response, updates the peer
    /// manager's stored metadata for that peer.
    pending_metadata_fetches: HashMap<OutboundRequestId, PeerId>,
    /// Fires every 15 seconds to drive `Ping` keepalives.
    ping_tick: Interval,
    /// Fires every 30 seconds to drive score-based peer pruning.
    score_prune_tick: Interval,
    /// Bootstrap ENRs; dialed once at startup to seed the peer table.
    bootnodes: Vec<Enr>,
    /// In-flight dial dedup set.
    ///
    /// Maps a `PeerId` to the `Instant` the dial was initiated.  A peer is
    /// skipped in `dial_peer` if it already has an entry here, is already
    /// connected, or is in a post-connect peer-manager state.  Entries are
    /// cleared in three places:
    ///   1. `on_swarm_connection_established` — connection succeeded.
    ///   2. `OutgoingConnectionError` arm — dial failed with a known `PeerId`.
    ///   3. `discovery_tick` TTL sweep — self-heals entries from addr-only
    ///      bootnode dial failures where `OutgoingConnectionError.peer_id=None`
    ///      cannot key into this map.
    pending_dials: HashMap<PeerId, Instant>,
    /// Gossip validation tasks dispatched via `spawn_blocking`.
    ///
    /// Each task returns `(verdict, propagation_source, message_id, topic,
    /// ssz_bytes, message)` so the main select loop can report the result
    /// to gossipsub, score the peer, and emit events without re-acquiring
    /// the data from the now-dropped task scope.
    #[allow(clippy::type_complexity)]
    gossip_tasks: tokio::task::JoinSet<(
        GossipVerdict,
        PeerId,
        gossipsub::MessageId,
        GossipTopic,
        Vec<u8>,
        gossipsub::Message,
    )>,
    _phantom: PhantomData<E>,
}

impl<
    E: EthSpec,
    H: Host<E> + LightClientProvider<E> + BlobProvider<E> + Send + Sync + 'static,
    S: PeerScorer,
> Network<E, H, S>
{
    /// Attempt an outbound dial to `peer_id` at `addr`, deduplicating concurrent dials.
    ///
    /// Returns `true` if a new dial was initiated, `false` if the dial was
    /// suppressed because one of the following is true:
    ///   - a dial to `peer_id` is already in flight (`pending_dials`),
    ///   - `peer_id` is already connected at the swarm level, or
    ///   - the peer manager already tracks `peer_id` in `Connecting`,
    ///     `Handshaking`, or `Connected` state.
    ///
    /// On a synchronous dial error the entry is immediately removed from
    /// `pending_dials` so the peer is not permanently blocked.
    pub fn dial_peer(&mut self, peer_id: PeerId, addr: libp2p::Multiaddr) -> bool {
        if self.pending_dials.contains_key(&peer_id) {
            tracing::debug!(%peer_id, "dial suppressed: already in pending_dials");
            return false;
        }
        if self.swarm.is_connected(&peer_id) {
            tracing::debug!(%peer_id, "dial suppressed: already connected");
            return false;
        }
        if matches!(
            self.peer_manager.peer_state(&peer_id),
            Some(PeerState::Connecting | PeerState::Handshaking | PeerState::Connected)
        ) {
            tracing::debug!(%peer_id, "dial suppressed: peer_manager state precludes re-dial");
            return false;
        }
        // Exponential dial backoff (M11 Phase 11 task 3): a peer that has
        // repeatedly failed to dial is held off until its backoff window
        // elapses. `NoopScorer` returns `now`, so this never suppresses.
        if self.peer_manager.next_dial_allowed(&peer_id) > Instant::now() {
            tracing::debug!(%peer_id, "dial suppressed: dial backoff window not yet elapsed");
            return false;
        }
        self.pending_dials.insert(peer_id, Instant::now());
        match self.swarm.dial(addr.clone()) {
            Ok(()) => true,
            Err(e) => {
                self.pending_dials.remove(&peer_id);
                tracing::debug!(error = %e, %peer_id, "dial failed synchronously");
                false
            }
        }
    }

    /// Drive the network event loop.
    ///
    /// Returns when a `NetworkCommand::Shutdown` is received or when
    /// the shutdown signal fires.
    pub async fn run(mut self) -> Result<(), NetworkError> {
        // Emit the local ENR once before the select loop so that consumers
        // waiting on `NetworkEvent::LocalEnr` (e.g. integration tests that
        // need the discv5 ENR with the real bound UDP port) can proceed.
        let local_enr = self.discovery.local_enr();
        self.emit_event(NetworkEvent::LocalEnr(local_enr)).await;

        // Dial bootnodes directly at startup.  discv5 FINDNODE against a fresh
        // bootnode with an empty routing table may return nothing, so we dial
        // bootnodes unconditionally via libp2p to seed the connection table.
        // Routed through dial_peer so that a simultaneous discovery-tick dial
        // to the same bootnode (which may fire within milliseconds) is deduped.
        let mut booted = 0u32;
        for enr in &self.bootnodes.clone() {
            let addr = match enr_to_dial_multiaddr(enr) {
                Some(a) => a,
                None => {
                    tracing::debug!(enr = %enr, "bootnode ENR has no dialable address; skipping");
                    continue;
                }
            };
            // Extract the PeerId embedded by enr_to_dial_multiaddr (/p2p/<pid>).
            let peer_id = match addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                    Some(pid)
                } else {
                    None
                }
            }) {
                Some(pid) => pid,
                None => {
                    tracing::debug!(addr = %addr, "bootnode multiaddr has no /p2p component; skipping");
                    continue;
                }
            };
            if self.dial_peer(peer_id, addr.clone()) {
                booted += 1;
                tracing::debug!(addr = %addr, "dialing bootnode");
            }
        }
        if booted > 0 {
            tracing::info!(count = booted, "dialed bootnodes at startup");
        }

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.on_swarm_event(event).await;
                }
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(NetworkCommand::Shutdown) | None => {
                            self.shutdown_goodbye().await;
                            break;
                        }
                        Some(cmd) => self.on_command(cmd),
                    }
                }
                dcmd = self.discovery_cmd_rx.recv() => {
                    if let Some(dcmd) = dcmd {
                        self.discovery.handle_discovery_command(dcmd);
                    }
                }
                _ = self.discovery_tick.tick() => {
                    // Sweep stale pending_dials entries before dialing new peers.
                    // Addr-only bootnode dial failures report peer_id=None in
                    // OutgoingConnectionError, so those entries cannot be cleared
                    // in the error arm.  This TTL sweep self-heals them so a peer
                    // is never permanently blocked from re-dial.
                    self.pending_dials.retain(|_, t| t.elapsed() < DIAL_PENDING_TTL);

                    // Run a discv5 FINDNODE query and dial any discovered peers.
                    let peers = self.discovery.find_peers().await;
                    let discovered = peers.len();
                    let mut dialed = 0u32;
                    for enr in peers {
                        let addr = match enr_to_dial_multiaddr(&enr) {
                            Some(a) => a,
                            None => {
                                tracing::debug!(
                                    enr = %enr,
                                    "discovered ENR has no dialable address; skipping"
                                );
                                continue;
                            }
                        };
                        // Extract the PeerId from the /p2p/<pid> component appended
                        // by enr_to_dial_multiaddr.  If absent, skip (no key to dedup on).
                        let peer_id = match addr.iter().find_map(|p| {
                            if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                                Some(pid)
                            } else {
                                None
                            }
                        }) {
                            Some(pid) => pid,
                            None => {
                                tracing::debug!(addr = %addr, "discovered peer addr has no /p2p component; skipping dial");
                                continue;
                            }
                        };
                        if self.dial_peer(peer_id, addr.clone()) {
                            dialed += 1;
                            tracing::debug!(addr = %addr, "dialing discovered peer");
                        }
                    }

                    // Reschedule discovery based on current deficit (M11 Phase 12
                    // task 3): large deficit → short interval, at/above target → slow.
                    let next = query_interval(
                        self.peer_manager.peer_count(),
                        self.peer_manager.target_peers(),
                    );
                    self.discovery_tick.reset_after(next);
                    tracing::debug!(discovered, dialed, interval_secs = next.as_secs(), "discovery tick complete");
                }
                _ = self.ping_tick.tick() => {
                    self.tick_ping();
                }
                _ = self.score_prune_tick.tick() => {
                    self.tick_score_prune();
                }
                Some(join_result) = self.gossip_tasks.join_next() => {
                    match join_result {
                        Ok((verdict, propagation_source, message_id, topic, ssz_bytes, message)) => {
                            // --- same logic as current lines 770-846 ---
                            // Convert verdict to gossipsub MessageAcceptance.
                            let score_event;
                            let acceptance = match &verdict {
                                GossipVerdict::Accept => {
                                    score_event = ScoreEvent::GossipAccept {
                                        topic: message.topic.clone(),
                                    };
                                    MessageAcceptance::Accept
                                }
                                GossipVerdict::Reject(reason) => {
                                    score_event = ScoreEvent::GossipReject {
                                        topic: message.topic.clone(),
                                        reason: reason.clone(),
                                    };
                                    MessageAcceptance::Reject
                                }
                                GossipVerdict::Ignore(reason) => {
                                    score_event = ScoreEvent::GossipIgnore {
                                        topic: message.topic.clone(),
                                        reason: reason.clone(),
                                    };
                                    MessageAcceptance::Ignore
                                }
                            };

                            // Report validation result to gossipsub.
                            if !self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .report_message_validation_result(&message_id, &propagation_source, acceptance)
                            {
                                tracing::debug!(%message_id, "report_message_validation_result returned false (message not in cache)");
                            }

                            // Increment gossip message counter for accepted messages.
                            // Label by topic kind name (e.g. "beacon_block").
                            // ADR cite: `D-metrics-prometheus-optin` (Phase 5).
                            if matches!(&verdict, GossipVerdict::Accept) {
                                let topic_label = topic_kind_name(&topic.kind);
                                metrics::counter!(
                                    METRIC_GOSSIP_MSG_TOTAL,
                                    "topic" => topic_label
                                )
                                .increment(1);
                            }

                            // Emit topic-specific events for accepted and selected-ignore messages.
                            match &verdict {
                                GossipVerdict::Accept => {
                                    if let GossipTopicKind::BlobSidecar(subnet) = topic.kind {
                                        self.emit_event(NetworkEvent::GossipBlobSidecar {
                                            subnet,
                                            peer: propagation_source,
                                            data: ssz_bytes,
                                        })
                                        .await;
                                    } else {
                                        self.emit_event(NetworkEvent::GossipMessage {
                                            topic,
                                            peer: propagation_source,
                                            data: ssz_bytes,
                                        })
                                        .await;
                                    }
                                }
                                GossipVerdict::Ignore(reason)
                                    if topic.kind == GossipTopicKind::BeaconBlock
                                        && reason == GOSSIP_REASON_PARENT_UNSEEN =>
                                {
                                    self.emit_event(NetworkEvent::UnknownParentBlock {
                                        topic,
                                        peer: propagation_source,
                                        data: ssz_bytes,
                                    })
                                    .await;
                                }
                                _ => {}
                            }

                            // Record score event for the peer, then update the
                            // peer-score gauge for its new bucket (M11 Phase 11
                            // task 4: gauge updated on each score change).
                            self.peer_manager
                                .record_event(propagation_source, score_event);
                            self.emit_peer_score_gauge(&propagation_source);
                        }
                        Err(join_err) => {
                            if join_err.is_panic() {
                                tracing::error!(%join_err, "gossip validation task panicked");
                            }
                        }
                    }
                }
                _ = &mut self.shutdown_signal => {
                    self.shutdown_goodbye().await;
                    break;
                }
            }
        }
        self.emit_event(NetworkEvent::Shutdown).await;
        tracing::info!("network event loop exited; Shutdown emitted");
        Ok(())
    }

    async fn on_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<PharosBehaviourEvent<E>>) {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::Gossipsub(gs_event)) => {
                self.on_gossip_event(gs_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcStatus(rr_event)) => {
                self.on_request_response_event(rr_event, RpcMethod::Status)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcGoodbye(rr_event)) => {
                self.on_request_response_event(rr_event, RpcMethod::Goodbye)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcPing(rr_event)) => {
                self.on_request_response_event(rr_event, RpcMethod::Ping)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcMetaData(rr_event)) => {
                self.on_request_response_event(rr_event, RpcMethod::MetaData)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcMetaDataV1(rr_event)) => {
                self.on_request_response_event(rr_event, RpcMethod::MetaDataV1)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcBlocksByRange(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::BlocksByRange)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcBlocksByRoot(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::BlocksByRoot)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcBootstrap(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::LightClientBootstrap)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcUpdatesByRange(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::LightClientUpdatesByRange)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcFinalityUpdate(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::LightClientFinalityUpdate)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcOptimisticUpdate(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::LightClientOptimisticUpdate)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcBlobSidecarsByRange(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::BlobSidecarsByRange)
                    .await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcBlobSidecarsByRoot(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event, RpcMethod::BlobSidecarsByRoot)
                    .await;
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                self.on_swarm_connection_established(peer_id, endpoint, num_established);
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed {
                peer_id,
                cause,
                num_established,
                ..
            } => {
                self.on_swarm_connection_closed(peer_id, cause.as_ref(), num_established)
                    .await;
            }
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "new listen address");
                self.emit_event(NetworkEvent::NewListenAddr(address)).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::Identify(id_event)) => {
                if let identify::Event::Received { peer_id, info, .. } = *id_event {
                    self.on_identify(peer_id, info).await;
                }
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let error_str = format!("{error}");
                self.emit_event(NetworkEvent::DialFailed {
                    peer: peer_id,
                    error: error_str,
                })
                .await;
                if let Some(pid) = peer_id {
                    self.peer_manager.record_event(
                        pid,
                        ScoreEvent::HandshakeFail {
                            kind: HandshakeFailKind::Timeout,
                        },
                    );
                }
                if let Some(pid) = peer_id {
                    self.pending_dials.remove(&pid);
                }
                self.peer_manager.note_dial_failure(peer_id);
            }
            libp2p::swarm::SwarmEvent::ExternalAddrConfirmed { address } => {
                tracing::info!(%address, "external address confirmed");
                // ENR update deferred to M3b (cross-fork ENR migration).
                self.emit_event(NetworkEvent::ExternalAddrConfirmed { address })
                    .await;
            }
            _ => {
                // Remaining swarm events are deferred to M11 (peer scoring,
                // listener errors, etc.). Debug-log for observability.
                tracing::debug!("swarm event (M11-deferred): {:?}", event);
            }
        }
    }

    /// Handle an incoming gossipsub event.
    async fn on_gossip_event(&mut self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => {
                self.on_gossip_message(propagation_source, message_id, message)
                    .await;
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                if let Ok(parsed) = GossipTopic::from_topic_hash(&topic, &self.topic_map) {
                    self.emit_event(NetworkEvent::PeerSubscribed {
                        peer: peer_id,
                        topic: parsed,
                    })
                    .await;
                } else {
                    tracing::debug!(%peer_id, ?topic, "peer subscribed to unknown topic; ignoring");
                }
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                if let Ok(parsed) = GossipTopic::from_topic_hash(&topic, &self.topic_map) {
                    // Leaving a per-subnet mesh (attestation / sync-committee /
                    // blob) is a subnet-non-propagation signal: the peer is no
                    // longer serving a subnet we expect coverage on (M11 Phase 0
                    // mapping table). Penalise via the scorer before forwarding
                    // the event.
                    if is_subnet_topic(&parsed.kind) {
                        self.peer_manager.record_event(
                            peer_id,
                            ScoreEvent::UnsubscribedFromExpectedSubnet {
                                topic: topic.clone(),
                            },
                        );
                        self.emit_peer_score_gauge(&peer_id);
                    }
                    self.emit_event(NetworkEvent::PeerUnsubscribed {
                        peer: peer_id,
                        topic: parsed,
                    })
                    .await;
                } else {
                    tracing::debug!(%peer_id, ?topic, "peer unsubscribed from unknown topic; ignoring");
                }
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                tracing::debug!(%peer_id, "gossipsub not supported");
            }
            gossipsub::Event::SlowPeer {
                peer_id,
                failed_messages,
            } => {
                // gossipsub reports the peer cannot keep up with message
                // delivery. Penalise proportionally to the total failed-message
                // count (M11 Phase 0 mapping table → ScoreEvent::SlowPeer).
                let failed = failed_messages.total();
                tracing::debug!(%peer_id, failed, "slow peer");
                self.peer_manager.record_event(
                    peer_id,
                    ScoreEvent::SlowPeer {
                        failed_messages: failed,
                    },
                );
                self.emit_peer_score_gauge(&peer_id);
            }
        }
    }

    /// Dispatch a received gossipsub `Message` through the validation pipeline.
    async fn on_gossip_message(
        &mut self,
        propagation_source: PeerId,
        message_id: gossipsub::MessageId,
        message: gossipsub::Message,
    ) {
        // Look up the parsed topic from our subscription table.
        let topic = match self.topic_lookup(&message.topic) {
            Some(t) => t,
            None => {
                tracing::debug!(
                    ?message.topic,
                    "received gossip on unknown topic; ignoring"
                );
                return;
            }
        };

        // Snappy-block-decompress once. The decompressed bytes are reused on
        // the Accept path for the event channel; the dispatcher sees them as
        // already-decoded SSZ. Per `p2p-interface.md:1038-1048` gossip uses
        // raw block compression.
        let ssz_bytes = match decode_snappy_block(&message.data, crate::codec::MAX_PAYLOAD_SIZE) {
            Ok(b) => b,
            Err(_) => {
                // Spec-required: report Reject to gossipsub and score the peer.
                if !self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        MessageAcceptance::Reject,
                    )
                {
                    tracing::debug!(%message_id, "report_message_validation_result returned false (message not in cache)");
                }
                self.peer_manager.record_event(
                    propagation_source,
                    ScoreEvent::GossipReject {
                        topic: message.topic,
                        reason: "snappy decode".to_string(),
                    },
                );
                return;
            }
        };

        // SSZ-decode + validate via the host on a blocking thread.
        // `dispatch_gossip_message` may call BLS verify (a blocking CPU op).
        // Running it on a blocking thread prevents stalling the async executor.
        // The task returns ALL captured state so the completion arm in the main
        // select loop can report the verdict without re-acquiring it.
        let host = self.host.clone();
        let topic = topic.clone();
        let bytes = ssz_bytes.clone();
        self.gossip_tasks.spawn_blocking(move || {
            let verdict = dispatch_gossip_message::<E, H>(host.as_ref(), &topic, &bytes);
            (
                verdict,
                propagation_source,
                message_id,
                topic,
                ssz_bytes,
                message,
            )
        });
    }

    /// Handle an inbound or outbound req-resp event.
    ///
    /// - Inbound requests are dispatched to `handle_request` and the response
    ///   is sent back via the response channel.
    /// - Outbound responses are resolved into the pending oneshot map.
    /// - Failures record scoring events on the peer.
    async fn on_request_response_event(
        &mut self,
        event: request_response::Event<RpcRequest, RpcResponse<E>>,
        method: RpcMethod,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id: _,
                    request,
                    channel,
                } => {
                    // Determine the method for scoring before moving `request`.
                    let method = rpc_method_from_request(&request);
                    // Capture inbound Goodbye reason before moving `request`.
                    let inbound_goodbye_reason = if let RpcRequest::Goodbye(r) = &request {
                        Some(*r)
                    } else {
                        None
                    };
                    // Track whether this is an inbound Status before moving `request`.
                    let is_inbound_status = matches!(request, RpcRequest::Status(_));

                    // Derive the negotiated protocol ID from the request variant so the
                    // handler can select MetaData v1 vs v2 per `D-metadata-v2-dual-handle`.
                    let negotiated_protocol_id = method.protocol_id();
                    let host = Arc::clone(&self.host);
                    let host_metadata = Arc::clone(&self.host_metadata);
                    // Handle synchronously to avoid lifetime complexity with &mut self.
                    // Time the request handler to record req-resp method latency.
                    // ADR cite: `D-metrics-prometheus-optin` (Phase 5).
                    let _rpc_t0 = std::time::Instant::now();
                    let response = handle_request::<E, H, S>(
                        host.as_ref(),
                        &host_metadata,
                        peer,
                        request,
                        &mut self.peer_manager,
                        negotiated_protocol_id,
                    )
                    .await;
                    let method_label = format!("{method:?}");
                    metrics::histogram!(
                        METRIC_RPC_LATENCY_SECONDS,
                        "method" => method_label
                    )
                    .record(_rpc_t0.elapsed().as_secs_f64());

                    // Emit PeerConnected for inbound Status after a successful handshake.
                    //
                    // Symmetry with outbound: `on_status_response` emits PeerConnected only
                    // after fork-digest validation succeeds. For inbound, `handle_request`
                    // calls `peer_manager.on_inbound_status` which transitions the peer to
                    // `Connected` iff the fork digest matches. Emit here before sending the
                    // response so consumers see the peer as ready before the remote sees
                    // the Status reply.
                    if is_inbound_status && matches!(response, RpcResponse::Status(_)) {
                        self.emit_event(NetworkEvent::PeerConnected(peer)).await;
                        self.peer_manager.record_event(
                            peer,
                            ScoreEvent::RpcSuccess {
                                method: RpcMethod::Status,
                            },
                        );
                    }

                    // Pre-register the Goodbye reason so ConnectionClosed carries it
                    // when the peer tears down the connection after sending Goodbye.
                    // Spec reference: specs/phase0/p2p-interface.md:1390-1395.
                    if let Some(goodbye_reason) = inbound_goodbye_reason {
                        self.peer_manager.note_disconnect_reason(
                            peer,
                            crate::types::DisconnectReason::Goodbye(goodbye_reason),
                        );
                    }

                    // Route send_response to the per-method behaviour that owns this
                    // channel. Calling send_response on the wrong behaviour is safe
                    // today (the channel is just a oneshot sender), but routing
                    // explicitly avoids the bug class if libp2p changes the semantics.
                    let send_err = {
                        let b = self.swarm.behaviour_mut();
                        match method {
                            RpcMethod::Status => b.rpc_status.0.send_response(channel, response),
                            RpcMethod::Goodbye => b.rpc_goodbye.0.send_response(channel, response),
                            RpcMethod::Ping => b.rpc_ping.0.send_response(channel, response),
                            RpcMethod::MetaData => {
                                b.rpc_metadata.0.send_response(channel, response)
                            }
                            RpcMethod::MetaDataV1 => {
                                b.rpc_metadata_v1.0.send_response(channel, response)
                            }
                            RpcMethod::BlocksByRange => {
                                b.rpc_blocks_by_range.0.send_response(channel, response)
                            }
                            RpcMethod::BlocksByRoot => {
                                b.rpc_blocks_by_root.0.send_response(channel, response)
                            }
                            RpcMethod::LightClientBootstrap => {
                                b.rpc_lc_bootstrap.0.send_response(channel, response)
                            }
                            RpcMethod::LightClientUpdatesByRange => {
                                b.rpc_lc_updates_by_range.0.send_response(channel, response)
                            }
                            RpcMethod::LightClientFinalityUpdate => {
                                b.rpc_lc_finality_update.0.send_response(channel, response)
                            }
                            RpcMethod::LightClientOptimisticUpdate => b
                                .rpc_lc_optimistic_update
                                .0
                                .send_response(channel, response),
                            RpcMethod::BlobSidecarsByRange => b
                                .rpc_blob_sidecars_by_range
                                .0
                                .send_response(channel, response),
                            RpcMethod::BlobSidecarsByRoot => b
                                .rpc_blob_sidecars_by_root
                                .0
                                .send_response(channel, response),
                        }
                    };
                    if send_err.is_err() {
                        tracing::warn!(%peer, "failed to send RPC response (channel closed)");
                    }

                    // Record RpcSuccess for non-Status methods. Inbound Status is
                    // recorded above together with PeerConnected to ensure ordering.
                    if method != RpcMethod::Status {
                        self.peer_manager
                            .record_event(peer, ScoreEvent::RpcSuccess { method });
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    // Route by `method` FIRST: `OutboundRequestId` is only unique within
                    // a single per-method behaviour, so checking maps by id alone can
                    // cross-deliver (e.g. a BlocksByRange response consuming a Status
                    // handshake entry that happens to share id 1). The internal-tracking
                    // maps are keyed by id but only ever hold their own method's ids.
                    if method == RpcMethod::Status
                        && self.pending_status_checks.contains_key(&request_id)
                    {
                        let hs_peer = self.pending_status_checks.remove(&request_id).unwrap();
                        self.on_status_response(hs_peer, &response).await;
                    } else if method == RpcMethod::Ping
                        && self.pending_ping_checks.contains_key(&request_id)
                    {
                        let ping_peer = self.pending_ping_checks.remove(&request_id).unwrap();
                        self.on_ping_response(ping_peer, &response);
                    } else if (method == RpcMethod::MetaData || method == RpcMethod::MetaDataV1)
                        && self.pending_metadata_fetches.contains_key(&request_id)
                    {
                        let meta_peer = self.pending_metadata_fetches.remove(&request_id).unwrap();
                        self.on_metadata_response(meta_peer, &response);
                    } else if let Some((_method, tx)) =
                        self.pending_rpc.remove(&(method, request_id))
                    {
                        // User-initiated outbound RPC (Phase 7 surface).
                        let _ = tx.send(Ok(response));
                    } else {
                        tracing::warn!(
                            ?method,
                            ?request_id,
                            "received response for unknown request"
                        );
                    }
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                tracing::warn!(%peer, ?error, "outbound RPC failure");
                // Route by `method` (see the Response handler): `request_id` is only
                // unique within a per-method behaviour.
                if method == RpcMethod::Status
                    && self.pending_status_checks.remove(&request_id).is_some()
                {
                    // Handshake Status timed out or failed — abort and disconnect.
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::HandshakeFail {
                            kind: HandshakeFailKind::Timeout,
                        },
                    );
                    self.peer_manager.on_disconnecting(peer);
                    self.swarm.disconnect_peer_id(peer).ok();
                } else if method == RpcMethod::Ping
                    && self.pending_ping_checks.remove(&request_id).is_some()
                {
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::RpcError {
                            method: RpcMethod::Ping,
                            kind: RpcErrorKind::ServerError,
                        },
                    );
                } else if (method == RpcMethod::MetaData || method == RpcMethod::MetaDataV1)
                    && self.pending_metadata_fetches.remove(&request_id).is_some()
                {
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::RpcError {
                            method: RpcMethod::MetaData,
                            kind: RpcErrorKind::ServerError,
                        },
                    );
                } else if let Some((method, tx)) = self.pending_rpc.remove(&(method, request_id)) {
                    let _ = tx.send(Err(NetworkError::Libp2p(error.to_string())));
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::RpcError {
                            method,
                            kind: RpcErrorKind::ServerError,
                        },
                    );
                }
            }
            request_response::Event::InboundFailure {
                peer,
                request_id: _,
                error,
                ..
            } => {
                tracing::warn!(%peer, ?error, "inbound RPC failure");
                self.peer_manager.record_event(
                    peer,
                    ScoreEvent::RpcError {
                        method: RpcMethod::Status, // conservative; method unknown on failure
                        kind: RpcErrorKind::StreamReset,
                    },
                );
            }
            request_response::Event::ResponseSent {
                peer, request_id, ..
            } => {
                tracing::debug!(%peer, ?request_id, "RPC response sent");
            }
        }
    }

    /// Route an outbound RPC request to the per-method `request_response::Behaviour`.
    ///
    /// Each method has its own behaviour instance so that multistream-select
    /// negotiates the EXACT per-method protocol string rather than always
    /// choosing the first registered protocol.
    fn send_rpc_request(&mut self, peer: &PeerId, req: RpcRequest) -> OutboundRequestId {
        let b = self.swarm.behaviour_mut();
        match &req {
            RpcRequest::Status(_) => b.rpc_status.0.send_request(peer, req),
            RpcRequest::Goodbye(_) => b.rpc_goodbye.0.send_request(peer, req),
            RpcRequest::Ping(_) => b.rpc_ping.0.send_request(peer, req),
            RpcRequest::MetaData => b.rpc_metadata.0.send_request(peer, req),
            // MetaDataV1 uses the v1 protocol behaviour.
            RpcRequest::MetaDataV1 => b.rpc_metadata_v1.0.send_request(peer, req),
            RpcRequest::BlocksByRange(_) => b.rpc_blocks_by_range.0.send_request(peer, req),
            RpcRequest::BlocksByRoot(_) => b.rpc_blocks_by_root.0.send_request(peer, req),
            // Light-client requests use the per-method LC behaviours.
            RpcRequest::LightClientBootstrap(_) => b.rpc_lc_bootstrap.0.send_request(peer, req),
            RpcRequest::LightClientUpdatesByRange(_) => {
                b.rpc_lc_updates_by_range.0.send_request(peer, req)
            }
            RpcRequest::LightClientFinalityUpdate => {
                b.rpc_lc_finality_update.0.send_request(peer, req)
            }
            RpcRequest::LightClientOptimisticUpdate => {
                b.rpc_lc_optimistic_update.0.send_request(peer, req)
            }
            RpcRequest::BlobSidecarsByRange(_) => {
                b.rpc_blob_sidecars_by_range.0.send_request(peer, req)
            }
            RpcRequest::BlobSidecarsByRoot(_) => {
                b.rpc_blob_sidecars_by_root.0.send_request(peer, req)
            }
        }
    }

    /// Send an outbound RPC request to `peer`, resolving the result via `reply`.
    ///
    /// Stashes the `reply` oneshot sender in `pending_rpc` keyed by the
    /// `OutboundRequestId` assigned by libp2p. The response is resolved in
    /// `on_request_response_event` when the peer replies.
    pub fn on_outgoing_request_command(
        &mut self,
        peer: PeerId,
        req: RpcRequest,
        reply: oneshot::Sender<Result<RpcResponse<E>, NetworkError>>,
    ) {
        let method = rpc_method_from_request(&req);
        let request_id = self.send_rpc_request(&peer, req);
        // Key by (method, id): per-method behaviours have independent id counters.
        self.pending_rpc
            .insert((method, request_id), (method, reply));
    }

    /// Look up a parsed `GossipTopic` by its `TopicHash`.
    fn topic_lookup(&self, hash: &TopicHash) -> Option<GossipTopic> {
        self.topic_map.get(hash).cloned()
    }

    /// Snappy-block-encode `ssz_payload` and publish it to the given topic.
    ///
    /// Gossip uses snappy block (raw) compression per
    /// `specs/phase0/p2p-interface.md:1038-1048`.
    ///
    /// Returns the `MessageId` assigned by gossipsub on success.
    pub fn on_publish_command(
        &mut self,
        topic: GossipTopic,
        ssz_payload: Vec<u8>,
    ) -> Result<gossipsub::MessageId, NetworkError> {
        let compressed = encode_snappy_block(&ssz_payload)?;
        let ident = IdentTopic::new(topic.topic_str());
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(ident, compressed)
            .map_err(|e| NetworkError::Libp2p(format!("gossipsub publish error: {e}")))
    }

    /// Handle a `Ping` response.
    ///
    /// Per `p2p-interface.md:1543-1575`: if the peer's seq_number is strictly
    /// greater than our stored value, issue a `GetMetaData` to fetch the
    /// updated metadata.
    fn on_ping_response(&mut self, peer_id: PeerId, response: &RpcResponse<E>) {
        let peer_seq = match response {
            RpcResponse::Ping(seq) => *seq,
            _ => return,
        };
        let stored_seq = self.peer_manager.peer_metadata_seq(&peer_id).unwrap_or(0);
        if peer_seq > stored_seq {
            let request_id = self.send_rpc_request(&peer_id, RpcRequest::MetaData);
            // Track only via pending_metadata_fetches; no oneshot to resolve.
            self.pending_metadata_fetches.insert(request_id, peer_id);
        }
    }

    /// Handle a `GetMetaData` response, updating the stored metadata.
    ///
    /// Extracts the phase-0 view from either `MetaDataResponse` variant for the
    /// seq_number-based keepalive check. The peer manager stores only the phase-0
    /// fields (`seq_number`, `attnets`) which are common to both v1 and v2.
    fn on_metadata_response(&mut self, peer_id: PeerId, response: &RpcResponse<E>) {
        use crate::rpc::types::MetaDataResponse;
        if let RpcResponse::MetaData(meta_resp) = response {
            let phase0_meta = match meta_resp {
                MetaDataResponse::V1(m) => m.clone(),
                MetaDataResponse::V2(m) => pharos_types::phase0::MetaData {
                    seq_number: m.seq_number,
                    attnets: m.attnets.clone(),
                },
            };
            self.peer_manager.on_metadata(peer_id, phase0_meta);
        }
    }

    /// Handle a completed identify exchange for `peer`.
    ///
    /// Updates the peer manager's stored `PeerInfo` with the agent version,
    /// protocol list, and observed address from `info`. Emits
    /// `NetworkEvent::PeerIdentified` with the updated snapshot. Drops the
    /// event when the peer is not in the connected map (unknown-peer identify;
    /// per D-peer-info-shape identify-flood mitigation by per-peer overwrite).
    async fn on_identify(&mut self, peer: PeerId, info: identify::Info) {
        let agent = info.agent_version.clone();
        let protocols: Vec<String> = info.protocols.iter().map(|p| p.to_string()).collect();
        let observed = info.observed_addr.clone();
        match self
            .peer_manager
            .update_identify(peer, agent, protocols, observed)
        {
            Some(snapshot) => {
                self.emit_event(NetworkEvent::PeerIdentified {
                    peer,
                    info: Box::new(snapshot),
                })
                .await;
            }
            None => {
                tracing::debug!(%peer, "identify event for unknown peer; dropping");
            }
        }
    }

    /// Complete or abort the handshake after receiving a `Status` response.
    ///
    /// If the peer's fork digest matches ours, transitions the peer to
    /// `Connected` and records the status.  If it differs, records a
    /// `HandshakeFail` score event, transitions to `Disconnecting`, sends
    /// `Goodbye(2 = IrrelevantNetwork)`, and disconnects.
    async fn on_status_response(&mut self, peer_id: PeerId, response: &RpcResponse<E>) {
        let peer_status = match response {
            RpcResponse::Status(s) => s.clone(),
            RpcResponse::Error { code, .. } => {
                // Peer returned an error to our Status request, likely a fork-
                // digest mismatch or a protocol error. Treat as a handshake
                // failure: disconnect and send Goodbye(IrrelevantNetwork).
                tracing::debug!(%peer_id, code, "Status request returned error; disconnecting");
                self.peer_manager.record_event(
                    peer_id,
                    ScoreEvent::HandshakeFail {
                        kind: HandshakeFailKind::ForkDigestMismatch,
                    },
                );
                // Pre-register reason so ConnectionClosed carries Goodbye(2).
                // Spec reference: specs/phase0/p2p-interface.md:1394 — 2 = Irrelevant network.
                self.peer_manager.note_disconnect_reason(
                    peer_id,
                    crate::types::DisconnectReason::Goodbye(GOODBYE_IRRELEVANT_NETWORK),
                );
                self.peer_manager.on_disconnecting(peer_id);
                self.send_rpc_request(
                    &peer_id,
                    crate::rpc::types::RpcRequest::Goodbye(GOODBYE_IRRELEVANT_NETWORK),
                );
                self.swarm.disconnect_peer_id(peer_id).ok();
                return;
            }
            _ => {
                tracing::warn!(%peer_id, "unexpected response type during Status handshake");
                return;
            }
        };

        self.peer_manager.on_status(peer_id, peer_status.clone());

        let our_fork = self.host.current_fork_digest();
        if peer_status.fork_digest != our_fork {
            tracing::debug!(
                %peer_id,
                peer_fork = ?peer_status.fork_digest,
                our_fork = ?our_fork,
                "fork digest mismatch; disconnecting"
            );
            self.peer_manager.record_event(
                peer_id,
                ScoreEvent::HandshakeFail {
                    kind: HandshakeFailKind::ForkDigestMismatch,
                },
            );
            // Pre-register reason so ConnectionClosed carries Goodbye(2) rather
            // than a generic clean-close. Spec reference:
            // specs/phase0/p2p-interface.md:1394 — reason 2 = Irrelevant network.
            self.peer_manager.note_disconnect_reason(
                peer_id,
                crate::types::DisconnectReason::Goodbye(GOODBYE_IRRELEVANT_NETWORK),
            );
            self.peer_manager.on_disconnecting(peer_id);
            // Send Goodbye(IrrelevantNetwork) fire-and-forget; no response expected.
            self.send_rpc_request(
                &peer_id,
                crate::rpc::types::RpcRequest::Goodbye(GOODBYE_IRRELEVANT_NETWORK),
            );
            self.swarm.disconnect_peer_id(peer_id).ok();
        } else {
            self.peer_manager.on_handshake_complete(peer_id);
            self.emit_event(NetworkEvent::PeerConnected(peer_id)).await;
            self.peer_manager.record_event(
                peer_id,
                ScoreEvent::RpcSuccess {
                    method: RpcMethod::Status,
                },
            );
        }
    }

    /// Handle a newly established libp2p connection.
    ///
    /// - Registers the peer in the peer manager (state → `Connecting`).
    /// - For outbound connections (we dialled): transitions to `Handshaking`
    ///   and sends a `Status` request. The response is handled in
    ///   `on_request_response_event` via `pending_status_checks`.
    ///   Per `p2p-interface.md:1352`.
    ///
    /// Gated on `num_established == 1`: libp2p may open redundant connections
    /// to the same peer (e.g. simultaneous dial). Re-registering on the second
    /// connection would overwrite `last_status` and corrupt the peer table.
    /// `num_established` from `SwarmEvent::ConnectionEstablished` includes the
    /// just-opened connection, so `.get() == 1` means this is the first.
    ///
    /// NOTE: ban()/Goodbye-driven removal lives in `on_request_response_event`
    /// and is intentionally OUTSIDE this num_established gate — a fork-mismatch
    /// ban must drop the peer unconditionally regardless of remaining connections.
    pub fn on_swarm_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
        num_established: std::num::NonZeroU32,
    ) {
        // Clear before the num_established gate so that BOTH the first
        // connection (n==1) AND a simultaneous mutual-dial second connection
        // (n>1) remove the pending entry.  Leaving it in on n>1 would suppress
        // a future re-dial after the redundant connection is torn down.
        self.pending_dials.remove(&peer_id);

        if num_established.get() == 1 {
            if self.peer_manager.is_banned(&peer_id) {
                tracing::warn!(
                    banned_peer = %peer_id,
                    "rejecting connection from banned peer"
                );
                self.peer_manager
                    .record_event(peer_id, ScoreEvent::BannedPeerConnected);
                self.swarm.disconnect_peer_id(peer_id).ok();
                return;
            }

            // Enforce max_peers on inbound connections (M11 Phase 12 task 2).
            // Outbound connections (we dialled) are never refused here — we chose
            // to dial them and they count against the same limit; `tick_score_prune`
            // handles any steady-state excess via `should_prune`.
            if !endpoint.is_dialer()
                && self.peer_manager.peer_count() >= self.peer_manager.max_peers()
            {
                tracing::debug!(
                    %peer_id,
                    peer_count = self.peer_manager.peer_count(),
                    max_peers = self.peer_manager.max_peers(),
                    "rejecting inbound connection: at max_peers limit"
                );
                self.swarm.disconnect_peer_id(peer_id).ok();
                return;
            }

            let dir = if endpoint.is_dialer() {
                ConnectionDirection::Outbound
            } else {
                ConnectionDirection::Inbound
            };

            let addrs = vec![endpoint.get_remote_address().clone()];
            self.peer_manager.on_connected(peer_id, dir, addrs);
            // A successful connection clears any accumulated dial backoff so a
            // peer that recovers is dialled at the base interval next time
            // (M11 Phase 11 task 3).
            self.peer_manager.record_dial_success(peer_id);

            if endpoint.is_dialer() {
                self.peer_manager.on_handshaking(peer_id);

                let (finalized_root, finalized_epoch) = {
                    let cp = self.host.finalized_checkpoint();
                    (cp.root, cp.epoch)
                };
                let (head_root, head_slot) = self.host.head();
                let local_status = BeaconStatus {
                    fork_digest: self.host.current_fork_digest(),
                    finalized_root,
                    finalized_epoch,
                    head_root,
                    head_slot,
                };

                // Send the Status request; track only via pending_status_checks.
                // The response handler uses that map to run fork-digest validation.
                // Do not insert into pending_rpc — there is no oneshot to resolve.
                let request_id = self.send_rpc_request(
                    &peer_id,
                    crate::rpc::types::RpcRequest::Status(local_status),
                );
                self.pending_status_checks.insert(request_id, peer_id);
            } else {
                // Inbound connection: do NOT emit PeerConnected here.
                // PeerConnected is emitted only after successful Status handshake
                // (see on_inbound_status_request). Emitting early would surface a
                // peer that may be on a wrong fork digest and get Goodbye'd seconds
                // later. Symmetry with outbound: both sides emit only post-handshake.
            }
        } else {
            tracing::trace!(
                %peer_id,
                n = num_established.get(),
                "redundant connection established; not re-registering"
            );
        }
    }

    /// Handle a closed libp2p connection, informing the peer manager and
    /// emitting a `PeerDisconnected` event.
    ///
    /// If a disconnect reason was pre-registered via
    /// `peer_manager.note_disconnect_reason` (e.g., Goodbye plumbing), that
    /// reason takes precedence over the libp2p `ConnectionError`.
    ///
    /// Gated on `num_established == 0`: libp2p may close one of several
    /// connections to the same peer. `num_established` from
    /// `SwarmEvent::ConnectionClosed` is the REMAINING connection count after
    /// this close, so `== 0` means this was the last connection to the peer.
    /// Removing the peer on a non-last close would wipe `last_status` while
    /// the peer is still reachable on the other connection.
    ///
    /// NOTE: ban()/Goodbye-driven removal lives in `on_request_response_event`
    /// and is intentionally OUTSIDE this num_established gate — a fork-mismatch
    /// ban must drop the peer unconditionally regardless of remaining connections.
    pub async fn on_swarm_connection_closed(
        &mut self,
        peer_id: PeerId,
        reason: Option<&ConnectionError>,
        num_established: u32,
    ) {
        if num_established == 0 {
            use crate::types::DisconnectReason;
            // Pre-registered reason wins (set before issuing the disconnect so the
            // Goodbye/fork-mismatch semantics are preserved even when libp2p delivers
            // a generic clean-close error).
            let dr = self
                .peer_manager
                .take_disconnect_reason(&peer_id)
                .unwrap_or_else(|| match reason {
                    // No error means a clean (graceful) close initiated by either side.
                    None => DisconnectReason::Other("clean close".into()),
                    Some(e) => DisconnectReason::Other(e.to_string()),
                });
            // on_disconnected records ScoreEvent::PeerDisconnected with the resolved reason.
            self.peer_manager.on_disconnected(peer_id, dr.clone());
            self.emit_event(NetworkEvent::PeerDisconnected(peer_id, dr))
                .await;
        } else {
            tracing::trace!(
                %peer_id,
                remaining = num_established,
                "non-last connection closed; peer retained"
            );
        }
    }

    /// Send a `Ping` keepalive to every `Connected` peer.
    ///
    /// Per `p2p-interface.md:1543-1575`: the local node sends
    /// `Ping(seq_number)` every 15 s. If the peer replies with a
    /// seq_number newer than the stored one, a follow-up `GetMetaData`
    /// is issued.
    pub fn tick_ping(&mut self) {
        let local_seq = self.host_metadata.load().seq_number;
        let connected: Vec<PeerId> = self.peer_manager.connected_peers().collect();
        for peer_id in connected {
            let request_id = self.send_rpc_request(&peer_id, RpcRequest::Ping(local_seq));
            // Track only via pending_ping_checks; no oneshot to resolve.
            self.pending_ping_checks.insert(request_id, peer_id);
        }
    }

    /// Prune peers that the scorer considers lowest-quality, and enforce the
    /// scorer's ban/disconnect threshold decisions (M11 Phase 11 task 3).
    ///
    /// Three enforcement sources, in order:
    /// 1. Peers at or below the **ban threshold** are banned (removed +
    ///    blocked from reconnecting for the ban window) and disconnected.
    /// 2. Peers at or below the **disconnect threshold** (but above ban) are
    ///    disconnected with `Goodbye(3)` (Fault/Error) but not banned.
    /// 3. Excess peers above `target_peers` are pruned by
    ///    `peer_manager.should_prune()` (lowest-scoring first).
    ///
    /// With `NoopScorer` every threshold check returns `false` and
    /// `should_prune()` is empty, so this stays a no-op.
    pub fn tick_score_prune(&mut self) {
        self.peer_manager.sweep_expired_bans();

        // Snapshot connected peers so we can consult the scorer thresholds
        // without holding an iterator borrow across the mutating actions.
        let connected: Vec<PeerId> = self.peer_manager.connected_peers().collect();
        for peer_id in &connected {
            if self.peer_manager.scorer_wants_ban(peer_id) {
                // Ban: remove + block reconnects for the ban window, then
                // disconnect with Goodbye(3 = Fault/Error). The phase0 Goodbye
                // table has no dedicated "banned" code; Fault/Error is the
                // closest fit (specs/phase0/p2p-interface.md:1393).
                self.peer_manager
                    .note_disconnect_reason(*peer_id, crate::types::DisconnectReason::ScorerLow);
                self.peer_manager.on_disconnecting(*peer_id);
                self.send_rpc_request(
                    peer_id,
                    crate::rpc::types::RpcRequest::Goodbye(GOODBYE_FAULT_ERROR),
                );
                self.peer_manager.ban(*peer_id, SCORE_BAN_DURATION);
                self.swarm.disconnect_peer_id(*peer_id).ok();
            } else if self.peer_manager.scorer_wants_disconnect(peer_id) {
                self.disconnect_with_goodbye(*peer_id, GOODBYE_FAULT_ERROR);
            }
        }

        // Prune any remaining excess (lowest-scoring first) to reach target.
        let to_prune = self.peer_manager.should_prune();
        for peer_id in to_prune {
            self.disconnect_with_goodbye(peer_id, GOODBYE_FAULT_ERROR);
        }
        self.emit_all_peer_score_gauges();
    }

    /// Pre-register `Goodbye(reason)`, send it fire-and-forget, and force the
    /// swarm-level disconnect. Shared by the disconnect-threshold and prune
    /// paths in [`tick_score_prune`].
    fn disconnect_with_goodbye(&mut self, peer_id: PeerId, reason: u64) {
        self.peer_manager
            .note_disconnect_reason(peer_id, crate::types::DisconnectReason::Goodbye(reason));
        self.peer_manager.on_disconnecting(peer_id);
        self.send_rpc_request(&peer_id, crate::rpc::types::RpcRequest::Goodbye(reason));
        self.swarm.disconnect_peer_id(peer_id).ok();
    }

    /// Update the peer-score gauge for a single peer's current bucket
    /// (M11 Phase 11 task 4). The gauge is labelled by score bucket so the
    /// Prometheus surface shows the distribution of peer quality.
    fn emit_peer_score_gauge(&self, peer_id: &PeerId) {
        let score = self.peer_manager.score(peer_id);
        metrics::gauge!(METRIC_PEER_SCORE, "bucket" => score_bucket_label(score)).set(score);
    }

    /// Recompute the per-bucket peer-score gauges across all connected peers.
    ///
    /// Sets each bucket gauge to the count of connected peers whose score falls
    /// in that bucket, so the Prometheus surface reflects the live distribution.
    fn emit_all_peer_score_gauges(&self) {
        let mut counts: [usize; SCORE_BUCKETS.len() + 1] = [0; SCORE_BUCKETS.len() + 1];
        for score in self.peer_manager.connected_peer_scores() {
            counts[score_bucket_index(score)] += 1;
        }
        for (idx, &label) in ALL_SCORE_BUCKET_LABELS.iter().enumerate() {
            metrics::gauge!(METRIC_PEER_SCORE, "bucket" => label).set(counts[idx] as f64);
        }
    }

    /// Send `Goodbye(ClientShutdown)` to every connected peer, then force-disconnect.
    ///
    /// Implements the D-shutdown-protocol ADR: best-effort Goodbye with a 500 ms
    /// bounded drain so a slow peer cannot hold up the shutdown indefinitely.
    ///
    /// Steps:
    /// 1. Collect connected peers.
    /// 2. Pre-register `DisconnectReason::Goodbye(GOODBYE_CLIENT_SHUTDOWN)` for each,
    ///    then send `RpcRequest::Goodbye(1)` fire-and-forget.
    /// 3. Run `drain_outbound_requests` bounded by a 500 ms timeout.
    /// 4. Force-disconnect each peer.
    ///
    /// Spec cite: `p2p-interface.md:1383-1385` (ClientShutdown = 1).
    async fn shutdown_goodbye(&mut self) {
        let peers: Vec<PeerId> = self.peer_manager.connected_peers().collect();
        if peers.is_empty() {
            return;
        }
        let expected = peers.len();
        for &peer in &peers {
            self.peer_manager.note_disconnect_reason(
                peer,
                crate::types::DisconnectReason::Goodbye(GOODBYE_CLIENT_SHUTDOWN),
            );
            self.peer_manager.on_disconnecting(peer);
            self.send_rpc_request(&peer, RpcRequest::Goodbye(GOODBYE_CLIENT_SHUTDOWN));
        }
        // Best-effort drain: wait up to 500 ms for Goodbye response/failure events.
        // Timeout result is intentionally ignored (ok = drained, Err = timed out).
        timeout(
            Duration::from_millis(500),
            self.drain_outbound_requests(expected),
        )
        .await
        .ok();
        // Force-disconnect each peer (idempotent if the peer already dropped us).
        for peer in &peers {
            self.swarm.disconnect_peer_id(*peer).ok();
        }
    }

    /// Poll the swarm until `expected` Goodbye response/failure events are observed,
    /// or the caller's timeout fires.
    ///
    /// Other swarm events encountered during the drain are trace-logged and discarded;
    /// the drain loop is not the normal event loop and must not process them fully.
    /// Counting logic: each Goodbye we sent expects exactly one
    /// `request_response::Event::OutboundFailure` or `::Message::Response` from the
    /// `RpcGoodbye` behaviour. One response/failure per peer decrements the counter;
    /// when the counter reaches 0 we return.
    async fn drain_outbound_requests(&mut self, mut expected: usize) {
        use libp2p::swarm::SwarmEvent;
        while expected > 0 {
            let ev = self.swarm.select_next_some().await;
            match &ev {
                SwarmEvent::Behaviour(PharosBehaviourEvent::RpcGoodbye(_)) => {
                    expected = expected.saturating_sub(1);
                    tracing::trace!(remaining = expected, "goodbye drain: RpcGoodbye event");
                }
                _ => {
                    tracing::trace!("goodbye drain: discarding non-goodbye swarm event");
                }
            }
        }
    }

    /// Emit a `NetworkEvent` to the consumer channel with bounded back-pressure.
    ///
    /// **Back-pressure policy** (`D-network-backpressure`):
    /// All call sites are inside `async fn` handlers (`run`, `on_swarm_event`,
    /// `on_gossip_event`, `on_request_response_event`), so an async signature is
    /// the correct approach here. The alternative — keeping `emit_event` sync
    /// and falling back to `tokio::runtime::Handle::current().block_on(timeout(...))`
    /// — would panic inside the tokio runtime because `block_on` cannot be called
    /// from an async context. Therefore this function is `async`.
    ///
    /// Behaviour:
    /// - Awaits `event_tx.send(ev)` under a 1-second timeout.
    /// - If the channel becomes available within 1 second, the event is delivered;
    ///   no events are dropped on a slow-but-live consumer.
    /// - If the consumer is fully stalled for more than 1 second, a warning is
    ///   logged and the function returns without dropping the task (graceful
    ///   degradation). The event is lost in that case, but the network loop
    ///   continues running.
    async fn emit_event(&mut self, ev: NetworkEvent) {
        let variant = ev.variant_name();
        match tokio::time::timeout(Duration::from_secs(1), self.event_tx.send(ev)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                // Receiver dropped; channel is closed.
                tracing::debug!("network event channel closed; event discarded");
            }
            Err(_) => {
                tracing::warn!(
                    event = variant,
                    queue_depth = self.event_channel_capacity,
                    "network event channel full for >1 s; dropping event (consumer stalled)"
                );
            }
        }
    }

    fn on_command(&mut self, cmd: NetworkCommand<E>) {
        match cmd {
            NetworkCommand::Publish {
                topic,
                ssz_payload,
                reply,
            } => {
                let result = self.on_publish_command(topic, ssz_payload);
                let _ = reply.send(result);
            }
            NetworkCommand::Subscribe { topic, reply } => {
                let ident = libp2p::gossipsub::IdentTopic::new(topic.topic_str());
                let result = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&ident)
                    .map(|_| ())
                    .map_err(|e| NetworkError::Libp2p(format!("subscribe failed: {e}")));
                if result.is_ok() {
                    self.topic_map.insert(topic.topic_hash(), topic);
                }
                let _ = reply.send(result);
            }
            NetworkCommand::Unsubscribe { topic, reply } => {
                let ident = libp2p::gossipsub::IdentTopic::new(topic.topic_str());
                // Remove from topic map regardless of unsubscribe result so we
                // stop dispatching messages for this topic.
                self.topic_map.remove(&topic.topic_hash());
                // Idempotent: gossipsub.unsubscribe returns false if we weren't
                // subscribed; that is not an error in the fork-migration path.
                let _ = self.swarm.behaviour_mut().gossipsub.unsubscribe(&ident);
                let _ = reply.send(Ok(()));
            }
            NetworkCommand::UpdateMetaData(new_meta) => {
                // Atomically swap the cached metadata; increment seq_number only
                // when attnets or syncnets actually changed.
                let old = self.host_metadata.load();
                if new_meta.attnets != old.attnets || new_meta.syncnets != old.syncnets {
                    let updated = AltairMetaData {
                        seq_number: old.seq_number.wrapping_add(1),
                        attnets: new_meta.attnets,
                        syncnets: new_meta.syncnets,
                    };
                    self.host_metadata.store(Arc::new(updated));
                }
            }
            NetworkCommand::Dial { addr, reply } => {
                let result = self
                    .swarm
                    .dial(addr)
                    .map_err(|e| NetworkError::Libp2p(e.to_string()));
                let _ = reply.send(result);
            }
            NetworkCommand::Disconnect { peer_id } => {
                self.swarm.disconnect_peer_id(peer_id).ok();
            }
            NetworkCommand::OutgoingRequest { peer, req, reply } => {
                self.on_outgoing_request_command(peer, req, reply);
            }
            // Shutdown is handled in the run() select loop before on_command is called.
            NetworkCommand::Shutdown => {}
            NetworkCommand::PickHighestHeadPeer { reply } => {
                // Iterate connected peers and return the one with the highest
                // `head_slot` in their last `Status` message.  Peers that have
                // not yet completed Status handshake (last_status = None) are
                // skipped.
                let best = self
                    .peer_manager
                    .connected_peers_with_status()
                    .max_by_key(|(_, status)| status.head_slot);
                let _ = reply.send(best.map(|(peer_id, _)| peer_id));
            }
            NetworkCommand::ListPeers { reply } => {
                let _ = reply.send(self.peer_manager.peer_infos());
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Map an `RpcRequest` variant to its `RpcMethod` for scoring.
pub(crate) fn rpc_method_from_request(req: &RpcRequest) -> RpcMethod {
    match req {
        RpcRequest::Status(_) => RpcMethod::Status,
        RpcRequest::Goodbye(_) => RpcMethod::Goodbye,
        RpcRequest::Ping(_) => RpcMethod::Ping,
        RpcRequest::MetaData => RpcMethod::MetaData,
        RpcRequest::MetaDataV1 => RpcMethod::MetaDataV1,
        RpcRequest::BlocksByRange(_) => RpcMethod::BlocksByRange,
        RpcRequest::BlocksByRoot(_) => RpcMethod::BlocksByRoot,
        RpcRequest::LightClientBootstrap(_) => RpcMethod::LightClientBootstrap,
        RpcRequest::LightClientUpdatesByRange(_) => RpcMethod::LightClientUpdatesByRange,
        RpcRequest::LightClientFinalityUpdate => RpcMethod::LightClientFinalityUpdate,
        RpcRequest::LightClientOptimisticUpdate => RpcMethod::LightClientOptimisticUpdate,
        RpcRequest::BlobSidecarsByRange(_) => RpcMethod::BlobSidecarsByRange,
        RpcRequest::BlobSidecarsByRoot(_) => RpcMethod::BlobSidecarsByRoot,
    }
}

// ── NetworkBuilder ────────────────────────────────────────────────────────────

/// Builder for `Network<E, H, S>`.
///
/// Call `new(host)` to start, chain configuration methods, then await
/// `build()`.  The builder starts with `NoopScorer`; call `.scorer(s)` to
/// substitute a real scorer.
///
/// Defaults:
/// - `listen_ip`: `127.0.0.1`
/// - `tcp_listen_port`: `9000`
/// - `quic_listen_port`: `None` (QUIC transport is wired for dialling but
///   no listener is started)
/// - `no_tcp`: `false` (TCP listener is started by default)
/// - `discv5_addr`: `127.0.0.1:9001` (note: UDP; avoids collision with TCP 9000)
/// - `local_key`: freshly generated secp256k1 keypair
/// - `bootnodes`: empty
/// - `event_channel_capacity`: 1024 (see `event_channel_capacity` for rationale)
pub struct NetworkBuilder<E, H, S> {
    host: Arc<H>,
    listen_ip: IpAddr,
    tcp_listen_port: u16,
    quic_listen_port: Option<u16>,
    /// When `true`, the TCP listener is NOT started. Used for QUIC-only test
    /// nodes (Task 8.2) where only the QUIC transport should be reachable.
    no_tcp: bool,
    discv5_addr: SocketAddr,
    bootnodes: Vec<Enr>,
    local_key: Keypair,
    scorer: S,
    /// Capacity of the `mpsc` channel from `Network` to `NetworkHandle`.
    ///
    /// Default: 1024. See `event_channel_capacity` for the trade-off.
    event_channel_capacity: usize,
    /// Hard cap on connected peers (M11 Phase 12). Default: 50.
    max_peers: usize,
    /// Desired steady-state connected peer count (M11 Phase 12). Default: 50.
    target_peers: usize,
    /// Directory for ENR seq persistence (`D-enr-seq-persistence`). `None`
    /// disables persistence (tests, ephemeral nodes).
    network_dir: Option<std::path::PathBuf>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, H: Host<E> + LightClientProvider<E> + BlobProvider<E>>
    NetworkBuilder<E, H, crate::scoring::NoopScorer>
{
    /// Create a new builder wrapping `host` with default settings.
    ///
    /// Returns a builder with `NoopScorer`; call `.scorer(s)` to
    /// provide a real implementation.
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
            listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            tcp_listen_port: 9000,
            quic_listen_port: None,
            no_tcp: false,
            discv5_addr: "127.0.0.1:9001".parse().unwrap(),
            bootnodes: Vec::new(),
            local_key: Keypair::generate_secp256k1(),
            scorer: crate::scoring::NoopScorer,
            event_channel_capacity: 1024,
            max_peers: 50,
            target_peers: 50,
            network_dir: None,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec, H: Host<E> + LightClientProvider<E> + BlobProvider<E>, S: PeerScorer>
    NetworkBuilder<E, H, S>
{
    /// Override the TCP listen port (default: 9000).
    pub fn tcp_listen_port(mut self, port: u16) -> Self {
        self.tcp_listen_port = port;
        self
    }

    /// Set an optional QUIC listen port.
    ///
    /// When `None` (the default) the QUIC transport is still configured for
    /// dialling but no UDP listener is started.
    pub fn quic_listen_port(mut self, port: Option<u16>) -> Self {
        self.quic_listen_port = port;
        self
    }

    /// Override the IP address for both TCP and QUIC listeners (default: `127.0.0.1`).
    pub fn listen_ip(mut self, ip: IpAddr) -> Self {
        self.listen_ip = ip;
        self
    }

    /// Disable the TCP listener.
    ///
    /// When `true`, the TCP listener is NOT started. Used for QUIC-only test
    /// nodes where only the QUIC transport should be reachable. Requires
    /// `quic_listen_port` to be set.
    pub fn no_tcp(mut self, v: bool) -> Self {
        self.no_tcp = v;
        self
    }

    /// Set the discv5 UDP listen address (default: `127.0.0.1:9001`).
    ///
    /// Note: discv5 uses UDP, distinct from the libp2p TCP port.
    pub fn discv5_addr(mut self, addr: SocketAddr) -> Self {
        self.discv5_addr = addr;
        self
    }

    /// Set bootstrap ENRs for discv5 routing table population.
    pub fn bootnodes(mut self, enrs: Vec<Enr>) -> Self {
        self.bootnodes = enrs;
        self
    }

    /// Override the local libp2p identity keypair (default: generated secp256k1).
    pub fn local_key(mut self, key: Keypair) -> Self {
        self.local_key = key;
        self
    }

    /// Substitute a peer scorer, changing the `S` type parameter.
    pub fn scorer<T: PeerScorer>(self, scorer: T) -> NetworkBuilder<E, H, T>
    where
        H: Host<E> + LightClientProvider<E> + BlobProvider<E>,
    {
        NetworkBuilder {
            host: self.host,
            listen_ip: self.listen_ip,
            tcp_listen_port: self.tcp_listen_port,
            quic_listen_port: self.quic_listen_port,
            no_tcp: self.no_tcp,
            discv5_addr: self.discv5_addr,
            bootnodes: self.bootnodes,
            local_key: self.local_key,
            scorer,
            event_channel_capacity: self.event_channel_capacity,
            max_peers: self.max_peers,
            target_peers: self.target_peers,
            network_dir: self.network_dir,
            _phantom: PhantomData,
        }
    }

    /// Set the hard cap on connected peers (default: 50).
    ///
    /// Inbound connections beyond this limit are rejected immediately at the
    /// swarm level (per M11 Phase 12 `D-connection-limit-prefer-high-score`).
    pub fn max_peers(mut self, max_peers: usize) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Set the desired steady-state peer count (default: 50).
    ///
    /// The discv5 discovery cadence scales with `target_peers - connected_peers`
    /// (per M11 Phase 12); `tick_score_prune` prunes to this level.
    pub fn target_peers(mut self, target_peers: usize) -> Self {
        self.target_peers = target_peers;
        self
    }

    /// Set the directory for ENR sequence-number persistence across restarts
    /// (`D-enr-seq-persistence`, M11 Phase 13).
    ///
    /// When set, the ENR seq is loaded from `<dir>/enr_seq` on startup and
    /// written back after every ENR mutation so restarts yield monotonically
    /// increasing sequence numbers. Pass the node's `<data-dir>/network/`
    /// directory. When absent (default) persistence is disabled.
    pub fn network_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.network_dir = Some(dir);
        self
    }

    /// Set the capacity of the outbound event channel (`Network → NetworkHandle`).
    ///
    /// **Default**: 1024.
    ///
    /// **Trade-off** (`D-network-backpressure`): a larger buffer absorbs short
    /// consumer stalls without back-pressure, at the cost of higher memory use
    /// and delayed drop detection. A smaller buffer (e.g. 2 in tests) exercises
    /// the bounded-await path sooner. The default of 1024 is sized for ~2 slots
    /// of worst-case mainnet gossip load (each slot can produce O(100) gossip
    /// events); a well-behaved consumer drains the channel inside one slot period
    /// (12 s). Values below 64 are uncommon in production but useful in tests.
    pub fn event_channel_capacity(mut self, capacity: usize) -> Self {
        self.event_channel_capacity = capacity;
        self
    }

    /// Construct the `Network` and return `(Network, NetworkHandle<E>, DiscoveryHandle)`.
    ///
    /// Steps:
    /// 1. Derive the discv5 `CombinedKey` from the libp2p secp256k1 keypair.
    /// 2. Compute initial subnet subscriptions from the node-id.
    /// 3. Start `DiscoveryService`.
    /// 4. Build the libp2p swarm via `SwarmBuilder`.
    /// 5. Subscribe to Phase-0 gossipsub topics; build the topic lookup map.
    /// 6. Add TCP listener; optionally add QUIC listener.
    /// 7. Wire mpsc channels and oneshot shutdown signal.
    pub async fn build(
        self,
    ) -> Result<(Network<E, H, S>, NetworkHandle<E>, DiscoveryHandle), NetworkError> {
        // ── Step 1: bridge libp2p keypair → discv5 CombinedKey ───────────────
        //
        // Extract the secp256k1 secret bytes from the libp2p keypair and
        // reconstruct a discv5 `CombinedKey`.  The `Keypair::try_into_secp256k1`
        // method clones the inner key; we use `secret().to_bytes()` to get the
        // 32-byte secret scalar.
        let secp_kp = self
            .local_key
            .clone()
            .try_into_secp256k1()
            .map_err(|_| NetworkError::Libp2p("keypair is not secp256k1".into()))?;
        let mut secret_bytes = secp_kp.secret().to_bytes();
        let combined_key = discv5::enr::CombinedKey::secp256k1_from_bytes(&mut secret_bytes)
            .map_err(|e| NetworkError::Libp2p(format!("CombinedKey from secret: {e}")))?;

        // ── Step 2: compute initial subnet subscriptions ──────────────────────
        let node_id = discv5::enr::NodeId::from(combined_key.public());
        let subnets = compute_subscribed_subnets::<E>(node_id, 0);
        let mut attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();
        for subnet_id in subnets {
            attnets.set(subnet_id as usize, true);
        }

        // ── Step 3: start DiscoveryService ───────────────────────────────────
        let fork_id = self.host.enr_fork_id();
        let fork_digest = self.host.current_fork_digest();
        // Clone bootnodes so the Network struct can dial them directly at startup.
        let bootnodes_for_network = self.bootnodes.clone();
        let discovery = DiscoveryService::start(DiscoveryConfig {
            listen_addr: self.discv5_addr,
            tcp_port: self.tcp_listen_port,
            quic_port: self.quic_listen_port,
            bootnodes: self.bootnodes,
            local_key: combined_key,
            fork_id,
            attnets: attnets.clone(),
            network_dir: self.network_dir,
        })
        .await?;

        // ── Step 4: build the libp2p swarm ────────────────────────────────────
        let local_key = self.local_key.clone();
        let public_key = local_key.public();

        // Use the spec-conforming gossipsub config.
        //
        // The message-id closure (in `gossip::config::gossipsub_behaviour`) takes
        // the PHASE-0 fork digest as a sentinel to distinguish the two message-id
        // formulas: phase0 topics match the sentinel and use the
        // `message_domain_valid_snappy ++ data` SHA256 formula; all other fork
        // digests (altair, bellatrix, …) fall through to the altair formula
        // (`first_8_bytes(SHA256(MESSAGE_DOMAIN_VALID_SNAPPY ++ topic_len ++ topic ++ data))`).
        //
        // Bellatrix uses the SAME message-id formula as altair
        // (`specs/bellatrix/p2p-interface.md` inherits from altair p2p-interface).
        // After Ph2, `fork_digest_for(Fork::Phase0)` is always the REAL phase0
        // digest (≠ bellatrix digest) regardless of the active fork, so the
        // comparison in the closure is spec-correct: bellatrix messages take the
        // else-branch (altair formula) as required.
        let phase0_fork_digest = self.host.fork_digest_for(crate::types::Fork::Phase0);
        let gossipsub = gossipsub_behaviour::<E>(phase0_fork_digest)?;

        // Build one request_response::Behaviour per RPC method so that
        // multistream-select negotiates the exact per-method protocol string.
        // Using a single behaviour with all six protocols causes multistream-select
        // to always pick the first registered protocol (Status) for every request.
        use crate::rpc::codec::RpcCodec;
        use crate::rpc::protocol::RpcProtocol;
        use crate::scoring::RpcMethod as M;
        use behaviour::{
            RpcBlobSidecarsByRangeBehaviour, RpcBlobSidecarsByRootBehaviour,
            RpcBlocksByRangeBehaviour, RpcBlocksByRootBehaviour, RpcGoodbyeBehaviour,
            RpcLcBootstrapBehaviour, RpcLcFinalityUpdateBehaviour, RpcLcOptimisticUpdateBehaviour,
            RpcLcUpdatesByRangeBehaviour, RpcMetaDataBehaviour, RpcMetaDataV1Behaviour,
            RpcPingBehaviour, RpcStatusBehaviour,
        };

        // Fork-context codec: used for methods that carry context bytes
        // (`specs/altair/p2p-interface.md:445-461`).
        let fork_ctx_arc: Arc<dyn crate::host::ForkContext> = self.host.clone();
        let ctx_codec = RpcCodec::<E>::with_fork_context(fork_ctx_arc);

        let mk_rr = |method: M| {
            request_response::Behaviour::new(
                vec![(RpcProtocol(method), ProtocolSupport::Full)],
                request_response::Config::default(),
            )
        };
        let mk_rr_ctx = |method: M| {
            request_response::Behaviour::with_codec(
                ctx_codec.clone(),
                vec![(RpcProtocol(method), ProtocolSupport::Full)],
                request_response::Config::default(),
            )
        };

        let identify_cfg = identify::Config::new("pharos/libp2p".into(), public_key.clone())
            .with_agent_version(pharos_utils::version::AGENT_STRING.to_string());
        let identify = identify::Behaviour::new(identify_cfg);
        let ping = ping::Behaviour::new(ping::Config::default());

        let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                transport::tcp_config(),
                noise::Config::new,
                transport::yamux_config,
            )
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?
            .with_quic()
            .with_dns()?
            .with_behaviour(|_key| PharosBehaviour::<E> {
                gossipsub,
                rpc_status: RpcStatusBehaviour(mk_rr(M::Status)),
                rpc_goodbye: RpcGoodbyeBehaviour(mk_rr(M::Goodbye)),
                rpc_ping: RpcPingBehaviour(mk_rr(M::Ping)),
                rpc_metadata: RpcMetaDataBehaviour(mk_rr(M::MetaData)),
                rpc_metadata_v1: RpcMetaDataV1Behaviour(mk_rr(M::MetaDataV1)),
                rpc_blocks_by_range: RpcBlocksByRangeBehaviour(mk_rr_ctx(M::BlocksByRange)),
                rpc_blocks_by_root: RpcBlocksByRootBehaviour(mk_rr_ctx(M::BlocksByRoot)),
                // Light-client behaviours use context-bytes codec (fork digest prefix per chunk).
                rpc_lc_bootstrap: RpcLcBootstrapBehaviour(mk_rr_ctx(M::LightClientBootstrap)),
                rpc_lc_updates_by_range: RpcLcUpdatesByRangeBehaviour(mk_rr_ctx(
                    M::LightClientUpdatesByRange,
                )),
                rpc_lc_finality_update: RpcLcFinalityUpdateBehaviour(mk_rr_ctx(
                    M::LightClientFinalityUpdate,
                )),
                rpc_lc_optimistic_update: RpcLcOptimisticUpdateBehaviour(mk_rr_ctx(
                    M::LightClientOptimisticUpdate,
                )),
                // Blob-sidecar behaviours use context-bytes codec (fork digest prefix per chunk).
                rpc_blob_sidecars_by_range: RpcBlobSidecarsByRangeBehaviour(mk_rr_ctx(
                    M::BlobSidecarsByRange,
                )),
                rpc_blob_sidecars_by_root: RpcBlobSidecarsByRootBehaviour(mk_rr_ctx(
                    M::BlobSidecarsByRoot,
                )),
                identify,
                ping,
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(transport::idle_timeout()))
            .build();

        // ── Step 5: subscribe to active-fork topics and build lookup map ─────
        //
        // `fork_digest` is `host.current_fork_digest()`, which after Ph2 is the
        // ACTIVE fork digest at startup (bellatrix when both altair+bellatrix are
        // at epoch 0, phase0 for a plain phase0 genesis).
        //
        // Base topics (5 beacon topics + attnets) are always subscribed.  When
        // the active fork is altair or bellatrix, the altair-era extras
        // (sync_committee_*, light_client_*) are also subscribed under the same
        // active digest so a bellatrix-at-genesis node starts on the full set.
        // (`D-bellatrix-startup-topic-set`)
        let mut swarm = swarm;
        let mut topic_map =
            subscribe_base_topics(&mut swarm.behaviour_mut().gossipsub, fork_digest, &attnets)?;

        // Determine the active fork from the digest; subscribe altair extras if ≥ altair.
        let active_fork = self.host.fork_from_context(&fork_digest.into_inner());
        match active_fork {
            Some(crate::types::Fork::Altair)
            | Some(crate::types::Fork::Bellatrix)
            | Some(crate::types::Fork::Capella) => {
                subscribe_altair_extra_topics::<E>(
                    &mut swarm.behaviour_mut().gossipsub,
                    fork_digest,
                    &mut topic_map,
                )?;
            }
            Some(crate::types::Fork::Deneb) | Some(crate::types::Fork::Electra) => {
                // Deneb/Electra: altair extras + the EIP-4844 blob_sidecar subnets.
                // Electra keeps the same gossip topic set as Deneb (the
                // beacon_attestation_* / beacon_aggregate_and_proof topics carry
                // the EIP-7549 attestation types but the topic NAMES are unchanged,
                // and they are already subscribed by `subscribe_base_topics`).
                // Per `specs/electra/p2p-interface.md:101-118`.
                subscribe_altair_extra_topics::<E>(
                    &mut swarm.behaviour_mut().gossipsub,
                    fork_digest,
                    &mut topic_map,
                )?;
                subscribe_deneb_blob_topics::<E>(
                    &mut swarm.behaviour_mut().gossipsub,
                    fork_digest,
                    &mut topic_map,
                )?;
            }
            // Phase0 or unknown digest: base topics only. No `_ =>` catch-all:
            // every `Fork` variant is matched explicitly so a future fork is a
            // compile error here rather than a silent topic-set regression.
            Some(crate::types::Fork::Phase0) | None => {}
        }

        // ── Step 6: add listeners ─────────────────────────────────────────────
        if !self.no_tcp {
            let tcp_addr: libp2p::Multiaddr =
                format!("/ip4/{}/tcp/{}", self.listen_ip, self.tcp_listen_port)
                    .parse()
                    .map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?;
            swarm
                .listen_on(tcp_addr)
                .map_err(|e| NetworkError::Libp2p(e.to_string()))?;
        }

        if let Some(quic_port) = self.quic_listen_port {
            let quic_addr: libp2p::Multiaddr =
                format!("/ip4/{}/udp/{}/quic-v1", self.listen_ip, quic_port)
                    .parse()
                    .map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?;
            swarm
                .listen_on(quic_addr)
                .map_err(|e| NetworkError::Libp2p(e.to_string()))?;
        }

        // ── Step 7: wire channels ─────────────────────────────────────────────
        let (cmd_tx, command_rx) = mpsc::channel::<NetworkCommand<E>>(64);
        let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(self.event_channel_capacity);
        let (shutdown_tx, shutdown_signal) = oneshot::channel::<()>();

        // Discovery command channel: `DiscoveryHandle` sends commands, the
        // `Network::run` loop polls and dispatches them to `DiscoveryService`.
        let (discovery_handle, discovery_cmd_rx) = discovery_channel();

        let peer_manager = PeerManager::new(self.scorer, self.max_peers, self.target_peers);

        // Discovery poll interval: 30 seconds.
        let discovery_tick = interval(std::time::Duration::from_secs(30));
        let ping_tick = interval(std::time::Duration::from_secs(15));
        let score_prune_tick = interval(std::time::Duration::from_secs(30));

        let local_peer_id = *swarm.local_peer_id();

        // Initialise the cached metadata from the host so the first Ping
        // response reflects the node's current seq_number / attnets / syncnets.
        let initial_meta = self.host.local_metadata();
        let host_metadata = Arc::new(ArcSwap::from_pointee(initial_meta));
        // Clone the Arc so `NetworkHandle` can expose live metadata reads to
        // external consumers (e.g. the Beacon API `NodeIdentityCache`) without
        // holding a reference to the non-Clone `Network` or `NetworkHandle`.
        let host_metadata_ref = Arc::clone(&host_metadata);

        let network = Network {
            swarm,
            discovery,
            peer_manager,
            host: self.host,
            host_metadata,
            topic_map,
            command_rx,
            discovery_cmd_rx,
            event_tx,
            event_channel_capacity: self.event_channel_capacity,
            discovery_tick,
            shutdown_signal,
            pending_rpc: HashMap::new(),
            pending_status_checks: HashMap::new(),
            pending_ping_checks: HashMap::new(),
            pending_metadata_fetches: HashMap::new(),
            ping_tick,
            score_prune_tick,
            bootnodes: bootnodes_for_network,
            pending_dials: HashMap::new(),
            gossip_tasks: tokio::task::JoinSet::new(),
            _phantom: PhantomData,
        };

        let handle = NetworkHandle::new(
            cmd_tx,
            event_rx,
            shutdown_tx,
            local_peer_id,
            node_id,
            host_metadata_ref,
        );

        Ok((network, handle, discovery_handle))
    }

    /// Build, spawn the network task on the current Tokio runtime, and return
    /// `(NetworkHandle<E>, DiscoveryHandle)`.
    ///
    /// The spawned task owns the `Network` and drives its `run()` loop.
    /// The returned `NetworkHandle` is the single owner of the event-receiver side.
    /// The returned `DiscoveryHandle` allows cross-fork ENR updates (Task 7.4).
    pub async fn spawn(self) -> Result<(NetworkHandle<E>, DiscoveryHandle), NetworkError>
    where
        H: 'static,
        S: 'static,
    {
        let (network, handle, discovery_handle) = self.build().await?;
        tokio::spawn(async move {
            if let Err(e) = network.run().await {
                tracing::error!("network task exited with error: {e}");
            } else {
                tracing::info!("network shutdown complete");
            }
        });
        Ok((handle, discovery_handle))
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────
//
// These methods are unconditionally `pub` so that integration tests in
// `tests/` (which are separate crates) can access them.  The `test_` prefix
// and `#[doc(hidden)]` make the intent clear: these are NOT production API.

impl<
    E: EthSpec,
    H: Host<E> + LightClientProvider<E> + BlobProvider<E> + Send + Sync + 'static,
    S: PeerScorer,
> Network<E, H, S>
{
    /// Returns `true` if `peer_id` is in the peer table and has a known
    /// `last_status` (i.e. completed the Status handshake).
    ///
    /// Only for test use; not part of the production API.
    #[doc(hidden)]
    pub fn test_peer_has_status(&self, peer_id: &PeerId) -> bool {
        self.peer_manager
            .connected_peers_with_status()
            .any(|(id, _)| id == *peer_id)
    }

    /// Returns `true` if `peer_id` is present in the peer table (any state).
    ///
    /// Only for test use; not part of the production API.
    #[doc(hidden)]
    pub fn test_peer_is_registered(&self, peer_id: &PeerId) -> bool {
        self.peer_manager.peer_state(peer_id).is_some()
    }

    /// Returns the number of entries currently in `pending_dials`.
    ///
    /// Only for test use; not part of the production API.
    /// Unconditionally `pub` so integration tests in `tests/` (separate crates) can access it.
    #[doc(hidden)]
    pub fn test_pending_dials_len(&self) -> usize {
        self.pending_dials.len()
    }

    /// Returns `true` if `peer_id` is in `pending_dials`.
    ///
    /// Only for test use; not part of the production API.
    /// Unconditionally `pub` so integration tests in `tests/` (separate crates) can access it.
    #[doc(hidden)]
    pub fn test_pending_dials_contains(&self, p: &PeerId) -> bool {
        self.pending_dials.contains_key(p)
    }

    /// Register a peer as `Connected` in the peer manager (M11 Phase 11 e2e
    /// test seam). Mirrors what `on_swarm_connection_established` does for the
    /// peer-table side so score-driven prune/gauge logic has a live peer set.
    #[doc(hidden)]
    pub fn test_register_connected_peer(&mut self, peer_id: PeerId) {
        self.peer_manager
            .on_connected(peer_id, ConnectionDirection::Inbound, Vec::new());
        self.peer_manager.on_handshake_complete(peer_id);
    }

    /// Drive the real `on_gossip_event` mapping for a synthetic gossipsub event
    /// (M11 Phase 11 e2e test seam). Used to feed `SlowPeer` / `Unsubscribed`.
    #[doc(hidden)]
    pub async fn test_on_gossip_event(&mut self, event: gossipsub::Event) {
        self.on_gossip_event(event).await;
    }

    /// Current scorer score for `peer_id` (M11 Phase 11 e2e test seam).
    #[doc(hidden)]
    pub fn test_peer_score(&self, peer_id: &PeerId) -> f64 {
        self.peer_manager.score(peer_id)
    }

    /// Lowest-scoring peers per the scorer (M11 Phase 11 e2e test seam).
    #[doc(hidden)]
    pub fn test_worst_peers(&self, count: usize) -> Vec<PeerId> {
        self.peer_manager.should_prune_n(count)
    }

    /// Drive the real per-method inbound rate-limit gate + penalty exactly as
    /// `handle_request` does (M11 Phase 11 e2e test seam). Returns `true` when
    /// the request is allowed; on rejection it records `RateLimitExceeded`,
    /// matching the wired handler path.
    #[doc(hidden)]
    pub fn test_rate_limit_request(&mut self, peer_id: PeerId, method: RpcMethod) -> bool {
        if self.peer_manager.allow_request(peer_id, method) {
            true
        } else {
            self.peer_manager
                .record_event(peer_id, ScoreEvent::RateLimitExceeded { method });
            self.emit_peer_score_gauge(&peer_id);
            false
        }
    }

    /// Drive the real score-prune enforcement tick (M11 Phase 11 e2e test seam).
    #[doc(hidden)]
    pub fn test_tick_score_prune(&mut self) {
        self.tick_score_prune();
    }

    /// `true` if the peer manager currently holds an active ban for `peer_id`
    /// (M11 Phase 11 e2e test seam).
    #[doc(hidden)]
    pub fn test_peer_is_banned(&self, peer_id: &PeerId) -> bool {
        self.peer_manager.is_banned(peer_id)
    }

    /// Current connected peer count (M11 Phase 12 test seam).
    #[doc(hidden)]
    pub fn test_peer_count(&self) -> usize {
        self.peer_manager.peer_count()
    }

    /// `max_peers` configured on this network (M11 Phase 12 test seam).
    #[doc(hidden)]
    pub fn test_max_peers(&self) -> usize {
        self.peer_manager.max_peers()
    }

    /// `target_peers` configured on this network (M11 Phase 12 test seam).
    #[doc(hidden)]
    pub fn test_target_peers(&self) -> usize {
        self.peer_manager.target_peers()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{
        BlockProvider, ForkContext, GossipValidator, GossipVerdict, LightClientProvider,
    };
    use crate::types::SubnetId;
    use pharos_types::MainnetEthSpec;
    use pharos_types::altair::MetaData as AltairMetaData;
    use pharos_types::phase0::primitives::ForkDigest;
    use pharos_types::phase0::{
        Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing, Root,
        SignedAggregateAndProof, SignedVoluntaryExit, Slot,
    };
    use pharos_utils::{Bytes4, Epoch};

    struct MockHost;

    impl ForkContext for MockHost {
        fn current_fork_digest(&self) -> ForkDigest {
            ForkDigest::from_array([0u8; 4])
        }
        fn enr_fork_id(&self) -> ENRForkID {
            ENRForkID {
                fork_digest: Bytes4::from_array([0u8; 4]),
                next_fork_version: Bytes4::from_array([0u8; 4]),
                next_fork_epoch: Epoch(u64::MAX),
            }
        }
        fn genesis_validators_root(&self) -> Root {
            Root::default()
        }
        fn fork_digest_for(&self, fork: crate::types::Fork) -> ForkDigest {
            use crate::types::Fork;
            // MockHost uses the zero digest for every fork; the explicit match
            // forces an update here if a future Fork variant is added.
            match fork {
                Fork::Phase0
                | Fork::Altair
                | Fork::Bellatrix
                | Fork::Capella
                | Fork::Deneb
                | Fork::Electra => ForkDigest::from_array([0u8; 4]),
            }
        }
        fn fork_from_context(&self, _ctx: &[u8; 4]) -> Option<crate::types::Fork> {
            None
        }
        fn local_metadata(&self) -> AltairMetaData {
            AltairMetaData::default()
        }
    }

    impl LightClientProvider<MainnetEthSpec> for MockHost {
        fn light_client_bootstrap(
            &self,
            _block_root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::AltairLightClientBootstrap> {
            None
        }
        fn light_client_updates_by_range(
            &self,
            _start_period: u64,
            _count: u64,
        ) -> Vec<<MainnetEthSpec as EthSpec>::AltairLightClientUpdate> {
            Vec::new()
        }
        fn light_client_finality_update(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::AltairLightClientFinalityUpdate> {
            None
        }
        fn light_client_optimistic_update(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::AltairLightClientOptimisticUpdate> {
            None
        }

        fn light_client_finality_update_capella(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::CapellaLightClientFinalityUpdate> {
            None
        }

        fn light_client_optimistic_update_capella(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::CapellaLightClientOptimisticUpdate> {
            None
        }

        fn light_client_finality_update_deneb(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::DenebLightClientFinalityUpdate> {
            None
        }

        fn light_client_optimistic_update_deneb(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::DenebLightClientOptimisticUpdate> {
            None
        }

        fn light_client_finality_update_electra(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::ElectraLightClientFinalityUpdate> {
            None
        }

        fn light_client_optimistic_update_electra(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::ElectraLightClientOptimisticUpdate> {
            None
        }
    }

    impl BlockProvider<MainnetEthSpec> for MockHost {
        fn block_by_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            None
        }
        fn blocks_by_range(
            &self,
            _start_slot: Slot,
            _count: u64,
        ) -> Vec<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            Vec::new()
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            Checkpoint {
                root: Root::default(),
                epoch: Epoch(0),
            }
        }
        fn head(&self) -> (Root, Slot) {
            (Root::default(), Slot(0))
        }
    }

    impl GossipValidator<MainnetEthSpec> for MockHost {
        fn validate_beacon_block(
            &self,
            _block: &<MainnetEthSpec as EthSpec>::SignedBeaconBlock,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_attestation(
            &self,
            _subnet: SubnetId,
            _att: &Attestation<2048>,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_aggregate_and_proof(
            &self,
            _msg: &SignedAggregateAndProof<2048>,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_voluntary_exit(&self, _exit: &SignedVoluntaryExit) -> GossipVerdict {
            unreachable!()
        }
        fn validate_proposer_slashing(&self, _slashing: &ProposerSlashing) -> GossipVerdict {
            unreachable!()
        }
        fn validate_attester_slashing(&self, _slashing: &AttesterSlashing<2048>) -> GossipVerdict {
            unreachable!()
        }
        fn validate_sync_committee_message(
            &self,
            _subnet: SubnetId,
            _msg: &pharos_types::altair::SyncCommitteeMessage,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_sync_committee_contribution_and_proof(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::AltairSignedContributionAndProof,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_light_client_finality_update(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::AltairLightClientFinalityUpdate,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_light_client_optimistic_update(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::AltairLightClientOptimisticUpdate,
        ) -> GossipVerdict {
            unreachable!()
        }

        fn validate_bls_to_execution_change(
            &self,
            _msg: &pharos_types::capella::operations::SignedBLSToExecutionChange,
        ) -> GossipVerdict {
            unreachable!()
        }

        fn validate_capella_light_client_finality_update(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::CapellaLightClientFinalityUpdate,
        ) -> GossipVerdict {
            unreachable!()
        }

        fn validate_capella_light_client_optimistic_update(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::CapellaLightClientOptimisticUpdate,
        ) -> GossipVerdict {
            unreachable!()
        }

        fn validate_blob_sidecar(
            &self,
            _subnet: SubnetId,
            _sidecar: &pharos_types::deneb::BlobSidecar,
        ) -> GossipVerdict {
            unreachable!()
        }
    }

    impl BlobProvider<MainnetEthSpec> for MockHost {
        fn blobs_by_range(
            &self,
            _start_slot: pharos_types::phase0::primitives::Slot,
            _count: u64,
        ) -> Vec<pharos_types::deneb::BlobSidecar> {
            vec![]
        }

        fn blobs_by_root(
            &self,
            _ids: &[(pharos_types::phase0::primitives::Root, u64)],
        ) -> Vec<pharos_types::deneb::BlobSidecar> {
            vec![]
        }
    }

    /// Verify that `Network::run` exits cleanly when `NetworkHandle::shutdown`
    /// is called.
    ///
    /// Uses `multi_thread` flavor because discv5 and libp2p both spawn Tokio
    /// tasks internally.
    #[tokio::test(flavor = "multi_thread")]
    async fn network_shutdown_smoke() {
        let (network, handle, _discovery_handle) =
            NetworkBuilder::<MainnetEthSpec, MockHost, _>::new(MockHost)
                .build()
                .await
                .expect("NetworkBuilder::build failed");

        let task = tokio::spawn(async move { network.run().await });

        handle.shutdown().await;

        let result = task.await.expect("network task panicked");
        assert!(result.is_ok(), "Network::run returned an error: {result:?}");
    }

    /// M11 Phase 11: only per-subnet topics are scored for subnet coverage; the
    /// `Unsubscribed` arm penalises a peer that leaves one of them.
    #[test]
    fn subnet_topics_are_scored_for_coverage() {
        use crate::topics::{GossipTopicKind, is_subnet_topic};
        assert!(is_subnet_topic(&GossipTopicKind::BeaconAttestation(3)));
        assert!(is_subnet_topic(&GossipTopicKind::SyncCommittee(1)));
        assert!(is_subnet_topic(&GossipTopicKind::BlobSidecar(0)));
        assert!(!is_subnet_topic(&GossipTopicKind::BeaconBlock));
        assert!(!is_subnet_topic(&GossipTopicKind::BeaconAggregateAndProof));
        assert!(!is_subnet_topic(&GossipTopicKind::VoluntaryExit));
    }

    /// M11 Phase 11 task 4: the peer-score gauge bucket label tracks the score
    /// region (ban / disconnect / negative / healthy / excellent).
    #[test]
    fn score_bucket_labels_partition_the_range() {
        assert_eq!(super::score_bucket_label(-200.0), "banned");
        assert_eq!(super::score_bucket_label(-100.0), "banned");
        assert_eq!(super::score_bucket_label(-75.0), "disconnect");
        assert_eq!(super::score_bucket_label(-50.0), "disconnect");
        assert_eq!(super::score_bucket_label(-1.0), "negative");
        assert_eq!(super::score_bucket_label(0.0), "negative");
        assert_eq!(super::score_bucket_label(25.0), "healthy");
        assert_eq!(super::score_bucket_label(50.0), "healthy");
        assert_eq!(super::score_bucket_label(100.0), "excellent");
    }
}
