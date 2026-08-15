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
use pharos_types::phase0::Status as BeaconStatus;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, interval};

use discv5::enr::EnrKey as _;

use crate::codec::snappy_frame::encode_snappy_frame;
use crate::discovery::enr::Enr;
use crate::discovery::service::{DiscoveryConfig, DiscoveryService};
use crate::discovery::subnets::compute_subscribed_subnets;
use crate::error::NetworkError;
use crate::gossip::config::gossipsub_behaviour;
use crate::gossip::{dispatch_gossip_message, subscribe_phase0_topics};
use crate::handle::NetworkHandle;
use crate::host::{GossipVerdict, Host};
use crate::peer::manager::PeerManager;
use crate::rpc::handler::handle_request;
use crate::rpc::types::{RpcRequest, RpcResponse};
use crate::scoring::{HandshakeFailKind, PeerScorer, RpcErrorKind, RpcMethod, ScoreEvent};
use crate::topics::GossipTopic;
use crate::types::{ConnectionDirection, GOODBYE_FAULT_ERROR, GOODBYE_IRRELEVANT_NETWORK};

use behaviour::{PharosBehaviour, PharosBehaviourEvent};

// ── Commands and Events ───────────────────────────────────────────────────────

/// Commands sent from `NetworkHandle` to the `Network` event loop.
///
/// Phase 7 expands this with dial, gossip-publish, subnet-subscribe, and
/// status-update variants.
pub enum NetworkCommand {
    /// Request a clean shutdown of the network task.
    Shutdown,
}

/// Events emitted from the `Network` event loop to external consumers.
///
/// Phase 4, 5, and 6 add gossip-received, rpc-request, and peer-status
/// variants.  An empty enum cannot be constructed; the channel field is
/// present for the type system only.
pub enum NetworkEvent {}

// ── Network ───────────────────────────────────────────────────────────────────

/// The running network task.
///
/// Constructed via `NetworkBuilder::build`.  Call `run()` to drive the
/// event loop.  Shut down by sending `NetworkCommand::Shutdown` via the
/// `NetworkHandle` or by dropping the handle's `shutdown_tx`.
pub struct Network<E: EthSpec, H: Host<E>, S: PeerScorer> {
    swarm: Swarm<PharosBehaviour<E>>,
    discovery: DiscoveryService,
    peer_manager: PeerManager<S>,
    host: Arc<H>,
    /// Maps subscribed topic hashes to their parsed `GossipTopic` for dispatch.
    topic_map: HashMap<TopicHash, GossipTopic>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<NetworkEvent>,
    discovery_tick: Interval,
    shutdown_signal: oneshot::Receiver<()>,
    /// Pending outbound RPC requests: maps `OutboundRequestId` to the
    /// originating method and the oneshot channel to resolve.
    #[allow(clippy::type_complexity)]
    pending_rpc: HashMap<
        OutboundRequestId,
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
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, H: Host<E>, S: PeerScorer> Network<E, H, S> {
    /// Drive the network event loop.
    ///
    /// Returns when a `NetworkCommand::Shutdown` is received or when
    /// the shutdown signal fires.
    pub async fn run(mut self) -> Result<(), NetworkError> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.on_swarm_event(event).await;
                }
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(NetworkCommand::Shutdown) => break,
                        None => break, // channel closed
                    }
                }
                _ = self.discovery_tick.tick() => {
                    // Run a discv5 FINDNODE query and drain results.
                    // Conversion of discovered ENRs to multiaddrs and dialling
                    // is wired in Phase 7.
                    let _peers = self.discovery.find_peers().await;
                }
                _ = self.ping_tick.tick() => {
                    self.tick_ping();
                }
                _ = self.score_prune_tick.tick() => {
                    self.tick_score_prune();
                }
                _ = &mut self.shutdown_signal => {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn on_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<PharosBehaviourEvent<E>>) {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::Gossipsub(gs_event)) => {
                self.on_gossip_event(gs_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RequestResponse(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.on_swarm_connection_established(peer_id, endpoint);
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                self.on_swarm_connection_closed(peer_id, cause.as_ref());
            }
            _ => {
                tracing::debug!("swarm event: {:?}", event);
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
                tracing::debug!(%peer_id, ?topic, "peer subscribed");
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                tracing::debug!(%peer_id, ?topic, "peer unsubscribed");
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                tracing::debug!(%peer_id, "gossipsub not supported");
            }
            gossipsub::Event::SlowPeer { peer_id, .. } => {
                tracing::debug!(%peer_id, "slow peer");
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

        // Decode and validate via the host.
        let verdict = dispatch_gossip_message::<E, H>(self.host.as_ref(), &topic, &message.data);

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

        // Record score event for the peer.
        self.peer_manager
            .record_event(propagation_source, score_event);
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

                    let host = Arc::clone(&self.host);
                    // Handle synchronously to avoid lifetime complexity with &mut self.
                    let response = handle_request::<E, H, S>(
                        host.as_ref(),
                        peer,
                        request,
                        &mut self.peer_manager,
                    )
                    .await;

                    if self
                        .swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, response)
                        .is_err()
                    {
                        tracing::warn!(%peer, "failed to send RPC response (channel closed)");
                    }

                    self.peer_manager
                        .record_event(peer, ScoreEvent::RpcSuccess { method });
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    // Each request_id belongs to exactly one tracking map.
                    if let Some(hs_peer) = self.pending_status_checks.remove(&request_id) {
                        // Handshake Status response.
                        self.on_status_response(hs_peer, &response);
                    } else if let Some(ping_peer) = self.pending_ping_checks.remove(&request_id) {
                        // Ping keepalive seq-number check.
                        self.on_ping_response(ping_peer, &response);
                    } else if let Some(meta_peer) =
                        self.pending_metadata_fetches.remove(&request_id)
                    {
                        // GetMetaData follow-up after Ping seq-number advance.
                        self.on_metadata_response(meta_peer, &response);
                    } else if let Some((_method, tx)) = self.pending_rpc.remove(&request_id) {
                        // User-initiated outbound RPC (Phase 7 surface).
                        let _ = tx.send(Ok(response));
                    } else {
                        tracing::warn!(?request_id, "received response for unknown request");
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
                // Clean all tracking maps; each request_id lives in at most one.
                if self.pending_status_checks.remove(&request_id).is_some() {
                    // Handshake Status timed out or failed — abort and disconnect.
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::HandshakeFail {
                            kind: HandshakeFailKind::Timeout,
                        },
                    );
                    self.peer_manager.on_disconnecting(peer);
                    self.swarm.disconnect_peer_id(peer).ok();
                } else if self.pending_ping_checks.remove(&request_id).is_some() {
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::RpcError {
                            method: RpcMethod::Ping,
                            kind: RpcErrorKind::ServerError,
                        },
                    );
                } else if self.pending_metadata_fetches.remove(&request_id).is_some() {
                    self.peer_manager.record_event(
                        peer,
                        ScoreEvent::RpcError {
                            method: RpcMethod::MetaData,
                            kind: RpcErrorKind::ServerError,
                        },
                    );
                } else if let Some((method, tx)) = self.pending_rpc.remove(&request_id) {
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
        let request_id = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, req);
        self.pending_rpc.insert(request_id, (method, reply));
    }

    /// Look up a parsed `GossipTopic` by its `TopicHash`.
    fn topic_lookup(&self, hash: &TopicHash) -> Option<GossipTopic> {
        self.topic_map.get(hash).cloned()
    }

    /// Snappy-frame-encode `ssz_payload` and publish it to the given topic.
    ///
    /// Returns the `MessageId` assigned by gossipsub on success.
    pub fn on_publish_command(
        &mut self,
        topic: GossipTopic,
        ssz_payload: Vec<u8>,
    ) -> Result<gossipsub::MessageId, NetworkError> {
        let framed = encode_snappy_frame(&ssz_payload)?;
        let ident = IdentTopic::new(topic.topic_str());
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(ident, framed)
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
            let request_id = self
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, RpcRequest::MetaData);
            // Track only via pending_metadata_fetches; no oneshot to resolve.
            self.pending_metadata_fetches.insert(request_id, peer_id);
        }
    }

    /// Handle a `GetMetaData` response, updating the stored metadata.
    fn on_metadata_response(&mut self, peer_id: PeerId, response: &RpcResponse<E>) {
        if let RpcResponse::MetaData(meta) = response {
            self.peer_manager.on_metadata(peer_id, meta.clone());
        }
    }

    /// Complete or abort the handshake after receiving a `Status` response.
    ///
    /// If the peer's fork digest matches ours, transitions the peer to
    /// `Connected` and records the status.  If it differs, records a
    /// `HandshakeFail` score event, transitions to `Disconnecting`, sends
    /// `Goodbye(2 = IrrelevantNetwork)`, and disconnects.
    fn on_status_response(&mut self, peer_id: PeerId, response: &RpcResponse<E>) {
        let peer_status = match response {
            RpcResponse::Status(s) => s.clone(),
            _ => {
                tracing::warn!(%peer_id, "expected Status response during handshake");
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
            self.peer_manager.on_disconnecting(peer_id);
            // Send Goodbye(IrrelevantNetwork) fire-and-forget; no response expected.
            self.swarm.behaviour_mut().request_response.send_request(
                &peer_id,
                crate::rpc::types::RpcRequest::Goodbye(GOODBYE_IRRELEVANT_NETWORK),
            );
            self.swarm.disconnect_peer_id(peer_id).ok();
        } else {
            self.peer_manager.on_handshake_complete(peer_id);
        }
    }

    /// Handle a newly established libp2p connection.
    ///
    /// - Registers the peer in the peer manager (state → `Connecting`).
    /// - For outbound connections (we dialled): transitions to `Handshaking`
    ///   and sends a `Status` request. The response is handled in
    ///   `on_request_response_event` via `pending_status_checks`.
    ///   Per `p2p-interface.md:1352`.
    pub fn on_swarm_connection_established(&mut self, peer_id: PeerId, endpoint: ConnectedPoint) {
        let dir = if endpoint.is_dialer() {
            ConnectionDirection::Outbound
        } else {
            ConnectionDirection::Inbound
        };

        let addrs = vec![endpoint.get_remote_address().clone()];
        self.peer_manager.on_connected(peer_id, dir, addrs);

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
            let request_id = self.swarm.behaviour_mut().request_response.send_request(
                &peer_id,
                crate::rpc::types::RpcRequest::Status(local_status),
            );
            self.pending_status_checks.insert(request_id, peer_id);
        }
    }

    /// Handle a closed libp2p connection, informing the peer manager.
    pub fn on_swarm_connection_closed(
        &mut self,
        peer_id: PeerId,
        reason: Option<&ConnectionError>,
    ) {
        use crate::types::DisconnectReason;
        let dr = match reason {
            // No error means a clean (graceful) close initiated by either side.
            None => DisconnectReason::Other("clean close".into()),
            Some(e) => DisconnectReason::Other(e.to_string()),
        };
        self.peer_manager.on_disconnected(peer_id, dr);
    }

    /// Send a `Ping` keepalive to every `Connected` peer.
    ///
    /// Per `p2p-interface.md:1543-1575`: the local node sends
    /// `Ping(seq_number)` every 15 s. If the peer replies with a
    /// seq_number newer than the stored one, a follow-up `GetMetaData`
    /// is issued.
    pub fn tick_ping(&mut self) {
        let local_seq = self.host.local_metadata().seq_number;
        let connected: Vec<PeerId> = self.peer_manager.connected_peers().collect();
        for peer_id in connected {
            let request_id = self
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, RpcRequest::Ping(local_seq));
            // Track only via pending_ping_checks; no oneshot to resolve.
            self.pending_ping_checks.insert(request_id, peer_id);
        }
    }

    /// Prune peers that the scorer considers lowest-quality.
    ///
    /// Calls `peer_manager.should_prune()` and for each returned `PeerId`
    /// sends `Goodbye(3)` (Fault/error) then disconnects from the swarm.
    /// With `NoopScorer` this is always a no-op.
    pub fn tick_score_prune(&mut self) {
        let to_prune = self.peer_manager.should_prune();
        for peer_id in to_prune {
            self.peer_manager.on_disconnecting(peer_id);
            // Goodbye is fire-and-forget; send directly without tracking.
            self.swarm.behaviour_mut().request_response.send_request(
                &peer_id,
                crate::rpc::types::RpcRequest::Goodbye(GOODBYE_FAULT_ERROR),
            );
            self.swarm.disconnect_peer_id(peer_id).ok();
        }
    }

    #[allow(dead_code)]
    async fn on_command(&mut self, _cmd: NetworkCommand) {
        // Phase 7 adds dial, publish, and subnet-subscribe handling.
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Map an `RpcRequest` variant to its `RpcMethod` for scoring.
fn rpc_method_from_request(req: &RpcRequest) -> RpcMethod {
    match req {
        RpcRequest::Status(_) => RpcMethod::Status,
        RpcRequest::Goodbye(_) => RpcMethod::Goodbye,
        RpcRequest::Ping(_) => RpcMethod::Ping,
        RpcRequest::MetaData => RpcMethod::MetaData,
        RpcRequest::BlocksByRange(_) => RpcMethod::BlocksByRange,
        RpcRequest::BlocksByRoot(_) => RpcMethod::BlocksByRoot,
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
/// - `discv5_addr`: `127.0.0.1:9001` (note: UDP; avoids collision with TCP 9000)
/// - `local_key`: freshly generated secp256k1 keypair
/// - `bootnodes`: empty
pub struct NetworkBuilder<E, H, S> {
    host: Arc<H>,
    listen_ip: IpAddr,
    tcp_listen_port: u16,
    quic_listen_port: Option<u16>,
    discv5_addr: SocketAddr,
    bootnodes: Vec<Enr>,
    local_key: Keypair,
    scorer: S,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, H: Host<E>> NetworkBuilder<E, H, crate::scoring::NoopScorer> {
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
            discv5_addr: "127.0.0.1:9001".parse().unwrap(),
            bootnodes: Vec::new(),
            local_key: Keypair::generate_secp256k1(),
            scorer: crate::scoring::NoopScorer,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec, H: Host<E>, S: PeerScorer> NetworkBuilder<E, H, S> {
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
    pub fn scorer<T: PeerScorer>(self, scorer: T) -> NetworkBuilder<E, H, T> {
        NetworkBuilder {
            host: self.host,
            listen_ip: self.listen_ip,
            tcp_listen_port: self.tcp_listen_port,
            quic_listen_port: self.quic_listen_port,
            discv5_addr: self.discv5_addr,
            bootnodes: self.bootnodes,
            local_key: self.local_key,
            scorer,
            _phantom: PhantomData,
        }
    }

    /// Construct the `Network` and return `(Network, NetworkHandle)`.
    ///
    /// Steps:
    /// 1. Derive the discv5 `CombinedKey` from the libp2p secp256k1 keypair.
    /// 2. Compute initial subnet subscriptions from the node-id.
    /// 3. Start `DiscoveryService`.
    /// 4. Build the libp2p swarm via `SwarmBuilder`.
    /// 5. Subscribe to Phase-0 gossipsub topics; build the topic lookup map.
    /// 6. Add TCP listener; optionally add QUIC listener.
    /// 7. Wire mpsc channels and oneshot shutdown signal.
    pub async fn build(self) -> Result<(Network<E, H, S>, NetworkHandle), NetworkError> {
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
        let discovery = DiscoveryService::start(DiscoveryConfig {
            listen_addr: self.discv5_addr,
            tcp_port: self.tcp_listen_port,
            quic_port: self.quic_listen_port,
            bootnodes: self.bootnodes,
            local_key: combined_key,
            fork_id,
            attnets: attnets.clone(),
        })
        .await?;

        // ── Step 4: build the libp2p swarm ────────────────────────────────────
        let local_key = self.local_key.clone();
        let public_key = local_key.public();

        // Use the spec-conforming gossipsub config (Phase 4).
        let gossipsub = gossipsub_behaviour::<E>()?;

        // Build request_response with all six protocol IDs, full support.
        use crate::rpc::protocol::RpcProtocol;
        use crate::scoring::RpcMethod as M;
        let protocols = vec![
            (RpcProtocol(M::Status), ProtocolSupport::Full),
            (RpcProtocol(M::Goodbye), ProtocolSupport::Full),
            (RpcProtocol(M::Ping), ProtocolSupport::Full),
            (RpcProtocol(M::MetaData), ProtocolSupport::Full),
            (RpcProtocol(M::BlocksByRange), ProtocolSupport::Full),
            (RpcProtocol(M::BlocksByRoot), ProtocolSupport::Full),
        ];
        let rr: request_response::Behaviour<crate::rpc::codec::RpcCodec<E>> =
            request_response::Behaviour::new(protocols, request_response::Config::default());

        let identify_cfg = identify::Config::new("/pharos/0.1.0".into(), public_key.clone());
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
                request_response: rr,
                identify,
                ping,
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(transport::idle_timeout()))
            .build();

        // ── Step 5: subscribe to Phase-0 topics and build lookup map ─────────
        let mut swarm = swarm;
        let topic_map =
            subscribe_phase0_topics(&mut swarm.behaviour_mut().gossipsub, fork_digest, &attnets)?;

        // ── Step 6: add listeners ─────────────────────────────────────────────
        let tcp_addr: libp2p::Multiaddr =
            format!("/ip4/{}/tcp/{}", self.listen_ip, self.tcp_listen_port)
                .parse()
                .map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?;
        swarm
            .listen_on(tcp_addr)
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

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
        let (cmd_tx, command_rx) = mpsc::channel::<NetworkCommand>(64);
        let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(1024);
        let (shutdown_tx, shutdown_signal) = oneshot::channel::<()>();

        let peer_manager = PeerManager::new(self.scorer, 100, 50);

        // Discovery poll interval: 30 seconds.
        let discovery_tick = interval(std::time::Duration::from_secs(30));
        let ping_tick = interval(std::time::Duration::from_secs(15));
        let score_prune_tick = interval(std::time::Duration::from_secs(30));

        let network = Network {
            swarm,
            discovery,
            peer_manager,
            host: self.host,
            topic_map,
            command_rx,
            event_tx,
            discovery_tick,
            shutdown_signal,
            pending_rpc: HashMap::new(),
            pending_status_checks: HashMap::new(),
            pending_ping_checks: HashMap::new(),
            pending_metadata_fetches: HashMap::new(),
            ping_tick,
            score_prune_tick,
            _phantom: PhantomData,
        };

        let handle = NetworkHandle::new(cmd_tx, event_rx, shutdown_tx);

        Ok((network, handle))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict};
    use crate::types::SubnetId;
    use pharos_types::MainnetEthSpec;
    use pharos_types::phase0::primitives::ForkDigest;
    use pharos_types::phase0::{
        AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, MetaData,
        ProposerSlashing, Root, SignedVoluntaryExit, Slot,
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
        fn local_metadata(&self) -> MetaData {
            MetaData::default()
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
        fn validate_aggregate_and_proof(&self, _msg: &AggregateAndProof<2048>) -> GossipVerdict {
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
    }

    /// Verify that `Network::run` exits cleanly when `NetworkHandle::shutdown`
    /// is called.
    ///
    /// Uses `multi_thread` flavor because discv5 and libp2p both spawn Tokio
    /// tasks internally.
    #[tokio::test(flavor = "multi_thread")]
    async fn network_shutdown_smoke() {
        let (network, handle) = NetworkBuilder::<MainnetEthSpec, MockHost, _>::new(MockHost)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

        let task = tokio::spawn(async move { network.run().await });

        handle.shutdown().await.expect("shutdown failed");

        let result = task.await.expect("network task panicked");
        assert!(result.is_ok(), "Network::run returned an error: {result:?}");
    }
}
