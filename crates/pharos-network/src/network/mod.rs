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
use std::time::Duration;

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
use tokio::time::{Interval, interval, timeout};

use discv5::enr::EnrKey as _;

use crate::codec::snappy_block::{decode_snappy_block, encode_snappy_block};
use crate::discovery::enr::Enr;
use crate::discovery::service::{DiscoveryConfig, DiscoveryService};
use crate::discovery::subnets::compute_subscribed_subnets;
use crate::error::NetworkError;
use crate::gossip::config::gossipsub_behaviour;
use crate::gossip::{dispatch_gossip_message, subscribe_phase0_topics};
use crate::handle::NetworkHandle;
use crate::host::{GossipVerdict, Host, LightClientProvider};
use crate::peer::manager::PeerManager;
use crate::rpc::handler::handle_request;
use crate::rpc::types::{RpcRequest, RpcResponse};
use crate::scoring::{HandshakeFailKind, PeerScorer, RpcErrorKind, RpcMethod, ScoreEvent};
use crate::topics::GossipTopic;
use crate::types::{
    ConnectionDirection, GOODBYE_CLIENT_SHUTDOWN, GOODBYE_FAULT_ERROR, GOODBYE_IRRELEVANT_NETWORK,
};

use behaviour::{PharosBehaviour, PharosBehaviourEvent};

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
}

// ── Network ───────────────────────────────────────────────────────────────────

/// The running network task.
///
/// Constructed via `NetworkBuilder::build`.  Call `run()` to drive the
/// event loop.  Shut down by sending `NetworkCommand::Shutdown` via the
/// `NetworkHandle` or by dropping the handle's `shutdown_tx`.
pub struct Network<E: EthSpec, H: Host<E> + LightClientProvider<E>, S: PeerScorer> {
    swarm: Swarm<PharosBehaviour<E>>,
    discovery: DiscoveryService,
    peer_manager: PeerManager<S>,
    host: Arc<H>,
    /// Maps subscribed topic hashes to their parsed `GossipTopic` for dispatch.
    topic_map: HashMap<TopicHash, GossipTopic>,
    command_rx: mpsc::Receiver<NetworkCommand<E>>,
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

impl<E: EthSpec, H: Host<E> + LightClientProvider<E>, S: PeerScorer> Network<E, H, S> {
    /// Drive the network event loop.
    ///
    /// Returns when a `NetworkCommand::Shutdown` is received or when
    /// the shutdown signal fires.
    pub async fn run(mut self) -> Result<(), NetworkError> {
        // Emit the local ENR once before the select loop so that consumers
        // waiting on `NetworkEvent::LocalEnr` (e.g. integration tests that
        // need the discv5 ENR with the real bound UDP port) can proceed.
        let local_enr = self.discovery.local_enr();
        self.emit_event(NetworkEvent::LocalEnr(local_enr));

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
                    self.shutdown_goodbye().await;
                    break;
                }
            }
        }
        if let Err(err) = self.event_tx.try_send(NetworkEvent::Shutdown) {
            tracing::warn!(error = %err, "network event channel send failed; event dropped");
        }
        tracing::info!("network event loop exited; Shutdown emitted");
        Ok(())
    }

    async fn on_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<PharosBehaviourEvent<E>>) {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::Gossipsub(gs_event)) => {
                self.on_gossip_event(gs_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcStatus(rr_event)) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcGoodbye(rr_event)) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcPing(rr_event)) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcMetaData(rr_event)) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcMetaDataV1(rr_event)) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcBlocksByRange(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcBlocksByRoot(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcBootstrap(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcUpdatesByRange(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcFinalityUpdate(
                rr_event,
            )) => {
                self.on_request_response_event(rr_event).await;
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::RpcLcOptimisticUpdate(
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
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "new listen address");
                self.emit_event(NetworkEvent::NewListenAddr(address));
            }
            libp2p::swarm::SwarmEvent::Behaviour(PharosBehaviourEvent::Identify(id_event)) => {
                if let identify::Event::Received { peer_id, info, .. } = *id_event {
                    self.on_identify(peer_id, info);
                }
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let error_str = format!("{error}");
                self.emit_event(NetworkEvent::DialFailed {
                    peer: peer_id,
                    error: error_str,
                });
                if let Some(pid) = peer_id {
                    self.peer_manager.record_event(
                        pid,
                        ScoreEvent::HandshakeFail {
                            kind: HandshakeFailKind::Timeout,
                        },
                    );
                }
                self.peer_manager.note_dial_failure(peer_id);
            }
            libp2p::swarm::SwarmEvent::ExternalAddrConfirmed { address } => {
                tracing::info!(%address, "external address confirmed");
                // ENR update deferred to M3b (cross-fork ENR migration).
                self.emit_event(NetworkEvent::ExternalAddrConfirmed { address });
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
                    });
                } else {
                    tracing::debug!(%peer_id, ?topic, "peer subscribed to unknown topic; ignoring");
                }
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                if let Ok(parsed) = GossipTopic::from_topic_hash(&topic, &self.topic_map) {
                    self.emit_event(NetworkEvent::PeerUnsubscribed {
                        peer: peer_id,
                        topic: parsed,
                    });
                } else {
                    tracing::debug!(%peer_id, ?topic, "peer unsubscribed from unknown topic; ignoring");
                }
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

        // SSZ-decode + validate via the host.
        let verdict = dispatch_gossip_message::<E, H>(self.host.as_ref(), &topic, &ssz_bytes);

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

        // Move the decompressed bytes into the event on Accept (no second decompress).
        if matches!(&verdict, GossipVerdict::Accept) {
            self.emit_event(NetworkEvent::GossipMessage {
                topic,
                peer: propagation_source,
                data: ssz_bytes,
            });
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
                    // Handle synchronously to avoid lifetime complexity with &mut self.
                    let response = handle_request::<E, H, S>(
                        host.as_ref(),
                        peer,
                        request,
                        &mut self.peer_manager,
                        negotiated_protocol_id,
                    )
                    .await;

                    // Emit PeerConnected for inbound Status after a successful handshake.
                    //
                    // Symmetry with outbound: `on_status_response` emits PeerConnected only
                    // after fork-digest validation succeeds. For inbound, `handle_request`
                    // calls `peer_manager.on_inbound_status` which transitions the peer to
                    // `Connected` iff the fork digest matches. Emit here before sending the
                    // response so consumers see the peer as ready before the remote sees
                    // the Status reply.
                    if is_inbound_status && matches!(response, RpcResponse::Status(_)) {
                        self.emit_event(NetworkEvent::PeerConnected(peer));
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
        self.pending_rpc.insert(request_id, (method, reply));
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
    fn on_identify(&mut self, peer: PeerId, info: identify::Info) {
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
                });
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
    fn on_status_response(&mut self, peer_id: PeerId, response: &RpcResponse<E>) {
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
            self.emit_event(NetworkEvent::PeerConnected(peer_id));
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
    }

    /// Handle a closed libp2p connection, informing the peer manager and
    /// emitting a `PeerDisconnected` event.
    ///
    /// If a disconnect reason was pre-registered via
    /// `peer_manager.note_disconnect_reason` (e.g., Goodbye plumbing), that
    /// reason takes precedence over the libp2p `ConnectionError`.
    pub fn on_swarm_connection_closed(
        &mut self,
        peer_id: PeerId,
        reason: Option<&ConnectionError>,
    ) {
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
        self.emit_event(NetworkEvent::PeerDisconnected(peer_id, dr));
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
            let request_id = self.send_rpc_request(&peer_id, RpcRequest::Ping(local_seq));
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
            // Pre-register reason before disconnect so ConnectionClosed carries
            // Goodbye(3 = Fault/Error). Spec: specs/phase0/p2p-interface.md:1395.
            self.peer_manager.note_disconnect_reason(
                peer_id,
                crate::types::DisconnectReason::Goodbye(GOODBYE_FAULT_ERROR),
            );
            self.peer_manager.on_disconnecting(peer_id);
            // Goodbye is fire-and-forget; send directly without tracking.
            self.send_rpc_request(
                &peer_id,
                crate::rpc::types::RpcRequest::Goodbye(GOODBYE_FAULT_ERROR),
            );
            self.swarm.disconnect_peer_id(peer_id).ok();
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

    /// Emit a `NetworkEvent` to the consumer channel.
    ///
    /// Uses `try_send` to avoid blocking the event loop. Logs a warning when
    /// the channel is full and the event is dropped (back-pressure via drop
    /// per D-channels).
    fn emit_event(&self, ev: NetworkEvent) {
        if let Err(err) = self.event_tx.try_send(ev) {
            tracing::warn!(error = %err, "network event channel send failed; event dropped");
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
        }
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
        RpcRequest::MetaDataV1 => RpcMethod::MetaDataV1,
        RpcRequest::BlocksByRange(_) => RpcMethod::BlocksByRange,
        RpcRequest::BlocksByRoot(_) => RpcMethod::BlocksByRoot,
        RpcRequest::LightClientBootstrap(_) => RpcMethod::LightClientBootstrap,
        RpcRequest::LightClientUpdatesByRange(_) => RpcMethod::LightClientUpdatesByRange,
        RpcRequest::LightClientFinalityUpdate => RpcMethod::LightClientFinalityUpdate,
        RpcRequest::LightClientOptimisticUpdate => RpcMethod::LightClientOptimisticUpdate,
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
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, H: Host<E> + LightClientProvider<E>>
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
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec, H: Host<E> + LightClientProvider<E>, S: PeerScorer> NetworkBuilder<E, H, S> {
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
        H: Host<E> + LightClientProvider<E>,
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
            _phantom: PhantomData,
        }
    }

    /// Construct the `Network` and return `(Network, NetworkHandle<E>)`.
    ///
    /// Steps:
    /// 1. Derive the discv5 `CombinedKey` from the libp2p secp256k1 keypair.
    /// 2. Compute initial subnet subscriptions from the node-id.
    /// 3. Start `DiscoveryService`.
    /// 4. Build the libp2p swarm via `SwarmBuilder`.
    /// 5. Subscribe to Phase-0 gossipsub topics; build the topic lookup map.
    /// 6. Add TCP listener; optionally add QUIC listener.
    /// 7. Wire mpsc channels and oneshot shutdown signal.
    pub async fn build(self) -> Result<(Network<E, H, S>, NetworkHandle<E>), NetworkError> {
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

        // Use the spec-conforming gossipsub config.
        // Phase-0 fork digest is captured once; the message-id closure uses it
        // to dispatch between phase-0 and altair message-id formulas per
        // `specs/altair/p2p-interface.md:163-171`.
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
        let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(1024);
        let (shutdown_tx, shutdown_signal) = oneshot::channel::<()>();

        let peer_manager = PeerManager::new(self.scorer, 100, 50);

        // Discovery poll interval: 30 seconds.
        let discovery_tick = interval(std::time::Duration::from_secs(30));
        let ping_tick = interval(std::time::Duration::from_secs(15));
        let score_prune_tick = interval(std::time::Duration::from_secs(30));

        let local_peer_id = *swarm.local_peer_id();

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

        let handle = NetworkHandle::new(cmd_tx, event_rx, shutdown_tx, local_peer_id, node_id);

        Ok((network, handle))
    }

    /// Build, spawn the network task on the current Tokio runtime, and return
    /// the `NetworkHandle<E>`.
    ///
    /// The spawned task owns the `Network` and drives its `run()` loop.
    /// The returned handle is the single owner of the event-receiver side.
    pub async fn spawn(self) -> Result<NetworkHandle<E>, NetworkError>
    where
        H: 'static,
        S: 'static,
    {
        let (network, handle) = self.build().await?;
        tokio::spawn(async move {
            if let Err(e) = network.run().await {
                tracing::error!("network task exited with error: {e}");
            } else {
                tracing::info!("network shutdown complete");
            }
        });
        Ok(handle)
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
        AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
        Root, SignedVoluntaryExit, Slot,
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
        fn fork_digest_for(&self, _fork: crate::types::Fork) -> ForkDigest {
            ForkDigest::from_array([0u8; 4])
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

        handle.shutdown().await;

        let result = task.await.expect("network task panicked");
        assert!(result.is_ok(), "Network::run returned an error: {result:?}");
    }
}
