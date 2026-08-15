//! `PharosBehaviour`: the combined `NetworkBehaviour` for the Pharos node.
//!
//! Composes gossipsub, six per-method request-response behaviours, identify,
//! and ping into a single struct that the libp2p swarm drives.
//!
//! Each Ethereum CL req-resp method is registered as a SEPARATE
//! `request_response::Behaviour` so that multistream-select negotiates the
//! correct per-method protocol string rather than always choosing the first
//! registered protocol. With a single combined behaviour, multistream-select
//! would always negotiate the first registered protocol (Status) for ALL
//! request types, causing every non-Status RPC to fail at codec decode.

use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, ping, request_response};
use pharos_types::EthSpec;

use crate::rpc::codec::RpcCodec;
use crate::rpc::types::{RpcRequest, RpcResponse};

pub use crate::rpc::protocol::RpcProtocol;

// ── Per-method RPC behaviour wrappers ─────────────────────────────────────────
//
// Each method needs its OWN `request_response::Behaviour` instance so that
// multistream-select negotiates the EXACT protocol string for that method.
// However, all six share the same Rust type `request_response::Behaviour<RpcCodec<E>>`,
// and `#[derive(NetworkBehaviour)]` requires `From<ToSwarm>` for each field,
// creating a conflict when multiple fields have the same `ToSwarm` type.
//
// Solution: wrap each behaviour in a distinct newtype so that each gets a
// distinct `type ToSwarm`. The wrappers delegate all `NetworkBehaviour`
// methods to the inner behaviour via `Deref`/explicit forwarding.

macro_rules! rpc_behaviour_wrapper {
    ($name:ident, $event_name:ident) => {
        /// Newtype wrapping `request_response::Behaviour<RpcCodec<E>>` to give each
        /// per-method RPC sub-behaviour a unique `type ToSwarm` for the derive macro.
        pub struct $name<E: EthSpec>(pub request_response::Behaviour<RpcCodec<E>>);

        /// Per-method event newtype so the outer enum has non-conflicting From impls.
        pub struct $event_name<E: EthSpec>(pub request_response::Event<RpcRequest, RpcResponse<E>>);

        impl<E: EthSpec> std::fmt::Debug for $event_name<E>
        where
            RpcResponse<E>: std::fmt::Debug,
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($event_name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl<E: EthSpec + Send + Sync + 'static> NetworkBehaviour for $name<E> {
            type ConnectionHandler =
                <request_response::Behaviour<RpcCodec<E>> as NetworkBehaviour>::ConnectionHandler;
            type ToSwarm = $event_name<E>;

            fn handle_pending_inbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                local_addr: &libp2p::Multiaddr,
                remote_addr: &libp2p::Multiaddr,
            ) -> Result<(), libp2p::swarm::ConnectionDenied> {
                self.0
                    .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
            }

            fn handle_established_inbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                peer: libp2p::PeerId,
                local_addr: &libp2p::Multiaddr,
                remote_addr: &libp2p::Multiaddr,
            ) -> Result<Self::ConnectionHandler, libp2p::swarm::ConnectionDenied> {
                self.0.handle_established_inbound_connection(
                    connection_id,
                    peer,
                    local_addr,
                    remote_addr,
                )
            }

            fn handle_pending_outbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                maybe_peer: Option<libp2p::PeerId>,
                addresses: &[libp2p::Multiaddr],
                effective_role: libp2p::core::Endpoint,
            ) -> Result<Vec<libp2p::Multiaddr>, libp2p::swarm::ConnectionDenied> {
                self.0.handle_pending_outbound_connection(
                    connection_id,
                    maybe_peer,
                    addresses,
                    effective_role,
                )
            }

            fn handle_established_outbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                peer: libp2p::PeerId,
                addr: &libp2p::Multiaddr,
                role_override: libp2p::core::Endpoint,
                port_use: libp2p::core::transport::PortUse,
            ) -> Result<Self::ConnectionHandler, libp2p::swarm::ConnectionDenied> {
                self.0.handle_established_outbound_connection(
                    connection_id,
                    peer,
                    addr,
                    role_override,
                    port_use,
                )
            }

            fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
                self.0.on_swarm_event(event);
            }

            fn on_connection_handler_event(
                &mut self,
                peer_id: libp2p::PeerId,
                connection_id: libp2p::swarm::ConnectionId,
                event: libp2p::swarm::THandlerOutEvent<Self>,
            ) {
                self.0
                    .on_connection_handler_event(peer_id, connection_id, event);
            }

            fn poll(
                &mut self,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<
                libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>,
            > {
                use std::task::Poll;
                match self.0.poll(cx) {
                    Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(e)) => {
                        Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent($event_name(e)))
                    }
                    Poll::Ready(other) => Poll::Ready(other.map_out(|_| unreachable!())),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    };
}

rpc_behaviour_wrapper!(RpcStatusBehaviour, RpcStatusEvent);
rpc_behaviour_wrapper!(RpcGoodbyeBehaviour, RpcGoodbyeEvent);
rpc_behaviour_wrapper!(RpcPingBehaviour, RpcPingEvent);
rpc_behaviour_wrapper!(RpcMetaDataBehaviour, RpcMetaDataEvent);
// MetaData v1 (phase-0) — serves `/eth2/beacon_chain/req/metadata/1/ssz_snappy`.
// Listed on the inbound side alongside `RpcMetaDataBehaviour` (v2) so
// multistream-select can negotiate the v1 protocol with older peers.
// Per `D-metadata-v2-dual-handle`.
rpc_behaviour_wrapper!(RpcMetaDataV1Behaviour, RpcMetaDataV1Event);
rpc_behaviour_wrapper!(RpcBlocksByRangeBehaviour, RpcBlocksByRangeEvent);
rpc_behaviour_wrapper!(RpcBlocksByRootBehaviour, RpcBlocksByRootEvent);
// Light-client req-resp behaviours per `specs/altair/light-client/p2p-interface.md`.
rpc_behaviour_wrapper!(RpcLcBootstrapBehaviour, RpcLcBootstrapEvent);
rpc_behaviour_wrapper!(RpcLcUpdatesByRangeBehaviour, RpcLcUpdatesByRangeEvent);
rpc_behaviour_wrapper!(RpcLcFinalityUpdateBehaviour, RpcLcFinalityUpdateEvent);
rpc_behaviour_wrapper!(RpcLcOptimisticUpdateBehaviour, RpcLcOptimisticUpdateEvent);

// ── PharosBehaviourEvent ──────────────────────────────────────────────────────

/// The aggregated event type produced by `PharosBehaviour<E>`.
#[derive(Debug)]
pub enum PharosBehaviourEvent<E: EthSpec>
where
    RpcResponse<E>: std::fmt::Debug,
{
    Gossipsub(gossipsub::Event),
    RpcStatus(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcGoodbye(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcPing(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcMetaData(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcMetaDataV1(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcBlocksByRange(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcBlocksByRoot(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcLcBootstrap(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcLcUpdatesByRange(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcLcFinalityUpdate(request_response::Event<RpcRequest, RpcResponse<E>>),
    RpcLcOptimisticUpdate(request_response::Event<RpcRequest, RpcResponse<E>>),
    /// Boxed to keep the enum size reasonable (`identify::Event` is large).
    Identify(Box<identify::Event>),
    Ping(ping::Event),
}

impl<E: EthSpec> From<gossipsub::Event> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: gossipsub::Event) -> Self {
        PharosBehaviourEvent::Gossipsub(e)
    }
}

impl<E: EthSpec> From<RpcStatusEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcStatusEvent<E>) -> Self {
        PharosBehaviourEvent::RpcStatus(e.0)
    }
}

impl<E: EthSpec> From<RpcGoodbyeEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcGoodbyeEvent<E>) -> Self {
        PharosBehaviourEvent::RpcGoodbye(e.0)
    }
}

impl<E: EthSpec> From<RpcPingEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcPingEvent<E>) -> Self {
        PharosBehaviourEvent::RpcPing(e.0)
    }
}

impl<E: EthSpec> From<RpcMetaDataEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcMetaDataEvent<E>) -> Self {
        PharosBehaviourEvent::RpcMetaData(e.0)
    }
}

impl<E: EthSpec> From<RpcMetaDataV1Event<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcMetaDataV1Event<E>) -> Self {
        PharosBehaviourEvent::RpcMetaDataV1(e.0)
    }
}

impl<E: EthSpec> From<RpcBlocksByRangeEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcBlocksByRangeEvent<E>) -> Self {
        PharosBehaviourEvent::RpcBlocksByRange(e.0)
    }
}

impl<E: EthSpec> From<RpcBlocksByRootEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcBlocksByRootEvent<E>) -> Self {
        PharosBehaviourEvent::RpcBlocksByRoot(e.0)
    }
}

impl<E: EthSpec> From<RpcLcBootstrapEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcLcBootstrapEvent<E>) -> Self {
        PharosBehaviourEvent::RpcLcBootstrap(e.0)
    }
}

impl<E: EthSpec> From<RpcLcUpdatesByRangeEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcLcUpdatesByRangeEvent<E>) -> Self {
        PharosBehaviourEvent::RpcLcUpdatesByRange(e.0)
    }
}

impl<E: EthSpec> From<RpcLcFinalityUpdateEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcLcFinalityUpdateEvent<E>) -> Self {
        PharosBehaviourEvent::RpcLcFinalityUpdate(e.0)
    }
}

impl<E: EthSpec> From<RpcLcOptimisticUpdateEvent<E>> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: RpcLcOptimisticUpdateEvent<E>) -> Self {
        PharosBehaviourEvent::RpcLcOptimisticUpdate(e.0)
    }
}

impl<E: EthSpec> From<identify::Event> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: identify::Event) -> Self {
        PharosBehaviourEvent::Identify(Box::new(e))
    }
}

impl<E: EthSpec> From<ping::Event> for PharosBehaviourEvent<E>
where
    RpcResponse<E>: std::fmt::Debug,
{
    fn from(e: ping::Event) -> Self {
        PharosBehaviourEvent::Ping(e)
    }
}

// ── PharosBehaviour ───────────────────────────────────────────────────────────

/// The combined libp2p `NetworkBehaviour` for the Pharos node.
///
/// Each Ethereum CL req-resp method has its own `request_response::Behaviour`
/// (wrapped in a newtype to avoid conflicting `From` impls) so that libp2p's
/// multistream-select negotiates the EXACT per-method protocol string for each
/// request. With a single combined behaviour, multistream-select would always
/// negotiate the first registered protocol (Status) for ALL requests, causing
/// all non-Status RPCs to fail.
#[derive(NetworkBehaviour)]
#[behaviour(
    to_swarm = "PharosBehaviourEvent<E>",
    prelude = "libp2p::swarm::derive_prelude"
)]
pub struct PharosBehaviour<E: EthSpec>
where
    RpcResponse<E>: std::fmt::Debug,
{
    pub gossipsub: gossipsub::Behaviour,
    pub rpc_status: RpcStatusBehaviour<E>,
    pub rpc_goodbye: RpcGoodbyeBehaviour<E>,
    pub rpc_ping: RpcPingBehaviour<E>,
    /// MetaData v2 (altair) — `/eth2/beacon_chain/req/metadata/2/ssz_snappy`.
    pub rpc_metadata: RpcMetaDataBehaviour<E>,
    /// MetaData v1 (phase-0 fallback) — `/eth2/beacon_chain/req/metadata/1/ssz_snappy`.
    ///
    /// Listed on the inbound side per `D-metadata-v2-dual-handle` so older peers
    /// that only know the v1 protocol can still exchange metadata.
    pub rpc_metadata_v1: RpcMetaDataV1Behaviour<E>,
    pub rpc_blocks_by_range: RpcBlocksByRangeBehaviour<E>,
    pub rpc_blocks_by_root: RpcBlocksByRootBehaviour<E>,
    /// Light-client req-resp behaviours per `specs/altair/light-client/p2p-interface.md`.
    pub rpc_lc_bootstrap: RpcLcBootstrapBehaviour<E>,
    pub rpc_lc_updates_by_range: RpcLcUpdatesByRangeBehaviour<E>,
    pub rpc_lc_finality_update: RpcLcFinalityUpdateBehaviour<E>,
    pub rpc_lc_optimistic_update: RpcLcOptimisticUpdateBehaviour<E>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}
