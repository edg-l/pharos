//! `PharosBehaviour`: the combined `NetworkBehaviour` for the Pharos node.
//!
//! Composes gossipsub, request-response (RPC), identify, and ping into a
//! single struct that the libp2p swarm drives.
//!
//! `PharosBehaviour<E>` is generic over `E: EthSpec` because
//! `request_response::Behaviour<RpcCodec<E>>` carries the `EthSpec` type
//! parameter through to `RpcResponse<E>`. The `E` type parameter is anchored
//! by the `request_response` field; no `PhantomData` field is needed.

use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, ping, request_response};
use pharos_types::EthSpec;

use crate::rpc::codec::RpcCodec;
use crate::rpc::types::{RpcRequest, RpcResponse};

pub use crate::rpc::protocol::RpcProtocol;

// ── PharosBehaviourEvent ──────────────────────────────────────────────────────

/// The aggregated event type produced by `PharosBehaviour<E>`.
///
/// The `#[derive(NetworkBehaviour)]` macro uses this type as
/// `to_swarm` (via `#[behaviour(to_swarm = "PharosBehaviourEvent")]`).
/// Each variant wraps the inner event from the corresponding sub-behaviour.
#[derive(Debug)]
pub enum PharosBehaviourEvent<E: EthSpec> {
    Gossipsub(gossipsub::Event),
    RequestResponse(request_response::Event<RpcRequest, RpcResponse<E>>),
    /// Boxed to keep the enum size reasonable (`identify::Event` is large).
    Identify(Box<identify::Event>),
    Ping(ping::Event),
}

impl<E: EthSpec> From<gossipsub::Event> for PharosBehaviourEvent<E> {
    fn from(e: gossipsub::Event) -> Self {
        PharosBehaviourEvent::Gossipsub(e)
    }
}

impl<E: EthSpec> From<request_response::Event<RpcRequest, RpcResponse<E>>>
    for PharosBehaviourEvent<E>
{
    fn from(e: request_response::Event<RpcRequest, RpcResponse<E>>) -> Self {
        PharosBehaviourEvent::RequestResponse(e)
    }
}

impl<E: EthSpec> From<identify::Event> for PharosBehaviourEvent<E> {
    fn from(e: identify::Event) -> Self {
        PharosBehaviourEvent::Identify(Box::new(e))
    }
}

impl<E: EthSpec> From<ping::Event> for PharosBehaviourEvent<E> {
    fn from(e: ping::Event) -> Self {
        PharosBehaviourEvent::Ping(e)
    }
}

// ── PharosBehaviour ───────────────────────────────────────────────────────────

/// The combined libp2p `NetworkBehaviour` for the Pharos node.
///
/// Generic over `E: EthSpec` because `RpcCodec<E>` (and thus
/// `request_response::Behaviour<RpcCodec<E>>`) carries the EthSpec type
/// parameter through to `RpcResponse<E>`. The `E` type parameter is held by
/// the `request_response` field; no additional `PhantomData` is required.
///
/// Fields:
/// - `gossipsub`: handles Ethereum CL gossip topics (Phase 4 wires validators).
/// - `request_response`: handles Ethereum CL req-resp protocols (Phase 5).
/// - `identify`: exchanges peer metadata on new connections.
/// - `ping`: maintains liveness measurements with connected peers.
#[derive(NetworkBehaviour)]
#[behaviour(
    to_swarm = "PharosBehaviourEvent<E>",
    prelude = "libp2p::swarm::derive_prelude"
)]
pub struct PharosBehaviour<E: EthSpec> {
    pub gossipsub: gossipsub::Behaviour,
    pub request_response: request_response::Behaviour<RpcCodec<E>>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}
