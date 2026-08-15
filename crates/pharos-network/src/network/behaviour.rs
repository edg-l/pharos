//! `PharosBehaviour`: the combined `NetworkBehaviour` for the Pharos node.
//!
//! Composes gossipsub, request-response (RPC), identify, and ping into a
//! single struct that the libp2p swarm drives.

use std::io;

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, ping, request_response};

// ── RPC stubs ─────────────────────────────────────────────────────────────────

/// The Ethereum CL req-resp codec.
///
/// The full SSZ + Snappy framing codec is implemented in Phase 5.
/// This type satisfies the `request_response::Codec` bound so that
/// `PharosBehaviour` compiles.  Every method returns an I/O error;
/// the `request_response::Behaviour<RpcCodec>` is wired up but will not
/// exchange any messages until Phase 5 supplies real encoding logic.
#[derive(Clone, Default)]
pub struct RpcCodec;

/// RPC request variants for Ethereum CL req-resp.  Phase 5 defines the
/// full set (`Status`, `Goodbye`, `BeaconBlocksByRange`, …).
#[derive(Debug, Clone)]
pub enum RpcRequest {}

/// RPC response variants for Ethereum CL req-resp.  Phase 5 defines the
/// full set.
#[derive(Debug, Clone)]
pub enum RpcResponse {}

/// The protocol string advertised during negotiation.  Phase 5 replaces this
/// with the full set of Ethereum CL protocol IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcProtocol;

impl AsRef<str> for RpcProtocol {
    fn as_ref(&self) -> &str {
        "/eth2/beacon_chain/req/pharos/1/ssz_snappy"
    }
}

#[async_trait]
impl request_response::Codec for RpcCodec {
    type Protocol = RpcProtocol;
    type Request = RpcRequest;
    type Response = RpcResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::Error::other("RPC codec not implemented (Phase 5)"))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::Error::other("RPC codec not implemented (Phase 5)"))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
        _req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::Error::other("RPC codec not implemented (Phase 5)"))
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
        _res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::Error::other("RPC codec not implemented (Phase 5)"))
    }
}

// ── PharosBehaviour ───────────────────────────────────────────────────────────

/// The aggregated event type produced by `PharosBehaviour`.
///
/// The `#[derive(NetworkBehaviour)]` macro uses this type as
/// `to_swarm` (via `#[behaviour(to_swarm = "PharosBehaviourEvent")]`).
/// Each variant wraps the inner event from the corresponding sub-behaviour.
#[derive(Debug)]
pub enum PharosBehaviourEvent {
    Gossipsub(gossipsub::Event),
    RequestResponse(request_response::Event<RpcRequest, RpcResponse>),
    /// Boxed to keep the enum size reasonable (`identify::Event` is large).
    Identify(Box<identify::Event>),
    Ping(ping::Event),
}

impl From<gossipsub::Event> for PharosBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        PharosBehaviourEvent::Gossipsub(e)
    }
}

impl From<request_response::Event<RpcRequest, RpcResponse>> for PharosBehaviourEvent {
    fn from(e: request_response::Event<RpcRequest, RpcResponse>) -> Self {
        PharosBehaviourEvent::RequestResponse(e)
    }
}

impl From<identify::Event> for PharosBehaviourEvent {
    fn from(e: identify::Event) -> Self {
        PharosBehaviourEvent::Identify(Box::new(e))
    }
}

impl From<ping::Event> for PharosBehaviourEvent {
    fn from(e: ping::Event) -> Self {
        PharosBehaviourEvent::Ping(e)
    }
}

/// The combined libp2p `NetworkBehaviour` for the Pharos node.
///
/// Fields:
/// - `gossipsub`: handles Ethereum CL gossip topics (Phase 4 wires validators).
/// - `request_response`: handles Ethereum CL req-resp protocols (Phase 5).
/// - `identify`: exchanges peer metadata on new connections.
/// - `ping`: maintains liveness measurements with connected peers.
#[derive(NetworkBehaviour)]
#[behaviour(
    to_swarm = "PharosBehaviourEvent",
    prelude = "libp2p::swarm::derive_prelude"
)]
pub struct PharosBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub request_response: request_response::Behaviour<RpcCodec>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}
