//! Pharos networking layer.
//!
//! Built on raw `libp2p` + `discv5`. Owns the CL-specific surface: gossipsub
//! topic schemes, message validation, req-resp protocol IDs, peer scoring,
//! ENR / fork-digest handling.

pub mod codec;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod handle;
pub mod host;
pub mod metadata;
pub mod network;
pub mod peer;
pub mod rpc;
pub mod scoring;
pub mod topics;
pub mod types;

pub use discovery::handle::DiscoveryHandle;
pub use discv5::enr::NodeId;
pub use error::NetworkError;
pub use handle::{NetworkCommandSender, NetworkHandle};
pub use host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict, Host};
pub use network::{Network, NetworkBuilder, NetworkCommand, NetworkEvent};
pub use rpc::types::{RpcRequest, RpcResponse};
pub use scoring::{NoopScorer, PeerScorer, ScoreEvent};
pub use topics::{GossipTopic, GossipTopicKind};
pub use types::{ConnectionDirection, DisconnectReason, ForkDigest, PeerInfo, SubnetId};
