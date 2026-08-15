//! `NetworkHandle` — the external API for issuing commands and receiving events.
//!
//! Design constraints (D-runtime-ownership ADR):
//! - One swarm-owning task; one event consumer.
//! - `mpsc::Receiver` is not `Clone`; `NetworkHandle` does NOT implement `Clone`.
//! - The command sender is exposed as a separately clonable `NetworkCommandSender`
//!   newtype for multi-producer use.
//! - Do NOT wrap `event_rx` in `Arc<Mutex<_>>`; that is a footgun for an mpsc
//!   receiver and violates single-consumer ownership.

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use pharos_ssz::Encode;
use pharos_types::EthSpec;
use tokio::sync::{mpsc, oneshot};

use crate::error::NetworkError;
use crate::network::{NetworkCommand, NetworkEvent};
use crate::rpc::types::{RpcRequest, RpcResponse};
use crate::topics::GossipTopic;

// ── NetworkCommandSender ──────────────────────────────────────────────────────

/// A clonable handle to the command-sender side of the network channel.
///
/// Multiple producers can hold a `NetworkCommandSender` to issue commands
/// without requiring ownership of the full `NetworkHandle`.
#[derive(Clone)]
pub struct NetworkCommandSender<E: EthSpec>(pub(crate) mpsc::Sender<NetworkCommand<E>>);

impl<E: EthSpec> NetworkCommandSender<E> {
    /// Send a raw `NetworkCommand` without waiting for a reply.
    pub async fn send(&self, cmd: NetworkCommand<E>) -> Result<(), NetworkError> {
        self.0
            .send(cmd)
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }
}

// ── NetworkHandle ─────────────────────────────────────────────────────────────

/// Handle to the running network task.
///
/// Provides the public command/event interface consumed by `pharos-node`.
///
/// Ownership rules:
/// - `NetworkHandle` has a SINGLE owner (not `Clone`) because the event
///   receiver (`mpsc::Receiver`) must not be shared.
/// - For multi-producer command use, clone the `NetworkCommandSender` obtained
///   from `command_sender()`.
pub struct NetworkHandle<E: EthSpec> {
    /// Send commands to the `Network` event loop.
    cmd_tx: mpsc::Sender<NetworkCommand<E>>,
    /// Receive events emitted by the `Network` event loop.
    ///
    /// Single consumer; never wrapped in `Arc<Mutex<_>>`.
    event_rx: mpsc::Receiver<NetworkEvent>,
    /// The local `PeerId` of this node.
    local_peer_id: PeerId,
    /// Fire to trigger a clean shutdown of the `Network` event loop.
    ///
    /// Wrapped in `Option` so `shutdown()` can take it by value.
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl<E: EthSpec> NetworkHandle<E> {
    /// Construct a new handle from the channel endpoints created by `NetworkBuilder::build`.
    pub(crate) fn new(
        cmd_tx: mpsc::Sender<NetworkCommand<E>>,
        event_rx: mpsc::Receiver<NetworkEvent>,
        shutdown_tx: oneshot::Sender<()>,
        local_peer_id: PeerId,
    ) -> Self {
        Self {
            cmd_tx,
            event_rx,
            local_peer_id,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Return a clonable `NetworkCommandSender` for multi-producer command use.
    pub fn command_sender(&self) -> NetworkCommandSender<E> {
        NetworkCommandSender(self.cmd_tx.clone())
    }

    /// The local `PeerId` of this node.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Receive the next event from the network task.
    ///
    /// Returns `None` when the network task has exited and the channel is
    /// drained. Uses `&mut self` to enforce single-consumer ownership.
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    /// SSZ-encode `payload`, snappy-frame it in the network task, and publish
    /// to `topic`.
    ///
    /// Returns the gossipsub `MessageId` assigned to the message.
    pub async fn publish(
        &self,
        topic: GossipTopic,
        payload: &impl Encode,
    ) -> Result<libp2p::gossipsub::MessageId, NetworkError> {
        let ssz_payload = payload.as_ssz_bytes();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::Publish {
                topic,
                ssz_payload,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Send an outbound RPC `req` to `peer`, waiting up to `timeout` for a
    /// response.
    pub async fn request(
        &self,
        peer: PeerId,
        req: RpcRequest,
        timeout: Duration,
    ) -> Result<RpcResponse<E>, NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::OutgoingRequest {
                peer,
                req,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        tokio::time::timeout(timeout, reply_rx)
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Subscribe to an additional gossipsub `topic` at runtime.
    pub async fn subscribe(&self, topic: GossipTopic) -> Result<(), NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::Subscribe {
                topic,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Dial a remote peer by multiaddr.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::Dial {
                addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Disconnect from `peer_id`.
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<(), NetworkError> {
        self.cmd_tx
            .send(NetworkCommand::Disconnect { peer_id })
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Shuts the network task down cleanly.
    ///
    /// Sends `NetworkCommand::Shutdown` via the command channel, then fires
    /// the oneshot shutdown signal.  Either signal alone is sufficient for
    /// `Network::run` to exit; both are sent for robustness.
    pub async fn shutdown(mut self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}
