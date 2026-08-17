//! `NetworkHandle` — the external API for issuing commands and receiving events.
//!
//! Design constraints (D-runtime-ownership ADR):
//! - One swarm-owning task; one event consumer.
//! - `mpsc::Receiver` is not `Clone`; `NetworkHandle` does NOT implement `Clone`.
//! - The command sender is exposed as a separately clonable `NetworkCommandSender`
//!   newtype for multi-producer use.
//! - Do NOT wrap `event_rx` in `Arc<Mutex<_>>`; that is a footgun for an mpsc
//!   receiver and violates single-consumer ownership.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use discv5::enr::NodeId;
use libp2p::{Multiaddr, PeerId};
use pharos_ssz::Encode;
use pharos_types::BeaconSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use tokio::sync::{mpsc, oneshot};

use crate::error::NetworkError;
use crate::network::{NetworkCommand, NetworkEvent};
use crate::rpc::types::{RpcRequest, RpcResponse};
use crate::topics::GossipTopic;
use crate::types::PeerInfo;

// ── NetworkCommandSender ──────────────────────────────────────────────────────

/// A clonable handle to the command-sender side of the network channel.
///
/// Multiple producers can hold a `NetworkCommandSender` to issue commands
/// without requiring ownership of the full `NetworkHandle`.
#[derive(Clone)]
pub struct NetworkCommandSender<E: BeaconSpec>(pub(crate) mpsc::Sender<NetworkCommand<E>>);

impl<E: BeaconSpec> NetworkCommandSender<E> {
    /// Construct a `NetworkCommandSender` from a raw mpsc sender.
    ///
    /// Exposed for test code in external crates that need a dummy sender whose
    /// receiver is held (or dropped) by the test harness.
    pub fn new(sender: mpsc::Sender<NetworkCommand<E>>) -> Self {
        Self(sender)
    }

    /// Send a raw `NetworkCommand` without waiting for a reply.
    pub async fn send(&self, cmd: NetworkCommand<E>) -> Result<(), NetworkError> {
        self.0
            .send(cmd)
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// SSZ-encode `payload`, snappy-frame it in the network task, and publish
    /// to `topic`.
    ///
    /// Returns the gossipsub `MessageId` assigned to the message.
    ///
    /// Identical semantics to `NetworkHandle::publish`; provided here so the
    /// block-ingestion loop can publish using the clonable `NetworkCommandSender`
    /// (not the non-`Clone` `NetworkHandle`).
    pub async fn publish(
        &self,
        topic: GossipTopic,
        payload: &impl Encode,
    ) -> Result<libp2p::gossipsub::MessageId, NetworkError> {
        let ssz_payload = payload.as_ssz_bytes();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.0
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
    ///
    /// Identical body to `NetworkHandle::request`; provided here so
    /// `NetworkBackfillProvider` can issue requests using only the clonable
    /// `NetworkCommandSender` (not the non-`Clone` `NetworkHandle`).
    pub async fn request(
        &self,
        peer: PeerId,
        req: RpcRequest,
        timeout: Duration,
    ) -> Result<RpcResponse<E>, NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.0
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

    /// Return a snapshot of every known peer's `PeerInfo`.
    ///
    /// Backs the Beacon API `/eth/v1/node/peers` and `/eth/v1/node/peer_count`
    /// endpoints. Returns an empty vec if the network task has shut down.
    pub async fn peers(&self) -> Vec<PeerInfo> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .0
            .send(NetworkCommand::ListPeers { reply: reply_tx })
            .await
            .is_err()
        {
            return Vec::new();
        }
        reply_rx.await.unwrap_or_default()
    }

    /// Return the highest `head_slot` across connected peers' last `Status`
    /// message, used by the per-slot heartbeat to estimate the sync ETA.
    ///
    /// Returns `None` when no peer status is known (no connected peers, or none
    /// have completed the Status handshake) or if the network task has shut down.
    pub async fn highest_head_slot(&self) -> Option<u64> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .0
            .send(NetworkCommand::HighestHeadSlot { reply: reply_tx })
            .await
            .is_err()
        {
            return None;
        }
        reply_rx.await.unwrap_or(None)
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
pub struct NetworkHandle<E: BeaconSpec> {
    /// Send commands to the `Network` event loop.
    cmd_tx: mpsc::Sender<NetworkCommand<E>>,
    /// Receive events emitted by the `Network` event loop.
    ///
    /// Single consumer; never wrapped in `Arc<Mutex<_>>`.
    /// Wrapped in `Option` so callers can move the receiver out via
    /// `take_event_receiver`, leaving the rest of the handle intact.
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    /// The local `PeerId` of this node.
    local_peer_id: PeerId,
    /// The discv5 `NodeId` derived from the local secp256k1 keypair.
    ///
    /// Used by `compute_subscribed_subnets` to compute initial attestation
    /// subnet assignments at startup.
    local_node_id: NodeId,
    /// Fire to trigger a clean shutdown of the `Network` event loop.
    ///
    /// Wrapped in `Option` so `shutdown()` can take it by value.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Shared reference to the live local `MetaData` (Altair v2).
    ///
    /// Cloned from `Network::host_metadata` at build time so the Beacon API
    /// `NodeIdentityCache` can read the current metadata seq/attnets/syncnets
    /// without holding a reference to the non-`Clone` `NetworkHandle`.
    host_metadata: Arc<ArcSwap<AltairMetaData>>,
}

impl<E: BeaconSpec> NetworkHandle<E> {
    /// Construct a new handle from the channel endpoints created by `NetworkBuilder::build`.
    pub(crate) fn new(
        cmd_tx: mpsc::Sender<NetworkCommand<E>>,
        event_rx: mpsc::Receiver<NetworkEvent>,
        shutdown_tx: oneshot::Sender<()>,
        local_peer_id: PeerId,
        local_node_id: NodeId,
        host_metadata: Arc<ArcSwap<AltairMetaData>>,
    ) -> Self {
        Self {
            cmd_tx,
            event_rx: Some(event_rx),
            local_peer_id,
            local_node_id,
            shutdown_tx: Some(shutdown_tx),
            host_metadata,
        }
    }

    /// Return a cloned `Arc` to the live local `MetaData` (Altair v2).
    ///
    /// The returned `Arc<ArcSwap<AltairMetaData>>` is a shared reference to
    /// `Network::host_metadata` and reflects live updates issued via
    /// `NetworkCommand::UpdateMetaData`. Safe to hold across `take_event_receiver`.
    ///
    /// Used by `pharos-node` to populate `NodeIdentityCache::metadata` for the
    /// Beacon API server (`D-api-node-identity-cache`).
    pub fn metadata_ref(&self) -> Arc<ArcSwap<AltairMetaData>> {
        Arc::clone(&self.host_metadata)
    }

    /// Return a clonable `NetworkCommandSender` for multi-producer command use.
    pub fn command_sender(&self) -> NetworkCommandSender<E> {
        NetworkCommandSender(self.cmd_tx.clone())
    }

    /// The local `PeerId` of this node.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// The discv5 `NodeId` of this node, derived from the local secp256k1 keypair.
    ///
    /// Used at startup to compute persistent attestation subnet assignments via
    /// `compute_subscribed_subnets`. Stored at build time so the keypair does
    /// not need to be retained after `NetworkBuilder::spawn`.
    pub fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    /// Receive the next event from the network task.
    ///
    /// Returns `None` when the network task has exited and the channel is
    /// drained. Uses `&mut self` to enforce single-consumer ownership.
    ///
    /// Panics if the event receiver has already been taken via `take_event_receiver`.
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx
            .as_mut()
            .expect("event receiver already taken")
            .recv()
            .await
    }

    /// Move the event receiver out of the handle.
    ///
    /// Allows the block-ingestion loop (or any other component) to own the
    /// `mpsc::Receiver<NetworkEvent>` directly, while the rest of the handle
    /// (command sender, peer ID, shutdown signal) remains intact.
    ///
    /// Panics if called more than once.
    pub fn take_event_receiver(&mut self) -> mpsc::Receiver<NetworkEvent> {
        self.event_rx.take().expect("event receiver already taken")
    }

    /// Wait until the network task emits a `LocalEnr` event, then return the
    /// node's signed ENR (which includes the real discv5 UDP port).
    ///
    /// Emitted once at startup by `Network::run` before the main select loop.
    /// Integration tests that need to pass this node's ENR as a bootnode to
    /// another test node should await this before calling `spawn_node`.
    ///
    /// Panics if the event receiver has already been taken via `take_event_receiver`.
    pub async fn wait_for_local_enr(&mut self) -> crate::discovery::enr::Enr {
        let rx = self
            .event_rx
            .as_mut()
            .expect("event receiver already taken");
        loop {
            match rx.recv().await {
                Some(NetworkEvent::LocalEnr(enr)) => return enr,
                Some(_) => continue,
                None => panic!("network channel closed before LocalEnr was emitted"),
            }
        }
    }

    /// Wait until the network task emits a `NewListenAddr` event, then return
    /// that multiaddr.
    ///
    /// Used by integration tests that bind on OS-assigned port 0 and need the
    /// real bound address before dialling. Panics if the channel closes before
    /// a `NewListenAddr` event is received (indicates the network task exited
    /// abnormally).
    ///
    /// Justification for adding this helper: `NetworkBuilder::build` calls
    /// `swarm.listen_on(addr)` which queues the bind request, but the real
    /// port is assigned asynchronously by the OS and reported via
    /// `SwarmEvent::NewListenAddr`. There is no synchronous API to query the
    /// actual bound port after `listen_on`; polling events is the only option.
    ///
    /// Panics if the event receiver has already been taken via `take_event_receiver`.
    pub async fn wait_for_listen_addr(&mut self) -> libp2p::Multiaddr {
        let rx = self
            .event_rx
            .as_mut()
            .expect("event receiver already taken");
        loop {
            match rx.recv().await {
                Some(NetworkEvent::NewListenAddr(addr)) => return addr,
                Some(_) => continue,
                None => panic!("network channel closed before NewListenAddr was emitted"),
            }
        }
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

    /// Unsubscribe from a gossipsub `topic` at runtime.
    ///
    /// Used by the fork-migration loop to drop phase-0 topics after crossing
    /// `ALTAIR_FORK_EPOCH`. Idempotent: unsubscribing a topic not currently
    /// subscribed succeeds silently.
    pub async fn unsubscribe(&self, topic: GossipTopic) -> Result<(), NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCommand::Unsubscribe {
                topic,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Update the local node's `MetaData` (Altair v2).
    ///
    /// The network task increments `seq_number` if the new attnets or syncnets
    /// differ from the cached value. No reply channel — fire-and-forget.
    pub async fn update_metadata(&self, meta: AltairMetaData) -> Result<(), NetworkError> {
        self.cmd_tx
            .send(NetworkCommand::UpdateMetaData(meta))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
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

    /// Return the `PeerId` with the highest `head_slot` among connected peers
    /// that have completed the Status handshake.  Returns `None` when no peers
    /// have a known `Status` yet.
    ///
    /// Issues a `NetworkCommand::PickHighestHeadPeer` and awaits the reply from
    /// the network task.
    pub async fn pick_highest_head_peer(&self) -> Option<PeerId> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCommand::PickHighestHeadPeer { reply: reply_tx })
            .await
            .is_err()
        {
            return None;
        }
        reply_rx.await.unwrap_or(None)
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
