//! Production `BackfillBlockProvider` backed by the p2p network.
//!
//! `NetworkBackfillProvider` implements `BackfillBlockProvider` by issuing a
//! `BeaconBlocksByRange` req-resp request to the peer chosen by `PeerPicker`.
//!
//! `PeerPicker` is a small trait used as `Arc<dyn PeerPicker>` so test code can
//! inject a `FixturePeerPicker` without wiring up the full network stack.
//! Because it is used as `dyn`, it must be `#[async_trait]`-annotated for
//! object-safety (the genuine reason — NOT because Rust lacks native async
//! fn-in-trait; Rust 1.85 has that, but it doesn't extend to `dyn`).

use std::sync::Arc;

use async_trait::async_trait;
use libp2p::PeerId;
use pharos_network::{
    NetworkCommandSender,
    rpc::types::{RpcRequest, RpcResponse},
};
use pharos_types::{BeaconSpec, phase0::BeaconBlocksByRangeRequest, phase0::primitives::Slot};

use crate::backfill::{BACKFILL_REQ_TIMEOUT, BackfillBlockProvider, BackfillError};

// ── PeerPicker ────────────────────────────────────────────────────────────────

/// Pick the best peer for a backfill request.
///
/// The production implementation (`NetworkHandlePeerPicker`) issues a
/// `NetworkCommand::PickHighestHeadPeer` via the command sender.  Tests inject
/// a `FixturePeerPicker` that returns a pre-configured `PeerId`.
///
/// Annotated with `#[async_trait]` for `dyn`-safety; this is the legitimate
/// reason (not a language gap — Rust 1.85 supports native `async fn` in trait
/// for non-`dyn` use).
#[async_trait]
pub trait PeerPicker: Send + Sync + 'static {
    async fn pick_highest_head_peer(&self) -> Option<PeerId>;
}

// ── NoopPeerPicker ────────────────────────────────────────────────────────────

/// A `PeerPicker` that always returns `None`.
///
/// Used when no real network peers are available (e.g. in tests that construct
/// `NetworkBackfillProvider` but exercise the `NoUsablePeers` path).
pub struct NoopPeerPicker;

#[async_trait]
impl PeerPicker for NoopPeerPicker {
    async fn pick_highest_head_peer(&self) -> Option<PeerId> {
        None
    }
}

// ── NetworkHandlePeerPicker ───────────────────────────────────────────────────

/// Production `PeerPicker` that forwards a `PickHighestHeadPeer` command to the
/// network task via the clonable `NetworkCommandSender`.
///
/// Constraint: must be called from within an `async` context (tokio runtime).
pub struct NetworkHandlePeerPicker<E: BeaconSpec> {
    sender: NetworkCommandSender<E>,
}

impl<E: BeaconSpec> NetworkHandlePeerPicker<E> {
    /// Create a new picker wrapping the given command sender.
    pub fn new(sender: NetworkCommandSender<E>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl<E: BeaconSpec> PeerPicker for NetworkHandlePeerPicker<E> {
    async fn pick_highest_head_peer(&self) -> Option<PeerId> {
        use pharos_network::NetworkCommand;
        use tokio::sync::oneshot;

        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .sender
            .send(NetworkCommand::PickHighestHeadPeer { reply: reply_tx })
            .await
            .is_err()
        {
            return None;
        }
        reply_rx.await.unwrap_or(None)
    }
}

// ── NetworkBackfillProvider ───────────────────────────────────────────────────

/// Production `BackfillBlockProvider` that issues `BeaconBlocksByRange` via the
/// p2p network.
///
/// `BackfillBlockProvider` uses native `async fn` in trait (Rust 1.85 stable)
/// because it is only used as a monomorphised generic; no `async-trait` is
/// needed on the impl.
pub struct NetworkBackfillProvider<E: BeaconSpec> {
    cmd: NetworkCommandSender<E>,
    peer_picker: Arc<dyn PeerPicker>,
}

impl<E: BeaconSpec> NetworkBackfillProvider<E> {
    /// Create a new provider using the given command sender and peer picker.
    pub fn new(cmd: NetworkCommandSender<E>, peer_picker: Arc<dyn PeerPicker>) -> Self {
        Self { cmd, peer_picker }
    }
}

impl<E: BeaconSpec> BackfillBlockProvider<E> for NetworkBackfillProvider<E>
where
    E::SignedBeaconBlock: Send + Sync + 'static,
{
    async fn blocks_by_range(
        &self,
        start_slot: Slot,
        count: u64,
    ) -> Result<Vec<E::SignedBeaconBlock>, BackfillError> {
        let req = || {
            RpcRequest::BlocksByRange(BeaconBlocksByRangeRequest {
                start_slot,
                count,
                step: 1,
            })
        };

        // Primary attempt.
        let peer1 = self
            .peer_picker
            .pick_highest_head_peer()
            .await
            .ok_or(BackfillError::NoUsablePeers)?;

        match self.cmd.request(peer1, req(), BACKFILL_REQ_TIMEOUT).await {
            Ok(RpcResponse::BlocksByRange(blocks)) => return Ok(blocks),
            Ok(other) => {
                return Err(BackfillError::Provider(format!(
                    "unexpected response variant: {other:?}"
                )));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    peer = ?peer1,
                    "backfill: primary peer failed; trying next-best"
                );
            }
        }

        // Single retry against the next-best peer (may be the same peer if
        // only one is connected — acceptable per D-backfill-driver ADR).
        let peer2 = self
            .peer_picker
            .pick_highest_head_peer()
            .await
            .ok_or(BackfillError::NoUsablePeers)?;

        match self.cmd.request(peer2, req(), BACKFILL_REQ_TIMEOUT).await {
            Ok(RpcResponse::BlocksByRange(blocks)) => Ok(blocks),
            Ok(other) => Err(BackfillError::Provider(format!(
                "unexpected response variant: {other:?}"
            ))),
            Err(_) => Err(BackfillError::NoUsablePeers),
        }
    }
}
