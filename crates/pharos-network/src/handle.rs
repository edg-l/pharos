//! `NetworkHandle` — the external API for issuing commands and receiving events.

use tokio::sync::{mpsc, oneshot};

use crate::error::NetworkError;
use crate::network::{NetworkCommand, NetworkEvent};

/// Handle to the running network task.
///
/// Provides the public command/event interface consumed by `pharos-node`.
/// A single owner holds the event receiver (`mpsc::Receiver` is not `Clone`);
/// the command sender (`cmd_tx`) is clonable for multi-producer use.
pub struct NetworkHandle {
    /// Send commands to the `Network` event loop.
    cmd_tx: mpsc::Sender<NetworkCommand>,
    /// Receive events emitted by the `Network` event loop.
    ///
    /// Held by a single consumer.  Phase 4/5/6 populate this channel.
    pub event_rx: mpsc::Receiver<NetworkEvent>,
    /// Fire to trigger a clean shutdown of the `Network` event loop.
    ///
    /// Wrapped in `Option` so `shutdown()` can take it by value.
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl NetworkHandle {
    /// Construct a new handle from the channel endpoints created by `NetworkBuilder::build`.
    pub(crate) fn new(
        cmd_tx: mpsc::Sender<NetworkCommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
        shutdown_tx: oneshot::Sender<()>,
    ) -> Self {
        Self {
            cmd_tx,
            event_rx,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// Shuts the network task down cleanly.
    ///
    /// Sends `NetworkCommand::Shutdown` via the command channel, then fires
    /// the oneshot shutdown signal.  Either signal alone is sufficient for
    /// `Network::run` to exit; both are sent for robustness.
    pub async fn shutdown(mut self) -> Result<(), NetworkError> {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}
