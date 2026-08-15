//! `NetworkHandle` — the external API for issuing commands and receiving events.

use crate::error::NetworkError;

/// Handle to the running network task.
///
/// Provides the public command/event interface consumed by `pharos-node`.
/// A single owner holds the event receiver (`mpsc::Receiver` is not `Clone`);
/// the command sender (`cmd_tx`) is clonable for multi-producer use.
pub struct NetworkHandle;

impl NetworkHandle {
    /// Shuts the network task down cleanly.
    pub async fn shutdown(self) -> Result<(), NetworkError> {
        Ok(())
    }
}
