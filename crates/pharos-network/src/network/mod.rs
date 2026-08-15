//! Core network task: `Network` struct and `NetworkBuilder`.
//!
//! `Network` owns the libp2p `Swarm`, the discv5 `DiscoveryService`, and the
//! `PeerManager`. `NetworkBuilder` constructs and starts the stack.

use crate::error::NetworkError;
use crate::handle::NetworkHandle;

/// The running network task.
///
/// Constructed via `NetworkBuilder::build`. Call `run()` to drive the event
/// loop, or `NetworkBuilder::spawn` to run it in a Tokio task.
pub struct Network;

/// Builder for `Network`.
pub struct NetworkBuilder;

impl NetworkBuilder {
    /// Consumes the builder and returns a `(Network, NetworkHandle)` pair.
    pub async fn build(self) -> Result<(Network, NetworkHandle), NetworkError> {
        Ok((Network, NetworkHandle))
    }
}
