//! Transport helpers for the Pharos libp2p stack.
//!
//! The transport stack ships both TCP (with Noise encryption and Yamux
//! multiplexing) and QUIC-v1 alongside DNS resolution.  Both transports share
//! a single [`PharosBehaviour`](super::behaviour::PharosBehaviour).
//!
//! Transport construction is performed inline via the libp2p 0.56
//! `SwarmBuilder` typed pipeline in [`super::NetworkBuilder::build`] rather
//! than via a hand-rolled `build_transport` function.  The `SwarmBuilder`
//! pipeline enforces correct composition at the type level and avoids the
//! boxing overhead of a hand-rolled transport.
//!
//! The chain used in `NetworkBuilder::build`:
//!
//! ```text
//! SwarmBuilder::with_existing_identity(local_key)
//!     .with_tokio()
//!     .with_tcp(tcp_config(), noise::Config::new, yamux_config)?
//!     .with_quic()
//!     .with_dns()?
//!     .with_behaviour(|key| PharosBehaviour { ... })?
//!     .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout()))
//!     .build()
//! ```
//!
//! Transport requirements: `specs/phase0/p2p-interface.md:142-203`.
//!
//! libp2p 0.56 `SwarmBuilder` docs:
//! <https://docs.rs/libp2p/0.56.0/libp2p/struct.SwarmBuilder.html>

use std::time::Duration;

/// TCP config for the Pharos transport stack.
///
/// `nodelay(true)` disables Nagle's algorithm, matching the recommendation in
/// `specs/phase0/p2p-interface.md` for low-latency gossip propagation.
pub fn tcp_config() -> libp2p::tcp::Config {
    libp2p::tcp::Config::default().nodelay(true)
}

/// Yamux multiplexer config for the Pharos transport stack.
///
/// Returns the library default, which is sufficient for Phase 0 operation.
/// Called as a function pointer (`transport::yamux_config`) by `SwarmBuilder`
/// to construct a fresh config per connection.
pub fn yamux_config() -> libp2p::yamux::Config {
    libp2p::yamux::Config::default()
}

/// Idle connection timeout for the Pharos swarm.
///
/// Connections with no open substreams are closed after this duration.
/// 60 seconds balances liveness checking frequency against connection churn.
pub fn idle_timeout() -> Duration {
    Duration::from_secs(60)
}
