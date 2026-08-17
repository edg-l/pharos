//! Integration tests for `pharos-network`.
//!
//! All integration tests compile into this one binary. Every test target links
//! the full dependency tree statically, so one target per crate bounds link time
//! and `target/` size by crate count rather than by test count. It also
//! leaves the process-global tracing dispatcher with a single owner.

mod common;

mod backpressure;
mod bellatrix_fork_migration;
mod connection_limits;
mod context_bytes;
mod data_columns_by_root_wire;
mod dial_dedup;
mod discovery;
mod events_m3a;
mod fork_epoch_migration;
mod goodbye;
mod gossip;
mod peer_scoring_e2e;
mod quic_connect;
mod redundant_connection;
mod rpc;
mod shutdown_goodbye;
