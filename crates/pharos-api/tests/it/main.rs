//! Integration tests for `pharos-api`.
//!
//! All integration tests compile into this one binary. Every test target links
//! the full dependency tree statically, so one target per crate bounds link time
//! and `target/` size by crate count rather than by test count.

mod blob_reads;
mod block_reads;
mod debug_reads;
mod light_client;
mod log_level;
mod rewards;
mod sse_events;
mod state_reads;
mod tier1_probes;
mod validator_and_auth;
mod validator_production_and_pool;
