//! Integration tests for `pharos-node`.
//!
//! All integration tests compile into this one binary. Every test target links
//! the full dependency tree statically, so one target per crate bounds link time
//! and `target/` size by crate count rather than by test count. It also
//! leaves the process-global tracing subscriber and metrics recorder with a
//! single owner.

mod common;

mod backward_backfill;
mod blob_da_pipeline;
mod block_production;
mod bls_to_exec_gossip_e2e;
mod capella_pipeline;
mod checkpoint_backfill_pipeline;
mod checkpoint_sync;
mod column_backfill_window;
mod deneb_pipeline;
mod electra_signing_root_repro;
mod engine_driver;
mod engine_pipeline;
mod freezer_migration;
mod fulu_lookup_da_gate;
mod fulu_pipeline;
mod get_payload_v2;
mod gossip_validators_e2e;
mod gossip_verdict_strings;
mod health_probe;
mod lc_gossip_publish;
mod live_block_persistence;
mod lookup_depth_exhaustion;
mod lookup_replay;
mod metadata_seq;
mod metrics_emission_oracle;
mod orphan_backfill_recovery;
mod persistence_restart;
mod restart_across_split;
mod shutdown_sequence;
mod slasher_replay;
mod state_replay;
mod two_node_persisted_blocks;
