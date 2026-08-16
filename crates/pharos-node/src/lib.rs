//! Library surface for `pharos-node`.
//!
//! Exposes internal modules so integration tests in `tests/` can access
//! `HostImpl<E>` and related types without duplicating construction logic.

pub mod api_event_adapter;
pub mod backfill;
pub mod backward_backfill;
pub mod blob_ingestion;
pub mod blob_prune;
pub mod block_ingestion;
pub mod block_production;
pub mod checkpoint_sync;
pub mod data_availability;
pub mod engine_driver;
pub mod engine_keepalive;
pub mod fork_migration;
pub mod freezer;
pub mod host_impl;
pub mod import;
pub mod jwt_autogen;
pub mod lookup;
pub mod network_backfill_provider;
pub mod network_lookup_provider;
pub mod op_pools;
pub mod pending_blocks;
pub mod pow_block;
pub mod slasher;
pub mod startup;
pub mod state_regen;
pub mod subnet_rotation;

pub use engine_driver::ExecutionEngineHandle;
