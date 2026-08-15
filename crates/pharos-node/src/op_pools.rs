//! In-memory operation pools for the beacon node.
//!
//! The implementation now lives in `pharos-types::pools` so both `pharos-api`
//! and `pharos-node` can reference `OperationPools<E>` without a circular dep.
//! This module re-exports everything for backward-compat with existing imports
//! in `host_impl.rs`, `block_production.rs`, and tests.

pub use pharos_types::pools::{BlockOperations, MAX_POOL_ENTRIES, OperationPools, SyncMessageKey};
