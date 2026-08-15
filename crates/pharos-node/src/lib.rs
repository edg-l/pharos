//! Library surface for `pharos-node`.
//!
//! Exposes internal modules so integration tests in `tests/` can access
//! `HostImpl<E>` and related types without duplicating construction logic.

pub mod block_ingestion;
pub mod engine_driver;
pub mod engine_keepalive;
pub mod fork_migration;
pub mod host_impl;
pub mod jwt_autogen;
pub mod pow_block;
pub mod startup;
pub mod subnet_rotation;

pub use engine_driver::ExecutionEngineHandle;
