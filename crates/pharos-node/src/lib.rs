//! Library surface for `pharos-node`.
//!
//! Exposes internal modules so integration tests in `tests/` can access
//! `HostImpl<E>` and related types without duplicating construction logic.

pub mod host_impl;
pub mod startup;
