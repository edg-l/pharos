//! Shared test scaffolding for `pharos-node` integration tests.
//!
//! `genesis` exposes a zero-cost cached genesis state for the minimal preset,
//! removing the need for per-test fixture files or `--genesis-state-path`
//! boilerplate.

pub mod genesis;
pub mod node;
