//! Shared test scaffolding for `pharos-node` integration tests.
//!
//! `genesis` exposes a zero-cost cached genesis state for the minimal preset,
//! removing the need for per-test fixture files or `--genesis-state-path`
//! boilerplate.
//!
//! `checkpoint_helpers` exposes `build_anchor_bellatrix` and
//! `build_backfill_chain` for use by checkpoint-sync + backfill integration
//! tests.

pub mod checkpoint_helpers;
pub mod genesis;
pub mod node;
