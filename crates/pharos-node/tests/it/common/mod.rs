//! Shared test scaffolding for `pharos-node` integration tests.
//!
//! `genesis` exposes a zero-cost cached genesis state for the minimal preset,
//! removing the need for per-test fixture files or `--genesis-state-path`
//! boilerplate.
//!
//! `checkpoint_helpers` exposes `build_anchor_bellatrix` and
//! `build_backfill_chain` for use by checkpoint-sync + backfill integration
//! tests.

use std::sync::OnceLock;

use pharos_utils::metrics::{PrometheusHandle, init_metrics_with_handle};

pub mod checkpoint_helpers;
pub mod genesis;
pub mod node;

/// The one Prometheus recorder for this test binary.
///
/// `install_recorder` accepts a single recorder per process, so every test that
/// needs a `PrometheusHandle` shares this one rather than racing to install its
/// own and silently losing the handle.
pub fn metrics_handle() -> &'static PrometheusHandle {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        init_metrics_with_handle().expect("no other Prometheus recorder in this test binary")
    })
}
