//! Ordered graceful-shutdown sequence.
//!
//! Per `D-graceful-shutdown-order`, the beacon node shuts down
//! in exactly this order on SIGTERM or SIGINT:
//!
//! (a) `shutdown_goodbye` — Goodbye(1) to every connected peer + 500 ms
//!     outbound-RPC drain (inside the network task, which also drains
//!     in-flight gossip-validation tasks first).
//! (b) Drain pending gossip publishes (gossip_tasks JoinSet inside the
//!     network task — done as part of step (a) in `shutdown_goodbye`).
//! (c) Save peer scores (already invoked inside `shutdown_goodbye`).
//! (d) Save ENR seq (already invoked inside the network task on dir-flush;
//!     ENR seq is written on every mutation, so no extra call here).
//! (e) `RocksStore::fsync` — `flush_wal(true)` + `flush()`.
//! (f) Exit 0.
//!
//! The function `run_shutdown_sequence` drives steps (a)→(f) via async
//! closures so that:
//! - production code passes real implementations, and
//! - the `shutdown_sequence_order` unit test can instrument each step with
//!   an ordered channel marker and assert the sequence.

use std::future::Future;

use pharos_storage::StorageError;

/// Drive the graceful-shutdown sequence from step (a) to step (f).
///
/// Each step is a closure (sync or async) so the test can substitute
/// instrumented stubs that record execution order without real I/O.
///
/// # Arguments
///
/// * `goodbye`     — async closure: send Goodbye + drain network.
/// * `drain_gossip`— async closure: drain pending gossip publishes
///   (a no-op in production because the network task drains internally;
///   provided here so the test can assert step (b) fires).
/// * `save_scores` — sync closure: persist peer scores.
/// * `save_enr`    — sync closure: persist ENR seq.
/// * `db_fsync`    — sync closure: flush/fsync the chain DB.
pub async fn run_shutdown_sequence<Fg, Fd, Fs, Fe, Ff>(
    goodbye: Fg,
    drain_gossip: Fd,
    save_scores: Fs,
    save_enr: Fe,
    db_fsync: Ff,
) where
    Fg: Future<Output = ()>,
    Fd: Future<Output = ()>,
    Fs: FnOnce(),
    Fe: FnOnce(),
    Ff: FnOnce() -> Result<(), StorageError>,
{
    // (a) + (b): network goodbye + gossip drain.
    goodbye.await;
    drain_gossip.await;

    // (c) save peer scores.
    save_scores();

    // (d) save ENR seq.
    save_enr();

    // (e) fsync chain DB.
    if let Err(e) = db_fsync() {
        tracing::warn!(error = %e, "chain DB fsync failed during shutdown");
    }

    // (f) exit 0 — caller returns from main().
}
