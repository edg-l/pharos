//! Oracle for M11 Phase 17 — graceful shutdown sequence order.
//!
//! Per the plan: "Test `shutdown_sequence_order`: instrument each step with an
//! ordered marker and assert the sequence runs in order on a simulated SIGTERM
//! (use a channel, not a real signal, in the unit test)."
//!
//! This test drives `run_shutdown_sequence` with stub closures that push a
//! string marker into an `mpsc` channel, then asserts that the channel
//! delivers the markers in the exact prescribed order.

use pharos_node::shutdown::run_shutdown_sequence;
use pharos_storage::StorageError;
use tokio::sync::mpsc;

/// Verify that `run_shutdown_sequence` fires all six steps in order:
/// (a) goodbye, (b) drain_gossip, (c) save_scores, (d) save_enr, (e) db_fsync.
/// (Step (f) is "exit 0" — the function returning is the observable proxy.)
#[tokio::test]
async fn shutdown_sequence_order() {
    let (tx, mut rx) = mpsc::unbounded_channel::<&'static str>();

    let tx_a = tx.clone();
    let tx_b = tx.clone();
    let tx_c = tx.clone();
    let tx_d = tx.clone();
    let tx_e = tx.clone();

    run_shutdown_sequence(
        // (a) goodbye
        async move {
            tx_a.send("goodbye").unwrap();
        },
        // (b) drain_gossip
        async move {
            tx_b.send("drain_gossip").unwrap();
        },
        // (c) save_scores
        move || {
            tx_c.send("save_scores").unwrap();
        },
        // (d) save_enr
        move || {
            tx_d.send("save_enr").unwrap();
        },
        // (e) db_fsync
        move || -> Result<(), StorageError> {
            tx_e.send("db_fsync").unwrap();
            Ok(())
        },
    )
    .await;

    // After run_shutdown_sequence returns, all steps have fired.
    // Drop the original sender so rx.recv() returns None after the last message.
    drop(tx);

    let mut steps: Vec<&str> = Vec::new();
    while let Some(step) = rx.recv().await {
        steps.push(step);
    }

    assert_eq!(
        steps,
        [
            "goodbye",
            "drain_gossip",
            "save_scores",
            "save_enr",
            "db_fsync"
        ],
        "shutdown steps must fire in order (a)→(b)→(c)→(d)→(e)"
    );
}

/// Verify that a db_fsync error does not panic — it is logged and the
/// sequence continues to (f) (function returns).
#[tokio::test]
async fn shutdown_sequence_fsync_error_does_not_panic() {
    let (tx, mut rx) = mpsc::unbounded_channel::<&'static str>();

    let tx_c = tx.clone();

    run_shutdown_sequence(
        async {},
        async {},
        || {},
        || {},
        move || -> Result<(), StorageError> {
            tx_c.send("fsync_called").unwrap();
            Err(StorageError::CorruptedData(
                "simulated fsync failure".into(),
            ))
        },
    )
    .await;

    drop(tx);

    let mut steps: Vec<&str> = Vec::new();
    while let Some(step) = rx.recv().await {
        steps.push(step);
    }

    // fsync was called (error path exercised) and the function returned normally.
    assert_eq!(steps, ["fsync_called"]);
}
