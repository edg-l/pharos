//! Metrics emission oracle test (Task 6.8 of M11 Phase 6).
//!
//! Verifies that `import_block` causes the `pharos_stf_process_block_seconds`
//! histogram to accumulate at least one sample beyond the initial zero-value
//! seed written by `register_metrics`.
//!
//! Strategy:
//!   (a) Take the binary-wide Prometheus recorder handle from `common`.
//!   (b) Build a one-block Bellatrix fixture chain and call `import_block`.
//!   (c) Render the Prometheus text and assert the histogram sample count for
//!       `pharos_stf_process_block_seconds` is greater than 1 (> 1 because
//!       `register_metrics` pre-seeds one 0.0 sample; the `import_block` call
//!       adds a second real observation).

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_fork_choice::get_forkchoice_store;
use pharos_ssz::TreeHash;
use pharos_stf::NullExecutionEngine;
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::config::RuntimeConfig;
use pharos_types::state::{BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinState};
use pharos_types::{BeaconSpec, MinimalBeaconSpec};

use tokio::sync::mpsc;

use pharos_node::data_availability::NoopDataAvailabilityChecker;
use pharos_node::engine_driver::NewPayloadRequest;
use pharos_node::import::import_block;

use crate::common::checkpoint_helpers::{
    BACKFILL_GENESIS_TIME_SECS, build_anchor_bellatrix, build_backfill_chain,
};

// ── Test ──────────────────────────────────────────────────────────────────────

/// Verify that one `import_block` causes the `process_block` histogram to
/// accumulate at least two observations (the seed zero + the real timing).
///
/// Per Task 6.8 (M11 Phase 6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_block_records_process_block_histogram() {
    let handle = crate::common::metrics_handle();

    // (a) Build a Bellatrix anchor state + one-block chain.
    let (anchor_state, anchor_signed) =
        build_anchor_bellatrix(pharos_types::phase0::Slot(0), BACKFILL_GENESIS_TIME_SECS);

    // Compute anchor block root from the inner message (before fork-wrapping).
    let anchor_block_root = anchor_signed.message.tree_hash_root();

    // Fork-wrap the anchor state and block for get_forkchoice_store.
    let fork_anchor_state = ForkMinState::Bellatrix(anchor_state.clone());
    let fork_anchor_block = ForkBeaconBlock::Bellatrix(anchor_signed.message.clone());

    let mut fc_store =
        get_forkchoice_store::<MinimalBeaconSpec>(fork_anchor_state, fork_anchor_block);

    // Advance the fork-choice store time so blocks are not rejected as future-slot.
    fc_store.time = BACKFILL_GENESIS_TIME_SECS + 1_000_000;

    let fc = Arc::new(RwLock::new(fc_store));

    // Seed the anchor state into block_states (import_block reads pre-state from here).
    {
        let mut w = fc.write();
        w.block_states.insert(
            anchor_block_root,
            ForkMinState::Bellatrix(anchor_state.clone()),
        );
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let rocks_store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("RocksStore::open"),
    );

    // Build one block on top of the anchor using the shared chain-builder helper.
    let chain = build_backfill_chain(&anchor_state, 1);
    assert_eq!(
        chain.len(),
        1,
        "build_backfill_chain must produce exactly 1 block"
    );
    let block = &chain[0];

    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(16);
    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        altair_fork_epoch: 0,
        ..Default::default()
    };

    // (b) Call import_block — state_transition fires inside and records the histogram.
    let result = import_block::<
        MinimalBeaconSpec,
        NullExecutionEngine,
        pharos_fork_choice::NoopPowBlockProvider,
        NoopDataAvailabilityChecker,
    >(
        block,
        &fc,
        &Arc::new(NullExecutionEngine),
        &pow_provider,
        &payload_tx,
        false, // validate_result: false — test blocks use zero BLS signatures
        &runtime_cfg,
        &rocks_store,
        &Arc::new(NoopDataAvailabilityChecker),
    )
    .await;

    // import_block must succeed; any failure indicates a test infrastructure bug.
    result.expect("import_block must succeed with NullExecutionEngine + validate_result=false");

    // (c) Render and inspect the histogram count.
    let rendered = handle.render();

    // Locate the `_count` summary line.
    // Prometheus text format: `pharos_stf_process_block_seconds_count N`
    let count_line = rendered
        .lines()
        .find(|l| l.starts_with("pharos_stf_process_block_seconds_count"))
        .unwrap_or_else(|| {
            panic!(
                "pharos_stf_process_block_seconds_count not found in rendered metrics:\n{rendered}"
            )
        });

    let count: u64 = count_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse sample count from line: {count_line}"));

    // register_metrics pre-seeds one 0.0 observation; import_block adds a real one.
    assert!(
        count > 1,
        "pharos_stf_process_block_seconds must have >1 observations after import_block; got {count}"
    );
}
