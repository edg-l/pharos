//! Integration test: cold-start checkpoint-sync writes anchor state + block
//! atomically to RocksDB via `fetch_checkpoint` + `apply_anchor`.
//!
//! Uses an axum mock Beacon API and a tempdir
//! `RocksStore`. Asserts the persisted `ForkChoiceSnapshot`, block, and state
//! are all present and consistent after the write.

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::{Router, routing::get};
use pharos_ssz::{Encode, TreeHash};
use pharos_storage::{RocksStore, RocksStoreConfig, Store as StoreTrait};
use pharos_types::MinimalBeaconSpec;
use pharos_types::bellatrix::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
};
use pharos_types::phase0::misc::Checkpoint;
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::state::MinimalBeaconState as ForkMinimalBeaconState;
use tokio::net::TcpListener;

use pharos_node::checkpoint_sync::{apply_anchor, fetch_checkpoint};

/// Bind to a random free port and return `(addr_string, TcpListener)`.
async fn bind_random() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (addr.to_string(), listener)
}

/// Cold-start checkpoint sync writes anchor state + block to RocksDB atomically.
///
/// Verifies:
///   - `snapshot.head_root == anchor.block_root`
///   - `store.get_block(anchor.block_root).is_some()`
///   - `store.get_state(anchor.state_root).is_some()`
///   - `store.get_forkchoice_snapshot().unwrap().head_slot == Slot(64)`
#[tokio::test]
async fn cold_start_checkpoint_sync_writes_anchor() {
    // ── Build a Bellatrix state with non-default fields ───────────────────────

    // Build a block body and header to populate `latest_block_header`.
    let body = MinimalBeaconBlockBody::default();
    let body_root: Root = body.tree_hash_root();

    let state_inner = MinimalBeaconState {
        genesis_time: 1_700_000_000u64,
        slot: Slot(64),
        current_justified_checkpoint: Checkpoint {
            epoch: Epoch(1),
            root: Root::from([0x10u8; 32]),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch(1),
            root: Root::from([0x10u8; 32]),
        },
        // `state_root` is zeroed in `latest_block_header` (per spec
        // `process_block_header`); only filled by `process_slot` next slot.
        latest_block_header: BeaconBlockHeader {
            slot: Slot(64),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root,
        },
        ..MinimalBeaconState::default()
    };

    // Compute the state root via the fork-enum (tree hash ignores the discriminant).
    let computed_state_root: Root =
        ForkMinimalBeaconState::Bellatrix(state_inner.clone()).tree_hash_root();

    // ── Build the matching signed block ───────────────────────────────────────
    //
    // The block served by the API has `message.state_root = computed_state_root`.

    let signed_block_inner = MinimalSignedBeaconBlock {
        message: MinimalBeaconBlock {
            slot: Slot(64),
            parent_root: Root::default(),
            state_root: computed_state_root,
            body: body.clone(),
            ..MinimalBeaconBlock::default()
        },
        ..MinimalSignedBeaconBlock::default()
    };

    // ── Derive the expected block_root ────────────────────────────────────────
    //
    // Same derivation as `fetch_checkpoint`: substitute `computed_state_root`
    // into a copy of `latest_block_header`, then `tree_hash_root()`.

    let expected_block_root: Root = {
        let h = BeaconBlockHeader {
            slot: Slot(64),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: computed_state_root,
            body_root,
        };
        h.tree_hash_root()
    };

    // Encode as raw per-fork SSZ (no fork-enum discriminant prefix).
    // The Beacon API returns per-fork bytes; the fork is identified by the
    // `Eth-Consensus-Version` header.
    let state_bytes = state_inner.as_ssz_bytes();
    let block_bytes = signed_block_inner.as_ssz_bytes();
    let block_root_hex = hex::encode(expected_block_root.as_slice());

    // ── Spin up the axum mock ─────────────────────────────────────────────────

    let state_arc = Arc::new(state_bytes);
    let block_arc = Arc::new(block_bytes);

    let app = Router::new()
        .route(
            "/eth/v2/debug/beacon/states/finalized",
            get({
                let sb = state_arc.clone();
                move || {
                    let sb = sb.clone();
                    async move {
                        let mut headers = HeaderMap::new();
                        headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                        (StatusCode::OK, headers, (*sb).clone())
                    }
                }
            }),
        )
        .route(
            &format!("/eth/v2/beacon/blocks/0x{block_root_hex}"),
            get({
                let bb = block_arc.clone();
                move || {
                    let bb = bb.clone();
                    async move {
                        let mut headers = HeaderMap::new();
                        headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                        (StatusCode::OK, headers, (*bb).clone())
                    }
                }
            }),
        );

    let (addr, listener) = bind_random().await;
    let server_handle = tokio::spawn(axum::serve(listener, app).into_future());

    // ── Fetch and apply anchor ────────────────────────────────────────────────

    let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
    let http = reqwest::Client::new();

    let anchor = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None)
        .await
        .expect("fetch_checkpoint should succeed");

    assert_eq!(
        anchor.block_root, expected_block_root,
        "block_root mismatch"
    );
    assert_eq!(
        anchor.state_root, computed_state_root,
        "state_root mismatch"
    );

    // Capture values before moving anchor into apply_anchor.
    let anchor_block_root = anchor.block_root;
    let anchor_state_root = anchor.state_root;
    let current_slot = {
        use pharos_types::views::BeaconStateView as _;
        anchor.state.slot().0
    };

    let datadir = tempfile::TempDir::new().unwrap();
    let store = RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
        path: datadir.path().join("chain_db"),
        create_if_missing: true,
    })
    .expect("open store");

    // This integration test exercises the fetch+persist path; its synthetic
    // anchor state carries no active validators, so bypass the weak-subjectivity
    // freshness gate (covered by dedicated unit tests in `checkpoint_sync.rs`).
    let snapshot = apply_anchor::<MinimalBeaconSpec>(anchor, &store, current_slot, true)
        .expect("apply_anchor should succeed");

    server_handle.abort();

    // ── Assert persisted state ────────────────────────────────────────────────

    assert_eq!(
        snapshot.head_root, anchor_block_root,
        "snapshot.head_root should equal anchor.block_root"
    );
    assert_eq!(
        snapshot.head_slot,
        Slot(64),
        "snapshot.head_slot should be 64"
    );

    assert!(
        <RocksStore as StoreTrait<MinimalBeaconSpec>>::get_block(&store, &anchor_block_root)
            .expect("get_block")
            .is_some(),
        "block should be persisted"
    );
    assert!(
        <RocksStore as StoreTrait<MinimalBeaconSpec>>::get_state(&store, &anchor_state_root)
            .expect("get_state")
            .is_some(),
        "state should be persisted"
    );

    let stored_snap =
        <RocksStore as StoreTrait<MinimalBeaconSpec>>::get_forkchoice_snapshot(&store)
            .expect("get_forkchoice_snapshot")
            .expect("snapshot should be present");

    assert_eq!(
        stored_snap.head_slot,
        Slot(64),
        "stored snapshot head_slot should be 64"
    );
    assert_eq!(
        stored_snap.head_root, anchor_block_root,
        "stored snapshot head_root should equal anchor block_root"
    );
}
