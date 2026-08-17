//! Integration test: engine driver loop marks INVALID payload blocks, and
//! `get_head` skips them.
//!
//!
//! Test scenario:
//! 1. Build a 2-block in-memory fork-choice store: anchor → block_a.
//! 2. Spawn `run_engine_driver_loop` with an axum mock that returns `INVALID`
//!    for `engine_newPayloadV1`.
//! 3. Send a `NewPayloadRequest` for block_a's root.
//! 4. Wait for the driver to process it.
//! 5. Assert `store.payload_statuses[block_a_root] == PayloadStatus::Invalid`.
//! 6. Assert `get_head` returns the anchor root (block_a is skipped).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use parking_lot::{Mutex, RwLock};
use pharos_engine::{EngineClient, JwtSecret, spawn_engine_actor};
use pharos_fork_choice::Store as FcStore;
use pharos_node::engine_driver::{
    NewPayloadRequest, compute_safe_block_hash, run_engine_driver_loop,
};
use pharos_ssz::TreeHash;
use pharos_types::phase0::primitives::Root;
use pharos_types::state::{BeaconBlock as ForkBeaconBlock, MinimalBeaconState};
use pharos_types::{MinimalBeaconSpec, PayloadStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

// ── Minimal genesis helper ────────────────────────────────────────────────────

fn minimal_genesis_state() -> MinimalBeaconState {
    pharos_types::state::MinimalBeaconState::Phase0(
        pharos_types::phase0::MinimalBeaconState::default(),
    )
}

// ── Mock Engine API server ────────────────────────────────────────────────────

#[derive(Clone)]
struct MockState {
    secret: Arc<JwtSecret>,
    responses: Arc<Mutex<HashMap<String, Value>>>,
}

#[derive(Deserialize)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    #[allow(dead_code)]
    params: Value,
    id: u64,
}

async fn rpc_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    // JWT validation
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let Some(token) = bearer else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "no token" })),
        )
            .into_response();
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.required_spec_claims.insert("iat".into());
    validation.validate_exp = false;
    let key = DecodingKey::from_secret(state.secret.as_bytes());
    if decode::<Value>(token, &key, &validation).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "bad token" })),
        )
            .into_response();
    }

    let result = state
        .responses
        .lock()
        .get(&req.method)
        .cloned()
        .unwrap_or(json!(null));
    let envelope = json!({"jsonrpc": "2.0", "id": req.id, "result": result});
    (StatusCode::OK, Json(envelope)).into_response()
}

struct Mock {
    url: reqwest::Url,
    secret: JwtSecret,
    responses: Arc<Mutex<HashMap<String, Value>>>,
}

impl Mock {
    fn set(&self, method: &str, value: Value) {
        self.responses.lock().insert(method.into(), value);
    }
}

async fn spawn_mock() -> Mock {
    let secret = JwtSecret::from_bytes([0xABu8; 32]);
    let responses = Arc::new(Mutex::new(HashMap::new()));
    let state = MockState {
        secret: Arc::new(secret.clone()),
        responses: responses.clone(),
    };
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url: reqwest::Url = format!("http://{addr}/").parse().unwrap();
    Mock {
        url,
        secret,
        responses,
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Builds a minimal in-memory `FcStore<MinimalBeaconSpec>` seeded with an anchor
/// block (representing the genesis) and one additional block (`block_a`).
///
/// Returns `(store, anchor_root, block_a_root)`.
fn build_two_block_store() -> (FcStore<MinimalBeaconSpec>, Root, Root) {
    let genesis_state = minimal_genesis_state();
    let state_root = genesis_state.tree_hash_root();

    let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MinimalBeaconBlock {
        state_root,
        ..Default::default()
    });
    let anchor_root: Root = anchor_block.tree_hash_root();

    let mut store =
        pharos_fork_choice::get_forkchoice_store::<MinimalBeaconSpec>(genesis_state, anchor_block);

    // Insert a second block (block_a) as a direct child of the anchor.
    // We use slot 1 and parent_root = anchor_root.
    let block_a = ForkBeaconBlock::Phase0(pharos_types::phase0::MinimalBeaconBlock {
        slot: pharos_types::phase0::Slot(1),
        parent_root: anchor_root,
        state_root: Root::from([0x11u8; 32]),
        ..Default::default()
    });
    let block_a_root: Root = block_a.tree_hash_root();

    // Manually insert block_a into the fork-choice store (bypass `on_block` to
    // avoid STF dependency in this unit-level integration test).
    store.blocks.insert(block_a_root, block_a);
    store
        .block_states
        .insert(block_a_root, MinimalBeaconState::default());

    // Give block_a a head weight by populating `unrealized_justifications`.
    store
        .unrealized_justifications
        .insert(block_a_root, store.justified_checkpoint.clone());

    (store, anchor_root, block_a_root)
}

#[tokio::test]
async fn engine_driver_marks_invalid_payload_and_skips_in_get_head() {
    // 1. Build fork-choice store.
    let (store, anchor_root, block_a_root) = build_two_block_store();
    let fc = Arc::new(RwLock::new(store));

    // 2. Spawn axum mock that returns INVALID for engine_newPayloadV1.
    let mock = spawn_mock().await;
    mock.set(
        "engine_newPayloadV1",
        json!({
            "status": "INVALID",
            "latestValidHash": null,
            "validationError": "test: forced invalid"
        }),
    );
    // engine_forkchoiceUpdatedV1 returns VALID to avoid confusing the driver.
    mock.set(
        "engine_forkchoiceUpdatedV1",
        json!({
            "payloadStatus": {
                "status": "VALID",
                "latestValidHash": null,
                "validationError": null
            },
            "payloadId": null
        }),
    );
    // engine_exchangeCapabilities for client init.
    mock.set(
        "engine_exchangeCapabilities",
        json!(["engine_newPayloadV1", "engine_forkchoiceUpdatedV1"]),
    );

    // 3. Spawn the engine actor + driver loop.
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(client, None);

    let (head_tx, head_rx) = watch::channel::<Option<pharos_node::engine_driver::HeadChange>>(None);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(16);

    {
        let fc_clone = Arc::clone(&fc);
        let eng = engine_handle.clone();
        let head_tx_driver = head_tx.clone();
        tokio::spawn(async move {
            run_engine_driver_loop::<MinimalBeaconSpec, pharos_fork_choice::NoopPowBlockProvider>(
                eng,
                fc_clone,
                head_rx,
                payload_rx,
                head_tx_driver,
                Arc::new(pharos_fork_choice::NoopPowBlockProvider),
            )
            .await;
        });
    }

    // 4. Send a NewPayloadRequest for block_a.
    let dummy_payload = pharos_engine::types::ExecutionPayloadV1 {
        parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        fee_recipient: "0x0000000000000000000000000000000000000000".into(),
        state_root: "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        receipts_root: "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        logs_bloom: "0x00".into(),
        prev_randao: "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        block_number: "0x1".into(),
        gas_limit: "0x1c9c380".into(),
        gas_used: "0x0".into(),
        timestamp: "0x1".into(),
        extra_data: "0x".into(),
        base_fee_per_gas: "0x0".into(),
        block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        transactions: vec![],
    };

    payload_tx
        .send(NewPayloadRequest {
            block_root: block_a_root,
            payload: pharos_engine::NewPayloadWire::V1(dummy_payload),
            _marker: std::marker::PhantomData,
        })
        .await
        .unwrap();

    // 5. Wait for the driver to process the request (give it up to 2 s).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("engine driver did not mark block_a as Invalid within timeout");
        }
        {
            let s = fc.read();
            if let Some(status) = s.payload_statuses.get(&block_a_root) {
                assert_eq!(
                    *status,
                    PayloadStatus::Invalid,
                    "engine driver must mark block_a as Invalid"
                );
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 6. Assert get_head returns the anchor (block_a is Invalid and skipped).
    //
    // `block_a` was inserted directly into the fork-choice store's `blocks` and
    // `block_states` maps (bypassing `on_block`) so LMD-GHOST does see it as a
    // candidate. With `PayloadStatus::Invalid`, `filter_block_tree` skips it and
    // the head reverts to the anchor root.
    let s = fc.read();
    assert_eq!(
        s.payload_statuses.get(&block_a_root),
        Some(&PayloadStatus::Invalid),
        "payload status must be Invalid after engine driver processes the request"
    );

    let head = pharos_fork_choice::get_head::<MinimalBeaconSpec>(&s);
    assert_eq!(
        head, anchor_root,
        "get_head must return the anchor root when block_a is Invalid"
    );

    // Drop head_tx to allow head_rx to close (stops driver loop).
    drop(head_tx);
}

// ── safe-hash tests ───────────────────────────────────────────────────────────

/// A Bellatrix head block with `PayloadStatus::NotValidated` must NEVER be
/// returned as the `safe_block_hash`.
///
/// The store has: anchor (Phase0, non-execution) → block_a (Bellatrix,
/// NotValidated). `compute_safe_block_hash` must resolve via
/// `latest_verified_ancestor` to the anchor, whose execution hash is the zero
/// hash (Phase0 has no execution payload).
///
/// Per ADR `D-safe-hash-verified-ancestor`.
// Block fields are set after Default::default(); struct-init syntax cannot
// express nested fields cleanly.
#[allow(clippy::field_reassign_with_default)]
#[test]
fn compute_safe_block_hash_never_returns_not_validated_head() {
    use pharos_fork_choice::get_forkchoice_store;
    use pharos_types::bellatrix::MinimalBeaconBlock as BellatrixBlock;
    use pharos_types::phase0::{BeaconBlock, Slot};
    use pharos_utils::Hash256;

    // Build genesis store (Phase0).
    let genesis_state =
        MinimalBeaconState::Phase0(pharos_types::phase0::MinimalBeaconState::default());
    let state_root = genesis_state.tree_hash_root();
    let mut raw_genesis = BeaconBlock::default();
    raw_genesis.state_root = state_root;
    let genesis_block = ForkBeaconBlock::Phase0(raw_genesis);
    let mut store: FcStore<MinimalBeaconSpec> =
        get_forkchoice_store::<MinimalBeaconSpec>(genesis_state, genesis_block);

    let anchor_root = store.justified_checkpoint.root;

    // Insert a Bellatrix child with a non-zero block_hash (execution-enabled).
    let exec_block_hash = Hash256::from_array([0xBB; 32]);
    let mut raw_exec = BellatrixBlock::default();
    raw_exec.slot = Slot(1);
    raw_exec.parent_root = anchor_root;
    raw_exec.body.execution_payload.block_hash = exec_block_hash;
    let exec_block = ForkBeaconBlock::Bellatrix(raw_exec);
    let exec_root = exec_block.tree_hash_root();
    store.blocks.insert(exec_root, exec_block);
    store
        .block_states
        .insert(exec_root, MinimalBeaconState::default());
    // Mark it NotValidated (optimistic).
    store.mark_payload_status(exec_root, PayloadStatus::NotValidated);
    // Give it weight so it would be chosen as head.
    store
        .unrealized_justifications
        .insert(exec_root, store.justified_checkpoint.clone());

    // compute_safe_block_hash must NOT return exec_block_hash because the block
    // is NotValidated. latest_verified_ancestor walks back to anchor (Phase0,
    // non-execution → zero hash).
    let safe = compute_safe_block_hash::<MinimalBeaconSpec>(&store);
    assert_ne!(
        safe, exec_block_hash,
        "a NotValidated Bellatrix head must never be the safe_block_hash"
    );
    // Anchor is Phase0 (no execution payload) → safe hash is the zero hash.
    assert_eq!(
        safe,
        Hash256::default(),
        "safe_block_hash must be zero (Phase0 anchor) when head is NotValidated"
    );
}
