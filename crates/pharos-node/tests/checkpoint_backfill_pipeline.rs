//! Mock end-to-end checkpoint-sync + backfill integration test.
//!
//! Drives the full checkpoint-sync → anchor-persist → fork-choice-rehydrate
//! → backfill-loop pipeline in-process without any out-of-process dependencies.
//!
//! Analogous to `engine_pipeline.rs` but for the M4b checkpoint-sync + backfill
//! flow (Task 5.4).
//!
//! Asserts:
//!   (a) `fc_store.head_slot == Slot(72)` after the backfill loop processes 8 blocks.
//!   (b) Engine mock recorded >= 8 `engine_newPayloadV1` calls.
//!   (c) Backfill loop exited `Ok(())`.
//!   (d) No panics, no `tokio::time::timeout` failures.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use parking_lot::{Mutex, RwLock};
use pharos_engine::{EngineClient, JwtSecret, spawn_engine_actor};
use pharos_fork_choice::get_head;
use pharos_ssz::{Encode, TreeHash};
use pharos_stf::NullExecutionEngine;
use pharos_storage::{ForkChoiceSnapshot, RocksStore, RocksStoreConfig};
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::primitives::{Root, Slot, Version};
use pharos_types::{EthSpec, MinimalEthSpec};
use pharos_utils::{Epoch, Hash256, Uint256};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use pharos_node::backfill::{BackfillBlockProvider, BackfillError, run_backfill_loop};
use pharos_node::checkpoint_sync::{apply_anchor, fetch_checkpoint};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::host_impl::HostImpl;
use pharos_node::pow_block::EnginePowBlockProvider;
use pharos_node::startup::rehydrate_fork_choice_store;

mod common;
use common::checkpoint_helpers::{
    BACKFILL_GENESIS_TIME_SECS, FC_STORE_TIME_ADVANCE_SECS, TERMINAL_BLOCK_HASH_BYTES,
    build_anchor_bellatrix, build_backfill_chain,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Anchor state is at slot 64 (one full 8-slot epoch in minimal preset).
const ANCHOR_SLOT: u64 = 64;

/// Number of backfill blocks (slots 65..=72).
const N_BACKFILL_BLOCKS: u64 = 8;

// ── Mock Engine API (Mock B) ──────────────────────────────────────────────────

#[derive(Clone, Default)]
struct CallCounters {
    new_payload: u64,
    fcu: u64,
}

#[derive(Clone)]
struct MockState {
    secret: Arc<JwtSecret>,
    responses: Arc<Mutex<HashMap<String, Value>>>,
    counters: Arc<Mutex<CallCounters>>,
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

    {
        let mut ctr = state.counters.lock();
        match req.method.as_str() {
            "engine_newPayloadV1" => ctr.new_payload += 1,
            "engine_forkchoiceUpdatedV1" => ctr.fcu += 1,
            _ => {}
        }
    }

    let result = state
        .responses
        .lock()
        .get(&req.method)
        .cloned()
        .unwrap_or(json!(null));
    (
        StatusCode::OK,
        Json(json!({"jsonrpc":"2.0","id":req.id,"result":result})),
    )
        .into_response()
}

struct EngineMock {
    url: reqwest::Url,
    secret: JwtSecret,
    responses: Arc<Mutex<HashMap<String, Value>>>,
    counters: Arc<Mutex<CallCounters>>,
}

impl EngineMock {
    fn set(&self, method: &str, val: Value) {
        self.responses.lock().insert(method.into(), val);
    }
    fn new_payload_count(&self) -> u64 {
        self.counters.lock().new_payload
    }
}

async fn spawn_engine_mock() -> EngineMock {
    let secret = JwtSecret::from_bytes([0u8; 32]);
    let responses = Arc::new(Mutex::new(HashMap::new()));
    let counters = Arc::new(Mutex::new(CallCounters::default()));
    let state = MockState {
        secret: Arc::new(secret.clone()),
        responses: responses.clone(),
        counters: counters.clone(),
    };
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url: reqwest::Url = format!("http://{addr}/").parse().unwrap();
    EngineMock {
        url,
        secret,
        responses,
        counters,
    }
}

// ── Mock Beacon API (Mock A) ──────────────────────────────────────────────────

async fn spawn_beacon_api_mock(
    state_bytes: Vec<u8>,
    block_bytes: Vec<u8>,
    block_root_hex: String,
) -> reqwest::Url {
    let state_bytes = Arc::new(state_bytes);
    let block_bytes = Arc::new(block_bytes);

    let app = Router::new()
        .route(
            "/eth/v2/debug/beacon/states/finalized",
            get({
                let sb = state_bytes.clone();
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
                let bb = block_bytes.clone();
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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/").parse().unwrap()
}

// ── FixtureBlockProvider (Provider C) ────────────────────────────────────────

/// In-process `BackfillBlockProvider` that returns the 8-block fixture chain on
/// the first call and `Ok(vec![])` on subsequent calls.
///
/// Not HTTP — `BeaconBlocksByRange` is a libp2p req-resp per `D-backfill-driver`.
#[derive(Clone)]
struct FixtureBlockProvider<E: EthSpec> {
    blocks: Arc<Mutex<Option<Vec<E::SignedBeaconBlock>>>>,
}

impl<E: EthSpec> FixtureBlockProvider<E> {
    fn new(blocks: Vec<E::SignedBeaconBlock>) -> Self {
        Self {
            blocks: Arc::new(Mutex::new(Some(blocks))),
        }
    }
}

impl BackfillBlockProvider<MinimalEthSpec> for FixtureBlockProvider<MinimalEthSpec> {
    async fn blocks_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
    ) -> Result<Vec<<MinimalEthSpec as EthSpec>::SignedBeaconBlock>, BackfillError> {
        let mut guard = self.blocks.lock();
        Ok(guard.take().unwrap_or_default())
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checkpoint_sync_then_backfill_advances_head() {
    let _ = tracing_subscriber::fmt::try_init();

    // ── 1. Build fixture chain ────────────────────────────────────────────────

    // Anchor state at slot 64. genesis_time = wall_now - 64 * SECONDS_PER_SLOT.
    // MinimalEthSpec::SLOT_DURATION_MS = 6_000, so SECONDS_PER_SLOT = 6.
    let seconds_per_slot = MinimalEthSpec::SLOT_DURATION_MS / 1000;
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let genesis_time = wall_now.saturating_sub(ANCHOR_SLOT * seconds_per_slot);

    let (anchor_state_inner, anchor_signed_block) =
        build_anchor_bellatrix(Slot(ANCHOR_SLOT), genesis_time);

    // Build 8 backfill blocks at slots 65..=72.
    let chain_blocks = build_backfill_chain(&anchor_state_inner, N_BACKFILL_BLOCKS);
    assert_eq!(chain_blocks.len(), N_BACKFILL_BLOCKS as usize);

    // ── 2. Compute anchor state_root and block_root (same as fetch_checkpoint) ─

    use pharos_types::state::MinimalBeaconState as ForkMinimalBeaconState;
    let fork_state = ForkMinimalBeaconState::Bellatrix(anchor_state_inner.clone());
    let computed_state_root: Root = fork_state.tree_hash_root();

    // Block root derived from latest_block_header with state_root substituted.
    let anchor_block_root: Root = {
        let mut h = anchor_state_inner.latest_block_header.clone();
        h.state_root = computed_state_root;
        h.tree_hash_root()
    };

    // ── 3. Spawn Mock A (Beacon API) ──────────────────────────────────────────

    // Encode as raw per-fork SSZ (no discriminant prefix), same as Beacon API.
    let state_bytes = anchor_state_inner.as_ssz_bytes();
    let block_bytes = anchor_signed_block.as_ssz_bytes();
    let block_root_hex = hex::encode(anchor_block_root.as_slice());

    let beacon_api_url = spawn_beacon_api_mock(state_bytes, block_bytes, block_root_hex).await;

    // ── 4. Spawn Mock B (Engine API) ──────────────────────────────────────────

    let engine_mock = spawn_engine_mock().await;
    engine_mock.set(
        "engine_newPayloadV1",
        json!({ "status": "VALID", "latestValidHash": null, "validationError": null }),
    );
    engine_mock.set(
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
    engine_mock.set(
        "engine_exchangeCapabilities",
        json!([
            "engine_newPayloadV1",
            "engine_forkchoiceUpdatedV1",
            "engine_exchangeCapabilities",
            "engine_exchangeTransitionConfigurationV1"
        ]),
    );
    engine_mock.set(
        "engine_exchangeTransitionConfigurationV1",
        json!({
            "terminalTotalDifficulty": "0x0",
            "terminalBlockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "terminalBlockNumber": "0x0"
        }),
    );

    // ── 5. Open tempdir RocksStore ────────────────────────────────────────────

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );

    // ── 6. Fetch checkpoint via Beacon API ────────────────────────────────────

    let http = reqwest::Client::new();
    let anchor = fetch_checkpoint::<MinimalEthSpec>(&beacon_api_url, &http, None)
        .await
        .expect("fetch_checkpoint must succeed");

    // ── 7. Persist anchor + synthesise fork-choice snapshot ──────────────────

    // `apply_anchor` now sets the correct checkpoint roots/epochs directly
    // (weak-subjectivity convention: anchor block = local finalized/justified
    // root). No caller-side patching needed; the snapshot is used as-is.
    let snapshot: ForkChoiceSnapshot =
        apply_anchor::<MinimalEthSpec>(anchor, &store).expect("apply_anchor must succeed");

    // ── 8. Rehydrate fork-choice store ────────────────────────────────────────

    let mut fc_store = rehydrate_fork_choice_store::<MinimalEthSpec>(&store, &snapshot)
        .expect("rehydrate_fork_choice_store must succeed");

    // Advance store time so that the fork-choice `current_slot` >=
    // `ANCHOR_SLOT + N_BACKFILL_BLOCKS`.  `genesis_time = wall_now -
    // ANCHOR_SLOT * seconds_per_slot`, so we need
    // `time >= genesis_time + (ANCHOR_SLOT + N_BACKFILL_BLOCKS) * seconds_per_slot`.
    // `FC_STORE_TIME_ADVANCE_SECS` (~11 days) past wall-clock satisfies this.
    // Use the public `on_tick` API rather than reaching into `fc_store.time`.
    pharos_fork_choice::on_tick::<MinimalEthSpec>(
        &mut fc_store,
        wall_now + FC_STORE_TIME_ADVANCE_SECS,
    );

    // Set terminal_block_hash override so the merge-transition guard passes.
    fc_store.set_terminal_config(
        Uint256::ZERO,
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );

    let fc_store = Arc::new(RwLock::new(fc_store));

    // ── 9. Build EngineClient + spawn engine actor ────────────────────────────

    let client = EngineClient::new(engine_mock.url.clone(), engine_mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(client, None);

    // ── 10. Wire channels ─────────────────────────────────────────────────────

    let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(64);

    // ── 11. Build HostImpl and wire engine ────────────────────────────────────

    let genesis_validators_root = Root::default();
    // Bellatrix-at-genesis schedule: all three epochs = 0.
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: Epoch(0),
        bellatrix_fork_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: Epoch(0),
        genesis_validators_root,
    };
    let mut host = HostImpl::<MinimalEthSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc_store),
        genesis_validators_root,
        fork_schedule,
        0,
        Arc::new(pharos_types::RuntimeConfig::default()),
    );
    host.wire_engine(head_tx.clone(), payload_tx.clone());
    let host = Arc::new(host);

    // ── 12. Spawn engine driver loop ──────────────────────────────────────────

    {
        let fc_clone = Arc::clone(&fc_store);
        let eng = engine_handle.clone();
        tokio::spawn(async move {
            run_engine_driver_loop::<MinimalEthSpec>(eng, fc_clone, head_rx, payload_rx).await;
        });
    }

    // ── 13. Spawn backfill loop with Provider C (FixtureBlockProvider) ────────

    let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle.clone()));
    let exec_engine = Arc::new(NullExecutionEngine);
    let provider = FixtureBlockProvider::<MinimalEthSpec>::new(chain_blocks);

    // Use a far-past genesis_time for the backfill loop's wall-slot computation
    // so that wall_slot >> ANCHOR_SLOT + N_BACKFILL_BLOCKS. The backfill loop
    // will process all 8 blocks and then block on the empty-provider retry delay
    // until we send the shutdown signal.
    let backfill_genesis_time_secs: u64 = BACKFILL_GENESIS_TIME_SECS;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let backfill_handle = {
        let fc_clone = Arc::clone(&fc_store);
        let host_clone = Arc::clone(&host);
        let ht = head_tx.clone();
        let pt = payload_tx.clone();
        tokio::spawn(async move {
            run_backfill_loop::<
                MinimalEthSpec,
                FixtureBlockProvider<MinimalEthSpec>,
                NullExecutionEngine,
                EnginePowBlockProvider,
            >(
                provider,
                host_clone,
                fc_clone,
                exec_engine,
                pow_provider,
                ht,
                pt,
                backfill_genesis_time_secs,
                shutdown_rx,
                std::sync::Arc::new(tokio::sync::Notify::new()),
                None,
            )
            .await
        })
    };

    // ── 14. Wait for head to advance to Slot(72) ──────────────────────────────

    let target_slot = Slot(ANCHOR_SLOT + N_BACKFILL_BLOCKS); // Slot(72)
    let fc_for_assert = Arc::clone(&fc_store);

    let head_reached = tokio::time::timeout(Duration::from_secs(30), async move {
        loop {
            let head_slot = {
                let s = fc_for_assert.read();
                let root = get_head::<MinimalEthSpec>(&s);
                s.blocks
                    .get(&root)
                    .map(|b| {
                        use pharos_types::views::BeaconBlockView as _;
                        b.slot()
                    })
                    .unwrap_or(Slot(0))
            };
            if head_slot >= target_slot {
                break head_slot;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timeout: head_slot did not reach Slot(72) within 30 seconds");

    // ── 15. Assertions ────────────────────────────────────────────────────────

    // (a) Head slot == Slot(72).
    assert_eq!(
        head_reached, target_slot,
        "head_slot must equal Slot(72) after processing all backfill blocks"
    );

    // Send shutdown signal so the backfill loop exits (it is blocked on the
    // empty-provider retry delay after processing all 8 blocks).
    let _ = shutdown_tx.send(true);

    // (c) Backfill loop exited Ok(()).
    let backfill_result = tokio::time::timeout(Duration::from_secs(10), backfill_handle)
        .await
        .expect("backfill_handle should complete within 10 s after shutdown signal")
        .expect("backfill task should not panic");
    assert!(
        backfill_result.is_ok(),
        "backfill loop must exit Ok(()), got: {backfill_result:?}"
    );

    // (b) Engine mock recorded >= 8 engine_newPayloadV1 calls.
    // Asserted after backfill_handle joins so all in-flight HTTP requests from
    // the engine driver have landed at the mock before we read the counter.
    assert!(
        engine_mock.new_payload_count() >= N_BACKFILL_BLOCKS,
        "expected >= {} engine_newPayloadV1 calls, got {}",
        N_BACKFILL_BLOCKS,
        engine_mock.new_payload_count()
    );

    // (d) No panics — reaching this point without panic proves (d).
    drop(head_tx);
    drop(payload_tx);
}
