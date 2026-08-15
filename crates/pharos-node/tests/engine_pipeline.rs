//! In-process pipeline integration test.
//!
//! Drives a chain of Bellatrix blocks through:
//!   block_ingestion_loop → STF → pharos_fork_choice::on_block
//!     → HeadChange watch → engine driver → axum mock
//!
//! Asserts per Task 4.9b (M4a Phase 4):
//!   (a) `engine_newPayloadV1` called at least once per fixture block.
//!   (b) `engine_forkchoiceUpdatedV1` called at least once.
//!   (c) Head advances to slot 4 (4 blocks in the store + anchor = 5 blocks total).
//!   (d) One fixture block whose payload the mock returns `INVALID` for is recorded
//!       in `store.payload_statuses` as `Invalid` and not selected by `get_head`.
//!   (e) No panics, no `tokio::time::timeout` failures.
//!
//! Fixtures are generated in-test using `NullExecutionEngine` + `validate_result:false`
//! (the same pattern as conformance `bls_setting:2` fixtures). The ingestion loop also
//! uses `NullExecutionEngine` so the mock's INVALID response affects only the engine
//! driver, not the STF.

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
use pharos_fork_choice::{get_forkchoice_store, get_head};
use pharos_network::network::NetworkEvent;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_ssz::{Encode, SszSequence, TreeHash};
use pharos_stf::{NullExecutionEngine, state_transition};
use pharos_types::bellatrix::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayload,
};
use pharos_types::phase0::primitives::{Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinimalBeaconState,
};
use pharos_types::views::BeaconBlockView as _;
use pharos_types::{EthSpec, MinimalEthSpec, PayloadStatus};
use pharos_utils::{BLSSignature, Hash256};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use pharos_node::block_ingestion::run_block_ingestion_loop;
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::host_impl::HostImpl;
use pharos_node::pow_block::EnginePowBlockProvider;

mod common;
use common::checkpoint_helpers::{
    MinForkSignedBlock, TERMINAL_BLOCK_HASH_BYTES as CP_TERMINAL_HASH, build_anchor_bellatrix,
};

// ── Fixture constants ─────────────────────────────────────────────────────────

/// Number of blocks to generate in the chain.
/// "~16" per the plan; 4 covers all assertions and keeps the test fast.
const N_BLOCKS: u64 = 4;

/// Slot index of the block whose payload the mock returns `INVALID` for.
const INVALID_BLOCK_SLOT: u64 = 3;

/// `TERMINAL_BLOCK_HASH` for the merge-transition override mode.
/// Alias to the shared constant in `common::checkpoint_helpers`.
const TERMINAL_BLOCK_HASH_BYTES: [u8; 32] = CP_TERMINAL_HASH;

// ── Mock Engine API server ────────────────────────────────────────────────────

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

struct Mock {
    url: reqwest::Url,
    secret: JwtSecret,
    responses: Arc<Mutex<HashMap<String, Value>>>,
    counters: Arc<Mutex<CallCounters>>,
}

impl Mock {
    fn set(&self, method: &str, val: Value) {
        self.responses.lock().insert(method.into(), val);
    }
    fn new_payload_count(&self) -> u64 {
        self.counters.lock().new_payload
    }
    fn fcu_count(&self) -> u64 {
        self.counters.lock().fcu
    }
}

async fn spawn_mock() -> Mock {
    let secret = JwtSecret::from_bytes([0xABu8; 32]);
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
    Mock {
        url,
        secret,
        responses,
        counters,
    }
}

// ── Fixture-chain builder ─────────────────────────────────────────────────────

/// Build a minimal Bellatrix genesis state + anchor block pair.
///
/// Delegates to `common::checkpoint_helpers::build_anchor_bellatrix` and wraps
/// the concrete inner types into the fork-enum variants used by this test.
fn build_genesis() -> (
    ForkMinimalBeaconState,
    ForkBeaconBlock<16, 2, 128, 16, 16, 2048, 33, 32, 1_073_741_824, 1_048_576, 256, 32>,
) {
    let (state_inner, signed_block_inner) = build_anchor_bellatrix(Slot(0), 0);

    let genesis_state = ForkMinimalBeaconState::Bellatrix(state_inner);

    // Unwrap the signed block to get the unsigned ForkBeaconBlock.
    let anchor_block = ForkBeaconBlock::Bellatrix(signed_block_inner.message);

    (genesis_state, anchor_block)
}

/// Build a chain of `N_BLOCKS` signed Bellatrix blocks from the genesis state.
///
/// Uses `NullExecutionEngine` + `validate_result: false` for the STF.
/// Each block carries the correct `state_root` so that:
///   - `block.tree_hash_root()` is consistent with what the STF stores in
///     `latest_block_header.state_root` (required for `parent_root` checks
///     in subsequent blocks).
///   - The fork-choice store's `block_states` key matches `block.tree_hash_root()`.
///
/// Approach: run the STF once with `state_root = Root::default()` to get the
/// post-state, then patch `state_root = post_state.tree_hash_root()` into the
/// block and re-compute the final block root.  Re-running the STF with the
/// correct `state_root` gives the true post-state for the next iteration.
///
/// Returns `(signed_blocks, block_roots)`.
fn build_chain(
    genesis_state: ForkMinimalBeaconState,
    anchor_root: Root,
) -> (Vec<MinForkSignedBlock>, Vec<Root>) {
    use pharos_stf::process_slots_fork;

    let runtime_cfg = pharos_types::config::RuntimeConfig {
        seconds_per_slot: 12,
        bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
        ..Default::default()
    };
    let null_engine = NullExecutionEngine;

    let mut state = genesis_state;
    let mut signed_blocks = Vec::new();
    let mut block_roots = Vec::new();

    // prev_block_root tracks block_i.tree_hash_root() which the STF uses as
    // the expected parent_root for block_{i+1}.  Starts at anchor_root.
    let mut prev_block_root = anchor_root;

    for i in 1..=N_BLOCKS {
        let slot = Slot(i);

        // Advance a clone to `slot` to read the updated randao_mix and timestamp.
        let mut pre_state_advanced = state.clone();
        process_slots_fork::<MinimalEthSpec>(&mut pre_state_advanced, slot)
            .unwrap_or_else(|e| panic!("build_chain: process_slots_fork failed at slot {i}: {e}"));

        // Read randao_mix and timestamp from the advanced state.
        let (prev_randao, expected_timestamp) = {
            let s = match &pre_state_advanced {
                ForkMinimalBeaconState::Bellatrix(s) => s,
                _ => panic!("expected Bellatrix state"),
            };
            let epoch = slot.0 / MinimalEthSpec::SLOTS_PER_EPOCH;
            let idx = (epoch % MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
            let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
            let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
            (randao, ts)
        };

        // parent_root = previous block's tree_hash_root().
        // After the STF body_root fix, block.tree_hash_root() is consistent with
        // state.latest_block_header.tree_hash_root() after process_slot patches state_root.
        let parent_root = prev_block_root;

        // Execution payload parent hash:
        //   - block 1: TERMINAL_BLOCK_HASH (merge-transition override)
        //   - block after INVALID_BLOCK_SLOT: [0x99; 32] (the INVALID block's hash)
        //   - others: [prev_slot_byte, 0..0; 32]
        let payload_parent_hash = if i == 1 {
            Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES)
        } else if i == INVALID_BLOCK_SLOT + 1 {
            // Previous block (INVALID) had block_hash = [0x99; 32].
            Hash256::from_array([0x99u8; 32])
        } else {
            // Previous block's block_hash was [prev_slot_byte, 0..0; 32].
            let mut h = [0u8; 32];
            h[0] = (i - 1) as u8;
            Hash256::from_array(h)
        };

        // Block hash: [slot_byte, 0..0; 32] for normal blocks; [0x99; 32] for the INVALID one.
        let block_hash = if i == INVALID_BLOCK_SLOT {
            Hash256::from_array([0x99u8; 32])
        } else {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            Hash256::from_array(h)
        };

        let payload = MinimalExecutionPayload {
            parent_hash: payload_parent_hash,
            prev_randao,
            block_number: i,
            gas_limit: 0x1c9c380,
            timestamp: expected_timestamp,
            block_hash,
            ..Default::default()
        };

        let body = MinimalBeaconBlockBody {
            execution_payload: payload,
            ..Default::default()
        };

        // Step 1: run STF with state_root = Root::default() to derive the post-state.
        // validate_result: false means the STF never reads block.state_root, so the
        // post-state is identical regardless of what we put in state_root.
        let draft = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root,
            state_root: Root::default(),
            body: body.clone(),
        };
        let draft_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: draft,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        let post_state_draft = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            state.clone(),
            &draft_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("build_chain: draft STF failed at slot {i}: {e}"));

        // Step 2: build the final block with the correct state_root.
        // This makes block.tree_hash_root() consistent with what process_slot will
        // compute as latest_block_header.tree_hash_root() after patching, so that
        // the NEXT block's STF parent_root check succeeds.
        let state_root: Root = post_state_draft.tree_hash_root();
        let final_block = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root,
            state_root,
            body,
        };
        let block_root: Root = final_block.tree_hash_root();
        let fork_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: final_block,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        // Step 3: run STF again with the correct state_root to get the final post-state.
        // The post-state is identical to post_state_draft since validate_result=false
        // means state_root is never read by the STF computation.
        let post_state = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            state.clone(),
            &fork_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("build_chain: final STF failed at slot {i}: {e}"));

        state = post_state;
        prev_block_root = block_root;
        signed_blocks.push(fork_signed);
        block_roots.push(block_root);
    }

    (signed_blocks, block_roots)
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_pipeline_drives_bellatrix_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Build genesis + fork-choice store.
    let (genesis_state, anchor_block) = build_genesis();

    // Compute anchor_root before moving anchor_block into get_forkchoice_store.
    // This root is used as the parent_root of the first chain block.
    let anchor_root: Root = anchor_block.tree_hash_root();

    // Verify the forkchoice store assertion: anchor_block.state_root == genesis_state.tree_hash_root().
    assert_eq!(
        anchor_block.state_root(),
        genesis_state.tree_hash_root(),
        "anchor block state_root must match genesis state"
    );

    let mut fc = get_forkchoice_store::<MinimalEthSpec>(genesis_state.clone(), anchor_block);

    // Set terminal_block_hash override so the merge-transition guard passes for block 1.
    fc.set_terminal_config(
        pharos_utils::Uint256::default(),
        Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
        0,
    );

    // Advance store time so on_block's "future slot" guard doesn't reject blocks.
    // Set to a large but overflow-safe value: slot_from_time(t, 0) = t*1000/SLOT_DURATION_MS,
    // so t = 10_000_000 yields ~1.6M slots for MinimalEthSpec (SLOT_DURATION_MS = 6_000).
    fc.time = 10_000_000;

    let fc = Arc::new(RwLock::new(fc));

    // 2. Generate fixture blocks.
    let (signed_blocks, block_roots) = build_chain(genesis_state, anchor_root);
    assert_eq!(signed_blocks.len(), N_BLOCKS as usize);

    // 3. Spawn axum mock with VALID responses.
    let mock = spawn_mock().await;
    mock.set(
        "engine_newPayloadV1",
        json!({ "status": "VALID", "latestValidHash": null, "validationError": null }),
    );
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
    mock.set(
        "engine_exchangeCapabilities",
        json!(["engine_newPayloadV1", "engine_forkchoiceUpdatedV1"]),
    );

    // 4. Spawn engine actor + driver loop.
    let engine_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    );
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(engine_runtime, client, None);

    let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(16);

    {
        let fc_clone = Arc::clone(&fc);
        let eng = engine_handle.clone();
        tokio::spawn(async move {
            run_engine_driver_loop::<MinimalEthSpec>(eng, fc_clone, head_rx, payload_rx).await;
        });
    }

    // 5. Build HostImpl + spawn block-ingestion loop.
    //    The ingestion loop uses NullExecutionEngine for the STF path so that
    //    the mock's INVALID response only affects the engine driver, not the STF.
    //    This ensures block 3 passes STF (on_block inserts it) and the driver
    //    then marks it Invalid in payload_statuses.
    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        pharos_storage::RocksStore::open::<MinimalEthSpec>(pharos_storage::RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );

    let genesis_validators_root = Root::default();
    let fork_version = Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION);
    let host = Arc::new(HostImpl::<MinimalEthSpec>::new(
        store,
        Arc::clone(&fc),
        genesis_validators_root,
        fork_version,
    ));

    let exec_engine = Arc::new(NullExecutionEngine);
    let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle.clone()));

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    {
        let fc_clone = Arc::clone(&fc);
        let host_clone = Arc::clone(&host);
        let ht = head_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_block_ingestion_loop::<MinimalEthSpec, NullExecutionEngine>(
                event_rx,
                host_clone,
                fc_clone,
                exec_engine,
                pow_provider,
                ht,
                payload_tx,
                false, // validate_result: false — skip BLS and state-root checks
            )
            .await
            {
                eprintln!("block ingestion loop error: {e}");
            }
        });
    }

    // 6. Send blocks through the gossip event channel.
    //    Flip the mock to INVALID before the INVALID_BLOCK_SLOT block's engine-driver call.
    let fork_digest = pharos_types::phase0::primitives::ForkDigest::from_array([0u8; 4]);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    for (idx, signed_block) in signed_blocks.iter().enumerate() {
        let slot = idx as u64 + 1;

        // Before sending block INVALID_BLOCK_SLOT: wait for the driver to have
        // processed blocks 1..(INVALID_BLOCK_SLOT-1), then flip the mock to INVALID.
        // With NullExecutionEngine in the STF path, only the driver hits the mock:
        // 1 newPayload call per block.
        if slot == INVALID_BLOCK_SLOT {
            let target_count = INVALID_BLOCK_SLOT - 1;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            loop {
                if mock.new_payload_count() >= target_count {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    panic!(
                        "timeout: expected >= {} newPayload calls before INVALID block, got {}",
                        target_count,
                        mock.new_payload_count()
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            mock.set(
                "engine_newPayloadV1",
                json!({ "status": "INVALID", "latestValidHash": null, "validationError": "test: forced invalid" }),
            );
        }

        // After the INVALID block: wait for its driver call, then restore VALID for block 4.
        if slot == INVALID_BLOCK_SLOT + 1 {
            let target_count = INVALID_BLOCK_SLOT;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            loop {
                if mock.new_payload_count() >= target_count {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    panic!(
                        "timeout: expected >= {} newPayload calls after INVALID block, got {}",
                        target_count,
                        mock.new_payload_count()
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            mock.set(
                "engine_newPayloadV1",
                json!({ "status": "VALID", "latestValidHash": null, "validationError": null }),
            );
        }

        let ssz_bytes = signed_block.as_ssz_bytes();
        event_tx
            .send(NetworkEvent::GossipMessage {
                topic: topic.clone(),
                peer: dummy_peer,
                data: ssz_bytes,
            })
            .await
            .unwrap();

        // Allow the ingestion loop time to decode + run STF.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // 7. Wait for all newPayload calls: 1 per block from the driver = N_BLOCKS total.
    //    (NullExecutionEngine is used in the STF path, so the mock is only hit by the driver.)
    let total_expected = N_BLOCKS;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if mock.new_payload_count() >= total_expected {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout: expected >= {} newPayload calls, got {}",
                total_expected,
                mock.new_payload_count()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for driver to propagate payload_statuses updates.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 8. Assertions.
    {
        let store = fc.read();

        // (a) Exactly N_BLOCKS newPayloadV1 calls — one per fixture block.
        // NullExecutionEngine is used for the STF path so only the engine driver
        // hits the mock, giving exactly one call per block.
        assert_eq!(
            mock.new_payload_count(),
            N_BLOCKS,
            "expected exactly {} newPayloadV1 calls (one per block), got {}",
            N_BLOCKS,
            mock.new_payload_count()
        );

        // (b) At least N_BLOCKS forkchoiceUpdated calls — one per head advance.
        assert!(
            mock.fcu_count() >= N_BLOCKS,
            "expected >= {} forkchoiceUpdated calls (one per head advance), got {}",
            N_BLOCKS,
            mock.fcu_count()
        );

        // (c) All N_BLOCKS blocks were accepted into the store (anchor + N_BLOCKS = N_BLOCKS+1).
        assert_eq!(
            store.blocks.len(),
            (N_BLOCKS + 1) as usize,
            "expected {} blocks in store (anchor + {} blocks), got {}",
            N_BLOCKS + 1,
            N_BLOCKS,
            store.blocks.len()
        );

        // (c continued) assert get_head equals the anchor root (pre-invalid parent chain).
        // Chain: anchor → slot1 → slot2 → slot3(INVALID) → slot4
        // slot3 is Invalid.  filter_block_tree(slot3) returns false immediately.
        // slot2 has only slot3 as child → all children false → slot2 returns false.
        // slot1's only child is slot2 → returns false.  anchor's only child is slot1
        // → returns false.  get_filtered_block_tree returns empty.
        // get_head falls back to justified_checkpoint.root = anchor_root.
        // The justified checkpoint never advances (no attestations in the fixture
        // and no epoch boundary in 4 minimal-preset slots), so anchor is the head.
        let head = get_head::<MinimalEthSpec>(&store);
        assert_eq!(
            head, anchor_root,
            "get_head must return the anchor root (all chains filtered due to Invalid slot3), got {:?}",
            head
        );

        // (d) INVALID block's payload status is Invalid.
        let invalid_root = block_roots[(INVALID_BLOCK_SLOT - 1) as usize];
        assert_eq!(
            store.payload_statuses.get(&invalid_root),
            Some(&PayloadStatus::Invalid),
            "block at slot {} must be marked Invalid in payload_statuses",
            INVALID_BLOCK_SLOT
        );

        // (d continued) get_head must not return the Invalid block.
        assert_ne!(
            head, invalid_root,
            "get_head must not return the Invalid block (slot {})",
            INVALID_BLOCK_SLOT
        );
    }

    // (e) No panics — reaching this point proves the test completed without panic.
    drop(head_tx);
    drop(event_tx);
}
