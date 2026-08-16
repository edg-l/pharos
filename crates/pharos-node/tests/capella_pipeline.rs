//! Capella pipeline integration test.
//!
//! Drives a chain of Capella blocks through:
//!   block_ingestion_loop → STF → pharos_fork_choice::on_block
//!     → HeadChange watch → engine driver → axum mock
//!
//! Asserts:
//!   (a) `engine_newPayloadV2` called at least once (capella head triggers V2 dispatch).
//!   (b) `engine_forkchoiceUpdatedV2` called at least once.
//!   (c) Head advances past the anchor slot.
//!   (d) No panics, no timeout failures.
//!
//! Uses `NullExecutionEngine` + `validate_result: false` so the mock only needs
//! to handle V2 calls from the engine driver; the STF path does not hit the mock.

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
use pharos_network::host::ForkContext as _;
use pharos_network::network::NetworkEvent;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::Fork as NetworkFork;
use pharos_ssz::{Encode, SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::{NullExecutionEngine, state_transition};
use pharos_types::altair::{MinimalSyncAggregate, MinimalSyncCommittee};
use pharos_types::capella::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayload,
};
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    MinimalBeaconState as ForkMinimalBeaconState, SignedBeaconBlock as ForkSignedBeaconBlock,
};
use pharos_types::views::BeaconBlockView as _;
use pharos_types::{BeaconSpec, MinimalBeaconSpec};
use pharos_utils::{BLSPubkey, BLSSignature, Epoch as UtilsEpoch, Hash256};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use pharos_node::block_ingestion::{IngestionEgress, run_block_ingestion_loop};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::host_impl::HostImpl;
use pharos_node::pow_block::EnginePowBlockProvider;

mod common;

// ── Type alias ────────────────────────────────────────────────────────────────

type MinForkSignedBlock = ForkSignedBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;

// ── Fixture constants ─────────────────────────────────────────────────────────

const N_BLOCKS: u64 = 3;

// ── Mock Engine API server ────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct CallCounters {
    new_payload_v2: u64,
    fcu_v2: u64,
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
            "engine_newPayloadV2" => ctr.new_payload_v2 += 1,
            "engine_forkchoiceUpdatedV2" => ctr.fcu_v2 += 1,
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
    fn new_payload_v2_count(&self) -> u64 {
        self.counters.lock().new_payload_v2
    }
    fn fcu_v2_count(&self) -> u64 {
        self.counters.lock().fcu_v2
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

// ── BLS test key ──────────────────────────────────────────────────────────────

fn test_pubkey() -> BLSPubkey {
    let sk = blst::min_pk::SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM");
    BLSPubkey::from_array(sk.sk_to_pk().compress())
}

// ── Anchor builder ────────────────────────────────────────────────────────────

/// Build a Capella genesis state + anchor block for the minimal preset.
///
/// The genesis state has one active validator so the STF can find a proposer.
/// Capella-at-genesis: `state.fork.current_version` = capella fork version.
fn build_capella_anchor(
    slot: Slot,
    genesis_time: u64,
) -> (MinimalBeaconState, MinimalSignedBeaconBlock) {
    let anchor_body = MinimalBeaconBlockBody::default();
    let anchor_body_root: Root = anchor_body.tree_hash_root();

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    let sync_committee = MinimalSyncCommittee {
        pubkeys: SszVector::from_vec(vec![
            test_pubkey();
            MinimalBeaconSpec::SYNC_COMMITTEE_SIZE as usize
        ])
        .unwrap(),
        aggregate_pubkey: test_pubkey(),
    };

    let state_inner = MinimalBeaconState {
        genesis_time,
        slot,
        fork: Fork {
            previous_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
            current_version: Version::from_array(MinimalBeaconSpec::CAPELLA_FORK_VERSION),
            epoch: UtilsEpoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(), // zeroed per spec (process_block_header)
            body_root: anchor_body_root,
        },
        validators: SszList::empty_tree().with_push(validator).unwrap(),
        balances: SszList::with_push(
            &SszList::default(),
            Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
        )
        .unwrap(),
        previous_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
        current_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
        inactivity_scores: SszList::with_push(&SszList::default(), 0u64).unwrap(),
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        ..MinimalBeaconState::default()
    };

    let fork_state = ForkMinimalBeaconState::Capella(state_inner.clone());
    let computed_state_root: Root = fork_state.tree_hash_root();

    let anchor_block = MinimalSignedBeaconBlock {
        message: MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: computed_state_root,
            body: anchor_body,
        },
        signature: BLSSignature::from_array([0u8; 96]),
    };

    (state_inner, anchor_block)
}

// ── Chain builder ─────────────────────────────────────────────────────────────

/// Build `N_BLOCKS` capella blocks from the capella genesis state.
///
/// Uses `NullExecutionEngine` + `validate_result: false` so the STF never
/// hits the mock — only the engine driver triggers V2 calls.
fn build_capella_chain(
    genesis_state: ForkMinimalBeaconState,
    anchor_root: Root,
) -> (Vec<MinForkSignedBlock>, Vec<Root>) {
    use pharos_stf::process_slots_fork;

    // The ingestion loop uses `RuntimeConfig::default()` which is mainnet (12 s/slot).
    // The chain builder must match so that `timestamp` and `seconds_per_slot` agree.
    let runtime_cfg = pharos_types::config::RuntimeConfig {
        capella_fork_version: MinimalBeaconSpec::CAPELLA_FORK_VERSION,
        capella_fork_epoch: 0,
        ..Default::default()
    };
    let null_engine = NullExecutionEngine;

    let mut state = genesis_state;
    let mut signed_blocks = Vec::new();
    let mut block_roots = Vec::new();
    let mut prev_block_root = anchor_root;

    for i in 1..=N_BLOCKS {
        let slot = Slot(i);

        // Advance a clone to `slot` to derive randao_mix and timestamp.
        let mut pre_state_advanced = state.clone();
        process_slots_fork::<MinimalBeaconSpec>(
            &mut pre_state_advanced,
            slot,
            pharos_stf::ForkEpochs::never(),
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("build_capella_chain: process_slots_fork at slot {i}: {e}"));

        let (prev_randao, expected_timestamp) = {
            let s = match &pre_state_advanced {
                ForkMinimalBeaconState::Capella(s) => s,
                other => panic!("expected Capella state, got {other:?}"),
            };
            let epoch = slot.0 / MinimalBeaconSpec::SLOTS_PER_EPOCH;
            let idx = (epoch % MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
            let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
            let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
            (randao, ts)
        };

        // Payload parent hash:
        //   - block 1: Hash256::default() (genesis capella state has zeroed execution
        //     payload header; no merge-transition guard in capella process_execution_payload).
        //   - subsequent blocks: previous block's block_hash ([prev_slot_byte, 0...; 32]).
        let payload_parent_hash = if i == 1 {
            Hash256::default()
        } else {
            let mut h = [0u8; 32];
            h[0] = (i - 1) as u8;
            Hash256::from_array(h)
        };
        let mut bh = [0u8; 32];
        bh[0] = i as u8;
        let block_hash = Hash256::from_array(bh);

        let payload = MinimalExecutionPayload {
            parent_hash: payload_parent_hash,
            prev_randao,
            block_number: i,
            gas_limit: 0x1c9c380,
            timestamp: expected_timestamp,
            block_hash,
            ..Default::default()
        };

        // Empty sync aggregate: G2_POINT_AT_INFINITY for zero participants.
        const G2_INFINITY: [u8; 96] = {
            let mut b = [0u8; 96];
            b[0] = 0xc0;
            b
        };
        let sync_aggregate = MinimalSyncAggregate {
            sync_committee_signature: BLSSignature::from_array(G2_INFINITY),
            ..Default::default()
        };

        let body = MinimalBeaconBlockBody {
            execution_payload: payload,
            sync_aggregate,
            ..Default::default()
        };

        // Draft pass (state_root = default) to get post-state.
        let draft = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: prev_block_root,
            state_root: Root::default(),
            body: body.clone(),
        };
        let draft_signed = MinForkSignedBlock::Capella(MinimalSignedBeaconBlock {
            message: draft,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        let (post_state_draft, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
            state.clone(),
            &draft_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("build_capella_chain: draft STF at slot {i}: {e}"));

        // Final block with correct state_root.
        let state_root: Root = post_state_draft.tree_hash_root();
        let final_block = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: prev_block_root,
            state_root,
            body,
        };
        let block_root: Root = final_block.tree_hash_root();
        let fork_signed = MinForkSignedBlock::Capella(MinimalSignedBeaconBlock {
            message: final_block,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        // Final STF pass with correct state_root.
        let (post_state, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
            state.clone(),
            &fork_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| panic!("build_capella_chain: final STF at slot {i}: {e}"));

        state = post_state;
        prev_block_root = block_root;
        signed_blocks.push(fork_signed);
        block_roots.push(block_root);
    }

    (signed_blocks, block_roots)
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capella_pipeline_drives_v2_engine_calls() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Build capella genesis + fork-choice store.
    let (state_inner, anchor_signed) = build_capella_anchor(Slot(0), 0);
    let genesis_state = ForkMinimalBeaconState::Capella(state_inner);
    let anchor_block = pharos_types::state::BeaconBlock::Capella(anchor_signed.message.clone());

    let anchor_root: Root = anchor_block.tree_hash_root();

    assert_eq!(
        anchor_block.state_root(),
        genesis_state.tree_hash_root(),
        "anchor block state_root must match genesis state"
    );

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(genesis_state.clone(), anchor_block);

    // Advance store time so on_block's future-slot guard passes.
    fc.time = 10_000_000;

    let fc = Arc::new(RwLock::new(fc));

    // 2. Generate capella fixture blocks.
    let (signed_blocks, block_roots) = build_capella_chain(genesis_state, anchor_root);
    assert_eq!(signed_blocks.len(), N_BLOCKS as usize);

    // 3. Spawn axum mock with VALID V2 responses.
    let mock = spawn_mock().await;
    mock.set(
        "engine_newPayloadV2",
        json!({ "status": "VALID", "latestValidHash": null, "validationError": null }),
    );
    mock.set(
        "engine_forkchoiceUpdatedV2",
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
        json!(["engine_newPayloadV2", "engine_forkchoiceUpdatedV2"]),
    );

    // 4. Spawn engine actor + driver loop.
    let client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(client, None);

    let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
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

    // 5. Build HostImpl + spawn block-ingestion loop.
    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        pharos_storage::RocksStore::open::<MinimalBeaconSpec>(pharos_storage::RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );

    let genesis_validators_root = Root::default();

    // Capella-at-genesis schedule: all four epochs = 0 (immediate capella from slot 0).
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalBeaconSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalBeaconSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: UtilsEpoch(0),
        bellatrix_fork_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: UtilsEpoch(0),
        capella_fork_version: Version::from_array(MinimalBeaconSpec::CAPELLA_FORK_VERSION),
        capella_fork_epoch: UtilsEpoch(0),
        deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
        deneb_fork_epoch: UtilsEpoch(u64::MAX),
        electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
        electra_fork_epoch: UtilsEpoch(u64::MAX),
        fulu_fork_version: Version::from_array([0x06, 0x00, 0x00, 0x00]),
        fulu_fork_epoch: UtilsEpoch(u64::MAX),
        blob_schedule: Vec::new(),
        genesis_validators_root,
    };

    let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
        store,
        Arc::clone(&fc),
        genesis_validators_root,
        fork_schedule,
        0,
        Arc::new(pharos_types::RuntimeConfig {
            capella_fork_version: MinimalBeaconSpec::CAPELLA_FORK_VERSION,
            capella_fork_epoch: 0,
            ..Default::default()
        }),
    ));

    let exec_engine = Arc::new(NullExecutionEngine);
    let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle.clone()));

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    {
        let fc_clone = Arc::clone(&fc);
        let host_clone = Arc::clone(&host);
        let (dummy_net_tx, _dummy_net_rx) = tokio::sync::mpsc::channel(1);
        let dummy_net = pharos_network::NetworkCommandSender::new(dummy_net_tx);
        let ingestion_egress = IngestionEgress {
            head_tx: head_tx.clone(),
            payload_tx,
            network: dummy_net,
            notify_backfill: std::sync::Arc::new(tokio::sync::Notify::new()),
            lookup_tx: tokio::sync::mpsc::channel(1).0,
            reinject_tx: tokio::sync::mpsc::channel(1).0,
        };
        tokio::spawn(async move {
            use pharos_node::data_availability::{BlobAwaitingBlocks, NoopDataAvailabilityChecker};
            if let Err(e) = run_block_ingestion_loop::<
                MinimalBeaconSpec,
                NullExecutionEngine,
                NoopDataAvailabilityChecker,
            >(
                event_rx,
                tokio::sync::mpsc::channel(1).1,
                host_clone,
                fc_clone,
                exec_engine,
                pow_provider,
                ingestion_egress,
                false, // validate_result: false — skip BLS and state-root checks
                Arc::new(NoopDataAvailabilityChecker),
                Arc::new(BlobAwaitingBlocks::new()),
                None,
                None,
                None,
            )
            .await
            {
                eprintln!("block ingestion loop error: {e}");
            }
        });
    }

    // 6. Send blocks through the gossip event channel using the capella fork digest.
    let capella_fork_digest = host.fork_digest_for(NetworkFork::Capella);
    let topic = GossipTopic {
        fork_digest: capella_fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    for signed_block in &signed_blocks {
        // Encode the inner capella block directly (raw per-fork SSZ, no discriminant).
        let ssz_bytes = match signed_block {
            MinForkSignedBlock::Capella(inner) => inner.as_ssz_bytes(),
            _ => unreachable!("build_capella_chain always yields Capella blocks"),
        };
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

    // 7. Wait for V2 calls: 1 per block from the driver = N_BLOCKS total.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if mock.new_payload_v2_count() >= N_BLOCKS {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout: expected >= {} engine_newPayloadV2 calls, got {}",
                N_BLOCKS,
                mock.new_payload_v2_count()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // 8. Assertions.
    {
        let store = fc.read();

        // (a) At least N_BLOCKS engine_newPayloadV2 calls — one per capella block.
        assert!(
            mock.new_payload_v2_count() >= N_BLOCKS,
            "expected >= {} engine_newPayloadV2 calls, got {}",
            N_BLOCKS,
            mock.new_payload_v2_count()
        );

        // (b) At least one engine_forkchoiceUpdatedV2 call (head is capella).
        assert!(
            mock.fcu_v2_count() >= 1,
            "expected >= 1 engine_forkchoiceUpdatedV2 call, got {}",
            mock.fcu_v2_count()
        );

        // (c) All N_BLOCKS blocks are in the store (anchor + N_BLOCKS).
        assert_eq!(
            store.blocks.len(),
            (N_BLOCKS + 1) as usize,
            "expected {} blocks in store (anchor + {} capella blocks), got {}",
            N_BLOCKS + 1,
            N_BLOCKS,
            store.blocks.len()
        );

        // (c continued) Head advanced past the anchor slot.
        let head = get_head::<MinimalBeaconSpec>(&store);
        let last_block_root = *block_roots.last().unwrap();
        assert_eq!(
            head, last_block_root,
            "head should be the last capella block, got {:?}",
            head
        );
    }

    // (d) No panics — reaching this point proves the test completed without panic.
    drop(head_tx);
    drop(event_tx);
}
