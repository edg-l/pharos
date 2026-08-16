//! Block-production integration test.
//!
//! Exercises `produce_block` on a synthetic Capella head state with a mock EL,
//! then verifies the produced block is self-consistent (its `state_root` matches
//! what the STF produces for the same block). Feeds the produced block back
//! through the block-ingestion loop to exercise the full import round-trip and
//! catch any lock-ordering bugs.
//!
//! Per Task 4.7 (M9-Validator Phase 4).

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
use pharos_ssz::{Encode as _, SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::{
    DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, NullExecutionEngine, compute_signing_root, get_domain,
};
use pharos_types::altair::MinimalSyncCommittee;
use pharos_types::capella::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
};
use pharos_types::config::RuntimeConfig;
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinimalBeaconState,
    SignedBeaconBlock as ForkSignedBeaconBlock,
};
use pharos_types::views::BeaconBlockView as _;
use pharos_types::{EthSpec, MinimalEthSpec};
use pharos_utils::{BLSPubkey, BLSSignature, Epoch as UtilsEpoch};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, watch};

use pharos_node::block_ingestion::{IngestionEgress, run_block_ingestion_loop};
use pharos_node::block_production::produce_block;
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::host_impl::HostImpl;
use pharos_node::op_pools::OperationPools;
use pharos_node::pow_block::EnginePowBlockProvider;

mod common;

// ── Type aliases ──────────────────────────────────────────────────────────────

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
>;

// ── Mock Engine API server ────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct CallCounters {
    fcu_v2_with_attrs: u64,
    get_payload_v2: u64,
    new_payload_v2: u64,
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
            "engine_getPayloadV2" => ctr.get_payload_v2 += 1,
            "engine_forkchoiceUpdatedV2" => {
                if let Some(arr) = req.params.as_array() {
                    if arr.len() > 1 && !arr[1].is_null() {
                        ctr.fcu_v2_with_attrs += 1;
                    }
                }
            }
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
    fn fcu_v2_with_attrs_count(&self) -> u64 {
        self.counters.lock().fcu_v2_with_attrs
    }
    fn get_payload_v2_count(&self) -> u64 {
        self.counters.lock().get_payload_v2
    }
    #[allow(dead_code)]
    fn new_payload_v2_count(&self) -> u64 {
        self.counters.lock().new_payload_v2
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

fn test_secret_key() -> pharos_utils::bls::BLSSecretKey {
    pharos_utils::bls::BLSSecretKey::key_gen(&[1u8; 32]).expect("valid IKM")
}

fn test_pubkey() -> BLSPubkey {
    test_secret_key().to_pubkey()
}

// ── Anchor Capella state builder ──────────────────────────────────────────────

fn build_capella_anchor(slot: Slot) -> (MinimalBeaconState, MinimalSignedBeaconBlock) {
    let anchor_body = MinimalBeaconBlockBody::default();
    let anchor_body_root: Root = anchor_body.tree_hash_root();

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    let sync_committee = MinimalSyncCommittee {
        pubkeys: SszVector::from_vec(vec![
            test_pubkey();
            MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize
        ])
        .unwrap(),
        aggregate_pubkey: test_pubkey(),
    };

    let state_inner = MinimalBeaconState {
        slot,
        fork: Fork {
            previous_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
            current_version: Version::from_array(MinimalEthSpec::CAPELLA_FORK_VERSION),
            epoch: UtilsEpoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root: anchor_body_root,
        },
        validators: SszList::empty_tree().with_push(validator).unwrap(),
        balances: SszList::default()
            .with_push(Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE))
            .unwrap(),
        previous_epoch_participation: SszList::default().with_push(0u8).unwrap(),
        current_epoch_participation: SszList::default().with_push(0u8).unwrap(),
        inactivity_scores: SszList::default().with_push(0u64).unwrap(),
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

// ── Helper: build a HostImpl for the ingestion loop ──────────────────────────

/// Returns `(host, _tmpdir)`.  The caller MUST keep `_tmpdir` alive for the
/// duration of the test; dropping it deletes the RocksDB data directory.
fn build_host(
    fc_store: Arc<RwLock<pharos_fork_choice::Store<MinimalEthSpec>>>,
) -> (Arc<HostImpl<MinimalEthSpec>>, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        pharos_storage::RocksStore::open::<MinimalEthSpec>(pharos_storage::RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );
    // Capella-at-genesis schedule
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: UtilsEpoch(0),
        bellatrix_fork_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: UtilsEpoch(0),
        capella_fork_version: Version::from_array(MinimalEthSpec::CAPELLA_FORK_VERSION),
        capella_fork_epoch: UtilsEpoch(0),
        deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
        deneb_fork_epoch: UtilsEpoch(u64::MAX),
        genesis_validators_root: Root::default(),
    };
    let host = Arc::new(HostImpl::<MinimalEthSpec>::new(
        store,
        fc_store,
        Root::default(),
        fork_schedule,
        0,
        Arc::new(RuntimeConfig::default()),
    ));
    (host, tmpdir)
}

// ── produce_block state_root consistency test ─────────────────────────────────

/// Asserts that the `state_root` embedded in a produced block is self-consistent:
/// feeding the SAME block (with the embedded `state_root`) back through the
/// block-ingestion loop must result in the head advancing to slot 1.
///
/// Uses a mock EL that returns a fixed (empty) `ExecutionPayloadV2` for
/// `engine_getPayloadV2`. The mock returns `VALID` for `engine_newPayloadV2` and
/// `engine_forkchoiceUpdatedV2`.
///
/// Tests:
///   (a) `produce_block` returns `Ok(...)` without panicking.
///   (b) The produced block's embedded `state_root` equals `post_state.tree_hash_root()`.
///   (c) `engine_forkchoiceUpdatedV2` with attributes was called (payload prep).
///   (d) `engine_getPayloadV2` was called.
///   (e) The embedded `state_root` survives an SSZ encode/decode round-trip
///       (the wire form the ingestion loop receives carries the same root).
///   (f) The produced block can be fed through the block-ingestion loop and the
///       head advances.
///
/// NOTE: the ingestion import here runs with `validate_result = false`, so the
/// node does NOT re-verify the `state_root` or the (absent) proposer/RANDAO
/// signatures — the produced block is intentionally unsigned at this stage.
/// Production-time `state_root` self-consistency is covered by assertion (b);
/// full signed-import `state_root` re-verification (`validate_result = true`)
/// requires the proposer + RANDAO signing path (Phase 6/7) and is exercised
/// end-to-end by the Phase 8 devnet acceptance gate.
#[tokio::test]
async fn produce_block_state_root_consistent_capella() {
    const ANCHOR_SLOT: u64 = 0;
    const PRODUCE_SLOT: u64 = 1;

    // ── Set up mock EL ────────────────────────────────────────────────────────

    let mock = spawn_mock().await;

    let payload_id = "0x0000000000000001";
    mock.set(
        "engine_forkchoiceUpdatedV2",
        json!({
            "payloadStatus": {
                "status": "VALID",
                "latestValidHash": format!("0x{}", "0".repeat(64)),
                "validationError": null
            },
            "payloadId": payload_id
        }),
    );

    let empty_payload = json!({
        "executionPayload": {
            "parentHash": format!("0x{}", "0".repeat(64)),
            "feeRecipient": format!("0x{}", "0".repeat(40)),
            "stateRoot": format!("0x{}", "0".repeat(64)),
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "prevRandao": format!("0x{}", "0".repeat(64)),
            "blockNumber": "0x1",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            // timestamp = genesis_time(0) + slot(1) * seconds_per_slot(6) = 6
            "timestamp": "0x6",
            "extraData": "0x",
            "baseFeePerGas": "0x1",
            "blockHash": format!("0x{}", "0".repeat(64)),
            "transactions": [],
            "withdrawals": []
        },
        "blockValue": "0x0",
        "blobsBundle": null,
        "shouldOverrideBuilder": false
    });
    mock.set("engine_getPayloadV2", empty_payload);

    mock.set(
        "engine_newPayloadV2",
        json!({
            "status": "VALID",
            "latestValidHash": format!("0x{}", "0".repeat(64)),
            "validationError": null
        }),
    );

    // ── Build anchor state ────────────────────────────────────────────────────

    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        capella_fork_version: MinimalEthSpec::CAPELLA_FORK_VERSION,
        capella_fork_epoch: 0,
        ..Default::default()
    };

    let (anchor_state_inner, anchor_signed) = build_capella_anchor(Slot(ANCHOR_SLOT));
    let fork_anchor_state = ForkMinimalBeaconState::Capella(anchor_state_inner);
    // get_forkchoice_store takes an unsigned BeaconBlock (not signed).
    let fork_anchor_block = ForkBeaconBlock::<
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
    >::Capella(anchor_signed.message.clone());
    let anchor_root: Root = fork_anchor_block.tree_hash_root();

    let mut fc =
        get_forkchoice_store::<MinimalEthSpec>(fork_anchor_state.clone(), fork_anchor_block);

    // Advance store time past PRODUCE_SLOT so the future-slot guard passes.
    fc.time = MinimalEthSpec::SLOT_DURATION_MS * (PRODUCE_SLOT + 2);
    fc.runtime_cfg = runtime_cfg.clone();

    // Pre-seed anchor state so produce_block can clone it via block_states.
    fc.block_states
        .insert(anchor_root, fork_anchor_state.clone());

    let fc_store = Arc::new(RwLock::new(fc));

    // ── Spawn engine actor ────────────────────────────────────────────────────

    let engine_client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(engine_client, None);

    // ── Build OperationPools ──────────────────────────────────────────────────

    let pools: Arc<OperationPools<MinimalEthSpec>> = Arc::new(OperationPools::default());

    // ── Call produce_block in spawn_blocking ──────────────────────────────────

    let fc_store_clone = Arc::clone(&fc_store);
    let pools_clone = Arc::clone(&pools);
    let engine_clone = engine_handle.clone();
    let runtime_cfg_clone = runtime_cfg.clone();

    let produce_result = tokio::task::spawn_blocking(move || {
        produce_block::<MinimalEthSpec>(
            &fc_store_clone,
            &pools_clone,
            &engine_clone,
            Slot(PRODUCE_SLOT),
            BLSSignature::default(), // randao_reveal (not verified; verify_signatures=false)
            [0u8; 32],               // graffiti
            "0x0000000000000000000000000000000000000000".to_string(),
            &runtime_cfg_clone,
        )
    })
    .await
    .expect("spawn_blocking join")
    .expect("produce_block succeeded");

    let (signed_block, post_state, _exec_value) = produce_result;

    // ── Assert (b): state_root consistency ────────────────────────────────────
    // The fork-enum SignedBeaconBlock does not implement the generic message()
    // method; match on the Capella variant explicitly.

    let embedded_state_root = match &signed_block {
        MinForkSignedBlock::Capella(inner) => inner.message.state_root,
        _ => panic!("produced block must be Capella variant for state_root check"),
    };
    let computed_state_root: Root = post_state.tree_hash_root();
    assert_eq!(
        embedded_state_root, computed_state_root,
        "produced block state_root must equal post_state.tree_hash_root()"
    );

    // ── Assert (c)+(d): engine calls ──────────────────────────────────────────

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        mock.fcu_v2_with_attrs_count() >= 1,
        "expected engine_forkchoiceUpdatedV2 with payload attributes"
    );
    assert!(
        mock.get_payload_v2_count() >= 1,
        "expected engine_getPayloadV2 call"
    );

    // ── Assert (e): block re-imports via block-ingestion loop ─────────────────
    // Exercise the concurrent produce+import path to surface lock-ordering bugs.

    let (head_tx, head_rx) = watch::channel(None::<HeadChange>);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(8);

    let (host, _tmpdir) = build_host(Arc::clone(&fc_store));

    // Spawn engine driver loop (drives newPayload from the payload_tx channel).
    let fc_store_drv = Arc::clone(&fc_store);
    let head_tx_clone = head_tx.clone();
    tokio::spawn(async move {
        run_engine_driver_loop::<MinimalEthSpec, pharos_fork_choice::NoopPowBlockProvider>(
            engine_handle,
            fc_store_drv,
            head_rx,
            payload_rx,
            head_tx_clone,
            Arc::new(pharos_fork_choice::NoopPowBlockProvider),
        )
        .await;
    });

    // Build ingestion loop infrastructure.
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);
    let (reinject_tx, reinject_rx) = mpsc::channel(8);
    let (dummy_net_tx, _dummy_net_rx) = tokio::sync::mpsc::channel(1);
    let dummy_net = pharos_network::NetworkCommandSender::new(dummy_net_tx);
    let egress = IngestionEgress {
        head_tx: head_tx.clone(),
        payload_tx,
        network: dummy_net,
        notify_backfill: Arc::new(Notify::new()),
        lookup_tx: tokio::sync::mpsc::channel(1).0,
        reinject_tx,
    };
    let fc_store_ing = Arc::clone(&fc_store);
    let exec_engine = Arc::new(NullExecutionEngine);
    // Build a second engine handle for the pow_provider (unused for Capella).
    let pow_engine_client = EngineClient::new(
        "http://127.0.0.1:1/".parse().unwrap(),
        JwtSecret::from_bytes([0u8; 32]),
    )
    .unwrap();
    let pow_engine_handle = spawn_engine_actor(pow_engine_client, None);
    let pow_provider = Arc::new(EnginePowBlockProvider::new(pow_engine_handle));

    // Clone host before moving into the ingestion loop closure so we can
    // still call fork_digest_for on the original after spawn.
    let host_for_digest = Arc::clone(&host);

    let join = tokio::spawn(async move {
        use pharos_node::data_availability::{BlobAwaitingBlocks, NoopDataAvailabilityChecker};
        let _ = run_block_ingestion_loop::<
            MinimalEthSpec,
            NullExecutionEngine,
            NoopDataAvailabilityChecker,
        >(
            event_rx,
            reinject_rx,
            host,
            fc_store_ing,
            exec_engine,
            pow_provider,
            egress,
            false, // validate_result: false — skip BLS and state-root checks
            Arc::new(NoopDataAvailabilityChecker),
            Arc::new(BlobAwaitingBlocks::new()),
            None,
        )
        .await;
    });

    // Encode the inner Capella signed block as raw SSZ (no fork-enum discriminant).
    let block_ssz = match &signed_block {
        MinForkSignedBlock::Capella(inner) => inner.as_ssz_bytes(),
        _ => panic!("produced block must be Capella variant"),
    };

    // Assert (e): the embedded state_root survives the SSZ wire round-trip the
    // ingestion loop decodes from — a corrupted-on-encode root would be caught
    // here independently of the in-memory `post_state`.
    {
        use pharos_ssz::Decode as _;
        let decoded = MinimalSignedBeaconBlock::from_ssz_bytes(&block_ssz)
            .expect("produced capella block must SSZ-decode");
        assert_eq!(
            decoded.message.state_root, embedded_state_root,
            "state_root must survive SSZ encode/decode"
        );
    }

    // Get the Capella fork digest from the host.
    let fork_digest = host_for_digest.fork_digest_for(NetworkFork::Capella);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    event_tx
        .send(NetworkEvent::GossipMessage {
            topic,
            peer: dummy_peer,
            data: block_ssz,
        })
        .await
        .expect("send block gossip event");

    // Wait for the head to advance.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let head = get_head::<MinimalEthSpec>(&fc_store.read());
        if head != anchor_root {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("head did not advance past anchor within 5 s");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Assert head is now at slot 1.
    let head = get_head::<MinimalEthSpec>(&fc_store.read());
    let head_slot = fc_store
        .read()
        .blocks
        .get(&head)
        .map(|b| b.slot())
        .expect("head block in store");
    assert_eq!(
        head_slot,
        Slot(PRODUCE_SLOT),
        "head slot after import must be produce_slot"
    );

    drop(event_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// Verify that concurrent `produce_block` calls do not deadlock or panic.
///
/// Exercises the lock-ordering constraint: `produce_block` takes the fc_store
/// read lock, drops it, then calls the engine. Concurrent calls should not
/// deadlock because no lock is held across the engine call.
#[tokio::test]
async fn produce_block_concurrent_no_deadlock() {
    const ANCHOR_SLOT: u64 = 0;

    let mock = spawn_mock().await;
    let payload_id = "0x0000000000000002";
    mock.set(
        "engine_forkchoiceUpdatedV2",
        json!({
            "payloadStatus": {
                "status": "VALID",
                "latestValidHash": format!("0x{}", "0".repeat(64)),
                "validationError": null
            },
            "payloadId": payload_id
        }),
    );
    let empty_payload = json!({
        "executionPayload": {
            "parentHash": format!("0x{}", "0".repeat(64)),
            "feeRecipient": format!("0x{}", "0".repeat(40)),
            "stateRoot": format!("0x{}", "0".repeat(64)),
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "prevRandao": format!("0x{}", "0".repeat(64)),
            "blockNumber": "0x2",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            // timestamp = genesis_time(0) + slot(1) * seconds_per_slot(6) = 6
            "timestamp": "0x6",
            "extraData": "0x",
            "baseFeePerGas": "0x1",
            "blockHash": format!("0x{}", "0".repeat(64)),
            "transactions": [],
            "withdrawals": []
        },
        "blockValue": "0x0",
        "blobsBundle": null,
        "shouldOverrideBuilder": false
    });
    mock.set("engine_getPayloadV2", empty_payload);

    mock.set(
        "engine_newPayloadV2",
        json!({
            "status": "VALID",
            "latestValidHash": format!("0x{}", "0".repeat(64)),
            "validationError": null
        }),
    );

    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        capella_fork_version: MinimalEthSpec::CAPELLA_FORK_VERSION,
        capella_fork_epoch: 0,
        ..Default::default()
    };

    let (anchor_state_inner, anchor_signed) = build_capella_anchor(Slot(ANCHOR_SLOT));
    let fork_anchor_state = ForkMinimalBeaconState::Capella(anchor_state_inner);
    let fork_anchor_block = ForkBeaconBlock::<
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
    >::Capella(anchor_signed.message.clone());
    let anchor_root: Root = fork_anchor_block.tree_hash_root();

    let mut fc =
        get_forkchoice_store::<MinimalEthSpec>(fork_anchor_state.clone(), fork_anchor_block);
    fc.time = MinimalEthSpec::SLOT_DURATION_MS * 2;
    fc.runtime_cfg = runtime_cfg.clone();
    fc.block_states
        .insert(anchor_root, fork_anchor_state.clone());

    let fc_store = Arc::new(RwLock::new(fc));

    let pools: Arc<OperationPools<MinimalEthSpec>> = Arc::new(OperationPools::default());
    let engine_client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(engine_client, None);

    // Spawn two concurrent produce_block calls.
    let h1 = {
        let fc = Arc::clone(&fc_store);
        let p = Arc::clone(&pools);
        let e = engine_handle.clone();
        let r = runtime_cfg.clone();
        tokio::task::spawn_blocking(move || {
            produce_block::<MinimalEthSpec>(
                &fc,
                &p,
                &e,
                Slot(1),
                BLSSignature::default(),
                [0u8; 32],
                "0x0000000000000000000000000000000000000000".to_string(),
                &r,
            )
        })
    };
    let h2 = {
        let fc = Arc::clone(&fc_store);
        let p = Arc::clone(&pools);
        let e = engine_handle.clone();
        let r = runtime_cfg.clone();
        tokio::task::spawn_blocking(move || {
            produce_block::<MinimalEthSpec>(
                &fc,
                &p,
                &e,
                Slot(1),
                BLSSignature::default(),
                [0u8; 32],
                "0x0000000000000000000000000000000000000000".to_string(),
                &r,
            )
        })
    };

    // Both must complete without deadlock within 10 seconds.
    let (r1, r2) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(h1, h2) })
        .await
        .expect("no deadlock: both produce_block calls completed within 10 s");

    r1.expect("spawn_blocking join 1")
        .expect("concurrent produce_block 1 must not return an error");
    r2.expect("spawn_blocking join 2")
        .expect("concurrent produce_block 2 must not return an error");
}

/// Task 8.6b: a produced block, signed with a real proposer + RANDAO signature,
/// re-imports through the ingestion loop with `validate_result = true`.
///
/// This is the end-to-end self-verification the Phase 4 `block_production` test
/// could not cover (it imports unsigned blocks with `validate_result = false`).
/// With `validate_result = true` the node re-runs, during import:
///   - the proposer block-signature check (`DOMAIN_BEACON_PROPOSER`),
///   - the RANDAO reveal check (`DOMAIN_RANDAO`),
///   - `process_block` with `verify_signatures = true` (incl. the empty
///     sync-aggregate G2-infinity check),
///   - the `state_root` re-computation,
/// all against the same block this node produced. Head must advance to the
/// produced slot, proving the produced block is self-consistent under full
/// verification.
#[tokio::test]
async fn produce_block_signed_reimports_validated_capella() {
    const ANCHOR_SLOT: u64 = 0;
    const PRODUCE_SLOT: u64 = 1;

    // ── Mock EL ───────────────────────────────────────────────────────────────
    let mock = spawn_mock().await;
    mock.set(
        "engine_forkchoiceUpdatedV2",
        json!({
            "payloadStatus": {
                "status": "VALID",
                "latestValidHash": format!("0x{}", "0".repeat(64)),
                "validationError": null
            },
            "payloadId": "0x0000000000000003"
        }),
    );
    mock.set(
        "engine_getPayloadV2",
        json!({
            "executionPayload": {
                "parentHash": format!("0x{}", "0".repeat(64)),
                "feeRecipient": format!("0x{}", "0".repeat(40)),
                "stateRoot": format!("0x{}", "0".repeat(64)),
                "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                "logsBloom": format!("0x{}", "0".repeat(512)),
                "prevRandao": format!("0x{}", "0".repeat(64)),
                "blockNumber": "0x1",
                "gasLimit": "0x1c9c380",
                "gasUsed": "0x0",
                "timestamp": "0x6",
                "extraData": "0x",
                "baseFeePerGas": "0x1",
                "blockHash": format!("0x{}", "0".repeat(64)),
                "transactions": [],
                "withdrawals": []
            },
            "blockValue": "0x0",
            "blobsBundle": null,
            "shouldOverrideBuilder": false
        }),
    );
    mock.set(
        "engine_newPayloadV2",
        json!({
            "status": "VALID",
            "latestValidHash": format!("0x{}", "0".repeat(64)),
            "validationError": null
        }),
    );

    // ── Anchor state ──────────────────────────────────────────────────────────
    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        capella_fork_version: MinimalEthSpec::CAPELLA_FORK_VERSION,
        capella_fork_epoch: 0,
        ..Default::default()
    };

    let (anchor_state_inner, anchor_signed) = build_capella_anchor(Slot(ANCHOR_SLOT));
    let fork_anchor_state = ForkMinimalBeaconState::Capella(anchor_state_inner);
    let fork_anchor_block = ForkBeaconBlock::<
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
    >::Capella(anchor_signed.message.clone());
    let anchor_root: Root = fork_anchor_block.tree_hash_root();

    let mut fc =
        get_forkchoice_store::<MinimalEthSpec>(fork_anchor_state.clone(), fork_anchor_block);
    fc.time = MinimalEthSpec::SLOT_DURATION_MS * (PRODUCE_SLOT + 2);
    fc.runtime_cfg = runtime_cfg.clone();
    fc.block_states
        .insert(anchor_root, fork_anchor_state.clone());
    let fc_store = Arc::new(RwLock::new(fc));

    let engine_client = EngineClient::new(mock.url.clone(), mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(engine_client, None);
    let pools: Arc<OperationPools<MinimalEthSpec>> = Arc::new(OperationPools::default());

    // ── Sign the RANDAO reveal with the proposer's real key ───────────────────
    // The single validator (index 0) has pubkey == test_pubkey() == sk.to_pubkey().
    let sk = test_secret_key();
    let epoch = UtilsEpoch(PRODUCE_SLOT / MinimalEthSpec::SLOTS_PER_EPOCH);
    let randao_domain =
        get_domain::<MinimalEthSpec>(&fork_anchor_state, DOMAIN_RANDAO, Some(epoch));
    let randao_signing_root = compute_signing_root(&epoch, randao_domain);
    let randao_reveal = sk.sign(randao_signing_root.as_slice());

    // ── Produce the block with the real RANDAO reveal ─────────────────────────
    let produce_result = tokio::task::spawn_blocking({
        let fc = Arc::clone(&fc_store);
        let p = Arc::clone(&pools);
        let e = engine_handle.clone();
        let r = runtime_cfg.clone();
        move || {
            produce_block::<MinimalEthSpec>(
                &fc,
                &p,
                &e,
                Slot(PRODUCE_SLOT),
                randao_reveal,
                [0u8; 32],
                "0x0000000000000000000000000000000000000000".to_string(),
                &r,
            )
        }
    })
    .await
    .expect("spawn_blocking join")
    .expect("produce_block succeeded");
    let (signed_block, _post_state, _exec_value) = produce_result;

    let inner = match &signed_block {
        MinForkSignedBlock::Capella(i) => i.clone(),
        _ => panic!("produced block must be Capella variant"),
    };

    // ── Sign the produced block as proposer ───────────────────────────────────
    let proposer_domain =
        get_domain::<MinimalEthSpec>(&fork_anchor_state, DOMAIN_BEACON_PROPOSER, Some(epoch));
    let block_signing_root = compute_signing_root(&inner.message, proposer_domain);
    let block_sig = sk.sign(block_signing_root.as_slice());

    // Sanity: the signature must verify locally before we feed it to the node.
    assert!(
        pharos_utils::bls::verify(&test_pubkey(), block_signing_root.as_slice(), &block_sig)
            .unwrap_or(false),
        "locally-produced proposer signature must verify"
    );

    let signed = MinimalSignedBeaconBlock {
        message: inner.message.clone(),
        signature: block_sig,
    };
    let block_ssz = signed.as_ssz_bytes();

    // ── Ingestion loop with validate_result = TRUE ────────────────────────────
    let (head_tx, head_rx) = watch::channel(None::<HeadChange>);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(8);
    let (host, _tmpdir) = build_host(Arc::clone(&fc_store));

    let fc_store_drv = Arc::clone(&fc_store);
    let head_tx_clone = head_tx.clone();
    tokio::spawn(async move {
        run_engine_driver_loop::<MinimalEthSpec, pharos_fork_choice::NoopPowBlockProvider>(
            engine_handle,
            fc_store_drv,
            head_rx,
            payload_rx,
            head_tx_clone,
            Arc::new(pharos_fork_choice::NoopPowBlockProvider),
        )
        .await;
    });

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);
    let (reinject_tx, reinject_rx) = mpsc::channel(8);
    let (dummy_net_tx, _dummy_net_rx) = tokio::sync::mpsc::channel(1);
    let dummy_net = pharos_network::NetworkCommandSender::new(dummy_net_tx);
    let egress = IngestionEgress {
        head_tx: head_tx.clone(),
        payload_tx,
        network: dummy_net,
        notify_backfill: Arc::new(Notify::new()),
        lookup_tx: tokio::sync::mpsc::channel(1).0,
        reinject_tx,
    };
    let fc_store_ing = Arc::clone(&fc_store);
    let exec_engine = Arc::new(NullExecutionEngine);
    let pow_engine_client = EngineClient::new(
        "http://127.0.0.1:1/".parse().unwrap(),
        JwtSecret::from_bytes([0u8; 32]),
    )
    .unwrap();
    let pow_engine_handle = spawn_engine_actor(pow_engine_client, None);
    let pow_provider = Arc::new(EnginePowBlockProvider::new(pow_engine_handle));
    let host_for_digest = Arc::clone(&host);

    let join = tokio::spawn(async move {
        use pharos_node::data_availability::{BlobAwaitingBlocks, NoopDataAvailabilityChecker};
        let _ = run_block_ingestion_loop::<
            MinimalEthSpec,
            NullExecutionEngine,
            NoopDataAvailabilityChecker,
        >(
            event_rx,
            reinject_rx,
            host,
            fc_store_ing,
            exec_engine,
            pow_provider,
            egress,
            true, // validate_result: TRUE — full BLS + state-root re-verification
            Arc::new(NoopDataAvailabilityChecker),
            Arc::new(BlobAwaitingBlocks::new()),
            None,
        )
        .await;
    });

    let fork_digest = host_for_digest.fork_digest_for(NetworkFork::Capella);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    event_tx
        .send(NetworkEvent::GossipMessage {
            topic,
            peer: libp2p::PeerId::random(),
            data: block_ssz,
        })
        .await
        .expect("send block gossip event");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if get_head::<MinimalEthSpec>(&fc_store.read()) != anchor_root {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("head did not advance past anchor within 5 s (validated import failed)");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let head = get_head::<MinimalEthSpec>(&fc_store.read());
    let head_slot = fc_store
        .read()
        .blocks
        .get(&head)
        .map(|b| b.slot())
        .expect("head block in store");
    assert_eq!(
        head_slot,
        Slot(PRODUCE_SLOT),
        "head slot after validated import must be produce_slot"
    );

    drop(event_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}
