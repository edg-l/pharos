//! Deneb pipeline integration test (Task 5.2 of M10-Deneb Phase 5).
//!
//! Exercises three paths end-to-end:
//!
//! 1. **Capella→Deneb crossing**: a capella anchor state with `deneb_fork_epoch = 1`
//!    is used as the pre-state.  When `import_block` runs `state_transition` on
//!    the deneb block at slot 9 (past epoch 1), `process_slots_fork` fires
//!    `upgrade_to_deneb`, converting the capella inner state to deneb before
//!    applying the block.  The test asserts the head advances past the fork.
//!
//! 2. **Deneb DA gate** — the deneb block body carries one `blob_kzg_commitment`,
//!    so the import DA gate is genuinely consulted (non-empty commitments) and
//!    `AvailableDAChecker` returns `Available` (sidecars treated as delivered),
//!    letting the block import. A versioned hash also flows into newPayloadV3.
//!
//! 3. **Engine V3** — an axum mock EL responds VALID to `engine_newPayloadV3`
//!    and `engine_forkchoiceUpdatedV3`, which the engine driver emits for deneb
//!    head changes.  The test asserts at least one V3 newPayload call was made.
//!
//! Uses `NullExecutionEngine` + `validate_result: false` for the STF so the
//! mock only needs to handle V3 calls from the engine driver.

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
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::altair::{MinimalSyncAggregate, MinimalSyncCommittee};
use pharos_types::capella::{
    MinimalBeaconBlock as CapellaMinimalBeaconBlock,
    MinimalBeaconBlockBody as CapellaMinimalBeaconBlockBody,
    MinimalBeaconState as CapellaMinimalBeaconState,
    MinimalSignedBeaconBlock as CapellaMinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayloadHeader as CapellaMinimalExecutionPayloadHeader,
};
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::{
    KZGCommitment, MinimalBeaconBlock as DenebMinimalBeaconBlock,
    MinimalBeaconBlockBody as DenebMinimalBeaconBlockBody,
    MinimalSignedBeaconBlock as DenebMinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayload as DenebMinimalExecutionPayload,
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

use pharos_node::data_availability::{DataAvailabilityChecker, DataAvailabilityVerdict};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::host_impl::HostImpl;
use pharos_node::import::import_block;
use pharos_node::lookup::{LookupBlockProvider, LookupError, LookupRequest, run_lookup_loop};
use pharos_node::pending_blocks::PendingBlocks;
use pharos_node::pow_block::EnginePowBlockProvider;

mod common;

// ── Test-only DA checker ────────────────────────────────────────────────────────

/// Returns `Available` for any block carrying blob commitments (i.e. the
/// sidecars are treated as delivered), and `Irrelevant` for a commitment-less
/// block. This drives the import DA gate through the real "commitments present
/// → checker consulted → Available → proceed" decision path, rather than the
/// `Irrelevant` bypass that an empty-commitments block would take.
struct AvailableDAChecker;

impl DataAvailabilityChecker<MinimalBeaconSpec> for AvailableDAChecker {
    fn is_data_available(
        &self,
        _block_root: Root,
        kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        if kzg_commitments.is_empty() {
            DataAvailabilityVerdict::Irrelevant
        } else {
            DataAvailabilityVerdict::Available
        }
    }
}

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
    8192,
    4,
    8192,
    16,
    2,
>;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Deneb fork epoch for the test chain (epoch 1 = slot 8 in minimal preset).
const DENEB_FORK_EPOCH: u64 = 1;

/// First deneb slot = epoch 1 * 8 slots/epoch + 1 = 9.
const DENEB_BLOCK_SLOT: u64 = 9;

/// Terminal block hash for the merge-transition override.
const TERMINAL_HASH: [u8; 32] = [0x01u8; 32];

// ── Mock Engine API ───────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct CallCounters {
    new_payload_v3: u64,
    fcu_v3: u64,
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
            "engine_newPayloadV3" => ctr.new_payload_v3 += 1,
            "engine_forkchoiceUpdatedV3" => ctr.fcu_v3 += 1,
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
    fn new_payload_v3_count(&self) -> u64 {
        self.counters.lock().new_payload_v3
    }
}

async fn spawn_engine_mock() -> EngineMock {
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
    EngineMock {
        url,
        secret,
        responses,
        counters,
    }
}

// ── Test pubkey helper ────────────────────────────────────────────────────────

fn test_pubkey() -> BLSPubkey {
    let sk = blst::min_pk::SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM");
    BLSPubkey::from_array(sk.sk_to_pk().compress())
}

// ── Fixture builders ──────────────────────────────────────────────────────────

/// Build a capella genesis anchor state at slot 0 with one active validator.
///
/// Returns `(inner_capella_state, anchor_signed_block, fork_enum_state)`.
fn build_capella_anchor(
    genesis_time: u64,
) -> (
    CapellaMinimalBeaconState,
    CapellaMinimalSignedBeaconBlock,
    ForkMinimalBeaconState,
) {
    let anchor_body = CapellaMinimalBeaconBlockBody::default();
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

    let state_inner = CapellaMinimalBeaconState {
        genesis_time,
        slot: Slot(0),
        fork: Fork {
            previous_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
            current_version: Version::from_array(MinimalBeaconSpec::CAPELLA_FORK_VERSION),
            epoch: UtilsEpoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(), // zeroed per spec
            body_root: anchor_body_root,
        },
        latest_execution_payload_header: CapellaMinimalExecutionPayloadHeader {
            block_hash: Hash256::from_array(TERMINAL_HASH),
            ..Default::default()
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
        ..CapellaMinimalBeaconState::default()
    };

    let fork_state = ForkMinimalBeaconState::Capella(state_inner.clone());
    let state_root: Root = fork_state.tree_hash_root();

    let anchor_block = CapellaMinimalSignedBeaconBlock {
        message: CapellaMinimalBeaconBlock {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: anchor_body,
        },
        signature: BLSSignature::from_array([0u8; 96]),
    };

    (state_inner, anchor_block, fork_state)
}

/// Build a single deneb block at `DENEB_BLOCK_SLOT` extending the capella anchor.
///
/// The `runtime_cfg` must carry `deneb_fork_epoch = 1` so that
/// `process_slots_fork` inside `state_transition` fires `upgrade_to_deneb` at
/// epoch 1 (slot 8) before processing the block at slot 9.
///
/// Returns `(fork_enum_signed_block, block_root)`.
fn build_deneb_block(
    genesis_state: ForkMinimalBeaconState,
    anchor_root: Root,
    runtime_cfg: &RuntimeConfig,
) -> (MinForkSignedBlock, Root) {
    let null_engine = NullExecutionEngine;
    let slot = Slot(DENEB_BLOCK_SLOT);

    // Advance a clone of the capella state to slot 9 — this triggers upgrade_to_deneb
    // at the epoch 1 boundary (slot 8) inside process_slots_fork.
    let fork_epochs = ForkEpochs::from_runtime_cfg(runtime_cfg);
    let mut pre_state_advanced = genesis_state.clone();
    process_slots_fork::<MinimalBeaconSpec>(
        &mut pre_state_advanced,
        slot,
        fork_epochs,
        runtime_cfg,
    )
    .expect("process_slots_fork for deneb block must succeed");

    // The advanced state should now be Deneb.
    assert!(
        matches!(pre_state_advanced, ForkMinimalBeaconState::Deneb(_)),
        "state after process_slots_fork past deneb_fork_epoch must be Deneb, got other variant"
    );

    // Extract randao_mix and expected timestamp from the deneb pre-state.
    let (prev_randao, expected_timestamp) = {
        let s = match &pre_state_advanced {
            ForkMinimalBeaconState::Deneb(s) => s,
            _ => unreachable!(),
        };
        let epoch = slot.0 / MinimalBeaconSpec::SLOTS_PER_EPOCH;
        let idx = (epoch % MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
        let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
        let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
        (randao, ts)
    };

    // Empty sync aggregate (G2 point at infinity for zero participants).
    const G2_INFINITY: [u8; 96] = {
        let mut b = [0u8; 96];
        b[0] = 0xc0;
        b
    };
    let sync_aggregate = MinimalSyncAggregate {
        sync_committee_signature: BLSSignature::from_array(G2_INFINITY),
        ..Default::default()
    };

    // Deneb execution payload: extends the terminal block hash from the anchor's
    // execution payload header.
    let payload = DenebMinimalExecutionPayload {
        parent_hash: Hash256::from_array(TERMINAL_HASH),
        prev_randao,
        block_number: 1,
        gas_limit: 0x1c9c380,
        timestamp: expected_timestamp,
        block_hash: Hash256::from_array([0x02u8; 32]),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        ..Default::default()
    };

    // Deneb block body carries one blob commitment, so the import DA gate is
    // genuinely consulted (non-empty -> AvailableDAChecker returns Available) and
    // a versioned hash flows into engine_newPayloadV3.
    let blob_kzg_commitments =
        SszList::with_push(&SszList::default(), KZGCommitment::from_array([0x11u8; 48]))
            .expect("push one commitment");
    let body = DenebMinimalBeaconBlockBody {
        execution_payload: payload,
        sync_aggregate,
        blob_kzg_commitments,
        ..Default::default()
    };

    // Draft pass (state_root = default) to obtain the post-state.
    let draft = DenebMinimalBeaconBlock {
        slot,
        proposer_index: ValidatorIndex(0),
        parent_root: anchor_root,
        state_root: Root::default(),
        body: body.clone(),
    };
    let draft_signed = MinForkSignedBlock::Deneb(DenebMinimalSignedBeaconBlock {
        message: draft,
        signature: BLSSignature::from_array([0u8; 96]),
    });

    let (post_state, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
        genesis_state,
        &draft_signed,
        &null_engine,
        false,
        runtime_cfg,
    )
    .expect("draft STF for deneb block must succeed");

    // Final block with correct state_root.
    let state_root: Root = post_state.tree_hash_root();
    let final_block = DenebMinimalBeaconBlock {
        slot,
        proposer_index: ValidatorIndex(0),
        parent_root: anchor_root,
        state_root,
        body,
    };
    let block_root: Root = final_block.tree_hash_root();

    let fork_signed = MinForkSignedBlock::Deneb(DenebMinimalSignedBeaconBlock {
        message: final_block,
        signature: BLSSignature::from_array([0u8; 96]),
    });

    (fork_signed, block_root)
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Capella→Deneb crossing + DA gate + Engine V3 pipeline.
///
/// Assertions:
/// (a) The fork-choice head advances to `DENEB_BLOCK_SLOT` after import.
/// (b) At least one `engine_newPayloadV3` call reaches the mock EL.
/// (c) No panics, no timeouts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deneb_pipeline_crossing_da_and_v3_engine() {
    let _ = tracing_subscriber::fmt::try_init();

    // ── 1. Build capella anchor + fork-choice store ───────────────────────────

    let genesis_time = 0u64;
    let (state_inner, anchor_signed, fork_state) = build_capella_anchor(genesis_time);

    let anchor_block = pharos_types::state::BeaconBlock::Capella(anchor_signed.message.clone());
    let anchor_root: Root = anchor_block.tree_hash_root();

    assert_eq!(
        anchor_block.state_root(),
        fork_state.tree_hash_root(),
        "anchor block state_root must match the genesis state"
    );

    let _ = state_inner; // used above for state construction

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(fork_state.clone(), anchor_block);

    // Advance store time so on_block's future-slot guard passes.
    fc.time = 10_000_000;
    // Override terminal block hash so the merge-transition guard passes.
    fc.set_terminal_config(
        pharos_utils::Uint256::ZERO,
        Hash256::from_array(TERMINAL_HASH),
        0,
    );

    // Runtime config: capella-at-genesis, deneb at epoch 1 (= slot 8 in minimal).
    // seconds_per_slot uses the default (12s) to match RuntimeConfig::default() timing.
    // The test uses genesis_time=0 and slot 9, so timestamp = 9 * 12 = 108.
    let runtime_cfg = RuntimeConfig {
        altair_fork_epoch: 0,
        altair_fork_version: MinimalBeaconSpec::ALTAIR_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        capella_fork_epoch: 0,
        capella_fork_version: MinimalBeaconSpec::CAPELLA_FORK_VERSION,
        deneb_fork_epoch: DENEB_FORK_EPOCH,
        deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
        ..RuntimeConfig::default()
    };

    // Thread the real runtime_cfg into the fc store so the backfill/ingestion
    // loops read the correct deneb_fork_epoch (per D-runtime-cfg-threading-live-loops).
    fc.runtime_cfg = runtime_cfg.clone();
    fc.set_fork_epochs(
        runtime_cfg.altair_fork_epoch,
        runtime_cfg.bellatrix_fork_epoch,
        runtime_cfg.capella_fork_epoch,
    );

    let fc = Arc::new(RwLock::new(fc));

    // ── 2. Build the deneb block (capella→deneb crossing) ─────────────────────

    let (deneb_signed, deneb_block_root) = build_deneb_block(fork_state, anchor_root, &runtime_cfg);

    // ── 3. Spawn mock EL returning VALID for V3 calls ─────────────────────────

    let engine_mock = spawn_engine_mock().await;
    let valid_payload_status = json!({
        "status": "VALID",
        "latestValidHash": null,
        "validationError": null
    });
    let valid_fcu = json!({
        "payloadStatus": {
            "status": "VALID",
            "latestValidHash": null,
            "validationError": null
        },
        "payloadId": null
    });
    engine_mock.set("engine_newPayloadV3", valid_payload_status.clone());
    engine_mock.set("engine_forkchoiceUpdatedV3", valid_fcu.clone());
    engine_mock.set(
        "engine_exchangeCapabilities",
        json!([
            "engine_newPayloadV1",
            "engine_newPayloadV2",
            "engine_newPayloadV3",
            "engine_forkchoiceUpdatedV1",
            "engine_forkchoiceUpdatedV2",
            "engine_forkchoiceUpdatedV3",
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

    // ── 4. Open RocksStore + wire engine + channels ───────────────────────────

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );

    let client = EngineClient::new(engine_mock.url.clone(), engine_mock.secret.clone()).unwrap();
    let engine_handle = spawn_engine_actor(client, None);

    let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);

    // ── 5. Build HostImpl ─────────────────────────────────────────────────────

    let genesis_validators_root = Root::default();
    // Capella-at-genesis, deneb at epoch 1.
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalBeaconSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalBeaconSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: UtilsEpoch(0),
        bellatrix_fork_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: UtilsEpoch(0),
        capella_fork_version: Version::from_array(MinimalBeaconSpec::CAPELLA_FORK_VERSION),
        capella_fork_epoch: UtilsEpoch(0),
        deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x01]),
        deneb_fork_epoch: UtilsEpoch(DENEB_FORK_EPOCH),
        electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x01]),
        electra_fork_epoch: UtilsEpoch(u64::MAX),
        genesis_validators_root,
    };

    let mut host = HostImpl::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc),
        genesis_validators_root,
        fork_schedule,
        0,
        Arc::new(runtime_cfg.clone()),
    );
    host.wire_engine(head_tx.clone(), payload_tx.clone());
    let _host = Arc::new(host);

    // ── 6. Spawn engine driver loop ───────────────────────────────────────────

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

    // ── 7. Import deneb block through the DA gate ─────────────────────────────

    let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle.clone()));
    let da_checker = Arc::new(AvailableDAChecker);

    // import_block runs: DA gate (commitments present → Available) → STF
    // (upgrade_to_deneb fires) → on_block → payload_tx push → head update.
    let import_result = import_block::<
        MinimalBeaconSpec,
        NullExecutionEngine,
        EnginePowBlockProvider,
        AvailableDAChecker,
    >(
        &deneb_signed,
        &fc,
        &Arc::new(NullExecutionEngine),
        &pow_provider,
        &payload_tx,
        false, // validate_result: false — test blocks have no real BLS signatures
        &runtime_cfg,
        &store,
        &da_checker,
    )
    .await;

    assert!(
        import_result.is_ok(),
        "import_block must succeed for the deneb block: {:?}",
        import_result.err()
    );

    // ── 8. Assert (a): head advanced to the deneb block slot ─────────────────

    let head = get_head::<MinimalBeaconSpec>(&fc.read());
    assert_eq!(
        head, deneb_block_root,
        "fork-choice head must be the deneb block root after import"
    );

    {
        let store_read = fc.read();
        let head_slot = store_read
            .blocks
            .get(&head)
            .map(|b| b.slot())
            .unwrap_or(Slot(0));
        assert_eq!(
            head_slot,
            Slot(DENEB_BLOCK_SLOT),
            "head slot must be DENEB_BLOCK_SLOT after import"
        );
    }

    // ── 9. Assert (b): at least one engine_newPayloadV3 call reached the mock ─

    // Wait for the engine driver to forward the head change to the EL.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if engine_mock.new_payload_v3_count() >= 1 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timeout: expected >= 1 engine_newPayloadV3 call, got {}",
                engine_mock.new_payload_v3_count()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        engine_mock.new_payload_v3_count() >= 1,
        "expected at least one engine_newPayloadV3 call to the mock EL"
    );

    // (c) Reaching here without panics / timeout proves no crash.
    drop(head_tx);
    drop(payload_tx);
}

// ── Lookup-path DA gate ─────────────────────────────────────────────────────────

/// Fixture `LookupBlockProvider` for the lookup-path DA test.
///
/// `blocks_by_root` is never called (the test drives the direct-import path:
/// the orphan's parent is already in the store). `blobs_by_root` records that
/// it was invoked and returns whatever sidecar set it was seeded with — empty
/// in this test, so the real `BlobAvailabilityChecker` sees no sidecars and
/// returns `NotAvailable`.
#[derive(Clone)]
struct BlobRecordingProvider {
    blobs_called: Arc<std::sync::atomic::AtomicBool>,
}

impl LookupBlockProvider<MinimalBeaconSpec> for BlobRecordingProvider {
    async fn blocks_by_root(
        &self,
        _roots: Vec<Root>,
    ) -> Result<Vec<MinForkSignedBlock>, LookupError> {
        Err(LookupError::NoUsablePeers)
    }

    async fn blobs_by_root(
        &self,
        _ids: Vec<pharos_types::deneb::BlobIdentifier>,
    ) -> Result<Vec<pharos_types::deneb::BlobSidecar>, LookupError> {
        self.blobs_called
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Serve no sidecars: the DA gate must reject (block not imported).
        Ok(Vec::new())
    }
}

/// Lookup-sync must run the REAL DA gate for a Deneb block fetched by root.
///
/// A Deneb block carrying a blob commitment, imported through the lookup
/// direct-import path, must co-fetch its sidecars via `BlobSidecarsByRoot` and
/// run `BlobAvailabilityChecker`. With no sidecars served the DA gate returns
/// `NotAvailable`, so the block must NOT be imported (head stays at the anchor).
/// Before the fix the lookup path used `NoopDataAvailabilityChecker`, which
/// would have imported this blob-less block unconditionally — a consensus hole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_runs_real_da_gate_for_deneb_block() {
    use pharos_network::host::ForkContext as _;
    use pharos_network::topics::{GossipTopic, GossipTopicKind};
    use pharos_network::types::Fork as NetworkFork;
    use pharos_ssz::Encode as _;

    let _ = tracing_subscriber::fmt::try_init();

    // Capella anchor + deneb-at-epoch-1 runtime config (mirrors the V3 test).
    let genesis_time = 0u64;
    let (_state_inner, anchor_signed, fork_state) = build_capella_anchor(genesis_time);
    let anchor_block = pharos_types::state::BeaconBlock::Capella(anchor_signed.message.clone());
    let anchor_root: Root = anchor_block.tree_hash_root();

    let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(fork_state.clone(), anchor_block);
    fc.time = 10_000_000;
    fc.set_terminal_config(
        pharos_utils::Uint256::ZERO,
        Hash256::from_array(TERMINAL_HASH),
        0,
    );
    let runtime_cfg = RuntimeConfig {
        altair_fork_epoch: 0,
        altair_fork_version: MinimalBeaconSpec::ALTAIR_FORK_VERSION,
        bellatrix_fork_epoch: 0,
        bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
        capella_fork_epoch: 0,
        capella_fork_version: MinimalBeaconSpec::CAPELLA_FORK_VERSION,
        deneb_fork_epoch: DENEB_FORK_EPOCH,
        deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
        ..RuntimeConfig::default()
    };
    fc.runtime_cfg = runtime_cfg.clone();
    fc.set_fork_epochs(
        runtime_cfg.altair_fork_epoch,
        runtime_cfg.bellatrix_fork_epoch,
        runtime_cfg.capella_fork_epoch,
    );
    let fc = Arc::new(RwLock::new(fc));

    // Deneb block carrying one blob commitment; its parent is the anchor (in store).
    let (deneb_signed, deneb_block_root) = build_deneb_block(fork_state, anchor_root, &runtime_cfg);

    // Host + store (no engine: DA rejects before the STF, so the engine is never hit).
    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );
    let genesis_validators_root = Root::default();
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalBeaconSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalBeaconSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: UtilsEpoch(0),
        bellatrix_fork_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: UtilsEpoch(0),
        capella_fork_version: Version::from_array(MinimalBeaconSpec::CAPELLA_FORK_VERSION),
        capella_fork_epoch: UtilsEpoch(0),
        deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x01]),
        deneb_fork_epoch: UtilsEpoch(DENEB_FORK_EPOCH),
        electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x01]),
        electra_fork_epoch: UtilsEpoch(u64::MAX),
        genesis_validators_root,
    };
    let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
        Arc::clone(&store),
        Arc::clone(&fc),
        genesis_validators_root,
        fork_schedule,
        genesis_time,
        Arc::new(runtime_cfg.clone()),
    ));

    // Channels for run_lookup_loop.
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);
    let (lookup_tx, lookup_rx) = mpsc::channel::<LookupRequest>(64);
    let (reinject_tx, _reinject_rx) =
        mpsc::channel::<pharos_node::block_ingestion::ReinjectBlock>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let pending = Arc::new(PendingBlocks::default());
    let notify_backfill = Arc::new(tokio::sync::Notify::new());
    let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);
    let exec_engine = Arc::new(NullExecutionEngine);

    let blobs_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let provider = BlobRecordingProvider {
        blobs_called: Arc::clone(&blobs_called),
    };

    let fc_for_assert = Arc::clone(&fc);

    let loop_handle = tokio::spawn(run_lookup_loop::<
        MinimalBeaconSpec,
        BlobRecordingProvider,
        NullExecutionEngine,
        pharos_fork_choice::NoopPowBlockProvider,
    >(
        lookup_rx,
        provider,
        Arc::clone(&host),
        Arc::clone(&fc),
        exec_engine,
        pow_provider,
        head_tx,
        payload_tx,
        Arc::clone(&pending),
        Arc::clone(&notify_backfill),
        reinject_tx,
        shutdown_rx,
    ));

    // Encode the deneb block as raw inner SSZ (as gossip carries it) and send it
    // as an UnknownParent orphan under the deneb fork digest.
    let deneb_ssz = match &deneb_signed {
        ForkSignedBeaconBlock::Deneb(inner) => inner.as_ssz_bytes(),
        _ => unreachable!("build_deneb_block always yields a Deneb block"),
    };
    let topic = GossipTopic {
        fork_digest: host.fork_digest_for(NetworkFork::Deneb),
        kind: GossipTopicKind::BeaconBlock,
    };
    lookup_tx
        .send(LookupRequest::UnknownParent {
            topic,
            peer: libp2p::PeerId::random(),
            data: deneb_ssz,
        })
        .await
        .unwrap();

    // Wait until the provider's blobs_by_root was invoked (co-fetch wired in).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !blobs_called.load(std::sync::atomic::Ordering::SeqCst) {
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout: lookup never co-fetched blob sidecars for the deneb block");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Give the import a moment to (not) complete, then assert head is unchanged:
    // the DA gate returned NotAvailable, so the deneb block was NOT imported.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let head = get_head::<MinimalBeaconSpec>(&fc_for_assert.read());
    assert_eq!(
        head, anchor_root,
        "deneb block with unavailable blobs must NOT be imported via lookup"
    );
    assert_ne!(
        head, deneb_block_root,
        "head must not advance to the blob-unavailable deneb block"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle).await;
}
