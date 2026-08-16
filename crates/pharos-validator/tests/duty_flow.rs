//! Integration test for the validator duty flow.
//!
//! Spins up a minimal axum mock beacon node, then exercises:
//! 1. Proposer slot: produce_block (BN v3) → slashing record written BEFORE
//!    publish → sign → publish.
//! 2. BN returns HTTP 503 on produce_block: no signing, no DB write.
//!
//! The mock tracks: which endpoints were called and the sequence of calls,
//! so we can assert the slashing record was written before the publish call.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use reqwest::Url;
use serde_json::json;
use tokio::net::TcpListener;

use pharos_validator::bn_client::BnClient;
use pharos_validator::run::{ValidatorEntry, run_proposer};
use pharos_validator::signing::ForkContext;
use pharos_validator::slashing::{SlashingError, SlashingProtection, SqliteSlashingProtection};

// ── Mock BN state ─────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct MockBnState {
    /// Ordered log of endpoint names called by the VC.
    call_log: Arc<Mutex<Vec<String>>>,
    /// When true, produce_block returns HTTP 503.
    produce_503: bool,
}

// ── Mock BN handlers ──────────────────────────────────────────────────────────

/// `GET /eth/v3/validator/blocks/{slot}` — returns a minimal block JSON.
async fn mock_produce_block(
    Path(slot): Path<u64>,
    State(state): State<MockBnState>,
) -> impl IntoResponse {
    state
        .call_log
        .lock()
        .unwrap()
        .push("produce_block".to_string());
    if state.produce_503 {
        return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({}))).into_response();
    }
    let body = json!({
        "version": "bellatrix",
        "data": {
            "slot": slot.to_string(),
            "proposer_index": "1",
            "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "body": {}
        }
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// `POST /eth/v2/beacon/blocks` — records the publish call.
async fn mock_publish_block(
    State(state): State<MockBnState>,
    _body: axum::body::Bytes,
) -> impl IntoResponse {
    state
        .call_log
        .lock()
        .unwrap()
        .push("publish_block".to_string());
    StatusCode::OK.into_response()
}

/// `GET /eth/v1/node/syncing` — always reports healthy.
async fn mock_syncing() -> impl IntoResponse {
    axum::Json(json!({
        "data": {
            "head_slot": "100",
            "sync_distance": "0",
            "is_syncing": false,
            "is_optimistic": false,
            "el_offline": false
        }
    }))
}

/// `GET /eth/v1/validator/attestation_data` — returns minimal attestation data.
async fn mock_attestation_data(State(state): State<MockBnState>) -> impl IntoResponse {
    state
        .call_log
        .lock()
        .unwrap()
        .push("attestation_data".to_string());
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    axum::Json(json!({
        "data": {
            "slot": "42",
            "index": "0",
            "beacon_block_root": zero,
            "source": { "epoch": "0", "root": zero },
            "target": { "epoch": "1", "root": zero }
        }
    }))
}

/// `POST /eth/v1/beacon/pool/attestations` — records the submit call.
async fn mock_submit_attestations(
    State(state): State<MockBnState>,
    _body: axum::body::Bytes,
) -> impl IntoResponse {
    state
        .call_log
        .lock()
        .unwrap()
        .push("submit_attestation".to_string());
    StatusCode::OK.into_response()
}

/// `GET /eth/v2/validator/aggregate_attestation` — returns a minimal aggregate.
async fn mock_aggregate_attestation() -> impl IntoResponse {
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    axum::Json(json!({
        "data": {
            "aggregation_bits": "0x01",
            "data": {
                "slot": "42",
                "index": "0",
                "beacon_block_root": zero,
                "source": { "epoch": "0", "root": zero },
                "target": { "epoch": "1", "root": zero }
            },
            "signature": "0x00"
        }
    }))
}

/// Catch-all OK for the aggregator/subscription POSTs (records nothing critical).
async fn mock_ok_post(_body: axum::body::Bytes) -> impl IntoResponse {
    StatusCode::OK.into_response()
}

// ── Mock BN spawn helper ──────────────────────────────────────────────────────

async fn spawn_mock_bn(state: MockBnState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/eth/v3/validator/blocks/{slot}", get(mock_produce_block))
        .route("/eth/v1/beacon/blocks", post(mock_publish_block))
        .route("/eth/v2/beacon/blocks", post(mock_publish_block))
        .route("/eth/v1/node/syncing", get(mock_syncing))
        .route(
            "/eth/v1/validator/attestation_data",
            get(mock_attestation_data),
        )
        .route(
            "/eth/v1/beacon/pool/attestations",
            post(mock_submit_attestations),
        )
        .route(
            "/eth/v2/validator/aggregate_attestation",
            get(mock_aggregate_attestation),
        )
        .route("/eth/v2/validator/aggregate_and_proofs", post(mock_ok_post))
        .route(
            "/eth/v1/validator/beacon_committee_subscriptions",
            post(mock_ok_post),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

// ── Slashing spy ─────────────────────────────────────────────────────────────

/// Wraps a real SqliteSlashingProtection and records call order.
struct SpySlashing {
    inner: SqliteSlashingProtection,
    /// Shared call log (same as MockBnState's) so we can interleave checks.
    call_log: Arc<Mutex<Vec<String>>>,
}

impl SlashingProtection for SpySlashing {
    fn check_and_record_block_proposal(
        &self,
        pubkey_hex: &str,
        slot: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError> {
        // Record BEFORE delegating to the real DB.
        self.call_log
            .lock()
            .unwrap()
            .push("slashing_record_block".to_string());
        self.inner
            .check_and_record_block_proposal(pubkey_hex, slot, signing_root)
    }

    fn check_and_record_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError> {
        self.call_log
            .lock()
            .unwrap()
            .push("slashing_record_att".to_string());
        self.inner.check_and_record_attestation(
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root,
        )
    }
}

// ── Helper: make a ValidatorEntry with a fresh BLS key ───────────────────────

fn make_validator_entry() -> ValidatorEntry {
    use pharos_utils::bls::BLSSecretKey;
    // Generate a deterministic secret key from a fixed scalar for test reproducibility.
    // blst::min_pk::SecretKey::keygen takes an IKM of at least 32 bytes.
    let ikm = b"pharos_test_vc_duty_flow_ikm_v01";
    let sk = BLSSecretKey::key_gen(ikm).expect("keygen must not fail with 32-byte IKM");
    let pk = sk.to_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk.as_slice()));
    ValidatorEntry {
        index: 1,
        pubkey_hex: pk_hex,
        secret_key: sk,
    }
}

// ── Test 1: proposer flow — slashing record before publish ────────────────────

#[tokio::test]
async fn test_proposer_slot_slashing_record_before_publish() {
    let call_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock_state = MockBnState {
        call_log: Arc::clone(&call_log),
        produce_503: false,
    };
    let (addr, _bn_task) = spawn_mock_bn(mock_state).await;

    let base_url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let bn = BnClient::new(vec![base_url]);

    let entry = make_validator_entry();
    let fork = ForkContext {
        current_version: [0x03, 0x00, 0x00, 0x00],
        genesis_validators_root: [0u8; 32],
    };

    // Use a real in-memory SQLite slashing DB (SQLite supports `:memory:`)
    // wrapped in the spy.
    let tmpdir = tempfile::tempdir().unwrap();
    let db_path = tmpdir.path().join("slashing.sqlite");
    let real_db = SqliteSlashingProtection::open(&db_path).unwrap();
    let spy_db = Arc::new(SpySlashing {
        inner: real_db,
        call_log: Arc::clone(&call_log),
    });

    let slot = 42u64;
    let epoch = slot / 32;

    run_proposer(&bn, &entry, slot, epoch, &fork, spy_db.as_ref(), None).await;

    let log = call_log.lock().unwrap().clone();
    eprintln!("call log: {:?}", log);

    // produce_block must have been called.
    assert!(
        log.contains(&"produce_block".to_string()),
        "produce_block should be called; log = {:?}",
        log
    );
    // Slashing record must be written.
    assert!(
        log.contains(&"slashing_record_block".to_string()),
        "slashing DB must record block; log = {:?}",
        log
    );
    // publish_block must have been called.
    assert!(
        log.contains(&"publish_block".to_string()),
        "block must be published; log = {:?}",
        log
    );

    // Critical invariant: slashing record BEFORE publish.
    let slashing_pos = log
        .iter()
        .position(|s| s == "slashing_record_block")
        .expect("slashing_record_block in log");
    let publish_pos = log
        .iter()
        .position(|s| s == "publish_block")
        .expect("publish_block in log");
    assert!(
        slashing_pos < publish_pos,
        "slashing record (pos {slashing_pos}) must come before publish (pos {publish_pos})"
    );
}

// ── Test 2: BN 503 → no sign, no DB write, no publish ────────────────────────

#[tokio::test]
async fn test_proposer_slot_bn_503_no_sign() {
    let call_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock_state = MockBnState {
        call_log: Arc::clone(&call_log),
        produce_503: true,
    };
    let (addr, _bn_task) = spawn_mock_bn(mock_state).await;

    let base_url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let bn = BnClient::new(vec![base_url]);

    let entry = make_validator_entry();
    let fork = ForkContext {
        current_version: [0x03, 0x00, 0x00, 0x00],
        genesis_validators_root: [0u8; 32],
    };

    let tmpdir = tempfile::tempdir().unwrap();
    let db_path = tmpdir.path().join("slashing_503.sqlite");
    let real_db = SqliteSlashingProtection::open(&db_path).unwrap();
    let spy_db = Arc::new(SpySlashing {
        inner: real_db,
        call_log: Arc::clone(&call_log),
    });

    let slot = 99u64;
    let epoch = slot / 32;

    run_proposer(&bn, &entry, slot, epoch, &fork, spy_db.as_ref(), None).await;

    let log = call_log.lock().unwrap().clone();
    eprintln!("call log (503 path): {:?}", log);

    // The VC tried produce_block.
    assert!(
        log.contains(&"produce_block".to_string()),
        "produce_block endpoint must be hit; log = {:?}",
        log
    );
    // NO slashing record must have been written.
    assert!(
        !log.contains(&"slashing_record_block".to_string()),
        "slashing DB must NOT record block when BN returns 503; log = {:?}",
        log
    );
    // NO publish must have happened.
    assert!(
        !log.contains(&"publish_block".to_string()),
        "block must NOT be published when BN returns 503; log = {:?}",
        log
    );
}

// ── Test 3: attester flow — single slashing record before submit ─────────────

#[tokio::test]
async fn test_attester_slot_slashing_record_before_submit() {
    use pharos_validator::bn_client::AttesterDuty;
    use pharos_validator::run::run_attester;

    let call_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock_state = MockBnState {
        call_log: Arc::clone(&call_log),
        produce_503: false,
    };
    let (addr, _bn_task) = spawn_mock_bn(mock_state).await;

    let base_url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let bn = BnClient::new(vec![base_url]);

    let entry = make_validator_entry();
    let fork = ForkContext {
        current_version: [0x03, 0x00, 0x00, 0x00],
        genesis_validators_root: [0u8; 32],
    };

    let tmpdir = tempfile::tempdir().unwrap();
    let db_path = tmpdir.path().join("slashing_att.sqlite");
    let real_db = SqliteSlashingProtection::open(&db_path).unwrap();
    let spy_db = Arc::new(SpySlashing {
        inner: real_db,
        call_log: Arc::clone(&call_log),
    });

    let duty = AttesterDuty {
        pubkey: entry.pubkey_hex.clone(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "64".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: "42".to_string(),
    };

    let slot = 42u64;
    run_attester(&bn, &entry, &duty, slot, &fork, spy_db.as_ref(), 0, 12_000).await;

    let log = call_log.lock().unwrap().clone();
    eprintln!("attester call log: {:?}", log);

    // attestation_data fetched, attestation recorded and submitted.
    assert!(
        log.contains(&"attestation_data".to_string()),
        "attestation_data should be fetched; log = {:?}",
        log
    );
    assert!(
        log.contains(&"submit_attestation".to_string()),
        "attestation must be submitted; log = {:?}",
        log
    );

    // The slashing record must be written EXACTLY ONCE (regression guard for the
    // double-check bug that recorded with a mismatched root and blocked submit).
    let att_records = log.iter().filter(|s| *s == "slashing_record_att").count();
    assert_eq!(
        att_records, 1,
        "attestation must be slashing-recorded exactly once; log = {:?}",
        log
    );

    // Critical invariant: slashing record BEFORE submit.
    let slashing_pos = log
        .iter()
        .position(|s| s == "slashing_record_att")
        .expect("slashing_record_att in log");
    let submit_pos = log
        .iter()
        .position(|s| s == "submit_attestation")
        .expect("submit_attestation in log");
    assert!(
        slashing_pos < submit_pos,
        "slashing record (pos {slashing_pos}) must come before submit (pos {submit_pos})"
    );
}
