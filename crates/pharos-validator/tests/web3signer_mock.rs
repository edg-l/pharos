//! Integration tests for the Web3Signer remote-signer path.
//!
//! Spins up a minimal axum mock Web3Signer that returns a fixed signature and
//! logs each `/api/v1/eth2/sign/<pubkey>` hit. Asserts:
//!
//! 1. `web3signer_commits_to_slashing_db_before_remote_sign` — the slashing DB
//!    record is committed BEFORE the remote signing HTTP call (the CRITICAL
//!    commit-before-sign ordering must wrap the remote call).
//! 2. `web3signer_slashing_rejection_blocks_remote_call` — a slashing-protection
//!    rejection prevents the remote call entirely (the mock signer is never hit).
//! 3. `web3signer_block_v2_roundtrips_through_mock` — a BLOCK_V2 request
//!    round-trips through the mock and produces the fixed signature, with the
//!    exact request JSON body captured and asserted.
//!
//! Does NOT hit a real Web3Signer — everything is a local axum mock.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use reqwest::Url;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use pharos_ssz::TreeHash;
use pharos_validator::signing::{ForkContext, sign_beacon_block};
use pharos_validator::slashing::{SlashingError, SlashingProtection, SqliteSlashingProtection};
use pharos_validator::web3signer::{Signer, Web3RemoteSigner};

// ── A fixed 96-byte signature the mock signer always returns ────────────────────

fn fixed_sig_hex() -> String {
    format!("0x{}", hex::encode([0x7Au8; 96]))
}

// ── Mock Web3Signer state ───────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct MockSignerState {
    /// Ordered log of events (shared with the slashing spy).
    call_log: Arc<Mutex<Vec<String>>>,
    /// The last request body the signer received.
    last_body: Arc<Mutex<Option<Value>>>,
}

/// `POST /api/v1/eth2/sign/{identifier}` — logs the hit and returns the fixed sig.
async fn mock_sign(
    Path(_pubkey): Path<String>,
    State(state): State<MockSignerState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    state
        .call_log
        .lock()
        .unwrap()
        .push("remote_sign".to_string());
    if let Ok(v) = serde_json::from_slice::<Value>(&body) {
        *state.last_body.lock().unwrap() = Some(v);
    }
    (
        StatusCode::OK,
        axum::Json(json!({ "signature": fixed_sig_hex() })),
    )
        .into_response()
}

async fn spawn_mock_signer(state: MockSignerState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/eth2/sign/{identifier}", post(mock_sign))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, task)
}

// ── Spy slashing DB: logs each record into the shared call log ──────────────────

struct SpySlashing {
    inner: SqliteSlashingProtection,
    call_log: Arc<Mutex<Vec<String>>>,
}

impl SlashingProtection for SpySlashing {
    fn check_and_record_block_proposal(
        &self,
        pubkey_hex: &str,
        slot: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError> {
        let res = self
            .inner
            .check_and_record_block_proposal(pubkey_hex, slot, signing_root);
        if res.is_ok() {
            self.call_log
                .lock()
                .unwrap()
                .push("slashing_record".to_string());
        }
        res
    }

    fn check_and_record_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError> {
        self.inner.check_and_record_attestation(
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root,
        )
    }
}

// ── A TreeHash test object ──────────────────────────────────────────────────────

struct TestRoot([u8; 32]);

impl TreeHash for TestRoot {
    const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;
    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn tree_hash_root(&self) -> pharos_utils::Hash256 {
        pharos_utils::Hash256::from_array(self.0)
    }
}

fn test_fork() -> ForkContext {
    ForkContext {
        current_version: [0x03, 0x00, 0x00, 0x00],
        genesis_validators_root: [0xCDu8; 32],
    }
}

fn remote_signer(addr: SocketAddr, pubkey_hex: &str) -> Web3RemoteSigner {
    let base = Url::parse(&format!("http://{}/", addr)).unwrap();
    Web3RemoteSigner::new(base, pubkey_hex.to_string())
}

// ── Test 1: slashing commit BEFORE remote sign ──────────────────────────────────

#[tokio::test]
async fn web3signer_commits_to_slashing_db_before_remote_sign() {
    let call_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let state = MockSignerState {
        call_log: Arc::clone(&call_log),
        last_body: Arc::new(Mutex::new(None)),
    };
    let (addr, _task) = spawn_mock_signer(state).await;

    let pubkey_hex = "0xb7354252aa5bce27ab9537fd0158515935f3c3861419e1b4b6c8219b5dbd15fcf907bddf275442f3e32f904f79807a2a";
    let signer = remote_signer(addr, pubkey_hex);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let real_db = SqliteSlashingProtection::open(tmp.path()).unwrap();
    let spy_db = SpySlashing {
        inner: real_db,
        call_log: Arc::clone(&call_log),
    };

    let block = TestRoot([0x11u8; 32]);
    let sig = sign_beacon_block(
        &signer,
        pubkey_hex,
        &block,
        100,
        &test_fork(),
        &spy_db,
        json!({"version": "BELLATRIX"}),
    )
    .await
    .expect("remote block signing must succeed");

    // Returned signature is the fixed mock signature.
    assert_eq!(
        format!("0x{}", hex::encode(sig.as_ref())),
        fixed_sig_hex(),
        "remote signer must produce the fixed mock signature"
    );

    let log = call_log.lock().unwrap().clone();
    let slash_pos = log.iter().position(|e| e == "slashing_record");
    let sign_pos = log.iter().position(|e| e == "remote_sign");
    assert!(
        slash_pos.is_some() && sign_pos.is_some(),
        "both events must have fired: {log:?}"
    );
    assert!(
        slash_pos < sign_pos,
        "slashing DB record MUST be committed before the remote signing call: {log:?}"
    );
}

// ── Test 2: slashing rejection blocks the remote call entirely ──────────────────

#[tokio::test]
async fn web3signer_slashing_rejection_blocks_remote_call() {
    let call_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let state = MockSignerState {
        call_log: Arc::clone(&call_log),
        last_body: Arc::new(Mutex::new(None)),
    };
    let (addr, _task) = spawn_mock_signer(state).await;

    let pubkey_hex = "0xb7354252aa5bce27ab9537fd0158515935f3c3861419e1b4b6c8219b5dbd15fcf907bddf275442f3e32f904f79807a2a";
    let signer = remote_signer(addr, pubkey_hex);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let real_db = SqliteSlashingProtection::open(tmp.path()).unwrap();
    let spy_db = SpySlashing {
        inner: real_db,
        call_log: Arc::clone(&call_log),
    };

    // First proposal at slot 50 succeeds (and hits the remote signer).
    let block1 = TestRoot([0x11u8; 32]);
    sign_beacon_block(
        &signer,
        pubkey_hex,
        &block1,
        50,
        &test_fork(),
        &spy_db,
        json!({}),
    )
    .await
    .expect("first proposal must succeed");

    // Capture how many remote_sign events fired so far.
    let remote_before = call_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| *e == "remote_sign")
        .count();

    // Second proposal at the SAME slot with a DIFFERENT root is slashable.
    let block2 = TestRoot([0x22u8; 32]);
    let err = sign_beacon_block(
        &signer,
        pubkey_hex,
        &block2,
        50,
        &test_fork(),
        &spy_db,
        json!({}),
    )
    .await
    .expect_err("double proposal must be rejected by slashing protection");

    assert!(
        format!("{err}").contains("slashing"),
        "error must be a slashing rejection: {err}"
    );

    // The remote signer must NOT have been hit a second time.
    let remote_after = call_log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| *e == "remote_sign")
        .count();
    assert_eq!(
        remote_before, remote_after,
        "a slashing rejection MUST prevent the remote signing call"
    );
}

// ── Test 3: BLOCK_V2 round-trips through the mock, request body asserted ────────

#[tokio::test]
async fn web3signer_block_v2_roundtrips_through_mock() {
    let last_body = Arc::new(Mutex::new(None));
    let state = MockSignerState {
        call_log: Arc::new(Mutex::new(Vec::new())),
        last_body: Arc::clone(&last_body),
    };
    let (addr, _task) = spawn_mock_signer(state).await;

    let pubkey_hex = "0xb7354252aa5bce27ab9537fd0158515935f3c3861419e1b4b6c8219b5dbd15fcf907bddf275442f3e32f904f79807a2a";
    let signer = remote_signer(addr, pubkey_hex);

    let block = TestRoot([0x11u8; 32]);
    let payload = json!({
        "version": "BELLATRIX",
        "block_header": {
            "slot": "100",
            "proposer_index": "1",
            "parent_root": "0x00",
            "state_root": "0x00",
            "body_root": "0x00",
        }
    });

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = SqliteSlashingProtection::open(tmp.path()).unwrap();

    let sig = sign_beacon_block(
        &signer,
        pubkey_hex,
        &block,
        100,
        &test_fork(),
        &db,
        payload.clone(),
    )
    .await
    .expect("block signing must succeed");
    assert_eq!(format!("0x{}", hex::encode(sig.as_ref())), fixed_sig_hex());

    // The mock received exactly the Web3Signer BLOCK_V2 request shape.
    let body = last_body
        .lock()
        .unwrap()
        .clone()
        .expect("signer received body");
    assert_eq!(body["type"], "BLOCK_V2");
    assert_eq!(body["beacon_block"], payload);
    assert_eq!(body["fork_info"]["fork"]["current_version"], "0x03000000");
    assert_eq!(
        body["fork_info"]["genesis_validators_root"],
        format!("0x{}", hex::encode([0xCDu8; 32]))
    );
    // The signing_root is the locally-computed authoritative BLS message.
    let signing_root = body["signing_root"].as_str().unwrap();
    assert!(signing_root.starts_with("0x") && signing_root.len() == 66);
}

// ── Test 4: a generic Signer dyn-dispatch over the remote signer compiles ───────

#[tokio::test]
async fn web3signer_usable_behind_dyn_signer() {
    let state = MockSignerState::default();
    let (addr, _task) = spawn_mock_signer(state).await;
    let pubkey_hex = "0xb7354252aa5bce27ab9537fd0158515935f3c3861419e1b4b6c8219b5dbd15fcf907bddf275442f3e32f904f79807a2a";
    let signer: Arc<dyn Signer> = Arc::new(remote_signer(addr, pubkey_hex));

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = SqliteSlashingProtection::open(tmp.path()).unwrap();
    let block = TestRoot([0x33u8; 32]);
    let sig = sign_beacon_block(
        &*signer,
        pubkey_hex,
        &block,
        7,
        &test_fork(),
        &db,
        json!({}),
    )
    .await
    .expect("dyn signer must sign");
    assert_eq!(format!("0x{}", hex::encode(sig.as_ref())), fixed_sig_hex());
}
