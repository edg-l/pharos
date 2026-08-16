//! Phase-2 beacon state-read integration tests (Task 2.7).
//!
//! Drives `build_router` over a mock `ChainStateApi` backed by a real (default
//! phase0) `BeaconState` carrying three validators, and exercises:
//! - state-id resolution (`head` / `genesis` / `finalized` / `<slot>` / `0x<root>`),
//!   plus the malformed (400) and unknown (404) error paths;
//! - `states/{id}/validators` filtering by index and by pubkey, and the single
//!   `states/{id}/validators/{validator_id}` endpoint;
//! - content negotiation: a JSON vs SSZ `Accept` round-trip on `states/{id}/root`,
//!   and a 406 for an unsupported explicit `Accept`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_network::discovery::enr::Enr;
use pharos_ssz::TreeHash;
use pharos_stf::phase0::state_write::BeaconStateWrite;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint, Validator};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use pharos_utils::{BLSPubkey, Bytes32, Gwei};
use tower::ServiceExt as _;

type State = <MainnetBeaconSpec as BeaconSpec>::BeaconState;

const FAR_FUTURE: u64 = u64::MAX;
const STATE_SLOT: u64 = 64; // epoch 2 at mainnet SLOTS_PER_EPOCH=32
const NUM_VALIDATORS: usize = 3;

/// Build a default phase0 state with `NUM_VALIDATORS` active validators, each
/// with a distinct pubkey (`[i+1, 0, 0, ...]`).
fn build_state() -> State {
    let mut s = State::default();
    s.set_slot(Slot(STATE_SLOT));
    for i in 0..NUM_VALIDATORS as u8 {
        let mut pk = [0u8; 48];
        pk[0] = i + 1;
        let v = Validator {
            pubkey: BLSPubkey::from(pk),
            withdrawal_credentials: Bytes32::default(),
            effective_balance: Gwei(32_000_000_000),
            slashed: false,
            activation_eligibility_epoch: Epoch(0),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(FAR_FUTURE),
            withdrawable_epoch: Epoch(FAR_FUTURE),
            cached_root: Default::default(),
        };
        s.push_validator(v).expect("push validator");
        s.push_balance(Gwei(32_000_000_000)).expect("push balance");
    }
    s
}

/// Pubkey of validator `i` as a `0x`-hex string (98 chars).
fn validator_pubkey_hex(i: u8) -> String {
    let mut pk = [0u8; 48];
    pk[0] = i + 1;
    format!("0x{}", hex::encode(pk))
}

// ── Mock ChainStateApi ──────────────────────────────────────────────────────

struct StateMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    state: State,
    head_root: Root,
    genesis_root: Root,
    state_root: Root,
}

impl StateMock {
    fn new() -> Self {
        let key = discv5::enr::CombinedKey::generate_secp256k1();
        let enr: Enr = discv5::enr::Enr::builder().build(&key).expect("build ENR");
        let meta = Arc::new(ArcSwap::from_pointee(AltairMetaData::default()));
        let identity = NodeIdentityCache {
            peer_id: PeerId::random(),
            enr,
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/9000".parse().unwrap()],
            discovery_addrs: vec![],
            metadata: meta,
        };
        let state = build_state();
        let state_root: Root = state.tree_hash_root();
        Self {
            identity,
            runtime_cfg: Arc::new(MainnetBeaconSpec::default_runtime_config()),
            state,
            head_root: Root::from([0xab; 32]),
            genesis_root: Root::from([0x00; 32]),
            state_root,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for StateMock {
    fn head_root(&self) -> Root {
        self.head_root
    }
    fn current_slot(&self) -> Slot {
        Slot(STATE_SLOT)
    }
    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        (
            0,
            Root::default(),
            <MainnetBeaconSpec as BeaconSpec>::GENESIS_FORK_VERSION,
        )
    }
    fn finalized_checkpoint(&self) -> Checkpoint {
        // Finalized at the head block so `finalized` id resolves to a known state.
        Checkpoint {
            epoch: Epoch(2),
            root: self.head_root,
        }
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(2),
            root: self.head_root,
        }
    }
    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
        if root == self.head_root {
            Some(BeaconBlockHeader {
                slot: Slot(STATE_SLOT),
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: self.state_root,
                body_root: Root::default(),
            })
        } else {
            None
        }
    }
    fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.runtime_cfg)
    }
    fn is_optimistic(&self) -> bool {
        false
    }
    fn is_optimistic_for_root(&self, _root: Root) -> bool {
        false
    }
    fn is_optimistic_node(&self) -> bool {
        false
    }
    fn is_syncing(&self) -> bool {
        false
    }
    fn node_identity(&self) -> &NodeIdentityCache {
        &self.identity
    }
    fn state_by_block_root(&self, root: Root) -> Option<State> {
        // The single state is the post-state of both head and genesis (anchor)
        // for the purpose of these tests.
        if root == self.head_root || root == self.genesis_root {
            Some(self.state.clone())
        } else {
            None
        }
    }
    fn state_by_state_root(&self, root: Root) -> Option<State> {
        if root == self.state_root {
            Some(self.state.clone())
        } else {
            None
        }
    }
    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        if slot == Slot(STATE_SLOT) {
            Some(self.head_root)
        } else {
            None
        }
    }
    fn genesis_block_root(&self) -> Root {
        self.genesis_root
    }
    fn sync_committee_pubkeys(&self, _root: Root) -> Option<SyncCommitteePubkeys> {
        // Phase0 state: no sync committee.
        None
    }

    fn block_by_root_for_api(
        &self,
        _root: Root,
    ) -> Result<Option<pharos_api::dto::block::SignedBlockForApi>, pharos_api::ApiError> {
        Ok(None)
    }

    fn signed_block_header_at(
        &self,
        _root: Root,
    ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)> {
        None
    }

    fn regenerate_state(
        &self,
        _target: RegenTarget,
    ) -> Result<<MainnetBeaconSpec as BeaconSpec>::BeaconState, pharos_api::ApiError> {
        Err(pharos_api::ApiError::NotFound(
            "regen not available in mock".into(),
        ))
    }

    fn fork_choice_dump(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        Ok(serde_json::json!({
            "justified_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "finalized_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "fork_choice_nodes": [],
        }))
    }

    fn fork_choice_heads(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        Ok(serde_json::json!({ "data": [] }))
    }

    fn state_to_json(
        &self,
        state: <MainnetBeaconSpec as pharos_types::BeaconSpec>::BeaconState,
    ) -> Result<serde_json::Value, pharos_api::ApiError> {
        pharos_api::beacon_state_to_json_full::<MainnetBeaconSpec>(state)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn make_router() -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(StateMock::new());
    build_router(ApiState::new(chain))
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

async fn get_with_accept(
    router: &axum::Router,
    path: &str,
    accept: &str,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let req = Request::builder()
        .uri(path)
        .header(header::ACCEPT, accept)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, ct, body.to_vec())
}

// ── id-resolution tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn resolve_head_root() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/root").await;
    assert_eq!(status, StatusCode::OK);
    let root = json["data"]["root"].as_str().unwrap();
    assert!(root.starts_with("0x"));
    assert_eq!(root.len(), 66);
    assert!(json["execution_optimistic"].is_boolean());
    assert!(json["finalized"].is_boolean());
}

#[tokio::test]
async fn resolve_genesis_fork() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/genesis/fork").await;
    assert_eq!(status, StatusCode::OK);
    let data = &json["data"];
    assert!(data["previous_version"].as_str().unwrap().starts_with("0x"));
    assert!(data["current_version"].as_str().unwrap().starts_with("0x"));
    assert!(data["epoch"].is_string(), "epoch must be quoted");
}

#[tokio::test]
async fn resolve_finalized_finality_checkpoints() {
    let router = make_router();
    let (status, json) = get_json(
        &router,
        "/eth/v1/beacon/states/finalized/finality_checkpoints",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"]["finalized"]["epoch"].is_string());
    assert!(
        json["data"]["current_justified"]["root"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
}

#[tokio::test]
async fn resolve_by_slot() {
    let router = make_router();
    let path = format!("/eth/v1/beacon/states/{STATE_SLOT}/root");
    let (status, json) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"]["root"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn resolve_by_root_hex() {
    let router = make_router();
    let head_hex = format!("0x{}", hex::encode([0xab; 32]));
    let path = format!("/eth/v1/beacon/states/{head_hex}/root");
    let (status, json) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"]["root"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn malformed_id_is_400() {
    let router = make_router();
    let (status, _) = get_json(&router, "/eth/v1/beacon/states/notanid/root").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_slot_is_404() {
    let router = make_router();
    let (status, _) = get_json(&router, "/eth/v1/beacon/states/999999/root").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── validators filtering ──────────────────────────────────────────────────────

#[tokio::test]
async fn validators_all() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/validators").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), NUM_VALIDATORS);
    assert_eq!(data[0]["index"].as_str().unwrap(), "0");
    assert_eq!(data[0]["status"].as_str().unwrap(), "active_ongoing");
}

#[tokio::test]
async fn validators_filter_by_index() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/validators?id=1").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["index"].as_str().unwrap(), "1");
}

#[tokio::test]
async fn validators_filter_by_pubkey() {
    let router = make_router();
    let pk = validator_pubkey_hex(2); // validator index 2
    let path = format!("/eth/v1/beacon/states/head/validators?id={pk}");
    let (status, json) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["index"].as_str().unwrap(), "2");
}

#[tokio::test]
async fn single_validator_by_index() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/validators/0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["index"].as_str().unwrap(), "0");
}

#[tokio::test]
async fn validators_filter_repeated_keys() {
    // Array style (?id=0&id=2) must return both, not just the last.
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/validators?id=0&id=2").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    let idxs: Vec<&str> = data.iter().map(|d| d["index"].as_str().unwrap()).collect();
    assert!(idxs.contains(&"0") && idxs.contains(&"2"));
}

#[tokio::test]
async fn validators_filter_mixed_repeated_and_comma() {
    // Mix of repeated keys and comma-separated values.
    let router = make_router();
    let (status, json) =
        get_json(&router, "/eth/v1/beacon/states/head/validators?id=0,1&id=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn validator_balances_filtered() {
    let router = make_router();
    let (status, json) = get_json(
        &router,
        "/eth/v1/beacon/states/head/validator_balances?id=0,2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["balance"].as_str().unwrap(), "32000000000");
}

// ── committees / randao / sync_committees ─────────────────────────────────────

#[tokio::test]
async fn committees_at_head() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/committees").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert!(!data.is_empty(), "epoch must have at least one committee");
    let c = &data[0];
    assert!(c["index"].is_string(), "committee index must be quoted");
    assert!(c["slot"].is_string(), "committee slot must be quoted");
    assert!(c["validators"].is_array());
}

#[tokio::test]
async fn committees_slot_outside_epoch_is_400() {
    let router = make_router();
    // STATE_SLOT=64 → epoch 2 (slots 64..96); slot 0 is outside epoch 2.
    let (status, _) = get_json(
        &router,
        "/eth/v1/beacon/states/head/committees?epoch=2&slot=0",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn randao_at_head() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/states/head/randao").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"]["randao"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn sync_committees_phase0_is_400() {
    // The mock state is phase0 — sync_committees must be a 400 (state found,
    // no committee), not a 404.
    let router = make_router();
    let (status, _) = get_json(&router, "/eth/v1/beacon/states/head/sync_committees").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── content negotiation ───────────────────────────────────────────────────────

#[tokio::test]
async fn root_json_vs_ssz_roundtrip() {
    let router = make_router();
    // JSON path.
    let (status, ct, body) = get_with_accept(
        &router,
        "/eth/v1/beacon/states/head/root",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ct.as_deref(), Some("application/json"));
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let json_root = json["data"]["root"].as_str().unwrap();
    let json_bytes = hex::decode(json_root.trim_start_matches("0x")).unwrap();

    // SSZ path.
    let (status, ct, ssz_body) = get_with_accept(
        &router,
        "/eth/v1/beacon/states/head/root",
        "application/octet-stream",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ct.as_deref(), Some("application/octet-stream"));
    assert_eq!(ssz_body.len(), 32, "state root SSZ is 32 bytes");
    assert_eq!(ssz_body, json_bytes, "SSZ root must equal JSON root bytes");
}

#[tokio::test]
async fn unsupported_accept_is_406() {
    let router = make_router();
    let (status, _ct, _body) =
        get_with_accept(&router, "/eth/v1/beacon/states/head/root", "text/csv").await;
    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
}
