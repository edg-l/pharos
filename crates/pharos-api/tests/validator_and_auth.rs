//! Phase-5 integration tests (Task 5.6).
//!
//! Verifies:
//! 1. Proposer duties match the state shuffling (each slot in the epoch has a
//!    valid proposer index drawn from the active validator set, and
//!    `dependent_root` is present in the response).
//! 2. Auth middleware rejects unauthenticated calls when a token is configured
//!    and allows them when the token is absent.
//! 3. `GET /eth/v1/debug/fork_choice` returns the expected node count.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router_with_auth};
use pharos_network::discovery::enr::Enr;
use pharos_ssz::TreeHash;
use pharos_stf::phase0::state_write::BeaconStateWrite;
use pharos_types::altair::{MainnetBeaconState as AltairMainnetState, MetaData as AltairMetaData};
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint, Validator};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use pharos_utils::{BLSPubkey, Bytes32, Gwei};
use tower::ServiceExt as _;

type State = <MainnetBeaconSpec as BeaconSpec>::BeaconState;

const FAR_FUTURE: u64 = u64::MAX;
const STATE_SLOT: u64 = 32; // epoch 1 at mainnet SLOTS_PER_EPOCH=32
const NUM_VALIDATORS: usize = 64; // need ≥ SLOTS_PER_EPOCH validators for proposer duties

fn build_state() -> State {
    let mut s = State::default();
    s.set_slot(Slot(STATE_SLOT));
    // Fill block_roots so get_block_root_at_slot doesn't return SlotOutOfRange.
    // Set slot 0's block_root to a deterministic value.
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

// ── Mock ChainStateApi ────────────────────────────────────────────────────────

struct DutiesMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    state: State,
    head_root: Root,
    genesis_root: Root,
    state_root: Root,
    /// Injected fork-choice nodes for the debug test.
    fc_node_count: usize,
}

impl DutiesMock {
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
            fc_node_count: 3,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for DutiesMock {
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
        Checkpoint {
            epoch: Epoch(1),
            root: self.head_root,
        }
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(1),
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

    fn state_to_json(
        &self,
        state: <MainnetBeaconSpec as pharos_types::BeaconSpec>::BeaconState,
    ) -> Result<serde_json::Value, pharos_api::ApiError> {
        pharos_api::beacon_state_to_json_full::<MainnetBeaconSpec>(state)
    }

    fn fork_choice_dump(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        // Build `fc_node_count` synthetic nodes for the test.
        let nodes: Vec<serde_json::Value> = (0..self.fc_node_count)
            .map(|i| {
                serde_json::json!({
                    "slot": i.to_string(),
                    "block_root": format!("0x{}", "ab".repeat(32)),
                    "parent_root": format!("0x{}", "00".repeat(32)),
                    "justified_epoch": "0",
                    "finalized_epoch": "0",
                    "weight": "0",
                    "validity": "valid",
                    "execution_block_hash": format!("0x{}", "00".repeat(32)),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "justified_checkpoint": {"epoch": "1", "root": format!("0x{}", hex::encode(self.head_root.as_slice()))},
            "finalized_checkpoint": {"epoch": "1", "root": format!("0x{}", hex::encode(self.head_root.as_slice()))},
            "fork_choice_nodes": nodes,
        }))
    }

    fn fork_choice_heads(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        Ok(serde_json::json!({ "data": [] }))
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_router(token: Option<String>) -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(DutiesMock::new());
    let state = ApiState::new(chain);
    build_router_with_auth(state, token)
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    // Use a large limit — full BeaconState JSON can be tens of MB with 8192 block_roots.
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

async fn get_with_bearer(router: &axum::Router, path: &str, token: &str) -> StatusCode {
    let req = Request::builder()
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap().status()
}

async fn post_json_with_bearer(
    router: &axum::Router,
    path: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = builder.body(Body::from(body_bytes)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Proposer duties: response contains `dependent_root`, `execution_optimistic`,
/// and `data` with SLOTS_PER_EPOCH entries each having a valid proposer index.
#[tokio::test]
async fn proposer_duties_returns_correct_assignments() {
    let router = make_router(None);
    let (status, json) = get_json(&router, "/eth/v1/validator/duties/proposer/1").await;

    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {json}");

    // `dependent_root` is required per beacon-APIs spec; lighthouse VC rejects if absent.
    assert!(
        json["dependent_root"].is_string(),
        "dependent_root must be present as a string, got: {json}"
    );

    assert!(
        json["execution_optimistic"].is_boolean(),
        "execution_optimistic must be boolean"
    );

    let data = json["data"].as_array().expect("data must be an array");
    // Mainnet: 32 slots per epoch → 32 proposer duties.
    assert_eq!(
        data.len(),
        MainnetBeaconSpec::SLOTS_PER_EPOCH as usize,
        "must have one proposer per slot"
    );

    // Each duty must have a proposer index in the active validator set.
    for duty in data {
        let slot = duty["slot"]
            .as_str()
            .expect("slot must be a string")
            .parse::<u64>()
            .unwrap();
        // epoch 1 → slots 32..63
        assert!((32..64).contains(&slot), "slot {slot} out of epoch 1 range");

        let vidx: u64 = duty["validator_index"]
            .as_str()
            .expect("validator_index must be a string")
            .parse()
            .unwrap();
        assert!(
            vidx < NUM_VALIDATORS as u64,
            "validator_index {vidx} out of range (have {NUM_VALIDATORS} validators)"
        );

        let pubkey = duty["pubkey"].as_str().expect("pubkey must be a string");
        assert!(pubkey.starts_with("0x"), "pubkey must be 0x-prefixed hex");
        assert_eq!(pubkey.len(), 98, "pubkey must be 48 bytes (96 hex + 0x)");
    }

    // Each slot in the epoch should appear exactly once.
    let slots: std::collections::HashSet<u64> = data
        .iter()
        .map(|d| d["slot"].as_str().unwrap().parse::<u64>().unwrap())
        .collect();
    assert_eq!(
        slots.len(),
        data.len(),
        "each slot must appear exactly once"
    );
}

/// `GET /eth/v2/validator/duties/proposer/{epoch}` — response shape matches
/// `~/dev/beacon-APIs/apis/validator/duties/proposer.v2.yaml`:
/// required fields `dependent_root`, `execution_optimistic`, `data`; NO `finalized`
/// field (the v2 yaml does not include it). On a pre-Fulu (phase0) state the
/// body must be byte-identical to the v1 response.
///
/// Also asserts the v2 route is auth-gated (403 on wrong token) and that the
/// `is_syncing()` 503 guard fires on a syncing mock.
///
/// (ADR: `D-proposer-duties-v2-shares-v1`, `D-proposer-dependent-root-fulu-fix`)
#[tokio::test]
async fn proposer_duties_v2_shape() {
    let router = make_router(None);

    // Happy path: 200 with correct shape.
    let (status, json) = get_json(&router, "/eth/v2/validator/duties/proposer/1").await;
    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {json}");

    // Required fields per proposer.v2.yaml.
    assert!(
        json["dependent_root"].is_string(),
        "dependent_root must be present as a string, got: {json}"
    );
    assert!(
        json["execution_optimistic"].is_boolean(),
        "execution_optimistic must be boolean"
    );
    let data = json["data"].as_array().expect("data must be an array");
    assert_eq!(
        data.len(),
        MainnetBeaconSpec::SLOTS_PER_EPOCH as usize,
        "must have one proposer per slot"
    );

    // `finalized` must NOT be present (v2 yaml only requires dependent_root +
    // execution_optimistic + data).
    assert!(
        json["finalized"].is_null(),
        "finalized must not be present in v2 response, got: {json}"
    );

    // Each duty has the required ProposerDuty fields.
    for duty in data {
        assert!(duty["pubkey"].as_str().unwrap().starts_with("0x"));
        assert!(duty["validator_index"].is_string());
        assert!(duty["slot"].is_string());
    }

    // On a pre-Fulu state v1 and v2 bodies should be identical.
    let (status_v1, json_v1) = get_json(&router, "/eth/v1/validator/duties/proposer/1").await;
    assert_eq!(status_v1, StatusCode::OK);
    assert_eq!(
        json["dependent_root"], json_v1["dependent_root"],
        "v1 and v2 dependent_root must match on pre-Fulu state"
    );
    assert_eq!(
        json["data"], json_v1["data"],
        "v1 and v2 data must be identical on pre-Fulu state"
    );

    // Auth gate: wrong token → 403.
    let token = "secret".to_string();
    let router_auth = make_router(Some(token.clone()));
    let sc = get_with_bearer(
        &router_auth,
        "/eth/v2/validator/duties/proposer/1",
        "wrongtoken",
    )
    .await;
    assert_eq!(sc, StatusCode::FORBIDDEN, "v2 must be auth-gated");

    // 503 when syncing.
    let syncing_router = make_syncing_router();
    let (sc_sync, _) = get_json(&syncing_router, "/eth/v2/validator/duties/proposer/1").await;
    assert_eq!(
        sc_sync,
        StatusCode::SERVICE_UNAVAILABLE,
        "v2 must return 503 when syncing"
    );
}

/// Auth gate: when token is configured, unauthenticated requests to
/// `/eth/v1/validator/*` return 401; correct Bearer passes.
#[tokio::test]
async fn auth_rejects_unauthenticated_when_token_set() {
    let token = "supersecret".to_string();
    let router = make_router(Some(token.clone()));

    // Missing Authorization header → 401.
    let (status, _) = get_json(&router, "/eth/v1/validator/duties/proposer/1").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expected 401 for missing token"
    );

    // Wrong token → 403.
    let status =
        get_with_bearer(&router, "/eth/v1/validator/duties/proposer/1", "wrongtoken").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected 403 for wrong token"
    );

    // Correct token → 200.
    let status = get_with_bearer(&router, "/eth/v1/validator/duties/proposer/1", &token).await;
    assert_eq!(status, StatusCode::OK, "expected 200 for correct token");
}

/// Auth gate: when no token is configured, requests to `/eth/v1/validator/*`
/// are allowed without Authorization header.
#[tokio::test]
async fn auth_allows_when_no_token_configured() {
    let router = make_router(None);
    let (status, _) = get_json(&router, "/eth/v1/validator/duties/proposer/1").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 with no auth configured"
    );
}

/// Auth does NOT gate non-validator endpoints.
#[tokio::test]
async fn auth_does_not_block_non_validator_endpoints() {
    let token = "secret".to_string();
    let router = make_router(Some(token));

    // Node endpoint is unprotected.
    let (status, _) = get_json(&router, "/eth/v1/node/syncing").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "non-validator endpoint must not require auth"
    );

    // Debug endpoint is unprotected.
    let (status, _) = get_json(&router, "/eth/v1/debug/fork_choice").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "debug/fork_choice must not require auth"
    );
}

/// `GET /eth/v1/debug/fork_choice` returns the expected node count.
#[tokio::test]
async fn debug_fork_choice_returns_expected_node_count() {
    let router = make_router(None);
    let (status, json) = get_json(&router, "/eth/v1/debug/fork_choice").await;

    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(
        json["justified_checkpoint"].is_object(),
        "justified_checkpoint must be present"
    );
    assert!(
        json["finalized_checkpoint"].is_object(),
        "finalized_checkpoint must be present"
    );

    let nodes = json["fork_choice_nodes"]
        .as_array()
        .expect("fork_choice_nodes must be an array");
    // The mock returns 3 nodes.
    assert_eq!(nodes.len(), 3, "expected 3 fork-choice nodes from mock");
}

// ── Additional mocks for fix-verification tests ───────────────────────────────

/// Syncing variant of `DutiesMock`: reports `is_syncing() = true`.
struct SyncingMock(DutiesMock);

impl ChainStateApi<MainnetBeaconSpec> for SyncingMock {
    fn head_root(&self) -> Root {
        self.0.head_root()
    }
    fn current_slot(&self) -> Slot {
        self.0.current_slot()
    }
    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        self.0.genesis()
    }
    fn finalized_checkpoint(&self) -> Checkpoint {
        self.0.finalized_checkpoint()
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        self.0.justified_checkpoint()
    }
    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
        self.0.block_header_at(root)
    }
    fn runtime_cfg(&self) -> std::sync::Arc<RuntimeConfig> {
        self.0.runtime_cfg()
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
        true
    }
    fn node_identity(&self) -> &NodeIdentityCache {
        self.0.node_identity()
    }
    fn state_by_block_root(&self, root: Root) -> Option<State> {
        self.0.state_by_block_root(root)
    }
    fn state_by_state_root(&self, root: Root) -> Option<State> {
        self.0.state_by_state_root(root)
    }
    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        self.0.block_root_for_slot(slot)
    }
    fn genesis_block_root(&self) -> Root {
        self.0.genesis_block_root()
    }
    fn sync_committee_pubkeys(&self, root: Root) -> Option<SyncCommitteePubkeys> {
        self.0.sync_committee_pubkeys(root)
    }
    fn block_by_root_for_api(
        &self,
        root: Root,
    ) -> Result<Option<pharos_api::dto::block::SignedBlockForApi>, pharos_api::ApiError> {
        self.0.block_by_root_for_api(root)
    }
    fn signed_block_header_at(
        &self,
        root: Root,
    ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)> {
        self.0.signed_block_header_at(root)
    }
    fn regenerate_state(&self, target: RegenTarget) -> Result<State, pharos_api::ApiError> {
        self.0.regenerate_state(target)
    }
    fn fork_choice_dump(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        self.0.fork_choice_dump()
    }
    fn fork_choice_heads(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        self.0.fork_choice_heads()
    }
    fn state_to_json(&self, state: State) -> Result<serde_json::Value, pharos_api::ApiError> {
        self.0.state_to_json(state)
    }
}

fn make_syncing_router() -> axum::Router {
    let chain: std::sync::Arc<dyn ChainStateApi<MainnetBeaconSpec>> =
        std::sync::Arc::new(SyncingMock(DutiesMock::new()));
    let state = ApiState::new(chain);
    build_router_with_auth(state, None)
}

/// Attester duties: `dependent_root` is present and each duty has the required fields.
#[tokio::test]
async fn attester_duties_returns_dependent_root() {
    let router = make_router(None);
    // Query duties for validators 0, 1, 2.
    let (status, json) = post_json_with_bearer(
        &router,
        "/eth/v1/validator/duties/attester/1",
        serde_json::json!(["0", "1", "2"]),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(
        json["dependent_root"].is_string(),
        "dependent_root must be present, got: {json}"
    );
    assert!(json["execution_optimistic"].is_boolean());

    let data = json["data"].as_array().expect("data must be an array");
    for duty in data {
        assert!(duty["pubkey"].as_str().unwrap().starts_with("0x"));
        assert!(duty["validator_index"].is_string());
        assert!(duty["committee_index"].is_string());
        assert!(duty["committee_length"].is_string());
        assert!(duty["committees_at_slot"].is_string());
        assert!(duty["validator_committee_index"].is_string());
        assert!(duty["slot"].is_string());
    }
}

// ── Fix 2: 503 when syncing ────────────────────────────────────────────────────

/// Proposer duties returns 503 when the node is syncing.
#[tokio::test]
async fn proposer_duties_returns_503_when_syncing() {
    let router = make_syncing_router();
    let (status, _) = get_json(&router, "/eth/v1/validator/duties/proposer/1").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 when syncing"
    );
}

/// Attester duties returns 503 when the node is syncing.
#[tokio::test]
async fn attester_duties_returns_503_when_syncing() {
    let router = make_syncing_router();
    let (status, _) = post_json_with_bearer(
        &router,
        "/eth/v1/validator/duties/attester/1",
        serde_json::json!(["0"]),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 when syncing"
    );
}

/// Sync duties returns 503 when the node is syncing.
#[tokio::test]
async fn sync_duties_returns_503_when_syncing() {
    let router = make_syncing_router();
    let (status, _) = post_json_with_bearer(
        &router,
        "/eth/v1/validator/duties/sync/1",
        serde_json::json!(["0"]),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 when syncing"
    );
}

// ── Fix 3: 400 on empty body ───────────────────────────────────────────────────

/// Attester duties returns 400 when the validator indices body is empty.
#[tokio::test]
async fn attester_duties_returns_400_on_empty_body() {
    let router = make_router(None);
    let (status, json) = post_json_with_bearer(
        &router,
        "/eth/v1/validator/duties/attester/1",
        serde_json::json!([]),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400 for empty body: {json}"
    );
    let msg = json["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("empty"),
        "error message should mention empty: {msg}"
    );
}

/// Sync duties returns 400 when the validator indices body is empty.
#[tokio::test]
async fn sync_duties_returns_400_on_empty_body() {
    let router = make_router(None);
    let (status, json) = post_json_with_bearer(
        &router,
        "/eth/v1/validator/duties/sync/1",
        serde_json::json!([]),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400 for empty body: {json}"
    );
}

/// `GET /eth/v2/debug/beacon/states/head` — returns fork-tagged JSON.
#[tokio::test]
async fn debug_state_returns_fork_tagged_json() {
    let router = make_router(None);
    let (status, json) = get_json(&router, "/eth/v2/debug/beacon/states/head").await;

    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    // Fork-tagged envelope fields.
    assert!(json["version"].is_string(), "version must be present");
    assert!(json["execution_optimistic"].is_boolean());
    assert!(json["finalized"].is_boolean());
    assert!(
        json["data"].is_object(),
        "data must be a BeaconState object"
    );

    // Phase0 state has genesis_time, slot, fork, validators, etc.
    let data = &json["data"];
    assert!(
        data["genesis_time"].is_string(),
        "genesis_time must be present"
    );
    assert!(data["slot"].is_string(), "slot must be present");
    assert_eq!(data["slot"].as_str().unwrap(), STATE_SLOT.to_string());
    assert!(data["validators"].is_array(), "validators must be an array");
    assert_eq!(
        data["validators"].as_array().unwrap().len(),
        NUM_VALIDATORS,
        "all validators must be present"
    );
    // Phase0 must include previous/current_epoch_attestations (Fix 1 check).
    assert!(
        data["previous_epoch_attestations"].is_array(),
        "previous_epoch_attestations must be present for Phase0"
    );
    assert!(
        data["current_epoch_attestations"].is_array(),
        "current_epoch_attestations must be present for Phase0"
    );
    // Phase0 must include eth1_data_votes, eth1_deposit_index, historical_roots, justification_bits.
    assert!(
        data["eth1_data_votes"].is_array(),
        "eth1_data_votes must be present"
    );
    assert!(
        data["eth1_deposit_index"].is_string(),
        "eth1_deposit_index must be present"
    );
    assert!(
        data["historical_roots"].is_array(),
        "historical_roots must be present"
    );
    assert!(
        data["justification_bits"].is_string(),
        "justification_bits must be present"
    );
}

// ── Fix 1: Altair fork-specific fields in debug/state JSON ────────────────────

/// `GET /eth/v2/debug/beacon/states/head` with an Altair state returns
/// Altair-specific fields: participation, inactivity_scores, sync committees.
#[tokio::test]
async fn debug_state_altair_has_fork_specific_fields() {
    use pharos_types::BeaconSpec as _;
    // Build an altair state wrapped in the fork enum.
    let altair_inner = AltairMainnetState::default();
    let altair_state = MainnetBeaconSpec::altair_into_state(altair_inner);

    // Use a mock whose state_by_block_root returns the altair state.
    struct AltairMock {
        inner: DutiesMock,
        altair_state: State,
    }
    impl ChainStateApi<MainnetBeaconSpec> for AltairMock {
        fn head_root(&self) -> Root {
            self.inner.head_root()
        }
        fn current_slot(&self) -> Slot {
            self.inner.current_slot()
        }
        fn genesis(&self) -> (u64, Root, [u8; 4]) {
            self.inner.genesis()
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            self.inner.finalized_checkpoint()
        }
        fn justified_checkpoint(&self) -> Checkpoint {
            self.inner.justified_checkpoint()
        }
        fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
            self.inner.block_header_at(root)
        }
        fn runtime_cfg(&self) -> std::sync::Arc<RuntimeConfig> {
            self.inner.runtime_cfg()
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
            self.inner.node_identity()
        }
        fn state_by_block_root(&self, _root: Root) -> Option<State> {
            Some(self.altair_state.clone())
        }
        fn state_by_state_root(&self, _root: Root) -> Option<State> {
            Some(self.altair_state.clone())
        }
        fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
            self.inner.block_root_for_slot(slot)
        }
        fn genesis_block_root(&self) -> Root {
            self.inner.genesis_block_root()
        }
        fn sync_committee_pubkeys(&self, root: Root) -> Option<SyncCommitteePubkeys> {
            self.inner.sync_committee_pubkeys(root)
        }
        fn block_by_root_for_api(
            &self,
            root: Root,
        ) -> Result<Option<pharos_api::dto::block::SignedBlockForApi>, pharos_api::ApiError>
        {
            self.inner.block_by_root_for_api(root)
        }
        fn signed_block_header_at(
            &self,
            root: Root,
        ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)> {
            self.inner.signed_block_header_at(root)
        }
        fn regenerate_state(&self, target: RegenTarget) -> Result<State, pharos_api::ApiError> {
            self.inner.regenerate_state(target)
        }
        fn fork_choice_dump(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
            self.inner.fork_choice_dump()
        }
        fn fork_choice_heads(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
            self.inner.fork_choice_heads()
        }
        fn state_to_json(&self, state: State) -> Result<serde_json::Value, pharos_api::ApiError> {
            pharos_api::beacon_state_to_json_full::<MainnetBeaconSpec>(state)
        }
    }

    let chain: std::sync::Arc<dyn ChainStateApi<MainnetBeaconSpec>> =
        std::sync::Arc::new(AltairMock {
            inner: DutiesMock::new(),
            altair_state,
        });
    let state_api = ApiState::new(chain);
    let router = build_router_with_auth(state_api, None);

    let (status, json) = get_json(&router, "/eth/v2/debug/beacon/states/head").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");

    let data = &json["data"];

    // Common fields must be present.
    assert!(data["genesis_time"].is_string(), "genesis_time missing");
    assert!(data["slot"].is_string(), "slot missing");
    assert!(
        data["eth1_data_votes"].is_array(),
        "eth1_data_votes missing"
    );
    assert!(
        data["eth1_deposit_index"].is_string(),
        "eth1_deposit_index missing"
    );
    assert!(
        data["historical_roots"].is_array(),
        "historical_roots missing"
    );
    assert!(
        data["justification_bits"].is_string(),
        "justification_bits missing"
    );

    // Altair-specific fields must be present (Fix 1 verification).
    assert!(
        data["previous_epoch_participation"].is_array(),
        "previous_epoch_participation missing"
    );
    assert!(
        data["current_epoch_participation"].is_array(),
        "current_epoch_participation missing"
    );
    assert!(
        data["inactivity_scores"].is_array(),
        "inactivity_scores missing"
    );
    assert!(
        data["current_sync_committee"].is_object(),
        "current_sync_committee missing"
    );
    assert!(
        data["next_sync_committee"].is_object(),
        "next_sync_committee missing"
    );

    // Phase0-only fields must NOT be present on an Altair state.
    assert!(
        data["previous_epoch_attestations"].is_null(),
        "previous_epoch_attestations must not exist for Altair"
    );
    assert!(
        data["current_epoch_attestations"].is_null(),
        "current_epoch_attestations must not exist for Altair"
    );

    // Sync committee object must have pubkeys and aggregate_pubkey.
    let curr_sc = &data["current_sync_committee"];
    assert!(
        curr_sc["pubkeys"].is_array(),
        "current_sync_committee.pubkeys missing"
    );
    assert!(
        curr_sc["aggregate_pubkey"].is_string(),
        "current_sync_committee.aggregate_pubkey missing"
    );
}
