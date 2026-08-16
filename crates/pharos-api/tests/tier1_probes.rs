//! Tier-1 Kurtosis readiness probe integration tests.
//!
//! Spins up `build_router` over a mock `ChainStateApi` (in-memory genesis)
//! and asserts JSON shape + HTTP status for all 7 Phase-1 endpoints.
//!
//! Endpoints tested:
//! - `GET /eth/v1/node/identity`
//! - `GET /eth/v1/node/version`
//! - `GET /eth/v1/node/syncing`
//! - `GET /eth/v1/node/health`
//! - `GET /eth/v1/beacon/genesis`
//! - `GET /eth/v1/beacon/headers/head`
//! - `GET /eth/v1/config/spec`

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec};
use tower::ServiceExt as _;

// ── Mock ChainStateApi ────────────────────────────────────────────────────────

struct MockChain {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    head_root: Root,
    head_header: Option<BeaconBlockHeader>,
    genesis_time: u64,
    genesis_validators_root: Root,
    genesis_fork_version: [u8; 4],
}

impl MockChain {
    fn new() -> Self {
        // Build a minimal ENR for the mock.
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

        let runtime_cfg = Arc::new(MainnetBeaconSpec::default_runtime_config());

        // Build a non-zero head root and header to exercise `block_header_at`.
        let head_root = Root::from([0xab; 32]);
        let head_header = BeaconBlockHeader {
            slot: Slot::from(42u64),
            proposer_index: ValidatorIndex(7),
            parent_root: Root::from([0x01; 32]),
            state_root: Root::from([0x02; 32]),
            body_root: Root::from([0x03; 32]),
        };

        Self {
            identity,
            runtime_cfg,
            head_root,
            head_header: Some(head_header),
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::from([0xff; 32]),
            genesis_fork_version: <MainnetBeaconSpec as BeaconSpec>::GENESIS_FORK_VERSION,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for MockChain {
    fn head_root(&self) -> Root {
        self.head_root
    }

    fn current_slot(&self) -> Slot {
        Slot::from(100u64)
    }

    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        (
            self.genesis_time,
            self.genesis_validators_root,
            self.genesis_fork_version,
        )
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(0u64),
            root: Root::default(),
        }
    }

    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(0u64),
            root: Root::default(),
        }
    }

    fn block_header_at(&self, _root: Root) -> Option<BeaconBlockHeader> {
        self.head_header.clone()
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

    fn state_by_block_root(
        &self,
        _root: Root,
    ) -> Option<<MainnetBeaconSpec as BeaconSpec>::BeaconState> {
        None
    }

    fn state_by_state_root(
        &self,
        _root: Root,
    ) -> Option<<MainnetBeaconSpec as BeaconSpec>::BeaconState> {
        None
    }

    fn block_root_for_slot(&self, _slot: Slot) -> Option<Root> {
        None
    }

    fn genesis_block_root(&self) -> Root {
        Root::default()
    }

    fn sync_committee_pubkeys(&self, _root: Root) -> Option<(Vec<[u8; 48]>, Vec<[u8; 48]>)> {
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

/// A minimal mock that delegates everything to `MockChain` but overrides
/// `is_syncing` and `is_optimistic` independently, for health-endpoint tests.
struct MockChainHealth {
    inner: MockChain,
    syncing: bool,
    optimistic: bool,
}

impl MockChainHealth {
    fn new(syncing: bool, optimistic: bool) -> Self {
        Self {
            inner: MockChain::new(),
            syncing,
            optimistic,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for MockChainHealth {
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

    fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
        self.inner.runtime_cfg()
    }

    fn is_optimistic(&self) -> bool {
        self.optimistic
    }

    fn is_optimistic_for_root(&self, _root: Root) -> bool {
        self.optimistic
    }

    fn is_optimistic_node(&self) -> bool {
        self.optimistic
    }

    fn is_syncing(&self) -> bool {
        self.syncing
    }

    fn node_identity(&self) -> &NodeIdentityCache {
        self.inner.node_identity()
    }

    fn state_by_block_root(
        &self,
        root: Root,
    ) -> Option<<MainnetBeaconSpec as BeaconSpec>::BeaconState> {
        self.inner.state_by_block_root(root)
    }

    fn state_by_state_root(
        &self,
        root: Root,
    ) -> Option<<MainnetBeaconSpec as BeaconSpec>::BeaconState> {
        self.inner.state_by_state_root(root)
    }

    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        self.inner.block_root_for_slot(slot)
    }

    fn genesis_block_root(&self) -> Root {
        self.inner.genesis_block_root()
    }

    fn sync_committee_pubkeys(&self, root: Root) -> Option<(Vec<[u8; 48]>, Vec<[u8; 48]>)> {
        self.inner.sync_committee_pubkeys(root)
    }

    fn block_by_root_for_api(
        &self,
        root: Root,
    ) -> Result<Option<pharos_api::dto::block::SignedBlockForApi>, pharos_api::ApiError> {
        self.inner.block_by_root_for_api(root)
    }

    fn signed_block_header_at(
        &self,
        root: Root,
    ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)> {
        self.inner.signed_block_header_at(root)
    }

    fn regenerate_state(
        &self,
        target: RegenTarget,
    ) -> Result<<MainnetBeaconSpec as BeaconSpec>::BeaconState, pharos_api::ApiError> {
        self.inner.regenerate_state(target)
    }

    fn fork_choice_dump(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        self.inner.fork_choice_dump()
    }

    fn fork_choice_heads(&self) -> Result<serde_json::Value, pharos_api::ApiError> {
        self.inner.fork_choice_heads()
    }

    fn state_to_json(
        &self,
        state: <MainnetBeaconSpec as pharos_types::BeaconSpec>::BeaconState,
    ) -> Result<serde_json::Value, pharos_api::ApiError> {
        self.inner.state_to_json(state)
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_router() -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(MockChain::new());
    let state = ApiState::new(chain);
    build_router(state)
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_identity() {
    let router = make_router();
    let (status, json) = get(&router, "/eth/v1/node/identity").await;
    assert_eq!(status, StatusCode::OK);
    let data = &json["data"];
    assert!(data["peer_id"].is_string(), "peer_id must be a string");
    assert!(data["enr"].is_string(), "enr must be a string");
    assert!(data["p2p_addresses"].is_array());
    assert!(data["discovery_addresses"].is_array());
    let meta = &data["metadata"];
    assert!(meta["seq_number"].is_string(), "seq_number must be quoted");
    assert!(meta["attnets"].is_string());
    assert!(
        meta["attnets"].as_str().unwrap().starts_with("0x"),
        "attnets must have 0x prefix"
    );
    assert!(meta["syncnets"].is_string());
    assert!(
        meta["syncnets"].as_str().unwrap().starts_with("0x"),
        "syncnets must have 0x prefix"
    );
}

#[tokio::test]
async fn test_version() {
    let router = make_router();
    let (status, json) = get(&router, "/eth/v1/node/version").await;
    assert_eq!(status, StatusCode::OK);
    let version = json["data"]["version"].as_str().unwrap();
    assert!(
        version.starts_with("Pharos/"),
        "version string must start with Pharos/"
    );
}

#[tokio::test]
async fn test_syncing() {
    let router = make_router();
    let (status, json) = get(&router, "/eth/v1/node/syncing").await;
    assert_eq!(status, StatusCode::OK);
    let data = &json["data"];
    assert!(data["head_slot"].is_string(), "head_slot must be quoted");
    assert!(
        data["sync_distance"].is_string(),
        "sync_distance must be quoted"
    );
    assert_eq!(data["is_syncing"], serde_json::Value::Bool(false));
    assert_eq!(data["is_optimistic"], serde_json::Value::Bool(false));
    assert!(data["el_offline"].is_boolean());
}

#[tokio::test]
async fn test_health_synced() {
    let router = make_router();
    let req = Request::builder()
        .uri("/eth/v1/node/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // is_syncing = false → 200 OK
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_genesis() {
    let router = make_router();
    let (status, json) = get(&router, "/eth/v1/beacon/genesis").await;
    assert_eq!(status, StatusCode::OK);
    let data = &json["data"];
    // genesis_time must be a quoted integer string
    assert!(
        data["genesis_time"].is_string(),
        "genesis_time must be quoted"
    );
    assert_eq!(
        data["genesis_time"].as_str().unwrap(),
        "1606824023",
        "genesis_time value mismatch"
    );
    // genesis_validators_root must be 0x-hex 32 bytes (66 chars)
    let gvr = data["genesis_validators_root"].as_str().unwrap();
    assert!(
        gvr.starts_with("0x"),
        "genesis_validators_root must have 0x prefix"
    );
    assert_eq!(gvr.len(), 66, "genesis_validators_root must be 32-byte hex");
    // genesis_fork_version must be 0x-hex 4 bytes (10 chars)
    let gfv = data["genesis_fork_version"].as_str().unwrap();
    assert!(
        gfv.starts_with("0x"),
        "genesis_fork_version must have 0x prefix"
    );
    assert_eq!(gfv.len(), 10, "genesis_fork_version must be 4-byte hex");
}

#[tokio::test]
async fn test_headers_head() {
    let router = make_router();
    let (status, json) = get(&router, "/eth/v1/beacon/headers/head").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["execution_optimistic"].is_boolean());
    assert!(json["finalized"].is_boolean());
    // Per beacon-APIs `headers/{block_id}`, `data` is a SINGLE header object
    // (not an array — the array shape is only for the `headers` LIST endpoint).
    let item = &json["data"];
    assert!(item.is_object(), "data must be a single header object");
    // root is 0x-hex
    let root = item["root"].as_str().unwrap();
    assert!(root.starts_with("0x"));
    assert_eq!(root.len(), 66);
    assert_eq!(item["canonical"], serde_json::Value::Bool(true));
    let msg = &item["header"]["message"];
    assert!(msg["slot"].is_string(), "slot must be quoted");
    assert!(
        msg["proposer_index"].is_string(),
        "proposer_index must be quoted"
    );
}

#[tokio::test]
async fn test_health_syncing() {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> =
        Arc::new(MockChainHealth::new(true, false));
    let state = ApiState::new(chain);
    let router = build_router(state);
    let req = Request::builder()
        .uri("/eth/v1/node/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // is_syncing = true → 206
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
}

#[tokio::test]
async fn test_health_optimistic() {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> =
        Arc::new(MockChainHealth::new(false, true));
    let state = ApiState::new(chain);
    let router = build_router(state);
    let req = Request::builder()
        .uri("/eth/v1/node/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // is_optimistic = true → 206
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
}

#[tokio::test]
async fn test_config_spec() {
    let router = make_router();
    let (status, json) = get(&router, "/eth/v1/config/spec").await;
    assert_eq!(status, StatusCode::OK);
    let data = &json["data"];
    assert!(data.is_object(), "data must be an object");
    // Spot-check a few keys
    assert!(
        data["SLOTS_PER_EPOCH"].is_string(),
        "SLOTS_PER_EPOCH must be present and quoted"
    );
    assert!(
        data["GENESIS_FORK_VERSION"]
            .as_str()
            .unwrap()
            .starts_with("0x"),
        "GENESIS_FORK_VERSION must be 0x-hex"
    );
    assert!(
        data["SYNC_COMMITTEE_SIZE"].is_string(),
        "SYNC_COMMITTEE_SIZE must be present and quoted"
    );
    assert!(
        data["ALTAIR_FORK_VERSION"]
            .as_str()
            .unwrap()
            .starts_with("0x"),
        "ALTAIR_FORK_VERSION must be 0x-hex"
    );
    assert!(
        data["CAPELLA_FORK_VERSION"]
            .as_str()
            .unwrap()
            .starts_with("0x"),
        "CAPELLA_FORK_VERSION must be 0x-hex"
    );
}
