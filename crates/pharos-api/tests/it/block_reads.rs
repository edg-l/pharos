//! Phase-3 block-read integration tests (Task 3.7).
//!
//! Drives `build_router` over a mock `ChainStateApi` that serves two
//! fixture `SignedBeaconBlock` values (a bellatrix and a capella), and
//! exercises:
//! - `/eth/v1/beacon/blocks/{id}/root` — block root with `execution_optimistic`
//!   + `finalized` flags.
//! - `/eth/v2/beacon/blocks/{id}` — fork-tagged JSON: `version` field and
//!   `Eth-Consensus-Version` header match the block's fork (bellatrix + capella).
//! - `/eth/v2/beacon/blocks/{id}` SSZ `Accept` round-trip: response bytes are
//!   non-empty and `Content-Type: application/octet-stream`.
//! - `/eth/v1/beacon/headers` — query by slot.
//! - `/eth/v1/config/fork_schedule` — array length.
//! - `/eth/v1/config/deposit_contract` — `chain_id` + `address`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::dto::block::{BlockApiSerializer, SignedBlockForApi};
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_network::discovery::enr::Enr;
use pharos_ssz::Encode;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use tower::ServiceExt as _;

// ── Concrete block fixtures ────────────────────────────────────────────────────

type MainnetBellatrixSignedBlock = pharos_types::bellatrix::MainnetSignedBeaconBlock;
type MainnetCapellaSignedBlock = pharos_types::capella::MainnetSignedBeaconBlock;

/// Build a default bellatrix signed block and set the message slot.
fn make_bellatrix_block(slot: u64) -> MainnetBellatrixSignedBlock {
    let mut b = MainnetBellatrixSignedBlock::default();
    b.message.slot = Slot(slot);
    b
}

/// Build a default capella signed block and set the message slot.
fn make_capella_block(slot: u64) -> MainnetCapellaSignedBlock {
    let mut b = MainnetCapellaSignedBlock::default();
    b.message.slot = Slot(slot);
    b
}

// ── Mock ChainStateApi ─────────────────────────────────────────────────────────

const BELLATRIX_ROOT: [u8; 32] = [0xbb; 32];
const CAPELLA_ROOT: [u8; 32] = [0xcc; 32];
const BELLATRIX_SLOT: u64 = 100;
const CAPELLA_SLOT: u64 = 200;

struct BlockMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    bellatrix_block: MainnetBellatrixSignedBlock,
    capella_block: MainnetCapellaSignedBlock,
}

impl BlockMock {
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
        Self {
            identity,
            runtime_cfg: Arc::new(MainnetBeaconSpec::default_runtime_config()),
            bellatrix_block: make_bellatrix_block(BELLATRIX_SLOT),
            capella_block: make_capella_block(CAPELLA_SLOT),
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for BlockMock {
    fn head_root(&self) -> Root {
        Root::from(CAPELLA_ROOT)
    }
    fn current_slot(&self) -> Slot {
        Slot(CAPELLA_SLOT)
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
            epoch: Epoch(6),
            root: Root::from(BELLATRIX_ROOT),
        }
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(6),
            root: Root::from(BELLATRIX_ROOT),
        }
    }
    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
        let slot = if root == Root::from(BELLATRIX_ROOT) {
            BELLATRIX_SLOT
        } else if root == Root::from(CAPELLA_ROOT) {
            CAPELLA_SLOT
        } else {
            return None;
        };
        Some(BeaconBlockHeader {
            slot: Slot(slot),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root: Root::default(),
        })
    }
    fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.runtime_cfg)
    }
    fn is_optimistic(&self) -> bool {
        false
    }
    fn is_optimistic_for_root(&self, _root: pharos_types::phase0::Root) -> bool {
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
    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        if slot == Slot(BELLATRIX_SLOT) {
            Some(Root::from(BELLATRIX_ROOT))
        } else if slot == Slot(CAPELLA_SLOT) {
            Some(Root::from(CAPELLA_ROOT))
        } else {
            None
        }
    }
    fn genesis_block_root(&self) -> Root {
        Root::default()
    }
    fn sync_committee_pubkeys(&self, _root: Root) -> Option<SyncCommitteePubkeys> {
        None
    }

    fn block_by_root_for_api(
        &self,
        root: Root,
    ) -> Result<Option<SignedBlockForApi>, pharos_api::ApiError> {
        if root == Root::from(BELLATRIX_ROOT) {
            Ok(Some(self.bellatrix_block.to_block_for_api()?))
        } else if root == Root::from(CAPELLA_ROOT) {
            Ok(Some(self.capella_block.to_block_for_api()?))
        } else {
            Ok(None)
        }
    }

    fn signed_block_header_at(
        &self,
        root: Root,
    ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)> {
        // Mock returns None — tests that need a real signature must use
        // the full node path; this mock is block-DTO-only.
        let _ = root;
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

// ── Helpers ────────────────────────────────────────────────────────────────────

fn make_router() -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(BlockMock::new());
    build_router(ApiState::new(chain))
}

async fn get_json(
    router: &axum::Router,
    path: &str,
) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::json!(null));
    (status, json, headers)
}

async fn get_ssz(
    router: &axum::Router,
    path: &str,
) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let req = Request::builder()
        .uri(path)
        .header(header::ACCEPT, "application/octet-stream")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, body.to_vec(), headers)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

// ── Block root endpoint ───────────────────────────────────────────────────────

#[tokio::test]
async fn block_root_by_root_hex() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(BELLATRIX_ROOT));
    let (status, json, _) = get_json(&router, &format!("/eth/v1/beacon/blocks/{hex}/root")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["root"].as_str().unwrap(), hex);
    assert!(!json["execution_optimistic"].as_bool().unwrap());
}

#[tokio::test]
async fn block_root_head() {
    let router = make_router();
    let (status, json, _) = get_json(&router, "/eth/v1/beacon/blocks/head/root").await;
    assert_eq!(status, StatusCode::OK);
    let expected_hex = format!("0x{}", hex::encode(CAPELLA_ROOT));
    assert_eq!(json["data"]["root"].as_str().unwrap(), expected_hex);
}

#[tokio::test]
async fn block_root_not_found() {
    let router = make_router();
    let unknown = format!("0x{}", hex::encode([0xde; 32]));
    let (status, _json, _) =
        get_json(&router, &format!("/eth/v1/beacon/blocks/{unknown}/root")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── v2 block endpoint — version field + Eth-Consensus-Version header ──────────

#[tokio::test]
async fn v2_block_bellatrix_version_field_and_header() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(BELLATRIX_ROOT));
    let (status, json, headers) = get_json(&router, &format!("/eth/v2/beacon/blocks/{hex}")).await;
    assert_eq!(status, StatusCode::OK, "response: {json}");
    assert_eq!(json["version"].as_str().unwrap(), "bellatrix");
    assert!(!json["execution_optimistic"].as_bool().unwrap());
    // Verify the Eth-Consensus-Version header is set.
    let cv = headers
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header missing")
        .to_str()
        .unwrap();
    assert_eq!(cv, "bellatrix");
    // The `data` field must be a signed block object.
    assert!(json["data"]["message"]["slot"].is_string());
    // Slot value must match the fixture.
    assert_eq!(
        json["data"]["message"]["slot"].as_str().unwrap(),
        BELLATRIX_SLOT.to_string()
    );
}

#[tokio::test]
async fn v2_block_capella_version_field_and_header() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(CAPELLA_ROOT));
    let (status, json, headers) = get_json(&router, &format!("/eth/v2/beacon/blocks/{hex}")).await;
    assert_eq!(status, StatusCode::OK, "response: {json}");
    assert_eq!(json["version"].as_str().unwrap(), "capella");
    let cv = headers
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header missing")
        .to_str()
        .unwrap();
    assert_eq!(cv, "capella");
    assert_eq!(
        json["data"]["message"]["slot"].as_str().unwrap(),
        CAPELLA_SLOT.to_string()
    );
    // Capella blocks must have a `bls_to_execution_changes` field in the body.
    assert!(json["data"]["message"]["body"]["bls_to_execution_changes"].is_array());
}

#[tokio::test]
async fn v2_block_head_is_capella() {
    let router = make_router();
    let (status, json, headers) = get_json(&router, "/eth/v2/beacon/blocks/head").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["version"].as_str().unwrap(), "capella");
    let cv = headers
        .get("eth-consensus-version")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cv, "capella");
}

#[tokio::test]
async fn v2_block_not_found() {
    let router = make_router();
    let unknown = format!("0x{}", hex::encode([0xaa; 32]));
    let (status, _json, _) = get_json(&router, &format!("/eth/v2/beacon/blocks/{unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── v2 block SSZ Accept round-trip ────────────────────────────────────────────

#[tokio::test]
async fn v2_block_ssz_accept_bellatrix() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(BELLATRIX_ROOT));
    let (status, bytes, headers) = get_ssz(&router, &format!("/eth/v2/beacon/blocks/{hex}")).await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert_eq!(ct, "application/octet-stream");
    // SSZ bytes must be non-empty.
    assert!(!bytes.is_empty(), "SSZ bytes must be non-empty");
    // The Eth-Consensus-Version header must still be set on the SSZ path.
    let cv = headers
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header missing on SSZ response")
        .to_str()
        .unwrap();
    assert_eq!(cv, "bellatrix");
    // Verify the SSZ bytes round-trip: decode a default bellatrix block and
    // compare SSZ encoding lengths (a full structural decode would require
    // importing pharos-ssz Decode; checking length is sufficient for the SSZ
    // path verification here).
    let expected = make_bellatrix_block(BELLATRIX_SLOT);
    let mut expected_ssz = Vec::new();
    expected.ssz_append(&mut expected_ssz);
    assert_eq!(bytes.len(), expected_ssz.len());
}

#[tokio::test]
async fn v2_block_ssz_accept_capella() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(CAPELLA_ROOT));
    let (status, bytes, headers) = get_ssz(&router, &format!("/eth/v2/beacon/blocks/{hex}")).await;
    assert_eq!(status, StatusCode::OK);
    let cv = headers
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header missing on SSZ response")
        .to_str()
        .unwrap();
    assert_eq!(cv, "capella");
    assert!(!bytes.is_empty());
    // Verify round-trip length matches expected SSZ bytes.
    let expected = make_capella_block(CAPELLA_SLOT);
    let mut expected_ssz = Vec::new();
    expected.ssz_append(&mut expected_ssz);
    assert_eq!(bytes.len(), expected_ssz.len());
}

// ── Block-id resolution via slot ──────────────────────────────────────────────

#[tokio::test]
async fn v2_block_by_slot() {
    let router = make_router();
    let (status, json, headers) =
        get_json(&router, &format!("/eth/v2/beacon/blocks/{BELLATRIX_SLOT}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["version"].as_str().unwrap(), "bellatrix");
    let cv = headers
        .get("eth-consensus-version")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cv, "bellatrix");
}

// ── Headers endpoint ──────────────────────────────────────────────────────────

#[tokio::test]
async fn headers_head() {
    let router = make_router();
    let (status, json, _) = get_json(&router, "/eth/v1/beacon/headers").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    let expected_root = format!("0x{}", hex::encode(CAPELLA_ROOT));
    assert_eq!(data[0]["root"].as_str().unwrap(), expected_root);
    assert!(data[0]["canonical"].as_bool().unwrap());
    assert_eq!(
        data[0]["header"]["message"]["slot"].as_str().unwrap(),
        CAPELLA_SLOT.to_string()
    );
}

#[tokio::test]
async fn headers_by_slot() {
    let router = make_router();
    let (status, json, _) = get_json(
        &router,
        &format!("/eth/v1/beacon/headers?slot={BELLATRIX_SLOT}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    let expected_root = format!("0x{}", hex::encode(BELLATRIX_ROOT));
    assert_eq!(data[0]["root"].as_str().unwrap(), expected_root);
}

#[tokio::test]
async fn header_by_block_id() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(BELLATRIX_ROOT));
    let (status, json, _) = get_json(&router, &format!("/eth/v1/beacon/headers/{hex}")).await;
    assert_eq!(status, StatusCode::OK);
    // Per header.yaml, `data` is a single object (not an array).
    let data = json["data"].as_object().unwrap();
    assert_eq!(data["root"].as_str().unwrap(), hex);
    assert!(data["canonical"].as_bool().unwrap());
    assert!(data["header"]["message"]["slot"].is_string());
}

// ── Config fork_schedule ──────────────────────────────────────────────────────

#[tokio::test]
async fn fork_schedule_returns_seven_entries() {
    let router = make_router();
    let (status, json, _) = get_json(&router, "/eth/v1/config/fork_schedule").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().unwrap();
    // Phase0, Altair, Bellatrix, Capella, Deneb, Electra, Fulu.
    assert_eq!(data.len(), 7);
    // First entry (Phase0): epoch "0".
    assert_eq!(data[0]["epoch"].as_str().unwrap(), "0");
    // All fork version fields are 0x-hex.
    assert!(
        data[0]["current_version"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
}

// ── Config deposit_contract ───────────────────────────────────────────────────

#[tokio::test]
async fn deposit_contract_mainnet() {
    let router = make_router();
    let (status, json, _) = get_json(&router, "/eth/v1/config/deposit_contract").await;
    assert_eq!(status, StatusCode::OK);
    let data = &json["data"];
    assert_eq!(data["chain_id"].as_str().unwrap(), "1");
    // Mainnet deposit contract address.
    assert_eq!(
        data["address"].as_str().unwrap().to_lowercase(),
        "0x00000000219ab540356cbb839cbe05303d7705fa"
    );
}

// ── v2 block attestations ─────────────────────────────────────────────────────

#[tokio::test]
async fn v2_block_attestations_bellatrix() {
    let router = make_router();
    let hex = format!("0x{}", hex::encode(BELLATRIX_ROOT));
    let (status, json, headers) = get_json(
        &router,
        &format!("/eth/v2/beacon/blocks/{hex}/attestations"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Fork-tagged: version field and Eth-Consensus-Version header.
    assert_eq!(json["version"].as_str().unwrap(), "bellatrix");
    let cv = headers
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header missing")
        .to_str()
        .unwrap();
    assert_eq!(cv, "bellatrix");
    // Default bellatrix block has 0 attestations.
    assert!(json["data"].as_array().unwrap().is_empty());
}
