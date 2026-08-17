//! Phase-4 blob sidecar integration tests.
//!
//! Exercises `GET /eth/v1/beacon/blobs/{block_id}` against a mock
//! `ChainStateApi` that can serve seeded blob sidecars.
//!
//! Tests:
//! - `get_blobs_returns_persisted` — mock returns 2 sidecars; `data.len()==2`, hex shape.
//! - `get_blobs_versioned_hash_filter` — filter to 1 sidecar by versioned hash.
//! - `get_blobs_pre_deneb_empty` — 200 `{data:[]}` when block exists but no sidecars.
//! - `get_blobs_block_not_found_404` — 404 for unknown block_id.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_kzg::kzg_commitment_to_versioned_hash;
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::{Blob, BlobSidecar, KZGCommitment, KZGProof};
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use tower::ServiceExt as _;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Block root that has blob sidecars seeded in the mock.
const BLOB_BLOCK_ROOT: [u8; 32] = [0xb1; 32];
/// Block root that resolves but has no sidecars (pre-Deneb simulation).
const EMPTY_BLOCK_ROOT: [u8; 32] = [0xe0; 32];

/// Build a `BlobSidecar` with a distinctive commitment (first byte `tag`).
fn make_sidecar(index: u64, tag: u8) -> BlobSidecar {
    let mut commitment = [0u8; 48];
    commitment[0] = tag;
    let mut proof = [0u8; 48];
    proof[0] = tag;

    // Default Blob is 131072 zero bytes — acceptable for shape tests.
    BlobSidecar {
        index,
        blob: Blob::default(),
        kzg_commitment: KZGCommitment::from(commitment),
        kzg_proof: KZGProof::from(proof),
        signed_block_header: Default::default(),
        kzg_commitment_inclusion_proof: Default::default(),
    }
}

// ── Mock ──────────────────────────────────────────────────────────────────────

struct BlobMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    /// Sidecars returned for `BLOB_BLOCK_ROOT`.
    sidecars: Vec<BlobSidecar>,
}

impl BlobMock {
    fn new(sidecars: Vec<BlobSidecar>) -> Self {
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
            sidecars,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for BlobMock {
    fn head_root(&self) -> Root {
        Root::from(BLOB_BLOCK_ROOT)
    }
    fn current_slot(&self) -> Slot {
        Slot(100)
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
            epoch: Epoch(0),
            root: Root::default(),
        }
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(0),
            root: Root::default(),
        }
    }
    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
        if root == Root::from(BLOB_BLOCK_ROOT) || root == Root::from(EMPTY_BLOCK_ROOT) {
            Some(BeaconBlockHeader {
                slot: Slot(100),
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
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
        if slot == Slot(100) {
            Some(Root::from(BLOB_BLOCK_ROOT))
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

    /// Override: return seeded sidecars only for `BLOB_BLOCK_ROOT`.
    fn blob_sidecars_by_root(&self, root: Root) -> Vec<pharos_types::deneb::BlobSidecar> {
        if root == Root::from(BLOB_BLOCK_ROOT) {
            self.sidecars.clone()
        } else {
            vec![]
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_router(sidecars: Vec<BlobSidecar>) -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(BlobMock::new(sidecars));
    build_router(ApiState::new(chain))
}

async fn get_json(
    router: &axum::Router,
    path: &str,
) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let hdrs = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::json!(null));
    (status, json, hdrs)
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
    let hdrs = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    (status, body.to_vec(), hdrs)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `data` has two entries; each is a `0x`-prefixed 131072-byte hex string.
///
/// Blob hex length = 2 + 131072 * 2 = 262146 chars.
/// Validates the response shape from `~/dev/beacon-APIs/apis/beacon/blobs/blobs.yaml`:
/// `{execution_optimistic, finalized, data: [Blob, ...]}`
/// where each `Blob` is `^0x[a-fA-F0-9]{262144}$`.
#[tokio::test]
async fn get_blobs_returns_persisted() {
    let sidecars = vec![make_sidecar(0, 0xaa), make_sidecar(1, 0xbb)];
    let router = make_router(sidecars);
    let root_hex = format!("0x{}", hex::encode(BLOB_BLOCK_ROOT));
    let path = format!("/eth/v1/beacon/blobs/{root_hex}");
    let (status, json, _hdrs) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "unexpected status; body={json}");

    // Top-level fields per spec yaml.
    assert!(
        json["execution_optimistic"].is_boolean(),
        "execution_optimistic must be boolean"
    );
    assert!(json["finalized"].is_boolean(), "finalized must be boolean");

    let data = json["data"].as_array().expect("data must be an array");
    assert_eq!(data.len(), 2, "expected 2 blobs");

    // Each blob is `0x` + 131072 bytes * 2 hex chars = 262144 hex chars + 2 prefix = 262146 total.
    for blob_val in data {
        let s = blob_val.as_str().expect("blob must be a string");
        assert!(s.starts_with("0x"), "blob must start with 0x");
        assert_eq!(
            s.len(),
            2 + 131_072 * 2,
            "blob hex must be 0x + 262144 hex chars"
        );
    }
}

/// When the `versioned_hashes` filter is provided, only matching blobs are
/// returned. Two sidecars seeded; filter selects one by its versioned hash.
#[tokio::test]
async fn get_blobs_versioned_hash_filter() {
    let sidecar0 = make_sidecar(0, 0xaa);
    let sidecar1 = make_sidecar(1, 0xbb);

    // Compute the versioned hash for sidecar0's commitment.
    let commitment0: [u8; 48] = sidecar0.kzg_commitment.into_inner();
    let vh0 = kzg_commitment_to_versioned_hash(&commitment0);
    let vh0_hex = format!("0x{}", hex::encode(vh0));

    let sidecars = vec![sidecar0, sidecar1];
    let router = make_router(sidecars);
    let root_hex = format!("0x{}", hex::encode(BLOB_BLOCK_ROOT));
    // CSV format: `?versioned_hashes=0xabc` — single value, no comma needed.
    let path = format!("/eth/v1/beacon/blobs/{root_hex}?versioned_hashes={vh0_hex}");
    let (status, json, _) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "unexpected status; body={json}");
    let data = json["data"].as_array().expect("data must be an array");
    assert_eq!(data.len(), 1, "filter should retain 1 blob");
}

/// A block that exists but has no sidecars stored (pre-Deneb or zero blobs)
/// returns 200 with `data: []`.
#[tokio::test]
async fn get_blobs_pre_deneb_empty() {
    let router = make_router(vec![]);
    // EMPTY_BLOCK_ROOT resolves (block_header_at returns Some) but has no sidecars.
    let root_hex = format!("0x{}", hex::encode(EMPTY_BLOCK_ROOT));
    let path = format!("/eth/v1/beacon/blobs/{root_hex}");
    let (status, json, _) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "pre-Deneb empty must be 200");
    let data = json["data"].as_array().expect("data must be an array");
    assert!(data.is_empty(), "data must be empty for pre-Deneb block");
    assert!(json["execution_optimistic"].is_boolean());
    assert!(json["finalized"].is_boolean());
}

/// An unknown block_id returns 404.
#[tokio::test]
async fn get_blobs_block_not_found_404() {
    let router = make_router(vec![]);
    let unknown_hex = format!("0x{}", hex::encode([0xde; 32]));
    let path = format!("/eth/v1/beacon/blobs/{unknown_hex}");
    let (status, json, _) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "unknown block must be 404");
    // Error body per `ErrorMessage` schema: {code, message}
    assert!(json["code"].is_number(), "error body must have code");
    assert!(json["message"].is_string(), "error body must have message");
}

/// SSZ `Accept: application/octet-stream` — bytes are returned with
/// `Content-Type: application/octet-stream` and length is N * BYTES_PER_BLOB.
#[tokio::test]
async fn get_blobs_ssz_content_type() {
    let sidecars = vec![make_sidecar(0, 0xaa)];
    let router = make_router(sidecars);
    let root_hex = format!("0x{}", hex::encode(BLOB_BLOCK_ROOT));
    let path = format!("/eth/v1/beacon/blobs/{root_hex}");
    let (status, body, hdrs) = get_ssz(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "SSZ response must be 200");
    let ct = hdrs
        .get(header::CONTENT_TYPE)
        .expect("Content-Type header must be present")
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/octet-stream");
    // One blob = 131072 bytes raw.
    assert_eq!(body.len(), 131_072, "one blob must be 131072 bytes");
}
