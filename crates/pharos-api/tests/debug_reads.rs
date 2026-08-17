//! M15 Phase 5 data column sidecar integration tests.
//!
//! Exercises `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}` against
//! a mock `ChainStateApi` that can serve seeded `DataColumnSidecar`s.
//!
//! Tests:
//! - `data_columns_returns_persisted` — mock returns 2 sidecars;
//!   `version:"fulu"`, `Eth-Consensus-Version` header set, `data.len()==2`,
//!   each entry has the required fields.
//! - `data_columns_indices_filter` — filter to 1 sidecar by `?indices=1`.
//! - `data_columns_pre_fulu_empty` — block exists but has no sidecars
//!   → 200 `{data:[]}`.
//! - `data_columns_block_not_found_404` — unknown block_id → 404.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::fulu::MainnetDataColumnSidecar;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use tower::ServiceExt as _;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Block root that has data column sidecars seeded in the mock.
const COL_BLOCK_ROOT: [u8; 32] = [0xc1; 32];
/// Block root that resolves but has no sidecars (pre-Fulu simulation).
const EMPTY_BLOCK_ROOT: [u8; 32] = [0xe0; 32];

/// Build a `MainnetDataColumnSidecar` with the given column `index`.
fn make_column_sidecar(index: u64) -> MainnetDataColumnSidecar {
    MainnetDataColumnSidecar {
        index,
        ..MainnetDataColumnSidecar::default()
    }
}

// ── Mock ──────────────────────────────────────────────────────────────────────

struct ColMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    /// Sidecars returned for `COL_BLOCK_ROOT`.
    sidecars: Vec<MainnetDataColumnSidecar>,
}

impl ColMock {
    fn new(sidecars: Vec<MainnetDataColumnSidecar>) -> Self {
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
        // Use a RuntimeConfig with fulu_fork_epoch = 0 so that slot 100 is in
        // the Fulu epoch range.
        let mut cfg = MainnetBeaconSpec::default_runtime_config();
        cfg.fulu_fork_epoch = 0;
        Self {
            identity,
            runtime_cfg: Arc::new(cfg),
            sidecars,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for ColMock {
    fn head_root(&self) -> Root {
        Root::from(COL_BLOCK_ROOT)
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
        if root == Root::from(COL_BLOCK_ROOT) || root == Root::from(EMPTY_BLOCK_ROOT) {
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
            Some(Root::from(COL_BLOCK_ROOT))
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

    /// Override: return seeded sidecars only for `COL_BLOCK_ROOT`.
    fn data_column_sidecars_by_root(
        &self,
        root: Root,
    ) -> Vec<pharos_types::fulu::MainnetDataColumnSidecar> {
        if root == Root::from(COL_BLOCK_ROOT) {
            self.sidecars.clone()
        } else {
            vec![]
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_router(sidecars: Vec<MainnetDataColumnSidecar>) -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(ColMock::new(sidecars));
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

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Two sidecars seeded; `version:"fulu"`, `Eth-Consensus-Version` header set,
/// `data` has 2 entries each with the required fields from
/// `~/dev/beacon-APIs/types/fulu/data_column_sidecar.yaml`:
/// `index`, `column`, `kzg_commitments`, `kzg_proofs`, `signed_block_header`,
/// `kzg_commitments_inclusion_proof`.
#[tokio::test]
async fn data_columns_returns_persisted() {
    let sidecars = vec![make_column_sidecar(0), make_column_sidecar(1)];
    let router = make_router(sidecars);
    let root_hex = format!("0x{}", hex::encode(COL_BLOCK_ROOT));
    let path = format!("/eth/v1/debug/beacon/data_column_sidecars/{root_hex}");
    let (status, json, hdrs) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "unexpected status; body={json}");

    // Fork envelope fields per spec yaml (`GetDebugDataColumnSidecarsResponse`).
    assert_eq!(
        json["version"].as_str(),
        Some("fulu"),
        "version must be 'fulu'"
    );
    assert!(
        json["execution_optimistic"].is_boolean(),
        "execution_optimistic must be boolean"
    );
    assert!(json["finalized"].is_boolean(), "finalized must be boolean");

    // `Eth-Consensus-Version` header.
    let ecv = hdrs
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header must be present")
        .to_str()
        .unwrap();
    assert_eq!(ecv, "fulu", "Eth-Consensus-Version must be 'fulu'");

    // Data array.
    let data = json["data"].as_array().expect("data must be an array");
    assert_eq!(data.len(), 2, "expected 2 sidecars");

    // Each sidecar must have all required fields from the spec yaml.
    for entry in data {
        assert!(entry["index"].is_string(), "index must be a quoted uint64");
        assert!(entry["column"].is_array(), "column must be an array");
        assert!(
            entry["kzg_commitments"].is_array(),
            "kzg_commitments must be an array"
        );
        assert!(
            entry["kzg_proofs"].is_array(),
            "kzg_proofs must be an array"
        );
        assert!(
            entry["signed_block_header"].is_object(),
            "signed_block_header must be an object"
        );
        assert!(
            entry["kzg_commitments_inclusion_proof"].is_array(),
            "kzg_commitments_inclusion_proof must be an array"
        );
        // signed_block_header sub-fields.
        let sbh = &entry["signed_block_header"];
        assert!(
            sbh["message"].is_object(),
            "signed_block_header.message must be an object"
        );
        assert!(
            sbh["message"]["slot"].is_string(),
            "slot must be a quoted uint64"
        );
        assert!(
            sbh["signature"].is_string(),
            "signature must be a hex string"
        );
    }
}

/// The `?indices=1` filter returns only the sidecar with `index == 1`.
#[tokio::test]
async fn data_columns_indices_filter() {
    let sidecars = vec![make_column_sidecar(0), make_column_sidecar(1)];
    let router = make_router(sidecars);
    let root_hex = format!("0x{}", hex::encode(COL_BLOCK_ROOT));
    let path = format!("/eth/v1/debug/beacon/data_column_sidecars/{root_hex}?indices=1");
    let (status, json, _) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "unexpected status; body={json}");
    let data = json["data"].as_array().expect("data must be an array");
    assert_eq!(data.len(), 1, "filter should retain 1 sidecar");
    assert_eq!(
        data[0]["index"].as_str(),
        Some("1"),
        "retained sidecar must have index '1'"
    );
}

/// A block that exists but has no sidecars (pre-Fulu or zero custodied columns)
/// returns 200 with `data: []`.
#[tokio::test]
async fn data_columns_pre_fulu_empty() {
    // EMPTY_BLOCK_ROOT resolves (block_header_at returns Some) but has no sidecars.
    let router = make_router(vec![]);
    let root_hex = format!("0x{}", hex::encode(EMPTY_BLOCK_ROOT));
    let path = format!("/eth/v1/debug/beacon/data_column_sidecars/{root_hex}");
    let (status, json, _) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::OK, "pre-Fulu empty must be 200");
    let data = json["data"].as_array().expect("data must be an array");
    assert!(
        data.is_empty(),
        "data must be empty when no sidecars are stored"
    );
    assert!(json["version"].is_string(), "version must be present");
    assert!(json["execution_optimistic"].is_boolean());
    assert!(json["finalized"].is_boolean());
}

/// An unknown block_id returns 404 with an `ErrorMessage` body.
#[tokio::test]
async fn data_columns_block_not_found_404() {
    let router = make_router(vec![]);
    let unknown_hex = format!("0x{}", hex::encode([0xde; 32]));
    let path = format!("/eth/v1/debug/beacon/data_column_sidecars/{unknown_hex}");
    let (status, json, _) = get_json(&router, &path).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "unknown block must be 404");
    // ErrorMessage schema: `{code, message}`.
    assert!(json["code"].is_number(), "error body must have code");
    assert!(json["message"].is_string(), "error body must have message");
}
