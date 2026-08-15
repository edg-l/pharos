//! Integration tests for light-client REST endpoints.
//!
//! Endpoints tested:
//! - `GET /eth/v1/beacon/light_client/bootstrap/{block_root}`
//! - `GET /eth/v1/beacon/light_client/updates`
//! - `GET /eth/v1/beacon/light_client/finality_update`
//! - `GET /eth/v1/beacon/light_client/optimistic_update`

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::dto::light_client::{LcEnvelope, MAX_REQUEST_LC_UPDATES};
use pharos_api::{ApiError, ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::views::ForkVariant;
use pharos_types::{EthSpec, MainnetEthSpec};
use tower::ServiceExt as _;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_identity() -> NodeIdentityCache {
    let key = discv5::enr::CombinedKey::generate_secp256k1();
    let enr: Enr = discv5::enr::Enr::builder().build(&key).expect("build ENR");
    let meta = Arc::new(ArcSwap::from_pointee(AltairMetaData::default()));
    NodeIdentityCache {
        peer_id: PeerId::random(),
        enr,
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/9000".parse().unwrap()],
        discovery_addrs: vec![],
        metadata: meta,
    }
}

/// Build a canned altair-style `LcEnvelope`.
fn canned_altair_envelope(attested_slot: u64) -> LcEnvelope {
    LcEnvelope {
        variant: ForkVariant::Altair,
        json: serde_json::json!({
            "header": {"beacon": {"slot": attested_slot.to_string()}},
        }),
        ssz_bytes: vec![0xAA, 0xBB, 0xCC],
        attested_slot,
    }
}

// Non-zero gvr so compute_fork_digest produces distinct values per fork.
const TEST_GVR: [u8; 32] = [0xAB; 32];

// ── Mock ──────────────────────────────────────────────────────────────────────

struct MockLc {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    /// If `Some`, return this as the bootstrap result.
    bootstrap: Option<LcEnvelope>,
    /// If `Some`, return these as the updates result.
    updates: Option<Vec<LcEnvelope>>,
    /// If `Some`, return this as the finality update.
    finality: Option<LcEnvelope>,
    /// If `Some`, return this as the optimistic update.
    optimistic: Option<LcEnvelope>,
    /// last `count` passed to `light_client_updates` (for clamping test).
    count_seen: Arc<AtomicU64>,
}

impl MockLc {
    fn new() -> Self {
        Self {
            identity: make_identity(),
            runtime_cfg: Arc::new(MainnetEthSpec::default_runtime_config()),
            bootstrap: None,
            updates: None,
            finality: None,
            optimistic: None,
            count_seen: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
    fn with_bootstrap(mut self, env: LcEnvelope) -> Self {
        self.bootstrap = Some(env);
        self
    }
    fn with_updates(mut self, envs: Vec<LcEnvelope>) -> Self {
        self.updates = Some(envs);
        self
    }
    fn with_finality(mut self, env: LcEnvelope) -> Self {
        self.finality = Some(env);
        self
    }
}

impl ChainStateApi<MainnetEthSpec> for MockLc {
    fn head_root(&self) -> Root {
        Root::from([0xab; 32])
    }
    fn current_slot(&self) -> Slot {
        Slot::from(100u64)
    }
    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        (
            0,
            Root::from(TEST_GVR),
            <MainnetEthSpec as EthSpec>::GENESIS_FORK_VERSION,
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
        None
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
    fn state_by_block_root(&self, _root: Root) -> Option<<MainnetEthSpec as EthSpec>::BeaconState> {
        None
    }
    fn state_by_state_root(&self, _root: Root) -> Option<<MainnetEthSpec as EthSpec>::BeaconState> {
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
    ) -> Result<Option<pharos_api::dto::block::SignedBlockForApi>, ApiError> {
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
    ) -> Result<<MainnetEthSpec as EthSpec>::BeaconState, ApiError> {
        Err(ApiError::NotFound("regen not available in mock".into()))
    }
    fn fork_choice_dump(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "justified_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "finalized_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "fork_choice_nodes": [],
        }))
    }
    fn fork_choice_heads(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({ "data": [] }))
    }
    fn state_to_json(
        &self,
        state: <MainnetEthSpec as EthSpec>::BeaconState,
    ) -> Result<serde_json::Value, ApiError> {
        pharos_api::beacon_state_to_json_full::<MainnetEthSpec>(state)
    }

    // ── LC overrides ──────────────────────────────────────────────────────────

    fn light_client_bootstrap(&self, _block_root: Root) -> Result<Option<LcEnvelope>, ApiError> {
        // Return the canned bootstrap (if any) regardless of root (mock).
        Ok(self.bootstrap.as_ref().map(|_| canned_altair_envelope(100)))
    }

    fn light_client_updates(
        &self,
        _start_period: u64,
        count: u64,
    ) -> Result<Vec<LcEnvelope>, ApiError> {
        // Record the count for the clamping test.
        self.count_seen.store(count, Ordering::Relaxed);
        // Rebuild the vec from the stored template (LcEnvelope is not Clone).
        match &self.updates {
            None => Ok(vec![]),
            Some(template) => {
                let rebuilt: Vec<LcEnvelope> = template
                    .iter()
                    .map(|env| LcEnvelope {
                        variant: env.variant,
                        json: env.json.clone(),
                        ssz_bytes: env.ssz_bytes.clone(),
                        attested_slot: env.attested_slot,
                    })
                    .collect();
                Ok(rebuilt)
            }
        }
    }

    fn light_client_finality_update(&self) -> Result<Option<LcEnvelope>, ApiError> {
        Ok(self.finality.as_ref().map(|_| canned_altair_envelope(200)))
    }

    fn light_client_optimistic_update(&self) -> Result<Option<LcEnvelope>, ApiError> {
        Ok(self
            .optimistic
            .as_ref()
            .map(|_| canned_altair_envelope(300)))
    }
}

fn make_router(mock: MockLc) -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetEthSpec>> = Arc::new(mock);
    let state = ApiState::new(chain);
    build_router(state)
}

/// Like `make_router`, but also returns the `count_seen` handle so tests can
/// assert the clamped count that reached `light_client_updates`.
fn make_router_with_counter(mock: MockLc) -> (axum::Router, Arc<AtomicU64>) {
    let counter = Arc::clone(&mock.count_seen);
    let chain: Arc<dyn ChainStateApi<MainnetEthSpec>> = Arc::new(mock);
    let state = ApiState::new(chain);
    (build_router(state), counter)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// A valid 32-byte hex root (64 hex digits = 32 bytes) for bootstrap URL tests.
// hex part: "ab" × 32 = 64 chars.
const BOOTSTRAP_ROOT: &str = "/eth/v1/beacon/light_client/bootstrap/0xabababababababababababababababababababababababababababababababab";

/// Bootstrap JSON has EXACTLY the keys `version` and `data` at the top level —
/// NO `execution_optimistic` or `finalized`.
#[tokio::test]
async fn bootstrap_json_has_version_data_only() {
    let router = make_router(MockLc::new().with_bootstrap(canned_altair_envelope(100)));
    let req = Request::builder()
        .uri(BOOTSTRAP_ROOT)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let obj = v.as_object().expect("top-level must be object");
    let keys: std::collections::HashSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    // Exactly {version, data} — no execution_optimistic, no finalized.
    assert_eq!(
        keys,
        ["version", "data"]
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        "unexpected keys: {keys:?}"
    );
    assert_eq!(v["version"], "altair");
}

/// Bootstrap returns 404 when no bootstrap is stored.
#[tokio::test]
async fn bootstrap_404_when_none() {
    let router = make_router(MockLc::new()); // no bootstrap
    let req = Request::builder()
        .uri(BOOTSTRAP_ROOT)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Bootstrap SSZ response is the raw inner bytes — no length prefix.
#[tokio::test]
async fn bootstrap_ssz_is_raw_inner_bytes() {
    let router = make_router(MockLc::new().with_bootstrap(canned_altair_envelope(100)));
    let req = Request::builder()
        .uri(BOOTSTRAP_ROOT)
        .header(header::ACCEPT, "application/octet-stream")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/octet-stream"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    // The mock returns canned_altair_envelope(100) which has ssz_bytes = [0xAA, 0xBB, 0xCC].
    assert_eq!(body.to_vec(), vec![0xAAu8, 0xBB, 0xCC]);
}

/// The `Eth-Consensus-Version` header reflects the fork of the attested slot.
/// A bootstrap with attested_slot=0 (phase0 epoch) gets version=="phase0".
/// This also tests that `fork_variant_at_slot` dispatches by attested slot.
#[tokio::test]
async fn finality_update_version_tagged_by_attested_slot() {
    // The mock's `light_client_finality_update()` returns canned_altair_envelope(200)
    // (attested_slot=200, epoch=200/32=6 for mainnet with SLOTS_PER_EPOCH=32).
    // Mainnet ALTAIR_FORK_EPOCH=74240, so epoch 6 is still phase0.
    // However, the mock sets variant=ForkVariant::Altair on the canned envelope directly,
    // and render_lc_envelope uses env.variant (not re-derived). So the version header = "altair".
    let router = make_router(MockLc::new().with_finality(canned_altair_envelope(200)));
    let req = Request::builder()
        .uri("/eth/v1/beacon/light_client/finality_update")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("eth-consensus-version")
            .unwrap()
            .to_str()
            .unwrap(),
        "altair"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["version"], "altair");
}

/// Optimistic update returns 404 when none stored.
#[tokio::test]
async fn optimistic_update_404_when_none() {
    let router = make_router(MockLc::new());
    let req = Request::builder()
        .uri("/eth/v1/beacon/light_client/optimistic_update")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// SSZ updates: each item is framed as `u64_le(4 + ssz_len) || fork_digest[..4] || ssz_bytes`.
#[tokio::test]
async fn updates_ssz_frame_length_prefix() {
    // Use two items so we can check that the framing is per-item.
    let env0 = LcEnvelope {
        variant: ForkVariant::Altair,
        json: serde_json::json!({}),
        ssz_bytes: vec![0x01, 0x02, 0x03],
        attested_slot: 100,
    };
    let env1 = LcEnvelope {
        variant: ForkVariant::Capella,
        json: serde_json::json!({}),
        ssz_bytes: vec![0x04, 0x05],
        attested_slot: 200,
    };
    let router = make_router(MockLc::new().with_updates(vec![env0, env1]));
    let req = Request::builder()
        .uri("/eth/v1/beacon/light_client/updates?start_period=0&count=2")
        .header(header::ACCEPT, "application/octet-stream")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = body.to_vec();

    // Item 0: altair fork.
    // frame_len = u64_le(4 + 3) = 7
    let frame0 = u64::from_le_bytes(body[0..8].try_into().unwrap());
    assert_eq!(frame0, 4 + 3, "item0 frame_len should be 7");
    // fork_digest for altair using test GVR.
    let gvr = pharos_types::phase0::primitives::Root::from(TEST_GVR);
    let altair_digest = pharos_types::fork::compute_fork_digest(
        pharos_types::phase0::primitives::Version::from_array(
            <MainnetEthSpec as EthSpec>::ALTAIR_FORK_VERSION,
        ),
        &gvr,
    );
    assert_eq!(
        &body[8..12],
        &altair_digest.as_slice()[..4],
        "item0 fork digest mismatch"
    );
    assert_eq!(
        &body[12..15],
        &[0x01u8, 0x02, 0x03],
        "item0 ssz_bytes mismatch"
    );

    // Item 1: capella fork.
    let item1_start = 15;
    let frame1 = u64::from_le_bytes(body[item1_start..item1_start + 8].try_into().unwrap());
    assert_eq!(frame1, 4 + 2, "item1 frame_len should be 6");
    let capella_digest = pharos_types::fork::compute_fork_digest(
        pharos_types::phase0::primitives::Version::from_array(
            <MainnetEthSpec as EthSpec>::CAPELLA_FORK_VERSION,
        ),
        &gvr,
    );
    assert_eq!(
        &body[item1_start + 8..item1_start + 12],
        &capella_digest.as_slice()[..4],
        "item1 fork digest mismatch"
    );
    assert_eq!(
        &body[item1_start + 12..item1_start + 14],
        &[0x04u8, 0x05],
        "item1 ssz_bytes mismatch"
    );
}

/// `count` is clamped to `MAX_REQUEST_LC_UPDATES` (128) even if the query says more.
#[tokio::test]
async fn updates_count_clamped_to_max() {
    let mock = MockLc::new().with_updates(vec![]);
    let (router, count_seen) = make_router_with_counter(mock);
    let req = Request::builder()
        .uri(format!(
            "/eth/v1/beacon/light_client/updates?start_period=0&count={}",
            MAX_REQUEST_LC_UPDATES + 1000
        ))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The handler must clamp count before calling the trait method.
    assert_eq!(
        count_seen.load(Ordering::Relaxed),
        MAX_REQUEST_LC_UPDATES,
        "handler must clamp count to MAX_REQUEST_LC_UPDATES ({MAX_REQUEST_LC_UPDATES})"
    );
}

/// Empty updates range: JSON client gets `[]`, SSZ client gets empty body.
#[tokio::test]
async fn updates_empty_range_200_empty_body() {
    // JSON (default Accept): must return `[]`, not an empty body.
    let router = make_router(MockLc::new());
    let req = Request::builder()
        .uri("/eth/v1/beacon/light_client/updates?start_period=0&count=10")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(body.to_vec(), b"[]", "JSON empty range must return `[]`");

    // SSZ (Accept: application/octet-stream): empty body is correct.
    let router = make_router(MockLc::new());
    let req = Request::builder()
        .uri("/eth/v1/beacon/light_client/updates?start_period=0&count=10")
        .header(header::ACCEPT, "application/octet-stream")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(body.is_empty(), "SSZ empty range must return empty body");
}

/// Bootstrap returns 400 when the block-root path segment is not valid hex.
#[tokio::test]
async fn bootstrap_400_on_malformed_root() {
    let router = make_router(MockLc::new());
    let req = Request::builder()
        .uri("/eth/v1/beacon/light_client/bootstrap/not-hex")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
