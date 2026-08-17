//! Integration tests for `POST /pharos/v1/log-level`.
//!
//! A: `None` reload handle → 503.
//! B: real reload handle + valid directive → 200, body echoes filter.
//! C: real reload handle + invalid directive → 400.
//! D: auth gate — no token → 401; correct bearer → 200/503 depending on handle.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router_with_auth};
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use tower::ServiceExt as _;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::reload;

// ── Minimal mock ──────────────────────────────────────────────────────────────

struct LogMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
}

impl LogMock {
    fn new() -> Self {
        let key = discv5::enr::CombinedKey::generate_secp256k1();
        let enr: Enr = discv5::enr::Enr::builder().build(&key).expect("build ENR");
        let meta = Arc::new(ArcSwap::from_pointee(AltairMetaData::default()));
        LogMock {
            identity: NodeIdentityCache {
                peer_id: PeerId::random(),
                enr,
                listen_addrs: vec![],
                discovery_addrs: vec![],
                metadata: meta,
            },
            runtime_cfg: Arc::new(MainnetBeaconSpec::default_runtime_config()),
        }
    }
}

type MState = <MainnetBeaconSpec as BeaconSpec>::BeaconState;

impl ChainStateApi<MainnetBeaconSpec> for LogMock {
    fn head_root(&self) -> Root {
        Root::default()
    }
    fn current_slot(&self) -> Slot {
        Slot(0)
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
            epoch: pharos_types::phase0::primitives::Epoch(0),
            root: Root::default(),
        }
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: pharos_types::phase0::primitives::Epoch(0),
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
    fn state_by_block_root(&self, _root: Root) -> Option<MState> {
        None
    }
    fn state_by_state_root(&self, _root: Root) -> Option<MState> {
        None
    }
    fn block_root_for_slot(&self, _slot: Slot) -> Option<Root> {
        None
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
    fn regenerate_state(&self, _target: RegenTarget) -> Result<MState, pharos_api::ApiError> {
        Err(pharos_api::ApiError::NotFound(
            "regen not available in mock".into(),
        ))
    }
    fn state_to_json(&self, state: MState) -> Result<serde_json::Value, pharos_api::ApiError> {
        pharos_api::beacon_state_to_json_full::<MainnetBeaconSpec>(state)
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
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn post_log_level(
    router: &axum::Router,
    filter: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::to_vec(&serde_json::json!({ "filter": filter })).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("/pharos/v1/log-level")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = builder.body(Body::from(body)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ── Test A: None handle → 503 ─────────────────────────────────────────────────

#[tokio::test]
async fn log_level_no_handle_returns_503() {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(LogMock::new());
    let state = ApiState::new(chain);
    let router = build_router_with_auth(state, None);

    let (status, _) = post_log_level(&router, "info", None).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 when handle is None"
    );
}

// ── Test B: valid directive → 200 with echoed filter ─────────────────────────

#[tokio::test]
async fn log_level_valid_directive_returns_200() {
    let initial = EnvFilter::new("info");
    let (layer, handle) = reload::Layer::new(initial);
    // Install the layer into a local subscriber for this test's scope.
    let registry = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(registry);

    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(LogMock::new());
    let event_bus = pharos_api::EventBus::new();
    let state = ApiState::new_with_bus_and_log_reload(chain, event_bus, Some(handle));
    let router = build_router_with_auth(state, None);

    let filter_str = "debug,pharos_network=trace";
    let (status, json) = post_log_level(&router, filter_str, None).await;
    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {json}");
    assert_eq!(
        json["filter"].as_str(),
        Some(filter_str),
        "response must echo the applied filter"
    );
}

// ── Test C: invalid directive → 400 ──────────────────────────────────────────

#[tokio::test]
async fn log_level_invalid_directive_returns_400() {
    let initial = EnvFilter::new("info");
    let (layer, handle) = reload::Layer::new(initial);
    let registry = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(registry);

    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(LogMock::new());
    let event_bus = pharos_api::EventBus::new();
    let state = ApiState::new_with_bus_and_log_reload(chain, event_bus, Some(handle));
    let router = build_router_with_auth(state, None);

    // "= = =" is a malformed RUST_LOG directive.
    let (status, _) = post_log_level(&router, "= = =", None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400 for malformed directive"
    );
}

// ── Test D: auth gate ─────────────────────────────────────────────────────────

#[tokio::test]
async fn log_level_auth_gate() {
    // Case D1: no Authorization header → 401.
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(LogMock::new());
    let state = ApiState::new(Arc::clone(&chain));
    let router = build_router_with_auth(state, Some("secret".to_string()));

    let (status, _) = post_log_level(&router, "info", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expected 401 for missing auth header"
    );

    // Case D2: correct bearer + no handle → reaches handler → 503.
    let chain2: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(LogMock::new());
    let state2 = ApiState::new(chain2);
    let router2 = build_router_with_auth(state2, Some("secret".to_string()));

    let (status, _) = post_log_level(&router2, "info", Some("secret")).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 (handle None) after auth passes"
    );

    // Case D3: correct bearer + real handle → 200.
    let initial = EnvFilter::new("info");
    let (layer, handle) = reload::Layer::new(initial);
    let registry = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(registry);

    let chain3: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(LogMock::new());
    let event_bus = pharos_api::EventBus::new();
    let state3 = ApiState::new_with_bus_and_log_reload(chain3, event_bus, Some(handle));
    let router3 = build_router_with_auth(state3, Some("secret".to_string()));

    let (status, _) = post_log_level(&router3, "debug", Some("secret")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 for correct bearer + real handle"
    );
}
