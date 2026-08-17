//! Validator production, signing and pool route tests.
//!
//! Covers every production, signing and pool route:
//! - Each production/signing route returns 200 (or 404 for aggregate) on a
//!   healthy non-optimistic node.
//! - Each production/signing route returns 503 when `is_optimistic_node()=true`.
//! - Pool GET routes return 200 with `{ "data": [] }`.
//! - Pool POST routes return 200.
//! - Beacon block publish returns 202 (broadcast-only, default impl).
//! - Node peers/peer_count return 200 with correct shape.
//! - Liveness returns 200 with correct shape.
//! - Validator registration and prepare_beacon_proposer return 200.
//! - Subscriptions return 200.

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::{ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router_with_auth};
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::electra::attestation::SingleAttestation;
use pharos_types::phase0::misc::AttestationData;
use pharos_types::phase0::primitives::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use pharos_utils::{BLSSignature, Bytes32, Uint256};
use serde_json::Value as JsonValue;
use tower::ServiceExt as _;

type State = <MainnetBeaconSpec as BeaconSpec>::BeaconState;

// ── Mock implementations ──────────────────────────────────────────────────────

/// Normal (healthy, non-syncing, non-optimistic) mock.
struct HealthyMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
}

impl HealthyMock {
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
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for HealthyMock {
    fn head_root(&self) -> Root {
        Root::from([0xab; 32])
    }
    fn current_slot(&self) -> Slot {
        Slot(100)
    }
    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        (0, Root::default(), [0u8; 4])
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
    fn state_by_block_root(&self, _root: Root) -> Option<State> {
        None
    }
    fn state_by_state_root(&self, _root: Root) -> Option<State> {
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
    fn signed_block_header_at(&self, _root: Root) -> Option<(BeaconBlockHeader, BLSSignature)> {
        None
    }
    fn regenerate_state(&self, _target: RegenTarget) -> Result<State, pharos_api::ApiError> {
        Err(pharos_api::ApiError::NotFound("regen not available".into()))
    }
    fn state_to_json(&self, state: State) -> Result<JsonValue, pharos_api::ApiError> {
        pharos_api::beacon_state_to_json_full::<MainnetBeaconSpec>(state)
    }
    fn fork_choice_dump(&self) -> Result<JsonValue, pharos_api::ApiError> {
        Ok(serde_json::json!({
            "justified_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "finalized_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "fork_choice_nodes": [],
        }))
    }
    fn fork_choice_heads(&self) -> Result<JsonValue, pharos_api::ApiError> {
        Ok(serde_json::json!({ "data": [] }))
    }

    // Overrides — return sensible test data.

    fn produce_block(
        &self,
        slot: Slot,
        _randao_reveal: BLSSignature,
        _graffiti: Bytes32,
    ) -> Result<(JsonValue, Uint256, Uint256), pharos_api::ApiError> {
        Ok((
            serde_json::json!({
                "version": "capella",
                "data": { "slot": slot.0.to_string() },
            }),
            Uint256::from(1000u64),
            Uint256::from(0u64),
        ))
    }

    fn produce_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData, pharos_api::ApiError> {
        use pharos_types::phase0::misc::Checkpoint;
        Ok(AttestationData {
            slot,
            index: committee_index,
            beacon_block_root: Root::from([0xab; 32]),
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(3),
                root: Root::from([0xcd; 32]),
            },
        })
    }

    fn validator_liveness(
        &self,
        epoch: Epoch,
        indices: Vec<ValidatorIndex>,
    ) -> Result<Vec<(ValidatorIndex, bool)>, pharos_api::ApiError> {
        // Return `is_live = true` for all requested indices in epoch 1.
        let is_live = epoch == Epoch(1);
        Ok(indices.into_iter().map(|i| (i, is_live)).collect())
    }

    fn peers(&self) -> Vec<JsonValue> {
        vec![serde_json::json!({
            "peer_id": "16Uiu2HAkuRF1",
            "state": "connected",
            "direction": "inbound",
            "last_seen_p2p_address": "/ip4/127.0.0.1/tcp/9000",
            "enr": "",
            "agent_string": "Pharos/test",
        })]
    }

    fn publish_block(&self, _block: JsonValue) -> Result<bool, pharos_api::ApiError> {
        // Return false = broadcast-only (202).
        Ok(false)
    }
}

/// Optimistic mock — all `is_optimistic_node()` → true.
struct OptimisticMock(HealthyMock);

impl ChainStateApi<MainnetBeaconSpec> for OptimisticMock {
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
    fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
        self.0.runtime_cfg()
    }
    fn is_optimistic(&self) -> bool {
        true
    }
    fn is_optimistic_for_root(&self, _root: Root) -> bool {
        true
    }
    fn is_optimistic_node(&self) -> bool {
        true
    }
    fn is_syncing(&self) -> bool {
        false
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
    fn signed_block_header_at(&self, root: Root) -> Option<(BeaconBlockHeader, BLSSignature)> {
        self.0.signed_block_header_at(root)
    }
    fn regenerate_state(&self, target: RegenTarget) -> Result<State, pharos_api::ApiError> {
        self.0.regenerate_state(target)
    }
    fn state_to_json(&self, state: State) -> Result<JsonValue, pharos_api::ApiError> {
        self.0.state_to_json(state)
    }
    fn fork_choice_dump(&self) -> Result<JsonValue, pharos_api::ApiError> {
        self.0.fork_choice_dump()
    }
    fn fork_choice_heads(&self) -> Result<JsonValue, pharos_api::ApiError> {
        self.0.fork_choice_heads()
    }
}

// ── PoolMock ──────────────────────────────────────────────────────────────────

/// A mock that stores attestations submitted via `submit_single_attestations`
/// and returns them from `pool_attestations`, proving BLOCKER 1 is wired.
///
/// Uses a runtime config with `electra_fork_epoch = 0` so `fork_variant_at_slot`
/// returns `Electra` for any slot, making the GET v2 response emit the electra
/// `committee_bits` shape.
struct PoolMock {
    inner: HealthyMock,
    attestations: Mutex<Vec<JsonValue>>,
    runtime_cfg: Arc<RuntimeConfig>,
}

impl PoolMock {
    fn new() -> Self {
        let mut cfg = MainnetBeaconSpec::default_runtime_config();
        // Set all fork epochs to 0 so any slot is in the electra fork.
        cfg.altair_fork_epoch = 0;
        cfg.bellatrix_fork_epoch = 0;
        cfg.capella_fork_epoch = 0;
        cfg.deneb_fork_epoch = 0;
        cfg.electra_fork_epoch = 0;
        Self {
            inner: HealthyMock::new(),
            attestations: Mutex::new(vec![]),
            runtime_cfg: Arc::new(cfg),
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for PoolMock {
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
        self.inner.node_identity()
    }
    fn state_by_block_root(&self, root: Root) -> Option<State> {
        self.inner.state_by_block_root(root)
    }
    fn state_by_state_root(&self, root: Root) -> Option<State> {
        self.inner.state_by_state_root(root)
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
    ) -> Result<Option<pharos_api::dto::block::SignedBlockForApi>, pharos_api::ApiError> {
        self.inner.block_by_root_for_api(root)
    }
    fn signed_block_header_at(&self, root: Root) -> Option<(BeaconBlockHeader, BLSSignature)> {
        self.inner.signed_block_header_at(root)
    }
    fn regenerate_state(&self, target: RegenTarget) -> Result<State, pharos_api::ApiError> {
        self.inner.regenerate_state(target)
    }
    fn state_to_json(&self, state: State) -> Result<JsonValue, pharos_api::ApiError> {
        self.inner.state_to_json(state)
    }
    fn fork_choice_dump(&self) -> Result<JsonValue, pharos_api::ApiError> {
        self.inner.fork_choice_dump()
    }
    fn fork_choice_heads(&self) -> Result<JsonValue, pharos_api::ApiError> {
        self.inner.fork_choice_heads()
    }
    fn publish_block(&self, block: JsonValue) -> Result<bool, pharos_api::ApiError> {
        self.inner.publish_block(block)
    }

    fn submit_single_attestations(
        &self,
        attestations: Vec<SingleAttestation>,
    ) -> Result<(), pharos_api::ApiError> {
        let mut store = self.attestations.lock().unwrap();
        for att in attestations {
            // Store as JSON with the same shape pool_attestations returns.
            // We set aggregation_bits = "0x03" (1-bit bitlist: bit0=1, sentinel=1).
            store.push(serde_json::json!({
                "aggregation_bits": "0x03",
                "data": {
                    "slot": att.data.slot.0.to_string(),
                    "index": att.data.index.0.to_string(),
                    "beacon_block_root": format!("0x{}", hex::encode(att.data.beacon_block_root.as_slice())),
                    "source": {
                        "epoch": att.data.source.epoch.0.to_string(),
                        "root": format!("0x{}", hex::encode(att.data.source.root.as_slice())),
                    },
                    "target": {
                        "epoch": att.data.target.epoch.0.to_string(),
                        "root": format!("0x{}", hex::encode(att.data.target.root.as_slice())),
                    },
                },
                "signature": format!("0x{}", hex::encode(att.signature.as_slice())),
            }));
        }
        Ok(())
    }

    fn pool_attestations(&self) -> Vec<JsonValue> {
        self.attestations.lock().unwrap().clone()
    }
}

fn make_pool_router() -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(PoolMock::new());
    let state = ApiState::new(chain);
    build_router_with_auth(state, None)
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_router() -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(HealthyMock::new());
    let state = ApiState::new(chain);
    build_router_with_auth(state, None)
}

fn make_optimistic_router() -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> =
        Arc::new(OptimisticMock(HealthyMock::new()));
    let state = ApiState::new(chain);
    build_router_with_auth(state, None)
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, JsonValue) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null);
    (status, json)
}

async fn post_json(router: &axum::Router, path: &str, body: JsonValue) -> (StatusCode, JsonValue) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null);
    (status, json)
}

// ── 5.2 tests: validator production routes ────────────────────────────────────

/// `GET /eth/v3/validator/blocks/{slot}` returns 200 with v3 envelope.
#[tokio::test]
async fn get_produce_block_v3_returns_200() {
    let router = make_router();
    let randao = format!("0x{}", "aa".repeat(96));
    let path = format!("/eth/v3/validator/blocks/100?randao_reveal={randao}");
    let (status, json) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["version"].is_string(), "version must be present");
    assert_eq!(json["execution_payload_blinded"], false);
    assert!(json["execution_payload_value"].is_string());
    assert!(json["consensus_block_value"].is_string());
    assert!(json["data"].is_object(), "data must be present");
}

/// `GET /eth/v3/validator/blocks/{slot}` returns 503 when optimistic.
#[tokio::test]
async fn get_produce_block_v3_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let randao = format!("0x{}", "aa".repeat(96));
    let path = format!("/eth/v3/validator/blocks/100?randao_reveal={randao}");
    let (status, _) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `GET /eth/v1/validator/attestation_data` returns 200 with correct shape.
#[tokio::test]
async fn get_attestation_data_returns_200() {
    let router = make_router();
    let (status, json) = get_json(
        &router,
        "/eth/v1/validator/attestation_data?slot=96&committee_index=0",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    let data = &json["data"];
    assert!(data["slot"].is_string());
    assert!(data["index"].is_string());
    assert!(
        data["beacon_block_root"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
    assert!(data["source"].is_object());
    assert!(data["target"].is_object());
}

/// `GET /eth/v1/validator/attestation_data` returns 503 when optimistic.
#[tokio::test]
async fn get_attestation_data_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let (status, _) = get_json(
        &router,
        "/eth/v1/validator/attestation_data?slot=96&committee_index=0",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `GET /eth/v2/validator/aggregate_attestation` returns 503 when optimistic.
#[tokio::test]
async fn get_aggregate_attestation_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let root = format!("0x{}", "ab".repeat(32));
    let path =
        format!("/eth/v2/validator/aggregate_attestation?slot=96&attestation_data_root={root}");
    let (status, _) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `GET /eth/v2/validator/aggregate_attestation` returns 404 (no pool) on healthy node.
#[tokio::test]
async fn get_aggregate_attestation_returns_404_when_no_pool() {
    let router = make_router();
    let root = format!("0x{}", "ab".repeat(32));
    let path =
        format!("/eth/v2/validator/aggregate_attestation?slot=96&attestation_data_root={root}");
    let (status, _) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404 (empty pool)");
}

/// `POST /eth/v2/validator/aggregate_and_proofs` returns 200.
#[tokio::test]
async fn post_aggregate_and_proofs_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v2/validator/aggregate_and_proofs",
        serde_json::json!([{"message": {}, "signature": format!("0x{}", "aa".repeat(96))}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `POST /eth/v2/validator/aggregate_and_proofs` returns 503 when optimistic.
#[tokio::test]
async fn post_aggregate_and_proofs_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let (status, _) = post_json(
        &router,
        "/eth/v2/validator/aggregate_and_proofs",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `POST /eth/v1/validator/prepare_beacon_proposer` returns 200.
#[tokio::test]
async fn post_prepare_beacon_proposer_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/prepare_beacon_proposer",
        serde_json::json!([{"validator_index": "0", "fee_recipient": "0x0000000000000000000000000000000000000000"}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `POST /eth/v1/validator/register_validator` returns 200.
#[tokio::test]
async fn post_register_validator_returns_200() {
    let router = make_router();
    let pubkey = format!("0x{}", "ab".repeat(48));
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/register_validator",
        serde_json::json!([{
            "message": {
                "pubkey": pubkey,
                "fee_recipient": "0x0000000000000000000000000000000000000000",
                "gas_limit": "30000000",
                "timestamp": "1000000",
            },
            "signature": format!("0x{}", "cc".repeat(96)),
        }]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `POST /eth/v1/validator/beacon_committee_subscriptions` returns 200.
#[tokio::test]
async fn post_beacon_committee_subscriptions_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/beacon_committee_subscriptions",
        serde_json::json!([{"validator_index": "0", "committee_index": "0", "slot": "100", "is_aggregator": false}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `POST /eth/v1/validator/sync_committee_subscriptions` returns 200.
#[tokio::test]
async fn post_sync_committee_subscriptions_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/sync_committee_subscriptions",
        serde_json::json!([{"validator_index": "0", "sync_committee_indices": ["0"], "until_epoch": "10"}]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

// ── 5.3 tests: sync-committee routes ─────────────────────────────────────────

/// `GET /eth/v1/validator/sync_committee_contribution` returns 503 when optimistic.
#[tokio::test]
async fn get_sync_committee_contribution_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let root = format!("0x{}", "ab".repeat(32));
    let path = format!(
        "/eth/v1/validator/sync_committee_contribution?slot=96&beacon_block_root={root}&subcommittee_index=0"
    );
    let (status, _) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `GET /eth/v1/validator/sync_committee_contribution` returns 404 (no pool) on healthy node.
#[tokio::test]
async fn get_sync_committee_contribution_returns_404_when_empty() {
    let router = make_router();
    let root = format!("0x{}", "ab".repeat(32));
    let path = format!(
        "/eth/v1/validator/sync_committee_contribution?slot=96&beacon_block_root={root}&subcommittee_index=0"
    );
    let (status, _) = get_json(&router, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404 (empty pool)");
}

/// `POST /eth/v1/validator/contribution_and_proofs` returns 200.
#[tokio::test]
async fn post_contribution_and_proofs_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/contribution_and_proofs",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `POST /eth/v1/validator/contribution_and_proofs` returns 503 when optimistic.
#[tokio::test]
async fn post_contribution_and_proofs_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/contribution_and_proofs",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `POST /eth/v1/validator/beacon_committee_selections` returns 200 with identity pass-through.
#[tokio::test]
async fn post_beacon_committee_selections_returns_200_with_echo() {
    let router = make_router();
    let body = serde_json::json!([{"validator_index": "0", "slot": "100", "selection_proof": format!("0x{}", "bb".repeat(96))}]);
    let (status, json) = post_json(
        &router,
        "/eth/v1/validator/beacon_committee_selections",
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array(), "data must be present");
}

/// `POST /eth/v1/validator/beacon_committee_selections` returns 503 when optimistic.
#[tokio::test]
async fn post_beacon_committee_selections_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/beacon_committee_selections",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `POST /eth/v1/validator/sync_committee_selections` returns 200 with identity pass-through.
#[tokio::test]
async fn post_sync_committee_selections_returns_200_with_echo() {
    let router = make_router();
    let body = serde_json::json!([{"validator_index": "0", "slot": "100", "subcommittee_index": "0", "selection_proof": format!("0x{}", "cc".repeat(96))}]);
    let (status, json) = post_json(
        &router,
        "/eth/v1/validator/sync_committee_selections",
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array(), "data must be present");
}

/// `POST /eth/v1/validator/sync_committee_selections` returns 503 when optimistic.
#[tokio::test]
async fn post_sync_committee_selections_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/sync_committee_selections",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

// ── 5.4 tests: liveness endpoint ─────────────────────────────────────────────

/// `POST /eth/v1/validator/liveness/1` returns 200 with `is_live: true` for epoch 1.
#[tokio::test]
async fn post_validator_liveness_returns_200() {
    let router = make_router();
    let (status, json) = post_json(
        &router,
        "/eth/v1/validator/liveness/1",
        serde_json::json!(["0", "1", "2"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    let data = json["data"].as_array().expect("data must be array");
    assert_eq!(data.len(), 3, "must have 3 entries");
    for entry in data {
        assert!(entry["index"].is_string(), "index must be string");
        assert!(entry["is_live"].is_boolean(), "is_live must be boolean");
        // epoch 1 → is_live=true per our HealthyMock impl.
        assert_eq!(entry["is_live"], true);
    }
}

/// `POST /eth/v1/validator/liveness/2` returns 200 with `is_live: false` for epoch != 1.
#[tokio::test]
async fn post_validator_liveness_returns_false_for_other_epochs() {
    let router = make_router();
    let (status, json) = post_json(
        &router,
        "/eth/v1/validator/liveness/2",
        serde_json::json!(["0"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    let data = json["data"].as_array().expect("data must be array");
    assert_eq!(data[0]["is_live"], false);
}

/// `POST /eth/v1/validator/liveness/1` returns 400 for empty body.
#[tokio::test]
async fn post_validator_liveness_returns_400_on_empty_body() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/validator/liveness/1",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400 for empty body"
    );
}

// ── 5.5 tests: beacon block publish ──────────────────────────────────────────

/// `POST /eth/v1/beacon/blocks` returns 202 (broadcast-only, default impl).
#[tokio::test]
async fn post_beacon_blocks_v1_returns_202() {
    let router = make_router();
    let block = serde_json::json!({"message": {}, "signature": format!("0x{}", "aa".repeat(96))});
    let (status, _) = post_json(&router, "/eth/v1/beacon/blocks", block).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "expected 202 (broadcast-only)"
    );
}

/// `POST /eth/v2/beacon/blocks` returns 202 (broadcast-only, default impl).
#[tokio::test]
async fn post_beacon_blocks_v2_returns_202() {
    let router = make_router();
    let block = serde_json::json!({"message": {}, "signature": format!("0x{}", "aa".repeat(96))});
    let (status, _) = post_json(&router, "/eth/v2/beacon/blocks", block).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "expected 202 (broadcast-only)"
    );
}

/// `POST /eth/v1/beacon/blocks` returns 503 when optimistic.
#[tokio::test]
async fn post_beacon_blocks_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let block = serde_json::json!({"message": {}, "signature": format!("0x{}", "aa".repeat(96))});
    let (status, _) = post_json(&router, "/eth/v1/beacon/blocks", block).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

/// `POST /eth/v2/beacon/blocks` returns 503 when optimistic.
#[tokio::test]
async fn post_beacon_blocks_v2_returns_503_when_optimistic() {
    let router = make_optimistic_router();
    let block = serde_json::json!({"message": {}, "signature": format!("0x{}", "aa".repeat(96))});
    let (status, _) = post_json(&router, "/eth/v2/beacon/blocks", block).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "expected 503");
}

// ── 5.6 tests: beacon pool routes ────────────────────────────────────────────

/// `GET /eth/v1/beacon/pool/attestations` returns 200 with `data` array.
#[tokio::test]
async fn get_pool_attestations_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/pool/attestations").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array(), "data must be array");
}

/// `POST /eth/v1/beacon/pool/attestations` returns 200 with valid attestation data.
#[tokio::test]
async fn post_pool_attestations_returns_200() {
    let router = make_router();
    // Construct a valid attestation JSON (aggregation_bits = single byte 0x01,
    // data has all required fields with correct types).
    let att = serde_json::json!({
        "aggregation_bits": "0x01",
        "data": {
            "slot": "96",
            "index": "0",
            "beacon_block_root": format!("0x{}", "ab".repeat(32)),
            "source": {"epoch": "0", "root": format!("0x{}", "00".repeat(32))},
            "target": {"epoch": "3", "root": format!("0x{}", "cd".repeat(32))},
        },
        "signature": format!("0x{}", "aa".repeat(96)),
    });
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/attestations",
        serde_json::json!([att]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `POST /eth/v1/beacon/pool/attestations` returns 400 for malformed body.
#[tokio::test]
async fn post_pool_attestations_returns_400_on_invalid_body() {
    let router = make_router();
    let att = serde_json::json!({"aggregation_bits": "0x01", "data": {}, "signature": format!("0x{}", "aa".repeat(96))});
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/attestations",
        serde_json::json!([att]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400 for malformed attestation"
    );
}

/// `GET /eth/v1/beacon/pool/attester_slashings` returns 200 with `data` array.
#[tokio::test]
async fn get_pool_attester_slashings_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/pool/attester_slashings").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array());
}

/// `POST /eth/v1/beacon/pool/attester_slashings` returns 200.
#[tokio::test]
async fn post_pool_attester_slashings_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/attester_slashings",
        serde_json::json!({"attestation_1": {}, "attestation_2": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `GET /eth/v1/beacon/pool/proposer_slashings` returns 200 with `data` array.
#[tokio::test]
async fn get_pool_proposer_slashings_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/pool/proposer_slashings").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array());
}

/// `POST /eth/v1/beacon/pool/proposer_slashings` returns 200.
#[tokio::test]
async fn post_pool_proposer_slashings_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/proposer_slashings",
        serde_json::json!({"signed_header_1": {}, "signed_header_2": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `GET /eth/v1/beacon/pool/voluntary_exits` returns 200 with `data` array.
#[tokio::test]
async fn get_pool_voluntary_exits_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/pool/voluntary_exits").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array());
}

/// `POST /eth/v1/beacon/pool/voluntary_exits` returns 200.
#[tokio::test]
async fn post_pool_voluntary_exits_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/voluntary_exits",
        serde_json::json!({"message": {"epoch": "0", "validator_index": "0"}, "signature": format!("0x{}", "aa".repeat(96))}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `GET /eth/v1/beacon/pool/bls_to_execution_changes` returns 200 with `data` array.
#[tokio::test]
async fn get_pool_bls_to_execution_changes_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/pool/bls_to_execution_changes").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array());
}

/// `POST /eth/v1/beacon/pool/bls_to_execution_changes` returns 200.
#[tokio::test]
async fn post_pool_bls_to_execution_changes_returns_200() {
    let router = make_router();
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/bls_to_execution_changes",
        serde_json::json!([]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

/// `GET /eth/v1/beacon/pool/sync_committees` returns 200 with `data` array.
#[tokio::test]
async fn get_pool_sync_committees_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/beacon/pool/sync_committees").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    assert!(json["data"].is_array());
}

/// `POST /eth/v1/beacon/pool/sync_committees` returns 200.
#[tokio::test]
async fn post_pool_sync_committees_returns_200() {
    let router = make_router();
    let msg = serde_json::json!({"slot": "100", "beacon_block_root": format!("0x{}", "ab".repeat(32)), "validator_index": "0", "signature": format!("0x{}", "aa".repeat(96))});
    let (status, _) = post_json(
        &router,
        "/eth/v1/beacon/pool/sync_committees",
        serde_json::json!([msg]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected 200");
}

// ── 5.7 tests: node peers / peer_count ────────────────────────────────────────

/// `GET /eth/v1/node/peers` returns 200 with `data` array containing one peer.
#[tokio::test]
async fn get_node_peers_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/node/peers").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    let data = json["data"].as_array().expect("data must be array");
    assert_eq!(data.len(), 1, "expected 1 peer from mock");
    assert!(data[0]["peer_id"].is_string());
    assert_eq!(data[0]["state"], "connected");
}

/// `GET /eth/v1/node/peer_count` returns 200 with connected count.
#[tokio::test]
async fn get_node_peer_count_returns_200() {
    let router = make_router();
    let (status, json) = get_json(&router, "/eth/v1/node/peer_count").await;
    assert_eq!(status, StatusCode::OK, "expected 200: {json}");
    let data = &json["data"];
    assert!(
        data["connected"].is_string(),
        "connected must be quoted string"
    );
    assert_eq!(
        data["connected"].as_str().unwrap(),
        "1",
        "expected 1 connected peer"
    );
    assert_eq!(data["disconnecting"].as_str().unwrap(), "0");
    assert_eq!(data["disconnected"].as_str().unwrap(), "0");
    assert_eq!(data["connecting"].as_str().unwrap(), "0");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// POST JSON with an explicit extra header (used by v2 pool endpoints that
/// require `Eth-Consensus-Version`).
async fn post_json_with_header(
    router: &axum::Router,
    path: &str,
    body: JsonValue,
    header_name: &str,
    header_value: &str,
) -> (StatusCode, JsonValue) {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header_name, header_value)
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null);
    (status, json)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `POST /eth/v2/beacon/pool/attestations` with `electra` header and a valid
/// `SingleAttestation` body returns 200.
///
/// Per `attestations.v2.yaml`: electra+ → array of `Electra.SingleAttestation`
/// fields: `committee_index`, `attester_index`, `data`, `signature`.
#[tokio::test]
async fn pool_v2_post_electra_single_attestation() {
    let router = make_router();
    let single_att = serde_json::json!({
        "committee_index": "0",
        "attester_index": "1",
        "data": {
            "slot": "96",
            "index": "0",
            "beacon_block_root": format!("0x{}", "ab".repeat(32)),
            "source": {"epoch": "0", "root": format!("0x{}", "00".repeat(32))},
            "target": {"epoch": "3", "root": format!("0x{}", "cd".repeat(32))},
        },
        "signature": format!("0x{}", "aa".repeat(96)),
    });
    let (status, _) = post_json_with_header(
        &router,
        "/eth/v2/beacon/pool/attestations",
        serde_json::json!([single_att]),
        "eth-consensus-version",
        "electra",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 for electra SingleAttestation"
    );
}

/// `POST /eth/v2/beacon/pool/attestations` with `phase0` header and a valid
/// `Phase0.Attestation` body returns 200.
///
/// Per `attestations.v2.yaml`: pre-electra → array of `Phase0.Attestation`
/// fields: `aggregation_bits`, `data`, `signature`.
#[tokio::test]
async fn pool_v2_post_phase0_attestation() {
    let router = make_router();
    let att = serde_json::json!({
        "aggregation_bits": "0x01",
        "data": {
            "slot": "96",
            "index": "0",
            "beacon_block_root": format!("0x{}", "ab".repeat(32)),
            "source": {"epoch": "0", "root": format!("0x{}", "00".repeat(32))},
            "target": {"epoch": "3", "root": format!("0x{}", "cd".repeat(32))},
        },
        "signature": format!("0x{}", "aa".repeat(96)),
    });
    let (status, _) = post_json_with_header(
        &router,
        "/eth/v2/beacon/pool/attestations",
        serde_json::json!([att]),
        "eth-consensus-version",
        "phase0",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 for phase0 Attestation"
    );
}

/// `POST /eth/v2/beacon/pool/attestations` without the required
/// `Eth-Consensus-Version` header returns 400.
///
/// Per `attestations.v2.yaml`: header is `required: true`.
#[tokio::test]
async fn pool_v2_post_missing_header_400() {
    let router = make_router();
    let att = serde_json::json!([{
        "aggregation_bits": "0x01",
        "data": {},
        "signature": format!("0x{}", "aa".repeat(96)),
    }]);
    let body_bytes = serde_json::to_vec(&att).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/eth/v2/beacon/pool/attestations")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "expected 400 for missing Eth-Consensus-Version"
    );
}

/// `POST /eth/v2/beacon/pool/attestations` with an unknown fork string in
/// `Eth-Consensus-Version` returns 400.
#[tokio::test]
async fn pool_v2_post_unknown_fork_400() {
    let router = make_router();
    let (status, _) = post_json_with_header(
        &router,
        "/eth/v2/beacon/pool/attestations",
        serde_json::json!([]),
        "eth-consensus-version",
        "merkel",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected 400 for unknown fork name"
    );
}

/// `GET /eth/v2/beacon/pool/attestations` returns 200 with `{version, data}`
/// envelope and `Eth-Consensus-Version` response header.
///
/// Per `attestations.v2.yaml` (getPoolAttestationsV2): required fields are
/// `version` (enum string) and `data` (array).
#[tokio::test]
async fn pool_v2_get_attestations_shape() {
    let router = make_router();
    let req = Request::builder()
        .uri("/eth/v2/beacon/pool/attestations")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "expected 200");

    // Verify Eth-Consensus-Version response header is present.
    let header_val = resp
        .headers()
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header must be present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !header_val.is_empty(),
        "Eth-Consensus-Version header must not be empty"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json: JsonValue = serde_json::from_slice(&bytes).unwrap();

    // `version` must be a string from the enum.
    assert!(
        json["version"].is_string(),
        "version field must be present and a string"
    );
    // `data` must be an array.
    assert!(
        json["data"].is_array(),
        "data field must be present and an array"
    );
    // The version in the body must match the header.
    assert_eq!(
        json["version"].as_str().unwrap(),
        header_val,
        "version body field must match Eth-Consensus-Version header"
    );
}

/// `POST /eth/v2/beacon/pool/attester_slashings` with `electra` header and a
/// valid `Electra.AttesterSlashing` body returns 200.
///
/// Per `attester_slashings.v2.yaml` (submitPoolAttesterSlashingsV2):
/// fields: `attestation_1`, `attestation_2` each with
/// `attesting_indices`, `data`, `signature`.
#[tokio::test]
async fn pool_v2_post_attester_slashing_electra() {
    let router = make_router();
    let indexed_att = serde_json::json!({
        "attesting_indices": ["0", "1"],
        "data": {
            "slot": "96",
            "index": "0",
            "beacon_block_root": format!("0x{}", "ab".repeat(32)),
            "source": {"epoch": "0", "root": format!("0x{}", "00".repeat(32))},
            "target": {"epoch": "3", "root": format!("0x{}", "cd".repeat(32))},
        },
        "signature": format!("0x{}", "aa".repeat(96)),
    });
    let slashing = serde_json::json!({
        "attestation_1": indexed_att,
        "attestation_2": indexed_att,
    });
    let (status, _) = post_json_with_header(
        &router,
        "/eth/v2/beacon/pool/attester_slashings",
        slashing,
        "eth-consensus-version",
        "electra",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 for electra AttesterSlashing"
    );
}

/// `POST /eth/v2/beacon/pool/attester_slashings` with `phase0` header and a
/// valid `Phase0.AttesterSlashing` body returns 200.
///
/// Per `attester_slashings.v2.yaml`: pre-electra body is `Phase0.AttesterSlashing`.
#[tokio::test]
async fn pool_v2_post_attester_slashing_phase0() {
    let router = make_router();
    let indexed_att = serde_json::json!({
        "attesting_indices": ["0", "1"],
        "data": {
            "slot": "96",
            "index": "0",
            "beacon_block_root": format!("0x{}", "ab".repeat(32)),
            "source": {"epoch": "0", "root": format!("0x{}", "00".repeat(32))},
            "target": {"epoch": "3", "root": format!("0x{}", "cd".repeat(32))},
        },
        "signature": format!("0x{}", "aa".repeat(96)),
    });
    let slashing = serde_json::json!({
        "attestation_1": indexed_att,
        "attestation_2": indexed_att,
    });
    let (status, _) = post_json_with_header(
        &router,
        "/eth/v2/beacon/pool/attester_slashings",
        slashing,
        "eth-consensus-version",
        "phase0",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 for phase0 AttesterSlashing"
    );
}

/// `GET /eth/v2/beacon/pool/attester_slashings` returns 200 with `{version, data}`
/// envelope and `Eth-Consensus-Version` response header.
///
/// Per `attester_slashings.v2.yaml` (getPoolAttesterSlashingsV2): required
/// fields are `version` (enum string) and `data` (array).
#[tokio::test]
async fn pool_v2_get_attester_slashings_shape() {
    let router = make_router();
    let req = Request::builder()
        .uri("/eth/v2/beacon/pool/attester_slashings")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "expected 200");

    // Verify Eth-Consensus-Version response header is present.
    let header_val = resp
        .headers()
        .get("eth-consensus-version")
        .expect("Eth-Consensus-Version header must be present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !header_val.is_empty(),
        "Eth-Consensus-Version header must not be empty"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json: JsonValue = serde_json::from_slice(&bytes).unwrap();

    // `version` must be a string from the enum.
    assert!(
        json["version"].is_string(),
        "version field must be present and a string"
    );
    // `data` must be an array.
    assert!(
        json["data"].is_array(),
        "data field must be present and an array"
    );
    // The version in the body must match the header.
    assert_eq!(
        json["version"].as_str().unwrap(),
        header_val,
        "version body field must match Eth-Consensus-Version header"
    );
}

/// POST electra `SingleAttestation` lands in pool — a subsequent GET returns it.
///
/// This proves BLOCKER 1 is wired: `submit_single_attestations` actually stores
/// attestations rather than silently dropping them, and `pool_attestations`
/// returns the stored entries.
#[tokio::test]
async fn pool_v2_electra_single_att_post_lands_in_pool() {
    let router = make_pool_router();

    let sig = format!("0x{}", "aa".repeat(96));
    let bbr = format!("0x{}", "ab".repeat(32));
    let zero_root = format!("0x{}", "00".repeat(32));
    let cd_root = format!("0x{}", "cd".repeat(32));

    let single_att = serde_json::json!({
        "committee_index": "2",
        "attester_index": "7",
        "data": {
            "slot": "96",
            "index": "0",
            "beacon_block_root": bbr,
            "source": {"epoch": "0", "root": zero_root},
            "target": {"epoch": "3", "root": cd_root},
        },
        "signature": sig,
    });

    // POST to v2 pool with electra header.
    let (post_status, _) = post_json_with_header(
        &router,
        "/eth/v2/beacon/pool/attestations",
        serde_json::json!([single_att]),
        "eth-consensus-version",
        "electra",
    )
    .await;
    assert_eq!(post_status, StatusCode::OK, "POST must return 200");

    // GET v2 pool — the attestation must appear in data.
    let req = Request::builder()
        .uri("/eth/v2/beacon/pool/attestations")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET must return 200");

    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json: JsonValue = serde_json::from_slice(&bytes).unwrap();

    let data = json["data"].as_array().expect("data must be array");
    assert_eq!(data.len(), 1, "exactly one attestation must be in the pool");

    // The attestation must carry committee_bits (electra fork shape).
    assert!(
        data[0]["committee_bits"]
            .as_str()
            .unwrap_or("")
            .starts_with("0x"),
        "electra Attestation must have committee_bits hex field"
    );
    // data.slot must be preserved.
    assert_eq!(
        data[0]["data"]["slot"].as_str().unwrap(),
        "96",
        "slot must be preserved through pool round-trip"
    );
}
