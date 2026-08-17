//! M15-BeaconAPIGaps Phase 6 — rewards endpoint tests (Task 6.9).
//!
//! There are NO beacon-APIs test vectors for rewards, so these tests verify
//! (a) the routes resolve, (b) the JSON response shape matches the cited
//! `~/dev/beacon-APIs/types/rewards.yaml` field names exactly, and (c) the
//! `BlockRewards.total` sum identity holds. The real reward MATH (incl. the
//! per-fork altair / electra-projection dispatch) is proven by the Task 6.3
//! conformance gate (`phase0/rewards` + `altair/rewards` + `electra/operations`
//! all 0-fail after the STF factoring); these tests exercise the handler →
//! `ChainStateApi::*_rewards_data` → serialization path.
//!
//! `D-rewards-no-test-vectors-shape-only`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use libp2p::PeerId;
use pharos_api::{ApiError, ApiState, ChainStateApi, NodeIdentityCache, RegenTarget, build_router};
use pharos_network::discovery::enr::Enr;
use pharos_stf::rewards_api::{
    AttestationReward, AttestationRewardsData, BlockRewardComponents, IdealAttestationReward,
    SyncCommitteeReward,
};
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, SyncCommitteePubkeys};
use serde_json::Value as JsonValue;
use tower::ServiceExt as _;

type State = <MainnetBeaconSpec as BeaconSpec>::BeaconState;

// ── Mock ────────────────────────────────────────────────────────────────────────

/// What the mock returns for each rewards method.
#[derive(Default)]
struct RewardsBehaviour {
    attestation: Option<AttestationRewardsData>,
    block: Option<BlockRewardComponents>,
    sync: Option<Result<Vec<SyncCommitteeReward>, ApiError>>,
}

struct RewardsMock {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
    behaviour: RewardsBehaviour,
}

impl RewardsMock {
    fn new(behaviour: RewardsBehaviour) -> Self {
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
            behaviour,
        }
    }
}

impl ChainStateApi<MainnetBeaconSpec> for RewardsMock {
    fn head_root(&self) -> Root {
        Root::from([0xab; 32])
    }
    fn current_slot(&self) -> Slot {
        Slot(100)
    }
    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        (0, Root::from([0u8; 32]), [0u8; 4])
    }
    fn finalized_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(3),
            root: Root::from([0xf1; 32]),
        }
    }
    fn justified_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(4),
            root: Root::from([0xf2; 32]),
        }
    }
    fn block_header_at(&self, _root: Root) -> Option<BeaconBlockHeader> {
        Some(BeaconBlockHeader {
            slot: Slot(64),
            ..Default::default()
        })
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
        // Resolve numeric block_ids so `resolve_block_id("64")` succeeds.
        Some(Root::from([0xcd; 32]))
    }
    fn genesis_block_root(&self) -> Root {
        Root::from([0u8; 32])
    }
    fn sync_committee_pubkeys(&self, _root: Root) -> Option<SyncCommitteePubkeys> {
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
    fn regenerate_state(&self, _target: RegenTarget) -> Result<State, ApiError> {
        Err(ApiError::NotFound("regen not available in mock".into()))
    }
    fn state_to_json(&self, _state: State) -> Result<JsonValue, ApiError> {
        Ok(serde_json::json!({}))
    }
    fn fork_choice_dump(&self) -> Result<JsonValue, ApiError> {
        Ok(serde_json::json!({}))
    }
    fn fork_choice_heads(&self) -> Result<JsonValue, ApiError> {
        Ok(serde_json::json!({ "data": [] }))
    }

    // ── rewards overrides ──────────────────────────────────────────────────────
    fn attestation_rewards_data(
        &self,
        _epoch: u64,
        _ids: Option<Vec<String>>,
    ) -> Result<AttestationRewardsData, ApiError> {
        match &self.behaviour.attestation {
            Some(d) => Ok(d.clone()),
            None => Err(ApiError::NotFound("epoch not known".into())),
        }
    }
    fn block_rewards_data(&self, _block_root: Root) -> Result<BlockRewardComponents, ApiError> {
        match &self.behaviour.block {
            Some(c) => Ok(*c),
            None => Err(ApiError::NotFound("block not found".into())),
        }
    }
    fn sync_committee_rewards_data(
        &self,
        _block_root: Root,
        _ids: Option<Vec<String>>,
    ) -> Result<Vec<SyncCommitteeReward>, ApiError> {
        match &self.behaviour.sync {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(e)) => Err(clone_err(e)),
            None => Err(ApiError::NotFound("block not found".into())),
        }
    }
}

fn clone_err(e: &ApiError) -> ApiError {
    match e {
        ApiError::BadRequest(m) => ApiError::BadRequest(m.clone()),
        ApiError::Unauthorized(m) => ApiError::Unauthorized(m.clone()),
        ApiError::Forbidden(m) => ApiError::Forbidden(m.clone()),
        ApiError::NotFound(m) => ApiError::NotFound(m.clone()),
        ApiError::NotAcceptable(m) => ApiError::NotAcceptable(m.clone()),
        ApiError::Internal(m) => ApiError::Internal(m.clone()),
        ApiError::NotSynced(m) => ApiError::NotSynced(m.clone()),
    }
}

fn router(behaviour: RewardsBehaviour) -> axum::Router {
    let chain: Arc<dyn ChainStateApi<MainnetBeaconSpec>> = Arc::new(RewardsMock::new(behaviour));
    build_router(ApiState::new(chain))
}

async fn body_json(resp: axum::response::Response) -> JsonValue {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Fixtures ────────────────────────────────────────────────────────────────────

fn altair_attestation_data() -> AttestationRewardsData {
    AttestationRewardsData {
        ideal_rewards: vec![IdealAttestationReward {
            effective_balance: 32_000_000_000,
            head: 2500,
            target: 5000,
            source: 5000,
            inclusion_delay: None,
            inactivity: 0,
        }],
        total_rewards: vec![AttestationReward {
            validator_index: 0,
            head: 2000,
            target: 2000,
            source: 4000,
            inclusion_delay: None,
            inactivity: -1,
        }],
    }
}

fn phase0_attestation_data() -> AttestationRewardsData {
    AttestationRewardsData {
        ideal_rewards: vec![IdealAttestationReward {
            effective_balance: 32_000_000_000,
            head: 0,
            target: 0,
            source: 0,
            inclusion_delay: Some(0),
            inactivity: 0,
        }],
        total_rewards: vec![AttestationReward {
            validator_index: 0,
            head: 2000,
            target: 2000,
            source: 4000,
            inclusion_delay: Some(123),
            inactivity: 0,
        }],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn attestation_rewards_altair_shape() {
    let app = router(RewardsBehaviour {
        attestation: Some(altair_attestation_data()),
        ..Default::default()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/eth/v1/beacon/rewards/attestations/5")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert!(v["execution_optimistic"].is_boolean());
    assert!(v["finalized"].is_boolean());
    let data = &v["data"];
    let total = &data["total_rewards"][0];
    // Required AttestationRewards fields per types/rewards.yaml.
    for f in ["validator_index", "head", "target", "source", "inactivity"] {
        assert!(total[f].is_string(), "missing total_rewards field {f}");
    }
    // altair → NO inclusion_delay.
    assert!(total.get("inclusion_delay").is_none());
    // Signed values round-trip (negative inactivity).
    assert_eq!(total["inactivity"], "-1");
    let ideal = &data["ideal_rewards"][0];
    for f in [
        "effective_balance",
        "head",
        "target",
        "source",
        "inactivity",
    ] {
        assert!(ideal[f].is_string(), "missing ideal_rewards field {f}");
    }
    assert!(ideal.get("inclusion_delay").is_none());
}

#[tokio::test]
async fn attestation_rewards_phase0_has_inclusion_delay() {
    let app = router(RewardsBehaviour {
        attestation: Some(phase0_attestation_data()),
        ..Default::default()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/eth/v1/beacon/rewards/attestations/5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let total = &v["data"]["total_rewards"][0];
    // phase0 → inclusion_delay present (Uint64 string).
    assert_eq!(total["inclusion_delay"], "123");
    let ideal = &v["data"]["ideal_rewards"][0];
    assert_eq!(ideal["inclusion_delay"], "0");
}

#[tokio::test]
async fn attestation_rewards_unknown_epoch_404() {
    // No attestation behaviour → mock returns NotFound → 404.
    let app = router(RewardsBehaviour::default());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/eth/v1/beacon/rewards/attestations/999999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn block_rewards_shape_and_total_identity() {
    let components = BlockRewardComponents {
        proposer_index: 123,
        attestations: 1000,
        sync_aggregate: 200,
        proposer_slashings: 50,
        attester_slashings: 30,
    };
    let app = router(RewardsBehaviour {
        block: Some(components),
        ..Default::default()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/eth/v1/beacon/rewards/blocks/head")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let data = &v["data"];
    for f in [
        "proposer_index",
        "total",
        "attestations",
        "sync_aggregate",
        "proposer_slashings",
        "attester_slashings",
    ] {
        assert!(data[f].is_string(), "missing BlockRewards field {f}");
    }
    // total == attestations + sync_aggregate + proposer_slashings + attester_slashings.
    let total: u64 = data["total"].as_str().unwrap().parse().unwrap();
    let parts: u64 = [
        "attestations",
        "sync_aggregate",
        "proposer_slashings",
        "attester_slashings",
    ]
    .iter()
    .map(|f| data[*f].as_str().unwrap().parse::<u64>().unwrap())
    .sum();
    assert_eq!(total, parts);
    assert_eq!(total, 1280);
    assert_eq!(data["proposer_index"], "123");
}

#[tokio::test]
async fn block_rewards_not_found_404() {
    let app = router(RewardsBehaviour::default());
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/eth/v1/beacon/rewards/blocks/head")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sync_committee_rewards_shape() {
    let rewards = vec![
        SyncCommitteeReward {
            validator_index: 7,
            reward: 2000,
        },
        SyncCommitteeReward {
            validator_index: 9,
            reward: -2000,
        },
    ];
    let app = router(RewardsBehaviour {
        sync: Some(Ok(rewards)),
        ..Default::default()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/eth/v1/beacon/rewards/sync_committee/head")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let arr = v["data"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    for entry in arr {
        assert!(entry["validator_index"].is_string());
        assert!(entry["reward"].is_string());
    }
    // Signed reward round-trips (negative for non-participant).
    assert_eq!(arr[0]["reward"], "2000");
    assert_eq!(arr[1]["reward"], "-2000");
}

#[tokio::test]
async fn sync_committee_rewards_pre_altair_400() {
    let app = router(RewardsBehaviour {
        sync: Some(Err(ApiError::BadRequest(
            "sync committee rewards are not available before altair".into(),
        ))),
        ..Default::default()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/eth/v1/beacon/rewards/sync_committee/head")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
