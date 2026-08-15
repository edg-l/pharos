//! Integration tests for `GET /eth/v1/events` (SSE stream).
//!
//! Tests:
//! - Happy-path: subscribe to `head` + `finalized_checkpoint`, push events on
//!   the bus, verify SSE frames arrive with correct `event:` + `data:` fields.
//! - Topic filtering: a `block` event is NOT delivered to a subscriber that
//!   only requested `head`.
//! - Unknown topic returns 400.
//! - `payload_attributes` (never emitted) is accepted without 400.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use libp2p::PeerId;
use pharos_api::{
    ApiEvent, ApiState, ChainStateApi, EventBus, NodeIdentityCache, RegenTarget, build_router,
    events::{BlockEventDto, FinalizedCheckpointEventDto, HeadEventDto},
};
use pharos_network::discovery::enr::Enr;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::{Epoch, Root, Slot};
use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
use pharos_types::{EthSpec, MainnetEthSpec};
use tower::ServiceExt as _;

// ── Mock ChainStateApi ────────────────────────────────────────────────────────

struct MockChain {
    identity: NodeIdentityCache,
    runtime_cfg: Arc<RuntimeConfig>,
}

impl MockChain {
    fn new() -> Self {
        let key = discv5::enr::CombinedKey::generate_secp256k1();
        let enr: Enr = discv5::enr::Enr::builder().build(&key).expect("build ENR");
        let meta = Arc::new(ArcSwap::from_pointee(AltairMetaData::default()));
        let identity = NodeIdentityCache {
            peer_id: PeerId::random(),
            enr,
            listen_addrs: vec![],
            discovery_addrs: vec![],
            metadata: meta,
        };
        let runtime_cfg = Arc::new(MainnetEthSpec::default_runtime_config());
        Self {
            identity,
            runtime_cfg,
        }
    }
}

impl ChainStateApi<MainnetEthSpec> for MockChain {
    fn head_root(&self) -> Root {
        Root::default()
    }
    fn current_slot(&self) -> Slot {
        Slot::from(0u64)
    }
    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        (0, Root::default(), [0u8; 4])
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
    ) -> Result<<MainnetEthSpec as EthSpec>::BeaconState, pharos_api::ApiError> {
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
        state: <MainnetEthSpec as pharos_types::EthSpec>::BeaconState,
    ) -> Result<serde_json::Value, pharos_api::ApiError> {
        pharos_api::beacon_state_to_json_full::<MainnetEthSpec>(state)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_router_with_bus() -> (axum::Router, Arc<EventBus>) {
    let chain: Arc<dyn ChainStateApi<MainnetEthSpec>> = Arc::new(MockChain::new());
    let bus = EventBus::new();
    let state = ApiState::new_with_bus(chain, Arc::clone(&bus));
    (build_router(state), bus)
}

/// Parse SSE events from a raw byte string.
///
/// Returns a list of `(event_type, data_json_str)` pairs.
fn parse_sse(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut event_type = String::new();
    let mut data = String::new();

    for line in raw.lines() {
        if line.is_empty() {
            if !data.is_empty() {
                out.push((event_type.clone(), data.clone()));
                event_type.clear();
                data.clear();
            }
        } else if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data = rest.trim().to_string();
        }
    }
    // Flush a final event not followed by a blank line.
    if !data.is_empty() {
        out.push((event_type, data));
    }
    out
}

/// Collect SSE body chunks for `timeout` duration.
///
/// Drives the streaming body and collects all bytes that arrive before the
/// timeout.  Returns the collected raw SSE text.
///
/// Uses `http_body_util::BodyExt` (a transitive dep via axum) to collect frames.
async fn collect_sse(body: axum::body::Body, timeout: Duration) -> String {
    use futures::StreamExt as _;

    let mut collected = Vec::new();
    let stream = body.into_data_stream();
    futures::pin_mut!(stream);

    let _ = tokio::time::timeout(timeout, async {
        while let Some(chunk) = stream.next().await {
            if let Ok(bytes) = chunk {
                collected.extend_from_slice(&bytes);
            }
        }
    })
    .await;

    String::from_utf8_lossy(&collected).into_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Push a `head` and a `finalized_checkpoint` event; verify both arrive with
/// correct `event:` labels and properly-shaped JSON `data:` payloads.
#[tokio::test]
async fn sse_head_and_finalized_checkpoint_delivered() {
    let (router, bus) = make_router_with_bus();

    // Spawn sender task: waits 50 ms (so the SSE handler subscribes first),
    // then pushes events.
    let tx = bus.sender();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let head = ApiEvent::Head(HeadEventDto {
            slot: 42,
            block: [0xab; 32],
            state: [0xcd; 32],
            epoch_transition: false,
            previous_duty_dependent_root: [0u8; 32],
            current_duty_dependent_root: [0u8; 32],
            execution_optimistic: false,
        });
        let fc = ApiEvent::FinalizedCheckpoint(FinalizedCheckpointEventDto {
            block: [0xef; 32],
            state: [0x12; 32],
            epoch: 2,
            execution_optimistic: false,
        });
        tx.send(head).ok();
        tx.send(fc).ok();
    });

    let req = Request::builder()
        .uri("/eth/v1/events?topics=head&topics=finalized_checkpoint")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("text/event-stream"),
        "content-type must be text/event-stream"
    );

    // Collect SSE frames for 500 ms (both events should arrive after 50 ms).
    let raw = collect_sse(resp.into_body(), Duration::from_millis(500)).await;
    let events = parse_sse(&raw);

    assert!(
        events.len() >= 2,
        "expected >= 2 events; got {}: {:?}",
        events.len(),
        raw
    );

    // First event: head
    assert_eq!(events[0].0, "head", "first event topic must be head");
    let head_data: serde_json::Value =
        serde_json::from_str(&events[0].1).expect("head data must be valid JSON");
    assert_eq!(head_data["slot"].as_str().unwrap(), "42");
    assert!(head_data["block"].as_str().unwrap().starts_with("0x"));
    assert_eq!(
        head_data["execution_optimistic"],
        serde_json::Value::Bool(false)
    );
    assert!(head_data["epoch_transition"].is_boolean());
    assert!(
        head_data["previous_duty_dependent_root"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
    assert!(
        head_data["current_duty_dependent_root"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );

    // Second event: finalized_checkpoint
    assert_eq!(
        events[1].0, "finalized_checkpoint",
        "second event must be finalized_checkpoint"
    );
    let fc_data: serde_json::Value =
        serde_json::from_str(&events[1].1).expect("finalized_checkpoint data must be valid JSON");
    assert_eq!(fc_data["epoch"].as_str().unwrap(), "2");
    assert!(fc_data["block"].as_str().unwrap().starts_with("0x"));
    assert!(fc_data["state"].as_str().unwrap().starts_with("0x"));
}

/// A `block` event pushed on the bus is NOT delivered to a subscriber that
/// only requested `head`.  Push block first, then head; only head arrives.
#[tokio::test]
async fn sse_topic_filtering_drops_unsubscribed_events() {
    let (router, bus) = make_router_with_bus();

    let tx = bus.sender();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Push block (should be filtered out).
        let block_ev = ApiEvent::Block(BlockEventDto {
            slot: 1,
            block: [0x01; 32],
            execution_optimistic: false,
        });
        tx.send(block_ev).ok();

        // Push head (should arrive).
        let head_ev = ApiEvent::Head(HeadEventDto {
            slot: 2,
            block: [0x02; 32],
            state: [0x03; 32],
            epoch_transition: false,
            previous_duty_dependent_root: [0u8; 32],
            current_duty_dependent_root: [0u8; 32],
            execution_optimistic: false,
        });
        tx.send(head_ev).ok();
    });

    let req = Request::builder()
        .uri("/eth/v1/events?topics=head")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Collect for 500 ms: the block event is filtered, only head arrives.
    let raw = collect_sse(resp.into_body(), Duration::from_millis(500)).await;
    let events = parse_sse(&raw);

    // At least 1 event (head); block must not appear.
    assert!(
        !events.is_empty(),
        "expected at least 1 event; got 0. raw: {:?}",
        raw
    );
    assert_eq!(events[0].0, "head", "first event must be head, not block");

    let data: serde_json::Value = serde_json::from_str(&events[0].1).unwrap();
    assert_eq!(data["slot"].as_str().unwrap(), "2");

    // Verify no block event crept in.
    for (topic, _) in &events {
        assert_ne!(topic, "block", "block event must be filtered out");
    }
}

/// An unknown topic string must return HTTP 400.
#[tokio::test]
async fn sse_unknown_topic_returns_400() {
    let (router, _bus) = make_router_with_bus();

    let req = Request::builder()
        .uri("/eth/v1/events?topics=weather_forecast")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("weather_forecast"),
        "400 body must name the bad topic"
    );
}

/// Absent `?topics=` query parameter returns HTTP 400.
#[tokio::test]
async fn sse_missing_topics_returns_400() {
    let (router, _bus) = make_router_with_bus();

    let req = Request::builder()
        .uri("/eth/v1/events")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing topics must return 400"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        json["message"].as_str().unwrap().contains("topics"),
        "400 body must mention 'topics'"
    );
}

/// Empty `?topics=` value (e.g. `?topics=`) returns HTTP 400.
#[tokio::test]
async fn sse_empty_topics_returns_400() {
    let (router, _bus) = make_router_with_bus();

    let req = Request::builder()
        .uri("/eth/v1/events?topics=")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty topics must return 400"
    );
}

/// `payload_attributes` is a valid spec topic but is never emitted at M7.
/// A subscriber requesting it must receive a 200 SSE stream, not a 400.
/// Mixing it with `head` still delivers the head frame.
#[tokio::test]
async fn sse_payload_attributes_accepted_not_400() {
    let (router, bus) = make_router_with_bus();

    let tx = bus.sender();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let head_ev = ApiEvent::Head(HeadEventDto {
            slot: 5,
            block: [0x05; 32],
            state: [0x06; 32],
            epoch_transition: false,
            previous_duty_dependent_root: [0u8; 32],
            current_duty_dependent_root: [0u8; 32],
            execution_optimistic: false,
        });
        tx.send(head_ev).ok();
    });

    let req = Request::builder()
        .uri("/eth/v1/events?topics=head&topics=payload_attributes")
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "payload_attributes must not return 400"
    );

    let raw = collect_sse(resp.into_body(), Duration::from_millis(500)).await;
    let events = parse_sse(&raw);

    assert!(!events.is_empty(), "expected at least 1 event (head)");
    assert_eq!(events[0].0, "head");
    let data: serde_json::Value = serde_json::from_str(&events[0].1).unwrap();
    assert_eq!(data["slot"].as_str().unwrap(), "5");
}
