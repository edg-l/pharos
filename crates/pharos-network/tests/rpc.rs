mod common;

use std::time::Duration;

use common::{CapturingScorer, NetworkEvent, TestHost, spawn_node, spawn_node_with_scorer};
use libp2p::PeerId;
use pharos_network::rpc::types::{
    LightClientBootstrapRequest, LightClientUpdatesByRangeRequest, MetaDataResponse, RpcResponse,
};
use pharos_network::scoring::{RpcMethod, ScoreEvent};
use pharos_network::{NetworkHandle, RpcRequest};
use pharos_ssz::TreeHash;
use pharos_types::MainnetBeaconSpec;
use pharos_types::altair::light_client::{
    LightClientBootstrap, LightClientHeader, LightClientUpdate,
};
use pharos_types::phase0::primitives::{ForkDigest, Root, Slot};
use pharos_types::phase0::{
    BeaconBlocksByRangeRequest, MainnetSignedBeaconBlock as Phase0MainnetBlock,
};
use pharos_types::state::MainnetSignedBeaconBlock;
use tokio::time::timeout;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
const ALTAIR_FORK_DIGEST: [u8; 4] = [0x0a, 0x1b, 0x2c, 0x3d];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

fn altair_fd() -> ForkDigest {
    ForkDigest::from_array(ALTAIR_FORK_DIGEST)
}

/// Wait for `PeerConnected(expected_peer)` on `handle`.
async fn wait_connected(handle: &mut NetworkHandle<MainnetBeaconSpec>, expected_peer: PeerId) {
    timeout(Duration::from_secs(5), async {
        loop {
            match handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == expected_peer => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("PeerConnected not received within 5s");
}

/// Dial B from A and wait for both sides to emit PeerConnected.
async fn connect_and_wait(node_a: &mut common::TestNode, node_b: &mut common::TestNode) {
    node_a
        .handle
        .dial(node_b.listen_addr.clone())
        .await
        .expect("dial failed");
    wait_connected(&mut node_a.handle, node_b.peer_id).await;
    wait_connected(&mut node_b.handle, node_a.peer_id).await;
}

/// Both peers exchange Status on connection. PeerConnected on both sides proves
/// the Status exchange (with matching fork digest) succeeded.
///
/// `ScoreEvent::RpcSuccess { method: Status }` must be recorded on both sides:
/// - Outbound side (A): recorded in `on_status_response` after fork-digest match.
/// - Inbound side (B): recorded in `on_request_response_event` after the inbound
///   Status handler returns `RpcResponse::Status`.
/// Verified via `CapturingScorer` on each side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_handshake() {
    let scorer_a = CapturingScorer::default();
    let scorer_b = CapturingScorer::default();

    let mut node_a =
        spawn_node_with_scorer(vec![], TestHost::new(fd()), false, Some(scorer_a.clone())).await;
    let mut node_b =
        spawn_node_with_scorer(vec![], TestHost::new(fd()), false, Some(scorer_b.clone())).await;

    connect_and_wait(&mut node_a, &mut node_b).await;

    // Give the network task one yield to flush any score events that are
    // recorded after the PeerConnected event is emitted.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Both sides must have recorded ScoreEvent::RpcSuccess { method: Status }.
    assert!(
        scorer_a.0.lock().unwrap().iter().any(
            |e| matches!(e, ScoreEvent::RpcSuccess { method } if *method == RpcMethod::Status)
        ),
        "node A scorer missing ScoreEvent::RpcSuccess {{ method: Status }}"
    );
    assert!(
        scorer_b.0.lock().unwrap().iter().any(
            |e| matches!(e, ScoreEvent::RpcSuccess { method } if *method == RpcMethod::Status)
        ),
        "node B scorer missing ScoreEvent::RpcSuccess {{ method: Status }}"
    );
}

/// A sends Ping(42) to B; B responds with its seq_number (0 from default MetaData).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_round_trip() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let response = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, RpcRequest::Ping(42), Duration::from_secs(5)),
    )
    .await
    .expect("Ping timed out at test level")
    .expect("Ping RPC failed");

    match response {
        RpcResponse::Ping(seq) => assert_eq!(seq, 0, "expected seq_number 0"),
        other => panic!("expected RpcResponse::Ping, got: {other:?}"),
    }
}

/// A sends GetMetaData to B; B responds with default MetaData (seq_number = 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_round_trip() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let response = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, RpcRequest::MetaData, Duration::from_secs(5)),
    )
    .await
    .expect("MetaData timed out at test level")
    .expect("MetaData RPC failed");

    match response {
        RpcResponse::MetaData(meta) => {
            // MetaData v2 response: extract seq_number from the V2 variant.
            use pharos_network::rpc::types::MetaDataResponse;
            let seq = match &meta {
                MetaDataResponse::V2(m) => m.seq_number,
                MetaDataResponse::V1(m) => m.seq_number,
            };
            assert_eq!(seq, 0, "expected default seq_number 0");
        }
        other => panic!("expected RpcResponse::MetaData, got: {other:?}"),
    }
}

/// B preloaded with 5 blocks at slots [10..15]. A sends BeaconBlocksByRange and
/// receives 5 blocks in ascending slot order.
///
/// The historical-window check in `handle_request` (rpc/handler.rs:80) requires:
///   `start_slot >= head_slot - (min_epochs * SLOTS_PER_EPOCH)`
/// For mainnet: min_epochs = 33024, SLOTS_PER_EPOCH = 32, offset = 1,056,768.
/// We set `head_slot = 1,056,778` so `oldest_allowed = 10` (slot 10 is exactly
/// the boundary). This is set via `TestHost::with_head_slot`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocks_by_range_request() {
    let mut blocks_for_b: Vec<(pharos_types::phase0::Root, MainnetSignedBeaconBlock)> = Vec::new();
    for slot_num in 10u64..15 {
        let mut inner = Phase0MainnetBlock::default();
        inner.message.slot = Slot(slot_num);
        let root = inner.message.tree_hash_root();
        blocks_for_b.push((root, MainnetSignedBeaconBlock::Phase0(inner)));
    }

    // head_slot = 1,056,778: oldest_allowed = 1,056,778 - 1,056,768 = 10. slot 10 >= 10. OK.
    let b_host = TestHost::new(fd())
        .with_blocks(blocks_for_b)
        .with_head_slot(Slot(1_056_778));

    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], b_host, false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let req = RpcRequest::BlocksByRange(BeaconBlocksByRangeRequest {
        start_slot: Slot(10),
        count: 5,
        step: 1,
    });

    let response = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, req, Duration::from_secs(5)),
    )
    .await
    .expect("BlocksByRange timed out at test level")
    .expect("BlocksByRange RPC failed");

    match response {
        RpcResponse::BlocksByRange(blocks) => {
            assert_eq!(blocks.len(), 5, "expected 5 blocks, got {}", blocks.len());
            for (i, block) in blocks.iter().enumerate() {
                let slot = match block {
                    MainnetSignedBeaconBlock::Phase0(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Altair(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Bellatrix(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Capella(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Deneb(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Electra(inner) => inner.message.slot.0,
                };
                assert_eq!(slot, 10 + i as u64, "block {i} slot mismatch");
            }
        }
        other => panic!("expected RpcResponse::BlocksByRange, got: {other:?}"),
    }
}

/// A sends BeaconBlocksByRoot([root_a, root_b]) to B; B responds with both blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocks_by_root_request() {
    use pharos_ssz::SszList;
    use pharos_types::phase0::BeaconBlocksByRootRequest;

    let mut inner_a = Phase0MainnetBlock::default();
    inner_a.message.slot = Slot(100);
    let root_a = inner_a.message.tree_hash_root();
    let block_a = MainnetSignedBeaconBlock::Phase0(inner_a);

    let mut inner_b = Phase0MainnetBlock::default();
    inner_b.message.slot = Slot(200);
    let root_b = inner_b.message.tree_hash_root();
    let block_b_val = MainnetSignedBeaconBlock::Phase0(inner_b);

    let b_host = TestHost::new(fd()).with_blocks(vec![(root_a, block_a), (root_b, block_b_val)]);

    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], b_host, false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let roots = SszList::<pharos_types::phase0::Root, 1024>::from_vec(vec![root_a, root_b])
        .expect("SszList from 2 roots");
    let req = RpcRequest::BlocksByRoot(BeaconBlocksByRootRequest { block_roots: roots });

    let response = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, req, Duration::from_secs(5)),
    )
    .await
    .expect("BlocksByRoot timed out at test level")
    .expect("BlocksByRoot RPC failed");

    match response {
        RpcResponse::BlocksByRoot(blocks) => {
            assert_eq!(blocks.len(), 2, "expected 2 blocks, got {}", blocks.len());
            let slots: Vec<u64> = blocks
                .iter()
                .map(|b| match b {
                    MainnetSignedBeaconBlock::Phase0(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Altair(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Bellatrix(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Capella(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Deneb(inner) => inner.message.slot.0,
                    MainnetSignedBeaconBlock::Electra(inner) => inner.message.slot.0,
                })
                .collect();
            assert!(slots.contains(&100), "slot 100 block missing");
            assert!(slots.contains(&200), "slot 200 block missing");
        }
        other => panic!("expected RpcResponse::BlocksByRoot, got: {other:?}"),
    }
}

/// Both MetaData v1 and v2 requests to the same node succeed.
///
/// Node A sends `RpcRequest::MetaData` (v2 protocol) → expects `MetaDataResponse::V2`.
/// Node A sends `RpcRequest::MetaDataV1` (v1 protocol) → expects `MetaDataResponse::V1`.
///
/// Verifies `D-metadata-v2-dual-handle`: node B registers both protocol IDs on
/// the inbound side; the handler selects V1 or V2 based on the negotiated protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_v1_v2_dual_handle() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    // v2 request: A asks for MetaData via v2 protocol → should receive MetaDataResponse::V2.
    let resp_v2 = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, RpcRequest::MetaData, Duration::from_secs(5)),
    )
    .await
    .expect("MetaData (v2) timed out")
    .expect("MetaData (v2) RPC failed");

    match resp_v2 {
        RpcResponse::MetaData(MetaDataResponse::V2(m)) => {
            assert_eq!(m.seq_number, 0, "expected default seq_number 0 for v2");
        }
        other => panic!("expected RpcResponse::MetaData(V2), got: {other:?}"),
    }

    // v1 request: A asks for MetaData via v1 protocol → should receive MetaDataResponse::V1.
    let resp_v1 = timeout(
        Duration::from_secs(5),
        node_a.handle.request(
            node_b.peer_id,
            RpcRequest::MetaDataV1,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("MetaData (v1) timed out")
    .expect("MetaData (v1) RPC failed");

    match resp_v1 {
        RpcResponse::MetaData(MetaDataResponse::V1(m)) => {
            assert_eq!(m.seq_number, 0, "expected default seq_number 0 for v1");
        }
        other => panic!("expected RpcResponse::MetaData(V1), got: {other:?}"),
    }
}

/// A requests a `LightClientBootstrap` from B; B serves an SSZ-round-trip-equal bootstrap.
///
/// Node B is preloaded with a `LightClientBootstrap` keyed by a specific block root.
/// A requests it; the response SSZ-encodes identically to the preloaded object.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn light_client_bootstrap_round_trip() {
    use pharos_ssz::Encode;

    // Build a default LightClientBootstrap with a distinctive header slot.
    let beacon = pharos_types::phase0::operations::BeaconBlockHeader {
        slot: Slot(77),
        ..Default::default()
    };
    let bootstrap: LightClientBootstrap<512> = LightClientBootstrap {
        header: LightClientHeader { beacon },
        ..Default::default()
    };

    // Use the SSZ hash of the header as the block root key.
    use pharos_ssz::TreeHash;
    let block_root: Root = bootstrap.header.beacon.tree_hash_root();

    let b_host = TestHost::new(fd())
        .with_altair_fork_digest(altair_fd())
        .with_lc_bootstrap(block_root, bootstrap.clone());

    let mut node_a = spawn_node(
        vec![],
        TestHost::new(fd()).with_altair_fork_digest(altair_fd()),
        false,
    )
    .await;
    let mut node_b = spawn_node(vec![], b_host, false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let req = RpcRequest::LightClientBootstrap(LightClientBootstrapRequest(block_root));

    let response = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, req, Duration::from_secs(5)),
    )
    .await
    .expect("LightClientBootstrap timed out")
    .expect("LightClientBootstrap RPC failed");

    match response {
        RpcResponse::LightClientBootstrap(got) => {
            assert_eq!(
                got.as_ssz_bytes(),
                bootstrap.as_ssz_bytes(),
                "LightClientBootstrap SSZ round-trip mismatch"
            );
        }
        other => panic!("expected RpcResponse::LightClientBootstrap, got: {other:?}"),
    }
}

/// A requests 5 `LightClientUpdate` objects by range from B; B serves all 5.
///
/// Node B is preloaded with 5 updates at consecutive signature slots.
/// A sends `LightClientUpdatesByRange { start_period: 0, count: 5 }`.
/// The response contains 5 SSZ-round-trip-equal updates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn light_client_updates_by_range_round_trip() {
    use pharos_ssz::Encode;

    // Build 5 default LightClientUpdates with distinctive signature slots.
    let updates: Vec<LightClientUpdate<512>> = (0u64..5)
        .map(|i| LightClientUpdate {
            signature_slot: Slot(100 + i),
            ..Default::default()
        })
        .collect();

    let b_host = TestHost::new(fd())
        .with_altair_fork_digest(altair_fd())
        .with_lc_updates(updates.clone());

    let mut node_a = spawn_node(
        vec![],
        TestHost::new(fd()).with_altair_fork_digest(altair_fd()),
        false,
    )
    .await;
    let mut node_b = spawn_node(vec![], b_host, false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let req = RpcRequest::LightClientUpdatesByRange(LightClientUpdatesByRangeRequest {
        start_period: 0,
        count: 5,
    });

    let response = timeout(
        Duration::from_secs(5),
        node_a
            .handle
            .request(node_b.peer_id, req, Duration::from_secs(5)),
    )
    .await
    .expect("LightClientUpdatesByRange timed out")
    .expect("LightClientUpdatesByRange RPC failed");

    match response {
        RpcResponse::LightClientUpdatesByRange(got) => {
            assert_eq!(got.len(), 5, "expected 5 updates, got {}", got.len());
            for (i, (expected, actual)) in updates.iter().zip(got.iter()).enumerate() {
                assert_eq!(
                    expected.as_ssz_bytes(),
                    actual.as_ssz_bytes(),
                    "update {i} SSZ round-trip mismatch"
                );
            }
        }
        other => panic!("expected RpcResponse::LightClientUpdatesByRange, got: {other:?}"),
    }
}
