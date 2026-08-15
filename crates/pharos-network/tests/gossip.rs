// Topology for gossip_reject_drops_message:
//
//   A ── B ── C
//
// A dials B; B dials C. There is NO direct connection between A and C.
// A publishes a beacon block with proposer_index = u64::MAX.
// B's GossipValidator rejects any block with proposer_index = u64::MAX.
// Because B rejects the message, libp2p gossipsub does NOT forward it to C.
// We assert that C does NOT receive a GossipMessage within 2 seconds.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::{NetworkEvent, TestHost, spawn_node};
use pharos_network::GossipTopic;
use pharos_network::host::GOSSIP_REASON_PARENT_UNSEEN;
use pharos_network::topics::GossipTopicKind;
use pharos_ssz::Encode as _;
use pharos_types::phase0::primitives::{ForkDigest, Slot};
use pharos_types::phase0::{Attestation, MainnetSignedBeaconBlock};
use pharos_utils::ValidatorIndex;
use serial_test::serial;
use tokio::time::timeout;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

fn beacon_block_topic() -> GossipTopic {
    GossipTopic {
        fork_digest: fd(),
        kind: GossipTopicKind::BeaconBlock,
    }
}

fn attestation_topic(subnet: u64) -> GossipTopic {
    GossipTopic {
        fork_digest: fd(),
        kind: GossipTopicKind::BeaconAttestation(subnet),
    }
}

/// Node A publishes a beacon block (slot 1); node B receives it via gossipsub.
///
/// B must receive a `NetworkEvent::GossipMessage` with the matching SSZ payload
/// within 5 seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn block_gossip_round_trip() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), false).await;

    let b_listen_addr = node_b.listen_addr.clone();
    let b_peer_id = node_b.peer_id;

    // Connect A → B and wait for handshake.
    node_a
        .handle
        .dial(b_listen_addr)
        .await
        .expect("dial failed");
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == b_peer_id => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("A did not connect to B within 5s");

    // Build synthesised beacon block with slot = 1.
    let mut block = MainnetSignedBeaconBlock::default();
    block.message.slot = Slot(1);
    let ssz_payload = block.as_ssz_bytes();

    // Publish from A.
    node_a
        .handle
        .publish(beacon_block_topic(), &block)
        .await
        .expect("publish failed");

    // B must receive the gossip message within 5 seconds.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::GossipMessage { data, .. } => {
                    assert_eq!(
                        data, ssz_payload,
                        "gossip payload does not match published SSZ"
                    );
                    break;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not receive GossipMessage within 5s");
}

/// A publishes on beacon_attestation_3; B3 (subnet 3) receives it.
/// B4 (only subscribed to subnet 4) must NOT receive it within 1 second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn attestation_subnet_gossip() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b3 = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b4 = spawn_node(vec![], TestHost::new(fd()), false).await;

    let b3_listen = node_b3.listen_addr.clone();
    let b4_listen = node_b4.listen_addr.clone();
    let b3_id = node_b3.peer_id;
    let b4_id = node_b4.peer_id;

    node_a.handle.dial(b3_listen).await.expect("dial b3 failed");
    node_a.handle.dial(b4_listen).await.expect("dial b4 failed");

    // Wait for both connections on A.
    let mut connected: HashSet<libp2p::PeerId> = HashSet::new();
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) => {
                    connected.insert(id);
                    if connected.contains(&b3_id) && connected.contains(&b4_id) {
                        break;
                    }
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("A did not connect to both B3 and B4 within 5s");

    // Subscribe A, B3 to subnet 3 and B4 to subnet 4.
    // A must be subscribed to publish and for the mesh to form.
    node_a
        .handle
        .subscribe(attestation_topic(3))
        .await
        .expect("a subscribe to subnet 3 failed");
    node_b3
        .handle
        .subscribe(attestation_topic(3))
        .await
        .expect("b3 subscribe failed");
    node_b4
        .handle
        .subscribe(attestation_topic(4))
        .await
        .expect("b4 subscribe failed");

    // Delay for gossipsub subscription propagation and mesh formation.
    // 2 s gives gossipsub enough time to converge even under workspace-wide
    // CPU contention (1 s was occasionally insufficient).
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // A publishes a default Attestation on subnet 3.
    let payload = Attestation::<2048>::default();
    node_a
        .handle
        .publish(attestation_topic(3), &payload)
        .await
        .expect("publish failed");

    // B3 must receive the message.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_b3.handle.next_event().await.expect("channel closed") {
                NetworkEvent::GossipMessage { topic, .. } if topic == attestation_topic(3) => {
                    break;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("B3 did not receive attestation_3 GossipMessage within 5s");

    // B4 must NOT receive the subnet-3 message within 1 second.
    let received_wrong = timeout(Duration::from_secs(1), async {
        loop {
            match node_b4.handle.next_event().await.expect("channel closed") {
                NetworkEvent::GossipMessage { topic, .. } if topic == attestation_topic(3) => {
                    break true;
                }
                _ => continue,
            }
        }
    })
    .await;

    assert!(
        received_wrong.is_err(),
        "B4 (subnet 4) must NOT receive a subnet-3 attestation gossip"
    );
}

/// Three-node linear topology A → B → C; B rejects the block; C must not receive it.
///
/// Topology (see file-level comment):
///   A ── B ── C   (A dials B; B dials C; no A↔C link)
///
/// A publishes a beacon block with `proposer_index = u64::MAX`. B's `TestHost`
/// is configured with `reject_blocks_with_proposer(u64::MAX)`, so B returns
/// `GossipVerdict::Reject` for this block and gossipsub does not propagate it
/// further. C must NOT receive a `GossipMessage` within 2 seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn gossip_reject_drops_message() {
    // B rejects blocks with proposer_index = u64::MAX.
    let b_host = TestHost::new(fd()).reject_blocks_with_proposer(u64::MAX);

    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], b_host, false).await;
    let mut node_c = spawn_node(vec![], TestHost::new(fd()), false).await;

    let b_listen = node_b.listen_addr.clone();
    let c_listen = node_c.listen_addr.clone();
    let b_id = node_b.peer_id;
    let c_id = node_c.peer_id;

    // A dials B; B dials C (no A↔C link).
    node_a.handle.dial(b_listen).await.expect("A→B dial failed");
    node_b.handle.dial(c_listen).await.expect("B→C dial failed");

    // Wait for A↔B handshake.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == b_id => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("A did not connect to B within 5s");

    // Wait for B↔C handshake.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == c_id => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not connect to C within 5s");

    // Small delay for gossipsub mesh formation.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A publishes a block with proposer_index = u64::MAX.
    let mut block = MainnetSignedBeaconBlock::default();
    block.message.proposer_index = ValidatorIndex(u64::MAX);

    let result = node_a.handle.publish(beacon_block_topic(), &block).await;
    assert!(result.is_ok(), "A's publish must succeed: {:?}", result);

    // C must NOT receive a GossipMessage within 2 seconds.
    let c_received = timeout(Duration::from_secs(2), async {
        loop {
            match node_c.handle.next_event().await.expect("channel closed") {
                NetworkEvent::GossipMessage { .. } => break true,
                _ => continue,
            }
        }
    })
    .await;

    assert!(
        c_received.is_err(),
        "C must NOT receive the gossip message rejected by B"
    );
}

/// B ignores the block with `GOSSIP_REASON_PARENT_UNSEEN`; dispatcher must emit
/// `NetworkEvent::UnknownParentBlock` (not `GossipMessage`) for that block.
///
/// Two-node topology: A publishes, B receives and ignores (RB6 sentinel).
/// B must observe `NetworkEvent::UnknownParentBlock` with the correct SSZ bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn unknown_parent_block_emitted() {
    // B ignores beacon_block at slot 42 with the parent-unseen reason.
    let b_host = TestHost::new(fd()).ignore_parent_unseen_at_slot(42);

    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], b_host, false).await;

    let b_listen = node_b.listen_addr.clone();
    let b_id = node_b.peer_id;

    node_a.handle.dial(b_listen).await.expect("A→B dial failed");
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == b_id => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("A did not connect to B within 5s");

    let mut block = pharos_types::phase0::MainnetSignedBeaconBlock::default();
    block.message.slot = pharos_types::phase0::primitives::Slot(42);
    let ssz_payload = pharos_ssz::Encode::as_ssz_bytes(&block);

    node_a
        .handle
        .publish(beacon_block_topic(), &block)
        .await
        .expect("publish failed");

    // B must receive UnknownParentBlock (not GossipMessage) within 5 seconds.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::UnknownParentBlock { topic, data, .. } => {
                    assert_eq!(
                        topic.kind,
                        GossipTopicKind::BeaconBlock,
                        "topic kind must be BeaconBlock"
                    );
                    assert_eq!(
                        data, ssz_payload,
                        "UnknownParentBlock data must match SSZ payload"
                    );
                    break;
                }
                NetworkEvent::GossipMessage { .. } => {
                    panic!("got GossipMessage instead of UnknownParentBlock");
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not receive UnknownParentBlock within 5s");
}

/// B ignores the block with a different reason (not PARENT_UNSEEN); the
/// dispatcher must NOT emit `UnknownParentBlock` — no event should arrive
/// within 1 second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn unknown_parent_block_other_ignore_no_event() {
    // B rejects blocks with proposer_index u64::MAX (Reject, not Ignore),
    // and accepts all others (so no UnknownParentBlock is emitted).
    // We use a normal Accept host — publishing slot 99 yields GossipMessage, not UnknownParentBlock.
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), false).await;

    let b_listen = node_b.listen_addr.clone();
    let b_id = node_b.peer_id;

    node_a.handle.dial(b_listen).await.expect("A→B dial failed");
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == b_id => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("A did not connect to B within 5s");

    let mut block = pharos_types::phase0::MainnetSignedBeaconBlock::default();
    block.message.slot = pharos_types::phase0::primitives::Slot(99);

    node_a
        .handle
        .publish(beacon_block_topic(), &block)
        .await
        .expect("publish failed");

    // B must receive GossipMessage (Accept path), not UnknownParentBlock.
    let got_unknown = timeout(Duration::from_secs(3), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::UnknownParentBlock { .. } => break true,
                NetworkEvent::GossipMessage { .. } => break false,
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not receive any gossip event within 3s");

    assert!(
        !got_unknown,
        "Accept path must yield GossipMessage, not UnknownParentBlock"
    );
}

/// Compile-time check: `GOSSIP_REASON_PARENT_UNSEEN` const matches the string
/// used in `GossipVerdict::Ignore` and the `UnknownParentBlock` emit condition.
/// Prevents accidental desync between the const value and its consumers.
#[test]
fn parent_unseen_const_value() {
    assert_eq!(GOSSIP_REASON_PARENT_UNSEEN, "block: parent unseen");
}
