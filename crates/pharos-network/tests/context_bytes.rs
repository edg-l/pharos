// Integration tests for Phase 5 additions:
//
// (a) `context_bytes_codec`: two nodes exchange `BlocksByRange/v2` carrying
//     mixed phase-0 + altair blocks; both decode correctly with the right fork
//     variant identified via context bytes.
//
// (b) `altair_gossip_message_id`: round-trip a `sync_committee_contribution_and_proof`
//     payload; assert the returned MessageId incorporates the topic per the altair
//     message-id formula.

mod common;

use std::time::Duration;

use common::{NetworkEvent, TestHost, spawn_node};
use libp2p::gossipsub::MessageId;
use pharos_network::GossipTopic;
use pharos_network::codec::snappy_block::encode_snappy_block;
use pharos_network::gossip::message_id::{
    MESSAGE_DOMAIN_VALID_SNAPPY, compute_message_id, parse_fork_digest_from_topic_str,
};
use pharos_network::rpc::types::RpcResponse;
use pharos_network::topics::GossipTopicKind;
use pharos_network::{NetworkHandle, RpcRequest};
use pharos_ssz::{Encode as _, TreeHash as _};
use pharos_types::MainnetEthSpec;
use pharos_types::altair::MainnetSignedBeaconBlock as AltairMainnetBlock;
use pharos_types::altair::SignedContributionAndProof;
use pharos_types::phase0::BeaconBlocksByRangeRequest;
use pharos_types::phase0::MainnetSignedBeaconBlock as Phase0MainnetBlock;
use pharos_types::phase0::primitives::{ForkDigest, Slot};
use pharos_types::state::MainnetSignedBeaconBlock;
use serial_test::serial;
use tokio::time::timeout;

// Distinct phase-0 and altair fork digests — must differ for context-bytes dispatch.
const PHASE0_FD: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
const ALTAIR_FD: [u8; 4] = [0x05, 0x06, 0x07, 0x08];

fn phase0_fd() -> ForkDigest {
    ForkDigest::from_array(PHASE0_FD)
}

fn altair_fd() -> ForkDigest {
    ForkDigest::from_array(ALTAIR_FD)
}

fn make_host_with_altair() -> TestHost {
    TestHost::new(phase0_fd()).with_altair_fork_digest(altair_fd())
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

async fn wait_connected(handle: &mut NetworkHandle<MainnetEthSpec>, expected_peer: libp2p::PeerId) {
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

// ── (a) context_bytes_codec ───────────────────────────────────────────────────

/// B preloads one Phase-0 block (slot 10) and one Altair block (slot 11).
/// A sends `BlocksByRange` requesting both slots.
/// After decode, slot 10 must be a `Phase0` variant and slot 11 an `Altair` variant.
///
/// This validates the context-bytes codec end-to-end: the server (B) writes the
/// 4-byte fork digest before each chunk, and the client (A) dispatches SSZ-decode
/// based on the resolved `Fork`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn context_bytes_codec() {
    // Build a Phase-0 block at slot 10.
    let mut phase0_inner = Phase0MainnetBlock::default();
    phase0_inner.message.slot = Slot(10);
    let root0 = phase0_inner.message.tree_hash_root();
    let block_phase0 = MainnetSignedBeaconBlock::Phase0(phase0_inner);

    // Build an Altair block at slot 11.
    let mut altair_inner = AltairMainnetBlock::default();
    altair_inner.message.slot = Slot(11);
    let root1 = altair_inner.message.tree_hash_root();
    let block_altair = MainnetSignedBeaconBlock::Altair(altair_inner);

    // Node B serves both blocks. head_slot large enough to allow slot 10:
    // oldest_allowed = head_slot - 1,056,768; set head_slot = 1,056,778.
    let b_host = make_host_with_altair()
        .with_blocks(vec![(root0, block_phase0), (root1, block_altair)])
        .with_head_slot(Slot(1_056_778));

    let mut node_a = spawn_node(vec![], make_host_with_altair(), false).await;
    let mut node_b = spawn_node(vec![], b_host, false).await;
    connect_and_wait(&mut node_a, &mut node_b).await;

    let req = RpcRequest::BlocksByRange(BeaconBlocksByRangeRequest {
        start_slot: Slot(10),
        count: 2,
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
            assert_eq!(blocks.len(), 2, "expected 2 blocks, got {}", blocks.len());

            // Sort by slot to get a stable order.
            let mut sorted = blocks;
            sorted.sort_by_key(|b| match b {
                MainnetSignedBeaconBlock::Phase0(inner) => inner.message.slot.0,
                MainnetSignedBeaconBlock::Altair(inner) => inner.message.slot.0,
                MainnetSignedBeaconBlock::Bellatrix(inner) => inner.message.slot.0,
                MainnetSignedBeaconBlock::Capella(inner) => inner.message.slot.0,
            });

            // Slot 10 must be Phase0.
            assert!(
                matches!(&sorted[0], MainnetSignedBeaconBlock::Phase0(inner) if inner.message.slot.0 == 10),
                "slot 10 block must be Phase0 variant; got: {:?}",
                sorted[0]
            );

            // Slot 11 must be Altair.
            assert!(
                matches!(&sorted[1], MainnetSignedBeaconBlock::Altair(inner) if inner.message.slot.0 == 11),
                "slot 11 block must be Altair variant; got: {:?}",
                sorted[1]
            );
        }
        other => panic!("expected RpcResponse::BlocksByRange, got: {other:?}"),
    }
}

// ── (b) altair_gossip_message_id ─────────────────────────────────────────────

/// A publishes a `sync_committee_contribution_and_proof` payload on an altair
/// fork-digest topic. The returned `MessageId` must equal the altair message-id
/// formula: `SHA256(DOMAIN_VALID || uint_to_bytes(len(topic)) || topic || decompressed)[:20]`.
///
/// B must also receive the gossip message (confirming round-trip propagation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn altair_gossip_message_id() {
    let mut node_a = spawn_node(vec![], make_host_with_altair(), false).await;
    let mut node_b = spawn_node(vec![], make_host_with_altair(), false).await;

    let b_listen = node_b.listen_addr.clone();
    let b_id = node_b.peer_id;

    node_a.handle.dial(b_listen).await.expect("dial failed");
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

    // Use the altair fork digest on the topic — this triggers the altair formula.
    let topic = GossipTopic {
        fork_digest: altair_fd(),
        kind: GossipTopicKind::SyncCommitteeContributionAndProof,
    };

    // Both nodes must subscribe to receive the message.
    node_a
        .handle
        .subscribe(topic.clone())
        .await
        .expect("A subscribe failed");
    node_b
        .handle
        .subscribe(topic.clone())
        .await
        .expect("B subscribe failed");

    // Allow gossipsub subscription propagation and mesh formation.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Build a default `SignedContributionAndProof<128>` (mainnet subcommittee size).
    let payload = SignedContributionAndProof::<128>::default();
    let ssz_bytes = payload.as_ssz_bytes();

    // The network layer snappy-block-compresses SSZ bytes before publishing.
    // The message_id_fn closure sees the compressed wire bytes. It then tries
    // to decompress (snappy block) and on success uses DOMAIN_VALID_SNAPPY.
    let compressed = encode_snappy_block(&ssz_bytes).expect("snappy encode failed");

    // Compute the expected altair message-id from the compressed wire bytes.
    let topic_str = topic.topic_str();
    let topic_fd = parse_fork_digest_from_topic_str(&topic_str)
        .expect("parse_fork_digest_from_topic_str failed");
    // The phase-0 digest captured at gossipsub construction is PHASE0_FD.
    // topic_fd (ALTAIR_FD) != PHASE0_FD, so the altair formula is used.
    assert_ne!(
        topic_fd, PHASE0_FD,
        "topic fork digest must differ from phase-0 for altair formula"
    );

    // compute_message_id(&topic_str, &compressed, &PHASE0_FD) sees compressed bytes,
    // decompresses them to ssz_bytes (valid-snappy path), and produces:
    // SHA256(DOMAIN_VALID || len(topic) || topic || ssz_bytes)[:20].
    let expected_id = compute_message_id(&topic_str, &compressed, &PHASE0_FD);

    // Publish from A and capture the returned MessageId.
    let returned_id = node_a
        .handle
        .publish(topic.clone(), &payload)
        .await
        .expect("publish failed");

    // The returned MessageId bytes must match the altair formula output.
    assert_eq!(
        returned_id,
        MessageId::from(expected_id.to_vec()),
        "returned MessageId must match the altair message-id formula"
    );

    // Verify the message-id uses the valid-snappy domain (not invalid):
    // SHA256(DOMAIN_VALID || uint_to_bytes(len(topic)) || topic || decompressed)[:20].
    let topic_bytes = topic_str.as_bytes();
    let topic_len_le = (topic_bytes.len() as u64).to_le_bytes();
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_DOMAIN_VALID_SNAPPY);
    hasher.update(topic_len_le);
    hasher.update(topic_bytes);
    hasher.update(&ssz_bytes); // decompressed (valid-snappy path)
    let full = hasher.finalize();
    let mut hand_computed = [0u8; 20];
    hand_computed.copy_from_slice(&full[..20]);
    assert_eq!(
        expected_id, hand_computed,
        "compute_message_id must produce the valid-snappy altair formula"
    );

    // B must receive the gossip message confirming round-trip propagation.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::GossipMessage {
                    topic: recv_topic, ..
                } if recv_topic == topic => {
                    break;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not receive SyncCommitteeContributionAndProof GossipMessage within 5s");
}
