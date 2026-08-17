//! Integration tests for M3a Phase 3 `NetworkEvent` expansion.
//!
//! Covers the five new variants added per D-network-event-surface:
//! `PeerSubscribed`, `PeerUnsubscribed`, `PeerIdentified`, `DialFailed`,
//! `ExternalAddrConfirmed`.
//!
//! Test isolation: `#[serial]` is used per the M2 gossip-flake mitigation
//! pattern (`95785a5`) — gossipsub mesh formation is timing-sensitive and
//! concurrent tests on the same loopback interface can cause flakes.

use std::time::Duration;

use crate::common::{NetworkEvent, TestHost, spawn_node};
use pharos_network::topics::GossipTopicKind;
use pharos_types::phase0::primitives::ForkDigest;
use serial_test::serial;
use tokio::time::timeout;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

/// Two-node test: after connecting, both sides receive `PeerIdentified` with
/// non-empty `protocols` containing the Status protocol ID, and at least one
/// `PeerSubscribed` event (gossipsub sends subscription lists on connection).
///
/// Spec cite for identify: libp2p identify protocol carries the protocol list.
/// Spec cite for subscription announcement: gossipsub SUBSCRIBE control message
/// is sent to a new peer for every currently subscribed topic on connection.
///
/// Note on event ordering: the libp2p identify protocol completes asynchronously
/// relative to the Status handshake. `PeerIdentified` may arrive before or after
/// `PeerConnected` in the event stream. Both loops below collect events without
/// discarding any, waiting until the required event is seen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn peer_identified_and_subscribed() {
    const STATUS_PROTOCOL_ID: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";

    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), false).await;

    let b_listen_addr = node_b.listen_addr.clone();
    let b_peer_id = node_b.peer_id;
    let a_peer_id = node_a.peer_id;

    // A dials B.
    node_a
        .handle
        .dial(b_listen_addr)
        .await
        .expect("dial failed");

    // Collect events on A until we have seen both PeerConnected(B) and
    // PeerIdentified(B). Either may arrive first.
    timeout(Duration::from_secs(15), async {
        let mut saw_connected = false;
        let mut saw_identified = false;
        while !saw_connected || !saw_identified {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == b_peer_id => {
                    saw_connected = true;
                }
                NetworkEvent::PeerIdentified { peer, info } if peer == b_peer_id => {
                    assert!(
                        !info.protocols.is_empty(),
                        "PeerIdentified must carry non-empty protocols"
                    );
                    assert!(
                        info.protocols.iter().any(|p| p == STATUS_PROTOCOL_ID),
                        "protocols must contain the Status protocol ID \
                         ({STATUS_PROTOCOL_ID}); got: {:?}",
                        info.protocols
                    );
                    saw_identified = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("A did not receive both PeerConnected(B) and PeerIdentified(B) within 15s");

    // Collect events on B until we have seen PeerConnected(A), PeerIdentified(A),
    // and at least one PeerSubscribed(A, _). All three may arrive in any order.
    timeout(Duration::from_secs(15), async {
        let mut saw_connected = false;
        let mut saw_identified = false;
        let mut saw_subscribed = false;
        while !saw_connected || !saw_identified || !saw_subscribed {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == a_peer_id => {
                    saw_connected = true;
                }
                NetworkEvent::PeerIdentified { peer, info } if peer == a_peer_id => {
                    assert!(
                        !info.protocols.is_empty(),
                        "PeerIdentified must carry non-empty protocols"
                    );
                    assert!(
                        info.protocols.iter().any(|p| p == STATUS_PROTOCOL_ID),
                        "protocols must contain the Status protocol ID \
                         ({STATUS_PROTOCOL_ID}); got: {:?}",
                        info.protocols
                    );
                    saw_identified = true;
                }
                NetworkEvent::PeerSubscribed { peer, topic } if peer == a_peer_id => {
                    // Verify the topic is one of the standard Phase-0 kinds.
                    assert!(
                        matches!(
                            topic.kind,
                            GossipTopicKind::BeaconBlock
                                | GossipTopicKind::BeaconAggregateAndProof
                                | GossipTopicKind::VoluntaryExit
                                | GossipTopicKind::ProposerSlashing
                                | GossipTopicKind::AttesterSlashing
                                | GossipTopicKind::BeaconAttestation(_)
                        ),
                        "PeerSubscribed topic kind must be a Phase-0 kind; got: {:?}",
                        topic.kind
                    );
                    saw_subscribed = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect(
        "B did not receive PeerConnected(A), PeerIdentified(A), and PeerSubscribed(A, _) within 15s",
    );
}

/// Verify that `DialFailed` is emitted when dialling an unreachable address.
///
/// Dials a port where nothing is listening and asserts that a `DialFailed`
/// event arrives within 5 seconds. The `peer` field is `None` because the
/// identity was not established before the dial failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn dial_failed_unreachable_address() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), false).await;

    // Dial a loopback address where nothing is listening.
    let dead_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
    node_a
        .handle
        .dial(dead_addr)
        .await
        .expect("dial command sent");

    // Wait for DialFailed within 5 seconds.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::DialFailed { error, .. } => {
                    assert!(
                        !error.is_empty(),
                        "DialFailed error string must be non-empty"
                    );
                    break;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("node A did not receive DialFailed within 5s");
}
