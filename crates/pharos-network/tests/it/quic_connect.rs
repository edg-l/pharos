use std::time::Duration;

use crate::common::{NetworkEvent, TestHost, spawn_node};
use discv5::enr::{CombinedKey, EnrKey, EnrPublicKey as _};
use libp2p::multiaddr::Protocol;
use pharos_network::discovery::enr::{build_local_enr, enr_to_dial_addrs};
use pharos_ssz::Bitvector;
use pharos_types::phase0::ENRForkID;
use pharos_types::phase0::primitives::{ATTESTATION_SUBNET_COUNT, ForkDigest};
use pharos_utils::{Bytes4, Epoch};
use std::net::Ipv4Addr;
use tokio::time::timeout;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

/// Returns `true` if `addr` carries a `/quic-v1` component.
fn is_quic_v1(addr: &libp2p::Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

/// Two QUIC-only nodes connect and both emit `PeerConnected`.
///
/// Node A is started with `quic_only = true`. Node B is also `quic_only = true`.
/// A dials B's QUIC multiaddr. Both sides must emit `NetworkEvent::PeerConnected`
/// within 5 seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_connect_over_quic() {
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), true).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), true).await;

    // A dials B's QUIC listen address.
    node_a
        .handle
        .dial(node_b.listen_addr.clone())
        .await
        .expect("dial failed");

    // Both sides must emit PeerConnected within 5 seconds.
    let peer_b_id = node_b.peer_id;
    let peer_a_id = node_a.peer_id;

    let a_connected = timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == peer_b_id => break,
                _ => continue,
            }
        }
    });

    let b_connected = timeout(Duration::from_secs(5), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == peer_a_id => break,
                _ => continue,
            }
        }
    });

    a_connected
        .await
        .expect("node A did not receive PeerConnected within 5s");
    b_connected
        .await
        .expect("node B did not receive PeerConnected within 5s");
}

/// A peer advertising a QUIC ENR is dialed QUIC-first and connects over QUIC.
///
/// This exercises the full QUIC-first outbound path:
///   1. `enr_to_dial_addrs` orders a dual-stack ENR with the `/quic-v1` address
///      at index 0 (QUIC-first), ahead of any TCP address, and derives the
///      peer_id from the ENR's secp256k1 key.
///   2. Node B listens on QUIC only; its real bound listen address is a
///      `/quic-v1` multiaddr.
///   3. Node A dials that `/quic-v1` address and establishes a connection,
///      emitting `NetworkEvent::PeerConnected(peer_b)`.
///
/// `NetworkEvent::PeerConnected` carries only the `PeerId`; the harness does
/// not surface the established connection's endpoint/multiaddr. The assertions
/// therefore prove QUIC-first via (a) `enr_to_dial_addrs` ordering placing
/// `/quic-v1` at index 0 and (b) a successful connection over B's `/quic-v1`
/// listen address (asserted to contain a `/quic-v1` component).
///
/// MANUAL VERIFICATION: to confirm the established connection is genuinely
/// quic-v1 on a live network, run `scripts/run-hoodi.sh` and trace the swarm's
/// `SwarmEvent::ConnectionEstablished { endpoint, .. }` — the `endpoint`'s
/// `get_remote_address()` will contain `/udp/<port>/quic-v1` (no `/tcp/`
/// component) for QUIC peers dialed via this path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialed_peer_with_quic_enr_connects_over_quic() {
    // ── (1) enr_to_dial_addrs orders /quic-v1 first on a dual-stack ENR ─────────
    // Build a dual-stack (quic4 + tcp4) ENR with a real secp256k1 key and assert
    // the QUIC address sorts before the TCP address, and that the peer_id derives
    // from the ENR key.
    let key = CombinedKey::generate_secp256k1();
    let fork_id = ENRForkID {
        fork_digest: Bytes4::from_array(FORK_DIGEST),
        next_fork_version: Bytes4::from_array([0u8; 4]),
        next_fork_epoch: Epoch(u64::MAX),
    };
    let enr = build_local_enr(
        &key,
        Some(Ipv4Addr::new(127, 0, 0, 1)), // ip4
        Some(9000),                        // udp4 (discv5)
        Some(9000),                        // tcp4
        Some(9001),                        // quic_port (IPv4 QUIC)
        None,                              // quic6_port
        None,                              // ip6
        None,                              // udp6
        None,                              // tcp6
        fork_id,
        Bitvector::<ATTESTATION_SUBNET_COUNT>::new(), // attnets
        None,                                         // cgc
        1,                                            // initial_seq
    )
    .expect("build_local_enr failed");

    let (enr_peer_id, addrs) = enr_to_dial_addrs(&enr).expect("ENR should be dialable");
    assert_eq!(addrs.len(), 2, "expected quic4 + tcp4 addresses");
    assert!(
        is_quic_v1(&addrs[0]),
        "QUIC-first: addrs[0] must be /quic-v1, got {}",
        addrs[0]
    );
    assert_eq!(
        addrs[0].to_string(),
        "/ip4/127.0.0.1/udp/9001/quic-v1",
        "addrs[0] must be the bare quic-v1 form"
    );
    assert!(
        !is_quic_v1(&addrs[1]),
        "addrs[1] must be the TCP fallback, got {}",
        addrs[1]
    );
    assert_eq!(
        addrs[1].to_string(),
        "/ip4/127.0.0.1/tcp/9000",
        "addrs[1] must be the bare tcp form"
    );
    // The peer_id derives from the ENR's secp256k1 key (matches the key's PeerId).
    let expected_peer_id = libp2p::identity::PublicKey::from(
        libp2p::identity::secp256k1::PublicKey::try_from_bytes(&key.public().encode())
            .expect("secp256k1 pubkey"),
    )
    .to_peer_id();
    assert_eq!(
        enr_peer_id, expected_peer_id,
        "derived peer_id must match the ENR key"
    );

    // ── (2)+(3) Drive a real QUIC dial and assert PeerConnected ─────────────────
    let mut node_b = spawn_node(vec![], TestHost::new(fd()), true).await;
    let mut node_a = spawn_node(vec![], TestHost::new(fd()), true).await;

    // B is QUIC-only: its real bound listen address must be a /quic-v1 multiaddr.
    assert!(
        is_quic_v1(&node_b.listen_addr),
        "node B must listen on /quic-v1, got {}",
        node_b.listen_addr
    );

    let peer_b_id = node_b.peer_id;

    // A dials B's real bound /quic-v1 address (the QUIC-first dial entry point).
    node_a
        .handle
        .dial(node_b.listen_addr.clone())
        .await
        .expect("dial failed");

    // A must establish a connection to B over QUIC within 5 seconds.
    let a_connected = timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == peer_b_id => break,
                _ => continue,
            }
        }
    });

    // Drive B's event loop too so the QUIC handshake completes promptly.
    let peer_a_id = node_a.peer_id;
    let b_connected = timeout(Duration::from_secs(5), async {
        loop {
            match node_b.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerConnected(id) if id == peer_a_id => break,
                _ => continue,
            }
        }
    });

    a_connected
        .await
        .expect("node A did not connect to B over QUIC within 5s");
    b_connected
        .await
        .expect("node B did not observe A's QUIC connection within 5s");
}
