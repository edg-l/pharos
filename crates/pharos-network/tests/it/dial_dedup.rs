//! Regression test for in-flight dial deduplication (Leg A).
//!
//! ## Bug being tested
//!
//! Before this fix, pharos would double-dial a reference CL client on startup: the
//! bootnode dial in `run()` and the discovery-tick dial both targeted the same
//! `PeerId` ~2 ms apart, before either connection had established.  Both dials
//! proceeded independently → duplicate TCP connection → the reference CL sent
//! `Goodbye reason=250` → both connections closed → 0 peers → terminal.
//!
//! ## What this test proves
//!
//! 1. The first `dial_peer(pid, addrs)` call returns `true` and registers the
//!    peer in `pending_dials`.
//! 2. A second `dial_peer(pid, addrs)` call for the **same** peer while the
//!    first dial is still in flight returns `false` and leaves `pending_dials`
//!    unchanged.
//! 3. After `on_swarm_connection_established(pid, n=1)` the entry is removed
//!    from `pending_dials` (cleared before the RC2 gate).
//! 4. After `on_swarm_connection_established(pid, n=2)` (mutual-dial second
//!    connection) the entry is ALSO removed (same pre-gate clear path).
//!
//! ## Approach: direct handler test
//!
//! We build a `Network` via `NetworkBuilder::build()` (no spawn) and call
//! `dial_peer` directly.  The first dial goes to a syntactically-valid but
//! unreachable loopback address (127.0.0.2:19999) as a bare TCP addr
//! so `swarm.dial` accepts it (no synchronous transport error).  This mirrors
//! `redundant_connection.rs`.
//!
//! Pre-fix, the second `dial_peer` call would proceed (no dedup), resulting in
//! two concurrent dials to the same peer — the bug.

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;

use libp2p::PeerId;
use libp2p::core::ConnectedPoint;
use libp2p::identity::Keypair;
use pharos_network::NetworkBuilder;
use pharos_types::MainnetBeaconSpec;
use pharos_types::phase0::primitives::ForkDigest;

use crate::common::TestHost;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

/// Build a syntactically-valid bare multiaddr to an unreachable address.
///
/// Returns a bare addr (no `/p2p` suffix) matching the new `dial_peer` API:
/// peer_id is passed separately and addresses must be bare.
fn unreachable_addr() -> libp2p::Multiaddr {
    "/ip4/127.0.0.2/tcp/19999".parse().unwrap()
}

/// Inbound endpoint for direct `on_swarm_connection_established` calls.
///
/// Inbound so that `on_swarm_connection_established` does NOT attempt to send
/// a Status RPC request, which would require a live transport connection.
fn inbound_endpoint() -> ConnectedPoint {
    let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();
    ConnectedPoint::Listener {
        local_addr: addr.clone(),
        send_back_addr: addr,
    }
}

/// Verify that a second concurrent dial to the same peer is suppressed.
///
/// Pre-fix: both `dial_peer` calls would succeed (return true) because there
/// was no dedup set.  Post-fix: only the first returns true.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dial_dedup_suppresses_second_concurrent_dial() {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (mut network, handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

    let remote_peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    let addr = unreachable_addr();

    // ── First dial: should be accepted ───────────────────────────────────────
    let first = network.dial_peer(remote_peer, vec![addr.clone()]);
    assert!(first, "first dial_peer call must return true");
    assert_eq!(
        network.test_pending_dials_len(),
        1,
        "pending_dials must have 1 entry after first dial"
    );
    assert!(
        network.test_pending_dials_contains(&remote_peer),
        "pending_dials must contain the peer after first dial"
    );

    // ── Second dial (same peer, in-flight): must be suppressed ───────────────
    // Pre-fix: this would also return true (no dedup) — the bug.
    let second = network.dial_peer(remote_peer, vec![addr.clone()]);
    assert!(
        !second,
        "second dial_peer call to same peer must return false"
    );
    assert_eq!(
        network.test_pending_dials_len(),
        1,
        "pending_dials must still have exactly 1 entry after suppressed second dial"
    );

    // ── Connection established (n=1): pending entry must be cleared ──────────
    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(1).unwrap(),
    );
    assert!(
        !network.test_pending_dials_contains(&remote_peer),
        "pending_dials must be cleared after ConnectionEstablished (n=1)"
    );
    assert_eq!(network.test_pending_dials_len(), 0);

    drop(handle);
}

/// Verify that `on_swarm_connection_established(n=2)` also clears pending_dials.
///
/// This covers the mutual-dial scenario: both sides dial simultaneously, libp2p
/// opens two connections.  The pending entry must be cleared on the FIRST
/// ConnectionEstablished event regardless of `num_established` value, because
/// the dial resolved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dial_dedup_cleared_on_mutual_dial_second_connection() {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (mut network, handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

    let remote_peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    let addr = unreachable_addr();

    // Initiate a dial to put the peer in pending_dials.
    assert!(network.dial_peer(remote_peer, vec![addr]));
    assert!(network.test_pending_dials_contains(&remote_peer));

    // Simulate the mutual-dial case: ConnectionEstablished fires with n=2
    // (a second connection opened before the first was fully tracked).
    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(2).unwrap(),
    );
    assert!(
        !network.test_pending_dials_contains(&remote_peer),
        "pending_dials must be cleared even for ConnectionEstablished n=2 (mutual-dial)"
    );

    drop(handle);
}

/// Verify that a dial to a different peer does NOT suppress a dial to our target.
///
/// Regression guard: the dedup set is keyed by PeerId, so unrelated peers
/// must not interfere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dial_dedup_distinct_peers_are_independent() {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (mut network, handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

    let peer_a: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    let peer_b: PeerId = Keypair::generate_secp256k1().public().to_peer_id();

    let addr_a = unreachable_addr();
    let addr_b = unreachable_addr();

    assert!(
        network.dial_peer(peer_a, vec![addr_a.clone()]),
        "dial to peer_a must succeed"
    );
    assert!(
        network.dial_peer(peer_b, vec![addr_b.clone()]),
        "dial to peer_b must succeed (distinct peer)"
    );
    assert_eq!(network.test_pending_dials_len(), 2);

    // Second dial to peer_a is suppressed; peer_b is unaffected.
    assert!(
        !network.dial_peer(peer_a, vec![addr_a]),
        "second dial to peer_a must be suppressed"
    );
    assert_eq!(
        network.test_pending_dials_len(),
        2,
        "only 2 entries: one per distinct peer"
    );

    drop(handle);
}
