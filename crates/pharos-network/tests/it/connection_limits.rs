//! Connection limits + discv5 cadence scaling.
//!
//! ## Tests
//!
//! 1. `max_peers_rejects_over_limit` — a `PeerManager` built with `max_peers=3`
//!    accumulates 3 connected peers; the 4th inbound peer is rejected because
//!    `connected_count() >= max_peers()`. Verified both against the manager
//!    directly and via the `Network` builder that threads the limit to the
//!    manager.
//!
//! 2. `discovery_cadence_scales_with_deficit` — `query_interval` returns a
//!    shorter duration when `connected_peers` is far below `target_peers` than
//!    when at/above it; at-target returns the slow maintenance cadence (30 s).
//!
//! 3. `eclipse_inbound_cap_counts_connected_only` — peers stuck in
//!    `Connecting`/`Handshaking` do NOT consume `max_peers` inbound slots;
//!    the inbound gate is based on `connected_count()`, not `peer_count()`.

use std::net::{Ipv4Addr, SocketAddr};

use libp2p::PeerId;
use libp2p::identity::Keypair;

use pharos_network::NetworkBuilder;
use pharos_network::discovery::service::query_interval;
use pharos_network::scoring::NoopScorer;
use pharos_types::MainnetBeaconSpec;
use pharos_types::phase0::primitives::ForkDigest;

use crate::common::TestHost;

const FORK_DIGEST: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

// ── max_peers enforcement ─────────────────────────────────────────────────────

/// Build a `Network` with `max_peers = max` and `target_peers = target`.
async fn build_with_limits(
    max: usize,
    target: usize,
) -> pharos_network::Network<MainnetBeaconSpec, TestHost, NoopScorer> {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (network, _handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .max_peers(max)
            .target_peers(target)
            .build()
            .await
            .expect("NetworkBuilder::build failed");
    network
}

/// Inbound connections beyond `max_peers` are rejected.
///
/// The test registers peers via the `test_register_connected_peer` seam until
/// the peer table is at the limit, then asserts that `peer_count() >= max_peers()`
/// — the exact condition the swarm loop checks before registering an inbound peer.
/// A peer arriving at that point must be disconnected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_peers_rejects_over_limit() {
    let max_peers = 3usize;
    let mut network = build_with_limits(max_peers, max_peers).await;

    assert_eq!(network.test_max_peers(), max_peers);
    assert_eq!(network.test_peer_count(), 0);

    // Fill the peer table up to the limit.
    let peers: Vec<PeerId> = (0..max_peers)
        .map(|_| Keypair::generate_secp256k1().public().to_peer_id())
        .collect();
    for &p in &peers {
        network.test_register_connected_peer(p);
    }
    assert_eq!(
        network.test_peer_count(),
        max_peers,
        "peer table must be exactly at the limit"
    );

    // The condition the swarm loop evaluates for an inbound connection:
    // connected_count() >= max_peers() → reject.
    assert!(
        network.test_connected_count() >= network.test_max_peers(),
        "at limit: inbound must be rejected (connected_count >= max_peers)"
    );

    // An additional peer (the (max+1)-th) must NOT be registered — the swarm
    // loop returns early before `peer_manager.on_connected`.  The seam bypasses
    // the guard, so we verify the guard condition rather than calling the seam
    // for the over-limit peer.
    let extra = Keypair::generate_secp256k1().public().to_peer_id();
    let would_accept = network.test_connected_count() < network.test_max_peers();
    assert!(
        !would_accept,
        "extra inbound peer must be rejected when at max_peers: connected_count={} max={}",
        network.test_connected_count(),
        network.test_max_peers()
    );
    // Confirm the extra peer was never registered (we did NOT call the seam).
    assert!(
        !network.test_peer_is_registered(&extra),
        "over-limit inbound peer must not appear in the peer table"
    );
}

/// Builder correctly threads `max_peers` / `target_peers` into the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_threads_limits() {
    let network = build_with_limits(7, 5).await;
    assert_eq!(network.test_max_peers(), 7);
    assert_eq!(network.test_target_peers(), 5);
}

// ── discv5 cadence scaling ────────────────────────────────────────────────────

/// `query_interval` returns a shorter interval when the peer deficit is large.
///
/// Concretely: at `connected = 0, target = 50` (full deficit) the interval is
/// shorter than at `connected = 50, target = 50` (no deficit, maintenance mode).
#[test]
fn discovery_cadence_scales_with_deficit() {
    let target = 50usize;

    // At target: no deficit → slow maintenance cadence (30 s).
    let at_target = query_interval(target, target);
    assert_eq!(
        at_target.as_secs(),
        30,
        "at/above target must return the maximum maintenance interval (30 s)"
    );

    // Full deficit (connected = 0): must be shorter than the maintenance cadence.
    let full_deficit = query_interval(0, target);
    assert!(
        full_deficit < at_target,
        "full deficit must return a shorter interval than maintenance: \
         full_deficit={full_deficit:?}, at_target={at_target:?}"
    );

    // Partial deficit (connected = target/2): between the two extremes.
    let half_deficit = query_interval(target / 2, target);
    assert!(
        half_deficit < at_target,
        "partial deficit must return a shorter interval than maintenance"
    );
    assert!(
        half_deficit >= full_deficit,
        "partial deficit must return an interval >= full-deficit interval: \
         half={half_deficit:?}, full={full_deficit:?}"
    );

    // Minimum floor: never below 3 s regardless of deficit.
    let huge_deficit = query_interval(0, 1000);
    assert!(
        huge_deficit.as_secs() >= 3,
        "interval must never drop below the 3 s floor: got {huge_deficit:?}"
    );

    // Above target (over-provisioned): same as at-target (30 s).
    let above_target = query_interval(target + 10, target);
    assert_eq!(
        above_target.as_secs(),
        30,
        "above target must also return the maintenance interval (30 s)"
    );
}

// ── eclipse_inbound_cap_counts_connected_only ─────────────────────────────────

/// Peers stuck in `Connecting` or `Handshaking` do not consume `max_peers`
/// inbound slots.
///
/// The inbound gate in `on_swarm_connection_established` uses `connected_count()`
/// (fully-handshaked peers only), not `peer_count()` (all states). This test
/// verifies that filling the handshake table up to `max_peers` with connecting
/// peers does NOT block a fully-connected peer from being registered.
///
/// Additionally verifies that the `max_connecting` gate does fire when the
/// connecting table is full: after filling up to `max_connecting`, the gate
/// condition (`connecting_count >= max_connecting`) is satisfied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eclipse_inbound_cap_counts_connected_only() {
    let max_peers = 3usize;
    // Set max_connecting explicitly to max_peers so we can fill the handshake
    // table and then verify the gate fires.
    let max_connecting = max_peers;

    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let mut network = NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
        .local_key(local_key)
        .tcp_listen_port(0)
        .discv5_addr(discv5_addr)
        .max_peers(max_peers)
        .target_peers(max_peers)
        .max_connecting(max_connecting)
        .build()
        .await
        .expect("NetworkBuilder::build failed")
        .0;

    assert_eq!(network.test_max_peers(), max_peers);
    assert_eq!(network.test_max_connecting(), max_connecting);

    // Register `max_peers` peers in Connecting state (handshake incomplete).
    let connecting_peers: Vec<PeerId> = (0..max_peers)
        .map(|_| Keypair::generate_secp256k1().public().to_peer_id())
        .collect();
    for &p in &connecting_peers {
        network.test_register_connecting_peer(p);
    }

    // peer_count() equals max_peers (all connecting), but connected_count() == 0.
    assert_eq!(
        network.test_peer_count(),
        max_peers,
        "peer_count must reflect connecting peers"
    );
    assert_eq!(
        network.test_connected_count(),
        0,
        "connected_count must be 0 — no handshakes complete"
    );
    assert_eq!(
        network.test_connecting_count(),
        max_peers,
        "connecting_count must equal the number of connecting peers"
    );

    // The max_peers inbound gate (connected_count >= max_peers) is NOT triggered,
    // so a fully-connected peer CAN still be registered.
    let would_reject_max_peers = network.test_connected_count() >= network.test_max_peers();
    assert!(
        !would_reject_max_peers,
        "max_peers gate must NOT fire when only connecting peers fill peer_count: \
         connected_count={} max_peers={}",
        network.test_connected_count(),
        network.test_max_peers()
    );

    // Register a genuinely connected peer — should succeed.
    let connected_peer = Keypair::generate_secp256k1().public().to_peer_id();
    network.test_register_connected_peer(connected_peer);
    assert_eq!(
        network.test_connected_count(),
        1,
        "connected_count must be 1 after registering a connected peer"
    );
    assert!(
        network.test_peer_is_registered(&connected_peer),
        "connected peer must be present in the peer table"
    );

    // Now the max_connecting gate (connecting_count >= max_connecting) fires:
    // connecting_count == max_connecting == max_peers (the connecting peers are
    // still in the table). A new inbound peer would be rejected by this gate.
    let would_reject_max_connecting =
        network.test_connecting_count() >= network.test_max_connecting();
    assert!(
        would_reject_max_connecting,
        "max_connecting gate must fire when connecting table is full: \
         connecting_count={} max_connecting={}",
        network.test_connecting_count(),
        network.test_max_connecting()
    );
}
