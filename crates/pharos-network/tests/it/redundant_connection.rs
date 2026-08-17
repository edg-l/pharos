//! Integration test for RC2: num_established gate on peer
//! (de)registration.
//!
//! ## Approach: fallback — direct handler test with synthetic num_established
//!
//! The preferred approach (two in-process nodes, open a real second TCP
//! connection between the same peer pair, close it) is not viable because
//! libp2p's transport layer deduplicates connections to the same peer: a
//! second dial to a peer that is already connected returns a transport error
//! before `SwarmEvent::ConnectionEstablished` can fire for the duplicate.
//! Fighting that would require OS-level TCP tricks, making the test brittle
//! and platform-dependent.
//!
//! Instead we directly call `on_swarm_connection_established` and
//! `on_swarm_connection_closed` on a real `Network` instance (obtained via
//! `NetworkBuilder::build()`) with synthetic `num_established` values.  This
//! lets us precisely verify the gating logic without transport hackery.
//!
//! ## Why the tests are fail-first
//!
//! Against pre-Phase-2 code (no num_established gate):
//! - `on_swarm_connection_established(n=2)` would call `peer_manager.on_connected`,
//!   registering the peer.  Assertion "NOT registered after n=2" would fail.
//! - `on_swarm_connection_closed(remaining=1)` would call `peer_manager.on_disconnected`,
//!   removing the peer.  Assertion "still registered after non-last close" would fail.

use std::num::NonZeroU32;

use std::net::{Ipv4Addr, SocketAddr};

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

/// Construct a fake inbound `ConnectedPoint` for use in direct handler tests.
///
/// We use an inbound (Listener) endpoint so that `on_swarm_connection_established`
/// does NOT attempt to send a Status RPC request via the swarm (which would
/// require an active transport connection to the remote peer).
fn inbound_endpoint() -> ConnectedPoint {
    let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();
    ConnectedPoint::Listener {
        local_addr: addr.clone(),
        send_back_addr: addr,
    }
}

/// Verify that the num_established gate correctly prevents peer table corruption
/// from redundant libp2p connections.
///
/// State machine exercised:
/// 1. ConnectionEstablished(n=2) — redundant: peer NOT registered.
/// 2. ConnectionEstablished(n=1) — first:     peer IS registered.
/// 3. ConnectionClosed(remaining=1) — non-last: peer STILL registered.
/// 4. ConnectionClosed(remaining=0) — last:     peer REMOVED.
///
/// Steps 1 and 3 are the fail-first assertions: they would fail against the
/// pre-Phase-2 code that ignores `num_established`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn num_established_gate_preserves_peer_on_redundant_connection() {
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

    // ── Step 1: redundant establish (num_established = 2) ─────────────────────
    // Pre-Phase-2: registers the peer. Post-Phase-2: does nothing (trace only).
    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(2).unwrap(),
    );
    assert!(
        !network.test_peer_is_registered(&remote_peer),
        "redundant ConnectionEstablished (n=2) must NOT register the peer"
    );

    // ── Step 2: first connection established (num_established = 1) ────────────
    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(1).unwrap(),
    );
    assert!(
        network.test_peer_is_registered(&remote_peer),
        "first ConnectionEstablished (n=1) must register the peer"
    );

    // ── Step 3: non-last close (remaining = 1) ────────────────────────────────
    // Pre-Phase-2: removes the peer. Post-Phase-2: does nothing (trace only).
    network
        .on_swarm_connection_closed(remote_peer, None, 1)
        .await;
    assert!(
        network.test_peer_is_registered(&remote_peer),
        "non-last ConnectionClosed (remaining=1) must NOT remove the peer"
    );

    // ── Step 4: last close (remaining = 0) ────────────────────────────────────
    // Both old and new code remove and emit PeerDisconnected.
    network
        .on_swarm_connection_closed(remote_peer, None, 0)
        .await;
    assert!(
        !network.test_peer_is_registered(&remote_peer),
        "last ConnectionClosed (remaining=0) must remove the peer"
    );

    // The Network is not running (run() was not called), so events accumulate in
    // the channel but are not drained here. The critical assertions are (1)-(4).
    drop(handle);
}

/// Verify that a normal single-connection lifecycle is unaffected by the gate.
///
/// establish(n=1) → close(remaining=0) must register then remove, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_connection_lifecycle_is_clean() {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (mut network, _handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

    let remote_peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();

    assert!(
        !network.test_peer_is_registered(&remote_peer),
        "peer must not be registered before any connection"
    );

    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(1).unwrap(),
    );
    assert!(
        network.test_peer_is_registered(&remote_peer),
        "peer must be registered after first establish"
    );

    network
        .on_swarm_connection_closed(remote_peer, None, 0)
        .await;
    assert!(
        !network.test_peer_is_registered(&remote_peer),
        "peer must be removed after last close"
    );
}

/// Verify that a redundant establish followed immediately by a non-last close
/// does not register or corrupt the peer state.
///
/// Scenario: libp2p fires ConnectionEstablished(n=2) then ConnectionClosed(remaining=1)
/// for a transient second connection — the primary connection is still live.
/// The peer that was registered from n=1 must survive intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redundant_establish_then_non_last_close_leaves_peer_intact() {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (mut network, _handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

    let remote_peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();

    // Primary connection opens first.
    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(1).unwrap(),
    );
    assert!(network.test_peer_is_registered(&remote_peer));

    // A redundant connection opens (n=2).
    network.on_swarm_connection_established(
        remote_peer,
        inbound_endpoint(),
        NonZeroU32::new(2).unwrap(),
    );
    assert!(
        network.test_peer_is_registered(&remote_peer),
        "peer must still be registered after redundant n=2 establish"
    );

    // The redundant connection closes (remaining=1 — primary still up).
    network
        .on_swarm_connection_closed(remote_peer, None, 1)
        .await;
    assert!(
        network.test_peer_is_registered(&remote_peer),
        "peer must still be registered after non-last close (remaining=1)"
    );

    // Primary connection closes (remaining=0 — peer gone).
    network
        .on_swarm_connection_closed(remote_peer, None, 0)
        .await;
    assert!(
        !network.test_peer_is_registered(&remote_peer),
        "peer must be removed after last close (remaining=0)"
    );
}
