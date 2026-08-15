//! Integration test: Goodbye(ClientShutdown) on graceful node shutdown.
//!
//! Spec cite: `p2p-interface.md:1393` — reason code 1 = ClientShutdown.
//! D-shutdown-protocol: best-effort Goodbye, 500 ms bounded drain.
//!
//! When node A shuts down cleanly, it sends `Goodbye(1)` to every connected
//! peer before closing the TCP connection. Node B must observe
//! `NetworkEvent::PeerDisconnected(_, DisconnectReason::Goodbye(1))`.

mod common;

use std::time::Duration;

use common::{NetworkEvent, TestHost, spawn_node};
use pharos_network::DisconnectReason;
use pharos_network::types::GOODBYE_CLIENT_SHUTDOWN;
use pharos_types::phase0::primitives::ForkDigest;
use serial_test::serial;
use tokio::time::timeout;

/// Fork digest shared by both nodes so they complete the Status handshake.
const FORK: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

/// Node A shuts down via `NetworkHandle::shutdown`. Node B must receive
/// `NetworkEvent::PeerDisconnected(A, DisconnectReason::Goodbye(GOODBYE_CLIENT_SHUTDOWN))`
/// within 1 second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn shutdown_sends_goodbye_client_shutdown() {
    let fd = ForkDigest::from_array(FORK);

    let node_a = spawn_node(vec![], TestHost::new(fd), false).await;
    let mut node_b = spawn_node(vec![], TestHost::new(fd), false).await;

    let a_listen = node_a.listen_addr.clone();
    let a_peer_id = node_a.peer_id;

    // B dials A; both will complete the Status handshake (same fork digest).
    node_b.handle.dial(a_listen).await.expect("dial failed");

    // Wait for B to see PeerConnected(A) confirming the handshake is done.
    timeout(Duration::from_secs(5), async {
        loop {
            match node_b
                .handle
                .next_event()
                .await
                .expect("B event channel closed")
            {
                NetworkEvent::PeerConnected(id) if id == a_peer_id => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not see PeerConnected(A) within 5s");

    // Shut A down. This triggers shutdown_goodbye: A sends Goodbye(1) to B,
    // drains responses for up to 500 ms, then force-disconnects.
    node_a.handle.shutdown().await;

    // B must receive PeerDisconnected(A, Goodbye(GOODBYE_CLIENT_SHUTDOWN)) within 1 s.
    timeout(Duration::from_secs(1), async {
        loop {
            match node_b
                .handle
                .next_event()
                .await
                .expect("B event channel closed")
            {
                NetworkEvent::PeerDisconnected(id, DisconnectReason::Goodbye(code))
                    if id == a_peer_id && code == GOODBYE_CLIENT_SHUTDOWN =>
                {
                    break;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("B did not receive PeerDisconnected(A, Goodbye(1)) within 1s");
}
