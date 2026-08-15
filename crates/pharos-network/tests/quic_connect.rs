mod common;

use std::time::Duration;

use common::{NetworkEvent, TestHost, spawn_node};
use pharos_types::phase0::primitives::ForkDigest;
use tokio::time::timeout;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
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
