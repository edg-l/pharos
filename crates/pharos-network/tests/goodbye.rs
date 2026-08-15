mod common;

use std::time::Duration;

use common::{NetworkEvent, TestHost, spawn_node};
use pharos_types::phase0::primitives::ForkDigest;
use tokio::time::timeout;

/// Fork digest for node A: [0xaa, 0xbb, 0xcc, 0xdd].
const FORK_A: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
/// Fork digest for node B: [0x11, 0x22, 0x33, 0x44].
const FORK_B: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// When two nodes with different fork digests connect, the initiating node (A)
/// must detect the mismatch, send Goodbye(2 = IrrelevantNetwork), and disconnect.
///
/// Spec reference: `specs/phase0/p2p-interface.md:1394` — reason 2 = Irrelevant network.
/// This value is also `GOODBYE_IRRELEVANT_NETWORK = 2` in `crates/pharos-network/src/types.rs`.
///
/// A receives `NetworkEvent::PeerDisconnected(B.peer_id, DisconnectReason::Goodbye(2))`
/// within 5 seconds. The reason is plumbed via `peer_manager.note_disconnect_reason`
/// (set in `on_status_response` before calling `disconnect_peer_id`) so that when
/// libp2p delivers the `ConnectionClosed` event, `on_swarm_connection_closed` attaches
/// the pre-registered Goodbye(2) instead of the generic "clean close" fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_on_fork_digest_mismatch() {
    let fd_a = ForkDigest::from_array(FORK_A);
    let fd_b = ForkDigest::from_array(FORK_B);

    let mut node_a = spawn_node(vec![], TestHost::new(fd_a), false).await;
    let node_b = spawn_node(vec![], TestHost::new(fd_b), false).await;

    let b_listen = node_b.listen_addr.clone();
    let b_peer_id = node_b.peer_id;

    // A dials B.
    node_a.handle.dial(b_listen).await.expect("dial failed");

    // A must receive PeerDisconnected(B, Goodbye(2)) within 5 seconds.
    // The disconnect happens because:
    // 1. A sends Status(fork_digest=FORK_A) to B.
    // 2. B replies with Status(fork_digest=FORK_B).
    // 3. A detects the fork mismatch in on_status_response, pre-registers
    //    DisconnectReason::Goodbye(2), sends the Goodbye RPC, and disconnects.
    // 4. A receives ConnectionClosed → on_swarm_connection_closed uses the
    //    pre-registered reason → emits PeerDisconnected(B, Goodbye(2)).
    timeout(Duration::from_secs(5), async {
        loop {
            match node_a.handle.next_event().await.expect("channel closed") {
                NetworkEvent::PeerDisconnected(
                    id,
                    pharos_network::DisconnectReason::Goodbye(2),
                ) if id == b_peer_id => {
                    break;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("A did not receive PeerDisconnected(B, Goodbye(2)) within 5s");
}
