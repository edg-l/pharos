//! Integration test: two pharos-node instances exchange persisted blocks, node
//! A restarts, and B retrieves the same blocks again.
//!
//! Exercises:
//! 1. Block persistence across `HostImpl`/`RocksStore` open/close.
//! 2. `BlocksByRange` req-resp over a real libp2p TCP connection.
//! 3. Peer reconnect after one side kills and restarts.
//!
//! The test is `#[serial]` because it binds OS-assigned ports and spawns real
//! network tasks. Parallel execution with other port-binding tests risks
//! flakiness from resource contention; `serial_test::serial` prevents that.
//!
//! Spec cites: `p2p-interface.md:1413-1417` (BlocksByRange ordering).
//! `D-rocksdb` warm-restart correctness (M3a Edge Cases).

mod common;

use std::time::Duration;

use pharos_network::NetworkEvent;
use pharos_network::rpc::types::RpcRequest;
use pharos_storage::{BlockTransition, RocksStore, RocksStoreConfig, Store as StoreTrait};
use pharos_types::MinimalEthSpec;
use pharos_types::phase0::{
    BeaconBlocksByRangeRequest, MinimalBeaconBlock, MinimalSignedBeaconBlock, Slot,
};
use serial_test::serial;

use common::node::{build_host, spawn_node};

/// Build 10 synthetic blocks at slots 1..=10.
///
/// Blocks are default-valued except for `slot`, which is unique. Each block's
/// root is `hash_tree_root(block.message)` so roots are deterministic and
/// distinct per slot.
fn make_blocks() -> Vec<(
    pharos_types::phase0::primitives::Root,
    MinimalSignedBeaconBlock,
)> {
    use pharos_ssz::TreeHash;
    (1u64..=10)
        .map(|n| {
            let block = MinimalSignedBeaconBlock {
                message: MinimalBeaconBlock {
                    slot: Slot(n),
                    ..MinimalBeaconBlock::default()
                },
                ..MinimalSignedBeaconBlock::default()
            };
            let root = block.message.tree_hash_root();
            (root, block)
        })
        .collect()
}

/// Populate a `RocksStore` at `path` with the given blocks.
///
/// Uses `write_block_transition` to write both the block and its slot-index
/// entry atomically so that `get_blocks_by_range` (which iterates the
/// `slot_to_block_root` CF) can find them.
fn populate_store(
    path: &std::path::Path,
    blocks: &[(
        pharos_types::phase0::primitives::Root,
        MinimalSignedBeaconBlock,
    )],
) {
    let store = RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
        path: path.join("chain_db"),
        create_if_missing: true,
    })
    .expect("open RocksStore for pre-population");

    for (root, block) in blocks {
        let transition = BlockTransition::<MinimalEthSpec> {
            block: Some((*root, block.clone())),
            slot_index: Some((block.message.slot, *root)),
            state: None,
            forkchoice: None,
        };
        <RocksStore as StoreTrait<MinimalEthSpec>>::write_block_transition(&store, transition)
            .expect("write_block_transition must succeed");
    }
    // Store closes here (dropped).
}

/// Wait for `NetworkEvent::PeerConnected` on `handle`.
///
/// Panics if the channel closes before a `PeerConnected` event is received.
/// Uses a 10-second timeout to prevent test hangs.
async fn wait_connected(handle: &mut pharos_network::NetworkHandle<MinimalEthSpec>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = handle
                .next_event()
                .await
                .expect("network channel closed waiting for PeerConnected");
            if let NetworkEvent::PeerConnected(_) = event {
                return;
            }
        }
    })
    .await
    .expect("timed out waiting for PeerConnected");
}

/// Two-node persisted-block exchange with warm restart of node A.
///
/// Steps:
/// 1. Pre-populate node A's store with blocks at slots 1..=10.
/// 2. Spawn A and B; B dials A; wait for `PeerConnected` on B.
/// 3. B issues `BlocksByRange(start_slot=1, count=10)` to A.
/// 4. Assert all 10 blocks, in slot order.
/// 5. Shut down A. Restart A at the same datadir; B re-dials; wait for reconnect.
/// 6. B issues the same request. Assert the same 10 blocks again.
#[tokio::test]
#[serial]
async fn persisted_blocks_survive_restart() {
    // ── Build test data ───────────────────────────────────────────────────────

    let blocks = make_blocks();
    let dir_a = tempfile::TempDir::new().unwrap();

    // Pre-populate before any node is running so the DB is cleanly closed.
    populate_store(dir_a.path(), &blocks);

    // ── First boot of A ───────────────────────────────────────────────────────

    let dir_b = tempfile::TempDir::new().unwrap();
    let host_a1 = build_host(dir_a.path());
    let host_b = build_host(dir_b.path());

    let node_a1 = spawn_node(vec![], host_a1, None).await;
    let mut node_b = spawn_node(vec![node_a1.enr.clone()], host_b, None).await;

    // B dials A.
    node_b
        .handle
        .dial(node_a1.listen_addr.clone())
        .await
        .expect("dial must succeed");

    wait_connected(&mut node_b.handle).await;

    // ── First BlocksByRange round-trip ────────────────────────────────────────

    let req = RpcRequest::BlocksByRange(BeaconBlocksByRangeRequest {
        start_slot: Slot(1),
        count: 10,
        step: 1,
    });
    let resp = node_b
        .handle
        .request(node_a1.peer_id, req.clone(), Duration::from_secs(10))
        .await
        .expect("BlocksByRange request must succeed");

    let received_blocks = match resp {
        pharos_network::rpc::types::RpcResponse::BlocksByRange(v) => v,
        _other => panic!("expected BlocksByRange response, got unexpected variant"),
    };

    assert_eq!(received_blocks.len(), 10, "must receive exactly 10 blocks");
    for (i, blk) in received_blocks.iter().enumerate() {
        assert_eq!(
            blk.message.slot.0,
            (i as u64) + 1,
            "blocks must be in ascending slot order"
        );
    }

    // ── Shut down A ───────────────────────────────────────────────────────────

    node_a1.handle.shutdown().await;
    // Give tokio a tick to process the shutdown.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Restart A at the same datadir ─────────────────────────────────────────

    let host_a2 = build_host(dir_a.path());
    let node_a2 = spawn_node(vec![], host_a2, None).await;

    // B re-dials the restarted A at its new listen address.
    node_b
        .handle
        .dial(node_a2.listen_addr.clone())
        .await
        .expect("re-dial must succeed");

    wait_connected(&mut node_b.handle).await;

    // ── Second BlocksByRange round-trip (same blocks, warm restart) ───────────

    let resp2 = node_b
        .handle
        .request(node_a2.peer_id, req, Duration::from_secs(10))
        .await
        .expect("BlocksByRange request on restarted node must succeed");

    let received_blocks2 = match resp2 {
        pharos_network::rpc::types::RpcResponse::BlocksByRange(v) => v,
        _other => panic!("expected BlocksByRange response after restart, got unexpected variant"),
    };

    assert_eq!(
        received_blocks2.len(),
        10,
        "must receive exactly 10 blocks after restart"
    );
    for (i, blk) in received_blocks2.iter().enumerate() {
        assert_eq!(
            blk.message.slot.0,
            (i as u64) + 1,
            "blocks must be in ascending slot order after restart"
        );
    }

    // Assert SSZ equality between first and second round-trips.
    assert_eq!(
        received_blocks, received_blocks2,
        "blocks from restarted node must be SSZ-equal to original"
    );

    // ── Cleanup ───────────────────────────────────────────────────────────────

    node_a2.handle.shutdown().await;
    node_b.handle.shutdown().await;
}
