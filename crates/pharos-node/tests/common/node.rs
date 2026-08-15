//! `pharos-node` integration test node spawner.
//!
//! `spawn_node` creates a real `HostImpl<MinimalEthSpec>` backed by a
//! `RocksStore` and wires it into `NetworkBuilder`, then drives the network
//! task in a background tokio task. Unlike the network-crate's `TestHost`,
//! this uses the real production host so persistence round-trips can be
//! exercised.
//!
//! The returned `TestNode` exposes the `NetworkHandle` and the bound listen
//! address so callers can dial from a second node.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use pharos_network::discovery::enr::Enr;
use pharos_network::{NetworkBuilder, NetworkEvent, NetworkHandle};
use pharos_node::host_impl::HostImpl;
use pharos_ssz::TreeHash;
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::MinimalEthSpec;
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::primitives::{Root, Version};
use pharos_types::state::BeaconBlock as ForkBeaconBlock;
use pharos_utils::Epoch;

use super::genesis::minimal_genesis;

// ── TestNode ──────────────────────────────────────────────────────────────────

/// A running `pharos-node` test instance.
///
/// Contains the `NetworkHandle` for issuing commands, the local `PeerId`, the
/// signed discv5 `Enr`, and the real bound TCP listen address.
#[allow(dead_code)]
pub struct TestNode {
    pub handle: NetworkHandle<MinimalEthSpec>,
    pub peer_id: PeerId,
    pub enr: Enr,
    pub listen_addr: Multiaddr,
}

// ── build_host ────────────────────────────────────────────────────────────────

/// Build a `HostImpl<MinimalEthSpec>` backed by a `RocksStore` at `path`.
///
/// Derives the anchor state from `minimal_genesis()` (cached, deterministic).
/// The genesis `SignedBeaconBlock` is constructed with `state_root` set to the
/// hash-tree-root of the genesis state and an empty (zero) signature, matching
/// the production cold-start convention.
///
/// All test nodes built this way share the same fork digest and can handshake
/// successfully.
#[allow(dead_code)]
pub fn build_host(path: &Path) -> HostImpl<MinimalEthSpec> {
    let store = Arc::new(
        RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
            path: path.join("chain_db"),
            create_if_missing: true,
        })
        .expect("open RocksStore"),
    );

    let genesis_state = minimal_genesis().clone();
    let state_root = genesis_state.tree_hash_root();
    let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MinimalBeaconBlock {
        state_root,
        ..pharos_types::phase0::MinimalBeaconBlock::default()
    });
    let fc_store =
        pharos_fork_choice::get_forkchoice_store::<MinimalEthSpec>(genesis_state, anchor_block);
    let fork_choice = Arc::new(RwLock::new(fc_store));

    let gvr = Root::default();
    // Phase0-only schedule: altair/bellatrix epochs = FAR_FUTURE, versions = mainnet defaults.
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
        altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
        altair_fork_epoch: Epoch(u64::MAX),
        bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
        bellatrix_fork_epoch: Epoch(u64::MAX),
        capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
        capella_fork_epoch: Epoch(u64::MAX),
        genesis_validators_root: gvr,
    };
    HostImpl::new(
        store,
        fork_choice,
        gvr,
        fork_schedule,
        0,
        Arc::new(pharos_types::RuntimeConfig::default()),
    )
}

// ── spawn_node ────────────────────────────────────────────────────────────────

/// Spawn a single `pharos-node` test node and wait for both `LocalEnr` and
/// `NewListenAddr` startup events.
///
/// Binds to OS-assigned ports. Pass `bootnodes` to connect to peer nodes at
/// startup; pass `[]` for a standalone node.
///
/// After `spawn_node` returns:
/// - `TestNode::listen_addr` is the real bound TCP multiaddr.
/// - `TestNode::enr` is the locally signed ENR including the real discv5 UDP port.
#[allow(dead_code)]
pub async fn spawn_node(
    bootnodes: Vec<Enr>,
    host: HostImpl<MinimalEthSpec>,
    key: Option<Keypair>,
) -> TestNode {
    let local_key = key.unwrap_or_else(Keypair::generate_secp256k1);
    let peer_id = local_key.public().to_peer_id();

    let discv5_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    let (mut handle, _discovery_handle) =
        NetworkBuilder::<MinimalEthSpec, HostImpl<MinimalEthSpec>, _>::new(host)
            .local_key(local_key)
            .listen_ip(listen_ip)
            .discv5_addr(discv5_addr)
            .bootnodes(bootnodes)
            .tcp_listen_port(0)
            .spawn()
            .await
            .expect("NetworkBuilder::spawn failed");

    // Collect events until we have both LocalEnr and NewListenAddr.
    let mut enr: Option<Enr> = None;
    let mut listen_addr: Option<Multiaddr> = None;

    while enr.is_none() || listen_addr.is_none() {
        match handle
            .next_event()
            .await
            .expect("network channel closed before startup events")
        {
            NetworkEvent::LocalEnr(e) => {
                enr = Some(e);
            }
            NetworkEvent::NewListenAddr(addr) if listen_addr.is_none() => {
                listen_addr = Some(addr);
            }
            _ => {}
        }
    }

    TestNode {
        handle,
        peer_id,
        enr: enr.unwrap(),
        listen_addr: listen_addr.unwrap(),
    }
}
