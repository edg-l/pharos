//! RPC round-trip benchmark: `BeaconBlocksByRange` over loopback.
//!
//! Spawns two `Network<E>` instances, completes the Status handshake, then
//! measures the full wire round-trip cost of a `BlocksByRange(count=1)` request.
//!
//! The tokio runtime is built ONCE in bench setup (outside the criterion
//! closure) to avoid the overhead of creating/tearing down thousands of
//! runtimes per criterion sample.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};

use pharos_network::host::{
    BlobProvider, BlockProvider, DataColumnProvider, ForkContext, GossipValidator, GossipVerdict,
    LightClientProvider,
};
use pharos_network::scoring::NoopScorer;
use pharos_network::types::{Fork, SubnetId};
use pharos_network::{NetworkBuilder, NetworkEvent, NetworkHandle, RpcRequest};
use pharos_types::MainnetBeaconSpec as E;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::phase0::primitives::ForkDigest;
use pharos_types::phase0::{
    Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing, Root,
    SignedAggregateAndProof, SignedVoluntaryExit, Slot,
};
use pharos_utils::{Bytes4, Epoch};

// ── Minimal in-bench host ─────────────────────────────────────────────────────

/// Minimal `Host<E>` for benchmarking: accepts all gossip, returns empty blocks.
struct BenchHost {
    fork_digest: ForkDigest,
}

impl BenchHost {
    fn new(fd: [u8; 4]) -> Self {
        Self {
            fork_digest: ForkDigest::from_array(fd),
        }
    }
}

impl ForkContext for BenchHost {
    fn current_fork_digest(&self) -> ForkDigest {
        self.fork_digest
    }
    fn enr_fork_id(&self) -> ENRForkID {
        ENRForkID {
            fork_digest: self.fork_digest,
            next_fork_version: Bytes4::from_array([0u8; 4]),
            next_fork_epoch: Epoch(u64::MAX),
        }
    }
    fn genesis_validators_root(&self) -> Root {
        Root::default()
    }
    fn fork_digest_for(&self, _fork: Fork) -> ForkDigest {
        self.fork_digest
    }
    fn fork_from_context(&self, ctx: &[u8; 4]) -> Option<Fork> {
        if *ctx == self.fork_digest.into_inner() {
            Some(Fork::Phase0)
        } else {
            None
        }
    }
    fn local_metadata(&self) -> AltairMetaData {
        AltairMetaData::default()
    }
}

type LcBootstrap = <E as pharos_types::BeaconSpec>::AltairLightClientBootstrap;
type LcUpdate = <E as pharos_types::BeaconSpec>::AltairLightClientUpdate;

impl LightClientProvider<E> for BenchHost {
    fn light_client_bootstrap(&self, _root: Root) -> Option<LcBootstrap> {
        None
    }
    fn light_client_updates_by_range(&self, _start: u64, _count: u64) -> Vec<LcUpdate> {
        vec![]
    }
    fn light_client_finality_update(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::AltairLightClientFinalityUpdate> {
        None
    }
    fn light_client_optimistic_update(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::AltairLightClientOptimisticUpdate> {
        None
    }

    fn light_client_finality_update_capella(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::CapellaLightClientFinalityUpdate> {
        None
    }

    fn light_client_optimistic_update_capella(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::CapellaLightClientOptimisticUpdate> {
        None
    }

    fn light_client_finality_update_deneb(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::DenebLightClientFinalityUpdate> {
        None
    }

    fn light_client_optimistic_update_deneb(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::DenebLightClientOptimisticUpdate> {
        None
    }

    fn light_client_finality_update_electra(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::ElectraLightClientFinalityUpdate> {
        None
    }

    fn light_client_optimistic_update_electra(
        &self,
    ) -> Option<<E as pharos_types::BeaconSpec>::ElectraLightClientOptimisticUpdate> {
        None
    }
}

impl BlockProvider<E> for BenchHost {
    fn block_by_root(
        &self,
        _root: Root,
    ) -> Option<<E as pharos_types::BeaconSpec>::SignedBeaconBlock> {
        None
    }
    /// Returns empty Vec — bench measures wire round-trip cost, not body fetching.
    fn blocks_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
    ) -> Vec<<E as pharos_types::BeaconSpec>::SignedBeaconBlock> {
        vec![]
    }
    fn finalized_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            root: Root::default(),
            epoch: Epoch(0),
        }
    }
    fn head(&self) -> (Root, Slot) {
        // Return a large head slot so the historical-window check passes for
        // any requested start_slot in the bench.
        (Root::default(), Slot(2_000_000))
    }
}

impl GossipValidator<E> for BenchHost {
    fn validate_beacon_block(
        &self,
        _block: &<E as pharos_types::BeaconSpec>::SignedBeaconBlock,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_attestation(&self, _subnet: SubnetId, _att: &Attestation<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_aggregate_and_proof(&self, _msg: &SignedAggregateAndProof<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_voluntary_exit(&self, _exit: &SignedVoluntaryExit) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_proposer_slashing(&self, _slashing: &ProposerSlashing) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_attester_slashing(&self, _slashing: &AttesterSlashing<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_sync_committee_message(
        &self,
        _subnet: SubnetId,
        _msg: &pharos_types::altair::SyncCommitteeMessage,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_sync_committee_contribution_and_proof(
        &self,
        _msg: &<E as pharos_types::BeaconSpec>::AltairSignedContributionAndProof,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_light_client_finality_update(
        &self,
        _msg: &<E as pharos_types::BeaconSpec>::AltairLightClientFinalityUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }
    fn validate_light_client_optimistic_update(
        &self,
        _msg: &<E as pharos_types::BeaconSpec>::AltairLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_bls_to_execution_change(
        &self,
        _msg: &pharos_types::capella::operations::SignedBLSToExecutionChange,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_capella_light_client_finality_update(
        &self,
        _msg: &<E as pharos_types::BeaconSpec>::CapellaLightClientFinalityUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_capella_light_client_optimistic_update(
        &self,
        _msg: &<E as pharos_types::BeaconSpec>::CapellaLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_blob_sidecar(
        &self,
        _subnet: pharos_network::types::SubnetId,
        _sidecar: &pharos_types::deneb::BlobSidecar,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }
}

impl BlobProvider<E> for BenchHost {
    fn blobs_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
    ) -> Vec<pharos_types::deneb::BlobSidecar> {
        Vec::new()
    }
    fn blobs_by_root(&self, _ids: &[(Root, u64)]) -> Vec<pharos_types::deneb::BlobSidecar> {
        Vec::new()
    }
}

impl DataColumnProvider<E> for BenchHost {
    fn data_columns_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
        _columns: &[u64],
    ) -> Vec<pharos_types::fulu::DataColumnSidecar<4096, 4>> {
        Vec::new()
    }
    fn data_columns_by_root(
        &self,
        _ids: &[(Root, Vec<u64>)],
    ) -> Vec<pharos_types::fulu::DataColumnSidecar<4096, 4>> {
        Vec::new()
    }
}

// ── Spawn helpers ─────────────────────────────────────────────────────────────

/// Spawn a single bench node and return `(handle, peer_id, listen_addr)`.
async fn spawn_bench_node(fd: [u8; 4]) -> (NetworkHandle<E>, PeerId, Multiaddr) {
    let local_key = Keypair::generate_secp256k1();
    let peer_id = local_key.public().to_peer_id();
    let discv5_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    let (mut handle, _disc) = NetworkBuilder::<E, BenchHost, NoopScorer>::new(BenchHost::new(fd))
        .local_key(local_key)
        .listen_ip(listen_ip)
        .discv5_addr(discv5_addr)
        .tcp_listen_port(0)
        .spawn()
        .await
        .expect("NetworkBuilder::spawn failed");

    let mut listen_addr: Option<Multiaddr> = None;
    while listen_addr.is_none() {
        if let NetworkEvent::NewListenAddr(addr) =
            handle.next_event().await.expect("channel closed")
        {
            listen_addr = Some(addr);
        }
    }

    (handle, peer_id, listen_addr.unwrap())
}

/// Dial B from A; wait for `PeerConnected` on both sides.
async fn connect_peers(
    node_a: &mut NetworkHandle<E>,
    node_b_addr: Multiaddr,
    node_b_id: PeerId,
    node_b: &mut NetworkHandle<E>,
    node_a_id: PeerId,
) {
    node_a.dial(node_b_addr).await.expect("dial failed");

    // Drain events until both sides see PeerConnected.
    let mut a_connected = false;
    let mut b_connected = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !a_connected || !b_connected {
        tokio::select! {
            event = node_a.next_event(), if !a_connected => {
                if matches!(event, Some(NetworkEvent::PeerConnected(id)) if id == node_b_id) {
                    a_connected = true;
                }
            }
            event = node_b.next_event(), if !b_connected => {
                if matches!(event, Some(NetworkEvent::PeerConnected(id)) if id == node_a_id) {
                    b_connected = true;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!("PeerConnected not received within 10s");
            }
        }
    }
}

// ── Criterion benchmark ───────────────────────────────────────────────────────

fn criterion_benchmark(c: &mut Criterion) {
    // Build the tokio runtime ONCE. Building a fresh Runtime on every criterion
    // sample would create thousands of runtimes per bench run and dominate the
    // wire-roundtrip measurement; criterion's docs flag this exact anti-pattern.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    const FD: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

    let (mut node_a, node_a_id, mut node_b, node_b_id, addr_b) = rt.block_on(async {
        let (a, a_id, _addr_a) = spawn_bench_node(FD).await;
        let (b, b_id, addr_b) = spawn_bench_node(FD).await;
        (a, a_id, b, b_id, addr_b)
    });

    rt.block_on(connect_peers(
        &mut node_a,
        addr_b,
        node_b_id,
        &mut node_b,
        node_a_id,
    ));

    let req = RpcRequest::BlocksByRange(pharos_types::phase0::BeaconBlocksByRangeRequest {
        start_slot: Slot(1),
        count: 1,
        step: 1,
    });

    c.bench_function("rpc_roundtrip/blocks_by_range_count_1", |b| {
        b.iter(|| {
            rt.block_on(async {
                node_a
                    .request(node_b_id, req.clone(), Duration::from_secs(2))
                    .await
                    .expect("BlocksByRange request failed in bench")
            })
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
