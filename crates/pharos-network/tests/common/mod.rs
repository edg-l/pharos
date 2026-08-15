//! Shared test scaffolding for pharos-network integration tests.
//!
//! `TestNode` wraps a running `NetworkHandle` with the peer's `PeerId`, `Enr`,
//! and real bound `listen_addr`. `TestHost` provides an in-memory `Host<E>`
//! implementation with a configurable `GossipValidator`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
pub use pharos_network::NetworkEvent;
use pharos_network::discovery::enr::Enr;
use pharos_network::host::{
    BlockProvider, ForkContext, GossipValidator, GossipVerdict, LightClientProvider,
};
use pharos_network::scoring::{PeerScorer, ScoreEvent};
use pharos_network::types::{Fork, SubnetId};
use pharos_network::{NetworkBuilder, NetworkHandle};
use pharos_types::MainnetEthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::phase0::primitives::ForkDigest;
use pharos_types::phase0::{
    AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
    Root, SignedVoluntaryExit, Slot,
};
use pharos_utils::{Bytes4, Epoch};

type LcBootstrap = <MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientBootstrap;
type LcUpdate = <MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientUpdate;

// ── TestHost ──────────────────────────────────────────────────────────────────

/// In-memory host implementation for integration tests.
///
/// Provides a configurable `GossipValidator` that either accepts all blocks or
/// rejects blocks whose `proposer_index` equals a configured sentinel value.
pub struct TestHost {
    fork_digest: ForkDigest,
    /// Altair fork digest for context-bytes codec tests. When `None`, the phase-0
    /// digest is used for all forks (safe for tests that don't exercise altair).
    altair_fork_digest: Option<ForkDigest>,
    blocks: Arc<Mutex<HashMap<Root, <MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock>>>,
    /// When `Some(idx)`, `validate_beacon_block` rejects any block with
    /// `proposer_index == idx`.
    reject_proposer_index: Option<u64>,
    /// The slot to report as the chain head, used to pass the historical window
    /// check in `handle_request` for `BlocksByRange`. Must be large enough that
    /// `start_slot >= head_slot - (min_epochs * SLOTS_PER_EPOCH)`.
    /// For mainnet: min_epochs = 33024, SLOTS_PER_EPOCH = 32, so offset = 1,056,768.
    /// Tests using slots [10..15] require head_slot >= 1,056,778. Default: 2,000,000.
    head_slot: Slot,
    /// Optional preloaded `LightClientBootstrap` objects keyed by block root.
    lc_bootstraps: Arc<Mutex<HashMap<Root, LcBootstrap>>>,
    /// Optional preloaded `LightClientUpdate` list for `UpdatesByRange` responses.
    lc_updates: Arc<Mutex<Vec<LcUpdate>>>,
}

#[allow(dead_code)]
impl TestHost {
    /// Construct a new `TestHost` with the given phase-0 fork digest.
    pub fn new(fork_digest: ForkDigest) -> Self {
        Self {
            fork_digest,
            altair_fork_digest: None,
            blocks: Arc::new(Mutex::new(HashMap::new())),
            reject_proposer_index: None,
            head_slot: Slot(2_000_000),
            lc_bootstraps: Arc::new(Mutex::new(HashMap::new())),
            lc_updates: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Builder helper: configure an altair fork digest for context-bytes tests.
    pub fn with_altair_fork_digest(mut self, altair_digest: ForkDigest) -> Self {
        self.altair_fork_digest = Some(altair_digest);
        self
    }

    /// Enable rejection of blocks with the given `proposer_index`.
    ///
    /// Used by `gossip_reject_drops_message` to make node B act as a validator
    /// that rejects the special-cased block, preventing propagation to node C.
    pub fn reject_blocks_with_proposer(mut self, proposer_index: u64) -> Self {
        self.reject_proposer_index = Some(proposer_index);
        self
    }

    /// Builder helper: preload `(root, block)` pairs before spawning.
    pub fn with_blocks(
        self,
        blocks: Vec<(
            Root,
            <MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock,
        )>,
    ) -> Self {
        {
            let mut map = self.blocks.lock().expect("TestHost blocks lock poisoned");
            for (root, block) in blocks {
                map.insert(root, block);
            }
        }
        self
    }

    /// Builder helper: set the head slot for BlocksByRange range checks.
    ///
    /// The handler computes `oldest_allowed = head_slot - (min_epochs * SLOTS_PER_EPOCH)`.
    /// For mainnet: min_epochs = 33024, SLOTS_PER_EPOCH = 32, offset = 1,056,768.
    /// To allow `start_slot = S`, set `head_slot >= S + 1,056,768`.
    pub fn with_head_slot(mut self, slot: Slot) -> Self {
        self.head_slot = slot;
        self
    }

    /// Insert a single block after construction.
    pub fn insert_block(
        &self,
        root: Root,
        block: <MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock,
    ) {
        self.blocks
            .lock()
            .expect("TestHost blocks lock poisoned")
            .insert(root, block);
    }

    /// Builder helper: preload a `LightClientBootstrap` keyed by block root.
    pub fn with_lc_bootstrap(self, root: Root, bootstrap: LcBootstrap) -> Self {
        self.lc_bootstraps
            .lock()
            .expect("TestHost lc_bootstraps lock poisoned")
            .insert(root, bootstrap);
        self
    }

    /// Builder helper: preload `LightClientUpdate` objects for `UpdatesByRange`.
    pub fn with_lc_updates(self, updates: Vec<LcUpdate>) -> Self {
        *self
            .lc_updates
            .lock()
            .expect("TestHost lc_updates lock poisoned") = updates;
        self
    }
}

impl ForkContext for TestHost {
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

    fn fork_digest_for(&self, fork: Fork) -> ForkDigest {
        match fork {
            Fork::Phase0 => self.fork_digest,
            Fork::Altair => self.altair_fork_digest.unwrap_or(self.fork_digest),
        }
    }

    fn fork_from_context(&self, ctx: &[u8; 4]) -> Option<Fork> {
        if *ctx == self.fork_digest.into_inner() {
            return Some(Fork::Phase0);
        }
        if let Some(afd) = &self.altair_fork_digest {
            if *ctx == afd.into_inner() {
                return Some(Fork::Altair);
            }
        }
        None
    }

    fn local_metadata(&self) -> AltairMetaData {
        AltairMetaData::default()
    }
}

impl LightClientProvider<MainnetEthSpec> for TestHost {
    fn light_client_bootstrap(
        &self,
        block_root: Root,
    ) -> Option<<MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientBootstrap> {
        self.lc_bootstraps
            .lock()
            .expect("TestHost lc_bootstraps lock poisoned")
            .get(&block_root)
            .cloned()
    }

    fn light_client_updates_by_range(
        &self,
        _start_period: u64,
        count: u64,
    ) -> Vec<<MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientUpdate> {
        let updates = self
            .lc_updates
            .lock()
            .expect("TestHost lc_updates lock poisoned");
        updates.iter().take(count as usize).cloned().collect()
    }

    fn light_client_finality_update(
        &self,
    ) -> Option<<MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientFinalityUpdate> {
        None
    }

    fn light_client_optimistic_update(
        &self,
    ) -> Option<<MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientOptimisticUpdate> {
        None
    }
}

impl BlockProvider<MainnetEthSpec> for TestHost {
    fn block_by_root(
        &self,
        root: Root,
    ) -> Option<<MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock> {
        self.blocks
            .lock()
            .expect("TestHost blocks lock poisoned")
            .get(&root)
            .cloned()
    }

    fn blocks_by_range(
        &self,
        start_slot: Slot,
        count: u64,
    ) -> Vec<<MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock> {
        use pharos_types::SignedBeaconBlock;
        let map = self.blocks.lock().expect("TestHost blocks lock poisoned");
        let mut results: Vec<_> = map
            .values()
            .filter(|b| {
                let s = match b {
                    SignedBeaconBlock::Phase0(inner) => inner.message.slot.0,
                    SignedBeaconBlock::Altair(inner) => inner.message.slot.0,
                    SignedBeaconBlock::Bellatrix(inner) => inner.message.slot.0,
                };
                s >= start_slot.0 && s < start_slot.0 + count
            })
            .cloned()
            .collect();
        results.sort_by_key(|b| match b {
            SignedBeaconBlock::Phase0(inner) => inner.message.slot.0,
            SignedBeaconBlock::Altair(inner) => inner.message.slot.0,
            SignedBeaconBlock::Bellatrix(inner) => inner.message.slot.0,
        });
        results
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            root: Root::default(),
            epoch: Epoch(0),
        }
    }

    fn head(&self) -> (Root, Slot) {
        (Root::default(), self.head_slot)
    }
}

impl GossipValidator<MainnetEthSpec> for TestHost {
    fn validate_beacon_block(
        &self,
        block: &<MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock,
    ) -> GossipVerdict {
        use pharos_types::SignedBeaconBlock;
        if let Some(reject_idx) = self.reject_proposer_index {
            let proposer_index = match block {
                SignedBeaconBlock::Phase0(inner) => inner.message.proposer_index.0,
                SignedBeaconBlock::Altair(inner) => inner.message.proposer_index.0,
                SignedBeaconBlock::Bellatrix(inner) => inner.message.proposer_index.0,
            };
            if proposer_index == reject_idx {
                return GossipVerdict::Reject(format!(
                    "proposer_index {reject_idx} rejected by test policy"
                ));
            }
        }
        GossipVerdict::Accept
    }

    fn validate_attestation(&self, _subnet: SubnetId, _att: &Attestation<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_aggregate_and_proof(&self, _msg: &AggregateAndProof<2048>) -> GossipVerdict {
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
        _msg: &<MainnetEthSpec as pharos_types::EthSpec>::AltairSignedContributionAndProof,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_light_client_finality_update(
        &self,
        _msg: &<MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientFinalityUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_light_client_optimistic_update(
        &self,
        _msg: &<MainnetEthSpec as pharos_types::EthSpec>::AltairLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }
}

// ── CapturingScorer ───────────────────────────────────────────────────────────

/// A `PeerScorer` that records every `ScoreEvent` for later inspection in tests.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct CapturingScorer(pub Arc<Mutex<Vec<ScoreEvent>>>);

impl PeerScorer for CapturingScorer {
    fn record(&mut self, _peer: PeerId, event: ScoreEvent) {
        self.0.lock().unwrap().push(event);
    }

    fn score(&self, _peer: &PeerId) -> f64 {
        0.0
    }

    fn worst_peers(&self, _count: usize) -> Vec<PeerId> {
        vec![]
    }
}

// ── TestNode ──────────────────────────────────────────────────────────────────

/// A running test network node.
#[allow(dead_code)]
pub struct TestNode {
    pub handle: NetworkHandle<MainnetEthSpec>,
    pub peer_id: PeerId,
    /// The node's discv5 ENR (with real bound UDP port).
    pub enr: Enr,
    /// The real bound libp2p listen address (TCP or QUIC).
    pub listen_addr: Multiaddr,
}

/// Spawn a single test node and wait for both the ENR and listen address.
///
/// Binds to OS-assigned ports. If `quic_only` is true, the TCP listener port
/// is set to 0 (disabled) and a QUIC listener is started on an OS-assigned
/// UDP port instead; otherwise TCP is used.
///
/// The fork digest is carried by `host` (`TestHost::new(fd)`); there is no
/// separate `fork_digest` parameter — `TestHost` is the authoritative source.
///
/// Pass `Some(scorer)` to plug in a `CapturingScorer`; `None` uses `NoopScorer`.
///
/// After `spawn_node` returns:
/// - `TestNode::listen_addr` is the real bound TCP or QUIC multiaddr.
/// - `TestNode::enr` is the locally signed ENR including the real discv5 UDP port.
#[allow(dead_code)]
pub async fn spawn_node(bootnodes: Vec<Enr>, host: TestHost, quic_only: bool) -> TestNode {
    spawn_node_with_scorer(bootnodes, host, quic_only, None).await
}

/// Like `spawn_node` but accepts an optional `CapturingScorer`.
#[allow(dead_code)]
pub async fn spawn_node_with_scorer(
    bootnodes: Vec<Enr>,
    host: TestHost,
    quic_only: bool,
    scorer: Option<CapturingScorer>,
) -> TestNode {
    let local_key = Keypair::generate_secp256k1();
    let peer_id = local_key.public().to_peer_id();

    let discv5_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    let base_builder = NetworkBuilder::<MainnetEthSpec, TestHost, _>::new(host)
        .local_key(local_key)
        .listen_ip(listen_ip)
        .discv5_addr(discv5_addr)
        .bootnodes(bootnodes);

    // If a CapturingScorer was provided, wire it in; otherwise keep NoopScorer.
    let mut handle = if let Some(s) = scorer {
        let builder = base_builder.scorer(s);
        let builder = if quic_only {
            builder.no_tcp(true).quic_listen_port(Some(0))
        } else {
            builder.tcp_listen_port(0)
        };
        let (h, _disc) = builder.spawn().await.expect("NetworkBuilder::spawn failed");
        h
    } else {
        let builder = if quic_only {
            base_builder.no_tcp(true).quic_listen_port(Some(0))
        } else {
            base_builder.tcp_listen_port(0)
        };
        let (h, _disc) = builder.spawn().await.expect("NetworkBuilder::spawn failed");
        h
    };

    // Collect events until we have both LocalEnr and NewListenAddr.
    // LocalEnr is emitted first (before the select loop in Network::run).
    // NewListenAddr is emitted when the OS assigns the port.
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
                // For quic_only, the only listener is QUIC, so the first
                // NewListenAddr will be the QUIC address. For TCP mode, the
                // first NewListenAddr is the TCP address.
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
