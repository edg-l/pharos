//! Core network task: `Network` struct and `NetworkBuilder`.
//!
//! `Network` owns the libp2p `Swarm`, the discv5 `DiscoveryService`, and the
//! `PeerManager`. `NetworkBuilder` constructs the full stack.
//!
//! Transport construction follows the libp2p 0.56 `SwarmBuilder` typed
//! pipeline (see `transport` module).  Cite:
//! <https://docs.rs/libp2p/0.56.0/libp2p/struct.SwarmBuilder.html>

pub mod behaviour;
pub mod transport;

use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use futures::StreamExt as _;
use libp2p::gossipsub::{self, MessageAuthenticity};
use libp2p::identify;
use libp2p::identity::Keypair;
use libp2p::noise;
use libp2p::ping;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::{Swarm, SwarmBuilder};
use pharos_ssz::Bitvector;
use pharos_types::EthSpec;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, interval};

use discv5::enr::EnrKey as _;

use crate::discovery::enr::Enr;
use crate::discovery::service::{DiscoveryConfig, DiscoveryService};
use crate::discovery::subnets::compute_subscribed_subnets;
use crate::error::NetworkError;
use crate::handle::NetworkHandle;
use crate::host::Host;
use crate::peer::manager::PeerManager;
use crate::scoring::PeerScorer;

use behaviour::{PharosBehaviour, PharosBehaviourEvent, RpcProtocol};

// ── Commands and Events ───────────────────────────────────────────────────────

/// Commands sent from `NetworkHandle` to the `Network` event loop.
///
/// Phase 7 expands this with dial, gossip-publish, subnet-subscribe, and
/// status-update variants.
pub enum NetworkCommand {
    /// Request a clean shutdown of the network task.
    Shutdown,
}

/// Events emitted from the `Network` event loop to external consumers.
///
/// Phase 4, 5, and 6 add gossip-received, rpc-request, and peer-status
/// variants.  An empty enum cannot be constructed; the channel field is
/// present for the type system only.
pub enum NetworkEvent {}

// ── Network ───────────────────────────────────────────────────────────────────

/// The running network task.
///
/// Constructed via `NetworkBuilder::build`.  Call `run()` to drive the
/// event loop.  Shut down by sending `NetworkCommand::Shutdown` via the
/// `NetworkHandle` or by dropping the handle's `shutdown_tx`.
pub struct Network<E: EthSpec, H: Host<E>, S: PeerScorer> {
    swarm: Swarm<PharosBehaviour>,
    discovery: DiscoveryService,
    #[allow(dead_code)]
    peer_manager: PeerManager<S>,
    #[allow(dead_code)]
    host: Arc<H>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<NetworkEvent>,
    discovery_tick: Interval,
    shutdown_signal: oneshot::Receiver<()>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, H: Host<E>, S: PeerScorer> Network<E, H, S> {
    /// Drive the network event loop.
    ///
    /// Returns when a `NetworkCommand::Shutdown` is received or when
    /// the shutdown signal fires.
    pub async fn run(mut self) -> Result<(), NetworkError> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.on_swarm_event(event).await;
                }
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(NetworkCommand::Shutdown) => break,
                        None => break, // channel closed
                    }
                }
                _ = self.discovery_tick.tick() => {
                    // Run a discv5 FINDNODE query and drain results.
                    // Conversion of discovered ENRs to multiaddrs and dialling
                    // is wired in Phase 7.
                    let _peers = self.discovery.find_peers().await;
                }
                _ = &mut self.shutdown_signal => {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn on_swarm_event(&mut self, _event: libp2p::swarm::SwarmEvent<PharosBehaviourEvent>) {
        // Phase 4 wires gossip; Phase 5 wires req-resp; Phase 6 wires
        // identify and scoring.
    }

    #[allow(dead_code)]
    async fn on_command(&mut self, _cmd: NetworkCommand) {
        // Phase 7 adds dial, publish, and subnet-subscribe handling.
    }
}

// ── NetworkBuilder ────────────────────────────────────────────────────────────

/// Builder for `Network<E, H, S>`.
///
/// Call `new(host)` to start, chain configuration methods, then await
/// `build()`.  The builder starts with `NoopScorer`; call `.scorer(s)` to
/// substitute a real scorer.
///
/// Defaults:
/// - `listen_ip`: `127.0.0.1`
/// - `tcp_listen_port`: `9000`
/// - `quic_listen_port`: `None` (QUIC transport is wired for dialling but
///   no listener is started)
/// - `discv5_addr`: `127.0.0.1:9001` (note: UDP; avoids collision with TCP 9000)
/// - `local_key`: freshly generated secp256k1 keypair
/// - `bootnodes`: empty
pub struct NetworkBuilder<E, H, S> {
    host: Arc<H>,
    listen_ip: IpAddr,
    tcp_listen_port: u16,
    quic_listen_port: Option<u16>,
    discv5_addr: SocketAddr,
    bootnodes: Vec<Enr>,
    local_key: Keypair,
    scorer: S,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, H: Host<E>> NetworkBuilder<E, H, crate::scoring::NoopScorer> {
    /// Create a new builder wrapping `host` with default settings.
    ///
    /// Returns a builder with `NoopScorer`; call `.scorer(s)` to
    /// provide a real implementation.
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
            listen_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            tcp_listen_port: 9000,
            quic_listen_port: None,
            discv5_addr: "127.0.0.1:9001".parse().unwrap(),
            bootnodes: Vec::new(),
            local_key: Keypair::generate_secp256k1(),
            scorer: crate::scoring::NoopScorer,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec, H: Host<E>, S: PeerScorer> NetworkBuilder<E, H, S> {
    /// Override the TCP listen port (default: 9000).
    pub fn tcp_listen_port(mut self, port: u16) -> Self {
        self.tcp_listen_port = port;
        self
    }

    /// Set an optional QUIC listen port.
    ///
    /// When `None` (the default) the QUIC transport is still configured for
    /// dialling but no UDP listener is started.
    pub fn quic_listen_port(mut self, port: Option<u16>) -> Self {
        self.quic_listen_port = port;
        self
    }

    /// Override the IP address for both TCP and QUIC listeners (default: `127.0.0.1`).
    pub fn listen_ip(mut self, ip: IpAddr) -> Self {
        self.listen_ip = ip;
        self
    }

    /// Set the discv5 UDP listen address (default: `127.0.0.1:9001`).
    ///
    /// Note: discv5 uses UDP, distinct from the libp2p TCP port.
    pub fn discv5_addr(mut self, addr: SocketAddr) -> Self {
        self.discv5_addr = addr;
        self
    }

    /// Set bootstrap ENRs for discv5 routing table population.
    pub fn bootnodes(mut self, enrs: Vec<Enr>) -> Self {
        self.bootnodes = enrs;
        self
    }

    /// Override the local libp2p identity keypair (default: generated secp256k1).
    pub fn local_key(mut self, key: Keypair) -> Self {
        self.local_key = key;
        self
    }

    /// Substitute a peer scorer, changing the `S` type parameter.
    pub fn scorer<T: PeerScorer>(self, scorer: T) -> NetworkBuilder<E, H, T> {
        NetworkBuilder {
            host: self.host,
            listen_ip: self.listen_ip,
            tcp_listen_port: self.tcp_listen_port,
            quic_listen_port: self.quic_listen_port,
            discv5_addr: self.discv5_addr,
            bootnodes: self.bootnodes,
            local_key: self.local_key,
            scorer,
            _phantom: PhantomData,
        }
    }

    /// Construct the `Network` and return `(Network, NetworkHandle)`.
    ///
    /// Steps:
    /// 1. Derive the discv5 `CombinedKey` from the libp2p secp256k1 keypair.
    /// 2. Compute initial subnet subscriptions from the node-id.
    /// 3. Start `DiscoveryService`.
    /// 4. Build the libp2p swarm via `SwarmBuilder`.
    /// 5. Add TCP listener; optionally add QUIC listener.
    /// 6. Wire mpsc channels and oneshot shutdown signal.
    pub async fn build(self) -> Result<(Network<E, H, S>, NetworkHandle), NetworkError> {
        // ── Step 1: bridge libp2p keypair → discv5 CombinedKey ───────────────
        //
        // Extract the secp256k1 secret bytes from the libp2p keypair and
        // reconstruct a discv5 `CombinedKey`.  The `Keypair::try_into_secp256k1`
        // method clones the inner key; we use `secret().to_bytes()` to get the
        // 32-byte secret scalar.
        let secp_kp = self
            .local_key
            .clone()
            .try_into_secp256k1()
            .map_err(|_| NetworkError::Libp2p("keypair is not secp256k1".into()))?;
        let mut secret_bytes = secp_kp.secret().to_bytes();
        let combined_key = discv5::enr::CombinedKey::secp256k1_from_bytes(&mut secret_bytes)
            .map_err(|e| NetworkError::Libp2p(format!("CombinedKey from secret: {e}")))?;

        // ── Step 2: compute initial subnet subscriptions ──────────────────────
        let node_id = discv5::enr::NodeId::from(combined_key.public());
        let subnets = compute_subscribed_subnets::<E>(node_id, 0);
        let mut attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();
        for subnet_id in subnets {
            attnets.set(subnet_id as usize, true);
        }

        // ── Step 3: start DiscoveryService ───────────────────────────────────
        let fork_id = self.host.enr_fork_id();
        let discovery = DiscoveryService::start(DiscoveryConfig {
            listen_addr: self.discv5_addr,
            tcp_port: self.tcp_listen_port,
            quic_port: self.quic_listen_port,
            bootnodes: self.bootnodes,
            local_key: combined_key,
            fork_id,
            attnets,
        })
        .await?;

        // ── Step 4: build the libp2p swarm ────────────────────────────────────
        let local_key = self.local_key.clone();
        let public_key = local_key.public();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .build()
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?;
        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

        let rr = request_response::Behaviour::new(
            [(RpcProtocol, ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        let identify_cfg = identify::Config::new("/pharos/0.1.0".into(), public_key.clone());
        let identify = identify::Behaviour::new(identify_cfg);
        let ping = ping::Behaviour::new(ping::Config::default());

        let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                transport::tcp_config(),
                noise::Config::new,
                transport::yamux_config,
            )
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?
            .with_quic()
            .with_dns()?
            .with_behaviour(|_key| PharosBehaviour {
                gossipsub,
                request_response: rr,
                identify,
                ping,
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(transport::idle_timeout()))
            .build();

        // ── Step 5: add listeners ─────────────────────────────────────────────
        let mut swarm = swarm;

        let tcp_addr: libp2p::Multiaddr =
            format!("/ip4/{}/tcp/{}", self.listen_ip, self.tcp_listen_port)
                .parse()
                .map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?;
        swarm
            .listen_on(tcp_addr)
            .map_err(|e| NetworkError::Libp2p(e.to_string()))?;

        if let Some(quic_port) = self.quic_listen_port {
            let quic_addr: libp2p::Multiaddr =
                format!("/ip4/{}/udp/{}/quic-v1", self.listen_ip, quic_port)
                    .parse()
                    .map_err(|e: libp2p::multiaddr::Error| NetworkError::Libp2p(e.to_string()))?;
            swarm
                .listen_on(quic_addr)
                .map_err(|e| NetworkError::Libp2p(e.to_string()))?;
        }

        // ── Step 6: wire channels ─────────────────────────────────────────────
        let (cmd_tx, command_rx) = mpsc::channel::<NetworkCommand>(64);
        let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(1024);
        let (shutdown_tx, shutdown_signal) = oneshot::channel::<()>();

        let peer_manager = PeerManager::new(self.scorer, 100, 50);

        // Discovery poll interval: 30 seconds.
        let discovery_tick = interval(std::time::Duration::from_secs(30));

        let network = Network {
            swarm,
            discovery,
            peer_manager,
            host: self.host,
            command_rx,
            event_tx,
            discovery_tick,
            shutdown_signal,
            _phantom: PhantomData,
        };

        let handle = NetworkHandle::new(cmd_tx, event_rx, shutdown_tx);

        Ok((network, handle))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict};
    use crate::types::SubnetId;
    use pharos_types::MainnetEthSpec;
    use pharos_types::phase0::primitives::ForkDigest;
    use pharos_types::phase0::{
        AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
        Root, SignedVoluntaryExit, Slot,
    };
    use pharos_utils::{Bytes4, Epoch};

    struct MockHost;

    impl ForkContext for MockHost {
        fn current_fork_digest(&self) -> ForkDigest {
            ForkDigest::from_array([0u8; 4])
        }
        fn enr_fork_id(&self) -> ENRForkID {
            ENRForkID {
                fork_digest: Bytes4::from_array([0u8; 4]),
                next_fork_version: Bytes4::from_array([0u8; 4]),
                next_fork_epoch: Epoch(u64::MAX),
            }
        }
        fn genesis_validators_root(&self) -> Root {
            Root::default()
        }
    }

    impl BlockProvider<MainnetEthSpec> for MockHost {
        fn block_by_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            unreachable!("MockHost::block_by_root not called in Phase 3")
        }
        fn blocks_by_range(
            &self,
            _start_slot: Slot,
            _count: u64,
        ) -> Vec<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            unreachable!("MockHost::blocks_by_range not called in Phase 3")
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            unreachable!("MockHost::finalized_checkpoint not called in Phase 3")
        }
        fn head(&self) -> (Root, Slot) {
            unreachable!("MockHost::head not called in Phase 3")
        }
    }

    impl GossipValidator<MainnetEthSpec> for MockHost {
        fn validate_beacon_block(
            &self,
            _block: &<MainnetEthSpec as EthSpec>::SignedBeaconBlock,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_attestation(
            &self,
            _subnet: SubnetId,
            _att: &Attestation<2048>,
        ) -> GossipVerdict {
            unreachable!()
        }
        fn validate_aggregate_and_proof(&self, _msg: &AggregateAndProof<2048>) -> GossipVerdict {
            unreachable!()
        }
        fn validate_voluntary_exit(&self, _exit: &SignedVoluntaryExit) -> GossipVerdict {
            unreachable!()
        }
        fn validate_proposer_slashing(&self, _slashing: &ProposerSlashing) -> GossipVerdict {
            unreachable!()
        }
        fn validate_attester_slashing(&self, _slashing: &AttesterSlashing<2048>) -> GossipVerdict {
            unreachable!()
        }
    }

    /// Verify that `Network::run` exits cleanly when `NetworkHandle::shutdown`
    /// is called.
    ///
    /// Uses `multi_thread` flavor because discv5 and libp2p both spawn Tokio
    /// tasks internally.
    #[tokio::test(flavor = "multi_thread")]
    async fn network_shutdown_smoke() {
        let (network, handle) = NetworkBuilder::<MainnetEthSpec, MockHost, _>::new(MockHost)
            .build()
            .await
            .expect("NetworkBuilder::build failed");

        let task = tokio::spawn(async move { network.run().await });

        handle.shutdown().await.expect("shutdown failed");

        let result = task.await.expect("network task panicked");
        assert!(result.is_ok(), "Network::run returned an error: {result:?}");
    }
}
