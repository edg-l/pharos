//! discv5 discovery service wrapper.
//!
//! `DiscoveryService` owns the `discv5::Discv5` instance, drives peer
//! discovery queries, and updates the local ENR when subnet subscriptions
//! change.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use discv5::socket::ListenConfig;
use discv5::{ConfigBuilder, Discv5};
use pharos_ssz::{Bitvector, Encode};
use pharos_types::phase0::ENRForkID;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use tokio::sync::mpsc;
use tracing::warn;

use crate::discovery::enr::{
    Enr, build_local_enr, load_enr_seq, matches_local_fork, read_eth2_field, save_enr_seq,
};
use crate::error::NetworkError;

// ── Config ────────────────────────────────────────────────────────────────────

/// IP-family selection for the discv5 UDP listener and the ENR socket fields.
///
/// Mirrors `discv5::socket::ListenConfig` 1:1 (`D-discv5-dualstack`). The chosen
/// variant determines both which UDP socket(s) discv5 binds AND which
/// `ip{4,6}` / `udp{4,6}` fields the local ENR advertises:
///
/// - `Ipv4`      → ENR gets `ip4` / `udp4` only.
/// - `Ipv6`      → ENR gets `ip6` / `udp6` only.
/// - `DualStack` → ENR gets both `ip4` / `udp4` and `ip6` / `udp6`.
#[derive(Debug, Clone, Copy)]
pub enum DiscoveryListenConfig {
    /// IPv4-only discovery.
    Ipv4 { ip: Ipv4Addr, port: u16 },
    /// IPv6-only discovery.
    Ipv6 { ip: Ipv6Addr, port: u16 },
    /// Dual-stack discovery (binds both an IPv4 and an IPv6 UDP socket).
    DualStack {
        ipv4: Ipv4Addr,
        ipv4_port: u16,
        ipv6: Ipv6Addr,
        ipv6_port: u16,
    },
}

impl DiscoveryListenConfig {
    /// The IPv4 listen address (and ENR `ip4` / `udp4` source), if this config
    /// includes an IPv4 socket.
    fn ipv4(&self) -> Option<(Ipv4Addr, u16)> {
        match *self {
            Self::Ipv4 { ip, port } => Some((ip, port)),
            Self::DualStack {
                ipv4, ipv4_port, ..
            } => Some((ipv4, ipv4_port)),
            Self::Ipv6 { .. } => None,
        }
    }

    /// The IPv6 listen address (and ENR `ip6` / `udp6` source), if this config
    /// includes an IPv6 socket.
    fn ipv6(&self) -> Option<(Ipv6Addr, u16)> {
        match *self {
            Self::Ipv6 { ip, port } => Some((ip, port)),
            Self::DualStack {
                ipv6, ipv6_port, ..
            } => Some((ipv6, ipv6_port)),
            Self::Ipv4 { .. } => None,
        }
    }

    /// Build the discv5 `ListenConfig` for this family.
    fn to_listen_config(self) -> ListenConfig {
        match self {
            Self::Ipv4 { ip, port } => ListenConfig::Ipv4 { ip, port },
            Self::Ipv6 { ip, port } => ListenConfig::Ipv6 { ip, port },
            Self::DualStack {
                ipv4,
                ipv4_port,
                ipv6,
                ipv6_port,
            } => ListenConfig::DualStack {
                ipv4,
                ipv4_port,
                ipv6,
                ipv6_port,
            },
        }
    }
}

/// Configuration for `DiscoveryService::start`.
pub struct DiscoveryConfig {
    /// IP family + UDP socket(s) for discv5 to listen on. The IP(s) and port(s)
    /// are also advertised in the local ENR as the `ip{4,6}` / `udp{4,6}`
    /// fields (`D-discv5-dualstack`).
    pub listen: DiscoveryListenConfig,
    /// TCP port advertised in the local ENR as `tcp4` (the libp2p IPv4 TCP
    /// listen port). Peers use this to dial the node's libp2p stack over IPv4.
    pub tcp_port: u16,
    /// Optional TCP port advertised in the local ENR as `tcp6` (the libp2p IPv6
    /// TCP listen port). `None` when the node does not accept libp2p IPv6 TCP.
    pub tcp6_port: Option<u16>,
    /// Optional QUIC UDP port advertised in the local ENR under the `quic`
    /// key (IPv4). `None` means the node does not accept IPv4 QUIC connections.
    pub quic_port: Option<u16>,
    /// Optional QUIC UDP port advertised in the local ENR under the `quic6`
    /// key (IPv6). `None` means the node does not accept IPv6 QUIC connections.
    pub quic6_port: Option<u16>,
    /// Bootstrap ENRs added to the routing table on startup.
    pub bootnodes: Vec<Enr>,
    /// Local signing key used to build and sign the local ENR.
    pub local_key: discv5::enr::CombinedKey,
    /// Ethereum fork identity embedded in the `eth2` ENR key.
    pub fork_id: ENRForkID,
    /// Attestation subnet subscriptions embedded in the `attnets` ENR key.
    pub attnets: Bitvector<ATTESTATION_SUBNET_COUNT>,
    /// EIP-7594 custody group count advertised in the `cgc` ENR key from boot.
    /// `None` (or `0`) omits the key — a Fulu node must advertise a non-zero
    /// `cgc` from startup, else some CL clients ban it as out-of-range
    /// (`D-fulu-metadata-cgc-nonzero`).
    pub cgc: Option<u64>,
    /// Directory for persisting the ENR sequence number across restarts
    /// (`D-enr-seq-persistence`). `None` disables persistence (tests, ephemeral
    /// nodes). When `Some`, the ENR seq is loaded on startup and saved on every
    /// ENR mutation so restarts yield monotonically increasing sequence numbers.
    pub network_dir: Option<PathBuf>,
}

// ── Service ───────────────────────────────────────────────────────────────────

/// A running discv5 peer-discovery service.
///
/// Constructed via `DiscoveryService::start`. Call `find_peers` to run
/// iterative FINDNODE queries and `update_enr_attnets` to advertise new
/// subnet subscriptions.
pub struct DiscoveryService {
    /// The underlying discv5 instance.
    ///
    /// `pub(crate)` so that `discovery::handle::DiscoveryService::handle_discovery_command`
    /// can call `enr_insert` when the `DiscoveryHandle` receives an `UpdateEth2` command.
    pub(crate) discv5: Discv5,
    /// Event stream produced by discv5.
    ///
    /// discv5 0.10 returns a *bounded* `mpsc::Receiver`; the plan referenced
    /// an unbounded receiver, but the actual 0.10.4 API uses a bounded channel.
    /// See "Assumptions made" in the Phase 2 implementation report.
    events_rx: mpsc::Receiver<discv5::Event>,
    /// The fork identity we advertise and validate peers against.
    fork_id: ENRForkID,
    /// Directory for ENR seq persistence (`D-enr-seq-persistence`). `None` when
    /// persistence is disabled (ephemeral nodes / tests without a data dir).
    network_dir: Option<PathBuf>,
}

impl DiscoveryService {
    /// Start a discv5 service from the given `DiscoveryConfig`.
    ///
    /// Steps:
    /// 1. Build the local ENR, populating `ip{4,6}` / `udp{4,6}` / `tcp{4,6}` /
    ///    `quic{,6}` from the selected `DiscoveryListenConfig` family
    ///    (`D-discv5-dualstack`).
    /// 2. Construct `Discv5` with the matching `ListenConfig` variant.
    /// 3. Populate the routing table with `cfg.bootnodes`.
    /// 4. Start the background service tasks.
    /// 5. Obtain the event stream receiver.
    pub async fn start(cfg: DiscoveryConfig) -> Result<Self, NetworkError> {
        // Resolve the per-family IP/UDP sockets the ENR should advertise. A
        // dual-stack config yields both; single-stack yields one.
        let v4 = cfg.listen.ipv4();
        let v6 = cfg.listen.ipv6();

        // Load the persisted ENR sequence number so restarts continue from the
        // same seq rather than resetting to 1 (`D-enr-seq-persistence`).
        // `load_enr_seq` returns 1 when the file is absent (first start).
        let initial_seq = cfg.network_dir.as_deref().map(load_enr_seq).unwrap_or(1);

        // Build the local ENR with the per-family IP, UDP (discv5), TCP (libp2p),
        // and optional QUIC UDP ports populated, so peers discovering us can dial
        // both libp2p transports over whichever families this node serves.
        let local_enr = build_local_enr(
            &cfg.local_key,
            v4.map(|(ip, _)| ip),
            v4.map(|(_, port)| port),
            v4.map(|_| cfg.tcp_port),
            // Gate the v4 `quic` key on a v4 socket so an IPv6-only config never
            // advertises a v4 QUIC port without a v4 ip/tcp (matches `tcp4`).
            v4.and(cfg.quic_port),
            cfg.quic6_port,
            v6.map(|(ip, _)| ip),
            v6.map(|(_, port)| port),
            v6.and(cfg.tcp6_port),
            cfg.fork_id.clone(),
            cfg.attnets,
            cfg.cgc,
            initial_seq,
        )?;

        // discv5 0.10 ConfigBuilder (renamed from Discv5ConfigBuilder). The
        // ListenConfig variant follows the selected IP family.
        let listen_config = cfg.listen.to_listen_config();
        let discv5_config = ConfigBuilder::new(listen_config).build();

        // Discv5::new returns Result<Self, &'static str>.
        let mut discv5 = Discv5::new(local_enr, cfg.local_key, discv5_config)
            .map_err(|e| NetworkError::Discv5(e.to_string()))?;

        // Populate routing table with bootnodes.
        for bootnode in cfg.bootnodes {
            if let Err(e) = discv5.add_enr(bootnode) {
                warn!(error = e, "failed to add bootnode ENR to routing table");
            }
        }

        // Start the background discv5 service tasks.
        discv5
            .start()
            .await
            .map_err(|e| NetworkError::Discv5(e.to_string()))?;

        // Obtain the bounded event stream receiver.
        // discv5 0.10.4 returns mpsc::Receiver<Event> (bounded), not unbounded.
        let events_rx = discv5
            .event_stream()
            .await
            .map_err(|e| NetworkError::Discv5(e.to_string()))?;

        // Persist the initial seq now that the ENR is built (write-on-start so a
        // crash before the first mutation still advances the seq on next restart).
        if let Some(ref dir) = cfg.network_dir
            && let Err(e) = save_enr_seq(dir, discv5.local_enr().seq())
        {
            warn!(error = %e, "failed to persist initial ENR seq; continuing without persistence");
        }

        Ok(Self {
            discv5,
            events_rx,
            fork_id: cfg.fork_id,
            network_dir: cfg.network_dir,
        })
    }

    // ── Task 2.2: find_peers ─────────────────────────────────────────────────

    /// Run an iterative FINDNODE query towards a random `NodeId` and return
    /// ENRs whose `fork_digest` matches the local fork.
    ///
    /// Peers without a valid `eth2` ENR key are silently excluded.
    pub async fn find_peers(&mut self) -> Vec<Enr> {
        let target = discv5::enr::NodeId::random();
        let results = match self.discv5.find_node(target).await {
            Ok(enrs) => enrs,
            Err(e) => {
                warn!(error = %e, "discv5 find_node query failed");
                return Vec::new();
            }
        };

        results
            .into_iter()
            .filter(|peer_enr| {
                match read_eth2_field(peer_enr) {
                    Ok(peer_fork_id) => matches_local_fork(&self.fork_id, &peer_fork_id),
                    Err(_) => false, // no eth2 key → exclude
                }
            })
            .collect()
    }

    // ── Task 2.3: update_enr_attnets ────────────────────────────────────────

    /// Rewrite the `attnets` ENR key to reflect new subnet subscriptions.
    ///
    /// SSZ-encodes `new_attnets` and inserts the bytes via `discv5.enr_insert`,
    /// which auto-increments the ENR sequence number and re-signs the record.
    /// Persists the new seq to disk for restart continuity
    /// (`D-enr-seq-persistence`).
    ///
    /// Per `~/dev/consensus-specs/specs/phase0/p2p-interface.md:1658-1660`:
    /// nodes MUST set the `attnets` key when any attestation subnet bit is set.
    pub fn update_enr_attnets(
        &mut self,
        new_attnets: Bitvector<ATTESTATION_SUBNET_COUNT>,
    ) -> Result<(), NetworkError> {
        let bytes = new_attnets.as_ssz_bytes();
        // Pass `&&[u8]` (bytes-string RLP) to match `build_local_enr`.
        self.discv5
            .enr_insert("attnets", &bytes.as_slice())
            .map(|_| ())
            .map_err(|e| NetworkError::Discv5(e.to_string()))?;
        self.persist_enr_seq();
        Ok(())
    }

    /// Write the current ENR seq to disk if a network directory is configured.
    ///
    /// Called after every ENR mutation (attnets update, eth2 update, syncnets
    /// update) so that restarts start from the latest seq.
    pub(crate) fn persist_enr_seq(&self) {
        if let Some(ref dir) = self.network_dir {
            let seq = self.discv5.local_enr().seq();
            if let Err(e) = save_enr_seq(dir, seq) {
                warn!(error = %e, seq, "failed to persist ENR seq after mutation");
            }
        }
    }

    /// Returns the locally signed ENR (a fresh clone from the discv5 internal
    /// `Arc<RwLock<_>>`). Always reflects the latest `enr_insert` updates.
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Returns a mutable reference to the event stream receiver.
    pub fn events_rx(&mut self) -> &mut mpsc::Receiver<discv5::Event> {
        &mut self.events_rx
    }
}

// ── Phase 12: deficit-driven discovery cadence ───────────────────────────────

/// Compute the FINDNODE query interval as a function of peer count vs target.
///
/// Formula: linear scale from `MIN_INTERVAL` (connected = 0) to `MAX_INTERVAL`
/// (connected ≥ target), clamped to `[MIN_INTERVAL, MAX_INTERVAL]`:
///
/// ```text
/// interval = max(MIN, MAX * connected / target)
/// ```
///
/// - `connected = 0`      → `MIN_INTERVAL` (3 s, aggressive querying).
/// - `connected = target`  → `MAX_INTERVAL` (30 s, slow maintenance cadence).
/// - `connected = target/2`→ `MAX_INTERVAL / 2` (15 s, moderate cadence).
/// - `connected > target`  → `MAX_INTERVAL` (already over target, back off).
///
/// Lives in this module so callers can compute the interval without constructing
/// a `DiscoveryService` (e.g. unit tests, the `Network` run loop).
pub fn query_interval(connected_peers: usize, target_peers: usize) -> std::time::Duration {
    const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
    const MAX_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

    if connected_peers >= target_peers || target_peers == 0 {
        return MAX_INTERVAL;
    }
    let max_secs = MAX_INTERVAL.as_secs();
    let secs = max_secs * connected_peers as u64 / target_peers as u64;
    let secs = secs.max(MIN_INTERVAL.as_secs());
    std::time::Duration::from_secs(secs)
}

// ── Task 2.7: start/stop smoke test ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use discv5::enr::CombinedKey;
    use pharos_types::phase0::ENRForkID;
    use pharos_utils::{Bytes4, Epoch};

    fn test_fork_id() -> ENRForkID {
        ENRForkID {
            fork_digest: Bytes4::from_array([0x01, 0x02, 0x03, 0x04]),
            next_fork_version: Bytes4::from_array([0xde, 0xad, 0xbe, 0xef]),
            next_fork_epoch: Epoch(0),
        }
    }

    /// The `Ipv6`-only family variant is not reachable from the CLI (which is
    /// IPv4-primary), so cover its accessors + discv5 `ListenConfig` mapping
    /// here. Host-independent: builds no socket (`D-discv5-dualstack`).
    #[test]
    fn ipv6_only_listen_config_maps_correctly() {
        let cfg = DiscoveryListenConfig::Ipv6 {
            ip: Ipv6Addr::LOCALHOST,
            port: 9000,
        };
        assert_eq!(cfg.ipv4(), None);
        assert_eq!(cfg.ipv6(), Some((Ipv6Addr::LOCALHOST, 9000)));
        assert!(matches!(
            cfg.to_listen_config(),
            ListenConfig::Ipv6 { ip, port } if ip == Ipv6Addr::LOCALHOST && port == 9000
        ));
    }

    /// Smoke test: start a `DiscoveryService` on an OS-assigned port with no
    /// bootnodes, then drop it cleanly. No peer discovery is attempted.
    ///
    /// `multi_thread` flavor required because discv5 spawns background tasks.
    #[tokio::test(flavor = "multi_thread")]
    async fn discv5_start_stop_smoke() {
        let key = CombinedKey::generate_secp256k1();
        let fork_id = test_fork_id();
        let attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();

        let cfg = DiscoveryConfig {
            listen: DiscoveryListenConfig::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: 0,
            },
            tcp_port: 9000,
            tcp6_port: None,
            quic_port: None,
            quic6_port: None,
            bootnodes: Vec::new(),
            local_key: key,
            fork_id,
            attnets,
            cgc: None,
            network_dir: None,
        };

        let service = DiscoveryService::start(cfg)
            .await
            .expect("DiscoveryService::start failed");

        // Drop the service cleanly; Discv5::drop calls shutdown().
        drop(service);
    }

    /// Integration test for `D-enr-external-addr-update` (Finding 9, Task 6.5).
    ///
    /// Synthesizes `ExternalAddrConfirmed` by driving
    /// `UpdateExternalSocket(addr)` through `handle_discovery_command`, then
    /// asserts: (1) the local ENR's tcp4 socket reflects the new address, and
    /// (2) the ENR seq bumps EXACTLY ONCE across two identical confirmations.
    #[tokio::test(flavor = "multi_thread")]
    async fn external_addr_updates_enr_socket_and_bumps_seq_once() {
        use crate::discovery::handle::DiscoveryCommand;
        use std::net::SocketAddr;

        let key = CombinedKey::generate_secp256k1();
        let attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();

        let cfg = DiscoveryConfig {
            listen: DiscoveryListenConfig::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: 0,
            },
            tcp_port: 9000,
            tcp6_port: None,
            quic_port: None,
            quic6_port: None,
            bootnodes: Vec::new(),
            local_key: key,
            fork_id: test_fork_id(),
            attnets,
            cgc: None,
            network_dir: None,
        };

        let mut service = DiscoveryService::start(cfg)
            .await
            .expect("DiscoveryService::start failed");

        let initial_seq = service.local_enr().seq();
        let new_socket: SocketAddr = "203.0.113.7:9001".parse().unwrap();

        // Precondition: confirm the ENR tcp4 socket is NOT already set to
        // new_socket, so the first UpdateExternalSocket call is a genuine change.
        // If a future refactor initialises the ENR with this address, this
        // assertion will fail loudly rather than silently passing.
        assert_ne!(
            service.local_enr().tcp4_socket(),
            Some(match new_socket {
                SocketAddr::V4(v4) => v4,
                SocketAddr::V6(_) => unreachable!("test uses an ipv4 socket"),
            }),
            "precondition: ENR tcp4 socket must differ from new_socket before first update"
        );

        // First confirmation: real change → seq bumps, ENR reflects the socket.
        service.handle_discovery_command(DiscoveryCommand::UpdateExternalSocket(new_socket));
        let after_first = service.local_enr();
        assert_eq!(
            after_first.tcp4_socket(),
            Some(match new_socket {
                SocketAddr::V4(v4) => v4,
                SocketAddr::V6(_) => unreachable!("test uses an ipv4 socket"),
            }),
            "ENR tcp4 socket must reflect the confirmed external address"
        );
        let seq_after_first = after_first.seq();
        assert_eq!(
            seq_after_first,
            initial_seq + 1,
            "first external-socket update must bump the ENR seq once"
        );

        // Second identical confirmation: no change → seq must NOT bump again.
        service.handle_discovery_command(DiscoveryCommand::UpdateExternalSocket(new_socket));
        let after_second = service.local_enr();
        assert_eq!(
            after_second.seq(),
            seq_after_first,
            "identical external-socket update must NOT bump the ENR seq again"
        );

        drop(service);
    }

    /// Integration test for `D-discv5-dualstack` (Finding 11, Task 8.6).
    ///
    /// Starts a dual-stack `DiscoveryService` on loopback (`127.0.0.1` + `::1`)
    /// and asserts the local ENR carries BOTH the IPv4 (`ip4`/`tcp4`) and IPv6
    /// (`ip6`/`tcp6`) socket fields.
    ///
    /// `multi_thread` flavor: discv5 spawns background tasks.
    ///
    /// Environment note: a CI/sandbox host without a routable `::1` may fail the
    /// IPv6 UDP bind inside `DiscoveryService::start`. When that happens this
    /// test surfaces the bind error explicitly (it does NOT fake a pass); the
    /// ENR-building path is additionally covered by the pure unit test
    /// `discovery::enr::tests::enr_roundtrip_dualstack_ipv6_fields`.
    #[tokio::test(flavor = "multi_thread")]
    async fn dualstack_enr_carries_both_ip4_and_ip6() {
        let key = CombinedKey::generate_secp256k1();
        let attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();

        let cfg = DiscoveryConfig {
            listen: DiscoveryListenConfig::DualStack {
                ipv4: Ipv4Addr::LOCALHOST,
                ipv4_port: 0,
                ipv6: Ipv6Addr::LOCALHOST,
                ipv6_port: 0,
            },
            tcp_port: 9000,
            tcp6_port: Some(9000),
            quic_port: None,
            quic6_port: None,
            bootnodes: Vec::new(),
            local_key: key,
            fork_id: test_fork_id(),
            attnets,
            cgc: None,
            network_dir: None,
        };

        let service = match DiscoveryService::start(cfg).await {
            Ok(s) => s,
            Err(e) => {
                // A dual-stack bind needs a routable ::1; on a sandbox host that
                // lacks IPv6 loopback the v6 UDP bind fails for an environment
                // reason. Surface it rather than faking a pass — the ENR-build
                // path is covered by enr_roundtrip_dualstack_ipv6_fields.
                panic!(
                    "dual-stack DiscoveryService::start failed (likely no routable ::1 on this \
                     host): {e}"
                );
            }
        };

        let enr = service.local_enr();

        // IPv4 family present.
        assert_eq!(
            enr.ip4(),
            Some(Ipv4Addr::LOCALHOST),
            "dual-stack ENR must carry ip4"
        );
        assert_eq!(enr.tcp4(), Some(9000), "dual-stack ENR must carry tcp4");

        // IPv6 family present.
        assert_eq!(
            enr.ip6(),
            Some(Ipv6Addr::LOCALHOST),
            "dual-stack ENR must carry ip6"
        );
        assert_eq!(enr.tcp6(), Some(9000), "dual-stack ENR must carry tcp6");

        drop(service);
    }
}
