//! discv5 discovery service wrapper.
//!
//! `DiscoveryService` owns the `discv5::Discv5` instance, drives peer
//! discovery queries, and updates the local ENR when subnet subscriptions
//! change.

use std::net::{IpAddr, SocketAddr};
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

/// Configuration for `DiscoveryService::start`.
pub struct DiscoveryConfig {
    /// UDP socket address for discv5 to listen on. The IP and port are also
    /// advertised in the local ENR as the `ip` / `udp` fields.
    pub listen_addr: SocketAddr,
    /// TCP port advertised in the local ENR (the libp2p TCP listen port).
    /// Peers use this to dial the node's libp2p stack.
    pub tcp_port: u16,
    /// Optional QUIC UDP port advertised in the local ENR under the `quic`
    /// key (IPv4). `None` means the node does not accept QUIC connections.
    pub quic_port: Option<u16>,
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
    /// `cgc` from startup, else lighthouse bans it as out-of-range
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
    /// 1. Build the local ENR (no pre-set IP/TCP/UDP — discv5 derives them
    ///    from `listen_addr` after startup).
    /// 2. Construct `Discv5` with an `Ipv4`-mode `ListenConfig`.
    /// 3. Populate the routing table with `cfg.bootnodes`.
    /// 4. Start the background service tasks.
    /// 5. Obtain the event stream receiver.
    pub async fn start(cfg: DiscoveryConfig) -> Result<Self, NetworkError> {
        let ip = match cfg.listen_addr.ip() {
            IpAddr::V4(ip4) => ip4,
            IpAddr::V6(_) => {
                return Err(NetworkError::Discv5(
                    "IPv6 listen address not supported in DiscoveryService::start; use Ipv4".into(),
                ));
            }
        };
        let port = cfg.listen_addr.port();

        // Load the persisted ENR sequence number so restarts continue from the
        // same seq rather than resetting to 1 (`D-enr-seq-persistence`).
        // `load_enr_seq` returns 1 when the file is absent (first start).
        let initial_seq = cfg.network_dir.as_deref().map(load_enr_seq).unwrap_or(1);

        // Build the local ENR with IP, UDP (discv5), TCP (libp2p), and optional
        // QUIC UDP port populated, so peers discovering us can dial both
        // libp2p transports. IPv6 / quic6 are not populated in this phase.
        let local_enr = build_local_enr(
            &cfg.local_key,
            Some(ip),
            Some(port),
            Some(cfg.tcp_port),
            cfg.quic_port,
            None,
            cfg.fork_id.clone(),
            cfg.attnets,
            cfg.cgc,
            initial_seq,
        )?;

        // discv5 0.10 ConfigBuilder (renamed from Discv5ConfigBuilder).
        let listen_config = ListenConfig::Ipv4 { ip, port };
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
        if let Some(ref dir) = cfg.network_dir {
            if let Err(e) = save_enr_seq(dir, discv5.local_enr().seq()) {
                warn!(error = %e, "failed to persist initial ENR seq; continuing without persistence");
            }
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
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tcp_port: 9000,
            quic_port: None,
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
}
