//! `DiscoveryHandle` — external handle for updating the local discv5 ENR.
//!
//! `DiscoveryService` is owned by the `Network` event loop. `DiscoveryHandle`
//! exposes an outward-facing API for cross-fork ENR migration so that the
//! fork-migration loop in `pharos-node` can update the `eth2` ENR field when
//! the node crosses `ALTAIR_FORK_EPOCH`, without retaining a reference to the
//! full `Network` or `DiscoveryService`.
//!
//! Also exposes `update_enr_eth2` for cross-fork ENR migration.

use tokio::sync::{mpsc, oneshot};

use crate::discovery::enr::Enr;
use crate::error::NetworkError;
use pharos_ssz::{Bitvector, Encode as _};
use pharos_types::altair::constants::SYNC_COMMITTEE_SUBNET_COUNT;
use pharos_types::phase0::ENRForkID;

// ── DiscoveryCommand ──────────────────────────────────────────────────────────

/// Commands forwarded from `DiscoveryHandle` to the discovery actor.
pub(crate) enum DiscoveryCommand {
    /// Update the `eth2` ENR field with a new `ENRForkID`.
    ///
    /// SSZ-encodes `fork_id` and calls `discv5.enr_insert("eth2", ...)`,
    /// which auto-increments the ENR sequence number and re-signs.
    /// Per `specs/phase0/p2p-interface.md:1654-1656`.
    UpdateEth2 {
        fork_id: ENRForkID,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Update the `syncnets` ENR field with a new `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]`.
    ///
    /// SSZ-encodes the bitvector and calls `discv5.enr_insert("syncnets", ...)`.
    /// Per `specs/altair/p2p-interface.md:540-549`.
    /// Called by the BN `POST /eth/v1/validator/sync_committee_subscriptions` handler
    /// so the local ENR advertises which sync-committee subnets the VC has subscribed to.
    /// (`D-syncnets-enr-on-subscription`)
    UpdateSyncnets {
        syncnets: Bitvector<{ SYNC_COMMITTEE_SUBNET_COUNT }>,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Update the Fulu ENR fields in a single mutation: `eth2` (fork id), and
    /// optionally `cgc` (custody group count) + `nfd` (next fork digest).
    ///
    /// Per `specs/fulu/p2p-interface.md` (ENR `cgc` + `nfd`). Used by the
    /// BPO-boundary / custody-adjustment drivers so peers observe the updated
    /// fork identity, custody count, and next-fork digest together.
    UpdateFuluEnr {
        fork_id: ENRForkID,
        cgc: Option<u64>,
        nfd: Option<[u8; 4]>,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Update the local ENR's TCP socket to a confirmed external address.
    ///
    /// Issued by the `Network` event loop when libp2p confirms a new external
    /// address (`SwarmEvent::ExternalAddrConfirmed`). Calls
    /// `discv5.update_local_enr_socket(addr, is_tcp = true)` so peers
    /// discovering us over discv5 dial the routable address rather than a
    /// possibly-wrong configured socket. discv5 bumps the ENR seq + re-signs
    /// only when the socket actually changed (`D-enr-external-addr-update`).
    UpdateExternalSocket(std::net::SocketAddr),
    /// Read the current local ENR. Used by tests and operational diagnostics
    /// to confirm field updates landed.
    LocalEnr { reply: oneshot::Sender<Enr> },
}

// ── DiscoveryHandle ───────────────────────────────────────────────────────────

/// Handle for sending commands to the `DiscoveryService`.
///
/// Returned by `NetworkBuilder::build` alongside the `NetworkHandle`. The
/// fork-migration loop in `pharos-node` holds this to update the local ENR
/// when crossing `ALTAIR_FORK_EPOCH`.
///
/// Cheap to clone (single `mpsc::Sender`).
#[derive(Clone)]
pub struct DiscoveryHandle {
    cmd_tx: mpsc::Sender<DiscoveryCommand>,
}

impl DiscoveryHandle {
    /// Construct a new `DiscoveryHandle`.
    pub(crate) fn new(cmd_tx: mpsc::Sender<DiscoveryCommand>) -> Self {
        Self { cmd_tx }
    }

    /// Update the `eth2` ENR field with a new `ENRForkID`.
    ///
    /// Writes the new fork identity to the local ENR, increments the ENR
    /// sequence number, and re-publishes so that peers discovering us observe
    /// the updated field. Used by the fork-migration loop at `ALTAIR_FORK_EPOCH`.
    ///
    /// Per `specs/phase0/p2p-interface.md:1654-1656` and
    /// `specs/altair/p2p-interface.md` cross-fork ENR update requirements.
    pub async fn update_enr_eth2(&self, fork_id: ENRForkID) -> Result<(), NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(DiscoveryCommand::UpdateEth2 {
                fork_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Update the Fulu ENR fields (`eth2` + optional `cgc` + optional `nfd`).
    ///
    /// `cgc` is the EIP-7594 custody group count; `nfd` is the next fork digest
    /// (regular fork boundary OR the next BPO-boundary digest). Writing all
    /// three in one ENR mutation bumps the sequence number once and re-signs.
    /// Per `specs/fulu/p2p-interface.md` (ENR `cgc` + `nfd`).
    pub async fn update_enr_eth2_fulu(
        &self,
        fork_id: ENRForkID,
        cgc: Option<u64>,
        nfd: Option<[u8; 4]>,
    ) -> Result<(), NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(DiscoveryCommand::UpdateFuluEnr {
                fork_id,
                cgc,
                nfd,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Update the `syncnets` ENR field.
    ///
    /// Writes a `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]` to the local ENR under
    /// the `syncnets` key, increments the ENR sequence number, and re-publishes.
    /// Called by the BN `POST /eth/v1/validator/sync_committee_subscriptions`
    /// handler so peers discovering us see which sync-committee subnets we
    /// subscribe to.
    ///
    /// Per `specs/altair/p2p-interface.md:540-549`. (`D-syncnets-enr-on-subscription`)
    pub async fn update_enr_syncnets(
        &self,
        syncnets: Bitvector<{ SYNC_COMMITTEE_SUBNET_COUNT }>,
    ) -> Result<(), NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(DiscoveryCommand::UpdateSyncnets {
                syncnets,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    /// Read the current local ENR via the discovery service.
    ///
    /// Round-trips through the discovery actor so the caller sees the live
    /// state owned by the event loop (not a snapshot). Used by the cross-fork
    /// migration test to confirm `update_enr_eth2` actually mutated the ENR.
    pub async fn local_enr(&self) -> Result<Enr, NetworkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(DiscoveryCommand::LocalEnr { reply: reply_tx })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        reply_rx.await.map_err(|_| NetworkError::ChannelClosed)
    }
}

// ── DiscoveryService::handle_command ─────────────────────────────────────────

use super::service::DiscoveryService;

impl DiscoveryService {
    /// Process one `DiscoveryCommand` from the handle.
    ///
    /// Called by the network event loop when a command arrives on the
    /// discovery command channel.
    pub(crate) fn handle_discovery_command(&mut self, cmd: DiscoveryCommand) {
        match cmd {
            DiscoveryCommand::UpdateEth2 { fork_id, reply } => {
                let bytes = fork_id.as_ssz_bytes();
                // Pass `&&[u8]` (a reference to a slice), matching the encoding
                // used at `build_local_enr` (`add_value("eth2", &eth2_bytes.as_slice())`)
                // so the bytes-string RLP round-trips with `rlp_decode_bytes` on read.
                let result = self
                    .discv5
                    .enr_insert("eth2", &bytes.as_slice())
                    .map(|_| ())
                    .map_err(|e| NetworkError::Discv5(e.to_string()));
                if result.is_ok() {
                    self.persist_enr_seq();
                }
                let _ = reply.send(result);
            }
            DiscoveryCommand::UpdateFuluEnr {
                fork_id,
                cgc,
                nfd,
                reply,
            } => {
                use crate::discovery::enr::encode_cgc;
                // eth2 first.
                let eth2_bytes = fork_id.as_ssz_bytes();
                let mut result = self
                    .discv5
                    .enr_insert("eth2", &eth2_bytes.as_slice())
                    .map(|_| ())
                    .map_err(|e| NetworkError::Discv5(e.to_string()));
                // cgc (custody group count): big-endian, no leading zeros.
                if result.is_ok()
                    && let Some(c) = cgc
                {
                    let cgc_bytes = encode_cgc(c);
                    result = self
                        .discv5
                        .enr_insert("cgc", &cgc_bytes.as_slice())
                        .map(|_| ())
                        .map_err(|e| NetworkError::Discv5(e.to_string()));
                }
                // nfd (next fork digest): SSZ Bytes4 (4 raw bytes).
                if result.is_ok()
                    && let Some(digest) = nfd
                {
                    result = self
                        .discv5
                        .enr_insert("nfd", &digest.as_slice())
                        .map(|_| ())
                        .map_err(|e| NetworkError::Discv5(e.to_string()));
                }
                if result.is_ok() {
                    self.persist_enr_seq();
                }
                let _ = reply.send(result);
            }
            DiscoveryCommand::UpdateSyncnets { syncnets, reply } => {
                let bytes = syncnets.as_ssz_bytes();
                let result = self
                    .discv5
                    .enr_insert("syncnets", &bytes.as_slice())
                    .map(|_| ())
                    .map_err(|e| NetworkError::Discv5(e.to_string()));
                if result.is_ok() {
                    self.persist_enr_seq();
                }
                let _ = reply.send(result);
            }
            DiscoveryCommand::UpdateExternalSocket(addr) => {
                // libp2p's confirmed external address is the TCP transport
                // socket, so update the ENR's tcp4/tcp6 field. discv5 returns
                // `true` only when the socket actually changed (and in that
                // case it has already bumped the ENR seq + re-signed); persist
                // the new seq only on a real change. (`D-enr-external-addr-update`)
                //
                // IP-clobber warning: `update_local_enr_socket(is_tcp=true)` calls
                // `set_tcp_socket`, which also overwrites the ENR `ip`/`ip6` field
                // that discv5 uses for UDP reachability. Under asymmetric NAT the
                // TCP-observed external IP can differ from the UDP one; warn here so
                // the skew is visible in logs even though we still proceed (libp2p's
                // confirmed addr is authoritative for our TCP advertisement).
                let enr = self.discv5.local_enr();
                let incoming_ip = addr.ip();
                match addr {
                    std::net::SocketAddr::V4(_) => {
                        if let Some(current_ip4) = enr.ip4()
                            && std::net::IpAddr::V4(current_ip4) != incoming_ip
                        {
                            tracing::warn!(
                                current = %current_ip4,
                                confirmed = %incoming_ip,
                                "external TCP IP differs from ENR ip4; update_local_enr_socket \
                                 will overwrite the ip4 field used for discv5 UDP reachability \
                                 — possible asymmetric NAT (`D-enr-external-addr-update`)"
                            );
                        }
                    }
                    std::net::SocketAddr::V6(_) => {
                        if let Some(current_ip6) = enr.ip6()
                            && std::net::IpAddr::V6(current_ip6) != incoming_ip
                        {
                            tracing::warn!(
                                current = %current_ip6,
                                confirmed = %incoming_ip,
                                "external TCP IP differs from ENR ip6; update_local_enr_socket \
                                 will overwrite the ip6 field used for discv5 UDP reachability \
                                 — possible asymmetric NAT (`D-enr-external-addr-update`)"
                            );
                        }
                    }
                }
                let changed = self.discv5.update_local_enr_socket(addr, true);
                if changed {
                    self.persist_enr_seq();
                } else {
                    tracing::debug!(
                        %addr,
                        "external-socket ENR update suppressed: discv5 reports no change \
                         (socket already matches or ENR key error)"
                    );
                }
            }
            DiscoveryCommand::LocalEnr { reply } => {
                let _ = reply.send(self.local_enr());
            }
        }
    }
}

// ── Channel constructor ───────────────────────────────────────────────────────

/// Create the `(DiscoveryHandle, mpsc::Receiver<DiscoveryCommand>)` pair.
///
/// The receiver is polled by the network event loop; the sender is the
/// publicly visible `DiscoveryHandle`.
pub(crate) fn discovery_channel() -> (DiscoveryHandle, mpsc::Receiver<DiscoveryCommand>) {
    let (tx, rx) = mpsc::channel(16);
    (DiscoveryHandle::new(tx), rx)
}
