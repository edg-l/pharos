//! Per-method req-resp request handler.
//!
//! `handle_request` dispatches an inbound `RpcRequest` to the appropriate
//! host method and returns an `RpcResponse`. Scoring events are recorded via
//! the `PeerManager`.

use libp2p::PeerId;
use pharos_ssz::SszList;
use pharos_types::EthSpec;
use pharos_types::phase0::{ErrorMessage, Status};

use crate::host::Host;
use crate::peer::manager::PeerManager;
use crate::rpc::min_epochs::compute_min_epochs_for_block_requests;
use crate::rpc::types::{MAX_REQUEST_BLOCKS, RpcRequest, RpcResponse};
use crate::scoring::{HandshakeFailKind, PeerScorer, ScoreEvent};
use crate::types::DisconnectReason;

/// Handle an inbound `RpcRequest` and produce an `RpcResponse`.
///
/// Scoring events are forwarded to `peer_manager.record_event`. The `Host`
/// provides chain state needed to build responses.
pub async fn handle_request<E, H, S>(
    host: &H,
    peer: PeerId,
    req: RpcRequest,
    peer_manager: &mut PeerManager<S>,
) -> RpcResponse<E>
where
    E: EthSpec,
    H: Host<E>,
    S: PeerScorer,
{
    match req {
        RpcRequest::Status(incoming) => {
            let local = build_local_status(host);
            if incoming.fork_digest != local.fork_digest {
                peer_manager.record_event(
                    peer,
                    ScoreEvent::HandshakeFail {
                        kind: HandshakeFailKind::ForkDigestMismatch,
                    },
                );
                // Peer is on an incompatible fork; transition to Disconnecting
                // so the dialer's Goodbye tears us down cleanly.
                peer_manager.on_disconnecting(peer);
                return RpcResponse::Error {
                    code: 1,
                    message: make_error_message("fork digest mismatch"),
                };
            }
            // Fork digest matches: advance inbound peer through the handshake.
            peer_manager.on_inbound_status(peer, incoming);
            RpcResponse::Status(local)
        }

        RpcRequest::Goodbye(reason) => {
            tracing::debug!(%peer, reason, "received Goodbye");
            peer_manager.record_event(
                peer,
                ScoreEvent::PeerDisconnected {
                    reason: DisconnectReason::Goodbye(reason),
                },
            );
            RpcResponse::Goodbye(reason)
        }

        RpcRequest::Ping(_seq) => {
            let seq = host.local_metadata().seq_number;
            RpcResponse::Ping(seq)
        }

        RpcRequest::MetaData => RpcResponse::MetaData(host.local_metadata()),

        RpcRequest::BlocksByRange(req) => {
            let count = req.count.min(MAX_REQUEST_BLOCKS);
            // Derive current slot from head; use head slot as conservative proxy.
            let (_head_root, head_slot) = host.head();
            let min_epochs = compute_min_epochs_for_block_requests::<E>();
            let oldest_allowed = head_slot.0.saturating_sub(min_epochs * E::SLOTS_PER_EPOCH);
            if req.start_slot.0 < oldest_allowed {
                return RpcResponse::Error {
                    code: 3,
                    message: make_error_message("range out of historical window"),
                };
            }
            let blocks = host.blocks_by_range(req.start_slot, count);
            RpcResponse::BlocksByRange(blocks)
        }

        RpcRequest::BlocksByRoot(req) => {
            let blocks: Vec<E::SignedBeaconBlock> = req
                .block_roots
                .as_slice()
                .iter()
                .filter_map(|root| host.block_by_root(*root))
                .collect();
            RpcResponse::BlocksByRoot(blocks)
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_local_status<E, H>(host: &H) -> Status
where
    E: EthSpec,
    H: Host<E>,
{
    let checkpoint = host.finalized_checkpoint();
    let (head_root, head_slot) = host.head();
    Status {
        fork_digest: host.current_fork_digest(),
        finalized_root: checkpoint.root,
        finalized_epoch: checkpoint.epoch,
        head_root,
        head_slot,
    }
}

/// Build an `ErrorMessage` from a string slice (truncated to 256 bytes).
pub fn make_error_message(s: &str) -> ErrorMessage {
    let bytes = s.as_bytes();
    let truncated = &bytes[..256_usize.min(bytes.len())];
    let message = SszList::from_vec(truncated.to_vec())
        .expect("SszList<u8, 256> from <= 256 bytes is infallible");
    ErrorMessage { message }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict};
    use crate::peer::manager::PeerManager;
    use crate::scoring::NoopScorer;
    use crate::types::{ConnectionDirection, PeerState, SubnetId};
    use pharos_types::MainnetEthSpec;
    use pharos_types::phase0::primitives::ForkDigest;
    use pharos_types::phase0::{
        AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, MetaData,
        ProposerSlashing, Root, SignedVoluntaryExit, Slot,
    };
    use pharos_utils::{Bytes4, Epoch};

    struct MockHost {
        fork_digest: ForkDigest,
        metadata_seq: u64,
    }

    impl MockHost {
        fn new(fork_digest: ForkDigest, metadata_seq: u64) -> Self {
            Self {
                fork_digest,
                metadata_seq,
            }
        }
    }

    impl ForkContext for MockHost {
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
        fn local_metadata(&self) -> MetaData {
            MetaData {
                seq_number: self.metadata_seq,
                ..MetaData::default()
            }
        }
    }

    impl BlockProvider<MainnetEthSpec> for MockHost {
        fn block_by_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            None
        }
        fn blocks_by_range(
            &self,
            _start: Slot,
            _count: u64,
        ) -> Vec<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            Vec::new()
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            Checkpoint {
                root: Root::default(),
                epoch: Epoch(0),
            }
        }
        fn head(&self) -> (Root, Slot) {
            (Root::default(), Slot(0))
        }
    }

    impl GossipValidator<MainnetEthSpec> for MockHost {
        fn validate_beacon_block(
            &self,
            _b: &<MainnetEthSpec as EthSpec>::SignedBeaconBlock,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_attestation(&self, _s: SubnetId, _a: &Attestation<2048>) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_aggregate_and_proof(&self, _m: &AggregateAndProof<2048>) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_voluntary_exit(&self, _e: &SignedVoluntaryExit) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_proposer_slashing(&self, _s: &ProposerSlashing) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_attester_slashing(&self, _s: &AttesterSlashing<2048>) -> GossipVerdict {
            GossipVerdict::Accept
        }
    }

    fn make_peer_manager() -> PeerManager<NoopScorer> {
        PeerManager::new(NoopScorer, 10, 5)
    }

    /// A `Ping(42)` request returns `Ping(seq)` where `seq` is the mock host's
    /// metadata seq_number.
    #[tokio::test]
    async fn ping_returns_local_seq() {
        let host = MockHost::new(Bytes4::from_array([0u8; 4]), 7);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        let resp =
            handle_request::<MainnetEthSpec, _, _>(&host, peer, RpcRequest::Ping(42), &mut pm)
                .await;

        match resp {
            RpcResponse::Ping(seq) => assert_eq!(seq, 7, "Ping should return host's seq_number"),
            other => panic!("expected RpcResponse::Ping, got: {other:?}"),
        }
    }

    /// A `MetaData` request returns the host's metadata.
    #[tokio::test]
    async fn metadata_returns_host_metadata() {
        let host = MockHost::new(Bytes4::from_array([0u8; 4]), 3);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        let resp =
            handle_request::<MainnetEthSpec, _, _>(&host, peer, RpcRequest::MetaData, &mut pm)
                .await;

        match resp {
            RpcResponse::MetaData(m) => assert_eq!(m.seq_number, 3),
            other => panic!("expected RpcResponse::MetaData, got: {other:?}"),
        }
    }

    /// A `Status` request with matching fork digest returns `RpcResponse::Status`
    /// and transitions the inbound peer from `Connecting` to `Connected`.
    #[tokio::test]
    async fn status_matching_fork_digest() {
        let fd = Bytes4::from_array([0x01, 0x02, 0x03, 0x04]);
        let host = MockHost::new(fd, 0);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        // Register peer as inbound (simulates a remote dial-in).
        pm.on_connected(peer, ConnectionDirection::Inbound, Vec::new());
        assert_eq!(pm.peer_state(&peer), Some(PeerState::Connecting));

        let incoming = Status {
            fork_digest: fd,
            ..Status::default()
        };
        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            peer,
            RpcRequest::Status(incoming.clone()),
            &mut pm,
        )
        .await;
        assert!(matches!(resp, RpcResponse::Status(_)));

        // Inbound peer must now be Connected.
        assert_eq!(
            pm.peer_state(&peer),
            Some(PeerState::Connected),
            "inbound peer must reach Connected after matching Status"
        );
    }

    /// A `Status` request with mismatching fork digest returns an error and
    /// transitions the peer to `Disconnecting`.
    #[tokio::test]
    async fn status_mismatched_fork_digest() {
        let local_fd = Bytes4::from_array([0xAA, 0xBB, 0xCC, 0xDD]);
        let remote_fd = Bytes4::from_array([0x11, 0x22, 0x33, 0x44]);
        let host = MockHost::new(local_fd, 0);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        pm.on_connected(peer, ConnectionDirection::Inbound, Vec::new());

        let incoming = Status {
            fork_digest: remote_fd,
            ..Status::default()
        };
        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            peer,
            RpcRequest::Status(incoming),
            &mut pm,
        )
        .await;
        match resp {
            RpcResponse::Error { code, .. } => assert_eq!(code, 1),
            other => panic!("expected RpcResponse::Error, got: {other:?}"),
        }
        assert_eq!(
            pm.peer_state(&peer),
            Some(PeerState::Disconnecting),
            "fork-digest mismatch must transition peer to Disconnecting"
        );
    }
}
