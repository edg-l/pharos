//! Per-method req-resp request handler.
//!
//! `handle_request` dispatches an inbound `RpcRequest` to the appropriate
//! host method and returns an `RpcResponse`. Scoring events are recorded via
//! the `PeerManager`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use libp2p::PeerId;
use pharos_ssz::{SszList, SszSequence as _};
use pharos_types::EthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::phase0::{ErrorMessage, MetaData as Phase0MetaData, Status};

use crate::host::{BlobProvider, Host, LightClientProvider};
use crate::peer::manager::PeerManager;
use crate::rpc::min_epochs::compute_min_epochs_for_block_requests;
use crate::rpc::types::{
    MAX_REQUEST_BLOB_SIDECARS, MAX_REQUEST_BLOCKS, MAX_REQUEST_LIGHT_CLIENT_UPDATES,
    MetaDataResponse, RpcRequest, RpcResponse,
};
use crate::scoring::{HandshakeFailKind, PeerScorer, ScoreEvent};
use crate::types::DisconnectReason;

/// Handle an inbound `RpcRequest` and produce an `RpcResponse`.
///
/// `negotiated_protocol_id` is the protocol string that multistream-select
/// negotiated for this stream; used to select MetaData v1 vs v2 per
/// `D-metadata-v2-dual-handle`.
///
/// Scoring events are forwarded to `peer_manager.record_event`. The `Host`
/// provides chain state needed to build responses.
pub async fn handle_request<E, H, S>(
    host: &H,
    host_metadata: &Arc<ArcSwap<AltairMetaData>>,
    peer: PeerId,
    req: RpcRequest,
    peer_manager: &mut PeerManager<S>,
    negotiated_protocol_id: &str,
) -> RpcResponse<E>
where
    E: EthSpec,
    H: Host<E> + LightClientProvider<E> + BlobProvider<E>,
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
            // Read live metadata from the ArcSwap cache (updated by the subnet
            // rotation driver via NetworkCommand::UpdateMetaData), not from the
            // static host snapshot.
            let seq = host_metadata.load().seq_number;
            RpcResponse::Ping(seq)
        }

        // MetaData v2 (altair): serve full altair::MetaData with syncnets.
        // Per `D-metadata-v2-dual-handle`: select V1 or V2 based on the
        // protocol that multistream-select negotiated for this stream.
        RpcRequest::MetaData | RpcRequest::MetaDataV1 => {
            handle_metadata::<E>(host_metadata, negotiated_protocol_id)
        }

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

        // Light-client req-resp methods per
        // `specs/altair/light-client/p2p-interface.md`.
        RpcRequest::LightClientBootstrap(req) => {
            match host.light_client_bootstrap(req.0) {
                Some(bootstrap) => RpcResponse::LightClientBootstrap(bootstrap),
                None => RpcResponse::Error {
                    code: 3, // ResourceUnavailable
                    message: make_error_message("bootstrap not available for block root"),
                },
            }
        }

        RpcRequest::LightClientUpdatesByRange(req) => {
            // Reject requests that exceed the spec maximum per R5 (Light-client request flooding)
            // and `specs/altair/light-client/p2p-interface.md:35`.
            // Spec requires rejection (code 1 InvalidRequest), not silent clamping.
            if req.count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
                return RpcResponse::Error {
                    code: 1, // InvalidRequest
                    message: make_error_message("count exceeds MAX_REQUEST_LIGHT_CLIENT_UPDATES"),
                };
            }
            let updates = host.light_client_updates_by_range(req.start_period, req.count);
            RpcResponse::LightClientUpdatesByRange(updates)
        }

        RpcRequest::LightClientFinalityUpdate => {
            match host.light_client_finality_update() {
                Some(update) => RpcResponse::LightClientFinalityUpdate(update),
                None => RpcResponse::Error {
                    code: 3, // ResourceUnavailable
                    message: make_error_message("finality update not available"),
                },
            }
        }

        RpcRequest::LightClientOptimisticUpdate => {
            match host.light_client_optimistic_update() {
                Some(update) => RpcResponse::LightClientOptimisticUpdate(update),
                None => RpcResponse::Error {
                    code: 3, // ResourceUnavailable
                    message: make_error_message("optimistic update not available"),
                },
            }
        }

        // Blob sidecar req-resp methods per `specs/deneb/p2p-interface.md:816-968`.
        //
        // Serve what we have; silently omit sidecars outside the blob serve range
        // (pruner already removed them). `blobs_by_range` clamps to
        // `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` epochs from current slot.
        // Count is clamped to `MAX_REQUEST_BLOB_SIDECARS` to bound response size.
        RpcRequest::BlobSidecarsByRange(req) => {
            use pharos_types::phase0::primitives::Slot;
            let count = req.count.min(MAX_REQUEST_BLOB_SIDECARS);
            let sidecars = host.blobs_by_range(Slot(req.start_slot), count);
            RpcResponse::BlobSidecars(sidecars)
        }

        RpcRequest::BlobSidecarsByRoot(req) => {
            // Build `(block_root, index)` lookup list from `BlobIdentifier`s.
            let ids: Vec<_> = req
                .blob_ids
                .iter()
                .map(|id| (id.block_root, id.index))
                .collect();
            let sidecars = host.blobs_by_root(&ids);
            RpcResponse::BlobSidecars(sidecars)
        }
    }
}

// ── MetaData dual-handle ──────────────────────────────────────────────────────

/// Build a `MetaData` response selecting v1 or v2 by the negotiated protocol.
///
/// Per `D-metadata-v2-dual-handle`:
/// - `/metadata/1/ssz_snappy`: serve `MetaDataResponse::V1` (phase-0; drop `syncnets`).
/// - `/metadata/2/ssz_snappy` or unknown: serve `MetaDataResponse::V2` (altair; full).
///
/// The v1 view is derived from the v2 local metadata by copying `seq_number`
/// and `attnets` and discarding `syncnets`.
fn handle_metadata<E>(
    host_metadata: &Arc<ArcSwap<AltairMetaData>>,
    negotiated_protocol_id: &str,
) -> RpcResponse<E>
where
    E: EthSpec,
{
    // Read live metadata from the ArcSwap cache so peers see updates issued
    // by the subnet rotation driver (NetworkCommand::UpdateMetaData).
    let md = (**host_metadata.load()).clone();
    if negotiated_protocol_id == crate::scoring::RpcMethod::MetaDataV1.protocol_id() {
        // v1 peer: serve phase-0 MetaData (seq_number + attnets, no syncnets).
        let v1 = Phase0MetaData {
            seq_number: md.seq_number,
            attnets: md.attnets,
        };
        RpcResponse::MetaData(MetaDataResponse::V1(v1))
    } else {
        // v2 (or any other negotiation): serve full altair MetaData.
        RpcResponse::MetaData(MetaDataResponse::V2(md))
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
    use crate::host::{
        BlockProvider, ForkContext, GossipValidator, GossipVerdict, LightClientProvider,
    };
    use crate::peer::manager::PeerManager;
    use crate::scoring::NoopScorer;
    use crate::scoring::RpcMethod;
    use crate::types::{ConnectionDirection, PeerState, SubnetId};
    use pharos_types::MainnetEthSpec;
    use pharos_types::altair::MetaData as AltairMetaData;
    use pharos_types::phase0::primitives::{ForkDigest, Root};
    use pharos_types::phase0::{
        Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
        SignedAggregateAndProof, SignedVoluntaryExit, Slot,
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
        fn fork_digest_for(&self, _fork: crate::types::Fork) -> ForkDigest {
            self.fork_digest
        }
        fn fork_from_context(&self, _ctx: &[u8; 4]) -> Option<crate::types::Fork> {
            None
        }
        fn local_metadata(&self) -> AltairMetaData {
            AltairMetaData {
                seq_number: self.metadata_seq,
                ..AltairMetaData::default()
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
        fn validate_aggregate_and_proof(
            &self,
            _m: &SignedAggregateAndProof<2048>,
        ) -> GossipVerdict {
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
        fn validate_sync_committee_message(
            &self,
            _subnet: crate::types::SubnetId,
            _msg: &pharos_types::altair::SyncCommitteeMessage,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_sync_committee_contribution_and_proof(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::AltairSignedContributionAndProof,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_light_client_finality_update(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::AltairLightClientFinalityUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_light_client_optimistic_update(
            &self,
            _msg: &<MainnetEthSpec as EthSpec>::AltairLightClientOptimisticUpdate,
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
            _msg: &<MainnetEthSpec as pharos_types::EthSpec>::CapellaLightClientFinalityUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }

        fn validate_capella_light_client_optimistic_update(
            &self,
            _msg: &<MainnetEthSpec as pharos_types::EthSpec>::CapellaLightClientOptimisticUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }

        fn validate_blob_sidecar(
            &self,
            _subnet: crate::types::SubnetId,
            _sidecar: &pharos_types::deneb::BlobSidecar,
        ) -> GossipVerdict {
            unreachable!()
        }
    }

    impl LightClientProvider<MainnetEthSpec> for MockHost {
        fn light_client_bootstrap(
            &self,
            _block_root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::AltairLightClientBootstrap> {
            None
        }
        fn light_client_updates_by_range(
            &self,
            _start_period: u64,
            _count: u64,
        ) -> Vec<<MainnetEthSpec as EthSpec>::AltairLightClientUpdate> {
            Vec::new()
        }
        fn light_client_finality_update(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::AltairLightClientFinalityUpdate> {
            None
        }
        fn light_client_optimistic_update(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::AltairLightClientOptimisticUpdate> {
            None
        }

        fn light_client_finality_update_capella(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::CapellaLightClientFinalityUpdate> {
            None
        }

        fn light_client_optimistic_update_capella(
            &self,
        ) -> Option<<MainnetEthSpec as EthSpec>::CapellaLightClientOptimisticUpdate> {
            None
        }
    }

    impl BlobProvider<MainnetEthSpec> for MockHost {
        fn blobs_by_range(
            &self,
            _start_slot: pharos_types::phase0::primitives::Slot,
            _count: u64,
        ) -> Vec<pharos_types::deneb::BlobSidecar> {
            Vec::new()
        }
        fn blobs_by_root(
            &self,
            _ids: &[(pharos_types::phase0::primitives::Root, u64)],
        ) -> Vec<pharos_types::deneb::BlobSidecar> {
            Vec::new()
        }
    }

    fn make_peer_manager() -> PeerManager<NoopScorer> {
        PeerManager::new(NoopScorer, 10, 5)
    }

    // Convenience: build a MetaData v2 protocol ID string for test calls.
    fn v2_protocol() -> &'static str {
        RpcMethod::MetaData.protocol_id()
    }

    /// Build an `ArcSwap<AltairMetaData>` carrying a specific `seq_number`.
    fn make_md(seq: u64) -> Arc<ArcSwap<AltairMetaData>> {
        let md = AltairMetaData {
            seq_number: seq,
            ..AltairMetaData::default()
        };
        Arc::new(ArcSwap::from_pointee(md))
    }

    /// A `Ping(42)` request returns `Ping(seq)` where `seq` is the mock host's
    /// metadata seq_number.
    #[tokio::test]
    async fn ping_returns_local_seq() {
        let host = MockHost::new(Bytes4::from_array([0u8; 4]), 0);
        let md = make_md(7);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            &md,
            peer,
            RpcRequest::Ping(42),
            &mut pm,
            v2_protocol(),
        )
        .await;

        match resp {
            RpcResponse::Ping(seq) => assert_eq!(seq, 7, "Ping should return ArcSwap seq_number"),
            other => panic!("expected RpcResponse::Ping, got: {other:?}"),
        }
    }

    /// A `MetaData` (v2) request returns the cached altair metadata.
    #[tokio::test]
    async fn metadata_v2_returns_host_metadata() {
        let host = MockHost::new(Bytes4::from_array([0u8; 4]), 0);
        let md = make_md(3);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            &md,
            peer,
            RpcRequest::MetaData,
            &mut pm,
            v2_protocol(),
        )
        .await;

        match resp {
            RpcResponse::MetaData(MetaDataResponse::V2(m)) => assert_eq!(m.seq_number, 3),
            other => panic!("expected RpcResponse::MetaData(V2), got: {other:?}"),
        }
    }

    /// A `MetaData` (v1) request returns truncated phase-0 metadata.
    #[tokio::test]
    async fn metadata_v1_returns_v1_truncated() {
        let host = MockHost::new(Bytes4::from_array([0u8; 4]), 0);
        let md = make_md(5);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        let v1_protocol = RpcMethod::MetaDataV1.protocol_id();
        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            &md,
            peer,
            RpcRequest::MetaDataV1,
            &mut pm,
            v1_protocol,
        )
        .await;

        match resp {
            RpcResponse::MetaData(MetaDataResponse::V1(m)) => assert_eq!(m.seq_number, 5),
            other => panic!("expected RpcResponse::MetaData(V1), got: {other:?}"),
        }
    }

    /// `Ping` reflects updates to the `ArcSwap` after construction (regression
    /// guard for the bypass bug where handler called `host.local_metadata()`).
    #[tokio::test]
    async fn ping_reflects_arc_swap_updates() {
        let host = MockHost::new(Bytes4::from_array([0u8; 4]), 0);
        let md = make_md(1);
        let mut pm = make_peer_manager();
        let peer = PeerId::random();

        // Mutate the ArcSwap after construction; handler must see the new value.
        let updated = AltairMetaData {
            seq_number: 42,
            ..AltairMetaData::default()
        };
        md.store(Arc::new(updated));

        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            &md,
            peer,
            RpcRequest::Ping(0),
            &mut pm,
            v2_protocol(),
        )
        .await;

        match resp {
            RpcResponse::Ping(seq) => assert_eq!(seq, 42, "Ping must read live ArcSwap"),
            other => panic!("expected RpcResponse::Ping, got: {other:?}"),
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
        let md = make_md(0);
        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            &md,
            peer,
            RpcRequest::Status(incoming.clone()),
            &mut pm,
            v2_protocol(),
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
        let md = make_md(0);
        let resp = handle_request::<MainnetEthSpec, _, _>(
            &host,
            &md,
            peer,
            RpcRequest::Status(incoming),
            &mut pm,
            v2_protocol(),
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
