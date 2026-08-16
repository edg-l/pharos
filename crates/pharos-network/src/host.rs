//! Host trait boundaries: `ForkContext`, `BlockProvider`, `GossipValidator`.
//!
//! These traits decouple the network layer from the node implementation.
//! The node binary (`pharos-node`) provides concrete implementations over
//! `pharos-storage` + `pharos-fork-choice`. The network crate must not depend
//! on either of those crates.
//!
//! Plan reference: D-trait boundaries in `docs/m2-plan.md`.

use std::sync::Arc;

use pharos_types::BeaconSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::altair::SyncCommitteeMessage;
use pharos_types::capella::operations::SignedBLSToExecutionChange;
use pharos_types::deneb::BlobSidecar;
use pharos_types::electra::attestation::SingleAttestation;
use pharos_types::fulu::DataColumnSidecar;
use pharos_types::phase0::primitives::ForkDigest;
use pharos_types::phase0::{
    Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing, Root,
    SignedAggregateAndProof, SignedVoluntaryExit, Slot,
};

use crate::types::{Fork, SubnetId};

// ── GossipVerdict ─────────────────────────────────────────────────────────────

/// Sentinel reason string for RB6: the gossip block's parent has not been seen.
///
/// Used in `GossipVerdict::Ignore` by `validate_beacon_block` (pharos-node) and
/// compared by the network dispatcher to decide whether to emit
/// `NetworkEvent::UnknownParentBlock`. Single source of truth; callers must
/// reference this const rather than re-typing the literal.
pub const GOSSIP_REASON_PARENT_UNSEEN: &str = "block: parent unseen";

/// The verdict returned by a `GossipValidator` method.
///
/// Used to drive libp2p gossipsub message acceptance; maps directly onto
/// gossipsub's `MessageAcceptance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipVerdict {
    /// The message is valid; propagate it to other peers.
    Accept,
    /// The message is invalid; penalise the sender and discard.
    Reject(String),
    /// The message is not relevant right now; discard without penalising.
    Ignore(String),
}

// ── ForkContext ───────────────────────────────────────────────────────────────

/// Provides fork-digest and genesis-root information to the network layer.
///
/// Implemented by the node binary over the current `BeaconState` + clock.
pub trait ForkContext: Send + Sync + 'static {
    /// The 4-byte fork digest for the current fork.
    fn current_fork_digest(&self) -> ForkDigest;

    /// The ENR fork identifier (fork_digest + next_fork_version + next_fork_epoch).
    fn enr_fork_id(&self) -> ENRForkID;

    /// The genesis validators root used in fork-digest computation.
    fn genesis_validators_root(&self) -> Root;

    /// Returns the fork digest for the given `Fork`.
    ///
    /// Used by the context-bytes codec to prefix response chunks with the
    /// 4-byte fork digest per `specs/altair/p2p-interface.md:445-461`.
    fn fork_digest_for(&self, fork: Fork) -> ForkDigest;

    /// Maps a raw 4-byte context to a `Fork`.
    ///
    /// Returns `None` for any context bytes that do not correspond to a known
    /// fork digest. The codec emits a decode error on `None`.
    fn fork_from_context(&self, ctx: &[u8; 4]) -> Option<Fork>;

    /// The local node's current `MetaData` (Altair v2).
    ///
    /// Used by `Ping` and `MetaData` req-resp handlers to return the node's
    /// sequence number, attestation subnet bitfield, and sync-committee subnet
    /// bitfield. The v1 truncation (dropping `syncnets`) is done by the
    /// handler when the negotiated protocol ID is `/metadata/1/ssz_snappy`.
    /// Per `D-metadata-v2-dual-handle`.
    fn local_metadata(&self) -> AltairMetaData {
        AltairMetaData::default()
    }

    /// The set of data-column indices this node custodies (EIP-7594 PeerDAS).
    ///
    /// `node_id` is the local discv5 node id (big-endian 32-byte uint256).
    /// Implementations compute the custody column set via the Fulu DAS-core
    /// helpers (`get_custody_groups` + `compute_columns_for_custody_group`)
    /// over the node's custody-group count. The startup gossip subscription
    /// uses this to subscribe ONLY to `data_column_sidecar_{subnet}` topics
    /// covering the custodied columns, NOT all `DATA_COLUMN_SIDECAR_SUBNET_COUNT`
    /// subnets. Per `specs/fulu/p2p-interface.md` + `specs/fulu/das-core.md`.
    ///
    /// The default returns an empty set so non-Fulu test mocks compile
    /// unchanged.
    fn custody_columns(&self, node_id: [u8; 32]) -> Vec<u64> {
        let _ = node_id;
        Vec::new()
    }

    /// The slot of the earliest available block (`SignedBeaconBlock`) this node
    /// can serve, for the Fulu `Status` v2 `earliest_available_slot` field.
    ///
    /// Per `specs/fulu/p2p-interface.md` (`Status v2`). The default returns
    /// `Slot(0)` (genesis) so non-Fulu test mocks compile unchanged; HostImpl
    /// overrides it with the anchor / split slot.
    fn earliest_available_slot(&self) -> Slot {
        Slot::default()
    }

    /// The node's custody group count (`cgc`) for the Fulu `MetaData` v3
    /// `custody_group_count` field and the ENR `cgc` field.
    ///
    /// Per `specs/fulu/p2p-interface.md` (`MetaData`). The default returns
    /// `0` so non-Fulu test mocks compile unchanged; HostImpl overrides it
    /// with the node's current (sticky-high) custody group count.
    fn custody_group_count(&self) -> u64 {
        0
    }
}

// ── BlockProvider ─────────────────────────────────────────────────────────────

/// Provides block-lookup and chain-head information to the network layer.
///
/// Used by req-resp handlers to serve `BeaconBlocksByRange` and
/// `BeaconBlocksByRoot` responses without the network crate touching storage
/// directly.
pub trait BlockProvider<E: BeaconSpec>: Send + Sync + 'static {
    /// Retrieve a single block by its beacon block root.
    ///
    /// Returns `None` if the block is not in the local store.
    fn block_by_root(&self, root: Root) -> Option<E::SignedBeaconBlock>;

    /// Retrieve a range of blocks starting from `start_slot`.
    ///
    /// Returns up to `count` consecutive blocks. May return fewer if slots are
    /// empty or `start_slot + count` exceeds the current head.
    fn blocks_by_range(&self, start_slot: Slot, count: u64) -> Vec<E::SignedBeaconBlock>;

    /// The latest finalized checkpoint.
    fn finalized_checkpoint(&self) -> Checkpoint;

    /// The current chain head: `(block_root, slot)`.
    fn head(&self) -> (Root, Slot);
}

// ── GossipValidator ───────────────────────────────────────────────────────────

/// Validates gossip messages that require state-aware checks.
///
/// The network crate performs only protocol-level checks (topic validity,
/// SSZ decode, snappy decode, message-id). State-aware checks (proposer
/// signature, known parent, etc.) are delegated here.
///
/// Each method corresponds to one of the six Phase-0 gossip topics defined in
/// `specs/phase0/p2p-interface.md`.
///
/// The const generics (`MAX_VALIDATORS_PER_COMMITTEE`) match those used by the
/// concrete operation containers in `pharos-types`. Both mainnet and minimal
/// presets share `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
pub trait GossipValidator<E: BeaconSpec>: Send + Sync + 'static {
    /// Validate a `beacon_block` message.
    fn validate_beacon_block(&self, block: &E::SignedBeaconBlock) -> GossipVerdict;

    /// Validate a `beacon_attestation_{subnet_id}` message.
    ///
    /// `subnet` is the subnet id extracted from the topic string.
    /// `MAX_VALIDATORS_PER_COMMITTEE = 2048` for both mainnet and minimal.
    fn validate_attestation(&self, subnet: SubnetId, att: &Attestation<2048>) -> GossipVerdict;

    /// Validate a `beacon_aggregate_and_proof` message.
    ///
    /// Receives the full `SignedAggregateAndProof` so that validators can check
    /// both the selection proof (on `message.selection_proof`) and the outer
    /// aggregator signature (on `signature`).
    ///
    /// `MAX_VALIDATORS_PER_COMMITTEE = 2048` for both mainnet and minimal.
    fn validate_aggregate_and_proof(&self, msg: &SignedAggregateAndProof<2048>) -> GossipVerdict;

    /// Validate a `voluntary_exit` message.
    fn validate_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> GossipVerdict;

    /// Validate a `proposer_slashing` message.
    fn validate_proposer_slashing(&self, slashing: &ProposerSlashing) -> GossipVerdict;

    /// Validate an `attester_slashing` message.
    ///
    /// `MAX_VALIDATORS_PER_COMMITTEE = 2048` for both mainnet and minimal.
    fn validate_attester_slashing(&self, slashing: &AttesterSlashing<2048>) -> GossipVerdict;

    // ── Altair gossip topics ──────────────────────────────────────────────────
    //
    // Per `specs/altair/p2p-interface.md:184-188` and
    // `specs/altair/light-client/p2p-interface.md:47-48`.

    /// Validate a `sync_committee_<subnet_id>` message.
    ///
    /// `SyncCommitteeMessage` is not generic; it has no bitvector fields.
    fn validate_sync_committee_message(
        &self,
        subnet: SubnetId,
        msg: &SyncCommitteeMessage,
    ) -> GossipVerdict;

    /// Validate a `sync_committee_contribution_and_proof` message.
    ///
    /// `SYNC_SUBCOMMITTEE_SIZE` differs per preset:
    /// mainnet = 128, minimal = 8 (`SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT`).
    fn validate_sync_committee_contribution_and_proof(
        &self,
        msg: &E::AltairSignedContributionAndProof,
    ) -> GossipVerdict;

    /// Validate a `light_client_finality_update` message.
    fn validate_light_client_finality_update(
        &self,
        msg: &E::AltairLightClientFinalityUpdate,
    ) -> GossipVerdict;

    /// Validate a `light_client_optimistic_update` message.
    fn validate_light_client_optimistic_update(
        &self,
        msg: &E::AltairLightClientOptimisticUpdate,
    ) -> GossipVerdict;

    // ── Capella gossip topics ─────────────────────────────────────────────────
    //
    // Per `specs/capella/p2p-interface.md` and
    // `specs/capella/light-client/p2p-interface.md`.

    /// Validate a `bls_to_execution_change` message.
    ///
    /// `SignedBLSToExecutionChange` is not generic over `E` (no preset-sized
    /// fields); the type is the same across all presets.
    fn validate_bls_to_execution_change(&self, msg: &SignedBLSToExecutionChange) -> GossipVerdict;

    /// Validate a capella-fork `light_client_finality_update` message.
    ///
    /// The capella LC header shape differs from altair (adds `execution` +
    /// `execution_branch`). Full-node validation logic is otherwise identical.
    /// Per `specs/capella/light-client/p2p-interface.md`.
    fn validate_capella_light_client_finality_update(
        &self,
        msg: &E::CapellaLightClientFinalityUpdate,
    ) -> GossipVerdict;

    /// Validate a capella-fork `light_client_optimistic_update` message.
    ///
    /// Per `specs/capella/light-client/p2p-interface.md`.
    fn validate_capella_light_client_optimistic_update(
        &self,
        msg: &E::CapellaLightClientOptimisticUpdate,
    ) -> GossipVerdict;

    // ── Deneb gossip topics ───────────────────────────────────────────────────
    //
    // Per `specs/deneb/p2p-interface.md:489-586`.

    /// Validate a `blob_sidecar_{subnet_id}` message.
    ///
    /// `subnet` is the subnet id extracted from the topic string.
    /// All 14 validation rules per `specs/deneb/p2p-interface.md:497-585`.
    fn validate_blob_sidecar(&self, subnet: SubnetId, sidecar: &BlobSidecar) -> GossipVerdict;

    // ── Fulu gossip topics (EIP-7594 PeerDAS) ─────────────────────────────────
    //
    // Per `specs/fulu/p2p-interface.md` (`validate_data_column_sidecar_gossip`).

    /// Validate a `data_column_sidecar_{subnet_id}` message.
    ///
    /// `subnet` is the subnet id extracted from the topic string. All 13
    /// validation rules per `specs/fulu/p2p-interface.md`.
    ///
    /// The default body returns `Ignore`; concrete fulu hosts override it. This
    /// lets non-fulu test mocks compile unchanged.
    fn validate_data_column_sidecar(
        &self,
        subnet: SubnetId,
        sidecar: &DataColumnSidecar<4096, 4>,
    ) -> GossipVerdict {
        let _ = (subnet, sidecar);
        GossipVerdict::Ignore("data column sidecar validator not implemented".to_string())
    }

    // ── Electra gossip topics (EIP-7549) ──────────────────────────────────────
    //
    // Per `specs/electra/p2p-interface.md:225,476-591`.

    /// Validate a `beacon_attestation_{subnet_id}` message for an electra-epoch
    /// message: the subnet topic now carries `SingleAttestation`, NOT the
    /// multi-committee `Attestation`. Conflating the two SSZ shapes is an instant
    /// peer-ban hazard.
    ///
    /// `subnet` is the subnet id extracted from the topic string.
    /// Per `specs/electra/p2p-interface.md:476-591`.
    ///
    /// The default body returns `Ignore`; concrete hosts override it. This lets
    /// non-electra test mocks compile unchanged.
    fn validate_single_attestation(
        &self,
        subnet: SubnetId,
        att: &SingleAttestation,
    ) -> GossipVerdict {
        let _ = (subnet, att);
        GossipVerdict::Ignore("single attestation validator not implemented".to_string())
    }

    /// Validate a `beacon_aggregate_and_proof` message for an electra-epoch
    /// message: the aggregate carries the electra `Attestation` with
    /// `committee_bits` (EIP-7549). The multi-committee type stays on this
    /// aggregate path only; the subnet path uses `SingleAttestation`.
    ///
    /// Per `specs/electra/p2p-interface.md:225`.
    ///
    /// The default body returns `Ignore`; concrete hosts override it.
    fn validate_aggregate_and_proof_electra(
        &self,
        msg: &E::ElectraSignedAggregateAndProof,
    ) -> GossipVerdict {
        let _ = msg;
        GossipVerdict::Ignore("electra aggregate validator not implemented".to_string())
    }
}

// ── LightClientProvider ───────────────────────────────────────────────────────

/// Provides light-client data to the req-resp handler.
///
/// Implemented by `HostImpl<E>` in `pharos-node` via `pharos-storage`.  The
/// network crate does not touch storage directly; it delegates through this
/// trait boundary.
///
/// Per `D-light-client-server-only`: only the server (responder) side is
/// implemented; the consumer side is M5/M7 work.
pub trait LightClientProvider<E: BeaconSpec>: Send + Sync + 'static {
    /// Look up a `LightClientBootstrap` by trusted block root.
    ///
    /// Returns `None` if no snapshot is stored for `block_root`.
    /// Per `specs/altair/light-client/p2p-interface.md:56-68`.
    fn light_client_bootstrap(
        &self,
        block_root: pharos_types::phase0::primitives::Root,
    ) -> Option<E::AltairLightClientBootstrap>;

    /// Return `LightClientUpdate` objects for sync-committee periods
    /// `[start_period, start_period + count)`.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:70-86`.
    /// `count` has already been clamped to `MAX_REQUEST_LIGHT_CLIENT_UPDATES`
    /// by the caller.
    fn light_client_updates_by_range(
        &self,
        start_period: u64,
        count: u64,
    ) -> Vec<E::AltairLightClientUpdate>;

    /// Return the latest `LightClientFinalityUpdate`, if any.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:88-101`.
    fn light_client_finality_update(&self) -> Option<E::AltairLightClientFinalityUpdate>;

    /// Return the latest `LightClientOptimisticUpdate`, if any.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:103-116`.
    fn light_client_optimistic_update(&self) -> Option<E::AltairLightClientOptimisticUpdate>;

    /// Return the latest Capella `LightClientFinalityUpdate`, if any.
    ///
    /// Per `specs/capella/light-client/p2p-interface.md`.
    fn light_client_finality_update_capella(&self) -> Option<E::CapellaLightClientFinalityUpdate>;

    /// Return the latest Capella `LightClientOptimisticUpdate`, if any.
    ///
    /// Per `specs/capella/light-client/p2p-interface.md`.
    fn light_client_optimistic_update_capella(
        &self,
    ) -> Option<E::CapellaLightClientOptimisticUpdate>;

    /// Return the latest Deneb `LightClientFinalityUpdate`, if any.
    ///
    /// Per `specs/deneb/light-client/p2p-interface.md`.
    fn light_client_finality_update_deneb(&self) -> Option<E::DenebLightClientFinalityUpdate>;

    /// Return the latest Deneb `LightClientOptimisticUpdate`, if any.
    ///
    /// Per `specs/deneb/light-client/p2p-interface.md`.
    fn light_client_optimistic_update_deneb(&self) -> Option<E::DenebLightClientOptimisticUpdate>;

    /// Return the latest Electra `LightClientFinalityUpdate`, if any.
    ///
    /// Per `specs/electra/light-client/p2p-interface.md`.
    fn light_client_finality_update_electra(&self) -> Option<E::ElectraLightClientFinalityUpdate>;

    /// Return the latest Electra `LightClientOptimisticUpdate`, if any.
    ///
    /// Per `specs/electra/light-client/p2p-interface.md`.
    fn light_client_optimistic_update_electra(
        &self,
    ) -> Option<E::ElectraLightClientOptimisticUpdate>;
}

// Arc<T> blanket impl for LightClientProvider.
impl<T, E> LightClientProvider<E> for std::sync::Arc<T>
where
    T: LightClientProvider<E> + ?Sized,
    E: BeaconSpec,
{
    fn light_client_bootstrap(
        &self,
        block_root: pharos_types::phase0::primitives::Root,
    ) -> Option<E::AltairLightClientBootstrap> {
        (**self).light_client_bootstrap(block_root)
    }

    fn light_client_updates_by_range(
        &self,
        start_period: u64,
        count: u64,
    ) -> Vec<E::AltairLightClientUpdate> {
        (**self).light_client_updates_by_range(start_period, count)
    }

    fn light_client_finality_update(&self) -> Option<E::AltairLightClientFinalityUpdate> {
        (**self).light_client_finality_update()
    }

    fn light_client_optimistic_update(&self) -> Option<E::AltairLightClientOptimisticUpdate> {
        (**self).light_client_optimistic_update()
    }

    fn light_client_finality_update_capella(&self) -> Option<E::CapellaLightClientFinalityUpdate> {
        (**self).light_client_finality_update_capella()
    }

    fn light_client_optimistic_update_capella(
        &self,
    ) -> Option<E::CapellaLightClientOptimisticUpdate> {
        (**self).light_client_optimistic_update_capella()
    }

    fn light_client_finality_update_deneb(&self) -> Option<E::DenebLightClientFinalityUpdate> {
        (**self).light_client_finality_update_deneb()
    }

    fn light_client_optimistic_update_deneb(&self) -> Option<E::DenebLightClientOptimisticUpdate> {
        (**self).light_client_optimistic_update_deneb()
    }

    fn light_client_finality_update_electra(&self) -> Option<E::ElectraLightClientFinalityUpdate> {
        (**self).light_client_finality_update_electra()
    }

    fn light_client_optimistic_update_electra(
        &self,
    ) -> Option<E::ElectraLightClientOptimisticUpdate> {
        (**self).light_client_optimistic_update_electra()
    }
}

// ── BlobProvider ─────────────────────────────────────────────────────────────

/// Provides blob-sidecar data for `BlobSidecarsByRange` and `BlobSidecarsByRoot`
/// req-resp handlers.
///
/// The network crate does not read storage directly; it delegates through this
/// trait boundary to `pharos-storage`. Implemented by `HostImpl<E>` in
/// `pharos-node`.
///
/// Per `specs/deneb/p2p-interface.md:816-974`.
pub trait BlobProvider<E: BeaconSpec>: Send + Sync + 'static {
    /// Retrieve a contiguous range of blob sidecars starting from `start_slot`.
    ///
    /// Returns up to `count * MAX_BLOBS_PER_BLOCK` sidecars from canonical
    /// slots `[start_slot, start_slot + count)`. May return fewer if some slots
    /// have no blobs or are outside `blob_serve_range`. The caller clamps the
    /// response to `compute_max_request_blob_sidecars()`.
    fn blobs_by_range(&self, start_slot: Slot, count: u64) -> Vec<BlobSidecar>;

    /// Retrieve blob sidecars by `(block_root, blob_index)` pairs.
    ///
    /// For each `BlobIdentifier` that is found in the local store, the matching
    /// `BlobSidecar` is included in the response (in order). Unknown identifiers
    /// are silently omitted.
    fn blobs_by_root(&self, ids: &[(Root, u64)]) -> Vec<BlobSidecar>;
}

impl<T, E> BlobProvider<E> for Arc<T>
where
    T: BlobProvider<E> + ?Sized,
    E: BeaconSpec,
{
    fn blobs_by_range(&self, start_slot: Slot, count: u64) -> Vec<BlobSidecar> {
        (**self).blobs_by_range(start_slot, count)
    }

    fn blobs_by_root(&self, ids: &[(Root, u64)]) -> Vec<BlobSidecar> {
        (**self).blobs_by_root(ids)
    }
}

// ── DataColumnProvider ──────────────────────────────────────────────────────

/// Storage-backed retrieval of data-column sidecars for the EIP-7594 PeerDAS
/// req-resp handlers (`DataColumnSidecarsByRange` / `DataColumnSidecarsByRoot`).
///
/// Mirrors `BlobProvider<E>`: the network crate does not read storage directly;
/// it delegates through this trait boundary to `pharos-storage`. Implemented by
/// `HostImpl<E>` in `pharos-node`.
///
/// Per `specs/fulu/p2p-interface.md` (`DataColumnSidecarsByRange v1` /
/// `DataColumnSidecarsByRoot v1`).
pub trait DataColumnProvider<E: BeaconSpec>: Send + Sync + 'static {
    /// Retrieve column sidecars for the slots `[start_slot, start_slot + count)`
    /// restricted to the requested `columns`, in `(slot, column_index)` order.
    ///
    /// May return fewer than requested when slots have no columns or fall
    /// outside the `data_column_serve_range`. The caller clamps the response to
    /// `compute_max_request_data_column_sidecars()`.
    fn data_columns_by_range(
        &self,
        start_slot: Slot,
        count: u64,
        columns: &[u64],
    ) -> Vec<DataColumnSidecar<4096, 4>>;

    /// Retrieve column sidecars by `(block_root, columns)` identifiers.
    ///
    /// For each identifier, the matching sidecars present in the local store are
    /// included (in column order); unknown identifiers/columns are omitted.
    fn data_columns_by_root(&self, ids: &[(Root, Vec<u64>)]) -> Vec<DataColumnSidecar<4096, 4>>;
}

impl<T, E> DataColumnProvider<E> for Arc<T>
where
    T: DataColumnProvider<E> + ?Sized,
    E: BeaconSpec,
{
    fn data_columns_by_range(
        &self,
        start_slot: Slot,
        count: u64,
        columns: &[u64],
    ) -> Vec<DataColumnSidecar<4096, 4>> {
        (**self).data_columns_by_range(start_slot, count, columns)
    }

    fn data_columns_by_root(&self, ids: &[(Root, Vec<u64>)]) -> Vec<DataColumnSidecar<4096, 4>> {
        (**self).data_columns_by_root(ids)
    }
}

// ── Host ──────────────────────────────────────────────────────────────────────

/// Combined host trait: a single bound for `ForkContext + BlockProvider<E> + GossipValidator<E>`.
///
/// `Network<E, H, S>` takes a single `Arc<H>` rather than three separate arcs.
/// The blanket impl monomorphises once per concrete `(T, E)` pair (in practice
/// `(HostImpl, MainnetBeaconSpec)` plus the test mock); no dynamic dispatch is
/// introduced.
pub trait Host<E: BeaconSpec>: ForkContext + BlockProvider<E> + GossipValidator<E> {}

impl<T, E> Host<E> for T
where
    T: ForkContext + BlockProvider<E> + GossipValidator<E>,
    E: BeaconSpec,
{
}

// ── Arc<T> blanket impls ──────────────────────────────────────────────────────
//
// These allow `Arc<HostImpl<E>>` (and any other `Arc<T>` where `T` implements
// the sub-traits) to be used directly with `NetworkBuilder` and the `Host<E>`
// blanket. Resolves `Q-host-arc-vs-arclike` (M3a plan): single `Arc<HostImpl>`
// shared between the node binary and the network task.

impl<T> ForkContext for Arc<T>
where
    T: ForkContext + ?Sized,
{
    fn current_fork_digest(&self) -> ForkDigest {
        (**self).current_fork_digest()
    }

    fn enr_fork_id(&self) -> ENRForkID {
        (**self).enr_fork_id()
    }

    fn genesis_validators_root(&self) -> Root {
        (**self).genesis_validators_root()
    }

    fn fork_digest_for(&self, fork: Fork) -> ForkDigest {
        (**self).fork_digest_for(fork)
    }

    fn fork_from_context(&self, ctx: &[u8; 4]) -> Option<Fork> {
        (**self).fork_from_context(ctx)
    }

    fn local_metadata(&self) -> AltairMetaData {
        (**self).local_metadata()
    }

    fn custody_columns(&self, node_id: [u8; 32]) -> Vec<u64> {
        (**self).custody_columns(node_id)
    }

    fn earliest_available_slot(&self) -> Slot {
        (**self).earliest_available_slot()
    }

    fn custody_group_count(&self) -> u64 {
        (**self).custody_group_count()
    }
}

impl<T, E> BlockProvider<E> for Arc<T>
where
    T: BlockProvider<E> + ?Sized,
    E: BeaconSpec,
{
    fn block_by_root(&self, root: Root) -> Option<E::SignedBeaconBlock> {
        (**self).block_by_root(root)
    }

    fn blocks_by_range(&self, start_slot: Slot, count: u64) -> Vec<E::SignedBeaconBlock> {
        (**self).blocks_by_range(start_slot, count)
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        (**self).finalized_checkpoint()
    }

    fn head(&self) -> (Root, Slot) {
        (**self).head()
    }
}

impl<T, E> GossipValidator<E> for Arc<T>
where
    T: GossipValidator<E> + ?Sized,
    E: BeaconSpec,
{
    fn validate_beacon_block(&self, block: &E::SignedBeaconBlock) -> GossipVerdict {
        (**self).validate_beacon_block(block)
    }

    fn validate_attestation(&self, subnet: SubnetId, att: &Attestation<2048>) -> GossipVerdict {
        (**self).validate_attestation(subnet, att)
    }

    fn validate_aggregate_and_proof(&self, msg: &SignedAggregateAndProof<2048>) -> GossipVerdict {
        (**self).validate_aggregate_and_proof(msg)
    }

    fn validate_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> GossipVerdict {
        (**self).validate_voluntary_exit(exit)
    }

    fn validate_proposer_slashing(&self, slashing: &ProposerSlashing) -> GossipVerdict {
        (**self).validate_proposer_slashing(slashing)
    }

    fn validate_attester_slashing(&self, slashing: &AttesterSlashing<2048>) -> GossipVerdict {
        (**self).validate_attester_slashing(slashing)
    }

    fn validate_sync_committee_message(
        &self,
        subnet: SubnetId,
        msg: &SyncCommitteeMessage,
    ) -> GossipVerdict {
        (**self).validate_sync_committee_message(subnet, msg)
    }

    fn validate_sync_committee_contribution_and_proof(
        &self,
        msg: &E::AltairSignedContributionAndProof,
    ) -> GossipVerdict {
        (**self).validate_sync_committee_contribution_and_proof(msg)
    }

    fn validate_light_client_finality_update(
        &self,
        msg: &E::AltairLightClientFinalityUpdate,
    ) -> GossipVerdict {
        (**self).validate_light_client_finality_update(msg)
    }

    fn validate_light_client_optimistic_update(
        &self,
        msg: &E::AltairLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        (**self).validate_light_client_optimistic_update(msg)
    }

    fn validate_bls_to_execution_change(&self, msg: &SignedBLSToExecutionChange) -> GossipVerdict {
        (**self).validate_bls_to_execution_change(msg)
    }

    fn validate_capella_light_client_finality_update(
        &self,
        msg: &E::CapellaLightClientFinalityUpdate,
    ) -> GossipVerdict {
        (**self).validate_capella_light_client_finality_update(msg)
    }

    fn validate_capella_light_client_optimistic_update(
        &self,
        msg: &E::CapellaLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        (**self).validate_capella_light_client_optimistic_update(msg)
    }

    fn validate_blob_sidecar(&self, subnet: SubnetId, sidecar: &BlobSidecar) -> GossipVerdict {
        (**self).validate_blob_sidecar(subnet, sidecar)
    }

    fn validate_data_column_sidecar(
        &self,
        subnet: SubnetId,
        sidecar: &DataColumnSidecar<4096, 4>,
    ) -> GossipVerdict {
        (**self).validate_data_column_sidecar(subnet, sidecar)
    }

    fn validate_single_attestation(
        &self,
        subnet: SubnetId,
        att: &SingleAttestation,
    ) -> GossipVerdict {
        (**self).validate_single_attestation(subnet, att)
    }

    fn validate_aggregate_and_proof_electra(
        &self,
        msg: &E::ElectraSignedAggregateAndProof,
    ) -> GossipVerdict {
        (**self).validate_aggregate_and_proof_electra(msg)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::BeaconSpec;

    /// Compile-time witness that `Arc<T>` satisfies `Host<E>` when `T: Host<E>`.
    ///
    /// This function is never called; its existence proves the blanket impls
    /// compose correctly, resolving `Q-host-arc-vs-arclike`.
    fn _assert_arc_is_host<E: BeaconSpec, T: Host<E>>(_: Arc<T>) {}
}
