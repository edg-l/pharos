//! Deneb light-client containers.
//!
//! Per `specs/deneb/light-client/sync-protocol.md`.
//!
//! ## Changes from Capella
//!
//! `LightClientHeader.execution` is re-typed to `deneb::ExecutionPayloadHeader`
//! (adds `blob_gas_used` and `excess_blob_gas`).
//! `execution_branch` and all other containers are structurally identical.

use pharos_ssz::{Decode, Encode, SszVector, TreeHash};

use crate::altair::operations::{SyncAggregate, SyncCommittee};
use crate::deneb::execution_payload::ExecutionPayloadHeader as DenebExecutionPayloadHeader;
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::Slot;
use pharos_utils::Bytes32;

use crate::altair::light_client::{
    CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH, FINALITY_BRANCH_DEPTH, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH,
};
pub use crate::capella::light_client::{EXECUTION_BRANCH_DEPTH, EXECUTION_PAYLOAD_GINDEX};

// ── LightClientHeader ─────────────────────────────────────────────────────────

/// Deneb `LightClientHeader` per `specs/deneb/light-client/sync-protocol.md`.
///
/// Identical structure to capella header, but `execution` uses the
/// deneb `ExecutionPayloadHeader` (adds `blob_gas_used` / `excess_blob_gas`).
///
/// Const parameters:
/// 1. `BYTES_PER_LOGS_BLOOM`
/// 2. `MAX_EXTRA_DATA_BYTES`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientHeader<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64> {
    /// `beacon: BeaconBlockHeader`.
    pub beacon: BeaconBlockHeader,
    /// `execution: deneb::ExecutionPayloadHeader`.
    pub execution: DenebExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `execution_branch: ExecutionBranch` = `Vector[Bytes32, 4]`.
    pub execution_branch: SszVector<Bytes32, EXECUTION_BRANCH_DEPTH>,
}

impl<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64> Default
    for LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::default(),
            execution: DenebExecutionPayloadHeader::default(),
            execution_branch: SszVector::default(),
        }
    }
}

// ── LightClientBootstrap ──────────────────────────────────────────────────────

/// Deneb `LightClientBootstrap` per `specs/deneb/light-client/sync-protocol.md`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientBootstrap<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `header: LightClientHeader`
    pub header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `current_sync_committee: SyncCommittee`
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `current_sync_committee_branch: CurrentSyncCommitteeBranch`
    pub current_sync_committee_branch: SszVector<Bytes32, CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH>,
}

impl<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> Default for LightClientBootstrap<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            header: LightClientHeader::default(),
            current_sync_committee: SyncCommittee::default(),
            current_sync_committee_branch: SszVector::default(),
        }
    }
}

// ── LightClientUpdate ─────────────────────────────────────────────────────────

/// Deneb `LightClientUpdate` per `specs/deneb/light-client/sync-protocol.md`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientUpdate<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `attested_header: LightClientHeader`
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `next_sync_committee: SyncCommittee`
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `next_sync_committee_branch: NextSyncCommitteeBranch`
    pub next_sync_committee_branch: SszVector<Bytes32, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH>,
    /// `finalized_header: LightClientHeader`
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `finality_branch: FinalityBranch`
    pub finality_branch: SszVector<Bytes32, FINALITY_BRANCH_DEPTH>,
    /// `sync_aggregate: SyncAggregate`
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `signature_slot: Slot`
    pub signature_slot: Slot,
}

impl<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> Default for LightClientUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            attested_header: LightClientHeader::default(),
            next_sync_committee: SyncCommittee::default(),
            next_sync_committee_branch: SszVector::default(),
            finalized_header: LightClientHeader::default(),
            finality_branch: SszVector::default(),
            sync_aggregate: SyncAggregate::default(),
            signature_slot: Slot::default(),
        }
    }
}

// ── LightClientFinalityUpdate ─────────────────────────────────────────────────

/// Deneb `LightClientFinalityUpdate`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientFinalityUpdate<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `attested_header: LightClientHeader`
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `finalized_header: LightClientHeader`
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `finality_branch: FinalityBranch`
    pub finality_branch: SszVector<Bytes32, FINALITY_BRANCH_DEPTH>,
    /// `sync_aggregate: SyncAggregate`
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `signature_slot: Slot`
    pub signature_slot: Slot,
}

impl<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> Default
    for LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            attested_header: LightClientHeader::default(),
            finalized_header: LightClientHeader::default(),
            finality_branch: SszVector::default(),
            sync_aggregate: SyncAggregate::default(),
            signature_slot: Slot::default(),
        }
    }
}

// ── LightClientOptimisticUpdate ───────────────────────────────────────────────

/// Deneb `LightClientOptimisticUpdate`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientOptimisticUpdate<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `attested_header: LightClientHeader`
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `sync_aggregate: SyncAggregate`
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `signature_slot: Slot`
    pub signature_slot: Slot,
}

impl<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> Default
    for LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            attested_header: LightClientHeader::default(),
            sync_aggregate: SyncAggregate::default(),
            signature_slot: Slot::default(),
        }
    }
}

// ── Views ─────────────────────────────────────────────────────────────────────

impl<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> crate::views::LightClientFinalityUpdateView
    for LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn finalized_header_slot(&self) -> u64 {
        self.finalized_header.beacon.slot.0
    }

    fn finality_signature_slot(&self) -> u64 {
        self.signature_slot.0
    }
}

impl<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> crate::views::LightClientOptimisticUpdateView
    for LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn optimistic_attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }

    fn optimistic_signature_slot(&self) -> u64 {
        self.signature_slot.0
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet deneb `LightClientHeader`.
pub type MainnetLightClientHeader = LightClientHeader<256, 32>;

/// Mainnet deneb `LightClientBootstrap`.
pub type MainnetLightClientBootstrap = LightClientBootstrap<512, 256, 32>;

/// Mainnet deneb `LightClientUpdate`.
pub type MainnetLightClientUpdate = LightClientUpdate<512, 256, 32>;

/// Mainnet deneb `LightClientFinalityUpdate`.
pub type MainnetLightClientFinalityUpdate = LightClientFinalityUpdate<512, 256, 32>;

/// Mainnet deneb `LightClientOptimisticUpdate`.
pub type MainnetLightClientOptimisticUpdate = LightClientOptimisticUpdate<512, 256, 32>;

/// Minimal deneb `LightClientHeader`.
pub type MinimalLightClientHeader = LightClientHeader<256, 32>;

/// Minimal deneb `LightClientBootstrap`.
pub type MinimalLightClientBootstrap = LightClientBootstrap<32, 256, 32>;

/// Minimal deneb `LightClientUpdate`.
pub type MinimalLightClientUpdate = LightClientUpdate<32, 256, 32>;

/// Minimal deneb `LightClientFinalityUpdate`.
pub type MinimalLightClientFinalityUpdate = LightClientFinalityUpdate<32, 256, 32>;

/// Minimal deneb `LightClientOptimisticUpdate`.
pub type MinimalLightClientOptimisticUpdate = LightClientOptimisticUpdate<32, 256, 32>;
