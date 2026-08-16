//! Electra light-client containers.
//!
//! Per `specs/electra/light-client/sync-protocol.md`.
//!
//! ## Changes from Deneb
//!
//! EIP-7251 appended fields to `BeaconState`, which deepens the generalized
//! indices of the light-client merkle branches. The branch VECTOR LENGTHS are
//! therefore larger than deneb (and these lengths are mixed into
//! `hash_tree_root`, so the types are NOT interchangeable with deneb):
//!
//! | Branch                         | gindex (electra) | depth = floorlog2 |
//! | ------------------------------ | ---------------- | ----------------- |
//! | `current_sync_committee`       | 86               | 6 (was 5)         |
//! | `next_sync_committee`          | 87               | 6 (was 5)         |
//! | `finalized_checkpoint.root`    | 169              | 7 (was 6)         |
//!
//! `LightClientHeader` (deneb execution payload header, unchanged) and
//! `LightClientOptimisticUpdate` (no branch) are re-exported from deneb.

use pharos_ssz::{Decode, Encode, SszVector, TreeHash};

use crate::altair::operations::{SyncAggregate, SyncCommittee};
use crate::phase0::primitives::Slot;
use pharos_utils::Bytes32;

// LightClientHeader + LightClientOptimisticUpdate are structurally identical to
// deneb (header: deneb execution payload header; optimistic update: no branch).
// Re-exported under their real names so external refs (eth_spec, conformance)
// and the struct fields below both resolve here.
pub use crate::deneb::light_client::{
    LightClientHeader, LightClientOptimisticUpdate, MainnetLightClientHeader,
    MainnetLightClientOptimisticUpdate, MinimalLightClientHeader,
    MinimalLightClientOptimisticUpdate,
};

/// `floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA = 86)`.
pub const CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA: u64 = 6;
/// `floorlog2(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA = 87)`.
pub const NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA: u64 = 6;
/// `floorlog2(FINALIZED_ROOT_GINDEX_ELECTRA = 169)`.
pub const FINALITY_BRANCH_DEPTH_ELECTRA: u64 = 7;

// ── LightClientBootstrap ──────────────────────────────────────────────────────

/// Electra `LightClientBootstrap` (deeper `current_sync_committee_branch`).
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
    /// `current_sync_committee_branch: Vector[Bytes32, 6]`
    pub current_sync_committee_branch:
        SszVector<Bytes32, CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA>,
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

/// Electra `LightClientUpdate` (deeper next-sync + finality branches).
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
    /// `next_sync_committee_branch: Vector[Bytes32, 6]`
    pub next_sync_committee_branch: SszVector<Bytes32, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA>,
    /// `finalized_header: LightClientHeader`
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `finality_branch: Vector[Bytes32, 7]`
    pub finality_branch: SszVector<Bytes32, FINALITY_BRANCH_DEPTH_ELECTRA>,
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

/// Electra `LightClientFinalityUpdate` (deeper finality branch).
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
    /// `finality_branch: Vector[Bytes32, 7]`
    pub finality_branch: SszVector<Bytes32, FINALITY_BRANCH_DEPTH_ELECTRA>,
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

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet electra `LightClientBootstrap`.
pub type MainnetLightClientBootstrap = LightClientBootstrap<512, 256, 32>;
/// Mainnet electra `LightClientUpdate`.
pub type MainnetLightClientUpdate = LightClientUpdate<512, 256, 32>;
/// Mainnet electra `LightClientFinalityUpdate`.
pub type MainnetLightClientFinalityUpdate = LightClientFinalityUpdate<512, 256, 32>;

/// Minimal electra `LightClientBootstrap`.
pub type MinimalLightClientBootstrap = LightClientBootstrap<32, 256, 32>;
/// Minimal electra `LightClientUpdate`.
pub type MinimalLightClientUpdate = LightClientUpdate<32, 256, 32>;
/// Minimal electra `LightClientFinalityUpdate`.
pub type MinimalLightClientFinalityUpdate = LightClientFinalityUpdate<32, 256, 32>;
