//! Capella light-client containers.
//!
//! Per `specs/capella/light-client/sync-protocol.md`.
//!
//! ## Changes from Altair/Bellatrix
//!
//! `LightClientHeader` gains two new fields:
//! - `execution: ExecutionPayloadHeader` — Capella execution payload header.
//! - `execution_branch: ExecutionBranch` — Merkle branch of `execution_payload`
//!   within `BeaconBlockBody`.
//!
//! ## Branch length
//!
//! `EXECUTION_PAYLOAD_GINDEX = get_generalized_index(BeaconBlockBody, 'execution_payload') = 25`.
//! `floorlog2(25) = 4`, so `ExecutionBranch = Vector[Bytes32, 4]`.

use pharos_ssz::{Decode, Encode, SszVector, TreeHash};

use crate::altair::operations::{SyncAggregate, SyncCommittee};
use crate::capella::ExecutionPayloadHeader;
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::Slot;
use pharos_utils::Bytes32;

use crate::altair::light_client::{
    CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH, FINALITY_BRANCH_DEPTH, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH,
};

/// Generalized index of `execution_payload` within `BeaconBlockBody`.
///
/// `get_generalized_index(BeaconBlockBody, 'execution_payload')` = 25.
/// Per `specs/capella/light-client/sync-protocol.md` (Constants table).
pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;

/// Branch length for `ExecutionBranch`:
/// `Vector[Bytes32, floorlog2(EXECUTION_PAYLOAD_GINDEX)]`
/// = `Vector[Bytes32, floorlog2(25)]` = `Vector[Bytes32, 4]`.
/// Per `specs/capella/light-client/sync-protocol.md` (Types table).
pub const EXECUTION_BRANCH_DEPTH: u64 = 4;

// ── LightClientHeader ─────────────────────────────────────────────────────────

/// Capella `LightClientHeader` per `specs/capella/light-client/sync-protocol.md`.
///
/// Extends the Altair header with `execution` and `execution_branch`.
///
/// Const parameters (match `ExecutionPayloadHeader`):
/// 1. `BYTES_PER_LOGS_BLOOM`
/// 2. `MAX_EXTRA_DATA_BYTES`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientHeader<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64> {
    /// `beacon: BeaconBlockHeader`
    /// — `specs/capella/light-client/sync-protocol.md`.
    pub beacon: BeaconBlockHeader,
    /// `execution: ExecutionPayloadHeader`
    /// — `specs/capella/light-client/sync-protocol.md`.
    pub execution: ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `execution_branch: ExecutionBranch`
    /// = `Vector[Bytes32, floorlog2(25)]` = `Vector[Bytes32, 4]`.
    /// — `specs/capella/light-client/sync-protocol.md`.
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
            execution: ExecutionPayloadHeader::default(),
            execution_branch: SszVector::default(),
        }
    }
}

// ── LightClientBootstrap ──────────────────────────────────────────────────────

/// Capella `LightClientBootstrap` per `specs/capella/light-client/sync-protocol.md`.
///
/// Generic over `SYNC_COMMITTEE_SIZE` and execution payload header bounds.
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
    /// = `Vector[Bytes32, floorlog2(54)]` = `Vector[Bytes32, 5]`.
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

/// Capella `LightClientUpdate` per `specs/capella/light-client/sync-protocol.md`.
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
    /// = `Vector[Bytes32, floorlog2(55)]` = `Vector[Bytes32, 5]`.
    pub next_sync_committee_branch: SszVector<Bytes32, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH>,
    /// `finalized_header: LightClientHeader`
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `finality_branch: FinalityBranch`
    /// = `Vector[Bytes32, floorlog2(105)]` = `Vector[Bytes32, 6]`.
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

/// Capella `LightClientFinalityUpdate` per `specs/capella/light-client/sync-protocol.md`.
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
    /// = `Vector[Bytes32, floorlog2(105)]` = `Vector[Bytes32, 6]`.
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

/// Capella `LightClientOptimisticUpdate` per `specs/capella/light-client/sync-protocol.md`.
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

/// Mainnet capella `LightClientHeader`.
///
/// `BYTES_PER_LOGS_BLOOM = 256`, `MAX_EXTRA_DATA_BYTES = 32`.
pub type MainnetLightClientHeader = LightClientHeader<256, 32>;

/// Mainnet capella `LightClientBootstrap`.
pub type MainnetLightClientBootstrap = LightClientBootstrap<512, 256, 32>;

/// Mainnet capella `LightClientUpdate`.
pub type MainnetLightClientUpdate = LightClientUpdate<512, 256, 32>;

/// Mainnet capella `LightClientFinalityUpdate`.
pub type MainnetLightClientFinalityUpdate = LightClientFinalityUpdate<512, 256, 32>;

/// Mainnet capella `LightClientOptimisticUpdate`.
pub type MainnetLightClientOptimisticUpdate = LightClientOptimisticUpdate<512, 256, 32>;

/// Minimal capella `LightClientHeader`.
///
/// `BYTES_PER_LOGS_BLOOM = 256`, `MAX_EXTRA_DATA_BYTES = 32`.
pub type MinimalLightClientHeader = LightClientHeader<256, 32>;

/// Minimal capella `LightClientBootstrap`.
pub type MinimalLightClientBootstrap = LightClientBootstrap<32, 256, 32>;

/// Minimal capella `LightClientUpdate`.
pub type MinimalLightClientUpdate = LightClientUpdate<32, 256, 32>;

/// Minimal capella `LightClientFinalityUpdate`.
pub type MinimalLightClientFinalityUpdate = LightClientFinalityUpdate<32, 256, 32>;

/// Minimal capella `LightClientOptimisticUpdate`.
pub type MinimalLightClientOptimisticUpdate = LightClientOptimisticUpdate<32, 256, 32>;

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_ssz::{Decode, Encode};

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(val: T) {
        let encoded = val.as_ssz_bytes();
        let decoded = T::from_ssz_bytes(&encoded).expect("SSZ decode failed");
        assert_eq!(val, decoded);
    }

    #[test]
    fn light_client_header_mainnet_roundtrip() {
        roundtrip(MainnetLightClientHeader::default());
    }

    #[test]
    fn light_client_header_minimal_roundtrip() {
        roundtrip(MinimalLightClientHeader::default());
    }

    #[test]
    fn light_client_bootstrap_mainnet_roundtrip() {
        roundtrip(MainnetLightClientBootstrap::default());
    }

    #[test]
    fn light_client_bootstrap_minimal_roundtrip() {
        roundtrip(MinimalLightClientBootstrap::default());
    }

    #[test]
    fn light_client_update_mainnet_roundtrip() {
        roundtrip(MainnetLightClientUpdate::default());
    }

    #[test]
    fn light_client_update_minimal_roundtrip() {
        roundtrip(MinimalLightClientUpdate::default());
    }

    #[test]
    fn light_client_finality_update_mainnet_roundtrip() {
        roundtrip(MainnetLightClientFinalityUpdate::default());
    }

    #[test]
    fn light_client_finality_update_minimal_roundtrip() {
        roundtrip(MinimalLightClientFinalityUpdate::default());
    }

    #[test]
    fn light_client_optimistic_update_mainnet_roundtrip() {
        roundtrip(MainnetLightClientOptimisticUpdate::default());
    }

    #[test]
    fn light_client_optimistic_update_minimal_roundtrip() {
        roundtrip(MinimalLightClientOptimisticUpdate::default());
    }
}
