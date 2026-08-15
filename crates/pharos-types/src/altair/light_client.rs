//! Altair light-client containers.
//!
//! Per `specs/altair/light-client/sync-protocol.md`.
//!
//! Branch lengths derived from generalized indices in the spec:
//! - `FINALIZED_ROOT_GINDEX = 105` → `floorlog2(105) = 6`
//! - `CURRENT_SYNC_COMMITTEE_GINDEX = 54` → `floorlog2(54) = 5`
//! - `NEXT_SYNC_COMMITTEE_GINDEX = 55` → `floorlog2(55) = 5`

use pharos_ssz::{Decode, Encode, SszVector, TreeHash};

use crate::altair::operations::{SyncAggregate, SyncCommittee};
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::Slot;
use pharos_utils::Bytes32;

/// Generalized index of `finalized_checkpoint.root` within `BeaconState`.
///
/// `get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')` = 105.
/// Per `specs/altair/light-client/sync-protocol.md` (Constants table).
pub const FINALIZED_ROOT_GINDEX: u64 = 105;

/// Generalized index of `current_sync_committee` within `BeaconState`.
///
/// `get_generalized_index(BeaconState, 'current_sync_committee')` = 54.
/// Per `specs/altair/light-client/sync-protocol.md` (Constants table).
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 54;

/// Generalized index of `next_sync_committee` within `BeaconState`.
///
/// `get_generalized_index(BeaconState, 'next_sync_committee')` = 55.
/// Per `specs/altair/light-client/sync-protocol.md` (Constants table).
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 55;

/// Branch length for `FinalityBranch`:
/// `Vector[Bytes32, floorlog2(FINALIZED_ROOT_GINDEX)]`
/// = `Vector[Bytes32, floorlog2(105)]` = `Vector[Bytes32, 6]`.
/// Per `specs/altair/light-client/sync-protocol.md` (Types table).
pub const FINALITY_BRANCH_DEPTH: u64 = 6;

/// Branch length for `CurrentSyncCommitteeBranch`:
/// `Vector[Bytes32, floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX)]`
/// = `Vector[Bytes32, floorlog2(54)]` = `Vector[Bytes32, 5]`.
/// Per `specs/altair/light-client/sync-protocol.md` (Types table).
pub const CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH: u64 = 5;

/// Branch length for `NextSyncCommitteeBranch`:
/// `Vector[Bytes32, floorlog2(NEXT_SYNC_COMMITTEE_GINDEX)]`
/// = `Vector[Bytes32, floorlog2(55)]` = `Vector[Bytes32, 5]`.
/// Per `specs/altair/light-client/sync-protocol.md` (Types table).
pub const NEXT_SYNC_COMMITTEE_BRANCH_DEPTH: u64 = 5;

// ── LightClientHeader ─────────────────────────────────────────────────────────

/// `LightClientHeader` per `specs/altair/light-client/sync-protocol.md:90-91`.
///
/// Future upgrades may introduce additional fields to this structure.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct LightClientHeader {
    /// `beacon: BeaconBlockHeader`
    /// — `specs/altair/light-client/sync-protocol.md:91`.
    pub beacon: BeaconBlockHeader,
}

// ── LightClientBootstrap ──────────────────────────────────────────────────────

/// `LightClientBootstrap` per `specs/altair/light-client/sync-protocol.md:101-106`.
///
/// Generic over `SYNC_COMMITTEE_SIZE`.
/// `current_sync_committee_branch: CurrentSyncCommitteeBranch`
/// = `Vector[Bytes32, floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX)]`
/// = `Vector[Bytes32, 5]`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientBootstrap<const SYNC_COMMITTEE_SIZE: u64> {
    /// `header: LightClientHeader`
    /// — `specs/altair/light-client/sync-protocol.md:103`.
    pub header: LightClientHeader,
    /// `current_sync_committee: SyncCommittee`
    /// — `specs/altair/light-client/sync-protocol.md:105`.
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `current_sync_committee_branch: CurrentSyncCommitteeBranch`
    /// = `Vector[Bytes32, floorlog2(54)]` = `Vector[Bytes32, 5]`.
    /// — `specs/altair/light-client/sync-protocol.md:106`.
    pub current_sync_committee_branch: SszVector<Bytes32, CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH>,
}

impl<const SYNC_COMMITTEE_SIZE: u64> Default for LightClientBootstrap<SYNC_COMMITTEE_SIZE>
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

/// `LightClientUpdate` per `specs/altair/light-client/sync-protocol.md:112-125`.
///
/// Generic over `SYNC_COMMITTEE_SIZE`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientUpdate<const SYNC_COMMITTEE_SIZE: u64> {
    /// `attested_header: LightClientHeader`
    /// — `specs/altair/light-client/sync-protocol.md:114`.
    pub attested_header: LightClientHeader,
    /// `next_sync_committee: SyncCommittee`
    /// — `specs/altair/light-client/sync-protocol.md:116`.
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `next_sync_committee_branch: NextSyncCommitteeBranch`
    /// = `Vector[Bytes32, floorlog2(55)]` = `Vector[Bytes32, 5]`.
    /// — `specs/altair/light-client/sync-protocol.md:117`.
    pub next_sync_committee_branch: SszVector<Bytes32, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH>,
    /// `finalized_header: LightClientHeader`
    /// — `specs/altair/light-client/sync-protocol.md:119`.
    pub finalized_header: LightClientHeader,
    /// `finality_branch: FinalityBranch`
    /// = `Vector[Bytes32, floorlog2(105)]` = `Vector[Bytes32, 6]`.
    /// — `specs/altair/light-client/sync-protocol.md:120`.
    pub finality_branch: SszVector<Bytes32, FINALITY_BRANCH_DEPTH>,
    /// `sync_aggregate: SyncAggregate`
    /// — `specs/altair/light-client/sync-protocol.md:122`.
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `signature_slot: Slot`
    /// — `specs/altair/light-client/sync-protocol.md:124`.
    pub signature_slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: u64> Default for LightClientUpdate<SYNC_COMMITTEE_SIZE>
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

/// `LightClientFinalityUpdate` per
/// `specs/altair/light-client/sync-protocol.md:130-139`.
///
/// Generic over `SYNC_COMMITTEE_SIZE`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientFinalityUpdate<const SYNC_COMMITTEE_SIZE: u64> {
    /// `attested_header: LightClientHeader`
    /// — `specs/altair/light-client/sync-protocol.md:132`.
    pub attested_header: LightClientHeader,
    /// `finalized_header: LightClientHeader`
    /// — `specs/altair/light-client/sync-protocol.md:134`.
    pub finalized_header: LightClientHeader,
    /// `finality_branch: FinalityBranch`
    /// = `Vector[Bytes32, floorlog2(105)]` = `Vector[Bytes32, 6]`.
    /// — `specs/altair/light-client/sync-protocol.md:135`.
    pub finality_branch: SszVector<Bytes32, FINALITY_BRANCH_DEPTH>,
    /// `sync_aggregate: SyncAggregate`
    /// — `specs/altair/light-client/sync-protocol.md:137`.
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `signature_slot: Slot`
    /// — `specs/altair/light-client/sync-protocol.md:139`.
    pub signature_slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: u64> Default for LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>
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

/// `LightClientOptimisticUpdate` per
/// `specs/altair/light-client/sync-protocol.md:145-151`.
///
/// Generic over `SYNC_COMMITTEE_SIZE`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct LightClientOptimisticUpdate<const SYNC_COMMITTEE_SIZE: u64> {
    /// `attested_header: LightClientHeader`
    /// — `specs/altair/light-client/sync-protocol.md:147`.
    pub attested_header: LightClientHeader,
    /// `sync_aggregate: SyncAggregate`
    /// — `specs/altair/light-client/sync-protocol.md:149`.
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `signature_slot: Slot`
    /// — `specs/altair/light-client/sync-protocol.md:151`.
    pub signature_slot: Slot,
}

impl<const SYNC_COMMITTEE_SIZE: u64> Default for LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE> {
    fn default() -> Self {
        Self {
            attested_header: LightClientHeader::default(),
            sync_aggregate: SyncAggregate::default(),
            signature_slot: Slot::default(),
        }
    }
}

// ── LightClientStore ──────────────────────────────────────────────────────────

/// `LightClientStore` per `specs/altair/light-client/sync-protocol.md:157-170`.
///
/// Runtime store maintained by a light client; not SSZ-encoded on the wire.
/// Generic over `SYNC_COMMITTEE_SIZE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightClientStore<const SYNC_COMMITTEE_SIZE: u64> {
    /// `finalized_header: LightClientHeader`
    pub finalized_header: LightClientHeader,
    /// `current_sync_committee: SyncCommittee`
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `next_sync_committee: SyncCommittee`
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `best_valid_update: Optional[LightClientUpdate]`
    pub best_valid_update: Option<LightClientUpdate<SYNC_COMMITTEE_SIZE>>,
    /// `optimistic_header: LightClientHeader`
    pub optimistic_header: LightClientHeader,
    /// `previous_max_active_participants: uint64`
    pub previous_max_active_participants: u64,
    /// `current_max_active_participants: uint64`
    pub current_max_active_participants: u64,
}

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
    fn light_client_header_roundtrip() {
        roundtrip(LightClientHeader::default());
    }

    #[test]
    fn light_client_bootstrap_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetLightClientBootstrap::default());
    }

    #[test]
    fn light_client_bootstrap_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalLightClientBootstrap::default());
    }

    #[test]
    fn light_client_update_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetLightClientUpdate::default());
    }

    #[test]
    fn light_client_update_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalLightClientUpdate::default());
    }

    #[test]
    fn light_client_finality_update_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetLightClientFinalityUpdate::default());
    }

    #[test]
    fn light_client_finality_update_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalLightClientFinalityUpdate::default());
    }

    #[test]
    fn light_client_optimistic_update_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetLightClientOptimisticUpdate::default());
    }

    #[test]
    fn light_client_optimistic_update_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalLightClientOptimisticUpdate::default());
    }
}
