//! Altair sync committee operation containers.
//!
//! Beacon-chain containers per `specs/altair/beacon-chain.md:193-210`
//! (SyncAggregate, SyncCommittee).
//!
//! Validator-side containers per `specs/altair/validator.md:93-131`
//! (SyncCommitteeMessage, SyncCommitteeContribution, ContributionAndProof,
//! SignedContributionAndProof).

use pharos_ssz::{Bitvector, Decode, Encode, SszVector, TreeHash};
use pharos_utils::{BLSPubkey, BLSSignature};

use crate::phase0::primitives::{Root, Slot, ValidatorIndex};

// ── SyncAggregate ─────────────────────────────────────────────────────────────

/// `SyncAggregate` per `specs/altair/beacon-chain.md:196-199`.
///
/// Generic over `SYNC_COMMITTEE_SIZE` (a flat `u64` const).
/// Mainnet: `SYNC_COMMITTEE_SIZE = 512` (`presets/mainnet/altair.yaml:15`).
/// Minimal: `SYNC_COMMITTEE_SIZE = 32` (`presets/minimal/altair.yaml:15`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SyncAggregate<const SYNC_COMMITTEE_SIZE: u64> {
    /// `sync_committee_bits: Bitvector[SYNC_COMMITTEE_SIZE]`
    /// — `specs/altair/beacon-chain.md:197`.
    pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
    /// `sync_committee_signature: BLSSignature`
    /// — `specs/altair/beacon-chain.md:198`.
    pub sync_committee_signature: BLSSignature,
}

// ── SyncCommittee ─────────────────────────────────────────────────────────────

/// `SyncCommittee` per `specs/altair/beacon-chain.md:204-207`.
///
/// Generic over `SYNC_COMMITTEE_SIZE` (a flat `u64` const).
/// Mainnet: `SYNC_COMMITTEE_SIZE = 512` (`presets/mainnet/altair.yaml:15`).
/// Minimal: `SYNC_COMMITTEE_SIZE = 32` (`presets/minimal/altair.yaml:15`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct SyncCommittee<const SYNC_COMMITTEE_SIZE: u64> {
    /// `pubkeys: Vector[BLSPubkey, SYNC_COMMITTEE_SIZE]`
    /// — `specs/altair/beacon-chain.md:205`.
    pub pubkeys: SszVector<BLSPubkey, SYNC_COMMITTEE_SIZE>,
    /// `aggregate_pubkey: BLSPubkey`
    /// — `specs/altair/beacon-chain.md:206`.
    pub aggregate_pubkey: BLSPubkey,
}

impl<const SYNC_COMMITTEE_SIZE: u64> Default for SyncCommittee<SYNC_COMMITTEE_SIZE>
where
    BLSPubkey: Default + Clone,
{
    fn default() -> Self {
        Self {
            pubkeys: SszVector::default(),
            aggregate_pubkey: BLSPubkey::default(),
        }
    }
}

// ── SyncCommitteeMessage ──────────────────────────────────────────────────────

/// `SyncCommitteeMessage` per `specs/altair/validator.md:96-101`.
///
/// Produced by a validator in the sync committee for a given slot.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SyncCommitteeMessage {
    /// `slot: Slot` — `specs/altair/validator.md:97`.
    pub slot: Slot,
    /// `beacon_block_root: Root` — `specs/altair/validator.md:98`.
    pub beacon_block_root: Root,
    /// `validator_index: ValidatorIndex` — `specs/altair/validator.md:99`.
    pub validator_index: ValidatorIndex,
    /// `signature: BLSSignature` — `specs/altair/validator.md:100`.
    pub signature: BLSSignature,
}

// ── SyncCommitteeContribution ─────────────────────────────────────────────────

/// `SyncCommitteeContribution` per `specs/altair/validator.md:106-112`.
///
/// Aggregated contribution from a sync subcommittee.
/// Generic over `SYNC_SUBCOMMITTEE_SIZE` (a flat `u64` const).
/// `SYNC_SUBCOMMITTEE_SIZE = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT`.
/// Mainnet: 512 / 4 = 128. Minimal: 32 / 4 = 8.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SyncCommitteeContribution<const SYNC_SUBCOMMITTEE_SIZE: u64> {
    /// `slot: Slot` — `specs/altair/validator.md:107`.
    pub slot: Slot,
    /// `beacon_block_root: Root` — `specs/altair/validator.md:108`.
    pub beacon_block_root: Root,
    /// `subcommittee_index: uint64` — `specs/altair/validator.md:109`.
    pub subcommittee_index: u64,
    /// `aggregation_bits: Bitvector[SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT]`
    /// — `specs/altair/validator.md:110`.
    /// Expressed as `Bitvector<SYNC_SUBCOMMITTEE_SIZE>`.
    pub aggregation_bits: Bitvector<SYNC_SUBCOMMITTEE_SIZE>,
    /// `signature: BLSSignature` — `specs/altair/validator.md:111`.
    pub signature: BLSSignature,
}

// ── ContributionAndProof ──────────────────────────────────────────────────────

/// `ContributionAndProof` per `specs/altair/validator.md:117-120`.
///
/// Generic over `SYNC_SUBCOMMITTEE_SIZE`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ContributionAndProof<const SYNC_SUBCOMMITTEE_SIZE: u64> {
    /// `aggregator_index: ValidatorIndex` — `specs/altair/validator.md:118`.
    pub aggregator_index: ValidatorIndex,
    /// `contribution: SyncCommitteeContribution` — `specs/altair/validator.md:119`.
    pub contribution: SyncCommitteeContribution<SYNC_SUBCOMMITTEE_SIZE>,
    /// `selection_proof: BLSSignature` — `specs/altair/validator.md:120`.
    pub selection_proof: BLSSignature,
}

// ── SignedContributionAndProof ─────────────────────────────────────────────────

/// `SignedContributionAndProof` per `specs/altair/validator.md:126-129`.
///
/// Generic over `SYNC_SUBCOMMITTEE_SIZE`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedContributionAndProof<const SYNC_SUBCOMMITTEE_SIZE: u64> {
    /// `message: ContributionAndProof` — `specs/altair/validator.md:127`.
    pub message: ContributionAndProof<SYNC_SUBCOMMITTEE_SIZE>,
    /// `signature: BLSSignature` — `specs/altair/validator.md:128`.
    pub signature: BLSSignature,
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
    fn sync_aggregate_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetSyncAggregate::default());
    }

    #[test]
    fn sync_aggregate_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalSyncAggregate::default());
    }

    #[test]
    fn sync_committee_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetSyncCommittee::default());
    }

    #[test]
    fn sync_committee_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalSyncCommittee::default());
    }

    #[test]
    fn sync_committee_message_roundtrip() {
        roundtrip(SyncCommitteeMessage::default());
    }

    #[test]
    fn sync_committee_contribution_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetSyncCommitteeContribution::default());
    }

    #[test]
    fn sync_committee_contribution_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalSyncCommitteeContribution::default());
    }

    #[test]
    fn contribution_and_proof_mainnet_roundtrip() {
        roundtrip(ContributionAndProof::<128>::default());
    }

    #[test]
    fn contribution_and_proof_minimal_roundtrip() {
        roundtrip(ContributionAndProof::<8>::default());
    }

    #[test]
    fn signed_contribution_and_proof_mainnet_roundtrip() {
        roundtrip(SignedContributionAndProof::<128>::default());
    }

    #[test]
    fn signed_contribution_and_proof_minimal_roundtrip() {
        roundtrip(SignedContributionAndProof::<8>::default());
    }
}
