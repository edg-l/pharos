//! Altair `BeaconBlock` and `SignedBeaconBlock` containers.
//!
//! Mirrors the phase0 shape (`specs/phase0/beacon-chain.md:553-614`) but uses
//! the altair `BeaconBlockBody` (which adds `sync_aggregate`).
//! Per `specs/altair/beacon-chain.md:143-156`.

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_utils::BLSSignature;

use crate::altair::body::BeaconBlockBody;
use crate::phase0::primitives::{Root, Slot, ValidatorIndex};
use crate::views::{BeaconBlockView, SignedBeaconBlockView};

// ── BeaconBlock ───────────────────────────────────────────────────────────────

/// Altair `BeaconBlock` — same envelope as phase0 but body is altair.
///
/// Per `specs/phase0/beacon-chain.md:553-559` (envelope unchanged in altair).
/// Use the preset-specific type aliases `MainnetBeaconBlock` / `MinimalBeaconBlock`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlock<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:554`.
    pub slot: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:555`.
    pub proposer_index: ValidatorIndex,
    /// `parent_root: Root` — `specs/phase0/beacon-chain.md:556`.
    pub parent_root: Root,
    /// `state_root: Root` — `specs/phase0/beacon-chain.md:557`.
    pub state_root: Root,
    /// `body: BeaconBlockBody` (altair) — `specs/phase0/beacon-chain.md:558`.
    pub body: BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
}

// ── SignedBeaconBlock ─────────────────────────────────────────────────────────

/// Altair `SignedBeaconBlock` — same envelope as phase0 but message is altair.
///
/// Per `specs/phase0/beacon-chain.md:603-606` (envelope unchanged in altair).
/// Use the preset-specific type aliases `MainnetSignedBeaconBlock` /
/// `MinimalSignedBeaconBlock`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedBeaconBlock<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> {
    /// `message: BeaconBlock` (altair) — `specs/phase0/beacon-chain.md:604`.
    pub message: BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:605`.
    pub signature: BLSSignature,
}

// ── View trait impls ──────────────────────────────────────────────────────────

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> BeaconBlockView
    for BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >
{
    type Body = BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >;

    fn slot(&self) -> Slot {
        self.slot
    }
    fn proposer_index(&self) -> ValidatorIndex {
        self.proposer_index
    }
    fn parent_root(&self) -> Root {
        self.parent_root
    }
    fn state_root(&self) -> Root {
        self.state_root
    }
    fn body(&self) -> &Self::Body {
        &self.body
    }
}

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> SignedBeaconBlockView
    for SignedBeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >
{
    type Message = BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >;

    fn message(&self) -> &Self::Message {
        &self.message
    }
    fn signature(&self) -> &BLSSignature {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use pharos_ssz::{Decode, Encode};

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(val: T) {
        let encoded = val.as_ssz_bytes();
        let decoded = T::from_ssz_bytes(&encoded).expect("SSZ decode failed");
        assert_eq!(val, decoded);
    }

    #[test]
    fn beacon_block_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetBeaconBlock::default());
    }

    #[test]
    fn beacon_block_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalBeaconBlock::default());
    }

    #[test]
    fn signed_beacon_block_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetSignedBeaconBlock::default());
    }

    #[test]
    fn signed_beacon_block_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalSignedBeaconBlock::default());
    }
}
