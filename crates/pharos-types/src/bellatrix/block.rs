//! Bellatrix `BeaconBlock` and `SignedBeaconBlock` containers.
//!
//! Mirrors the altair shape but uses the bellatrix `BeaconBlockBody`
//! (which adds `execution_payload`).
//! Per `specs/bellatrix/beacon-chain.md:97-112`.

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_utils::BLSSignature;

use crate::bellatrix::body::BeaconBlockBody;
use crate::phase0::primitives::{Root, Slot, ValidatorIndex};
use crate::views::{BeaconBlockView, SignedBeaconBlockView};

// ── BeaconBlock ───────────────────────────────────────────────────────────────

/// Bellatrix `BeaconBlock` — same envelope as altair but body is bellatrix.
///
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:554`.
    pub slot: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:555`.
    pub proposer_index: ValidatorIndex,
    /// `parent_root: Root` — `specs/phase0/beacon-chain.md:556`.
    pub parent_root: Root,
    /// `state_root: Root` — `specs/phase0/beacon-chain.md:557`.
    pub state_root: Root,
    /// `body: BeaconBlockBody` (bellatrix) — `specs/phase0/beacon-chain.md:558`.
    pub body: BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
}

// ── SignedBeaconBlock ─────────────────────────────────────────────────────────

/// Bellatrix `SignedBeaconBlock` — same envelope as altair but message is bellatrix.
///
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `message: BeaconBlock` (bellatrix) — `specs/phase0/beacon-chain.md:604`.
    pub message: BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >;

    fn message(&self) -> &Self::Message {
        &self.message
    }
    fn signature(&self) -> &BLSSignature {
        &self.signature
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet bellatrix `BeaconBlock`.
pub type MainnetBeaconBlock = BeaconBlock<
    16,            // MAX_PROPOSER_SLASHINGS
    2,             // MAX_ATTESTER_SLASHINGS
    128,           // MAX_ATTESTATIONS
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    512,           // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
>;

/// Minimal bellatrix `BeaconBlock`.
pub type MinimalBeaconBlock = BeaconBlock<
    16,            // MAX_PROPOSER_SLASHINGS
    2,             // MAX_ATTESTER_SLASHINGS
    128,           // MAX_ATTESTATIONS
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    32,            // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
>;

/// Mainnet bellatrix `SignedBeaconBlock`.
pub type MainnetSignedBeaconBlock = SignedBeaconBlock<
    16,            // MAX_PROPOSER_SLASHINGS
    2,             // MAX_ATTESTER_SLASHINGS
    128,           // MAX_ATTESTATIONS
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    512,           // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
>;

/// Minimal bellatrix `SignedBeaconBlock`.
pub type MinimalSignedBeaconBlock = SignedBeaconBlock<
    16,            // MAX_PROPOSER_SLASHINGS
    2,             // MAX_ATTESTER_SLASHINGS
    128,           // MAX_ATTESTATIONS
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    32,            // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
>;

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
        roundtrip(super::MainnetBeaconBlock::default());
    }

    #[test]
    fn beacon_block_minimal_roundtrip() {
        roundtrip(super::MinimalBeaconBlock::default());
    }

    #[test]
    fn signed_beacon_block_mainnet_roundtrip() {
        roundtrip(super::MainnetSignedBeaconBlock::default());
    }

    #[test]
    fn signed_beacon_block_minimal_roundtrip() {
        roundtrip(super::MinimalSignedBeaconBlock::default());
    }
}
