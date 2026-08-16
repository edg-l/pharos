//! Deneb `BeaconBlock` and `SignedBeaconBlock` containers.
//!
//! Mirrors the Capella shape but uses the Deneb `BeaconBlockBody`
//! (which adds `blob_kzg_commitments` and a Deneb `ExecutionPayload`).
//! Per `specs/deneb/beacon-chain.md`.

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_utils::BLSSignature;

use crate::deneb::body::BeaconBlockBody;
use crate::phase0::primitives::{Root, Slot, ValidatorIndex};
use crate::views::{BeaconBlockView, SignedBeaconBlockView};

// ── BeaconBlock ───────────────────────────────────────────────────────────────

/// Deneb `BeaconBlock` — same envelope as Capella but body is Deneb.
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
> {
    /// `slot: Slot`.
    pub slot: Slot,
    /// `proposer_index: ValidatorIndex`.
    pub proposer_index: ValidatorIndex,
    /// `parent_root: Root`.
    pub parent_root: Root,
    /// `state_root: Root`.
    pub state_root: Root,
    /// `body: BeaconBlockBody` (deneb).
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >,
}

// ── SignedBeaconBlock ─────────────────────────────────────────────────────────

/// Deneb `SignedBeaconBlock` — same envelope as Capella but message is Deneb.
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
> {
    /// `message: BeaconBlock` (deneb).
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >,
    /// `signature: BLSSignature`.
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >;

    fn message(&self) -> &Self::Message {
        &self.message
    }
    fn signature(&self) -> &BLSSignature {
        &self.signature
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet deneb `BeaconBlock`.
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
    16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet)
    16,            // MAX_BLS_TO_EXECUTION_CHANGES
    4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK
>;

/// Minimal deneb `BeaconBlock`.
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
    4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal)
    16,            // MAX_BLS_TO_EXECUTION_CHANGES
    4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK
>;

/// Mainnet deneb `SignedBeaconBlock`.
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
    16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet)
    16,            // MAX_BLS_TO_EXECUTION_CHANGES
    4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK
>;

/// Minimal deneb `SignedBeaconBlock`.
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
    4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal)
    16,            // MAX_BLS_TO_EXECUTION_CHANGES
    4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK
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
