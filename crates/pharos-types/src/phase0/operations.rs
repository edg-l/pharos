//! Phase 0 beacon operation containers.
//!
//! Defined in `specs/phase0/beacon-chain.md:489-532` (Beacon operations
//! section) and `specs/phase0/beacon-chain.md:590-614` (Signed envelopes).

use pharos_ssz::{Bitlist, Decode, Encode, SszVector, TreeHash};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32};

use crate::phase0::misc::{AttestationData, IndexedAttestation};
use crate::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex};

// ── DepositMessage ────────────────────────────────────────────────────────────

/// `DepositMessage` per `specs/phase0/beacon-chain.md:452-456`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct DepositMessage {
    /// `pubkey: BLSPubkey` — `specs/phase0/beacon-chain.md:453`.
    pub pubkey: BLSPubkey,
    /// `withdrawal_credentials: Bytes32` — `specs/phase0/beacon-chain.md:454`.
    pub withdrawal_credentials: Bytes32,
    /// `amount: Gwei` — `specs/phase0/beacon-chain.md:455`.
    pub amount: Gwei,
}

// ── DepositData ───────────────────────────────────────────────────────────────

/// `DepositData` per `specs/phase0/beacon-chain.md:463-468`.
///
/// Note: `signature` is over `DepositMessage` (`specs/phase0/beacon-chain.md:460`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct DepositData {
    /// `pubkey: BLSPubkey` — `specs/phase0/beacon-chain.md:464`.
    pub pubkey: BLSPubkey,
    /// `withdrawal_credentials: Bytes32` — `specs/phase0/beacon-chain.md:465`.
    pub withdrawal_credentials: Bytes32,
    /// `amount: Gwei` — `specs/phase0/beacon-chain.md:466`.
    pub amount: Gwei,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:467`.
    pub signature: BLSSignature,
}

// ── BeaconBlockHeader ─────────────────────────────────────────────────────────

/// `BeaconBlockHeader` per `specs/phase0/beacon-chain.md:473-479`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlockHeader {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:474`.
    pub slot: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:475`.
    pub proposer_index: ValidatorIndex,
    /// `parent_root: Root` — `specs/phase0/beacon-chain.md:476`.
    pub parent_root: Root,
    /// `state_root: Root` — `specs/phase0/beacon-chain.md:477`.
    pub state_root: Root,
    /// `body_root: Root` — `specs/phase0/beacon-chain.md:478`.
    pub body_root: Root,
}

// ── SigningData ───────────────────────────────────────────────────────────────

/// `SigningData` per `specs/phase0/beacon-chain.md:484-487`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SigningData {
    /// `object_root: Root` — `specs/phase0/beacon-chain.md:485`.
    pub object_root: Root,
    /// `domain: Domain` — `specs/phase0/beacon-chain.md:486`.
    pub domain: crate::phase0::primitives::Domain,
}

// ── SignedBeaconBlockHeader ───────────────────────────────────────────────────

/// `SignedBeaconBlockHeader` per `specs/phase0/beacon-chain.md:611-614`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedBeaconBlockHeader {
    /// `message: BeaconBlockHeader` — `specs/phase0/beacon-chain.md:612`.
    pub message: BeaconBlockHeader,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:613`.
    pub signature: BLSSignature,
}

// ── ProposerSlashing ──────────────────────────────────────────────────────────

/// `ProposerSlashing` per `specs/phase0/beacon-chain.md:494-497`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProposerSlashing {
    /// `signed_header_1: SignedBeaconBlockHeader` — `specs/phase0/beacon-chain.md:495`.
    pub signed_header_1: SignedBeaconBlockHeader,
    /// `signed_header_2: SignedBeaconBlockHeader` — `specs/phase0/beacon-chain.md:496`.
    pub signed_header_2: SignedBeaconBlockHeader,
}

// ── AttesterSlashing ──────────────────────────────────────────────────────────

/// `AttesterSlashing` per `specs/phase0/beacon-chain.md:502-505`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AttesterSlashing<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `attestation_1: IndexedAttestation` — `specs/phase0/beacon-chain.md:503`.
    pub attestation_1: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `attestation_2: IndexedAttestation` — `specs/phase0/beacon-chain.md:504`.
    pub attestation_2: IndexedAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
}

// ── Attestation ───────────────────────────────────────────────────────────────

/// `Attestation` per `specs/phase0/beacon-chain.md:510-514`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Attestation<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]`
    /// — `specs/phase0/beacon-chain.md:511`.
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `data: AttestationData` — `specs/phase0/beacon-chain.md:512`.
    pub data: AttestationData,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:513`.
    pub signature: BLSSignature,
}

// ── Deposit ───────────────────────────────────────────────────────────────────

/// `Deposit` per `specs/phase0/beacon-chain.md:521-524`.
///
/// Generic over `DEPOSIT_PROOF_LENGTH` (= `DEPOSIT_CONTRACT_TREE_DEPTH + 1` = 33).
///
/// For both presets: `DEPOSIT_PROOF_LENGTH = 33`
/// (`specs/phase0/beacon-chain.md:194`: `DEPOSIT_CONTRACT_TREE_DEPTH = 32`).
/// This is a derived constant per the plan (B3).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct Deposit<const DEPOSIT_PROOF_LENGTH: u64> {
    /// `proof: Vector[Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH + 1]`
    /// — `specs/phase0/beacon-chain.md:522`.
    /// `DEPOSIT_PROOF_LENGTH = DEPOSIT_CONTRACT_TREE_DEPTH + 1 = 33`.
    pub proof: SszVector<pharos_utils::Bytes32, DEPOSIT_PROOF_LENGTH>,
    /// `data: DepositData` — `specs/phase0/beacon-chain.md:523`.
    pub data: DepositData,
}

impl<const DEPOSIT_PROOF_LENGTH: u64> Default for Deposit<DEPOSIT_PROOF_LENGTH>
where
    pharos_utils::Bytes32: Default + Clone,
{
    fn default() -> Self {
        Self {
            proof: SszVector::default(),
            data: DepositData::default(),
        }
    }
}

// ── Eth1Block ─────────────────────────────────────────────────────────────────

/// `Eth1Block` per `specs/phase0/validator.md:118-126`.
///
/// Represents a snapshot of an Eth1 block as seen by the beacon chain.
/// Preset-independent: all fields are primitive types.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Eth1Block {
    /// `timestamp: uint64` — `specs/phase0/validator.md:122`.
    pub timestamp: u64,
    /// `deposit_root: Root` — `specs/phase0/validator.md:123`.
    pub deposit_root: Root,
    /// `deposit_count: uint64` — `specs/phase0/validator.md:124`.
    pub deposit_count: u64,
}

// ── AggregateAndProof ─────────────────────────────────────────────────────────

/// `AggregateAndProof` per `specs/phase0/validator.md:128-135`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const) because it
/// wraps `Attestation<MAX_VALIDATORS_PER_COMMITTEE>`.
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `aggregator_index: ValidatorIndex` — `specs/phase0/validator.md:132`.
    pub aggregator_index: ValidatorIndex,
    /// `aggregate: Attestation` — `specs/phase0/validator.md:133`.
    pub aggregate: Attestation<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `selection_proof: BLSSignature` — `specs/phase0/validator.md:134`.
    pub selection_proof: BLSSignature,
}

// ── SignedAggregateAndProof ───────────────────────────────────────────────────

/// `SignedAggregateAndProof` per `specs/phase0/validator.md:137-142`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const) because it
/// wraps `AggregateAndProof<MAX_VALIDATORS_PER_COMMITTEE>`.
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedAggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `message: AggregateAndProof` — `specs/phase0/validator.md:140`.
    pub message: AggregateAndProof<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `signature: BLSSignature` — `specs/phase0/validator.md:141`.
    pub signature: BLSSignature,
}

// ── VoluntaryExit ─────────────────────────────────────────────────────────────

/// `VoluntaryExit` per `specs/phase0/beacon-chain.md:529-532`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct VoluntaryExit {
    /// `epoch: Epoch` — `specs/phase0/beacon-chain.md:530`.
    pub epoch: Epoch,
    /// `validator_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:531`.
    pub validator_index: ValidatorIndex,
}

// ── SignedVoluntaryExit ───────────────────────────────────────────────────────

/// `SignedVoluntaryExit` per `specs/phase0/beacon-chain.md:595-598`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedVoluntaryExit {
    /// `message: VoluntaryExit` — `specs/phase0/beacon-chain.md:596`.
    pub message: VoluntaryExit,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:597`.
    pub signature: BLSSignature,
}
