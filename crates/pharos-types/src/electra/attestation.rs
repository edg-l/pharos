//! Electra attestation containers.
//!
//! Per `specs/electra/beacon-chain.md` and `specs/electra/validator.md`.
//!
//! ## Changes from Deneb (EIP-7549)
//! - `Attestation.aggregation_bits` is now a `Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]`.
//! - `Attestation` gains `committee_bits: Bitvector[MAX_COMMITTEES_PER_SLOT]`.
//! - `IndexedAttestation.attesting_indices` limit is `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`.
//! - `AggregateAndProof.aggregate` uses the new `electra::Attestation`.
//! - `SingleAttestation` is a new type for per-committee attestations.

use pharos_ssz::{Bitlist, Bitvector, Decode, Encode, SszList, TreeHash};
use pharos_utils::BLSSignature;

use crate::phase0::misc::AttestationData;
use crate::phase0::primitives::{CommitteeIndex, ValidatorIndex};

// ── IndexedAttestation ────────────────────────────────────────────────────────

/// Electra `IndexedAttestation` per `specs/electra/beacon-chain.md`.
///
/// `attesting_indices` limit is now `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
/// = `MAX_AGGREGATION_BITS` (pre-computed literal to satisfy B2/B3).
///
/// For mainnet: `MAX_AGGREGATION_BITS = 131072` (`2048 * 64`).
/// For minimal: `MAX_AGGREGATION_BITS = 8192` (`2048 * 4`).
///
/// Const parameters:
/// 1. `MAX_AGGREGATION_BITS` — derived: `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct IndexedAttestation<const MAX_AGGREGATION_BITS: u64> {
    /// `attesting_indices: List[ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]`
    pub attesting_indices: SszList<ValidatorIndex, MAX_AGGREGATION_BITS>,
    /// `data: AttestationData`.
    pub data: AttestationData,
    /// `signature: BLSSignature`.
    pub signature: BLSSignature,
}

// ── AttesterSlashing ──────────────────────────────────────────────────────────

/// Electra `AttesterSlashing` per `specs/electra/beacon-chain.md`.
///
/// Uses the electra `IndexedAttestation` (EIP-7549 widened `attesting_indices`).
///
/// Const parameters:
/// 1. `MAX_AGGREGATION_BITS` — derived: `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AttesterSlashing<const MAX_AGGREGATION_BITS: u64> {
    /// `attestation_1: IndexedAttestation`.
    pub attestation_1: IndexedAttestation<MAX_AGGREGATION_BITS>,
    /// `attestation_2: IndexedAttestation`.
    pub attestation_2: IndexedAttestation<MAX_AGGREGATION_BITS>,
}

// ── Attestation ───────────────────────────────────────────────────────────────

/// Electra `Attestation` per `specs/electra/beacon-chain.md` (EIP-7549).
///
/// Changes:
/// - `aggregation_bits` is now `Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]`.
/// - New `committee_bits: Bitvector[MAX_COMMITTEES_PER_SLOT]`.
///
/// Const parameters, in order:
/// 1. `MAX_AGGREGATION_BITS` — derived: `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
/// 2. `MAX_COMMITTEES_PER_SLOT` — `presets/*/phase0.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Attestation<const MAX_AGGREGATION_BITS: u64, const MAX_COMMITTEES_PER_SLOT: u64> {
    /// `aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]`.
    pub aggregation_bits: Bitlist<MAX_AGGREGATION_BITS>,
    /// `data: AttestationData`.
    pub data: AttestationData,
    /// `signature: BLSSignature`.
    pub signature: BLSSignature,
    /// `committee_bits: Bitvector[MAX_COMMITTEES_PER_SLOT]` — [New in Electra:EIP7549].
    pub committee_bits: Bitvector<MAX_COMMITTEES_PER_SLOT>,
}

// ── AggregateAndProof ─────────────────────────────────────────────────────────

/// Electra `AggregateAndProof` per `specs/electra/validator.md` (EIP-7549).
///
/// Uses the electra `Attestation`.
///
/// Const parameters, in order:
/// 1. `MAX_AGGREGATION_BITS` — derived: `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
/// 2. `MAX_COMMITTEES_PER_SLOT` — `presets/*/phase0.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AggregateAndProof<const MAX_AGGREGATION_BITS: u64, const MAX_COMMITTEES_PER_SLOT: u64> {
    /// `aggregator_index: ValidatorIndex`.
    pub aggregator_index: ValidatorIndex,
    /// `aggregate: electra::Attestation`.
    pub aggregate: Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
    /// `selection_proof: BLSSignature`.
    pub selection_proof: BLSSignature,
}

// ── SignedAggregateAndProof ───────────────────────────────────────────────────

/// Electra `SignedAggregateAndProof` per `specs/electra/validator.md` (EIP-7549).
///
/// Uses the electra `AggregateAndProof`.
///
/// Const parameters, in order:
/// 1. `MAX_AGGREGATION_BITS` — derived: `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
/// 2. `MAX_COMMITTEES_PER_SLOT` — `presets/*/phase0.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedAggregateAndProof<
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
> {
    /// `message: AggregateAndProof`.
    pub message: AggregateAndProof<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
    /// `signature: BLSSignature`.
    pub signature: BLSSignature,
}

// ── SingleAttestation ─────────────────────────────────────────────────────────

/// `SingleAttestation` per `specs/electra/beacon-chain.md`.
///
/// A new container in Electra representing a single validator's attestation
/// before aggregation. Preset-independent (no const parameters).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SingleAttestation {
    /// `committee_index: CommitteeIndex`.
    pub committee_index: CommitteeIndex,
    /// `attester_index: ValidatorIndex`.
    pub attester_index: ValidatorIndex,
    /// `data: AttestationData`.
    pub data: AttestationData,
    /// `signature: BLSSignature`.
    pub signature: BLSSignature,
}

// ── Preset aliases ────────────────────────────────────────────────────────────

/// Mainnet electra `Attestation`.
///
/// `MAX_AGGREGATION_BITS = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT = 2048 * 64 = 131072`.
/// `MAX_COMMITTEES_PER_SLOT = 64`.
pub type MainnetAttestation = Attestation<131072, 64>;

/// Minimal electra `Attestation`.
///
/// `MAX_AGGREGATION_BITS = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT = 2048 * 4 = 8192`.
/// `MAX_COMMITTEES_PER_SLOT = 4`.
pub type MinimalAttestation = Attestation<8192, 4>;

/// Mainnet electra `IndexedAttestation`.
pub type MainnetIndexedAttestation = IndexedAttestation<131072>;

/// Minimal electra `IndexedAttestation`.
pub type MinimalIndexedAttestation = IndexedAttestation<8192>;

/// Mainnet electra `AttesterSlashing`.
pub type MainnetAttesterSlashing = AttesterSlashing<131072>;

/// Minimal electra `AttesterSlashing`.
pub type MinimalAttesterSlashing = AttesterSlashing<8192>;

/// Mainnet electra `AggregateAndProof`.
pub type MainnetAggregateAndProof = AggregateAndProof<131072, 64>;

/// Minimal electra `AggregateAndProof`.
pub type MinimalAggregateAndProof = AggregateAndProof<8192, 4>;

/// Mainnet electra `SignedAggregateAndProof`.
pub type MainnetSignedAggregateAndProof = SignedAggregateAndProof<131072, 64>;

/// Minimal electra `SignedAggregateAndProof`.
pub type MinimalSignedAggregateAndProof = SignedAggregateAndProof<8192, 4>;
