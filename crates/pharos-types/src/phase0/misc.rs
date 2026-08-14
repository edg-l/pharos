//! Miscellaneous Phase 0 containers.
//!
//! Containers from `specs/phase0/beacon-chain.md` Misc dependencies section
//! (lines 363-487). Containers defined after line 447 in that section
//! (`DepositMessage`, `DepositData`, `BeaconBlockHeader`, `SigningData`) live
//! in `operations.rs`.

use pharos_ssz::{Bitlist, Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32};

use crate::phase0::primitives::{CommitteeIndex, Epoch, Gwei, Root, Slot, ValidatorIndex, Version};

// ── Fork ──────────────────────────────────────────────────────────────────────

/// `Fork` per `specs/phase0/beacon-chain.md:366-370`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Fork {
    /// `previous_version: Version` — `specs/phase0/beacon-chain.md:367`.
    pub previous_version: Version,
    /// `current_version: Version` — `specs/phase0/beacon-chain.md:368`.
    pub current_version: Version,
    /// `epoch: Epoch` — `specs/phase0/beacon-chain.md:369`.
    pub epoch: Epoch,
}

// ── ForkData ──────────────────────────────────────────────────────────────────

/// `ForkData` per `specs/phase0/beacon-chain.md:375-378`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ForkData {
    /// `current_version: Version` — `specs/phase0/beacon-chain.md:376`.
    pub current_version: Version,
    /// `genesis_validators_root: Root` — `specs/phase0/beacon-chain.md:377`.
    pub genesis_validators_root: Root,
}

// ── Checkpoint ────────────────────────────────────────────────────────────────

/// `Checkpoint` per `specs/phase0/beacon-chain.md:383-386`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Checkpoint {
    /// `epoch: Epoch` — `specs/phase0/beacon-chain.md:384`.
    pub epoch: Epoch,
    /// `root: Root` — `specs/phase0/beacon-chain.md:385`.
    pub root: Root,
}

// ── Validator ─────────────────────────────────────────────────────────────────

/// `Validator` per `specs/phase0/beacon-chain.md:391-400`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Validator {
    /// `pubkey: BLSPubkey` — `specs/phase0/beacon-chain.md:392`.
    pub pubkey: BLSPubkey,
    /// `withdrawal_credentials: Bytes32` — `specs/phase0/beacon-chain.md:393`.
    pub withdrawal_credentials: Bytes32,
    /// `effective_balance: Gwei` — `specs/phase0/beacon-chain.md:394`.
    pub effective_balance: Gwei,
    /// `slashed: boolean` — `specs/phase0/beacon-chain.md:395`.
    pub slashed: bool,
    /// `activation_eligibility_epoch: Epoch` — `specs/phase0/beacon-chain.md:396`.
    pub activation_eligibility_epoch: Epoch,
    /// `activation_epoch: Epoch` — `specs/phase0/beacon-chain.md:397`.
    pub activation_epoch: Epoch,
    /// `exit_epoch: Epoch` — `specs/phase0/beacon-chain.md:398`.
    pub exit_epoch: Epoch,
    /// `withdrawable_epoch: Epoch` — `specs/phase0/beacon-chain.md:399`.
    pub withdrawable_epoch: Epoch,
}

// ── AttestationData ───────────────────────────────────────────────────────────

/// `AttestationData` per `specs/phase0/beacon-chain.md:405-411`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AttestationData {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:406`.
    pub slot: Slot,
    /// `index: CommitteeIndex` — `specs/phase0/beacon-chain.md:407`.
    pub index: CommitteeIndex,
    /// `beacon_block_root: Root` — `specs/phase0/beacon-chain.md:408`.
    pub beacon_block_root: Root,
    /// `source: Checkpoint` — `specs/phase0/beacon-chain.md:409`.
    pub source: Checkpoint,
    /// `target: Checkpoint` — `specs/phase0/beacon-chain.md:410`.
    pub target: Checkpoint,
}

// ── Eth1Data ──────────────────────────────────────────────────────────────────

/// `Eth1Data` per `specs/phase0/beacon-chain.md:435-439`.
///
/// Note: spec field `block_hash` is `Hash32` (alias for `Bytes32`); we use
/// `pharos_utils::Hash256` which is the same type (`FixedBytes<32>`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Eth1Data {
    /// `deposit_root: Root` — `specs/phase0/beacon-chain.md:436`.
    pub deposit_root: Root,
    /// `deposit_count: uint64` — `specs/phase0/beacon-chain.md:437`.
    pub deposit_count: u64,
    /// `block_hash: Hash32` (= Bytes32) — `specs/phase0/beacon-chain.md:438`.
    pub block_hash: pharos_utils::Hash256,
}

// ── HistoricalBatch ───────────────────────────────────────────────────────────

/// `HistoricalBatch` per `specs/phase0/beacon-chain.md:444-447`.
///
/// Generic over `SLOTS_PER_HISTORICAL_ROOT` (a flat `u64` const).
///
/// For mainnet: `SLOTS_PER_HISTORICAL_ROOT = 8192`
/// (`presets/mainnet/phase0.yaml:42`).
/// For minimal: `SLOTS_PER_HISTORICAL_ROOT = 64`
/// (`presets/minimal/phase0.yaml:42`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct HistoricalBatch<const SLOTS_PER_HISTORICAL_ROOT: u64> {
    /// `block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/phase0/beacon-chain.md:445`.
    pub block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/phase0/beacon-chain.md:446`.
    pub state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
}

impl<const SLOTS_PER_HISTORICAL_ROOT: u64> Default for HistoricalBatch<SLOTS_PER_HISTORICAL_ROOT>
where
    Root: Default + Clone,
{
    fn default() -> Self {
        Self {
            block_roots: SszVector::default(),
            state_roots: SszVector::default(),
        }
    }
}

// ── IndexedAttestation ────────────────────────────────────────────────────────

/// `IndexedAttestation` per `specs/phase0/beacon-chain.md:416-420`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct IndexedAttestation<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `attesting_indices: List[ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE]`
    /// — `specs/phase0/beacon-chain.md:417`.
    pub attesting_indices: SszList<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    /// `data: AttestationData` — `specs/phase0/beacon-chain.md:418`.
    pub data: AttestationData,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:419`.
    pub signature: BLSSignature,
}

// ── PendingAttestation ────────────────────────────────────────────────────────

/// `PendingAttestation` per `specs/phase0/beacon-chain.md:425-430`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingAttestation<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]`
    /// — `specs/phase0/beacon-chain.md:426`.
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `data: AttestationData` — `specs/phase0/beacon-chain.md:427`.
    pub data: AttestationData,
    /// `inclusion_delay: Slot` — `specs/phase0/beacon-chain.md:428`.
    pub inclusion_delay: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:429`.
    pub proposer_index: ValidatorIndex,
}
