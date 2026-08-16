//! Phase 0 beacon block containers.
//!
//! Defined in `specs/phase0/beacon-chain.md:534-614` (Beacon blocks and
//! signed envelopes).

use pharos_ssz::{Decode, Encode, SszList, TreeHash};
use pharos_utils::{BLSSignature, Bytes32};

use crate::phase0::misc::Eth1Data;
use crate::phase0::operations::{
    Attestation, AttesterSlashing, Deposit, ProposerSlashing, SignedVoluntaryExit,
};
use crate::phase0::primitives::{Root, Slot, ValidatorIndex};

// ── BeaconBlockBody ───────────────────────────────────────────────────────────

/// `BeaconBlockBody` per `specs/phase0/beacon-chain.md:539-548`.
///
/// Generic over the operation list limits. On stable Rust, associated consts
/// from a generic `E: BeaconSpec` type parameter cannot appear directly in
/// const-generic field-type positions; instead, each limit is an explicit
/// `const` parameter. Use the preset-specific type aliases:
/// - `MainnetBeaconBlockBody` (all mainnet limits)
/// - `MinimalBeaconBlockBody` (all minimal limits)
///
/// For mainnet constants see `presets/mainnet/phase0.yaml`.
/// For minimal constants see `presets/minimal/phase0.yaml`.
#[allow(clippy::too_many_arguments)]
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlockBody<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
> {
    /// `randao_reveal: BLSSignature` — `specs/phase0/beacon-chain.md:540`.
    pub randao_reveal: BLSSignature,
    /// `eth1_data: Eth1Data` — `specs/phase0/beacon-chain.md:541`.
    pub eth1_data: Eth1Data,
    /// `graffiti: Bytes32` — `specs/phase0/beacon-chain.md:542`.
    pub graffiti: Bytes32,
    /// `proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]`
    /// — `specs/phase0/beacon-chain.md:543`.
    pub proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    /// `attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]`
    /// — `specs/phase0/beacon-chain.md:544`.
    pub attester_slashings:
        SszList<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTER_SLASHINGS>,
    /// `attestations: List[Attestation, MAX_ATTESTATIONS]`
    /// — `specs/phase0/beacon-chain.md:545`.
    pub attestations: SszList<Attestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTATIONS>,
    /// `deposits: List[Deposit, MAX_DEPOSITS]`
    /// — `specs/phase0/beacon-chain.md:546`.
    pub deposits: SszList<Deposit<DEPOSIT_PROOF_LENGTH>, MAX_DEPOSITS>,
    /// `voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]`
    /// — `specs/phase0/beacon-chain.md:547`.
    pub voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
}

// ── BeaconBlock ───────────────────────────────────────────────────────────────

/// `BeaconBlock` per `specs/phase0/beacon-chain.md:553-559`.
///
/// Generic over the same limits as `BeaconBlockBody`. Use the preset-specific
/// type aliases `MainnetBeaconBlock` / `MinimalBeaconBlock`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlock<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
> {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:554`.
    pub slot: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:555`.
    pub proposer_index: ValidatorIndex,
    /// `parent_root: Root` — `specs/phase0/beacon-chain.md:556`.
    pub parent_root: Root,
    /// `state_root: Root` — `specs/phase0/beacon-chain.md:557`.
    pub state_root: Root,
    /// `body: BeaconBlockBody` — `specs/phase0/beacon-chain.md:558`.
    pub body: BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
    >,
}

// ── SignedBeaconBlock ─────────────────────────────────────────────────────────

/// `SignedBeaconBlock` per `specs/phase0/beacon-chain.md:603-606`.
///
/// Generic over the same limits as `BeaconBlock`. Use the preset-specific
/// type aliases `MainnetSignedBeaconBlock` / `MinimalSignedBeaconBlock`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedBeaconBlock<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
> {
    /// `message: BeaconBlock` — `specs/phase0/beacon-chain.md:604`.
    pub message: BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
    >,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:605`.
    pub signature: BLSSignature,
}
