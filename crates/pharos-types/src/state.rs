//! Fork-enum wrappers for beacon-chain container types.
//!
//! `D-altair-state-shape` (docs/m3b-plan.md:66-78): the enum-of-forks shape.
//! Each variant carries the concrete inner type (phase0 or altair). View
//! traits are implemented via match-delegation so downstream code that is
//! generic over `<S: BeaconStateView>` continues to work unchanged.
//!
//! `pharos_types::BeaconState` is this enum; `phase0::BeaconState` and
//! `altair::BeaconState` remain accessible as the inner concrete types.

use crate::altair;
use crate::phase0;
use crate::phase0::{
    BLSSignature, BeaconBlockHeader, Checkpoint, Eth1Data, Fork, ProposerSlashing, Root,
    SignedVoluntaryExit, Slot, Validator, ValidatorIndex,
};
use crate::views::{
    BeaconBlockBodyView, BeaconBlockView, BeaconStateView, ForkVariant, SignedBeaconBlockView,
};
use pharos_ssz::{BYTES_PER_LENGTH_OFFSET, Decode, Encode, SszError, TreeHash, TreeHashType};
use pharos_utils::{Bytes32, Gwei, Hash256};

// ── BeaconState enum ─────────────────────────────────────────────────────────

/// Fork-enum `BeaconState`.
///
/// `Phase0` and `Altair` variants carry the concrete preset-stamped structs.
///
/// For ergonomic use, prefer the preset aliases defined below:
/// `MainnetBeaconState`, `MinimalBeaconState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconState<
    // Phase0 / shared params
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    // Altair-only param
    const SYNC_COMMITTEE_SIZE: u64,
> {
    /// Phase0 inner state.
    Phase0(
        phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_PENDING_ATTESTATIONS,
            JUSTIFICATION_BITS_LENGTH,
            MAX_VALIDATORS_PER_COMMITTEE,
        >,
    ),
    /// Altair inner state.
    Altair(
        altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> Default
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
    >
where
    Root: Default + Clone,
    Gwei: Default + Clone,
    Hash256: Default + Clone,
{
    fn default() -> Self {
        BeaconState::Phase0(phase0::BeaconState::default())
    }
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> BeaconStateView
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
    >
{
    fn fork_variant(&self) -> ForkVariant {
        match self {
            BeaconState::Phase0(_) => ForkVariant::Phase0,
            BeaconState::Altair(_) => ForkVariant::Altair,
        }
    }

    fn genesis_time(&self) -> u64 {
        match self {
            BeaconState::Phase0(s) => s.genesis_time(),
            BeaconState::Altair(s) => s.genesis_time(),
        }
    }
    fn genesis_validators_root(&self) -> Root {
        match self {
            BeaconState::Phase0(s) => s.genesis_validators_root(),
            BeaconState::Altair(s) => s.genesis_validators_root(),
        }
    }
    fn slot(&self) -> Slot {
        match self {
            BeaconState::Phase0(s) => s.slot(),
            BeaconState::Altair(s) => s.slot(),
        }
    }
    fn fork(&self) -> &Fork {
        match self {
            BeaconState::Phase0(s) => s.fork(),
            BeaconState::Altair(s) => s.fork(),
        }
    }
    fn latest_block_header(&self) -> &BeaconBlockHeader {
        match self {
            BeaconState::Phase0(s) => s.latest_block_header(),
            BeaconState::Altair(s) => s.latest_block_header(),
        }
    }
    fn validators(&self) -> &[Validator] {
        match self {
            BeaconState::Phase0(s) => s.validators(),
            BeaconState::Altair(s) => s.validators(),
        }
    }
    fn balances(&self) -> &[Gwei] {
        match self {
            BeaconState::Phase0(s) => s.balances(),
            BeaconState::Altair(s) => s.balances(),
        }
    }
    fn block_roots(&self) -> &[Root] {
        match self {
            BeaconState::Phase0(s) => s.block_roots(),
            BeaconState::Altair(s) => s.block_roots(),
        }
    }
    fn state_roots(&self) -> &[Root] {
        match self {
            BeaconState::Phase0(s) => s.state_roots(),
            BeaconState::Altair(s) => s.state_roots(),
        }
    }
    fn randao_mixes(&self) -> &[Hash256] {
        match self {
            BeaconState::Phase0(s) => s.randao_mixes(),
            BeaconState::Altair(s) => s.randao_mixes(),
        }
    }
    fn slashings(&self) -> &[Gwei] {
        match self {
            BeaconState::Phase0(s) => s.slashings(),
            BeaconState::Altair(s) => s.slashings(),
        }
    }
    fn eth1_data(&self) -> &Eth1Data {
        match self {
            BeaconState::Phase0(s) => s.eth1_data(),
            BeaconState::Altair(s) => s.eth1_data(),
        }
    }
    fn previous_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            BeaconState::Phase0(s) => s.previous_justified_checkpoint(),
            BeaconState::Altair(s) => s.previous_justified_checkpoint(),
        }
    }
    fn current_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            BeaconState::Phase0(s) => s.current_justified_checkpoint(),
            BeaconState::Altair(s) => s.current_justified_checkpoint(),
        }
    }
    fn finalized_checkpoint(&self) -> &Checkpoint {
        match self {
            BeaconState::Phase0(s) => s.finalized_checkpoint(),
            BeaconState::Altair(s) => s.finalized_checkpoint(),
        }
    }
}

// SSZ for the fork-enum: INTERNAL STORAGE FORMAT, NOT spec SSZ.
// `ssz_append` prepends a 1-byte fork discriminant (0x00 = Phase0, 0x01 = Altair)
// then encodes the inner variant. Used by pharos-storage to round-trip a typed
// enum value without out-of-band fork metadata. Do NOT hand these bytes to a
// spec-compliant SSZ decoder; on the wire, forks are disambiguated by
// 4-byte context bytes per `specs/altair/p2p-interface.md` (handled in the
// pharos-network codec, not here).

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> Encode
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
    >
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            BeaconState::Phase0(s) => s.ssz_bytes_len(),
            BeaconState::Altair(s) => s.ssz_bytes_len(),
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            BeaconState::Phase0(s) => {
                buf.push(0x00);
                s.ssz_append(buf);
            }
            BeaconState::Altair(s) => {
                buf.push(0x01);
                s.ssz_append(buf);
            }
        }
    }
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> Decode
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
    >
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let disc = *bytes.first().ok_or(SszError::InvalidByteLength {
            found: 0,
            expected: 1,
        })?;
        let rest = &bytes[1..];
        match disc {
            0x00 => Ok(BeaconState::Phase0(phase0::BeaconState::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                MAX_PENDING_ATTESTATIONS,
                JUSTIFICATION_BITS_LENGTH,
                MAX_VALIDATORS_PER_COMMITTEE,
            >::from_ssz_bytes(rest)?)),
            0x01 => Ok(BeaconState::Altair(altair::BeaconState::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >::from_ssz_bytes(rest)?)),
            _ => Err(SszError::Custom(format!(
                "unknown BeaconState fork discriminant: {disc:#04x}"
            ))),
        }
    }
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> TreeHash
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
    >
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconState::Phase0(s) => s.tree_hash_root(),
            BeaconState::Altair(s) => s.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("BeaconState is a container; packed encoding is not used")
    }
}

// ── Preset-specific aliases ───────────────────────────────────────────────────

/// Mainnet fork-enum `BeaconState`.
pub type MainnetBeaconState = BeaconState<
    8192,              // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    2048,              // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    65536,             // EPOCHS_PER_HISTORICAL_VECTOR
    8192,              // EPOCHS_PER_SLASHINGS_VECTOR
    4096,              // MAX_PENDING_ATTESTATIONS
    4,                 // JUSTIFICATION_BITS_LENGTH
    2048,              // MAX_VALIDATORS_PER_COMMITTEE
    512,               // SYNC_COMMITTEE_SIZE
>;

/// Minimal fork-enum `BeaconState`.
pub type MinimalBeaconState = BeaconState<
    64,                // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    32,                // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    64,                // EPOCHS_PER_HISTORICAL_VECTOR
    64,                // EPOCHS_PER_SLASHINGS_VECTOR
    1024,              // MAX_PENDING_ATTESTATIONS
    4,                 // JUSTIFICATION_BITS_LENGTH
    2048,              // MAX_VALIDATORS_PER_COMMITTEE
    32,                // SYNC_COMMITTEE_SIZE
>;

// ── BeaconBlockBody enum ──────────────────────────────────────────────────────

/// Fork-enum `BeaconBlockBody`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconBlockBody<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    // Altair-only
    const SYNC_COMMITTEE_SIZE: u64,
> {
    Phase0(
        phase0::BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
        >,
    ),
    Altair(
        altair::BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
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
> Default
    for BeaconBlockBody<
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
    fn default() -> Self {
        BeaconBlockBody::Phase0(phase0::BeaconBlockBody::default())
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
> BeaconBlockBodyView
    for BeaconBlockBody<
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
    type Attestation = phase0::Attestation<MAX_VALIDATORS_PER_COMMITTEE>;
    type AttesterSlashing = phase0::AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>;
    type Deposit = phase0::Deposit<DEPOSIT_PROOF_LENGTH>;

    fn randao_reveal(&self) -> &BLSSignature {
        match self {
            BeaconBlockBody::Phase0(b) => b.randao_reveal(),
            BeaconBlockBody::Altair(b) => b.randao_reveal(),
        }
    }
    fn eth1_data(&self) -> &Eth1Data {
        match self {
            BeaconBlockBody::Phase0(b) => b.eth1_data(),
            BeaconBlockBody::Altair(b) => b.eth1_data(),
        }
    }
    fn graffiti(&self) -> &Bytes32 {
        match self {
            BeaconBlockBody::Phase0(b) => b.graffiti(),
            BeaconBlockBody::Altair(b) => b.graffiti(),
        }
    }
    fn proposer_slashings(&self) -> &[ProposerSlashing] {
        match self {
            BeaconBlockBody::Phase0(b) => b.proposer_slashings(),
            BeaconBlockBody::Altair(b) => b.proposer_slashings(),
        }
    }
    fn attester_slashings(&self) -> &[Self::AttesterSlashing] {
        match self {
            BeaconBlockBody::Phase0(b) => b.attester_slashings(),
            BeaconBlockBody::Altair(b) => b.attester_slashings(),
        }
    }
    fn attestations(&self) -> &[Self::Attestation] {
        match self {
            BeaconBlockBody::Phase0(b) => b.attestations(),
            BeaconBlockBody::Altair(b) => b.attestations(),
        }
    }
    fn deposits(&self) -> &[Self::Deposit] {
        match self {
            BeaconBlockBody::Phase0(b) => b.deposits(),
            BeaconBlockBody::Altair(b) => b.deposits(),
        }
    }
    fn voluntary_exits(&self) -> &[SignedVoluntaryExit] {
        match self {
            BeaconBlockBody::Phase0(b) => b.voluntary_exits(),
            BeaconBlockBody::Altair(b) => b.voluntary_exits(),
        }
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
> Encode
    for BeaconBlockBody<
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
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            BeaconBlockBody::Phase0(b) => b.ssz_bytes_len(),
            BeaconBlockBody::Altair(b) => b.ssz_bytes_len(),
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            BeaconBlockBody::Phase0(b) => {
                buf.push(0x00);
                b.ssz_append(buf);
            }
            BeaconBlockBody::Altair(b) => {
                buf.push(0x01);
                b.ssz_append(buf);
            }
        }
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
> Decode
    for BeaconBlockBody<
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
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let disc = *bytes.first().ok_or(SszError::InvalidByteLength {
            found: 0,
            expected: 1,
        })?;
        let rest = &bytes[1..];
        match disc {
            0x00 => Ok(BeaconBlockBody::Phase0(phase0::BeaconBlockBody::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
            >::from_ssz_bytes(rest)?)),
            0x01 => Ok(BeaconBlockBody::Altair(altair::BeaconBlockBody::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >::from_ssz_bytes(rest)?)),
            _ => Err(SszError::Custom(format!(
                "unknown BeaconBlockBody fork discriminant: {disc:#04x}"
            ))),
        }
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
> TreeHash
    for BeaconBlockBody<
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
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconBlockBody::Phase0(b) => b.tree_hash_root(),
            BeaconBlockBody::Altair(b) => b.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("BeaconBlockBody is a container; packed encoding is not used")
    }
}

// ── BeaconBlock enum ──────────────────────────────────────────────────────────

/// Fork-enum `BeaconBlock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconBlock<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> {
    Phase0(
        phase0::BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
        >,
    ),
    Altair(
        altair::BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
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
> Default
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
    fn default() -> Self {
        BeaconBlock::Phase0(phase0::BeaconBlock::default())
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
        match self {
            BeaconBlock::Phase0(b) => b.slot(),
            BeaconBlock::Altair(b) => b.slot(),
        }
    }
    fn proposer_index(&self) -> ValidatorIndex {
        match self {
            BeaconBlock::Phase0(b) => b.proposer_index(),
            BeaconBlock::Altair(b) => b.proposer_index(),
        }
    }
    fn parent_root(&self) -> Root {
        match self {
            BeaconBlock::Phase0(b) => b.parent_root(),
            BeaconBlock::Altair(b) => b.parent_root(),
        }
    }
    fn state_root(&self) -> Root {
        match self {
            BeaconBlock::Phase0(b) => b.state_root(),
            BeaconBlock::Altair(b) => b.state_root(),
        }
    }
    fn body(&self) -> &Self::Body {
        // The inner phase0::BeaconBlock and altair::BeaconBlock each store their
        // bodies as their own concrete types, which cannot be coerced to the
        // fork-enum `BeaconBlockBody` reference without an intermediate owned
        // value (which cannot be returned by reference from a &self method).
        //
        // STF callers should match on the BeaconBlock variant and call .body()
        // on the inner concrete type. This method is provided for trait
        // completeness only.
        unimplemented!(
            "BeaconBlockView::body() on the fork-enum BeaconBlock is not supported. \
             Match on the variant and call .body() on the inner type."
        )
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
> Encode
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
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            BeaconBlock::Phase0(b) => b.ssz_bytes_len(),
            BeaconBlock::Altair(b) => b.ssz_bytes_len(),
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            BeaconBlock::Phase0(b) => {
                buf.push(0x00);
                b.ssz_append(buf);
            }
            BeaconBlock::Altair(b) => {
                buf.push(0x01);
                b.ssz_append(buf);
            }
        }
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
> Decode
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
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let disc = *bytes.first().ok_or(SszError::InvalidByteLength {
            found: 0,
            expected: 1,
        })?;
        let rest = &bytes[1..];
        match disc {
            0x00 => Ok(BeaconBlock::Phase0(phase0::BeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
            >::from_ssz_bytes(rest)?)),
            0x01 => Ok(BeaconBlock::Altair(altair::BeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >::from_ssz_bytes(rest)?)),
            _ => Err(SszError::Custom(format!(
                "unknown BeaconBlock fork discriminant: {disc:#04x}"
            ))),
        }
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
> TreeHash
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
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconBlock::Phase0(b) => b.tree_hash_root(),
            BeaconBlock::Altair(b) => b.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("BeaconBlock is a container; packed encoding is not used")
    }
}

// ── SignedBeaconBlock enum ────────────────────────────────────────────────────

/// Fork-enum `SignedBeaconBlock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedBeaconBlock<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> {
    Phase0(
        phase0::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
        >,
    ),
    Altair(
        altair::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
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
> Default
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
    fn default() -> Self {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock::default())
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
        // Same limitation as BeaconBlock::body(): cannot produce a reference to
        // the fork-enum BeaconBlock from a reference to the inner concrete type.
        // Callers should match on the variant.
        unimplemented!(
            "SignedBeaconBlockView::message() on the fork-enum SignedBeaconBlock is not \
             supported. Match on the variant and call .message() on the inner type."
        )
    }

    fn signature(&self) -> &BLSSignature {
        match self {
            SignedBeaconBlock::Phase0(b) => b.signature(),
            SignedBeaconBlock::Altair(b) => b.signature(),
        }
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
> Encode
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
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            SignedBeaconBlock::Phase0(b) => b.ssz_bytes_len(),
            SignedBeaconBlock::Altair(b) => b.ssz_bytes_len(),
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            SignedBeaconBlock::Phase0(b) => {
                buf.push(0x00);
                b.ssz_append(buf);
            }
            SignedBeaconBlock::Altair(b) => {
                buf.push(0x01);
                b.ssz_append(buf);
            }
        }
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
> Decode
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
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let disc = *bytes.first().ok_or(SszError::InvalidByteLength {
            found: 0,
            expected: 1,
        })?;
        let rest = &bytes[1..];
        match disc {
            0x00 => Ok(SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
            >::from_ssz_bytes(
                rest
            )?)),
            0x01 => Ok(SignedBeaconBlock::Altair(altair::SignedBeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >::from_ssz_bytes(
                rest
            )?)),
            _ => Err(SszError::Custom(format!(
                "unknown SignedBeaconBlock fork discriminant: {disc:#04x}"
            ))),
        }
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
> TreeHash
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
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            SignedBeaconBlock::Phase0(b) => b.tree_hash_root(),
            SignedBeaconBlock::Altair(b) => b.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("SignedBeaconBlock is a container; packed encoding is not used")
    }
}

// ── Preset-specific aliases for block types ───────────────────────────────────

/// Mainnet fork-enum `BeaconBlockBody`.
pub type MainnetBeaconBlockBody = BeaconBlockBody<16, 2, 128, 16, 16, 2048, 33, 512>;

/// Minimal fork-enum `BeaconBlockBody`.
pub type MinimalBeaconBlockBody = BeaconBlockBody<16, 2, 128, 16, 16, 2048, 33, 32>;

/// Mainnet fork-enum `BeaconBlock`.
pub type MainnetBeaconBlock = BeaconBlock<16, 2, 128, 16, 16, 2048, 33, 512>;

/// Minimal fork-enum `BeaconBlock`.
pub type MinimalBeaconBlock = BeaconBlock<16, 2, 128, 16, 16, 2048, 33, 32>;

/// Mainnet fork-enum `SignedBeaconBlock`.
pub type MainnetSignedBeaconBlock = SignedBeaconBlock<16, 2, 128, 16, 16, 2048, 33, 512>;

/// Minimal fork-enum `SignedBeaconBlock`.
pub type MinimalSignedBeaconBlock = SignedBeaconBlock<16, 2, 128, 16, 16, 2048, 33, 32>;
