//! Phase 0 `BeaconState` container.
//!
//! Defined in `specs/phase0/beacon-chain.md:566-588`.

use pharos_ssz::{Bitvector, Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::Hash256;

use crate::phase0::misc::{Checkpoint, Eth1Data, Fork, PendingAttestation, Validator};
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::{Gwei, Root, Slot};

// ── BeaconState ───────────────────────────────────────────────────────────────

/// `BeaconState` per `specs/phase0/beacon-chain.md:566-588`.
///
/// On stable Rust, associated consts from a generic `E: EthSpec` type
/// parameter cannot appear directly in const-generic field-type positions
/// (the `generic_const_exprs` feature is nightly-only). Instead, each
/// preset-specific limit is expressed as an explicit `const` parameter.
///
/// Use the preset-specific type aliases `MainnetBeaconState` /
/// `MinimalBeaconState` rather than this struct directly.
///
/// Const parameters, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT` — `presets/*/phase0.yaml:42`
/// 2. `HISTORICAL_ROOTS_LIMIT` — `presets/*/phase0.yaml:53`
/// 3. `ETH1_DATA_VOTES_LIMIT` — derived: `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`
/// 4. `VALIDATOR_REGISTRY_LIMIT` — `presets/*/phase0.yaml:55`
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR` — `presets/*/phase0.yaml:49`
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR` — `presets/*/phase0.yaml:51`
/// 7. `MAX_PENDING_ATTESTATIONS` — derived: `MAX_ATTESTATIONS * SLOTS_PER_EPOCH`
/// 8. `JUSTIFICATION_BITS_LENGTH` — `specs/phase0/beacon-chain.md:195`
/// 9. `MAX_VALIDATORS_PER_COMMITTEE` — `presets/*/phase0.yaml:10`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct BeaconState<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
> {
    /// `genesis_time: uint64` — `specs/phase0/beacon-chain.md:567`.
    pub genesis_time: u64,
    /// `genesis_validators_root: Root` — `specs/phase0/beacon-chain.md:568`.
    pub genesis_validators_root: Root,
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:569`.
    pub slot: Slot,
    /// `fork: Fork` — `specs/phase0/beacon-chain.md:570`.
    pub fork: Fork,
    /// `latest_block_header: BeaconBlockHeader` — `specs/phase0/beacon-chain.md:571`.
    pub latest_block_header: BeaconBlockHeader,
    /// `block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/phase0/beacon-chain.md:572`.
    pub block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/phase0/beacon-chain.md:573`.
    pub state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]`
    /// — `specs/phase0/beacon-chain.md:574`.
    pub historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT>,
    /// `eth1_data: Eth1Data` — `specs/phase0/beacon-chain.md:575`.
    pub eth1_data: Eth1Data,
    /// `eth1_data_votes: List[Eth1Data, EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH]`
    /// — `specs/phase0/beacon-chain.md:576`.
    /// Limit = `ETH1_DATA_VOTES_LIMIT` (derived const, B3 fix).
    pub eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    /// `eth1_deposit_index: uint64` — `specs/phase0/beacon-chain.md:577`.
    pub eth1_deposit_index: u64,
    /// `validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/phase0/beacon-chain.md:578`.
    pub validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    /// `balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/phase0/beacon-chain.md:579`.
    pub balances: SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    /// `randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]`
    /// — `specs/phase0/beacon-chain.md:580`.
    pub randao_mixes: SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>,
    /// `slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]`
    /// — `specs/phase0/beacon-chain.md:581`.
    pub slashings: SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
    /// `previous_epoch_attestations: List[PendingAttestation, MAX_ATTESTATIONS * SLOTS_PER_EPOCH]`
    /// — `specs/phase0/beacon-chain.md:582`.
    /// Limit = `MAX_PENDING_ATTESTATIONS` (derived const, B3 fix).
    pub previous_epoch_attestations:
        SszList<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_PENDING_ATTESTATIONS>,
    /// `current_epoch_attestations: List[PendingAttestation, MAX_ATTESTATIONS * SLOTS_PER_EPOCH]`
    /// — `specs/phase0/beacon-chain.md:583`.
    /// Limit = `MAX_PENDING_ATTESTATIONS` (derived const, B3 fix).
    pub current_epoch_attestations:
        SszList<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_PENDING_ATTESTATIONS>,
    /// `justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]`
    /// — `specs/phase0/beacon-chain.md:584`.
    pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
    /// `previous_justified_checkpoint: Checkpoint` — `specs/phase0/beacon-chain.md:585`.
    pub previous_justified_checkpoint: Checkpoint,
    /// `current_justified_checkpoint: Checkpoint` — `specs/phase0/beacon-chain.md:586`.
    pub current_justified_checkpoint: Checkpoint,
    /// `finalized_checkpoint: Checkpoint` — `specs/phase0/beacon-chain.md:587`.
    pub finalized_checkpoint: Checkpoint,
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
    >
where
    Root: Default + Clone,
    Gwei: Default + Clone,
    Hash256: Default + Clone,
{
    fn default() -> Self {
        Self {
            genesis_time: 0,
            genesis_validators_root: Root::default(),
            slot: Slot::default(),
            fork: Fork::default(),
            latest_block_header: BeaconBlockHeader::default(),
            block_roots: SszVector::default(),
            state_roots: SszVector::default(),
            historical_roots: SszList::default(),
            eth1_data: Eth1Data::default(),
            eth1_data_votes: SszList::default(),
            eth1_deposit_index: 0,
            validators: SszList::default(),
            balances: SszList::default(),
            randao_mixes: SszVector::default(),
            slashings: SszVector::default(),
            previous_epoch_attestations: SszList::default(),
            current_epoch_attestations: SszList::default(),
            justification_bits: Bitvector::default(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
        }
    }
}
