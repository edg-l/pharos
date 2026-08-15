//! Altair `BeaconState` container.
//!
//! Per `specs/altair/beacon-chain.md:159-194` (Modified containers → BeaconState).
//!
//! Changes from phase0:
//! - `previous_epoch_attestations` / `current_epoch_attestations` replaced by
//!   `previous_epoch_participation` / `current_epoch_participation`
//!   (List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]).
//! - `inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]` added.
//! - `current_sync_committee: SyncCommittee` added.
//! - `next_sync_committee: SyncCommittee` added.

use pharos_ssz::{Bitvector, Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::Hash256;

use crate::altair::constants::ParticipationFlags;
use crate::altair::operations::SyncCommittee;
use crate::phase0::misc::{Checkpoint, Eth1Data, Fork, Validator};
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::{Gwei, Root, Slot};
use crate::views::{BeaconStateView, ForkVariant};

// ── BeaconState ───────────────────────────────────────────────────────────────

/// Altair `BeaconState` per `specs/altair/beacon-chain.md:159-194`.
///
/// Const parameters, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT` — `presets/*/phase0.yaml:42`
/// 2. `HISTORICAL_ROOTS_LIMIT` — `presets/*/phase0.yaml:53`
/// 3. `ETH1_DATA_VOTES_LIMIT` — derived: `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`
/// 4. `VALIDATOR_REGISTRY_LIMIT` — `presets/*/phase0.yaml:55`
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR` — `presets/*/phase0.yaml:49`
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR` — `presets/*/phase0.yaml:51`
/// 7. `JUSTIFICATION_BITS_LENGTH` — `specs/phase0/beacon-chain.md:195`
/// 8. `SYNC_COMMITTEE_SIZE` — `presets/*/altair.yaml:15`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct BeaconState<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> {
    /// `genesis_time: uint64` — `specs/altair/beacon-chain.md:160`.
    pub genesis_time: u64,
    /// `genesis_validators_root: Root` — `specs/altair/beacon-chain.md:161`.
    pub genesis_validators_root: Root,
    /// `slot: Slot` — `specs/altair/beacon-chain.md:162`.
    pub slot: Slot,
    /// `fork: Fork` — `specs/altair/beacon-chain.md:163`.
    pub fork: Fork,
    /// `latest_block_header: BeaconBlockHeader` — `specs/altair/beacon-chain.md:164`.
    pub latest_block_header: BeaconBlockHeader,
    /// `block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/altair/beacon-chain.md:165`.
    pub block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/altair/beacon-chain.md:166`.
    pub state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]`
    /// — `specs/altair/beacon-chain.md:167`.
    pub historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT>,
    /// `eth1_data: Eth1Data` — `specs/altair/beacon-chain.md:168`.
    pub eth1_data: Eth1Data,
    /// `eth1_data_votes: List[Eth1Data, ETH1_DATA_VOTES_LIMIT]`
    /// — `specs/altair/beacon-chain.md:169`.
    pub eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    /// `eth1_deposit_index: uint64` — `specs/altair/beacon-chain.md:170`.
    pub eth1_deposit_index: u64,
    /// `validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/altair/beacon-chain.md:171`.
    pub validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    /// `balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/altair/beacon-chain.md:172`.
    pub balances: SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    /// `randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]`
    /// — `specs/altair/beacon-chain.md:173`.
    pub randao_mixes: SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>,
    /// `slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]`
    /// — `specs/altair/beacon-chain.md:174`.
    pub slashings: SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
    /// `previous_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/altair/beacon-chain.md:176` ([Modified in Altair]).
    pub previous_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    /// `current_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/altair/beacon-chain.md:178` ([Modified in Altair]).
    pub current_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    /// `justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]`
    /// — `specs/altair/beacon-chain.md:179`.
    pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
    /// `previous_justified_checkpoint: Checkpoint` — `specs/altair/beacon-chain.md:180`.
    pub previous_justified_checkpoint: Checkpoint,
    /// `current_justified_checkpoint: Checkpoint` — `specs/altair/beacon-chain.md:181`.
    pub current_justified_checkpoint: Checkpoint,
    /// `finalized_checkpoint: Checkpoint` — `specs/altair/beacon-chain.md:182`.
    pub finalized_checkpoint: Checkpoint,
    /// `inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/altair/beacon-chain.md:184` ([New in Altair]).
    pub inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    /// `current_sync_committee: SyncCommittee`
    /// — `specs/altair/beacon-chain.md:186` ([New in Altair]).
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `next_sync_committee: SyncCommittee`
    /// — `specs/altair/beacon-chain.md:188` ([New in Altair]).
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> Default
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
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
            previous_epoch_participation: SszList::default(),
            current_epoch_participation: SszList::default(),
            justification_bits: Bitvector::default(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            inactivity_scores: SszList::default(),
            current_sync_committee: SyncCommittee::default(),
            next_sync_committee: SyncCommittee::default(),
        }
    }
}

// ── BeaconStateView impl ──────────────────────────────────────────────────────

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> BeaconStateView
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >
{
    fn fork_variant(&self) -> ForkVariant {
        ForkVariant::Altair
    }

    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }
    fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }
    fn slot(&self) -> Slot {
        self.slot
    }
    fn fork(&self) -> &Fork {
        &self.fork
    }
    fn latest_block_header(&self) -> &BeaconBlockHeader {
        &self.latest_block_header
    }
    fn validators(&self) -> &[Validator] {
        self.validators.as_slice()
    }
    fn balances(&self) -> &[Gwei] {
        self.balances.as_slice()
    }
    fn block_roots(&self) -> &[Root] {
        self.block_roots.as_slice()
    }
    fn state_roots(&self) -> &[Root] {
        self.state_roots.as_slice()
    }
    fn randao_mixes(&self) -> &[Hash256] {
        self.randao_mixes.as_slice()
    }
    fn slashings(&self) -> &[Gwei] {
        self.slashings.as_slice()
    }
    fn eth1_data(&self) -> &Eth1Data {
        &self.eth1_data
    }
    fn previous_justified_checkpoint(&self) -> &Checkpoint {
        &self.previous_justified_checkpoint
    }
    fn current_justified_checkpoint(&self) -> &Checkpoint {
        &self.current_justified_checkpoint
    }
    fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
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
    fn beacon_state_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetBeaconState::default());
    }

    #[test]
    fn beacon_state_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalBeaconState::default());
    }
}
