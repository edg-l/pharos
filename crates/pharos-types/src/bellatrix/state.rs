//! Bellatrix `BeaconState` container.
//!
//! Per `specs/bellatrix/beacon-chain.md:117-145` (Modified containers → BeaconState).
//!
//! Changes from altair:
//! - `latest_execution_payload_header: ExecutionPayloadHeader` added
//!   (`[New in Bellatrix]`).

use pharos_ssz::{Bitvector, Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::Hash256;

use crate::altair::constants::ParticipationFlags;
use crate::altair::operations::SyncCommittee;
use crate::bellatrix::execution_payload::ExecutionPayloadHeader;
use crate::phase0::misc::{Checkpoint, Eth1Data, Fork, Validator};
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::{Gwei, Root, Slot};
use crate::views::{BeaconStateView, ForkVariant};

// ── BeaconState ───────────────────────────────────────────────────────────────

/// Bellatrix `BeaconState` per `specs/bellatrix/beacon-chain.md:117-145`.
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
/// 9. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 10. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `genesis_time: uint64` — `specs/bellatrix/beacon-chain.md:118`.
    pub genesis_time: u64,
    /// `genesis_validators_root: Root` — `specs/bellatrix/beacon-chain.md:119`.
    pub genesis_validators_root: Root,
    /// `slot: Slot` — `specs/bellatrix/beacon-chain.md:120`.
    pub slot: Slot,
    /// `fork: Fork` — `specs/bellatrix/beacon-chain.md:121`.
    pub fork: Fork,
    /// `latest_block_header: BeaconBlockHeader` — `specs/bellatrix/beacon-chain.md:122`.
    pub latest_block_header: BeaconBlockHeader,
    /// `block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/bellatrix/beacon-chain.md:123`.
    pub block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/bellatrix/beacon-chain.md:124`.
    pub state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:125`.
    pub historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT>,
    /// `eth1_data: Eth1Data` — `specs/bellatrix/beacon-chain.md:126`.
    pub eth1_data: Eth1Data,
    /// `eth1_data_votes: List[Eth1Data, ETH1_DATA_VOTES_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:127`.
    pub eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    /// `eth1_deposit_index: uint64` — `specs/bellatrix/beacon-chain.md:128`.
    pub eth1_deposit_index: u64,
    /// `validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:129`.
    pub validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    /// `balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:130`.
    pub balances: SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    /// `randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]`
    /// — `specs/bellatrix/beacon-chain.md:131`.
    pub randao_mixes: SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>,
    /// `slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]`
    /// — `specs/bellatrix/beacon-chain.md:132`.
    pub slashings: SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
    /// `previous_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:133`.
    pub previous_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    /// `current_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:134`.
    pub current_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    /// `justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]`
    /// — `specs/bellatrix/beacon-chain.md:135`.
    pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
    /// `previous_justified_checkpoint: Checkpoint` — `specs/bellatrix/beacon-chain.md:136`.
    pub previous_justified_checkpoint: Checkpoint,
    /// `current_justified_checkpoint: Checkpoint` — `specs/bellatrix/beacon-chain.md:137`.
    pub current_justified_checkpoint: Checkpoint,
    /// `finalized_checkpoint: Checkpoint` — `specs/bellatrix/beacon-chain.md:138`.
    pub finalized_checkpoint: Checkpoint,
    /// `inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]`
    /// — `specs/bellatrix/beacon-chain.md:139`.
    pub inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    /// `current_sync_committee: SyncCommittee`
    /// — `specs/bellatrix/beacon-chain.md:140`.
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `next_sync_committee: SyncCommittee`
    /// — `specs/bellatrix/beacon-chain.md:141`.
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `latest_execution_payload_header: ExecutionPayloadHeader`
    /// — `specs/bellatrix/beacon-chain.md:143` ([New in Bellatrix]).
    pub latest_execution_payload_header:
        ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
            latest_execution_payload_header: ExecutionPayloadHeader::default(),
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn fork_variant(&self) -> ForkVariant {
        ForkVariant::Bellatrix
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

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet bellatrix `BeaconState`.
///
/// Const parameters, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT = 8192` (`presets/mainnet/phase0.yaml:42`)
/// 2. `HISTORICAL_ROOTS_LIMIT = 16_777_216` (`presets/mainnet/phase0.yaml:53`)
/// 3. `ETH1_DATA_VOTES_LIMIT = 2048` (= 64 * 32, derived)
/// 4. `VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776` (`presets/mainnet/phase0.yaml:55`)
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR = 65536` (`presets/mainnet/phase0.yaml:49`)
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR = 8192` (`presets/mainnet/phase0.yaml:51`)
/// 7. `JUSTIFICATION_BITS_LENGTH = 4` (`specs/phase0/beacon-chain.md:195`)
/// 8. `SYNC_COMMITTEE_SIZE = 512` (`presets/mainnet/altair.yaml:15`)
/// 9. `BYTES_PER_LOGS_BLOOM = 256` (`presets/mainnet/bellatrix.yaml`)
/// 10. `MAX_EXTRA_DATA_BYTES = 32` (`presets/mainnet/bellatrix.yaml`)
pub type MainnetBeaconState = BeaconState<
    8192,              // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    2048,              // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    65536,             // EPOCHS_PER_HISTORICAL_VECTOR
    8192,              // EPOCHS_PER_SLASHINGS_VECTOR
    4,                 // JUSTIFICATION_BITS_LENGTH
    512,               // SYNC_COMMITTEE_SIZE
    256,               // BYTES_PER_LOGS_BLOOM
    32,                // MAX_EXTRA_DATA_BYTES
>;

/// Minimal bellatrix `BeaconState`.
///
/// Const parameters, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT = 64` (`presets/minimal/phase0.yaml:42`)
/// 2. `HISTORICAL_ROOTS_LIMIT = 16_777_216` (`presets/minimal/phase0.yaml:53`)
/// 3. `ETH1_DATA_VOTES_LIMIT = 32` (= 4 * 8, derived)
/// 4. `VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776` (`presets/minimal/phase0.yaml:55`)
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR = 64` (`presets/minimal/phase0.yaml:49`)
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR = 64` (`presets/minimal/phase0.yaml:51`)
/// 7. `JUSTIFICATION_BITS_LENGTH = 4` (`specs/phase0/beacon-chain.md:195`)
/// 8. `SYNC_COMMITTEE_SIZE = 32` (`presets/minimal/altair.yaml:15`)
/// 9. `BYTES_PER_LOGS_BLOOM = 256` (`presets/minimal/bellatrix.yaml`)
/// 10. `MAX_EXTRA_DATA_BYTES = 32` (`presets/minimal/bellatrix.yaml`)
pub type MinimalBeaconState = BeaconState<
    64,                // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    32,                // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    64,                // EPOCHS_PER_HISTORICAL_VECTOR
    64,                // EPOCHS_PER_SLASHINGS_VECTOR
    4,                 // JUSTIFICATION_BITS_LENGTH
    32,                // SYNC_COMMITTEE_SIZE
    256,               // BYTES_PER_LOGS_BLOOM
    32,                // MAX_EXTRA_DATA_BYTES
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
    fn beacon_state_mainnet_roundtrip() {
        roundtrip(super::MainnetBeaconState::default());
    }

    #[test]
    fn beacon_state_minimal_roundtrip() {
        roundtrip(super::MinimalBeaconState::default());
    }
}
