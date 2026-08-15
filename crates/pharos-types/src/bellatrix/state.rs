//! Bellatrix `BeaconState` container.
//!
//! Per `specs/bellatrix/beacon-chain.md:117-145` (Modified containers → BeaconState).
//!
//! Changes from altair:
//! - `latest_execution_payload_header: ExecutionPayloadHeader` added
//!   (`[New in Bellatrix]`).

use pharos_ssz::{Bitvector, Decode, Encode, SszError, SszList, SszSequence, SszVector, TreeHash};
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
#[derive(Encode, TreeHash, Clone, Debug, PartialEq, Eq)]
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
            block_roots: SszVector::from_vec_tree(vec![
                Root::default();
                SLOTS_PER_HISTORICAL_ROOT as usize
            ])
            .expect("default block_roots tree init"),
            state_roots: SszVector::from_vec_tree(vec![
                Root::default();
                SLOTS_PER_HISTORICAL_ROOT as usize
            ])
            .expect("default state_roots tree init"),
            historical_roots: SszList::empty_tree(),
            eth1_data: Eth1Data::default(),
            eth1_data_votes: SszList::default(),
            eth1_deposit_index: 0,
            validators: SszList::empty_tree(),
            balances: SszList::default(),
            randao_mixes: SszVector::from_vec_tree(vec![
                Hash256::default();
                EPOCHS_PER_HISTORICAL_VECTOR as usize
            ])
            .expect("default randao_mixes tree init"),
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
>
    BeaconState<
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
    Hash256: Default + Clone,
{
    /// Convert all tree-set fields from Naive to Tree backend.
    pub fn into_tree_backend(mut self) -> Result<Self, SszError> {
        self.block_roots = self.block_roots.into_tree()?;
        self.state_roots = self.state_roots.into_tree()?;
        self.historical_roots = self.historical_roots.into_tree()?;
        self.validators = self.validators.into_tree()?;
        self.randao_mixes = self.randao_mixes.into_tree()?;
        Ok(self)
    }
}

// ── Manual Decode impl ────────────────────────────────────────────────────────

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
> Decode
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
    Hash256: Default + Clone,
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        pharos_ssz::BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        use pharos_ssz::SszDecoder;
        let mut decoder = SszDecoder::new(bytes);
        decoder.register_type::<u64>()?;
        decoder.register_type::<Root>()?;
        decoder.register_type::<Slot>()?;
        decoder.register_type::<Fork>()?;
        decoder.register_type::<BeaconBlockHeader>()?;
        decoder.register_type::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        decoder.register_type::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<Root, HISTORICAL_ROOTS_LIMIT>>()?;
        decoder.register_type::<Eth1Data>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>>(
            )?;
        decoder.register_type::<u64>()?;
        decoder.register_anonymous_variable_length_item::<SszList<Validator, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_type::<SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>>()?;
        decoder.register_type::<SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>>()?;
        decoder.register_anonymous_variable_length_item::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_anonymous_variable_length_item::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_type::<Bitvector<JUSTIFICATION_BITS_LENGTH>>()?;
        decoder.register_type::<Checkpoint>()?;
        decoder.register_type::<Checkpoint>()?;
        decoder.register_type::<Checkpoint>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<u64, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_type::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        decoder.register_type::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        decoder.register_anonymous_variable_length_item::<ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>()?;
        let genesis_time: u64 = decoder.decode_next::<u64>()?;
        let genesis_validators_root: Root = decoder.decode_next::<Root>()?;
        let slot: Slot = decoder.decode_next::<Slot>()?;
        let fork: Fork = decoder.decode_next::<Fork>()?;
        let latest_block_header: BeaconBlockHeader = decoder.decode_next::<BeaconBlockHeader>()?;
        let block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT> =
            decoder.decode_next::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        let state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT> =
            decoder.decode_next::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        let historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT> =
            decoder.decode_next::<SszList<Root, HISTORICAL_ROOTS_LIMIT>>()?;
        let eth1_data: Eth1Data = decoder.decode_next::<Eth1Data>()?;
        let eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT> =
            decoder.decode_next::<SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>>()?;
        let eth1_deposit_index: u64 = decoder.decode_next::<u64>()?;
        let validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<Validator, VALIDATOR_REGISTRY_LIMIT>>()?;
        let balances: SszList<Gwei, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>>()?;
        let randao_mixes: SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR> =
            decoder.decode_next::<SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>>()?;
        let slashings: SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> =
            decoder.decode_next::<SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>>()?;
        let previous_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        let current_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        let justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH> =
            decoder.decode_next::<Bitvector<JUSTIFICATION_BITS_LENGTH>>()?;
        let previous_justified_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let current_justified_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let finalized_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<u64, VALIDATOR_REGISTRY_LIMIT>>()?;
        let current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE> =
            decoder.decode_next::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        let next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE> =
            decoder.decode_next::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        let latest_execution_payload_header: ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        > = decoder
            .decode_next::<ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>()?;
        decoder.finish()?;
        Ok(Self {
            genesis_time,
            genesis_validators_root,
            slot,
            fork,
            latest_block_header,
            block_roots,
            state_roots,
            historical_roots,
            eth1_data,
            eth1_data_votes,
            eth1_deposit_index,
            validators,
            balances,
            randao_mixes,
            slashings,
            previous_epoch_participation,
            current_epoch_participation,
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
            inactivity_scores,
            current_sync_committee,
            next_sync_committee,
            latest_execution_payload_header,
        })
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
    fn validators(&self) -> Vec<Validator> {
        self.validators.iter().cloned().collect()
    }
    fn validators_iter(&self) -> Box<dyn Iterator<Item = &Validator> + '_> {
        Box::new(self.validators.iter())
    }
    fn validator(&self, idx: usize) -> Option<&Validator> {
        self.validators.get(idx)
    }
    fn num_validators(&self) -> usize {
        self.validators.len()
    }
    fn balances(&self) -> &[Gwei] {
        self.balances.as_slice()
    }
    fn block_roots(&self) -> Vec<Root> {
        self.block_roots.iter().cloned().collect()
    }
    fn block_root_at(&self, idx: usize) -> Option<Root> {
        self.block_roots.get(idx).copied()
    }
    fn state_roots(&self) -> Vec<Root> {
        self.state_roots.iter().cloned().collect()
    }
    fn state_root_at(&self, idx: usize) -> Option<Root> {
        self.state_roots.get(idx).copied()
    }
    fn randao_mixes(&self) -> Vec<Hash256> {
        self.randao_mixes.iter().cloned().collect()
    }
    fn randao_mix_at(&self, idx: usize) -> Option<Hash256> {
        self.randao_mixes.get(idx).copied()
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

    fn state() -> super::MinimalBeaconState {
        super::MinimalBeaconState::default()
    }

    #[test]
    fn validators_field_uses_tree_backend() {
        assert!(state().validators.backend_is_tree());
    }

    #[test]
    fn historical_roots_field_uses_tree_backend() {
        assert!(state().historical_roots.backend_is_tree());
    }

    #[test]
    fn state_roots_field_uses_tree_backend() {
        assert!(state().state_roots.backend_is_tree());
    }

    #[test]
    fn block_roots_field_uses_tree_backend() {
        assert!(state().block_roots.backend_is_tree());
    }

    #[test]
    fn randao_mixes_field_uses_tree_backend() {
        assert!(state().randao_mixes.backend_is_tree());
    }
}
