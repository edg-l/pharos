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

use pharos_ssz::{Bitvector, Decode, Encode, SszError, SszList, SszSequence, SszVector, TreeHash};
use pharos_utils::{CachedRoot, Hash256};

use crate::altair::constants::ParticipationFlags;
use crate::altair::operations::SyncCommittee;
use crate::phase0::misc::{Checkpoint, Eth1Data, Fork, Validator};
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::{Gwei, Root, Slot};
use crate::views::{BeaconStateView, ForkVariant, SyncCommitteePubkeys};

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
    /// Cached top-level Merkle root (see `phase0::BeaconState::cached_root`).
    #[ssz(skip)]
    pub cached_root: CachedRoot,
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
            cached_root: CachedRoot::default(),
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

    /// Lazily compute and cache the top-level Merkle root (see
    /// `phase0::BeaconState::cached_tree_hash_root`).
    pub fn cached_tree_hash_root(&self) -> Hash256 {
        self.cached_root
            .get_or_init(|| <Self as TreeHash>::tree_hash_root(self))
    }

    /// Clear the cached top-level Merkle root.
    pub fn invalidate_root_cache(&mut self) {
        self.cached_root.invalidate();
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
            cached_root: CachedRoot::default(),
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
    fn invalidate_root_cache(&mut self) {
        self.cached_root.invalidate();
    }
    fn into_tree_backend(self) -> Result<Self, pharos_ssz::SszError> {
        BeaconState::into_tree_backend(self)
    }
    fn sync_committee_pubkeys(&self) -> Option<SyncCommitteePubkeys> {
        Some((
            self.current_sync_committee
                .pubkeys
                .iter()
                .map(|pk| pk.into_inner())
                .collect(),
            self.next_sync_committee
                .pubkeys
                .iter()
                .map(|pk| pk.into_inner())
                .collect(),
        ))
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

    fn state() -> crate::altair::MinimalBeaconState {
        crate::altair::MinimalBeaconState::default()
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
