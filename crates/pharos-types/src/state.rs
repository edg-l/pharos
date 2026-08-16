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
use crate::bellatrix;
use crate::capella;
use crate::deneb;
use crate::electra;
use crate::phase0;
use crate::phase0::{
    BLSSignature, BeaconBlockHeader, Checkpoint, Eth1Data, Fork, ProposerSlashing, Root,
    SignedVoluntaryExit, Slot, Validator, ValidatorIndex,
};
use crate::views::{
    BeaconBlockBodyView, BeaconBlockView, BeaconStateView, ForkVariant, SignedBeaconBlockView,
    SyncCommitteePubkeys,
};
use pharos_ssz::{BYTES_PER_LENGTH_OFFSET, Decode, Encode, SszError, TreeHash, TreeHashType};
use pharos_utils::{Bytes32, Gwei, Hash256};

// ── BeaconState enum ─────────────────────────────────────────────────────────

/// Fork-enum `BeaconState`.
///
/// `Phase0`, `Altair`, `Bellatrix`, and `Capella` variants carry the concrete
/// preset-stamped structs.
///
/// For ergonomic use, prefer the preset aliases defined below:
/// `MainnetBeaconState`, `MinimalBeaconState`.
// Capella is larger than prior forks. Boxing variants would add heap indirection
// on every fork-enum access in the hot STF path; the size difference is acceptable.
#[allow(clippy::large_enum_variant)]
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
    // Bellatrix execution-layer params
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    // Electra pending queue params (EIP-7251)
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
    /// Bellatrix inner state.
    Bellatrix(
        bellatrix::BeaconState<
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
        >,
    ),
    /// Capella inner state.
    Capella(
        capella::BeaconState<
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
        >,
    ),
    /// Deneb inner state.
    Deneb(
        deneb::BeaconState<
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
        >,
    ),
    /// Electra inner state.
    Electra(
        electra::BeaconState<
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
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
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

// ── Inherent methods on the enum (fork-agnostic cache access) ────────────────

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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>
    BeaconState<
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
{
    /// Fork-agnostic wrapper over the inner per-fork
    /// `cached_tree_hash_root`. Lazily computes and caches the top-level
    /// Merkle root; subsequent calls return the cached value.
    ///
    /// Live-node callers (Beacon API, fork-choice, block production) should
    /// prefer this over the uncached `<Self as TreeHash>::tree_hash_root`.
    pub fn cached_tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconState::Phase0(s) => s.cached_tree_hash_root(),
            BeaconState::Altair(s) => s.cached_tree_hash_root(),
            BeaconState::Bellatrix(s) => s.cached_tree_hash_root(),
            BeaconState::Capella(s) => s.cached_tree_hash_root(),
            BeaconState::Deneb(s) => s.cached_tree_hash_root(),
            BeaconState::Electra(s) => s.cached_tree_hash_root(),
        }
    }

    /// Clear the cached top-level Merkle root.  STF entrypoints must call
    /// this after mutating any field.
    pub fn invalidate_root_cache(&mut self) {
        match self {
            BeaconState::Phase0(s) => s.invalidate_root_cache(),
            BeaconState::Altair(s) => s.invalidate_root_cache(),
            BeaconState::Bellatrix(s) => s.invalidate_root_cache(),
            BeaconState::Capella(s) => s.invalidate_root_cache(),
            BeaconState::Deneb(s) => s.invalidate_root_cache(),
            BeaconState::Electra(s) => s.invalidate_root_cache(),
        }
    }

    /// Flip the seven hot list/vector fields (`validators`, `historical_roots`,
    /// `state_roots`, `block_roots`, `randao_mixes`, `previous/current_epoch_attestations`)
    /// from `Backend::Naive` to `Backend::Tree`. Live-node entry points
    /// (checkpoint-sync apply, genesis init, storage rehydrate) must call this
    /// after SSZ-decoding a `BeaconState`; the decode path itself leaves states
    /// `Naive` per `D-no-tree-backend-on-decode`.
    pub fn into_tree_backend(self) -> Result<Self, SszError> {
        match self {
            BeaconState::Phase0(s) => Ok(BeaconState::Phase0(s.into_tree_backend()?)),
            BeaconState::Altair(s) => Ok(BeaconState::Altair(s.into_tree_backend()?)),
            BeaconState::Bellatrix(s) => Ok(BeaconState::Bellatrix(s.into_tree_backend()?)),
            BeaconState::Capella(s) => Ok(BeaconState::Capella(s.into_tree_backend()?)),
            BeaconState::Deneb(s) => Ok(BeaconState::Deneb(s.into_tree_backend()?)),
            BeaconState::Electra(s) => Ok(BeaconState::Electra(s.into_tree_backend()?)),
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
{
    fn fork_variant(&self) -> ForkVariant {
        match self {
            BeaconState::Phase0(_) => ForkVariant::Phase0,
            BeaconState::Altair(_) => ForkVariant::Altair,
            BeaconState::Bellatrix(_) => ForkVariant::Bellatrix,
            BeaconState::Capella(_) => ForkVariant::Capella,
            BeaconState::Deneb(_) => ForkVariant::Deneb,
            BeaconState::Electra(_) => ForkVariant::Electra,
        }
    }

    fn genesis_time(&self) -> u64 {
        match self {
            BeaconState::Phase0(s) => s.genesis_time(),
            BeaconState::Altair(s) => s.genesis_time(),
            BeaconState::Bellatrix(s) => s.genesis_time(),
            BeaconState::Capella(s) => s.genesis_time(),
            BeaconState::Deneb(s) => s.genesis_time(),
            BeaconState::Electra(s) => s.genesis_time(),
        }
    }
    fn genesis_validators_root(&self) -> Root {
        match self {
            BeaconState::Phase0(s) => s.genesis_validators_root(),
            BeaconState::Altair(s) => s.genesis_validators_root(),
            BeaconState::Bellatrix(s) => s.genesis_validators_root(),
            BeaconState::Capella(s) => s.genesis_validators_root(),
            BeaconState::Deneb(s) => s.genesis_validators_root(),
            BeaconState::Electra(s) => s.genesis_validators_root(),
        }
    }
    fn slot(&self) -> Slot {
        match self {
            BeaconState::Phase0(s) => s.slot(),
            BeaconState::Altair(s) => s.slot(),
            BeaconState::Bellatrix(s) => s.slot(),
            BeaconState::Capella(s) => s.slot(),
            BeaconState::Deneb(s) => s.slot(),
            BeaconState::Electra(s) => s.slot(),
        }
    }
    fn fork(&self) -> &Fork {
        match self {
            BeaconState::Phase0(s) => s.fork(),
            BeaconState::Altair(s) => s.fork(),
            BeaconState::Bellatrix(s) => s.fork(),
            BeaconState::Capella(s) => s.fork(),
            BeaconState::Deneb(s) => s.fork(),
            BeaconState::Electra(s) => s.fork(),
        }
    }
    fn latest_block_header(&self) -> &BeaconBlockHeader {
        match self {
            BeaconState::Phase0(s) => s.latest_block_header(),
            BeaconState::Altair(s) => s.latest_block_header(),
            BeaconState::Bellatrix(s) => s.latest_block_header(),
            BeaconState::Capella(s) => s.latest_block_header(),
            BeaconState::Deneb(s) => s.latest_block_header(),
            BeaconState::Electra(s) => s.latest_block_header(),
        }
    }
    fn validators(&self) -> Vec<Validator> {
        match self {
            BeaconState::Phase0(s) => s.validators(),
            BeaconState::Altair(s) => s.validators(),
            BeaconState::Bellatrix(s) => s.validators(),
            BeaconState::Capella(s) => s.validators(),
            BeaconState::Deneb(s) => s.validators(),
            BeaconState::Electra(s) => s.validators(),
        }
    }
    fn validators_iter(&self) -> Box<dyn Iterator<Item = &Validator> + '_> {
        match self {
            BeaconState::Phase0(s) => s.validators_iter(),
            BeaconState::Altair(s) => s.validators_iter(),
            BeaconState::Bellatrix(s) => s.validators_iter(),
            BeaconState::Capella(s) => s.validators_iter(),
            BeaconState::Deneb(s) => s.validators_iter(),
            BeaconState::Electra(s) => s.validators_iter(),
        }
    }
    fn validator(&self, idx: usize) -> Option<&Validator> {
        match self {
            BeaconState::Phase0(s) => s.validator(idx),
            BeaconState::Altair(s) => s.validator(idx),
            BeaconState::Bellatrix(s) => s.validator(idx),
            BeaconState::Capella(s) => s.validator(idx),
            BeaconState::Deneb(s) => s.validator(idx),
            BeaconState::Electra(s) => s.validator(idx),
        }
    }
    fn num_validators(&self) -> usize {
        match self {
            BeaconState::Phase0(s) => s.num_validators(),
            BeaconState::Altair(s) => s.num_validators(),
            BeaconState::Bellatrix(s) => s.num_validators(),
            BeaconState::Capella(s) => s.num_validators(),
            BeaconState::Deneb(s) => s.num_validators(),
            BeaconState::Electra(s) => s.num_validators(),
        }
    }
    fn balances(&self) -> &[Gwei] {
        match self {
            BeaconState::Phase0(s) => s.balances(),
            BeaconState::Altair(s) => s.balances(),
            BeaconState::Bellatrix(s) => s.balances(),
            BeaconState::Capella(s) => s.balances(),
            BeaconState::Deneb(s) => s.balances(),
            BeaconState::Electra(s) => s.balances(),
        }
    }
    fn block_roots(&self) -> Vec<Root> {
        match self {
            BeaconState::Phase0(s) => s.block_roots(),
            BeaconState::Altair(s) => s.block_roots(),
            BeaconState::Bellatrix(s) => s.block_roots(),
            BeaconState::Capella(s) => s.block_roots(),
            BeaconState::Deneb(s) => s.block_roots(),
            BeaconState::Electra(s) => s.block_roots(),
        }
    }
    fn block_root_at(&self, idx: usize) -> Option<Root> {
        match self {
            BeaconState::Phase0(s) => s.block_root_at(idx),
            BeaconState::Altair(s) => s.block_root_at(idx),
            BeaconState::Bellatrix(s) => s.block_root_at(idx),
            BeaconState::Capella(s) => s.block_root_at(idx),
            BeaconState::Deneb(s) => s.block_root_at(idx),
            BeaconState::Electra(s) => s.block_root_at(idx),
        }
    }
    fn state_roots(&self) -> Vec<Root> {
        match self {
            BeaconState::Phase0(s) => s.state_roots(),
            BeaconState::Altair(s) => s.state_roots(),
            BeaconState::Bellatrix(s) => s.state_roots(),
            BeaconState::Capella(s) => s.state_roots(),
            BeaconState::Deneb(s) => s.state_roots(),
            BeaconState::Electra(s) => s.state_roots(),
        }
    }
    fn state_root_at(&self, idx: usize) -> Option<Root> {
        match self {
            BeaconState::Phase0(s) => s.state_root_at(idx),
            BeaconState::Altair(s) => s.state_root_at(idx),
            BeaconState::Bellatrix(s) => s.state_root_at(idx),
            BeaconState::Capella(s) => s.state_root_at(idx),
            BeaconState::Deneb(s) => s.state_root_at(idx),
            BeaconState::Electra(s) => s.state_root_at(idx),
        }
    }
    fn randao_mixes(&self) -> Vec<Hash256> {
        match self {
            BeaconState::Phase0(s) => s.randao_mixes(),
            BeaconState::Altair(s) => s.randao_mixes(),
            BeaconState::Bellatrix(s) => s.randao_mixes(),
            BeaconState::Capella(s) => s.randao_mixes(),
            BeaconState::Deneb(s) => s.randao_mixes(),
            BeaconState::Electra(s) => s.randao_mixes(),
        }
    }
    fn randao_mix_at(&self, idx: usize) -> Option<Hash256> {
        match self {
            BeaconState::Phase0(s) => s.randao_mix_at(idx),
            BeaconState::Altair(s) => s.randao_mix_at(idx),
            BeaconState::Bellatrix(s) => s.randao_mix_at(idx),
            BeaconState::Capella(s) => s.randao_mix_at(idx),
            BeaconState::Deneb(s) => s.randao_mix_at(idx),
            BeaconState::Electra(s) => s.randao_mix_at(idx),
        }
    }
    fn slashings(&self) -> &[Gwei] {
        match self {
            BeaconState::Phase0(s) => s.slashings(),
            BeaconState::Altair(s) => s.slashings(),
            BeaconState::Bellatrix(s) => s.slashings(),
            BeaconState::Capella(s) => s.slashings(),
            BeaconState::Deneb(s) => s.slashings(),
            BeaconState::Electra(s) => s.slashings(),
        }
    }
    fn eth1_data(&self) -> &Eth1Data {
        match self {
            BeaconState::Phase0(s) => s.eth1_data(),
            BeaconState::Altair(s) => s.eth1_data(),
            BeaconState::Bellatrix(s) => s.eth1_data(),
            BeaconState::Capella(s) => s.eth1_data(),
            BeaconState::Deneb(s) => s.eth1_data(),
            BeaconState::Electra(s) => s.eth1_data(),
        }
    }
    fn eth1_data_votes(&self) -> Vec<Eth1Data> {
        match self {
            BeaconState::Phase0(s) => s.eth1_data_votes(),
            BeaconState::Altair(s) => s.eth1_data_votes(),
            BeaconState::Bellatrix(s) => s.eth1_data_votes(),
            BeaconState::Capella(s) => s.eth1_data_votes(),
            BeaconState::Deneb(s) => s.eth1_data_votes(),
            BeaconState::Electra(s) => s.eth1_data_votes(),
        }
    }
    fn eth1_deposit_index_u64(&self) -> u64 {
        match self {
            BeaconState::Phase0(s) => s.eth1_deposit_index_u64(),
            BeaconState::Altair(s) => s.eth1_deposit_index_u64(),
            BeaconState::Bellatrix(s) => s.eth1_deposit_index_u64(),
            BeaconState::Capella(s) => s.eth1_deposit_index_u64(),
            BeaconState::Deneb(s) => s.eth1_deposit_index_u64(),
            BeaconState::Electra(s) => s.eth1_deposit_index_u64(),
        }
    }
    fn historical_roots(&self) -> Vec<Root> {
        match self {
            BeaconState::Phase0(s) => s.historical_roots(),
            BeaconState::Altair(s) => s.historical_roots(),
            BeaconState::Bellatrix(s) => s.historical_roots(),
            BeaconState::Capella(s) => s.historical_roots(),
            BeaconState::Deneb(s) => s.historical_roots(),
            BeaconState::Electra(s) => s.historical_roots(),
        }
    }
    fn justification_bits_bytes(&self) -> Vec<u8> {
        match self {
            BeaconState::Phase0(s) => s.justification_bits_bytes(),
            BeaconState::Altair(s) => s.justification_bits_bytes(),
            BeaconState::Bellatrix(s) => s.justification_bits_bytes(),
            BeaconState::Capella(s) => s.justification_bits_bytes(),
            BeaconState::Deneb(s) => s.justification_bits_bytes(),
            BeaconState::Electra(s) => s.justification_bits_bytes(),
        }
    }
    fn previous_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            BeaconState::Phase0(s) => s.previous_justified_checkpoint(),
            BeaconState::Altair(s) => s.previous_justified_checkpoint(),
            BeaconState::Bellatrix(s) => s.previous_justified_checkpoint(),
            BeaconState::Capella(s) => s.previous_justified_checkpoint(),
            BeaconState::Deneb(s) => s.previous_justified_checkpoint(),
            BeaconState::Electra(s) => s.previous_justified_checkpoint(),
        }
    }
    fn current_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            BeaconState::Phase0(s) => s.current_justified_checkpoint(),
            BeaconState::Altair(s) => s.current_justified_checkpoint(),
            BeaconState::Bellatrix(s) => s.current_justified_checkpoint(),
            BeaconState::Capella(s) => s.current_justified_checkpoint(),
            BeaconState::Deneb(s) => s.current_justified_checkpoint(),
            BeaconState::Electra(s) => s.current_justified_checkpoint(),
        }
    }
    fn finalized_checkpoint(&self) -> &Checkpoint {
        match self {
            BeaconState::Phase0(s) => s.finalized_checkpoint(),
            BeaconState::Altair(s) => s.finalized_checkpoint(),
            BeaconState::Bellatrix(s) => s.finalized_checkpoint(),
            BeaconState::Capella(s) => s.finalized_checkpoint(),
            BeaconState::Deneb(s) => s.finalized_checkpoint(),
            BeaconState::Electra(s) => s.finalized_checkpoint(),
        }
    }
    fn invalidate_root_cache(&mut self) {
        match self {
            BeaconState::Phase0(s) => s.invalidate_root_cache(),
            BeaconState::Altair(s) => s.invalidate_root_cache(),
            BeaconState::Bellatrix(s) => s.invalidate_root_cache(),
            BeaconState::Capella(s) => s.invalidate_root_cache(),
            BeaconState::Deneb(s) => s.invalidate_root_cache(),
            BeaconState::Electra(s) => s.invalidate_root_cache(),
        }
    }
    fn into_tree_backend(self) -> Result<Self, SszError> {
        // Delegate to the inherent fork-enum method (defined above).
        BeaconState::into_tree_backend(self)
    }
    fn sync_committee_pubkeys(&self) -> Option<SyncCommitteePubkeys> {
        match self {
            BeaconState::Phase0(_) => None,
            BeaconState::Altair(s) => s.sync_committee_pubkeys(),
            BeaconState::Bellatrix(s) => s.sync_committee_pubkeys(),
            BeaconState::Capella(s) => s.sync_committee_pubkeys(),
            BeaconState::Deneb(s) => s.sync_committee_pubkeys(),
            BeaconState::Electra(s) => s.sync_committee_pubkeys(),
        }
    }
    fn previous_epoch_participation_u8s(&self) -> Vec<u8> {
        match self {
            BeaconState::Phase0(_) => vec![],
            BeaconState::Altair(s) => s.previous_epoch_participation_u8s(),
            BeaconState::Bellatrix(s) => s.previous_epoch_participation_u8s(),
            BeaconState::Capella(s) => s.previous_epoch_participation_u8s(),
            BeaconState::Deneb(s) => s.previous_epoch_participation_u8s(),
            BeaconState::Electra(s) => s.previous_epoch_participation_u8s(),
        }
    }
    fn current_epoch_participation_u8s(&self) -> Vec<u8> {
        match self {
            BeaconState::Phase0(_) => vec![],
            BeaconState::Altair(s) => s.current_epoch_participation_u8s(),
            BeaconState::Bellatrix(s) => s.current_epoch_participation_u8s(),
            BeaconState::Capella(s) => s.current_epoch_participation_u8s(),
            BeaconState::Deneb(s) => s.current_epoch_participation_u8s(),
            BeaconState::Electra(s) => s.current_epoch_participation_u8s(),
        }
    }
    fn inactivity_scores_u64s(&self) -> Vec<u64> {
        match self {
            BeaconState::Phase0(_) => vec![],
            BeaconState::Altair(s) => s.inactivity_scores_u64s(),
            BeaconState::Bellatrix(s) => s.inactivity_scores_u64s(),
            BeaconState::Capella(s) => s.inactivity_scores_u64s(),
            BeaconState::Deneb(s) => s.inactivity_scores_u64s(),
            BeaconState::Electra(s) => s.inactivity_scores_u64s(),
        }
    }
    fn sync_committee_aggregate_pubkeys(&self) -> Option<([u8; 48], [u8; 48])> {
        match self {
            BeaconState::Phase0(_) => None,
            BeaconState::Altair(s) => s.sync_committee_aggregate_pubkeys(),
            BeaconState::Bellatrix(s) => s.sync_committee_aggregate_pubkeys(),
            BeaconState::Capella(s) => s.sync_committee_aggregate_pubkeys(),
            BeaconState::Deneb(s) => s.sync_committee_aggregate_pubkeys(),
            BeaconState::Electra(s) => s.sync_committee_aggregate_pubkeys(),
        }
    }
    fn previous_epoch_attestations_raw(&self) -> Option<Vec<crate::views::PendingAttestationRaw>> {
        match self {
            BeaconState::Phase0(s) => s.previous_epoch_attestations_raw(),
            BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_)
            | BeaconState::Electra(_) => None,
        }
    }
    fn current_epoch_attestations_raw(&self) -> Option<Vec<crate::views::PendingAttestationRaw>> {
        match self {
            BeaconState::Phase0(s) => s.current_epoch_attestations_raw(),
            BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_)
            | BeaconState::Electra(_) => None,
        }
    }
    fn execution_payload_header_raw(&self) -> Option<crate::views::ExecutionPayloadHeaderRaw> {
        match self {
            BeaconState::Phase0(_) | BeaconState::Altair(_) => None,
            BeaconState::Bellatrix(s) => s.execution_payload_header_raw(),
            BeaconState::Capella(s) => s.execution_payload_header_raw(),
            BeaconState::Deneb(s) => s.execution_payload_header_raw(),
            BeaconState::Electra(s) => s.execution_payload_header_raw(),
        }
    }
    fn execution_payload_withdrawals_root(&self) -> Option<[u8; 32]> {
        match self {
            BeaconState::Capella(s) => s.execution_payload_withdrawals_root(),
            BeaconState::Deneb(s) => s.execution_payload_withdrawals_root(),
            BeaconState::Electra(s) => s.execution_payload_withdrawals_root(),
            _ => None,
        }
    }
    fn next_withdrawal_index_u64(&self) -> Option<u64> {
        match self {
            BeaconState::Capella(s) => s.next_withdrawal_index_u64(),
            BeaconState::Deneb(s) => s.next_withdrawal_index_u64(),
            BeaconState::Electra(s) => s.next_withdrawal_index_u64(),
            _ => None,
        }
    }
    fn next_withdrawal_validator_index_raw(&self) -> Option<u64> {
        match self {
            BeaconState::Capella(s) => s.next_withdrawal_validator_index_raw(),
            BeaconState::Deneb(s) => s.next_withdrawal_validator_index_raw(),
            BeaconState::Electra(s) => s.next_withdrawal_validator_index_raw(),
            _ => None,
        }
    }
    fn historical_summaries_raw(&self) -> Option<Vec<([u8; 32], [u8; 32])>> {
        match self {
            BeaconState::Capella(s) => s.historical_summaries_raw(),
            BeaconState::Deneb(s) => s.historical_summaries_raw(),
            BeaconState::Electra(s) => s.historical_summaries_raw(),
            _ => None,
        }
    }
}

// SSZ for the fork-enum: INTERNAL STORAGE FORMAT, NOT spec SSZ.
// `ssz_append` prepends a 1-byte fork discriminant (0x00 = Phase0, 0x01 = Altair,
// 0x02 = Bellatrix) then encodes the inner variant. Used by pharos-storage to
// round-trip a typed enum value without out-of-band fork metadata. Do NOT hand
// these bytes to a spec-compliant SSZ decoder; on the wire, forks are
// disambiguated by 4-byte context bytes per `specs/altair/p2p-interface.md`
// (handled in the pharos-network codec, not here).

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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
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
            BeaconState::Bellatrix(s) => s.ssz_bytes_len(),
            BeaconState::Capella(s) => s.ssz_bytes_len(),
            BeaconState::Deneb(s) => s.ssz_bytes_len(),
            BeaconState::Electra(s) => s.ssz_bytes_len(),
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
            BeaconState::Bellatrix(s) => {
                buf.push(0x02);
                s.ssz_append(buf);
            }
            BeaconState::Capella(s) => {
                buf.push(0x03);
                s.ssz_append(buf);
            }
            BeaconState::Deneb(s) => {
                buf.push(0x04);
                s.ssz_append(buf);
            }
            BeaconState::Electra(s) => {
                buf.push(0x05);
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
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
            0x02 => Ok(BeaconState::Bellatrix(bellatrix::BeaconState::<
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
            >::from_ssz_bytes(rest)?)),
            0x03 => Ok(BeaconState::Capella(capella::BeaconState::<
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
            >::from_ssz_bytes(rest)?)),
            0x04 => Ok(BeaconState::Deneb(deneb::BeaconState::<
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
            >::from_ssz_bytes(rest)?)),
            0x05 => Ok(BeaconState::Electra(electra::BeaconState::<
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
                PENDING_DEPOSITS_LIMIT,
                PENDING_PARTIAL_WITHDRAWALS_LIMIT,
                PENDING_CONSOLIDATIONS_LIMIT,
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
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconState::Phase0(s) => s.tree_hash_root(),
            BeaconState::Altair(s) => s.tree_hash_root(),
            BeaconState::Bellatrix(s) => s.tree_hash_root(),
            BeaconState::Capella(s) => s.tree_hash_root(),
            BeaconState::Deneb(s) => s.tree_hash_root(),
            BeaconState::Electra(s) => s.tree_hash_root(),
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
    256,               // BYTES_PER_LOGS_BLOOM
    32,                // MAX_EXTRA_DATA_BYTES
    134_217_728,       // PENDING_DEPOSITS_LIMIT (EIP-7251)
    134_217_728,       // PENDING_PARTIAL_WITHDRAWALS_LIMIT (EIP-7251)
    262_144,           // PENDING_CONSOLIDATIONS_LIMIT (EIP-7251)
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
    256,               // BYTES_PER_LOGS_BLOOM
    32,                // MAX_EXTRA_DATA_BYTES
    134_217_728,       // PENDING_DEPOSITS_LIMIT (EIP-7251)
    64,                // PENDING_PARTIAL_WITHDRAWALS_LIMIT (minimal)
    64,                // PENDING_CONSOLIDATIONS_LIMIT (minimal)
>;

// ── BeaconBlockBody enum ──────────────────────────────────────────────────────

/// Fork-enum `BeaconBlockBody`.
// Electra is larger than prior forks. Boxing would add heap indirection; size difference is acceptable.
#[allow(clippy::large_enum_variant)]
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
    // Bellatrix execution-layer params
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    // Capella params
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    // Deneb params
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    // Electra params
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
    Bellatrix(
        bellatrix::BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        capella::BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >,
    ),
    Deneb(
        deneb::BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
        >,
    ),
    Electra(
        electra::BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS, // = MAX_ATTESTER_SLASHINGS_ELECTRA
            MAX_ATTESTATIONS,       // = MAX_ATTESTATIONS_ELECTRA
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            MAX_AGGREGATION_BITS,
            MAX_COMMITTEES_PER_SLOT,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    type Attestation = phase0::Attestation<MAX_VALIDATORS_PER_COMMITTEE>;
    type AttesterSlashing = phase0::AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>;
    type Deposit = phase0::Deposit<DEPOSIT_PROOF_LENGTH>;

    fn randao_reveal(&self) -> &BLSSignature {
        match self {
            BeaconBlockBody::Phase0(b) => b.randao_reveal(),
            BeaconBlockBody::Altair(b) => b.randao_reveal(),
            BeaconBlockBody::Bellatrix(b) => b.randao_reveal(),
            BeaconBlockBody::Capella(b) => b.randao_reveal(),
            BeaconBlockBody::Deneb(b) => b.randao_reveal(),
            BeaconBlockBody::Electra(b) => b.randao_reveal(),
        }
    }
    fn eth1_data(&self) -> &Eth1Data {
        match self {
            BeaconBlockBody::Phase0(b) => b.eth1_data(),
            BeaconBlockBody::Altair(b) => b.eth1_data(),
            BeaconBlockBody::Bellatrix(b) => b.eth1_data(),
            BeaconBlockBody::Capella(b) => b.eth1_data(),
            BeaconBlockBody::Deneb(b) => b.eth1_data(),
            BeaconBlockBody::Electra(b) => b.eth1_data(),
        }
    }
    fn graffiti(&self) -> &Bytes32 {
        match self {
            BeaconBlockBody::Phase0(b) => b.graffiti(),
            BeaconBlockBody::Altair(b) => b.graffiti(),
            BeaconBlockBody::Bellatrix(b) => b.graffiti(),
            BeaconBlockBody::Capella(b) => b.graffiti(),
            BeaconBlockBody::Deneb(b) => b.graffiti(),
            BeaconBlockBody::Electra(b) => b.graffiti(),
        }
    }
    fn proposer_slashings(&self) -> &[ProposerSlashing] {
        match self {
            BeaconBlockBody::Phase0(b) => b.proposer_slashings(),
            BeaconBlockBody::Altair(b) => b.proposer_slashings(),
            BeaconBlockBody::Bellatrix(b) => b.proposer_slashings(),
            BeaconBlockBody::Capella(b) => b.proposer_slashings(),
            BeaconBlockBody::Deneb(b) => b.proposer_slashings(),
            BeaconBlockBody::Electra(b) => b.proposer_slashings(),
        }
    }
    fn attester_slashings(&self) -> &[Self::AttesterSlashing] {
        match self {
            BeaconBlockBody::Phase0(b) => b.attester_slashings(),
            BeaconBlockBody::Altair(b) => b.attester_slashings(),
            BeaconBlockBody::Bellatrix(b) => b.attester_slashings(),
            BeaconBlockBody::Capella(b) => b.attester_slashings(),
            BeaconBlockBody::Deneb(b) => b.attester_slashings(),
            // Electra uses a different AttesterSlashing type (EIP-7549); cast to empty slice via
            // the phase0 type (the fork-enum BeaconBlockBodyView uses phase0 types for these
            // associated types; callers that need electra slashings should match the variant).
            BeaconBlockBody::Electra(_) => &[],
        }
    }
    fn attestations(&self) -> &[Self::Attestation] {
        match self {
            BeaconBlockBody::Phase0(b) => b.attestations(),
            BeaconBlockBody::Altair(b) => b.attestations(),
            BeaconBlockBody::Bellatrix(b) => b.attestations(),
            BeaconBlockBody::Capella(b) => b.attestations(),
            BeaconBlockBody::Deneb(b) => b.attestations(),
            // Electra uses a different Attestation type (EIP-7549); cast to empty slice via
            // the phase0 type (callers that need electra attestations should match the variant).
            BeaconBlockBody::Electra(_) => &[],
        }
    }
    fn deposits(&self) -> &[Self::Deposit] {
        match self {
            BeaconBlockBody::Phase0(b) => b.deposits(),
            BeaconBlockBody::Altair(b) => b.deposits(),
            BeaconBlockBody::Bellatrix(b) => b.deposits(),
            BeaconBlockBody::Capella(b) => b.deposits(),
            BeaconBlockBody::Deneb(b) => b.deposits(),
            BeaconBlockBody::Electra(b) => b.deposits(),
        }
    }
    fn voluntary_exits(&self) -> &[SignedVoluntaryExit] {
        match self {
            BeaconBlockBody::Phase0(b) => b.voluntary_exits(),
            BeaconBlockBody::Altair(b) => b.voluntary_exits(),
            BeaconBlockBody::Bellatrix(b) => b.voluntary_exits(),
            BeaconBlockBody::Capella(b) => b.voluntary_exits(),
            BeaconBlockBody::Deneb(b) => b.voluntary_exits(),
            BeaconBlockBody::Electra(b) => b.voluntary_exits(),
        }
    }

    fn execution_block_hash(&self) -> Option<[u8; 32]> {
        match self {
            BeaconBlockBody::Phase0(b) => b.execution_block_hash(),
            BeaconBlockBody::Altair(b) => b.execution_block_hash(),
            BeaconBlockBody::Bellatrix(b) => b.execution_block_hash(),
            BeaconBlockBody::Capella(b) => b.execution_block_hash(),
            BeaconBlockBody::Deneb(b) => b.execution_block_hash(),
            BeaconBlockBody::Electra(b) => b.execution_block_hash(),
        }
    }

    fn num_blob_kzg_commitments(&self) -> usize {
        match self {
            BeaconBlockBody::Deneb(b) => b.num_blob_kzg_commitments(),
            BeaconBlockBody::Electra(b) => b.num_blob_kzg_commitments(),
            _ => 0,
        }
    }

    fn blob_kzg_commitments_slice(&self) -> &[crate::deneb::KZGCommitment] {
        match self {
            BeaconBlockBody::Deneb(b) => b.blob_kzg_commitments_slice(),
            BeaconBlockBody::Electra(b) => b.blob_kzg_commitments_slice(),
            _ => &[],
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            BeaconBlockBody::Bellatrix(b) => b.ssz_bytes_len(),
            BeaconBlockBody::Capella(b) => b.ssz_bytes_len(),
            BeaconBlockBody::Deneb(b) => b.ssz_bytes_len(),
            BeaconBlockBody::Electra(b) => b.ssz_bytes_len(),
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
            BeaconBlockBody::Bellatrix(b) => {
                buf.push(0x02);
                b.ssz_append(buf);
            }
            BeaconBlockBody::Capella(b) => {
                buf.push(0x03);
                b.ssz_append(buf);
            }
            BeaconBlockBody::Deneb(b) => {
                buf.push(0x04);
                b.ssz_append(buf);
            }
            BeaconBlockBody::Electra(b) => {
                buf.push(0x05);
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            0x02 => Ok(BeaconBlockBody::Bellatrix(bellatrix::BeaconBlockBody::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >::from_ssz_bytes(
                rest
            )?)),
            0x03 => Ok(BeaconBlockBody::Capella(capella::BeaconBlockBody::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >::from_ssz_bytes(
                rest
            )?)),
            0x04 => Ok(BeaconBlockBody::Deneb(deneb::BeaconBlockBody::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
            >::from_ssz_bytes(rest)?)),
            0x05 => Ok(BeaconBlockBody::Electra(electra::BeaconBlockBody::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
                MAX_AGGREGATION_BITS,
                MAX_COMMITTEES_PER_SLOT,
                MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
                MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
                MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
            >::from_ssz_bytes(
                rest
            )?)),
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconBlockBody::Phase0(b) => b.tree_hash_root(),
            BeaconBlockBody::Altair(b) => b.tree_hash_root(),
            BeaconBlockBody::Bellatrix(b) => b.tree_hash_root(),
            BeaconBlockBody::Capella(b) => b.tree_hash_root(),
            BeaconBlockBody::Deneb(b) => b.tree_hash_root(),
            BeaconBlockBody::Electra(b) => b.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("BeaconBlockBody is a container; packed encoding is not used")
    }
}

// ── BeaconBlock enum ──────────────────────────────────────────────────────────

/// Fork-enum `BeaconBlock`.
// Electra is larger than prior forks. Boxing would add heap indirection; size difference is acceptable.
#[allow(clippy::large_enum_variant)]
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
    Bellatrix(
        bellatrix::BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        capella::BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >,
    ),
    Deneb(
        deneb::BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
        >,
    ),
    Electra(
        electra::BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            MAX_AGGREGATION_BITS,
            MAX_COMMITTEES_PER_SLOT,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >;

    fn slot(&self) -> Slot {
        match self {
            BeaconBlock::Phase0(b) => b.slot(),
            BeaconBlock::Altair(b) => b.slot(),
            BeaconBlock::Bellatrix(b) => b.slot(),
            BeaconBlock::Capella(b) => b.slot(),
            BeaconBlock::Deneb(b) => b.slot(),
            BeaconBlock::Electra(b) => b.slot(),
        }
    }
    fn proposer_index(&self) -> ValidatorIndex {
        match self {
            BeaconBlock::Phase0(b) => b.proposer_index(),
            BeaconBlock::Altair(b) => b.proposer_index(),
            BeaconBlock::Bellatrix(b) => b.proposer_index(),
            BeaconBlock::Capella(b) => b.proposer_index(),
            BeaconBlock::Deneb(b) => b.proposer_index(),
            BeaconBlock::Electra(b) => b.proposer_index(),
        }
    }
    fn parent_root(&self) -> Root {
        match self {
            BeaconBlock::Phase0(b) => b.parent_root(),
            BeaconBlock::Altair(b) => b.parent_root(),
            BeaconBlock::Bellatrix(b) => b.parent_root(),
            BeaconBlock::Capella(b) => b.parent_root(),
            BeaconBlock::Deneb(b) => b.parent_root(),
            BeaconBlock::Electra(b) => b.parent_root(),
        }
    }
    fn state_root(&self) -> Root {
        match self {
            BeaconBlock::Phase0(b) => b.state_root(),
            BeaconBlock::Altair(b) => b.state_root(),
            BeaconBlock::Bellatrix(b) => b.state_root(),
            BeaconBlock::Capella(b) => b.state_root(),
            BeaconBlock::Deneb(b) => b.state_root(),
            BeaconBlock::Electra(b) => b.state_root(),
        }
    }
    fn body(&self) -> &Self::Body {
        // The inner concrete block types each store their bodies as their own
        // concrete types, which cannot be coerced to the fork-enum
        // `BeaconBlockBody` reference without an intermediate owned value
        // (which cannot be returned by reference from a &self method).
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            BeaconBlock::Bellatrix(b) => b.ssz_bytes_len(),
            BeaconBlock::Capella(b) => b.ssz_bytes_len(),
            BeaconBlock::Deneb(b) => b.ssz_bytes_len(),
            BeaconBlock::Electra(b) => b.ssz_bytes_len(),
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
            BeaconBlock::Bellatrix(b) => {
                buf.push(0x02);
                b.ssz_append(buf);
            }
            BeaconBlock::Capella(b) => {
                buf.push(0x03);
                b.ssz_append(buf);
            }
            BeaconBlock::Deneb(b) => {
                buf.push(0x04);
                b.ssz_append(buf);
            }
            BeaconBlock::Electra(b) => {
                buf.push(0x05);
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            0x02 => Ok(BeaconBlock::Bellatrix(bellatrix::BeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >::from_ssz_bytes(rest)?)),
            0x03 => Ok(BeaconBlock::Capella(capella::BeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >::from_ssz_bytes(rest)?)),
            0x04 => Ok(BeaconBlock::Deneb(deneb::BeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
            >::from_ssz_bytes(rest)?)),
            0x05 => Ok(BeaconBlock::Electra(electra::BeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
                MAX_AGGREGATION_BITS,
                MAX_COMMITTEES_PER_SLOT,
                MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
                MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
                MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            BeaconBlock::Phase0(b) => b.tree_hash_root(),
            BeaconBlock::Altair(b) => b.tree_hash_root(),
            BeaconBlock::Bellatrix(b) => b.tree_hash_root(),
            BeaconBlock::Capella(b) => b.tree_hash_root(),
            BeaconBlock::Deneb(b) => b.tree_hash_root(),
            BeaconBlock::Electra(b) => b.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("BeaconBlock is a container; packed encoding is not used")
    }
}

// ── SignedBeaconBlock enum ────────────────────────────────────────────────────

/// Fork-enum `SignedBeaconBlock`.
// Electra is larger than prior forks. Boxing would add heap indirection; size difference is acceptable.
#[allow(clippy::large_enum_variant)]
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
    Bellatrix(
        bellatrix::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        capella::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >,
    ),
    Deneb(
        deneb::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
        >,
    ),
    Electra(
        electra::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            MAX_AGGREGATION_BITS,
            MAX_COMMITTEES_PER_SLOT,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            SignedBeaconBlock::Bellatrix(b) => b.signature(),
            SignedBeaconBlock::Capella(b) => b.signature(),
            SignedBeaconBlock::Deneb(b) => b.signature(),
            SignedBeaconBlock::Electra(b) => b.signature(),
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            SignedBeaconBlock::Bellatrix(b) => b.ssz_bytes_len(),
            SignedBeaconBlock::Capella(b) => b.ssz_bytes_len(),
            SignedBeaconBlock::Deneb(b) => b.ssz_bytes_len(),
            SignedBeaconBlock::Electra(b) => b.ssz_bytes_len(),
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
            SignedBeaconBlock::Bellatrix(b) => {
                buf.push(0x02);
                b.ssz_append(buf);
            }
            SignedBeaconBlock::Capella(b) => {
                buf.push(0x03);
                b.ssz_append(buf);
            }
            SignedBeaconBlock::Deneb(b) => {
                buf.push(0x04);
                b.ssz_append(buf);
            }
            SignedBeaconBlock::Electra(b) => {
                buf.push(0x05);
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
            0x02 => Ok(SignedBeaconBlock::Bellatrix(
                bellatrix::SignedBeaconBlock::<
                    MAX_PROPOSER_SLASHINGS,
                    MAX_ATTESTER_SLASHINGS,
                    MAX_ATTESTATIONS,
                    MAX_DEPOSITS,
                    MAX_VOLUNTARY_EXITS,
                    MAX_VALIDATORS_PER_COMMITTEE,
                    DEPOSIT_PROOF_LENGTH,
                    SYNC_COMMITTEE_SIZE,
                    MAX_BYTES_PER_TRANSACTION,
                    MAX_TRANSACTIONS_PER_PAYLOAD,
                    BYTES_PER_LOGS_BLOOM,
                    MAX_EXTRA_DATA_BYTES,
                >::from_ssz_bytes(rest)?,
            )),
            0x03 => Ok(SignedBeaconBlock::Capella(capella::SignedBeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >::from_ssz_bytes(
                rest
            )?)),
            0x04 => Ok(SignedBeaconBlock::Deneb(deneb::SignedBeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
            >::from_ssz_bytes(
                rest
            )?)),
            0x05 => Ok(SignedBeaconBlock::Electra(electra::SignedBeaconBlock::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
                MAX_AGGREGATION_BITS,
                MAX_COMMITTEES_PER_SLOT,
                MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
                MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
                MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        match self {
            SignedBeaconBlock::Phase0(b) => b.tree_hash_root(),
            SignedBeaconBlock::Altair(b) => b.tree_hash_root(),
            SignedBeaconBlock::Bellatrix(b) => b.tree_hash_root(),
            SignedBeaconBlock::Capella(b) => b.tree_hash_root(),
            SignedBeaconBlock::Deneb(b) => b.tree_hash_root(),
            SignedBeaconBlock::Electra(b) => b.tree_hash_root(),
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("SignedBeaconBlock is a container; packed encoding is not used")
    }
}

// ── Preset-specific aliases for block types ───────────────────────────────────

/// Mainnet fork-enum `BeaconBlockBody`.
///
/// Params (20):
///   MAX_PROPOSER_SLASHINGS=16, MAX_ATTESTER_SLASHINGS=2, MAX_ATTESTATIONS=128,
///   MAX_DEPOSITS=16, MAX_VOLUNTARY_EXITS=16, MAX_VALIDATORS_PER_COMMITTEE=2048,
///   DEPOSIT_PROOF_LENGTH=33, SYNC_COMMITTEE_SIZE=512,
///   MAX_BYTES_PER_TRANSACTION=1_073_741_824, MAX_TRANSACTIONS_PER_PAYLOAD=1_048_576,
///   BYTES_PER_LOGS_BLOOM=256, MAX_EXTRA_DATA_BYTES=32, MAX_WITHDRAWALS_PER_PAYLOAD=16,
///   MAX_BLS_TO_EXECUTION_CHANGES=16, MAX_BLOB_COMMITMENTS_PER_BLOCK=4096,
///   MAX_AGGREGATION_BITS=131072, MAX_COMMITTEES_PER_SLOT=64,
///   MAX_DEPOSIT_REQUESTS_PER_PAYLOAD=8192, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD=16,
///   MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD=2
pub type MainnetBeaconBlockBody = BeaconBlockBody<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    512,
    1_073_741_824,
    1_048_576,
    256,
    32,
    16,
    16,
    4096,
    131072,
    64,
    8192,
    16,
    2,
>;

/// Minimal fork-enum `BeaconBlockBody`.
///
/// Params (20):
///   MAX_PROPOSER_SLASHINGS=16, MAX_ATTESTER_SLASHINGS=2, MAX_ATTESTATIONS=128,
///   MAX_DEPOSITS=16, MAX_VOLUNTARY_EXITS=16, MAX_VALIDATORS_PER_COMMITTEE=2048,
///   DEPOSIT_PROOF_LENGTH=33, SYNC_COMMITTEE_SIZE=32,
///   MAX_BYTES_PER_TRANSACTION=1_073_741_824, MAX_TRANSACTIONS_PER_PAYLOAD=1_048_576,
///   BYTES_PER_LOGS_BLOOM=256, MAX_EXTRA_DATA_BYTES=32, MAX_WITHDRAWALS_PER_PAYLOAD=4,
///   MAX_BLS_TO_EXECUTION_CHANGES=16, MAX_BLOB_COMMITMENTS_PER_BLOCK=4096,
///   MAX_AGGREGATION_BITS=8192, MAX_COMMITTEES_PER_SLOT=4,
///   MAX_DEPOSIT_REQUESTS_PER_PAYLOAD=8192, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD=16,
///   MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD=2
pub type MinimalBeaconBlockBody = BeaconBlockBody<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;

/// Mainnet fork-enum `BeaconBlock`.
pub type MainnetBeaconBlock = BeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    512,
    1_073_741_824,
    1_048_576,
    256,
    32,
    16,
    16,
    4096,
    131072,
    64,
    8192,
    16,
    2,
>;

/// Minimal fork-enum `BeaconBlock`.
pub type MinimalBeaconBlock = BeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;

/// Mainnet fork-enum `SignedBeaconBlock`.
pub type MainnetSignedBeaconBlock = SignedBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    512,
    1_073_741_824,
    1_048_576,
    256,
    32,
    16,
    16,
    4096,
    131072,
    64,
    8192,
    16,
    2,
>;

/// Minimal fork-enum `SignedBeaconBlock`.
pub type MinimalSignedBeaconBlock = SignedBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;
