//! Phase 0 `BeaconState` container.
//!
//! Defined in `specs/phase0/beacon-chain.md:566-588`.

use pharos_ssz::{Bitvector, Decode, Encode, SszError, SszList, SszVector, TreeHash};
use pharos_utils::{CachedRoot, Hash256};

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
#[derive(Encode, TreeHash, Clone, Debug, PartialEq, Eq)]
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
    /// Cached top-level Merkle root. Populated lazily by
    /// `cached_tree_hash_root()`; reset by `invalidate_root_cache()`.
    /// `CachedRoot` is transparent to the struct-level derives:
    /// `Clone` resets the cache (no stale-root after clone-mutate),
    /// `PartialEq`/`Eq` ignore it. `#[ssz(skip)]` excludes it from
    /// `Encode`/`Decode`/`TreeHash` derive emissions, so wire format and
    /// merkleization are unchanged.
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
            previous_epoch_attestations: SszList::empty_tree(),
            current_epoch_attestations: SszList::empty_tree(),
            justification_bits: Bitvector::default(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
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
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
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
    >
where
    Root: Default + Clone,
    Hash256: Default + Clone,
{
    /// Convert all tree-set fields from Naive to Tree backend.
    ///
    /// Called at the end of `Decode::from_ssz_bytes` so that SSZ-decoded states
    /// land on the tree backend for all seven tree-set fields.
    pub fn into_tree_backend(mut self) -> Result<Self, SszError> {
        self.block_roots = self.block_roots.into_tree()?;
        self.state_roots = self.state_roots.into_tree()?;
        self.historical_roots = self.historical_roots.into_tree()?;
        self.validators = self.validators.into_tree()?;
        self.randao_mixes = self.randao_mixes.into_tree()?;
        self.previous_epoch_attestations = self.previous_epoch_attestations.into_tree()?;
        self.current_epoch_attestations = self.current_epoch_attestations.into_tree()?;
        Ok(self)
    }

    /// Lazily compute and cache the top-level Merkle root.
    ///
    /// First call computes via `<Self as TreeHash>::tree_hash_root`; subsequent
    /// calls return the cached value without recomputing. Live-node callers
    /// (Beacon API, fork-choice, block production) should prefer this over the
    /// uncached trait method; STF entrypoints must call `invalidate_root_cache`
    /// after mutating to ensure the next call recomputes.
    pub fn cached_tree_hash_root(&self) -> Hash256 {
        self.cached_root
            .get_or_init(|| <Self as TreeHash>::tree_hash_root(self))
    }

    /// Clear the cached top-level Merkle root.
    ///
    /// STF entrypoints (`state_transition`, `process_slots`, `process_epoch`)
    /// must call this after mutating any field, before the next external
    /// caller invokes `cached_tree_hash_root`.
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
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
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
        decoder.register_type::<u64>()?; // genesis_time
        decoder.register_type::<Root>()?; // genesis_validators_root
        decoder.register_type::<Slot>()?; // slot
        decoder.register_type::<Fork>()?; // fork
        decoder.register_type::<BeaconBlockHeader>()?; // latest_block_header
        decoder.register_type::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?; // block_roots
        decoder.register_type::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?; // state_roots
        decoder
            .register_anonymous_variable_length_item::<SszList<Root, HISTORICAL_ROOTS_LIMIT>>()?; // historical_roots
        decoder.register_type::<Eth1Data>()?; // eth1_data
        decoder
            .register_anonymous_variable_length_item::<SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>>(
            )?; // eth1_data_votes
        decoder.register_type::<u64>()?; // eth1_deposit_index
        decoder.register_anonymous_variable_length_item::<SszList<Validator, VALIDATOR_REGISTRY_LIMIT>>()?; // validators
        decoder
            .register_anonymous_variable_length_item::<SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>>()?; // balances
        decoder.register_type::<SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>>()?; // randao_mixes
        decoder.register_type::<SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>>()?; // slashings
        decoder.register_anonymous_variable_length_item::<SszList<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_PENDING_ATTESTATIONS>>()?; // previous_epoch_attestations
        decoder.register_anonymous_variable_length_item::<SszList<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_PENDING_ATTESTATIONS>>()?; // current_epoch_attestations
        decoder.register_type::<Bitvector<JUSTIFICATION_BITS_LENGTH>>()?; // justification_bits
        decoder.register_type::<Checkpoint>()?; // previous_justified_checkpoint
        decoder.register_type::<Checkpoint>()?; // current_justified_checkpoint
        decoder.register_type::<Checkpoint>()?; // finalized_checkpoint
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
        let previous_epoch_attestations: SszList<
            PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
            MAX_PENDING_ATTESTATIONS,
        > =
            decoder.decode_next::<SszList<
                PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
                MAX_PENDING_ATTESTATIONS,
            >>()?;
        let current_epoch_attestations: SszList<
            PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
            MAX_PENDING_ATTESTATIONS,
        > =
            decoder.decode_next::<SszList<
                PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>,
                MAX_PENDING_ATTESTATIONS,
            >>()?;
        let justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH> =
            decoder.decode_next::<Bitvector<JUSTIFICATION_BITS_LENGTH>>()?;
        let previous_justified_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let current_justified_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let finalized_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
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
            previous_epoch_attestations,
            current_epoch_attestations,
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
            cached_root: CachedRoot::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::phase0::MinimalBeaconState;

    fn state() -> MinimalBeaconState {
        MinimalBeaconState::default()
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

    #[test]
    fn previous_epoch_attestations_field_uses_tree_backend() {
        assert!(state().previous_epoch_attestations.backend_is_tree());
    }

    #[test]
    fn current_epoch_attestations_field_uses_tree_backend() {
        assert!(state().current_epoch_attestations.backend_is_tree());
    }
}
