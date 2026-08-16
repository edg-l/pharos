//! Genesis state construction.
//!
//! Per `specs/phase0/beacon-chain.md` "Genesis" section (lines 1299-1359).

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    phase0::{
        BeaconBlockHeader, Deposit, DepositData, Epoch, Eth1Data, Fork, Gwei, Slot, ValidatorIndex,
    },
    state::BeaconState as ForkBeaconState,
};
use pharos_utils::{Bytes4, Hash256};

use crate::phase0::{
    accessors::get_active_validator_indices, helpers::GENESIS_EPOCH, operations::process_deposit,
    state_write::BeaconStateWrite,
};

// Per `specs/phase0/beacon-chain.md:191`.
const GENESIS_SLOT: Slot = Slot(0);

/// Construct a genesis `BeaconState` from an Eth1 block hash, timestamp, and
/// deposit list.
///
/// Per `specs/phase0/beacon-chain.md:1300-1337`.
pub fn initialize_beacon_state_from_eth1<E: EthSpec>(
    eth1_block_hash: Hash256,
    eth1_timestamp: u64,
    deposits: &[Deposit<33>],
) -> E::BeaconState
where
    E::BeaconState: BeaconStateMut + BeaconStateWrite,
    E::Phase0BeaconBlockBody: Default + TreeHash,
{
    let fork = Fork {
        previous_version: Bytes4::from_array(E::GENESIS_FORK_VERSION),
        current_version: Bytes4::from_array(E::GENESIS_FORK_VERSION),
        epoch: Epoch(GENESIS_EPOCH),
    };

    // Compute hash_tree_root(BeaconBlockBody()) for latest_block_header.body_root.
    let empty_body_root = E::Phase0BeaconBlockBody::default().tree_hash_root();

    let genesis_time = eth1_timestamp + E::GENESIS_DELAY;
    let eth1_data = Eth1Data {
        deposit_root: Hash256::default(),
        deposit_count: deposits.len() as u64,
        block_hash: eth1_block_hash,
    };

    // Seed RANDAO with Eth1 entropy: [eth1_block_hash] * EPOCHS_PER_HISTORICAL_VECTOR.
    let mut state = E::BeaconState::genesis_state(
        genesis_time,
        fork,
        eth1_data,
        empty_body_root,
        eth1_block_hash,
    );

    // Process deposits.
    // Per `specs/phase0/beacon-chain.md:1318-1321`: before each deposit, the
    // deposit_root is updated to the root of all deposits up to and including
    // that deposit's index. Because the proof in each Deposit is constructed
    // against this incrementally-updated root, `process_deposit`'s Merkle
    // branch check passes trivially at genesis.
    let leaves: Vec<&DepositData> = deposits.iter().map(|d| &d.data).collect();
    for (i, deposit) in deposits.iter().enumerate() {
        let deposit_root = compute_deposit_data_root(&leaves[..=i]);
        state.set_eth1_deposit_root(deposit_root);
        // verify_signatures=true: BLS proofs of possession are verified even at genesis.
        process_deposit::<E>(&mut state, deposit, true)
            .expect("genesis deposit Merkle proof verified above; invariant violated");
    }

    // Process activations.
    let n = state.validators_len();
    for index in 0..n {
        let balance = state.balance_at(index);
        let eff =
            (balance - balance % E::EFFECTIVE_BALANCE_INCREMENT).min(E::MAX_EFFECTIVE_BALANCE);
        state.set_validator_effective_balance(index, Gwei(eff));
        if eff == E::MAX_EFFECTIVE_BALANCE {
            state.set_validator_activation_eligibility_epoch(index, Epoch(GENESIS_EPOCH));
            state.set_validator_activation_epoch(index, Epoch(GENESIS_EPOCH));
        }
    }

    // genesis_validators_root = hash_tree_root(state.validators).
    let gvr = state.validators_tree_hash();
    state.set_genesis_validators_root(gvr);

    state
}

/// Return `true` iff `state` meets the genesis trigger conditions.
///
/// Per `specs/phase0/beacon-chain.md:1349-1354`.
pub fn is_valid_genesis_state<E: EthSpec>(state: &E::BeaconState) -> bool
where
    E::BeaconState: BeaconStateMut,
{
    if state.genesis_time_val() < E::MIN_GENESIS_TIME {
        return false;
    }
    let active = get_active_validator_indices::<E>(state, Epoch(GENESIS_EPOCH));
    active.len() as u64 >= E::MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
}

/// Return the genesis `BeaconBlock` (state_root = hash_tree_root(genesis_state)).
///
/// Per `specs/phase0/beacon-chain.md:1359`.
pub fn get_genesis_block<E: EthSpec>(genesis_state_root: Hash256) -> E::BeaconBlock
where
    E::BeaconBlock: Default + BeaconBlockMut,
{
    E::BeaconBlock::with_state_root(genesis_state_root)
}

// ── Deposit Merkle root helper ────────────────────────────────────────────────

/// Compute `hash_tree_root(List[DepositData, 2^DEPOSIT_CONTRACT_TREE_DEPTH](data))`.
///
/// The Python spec builds `deposit_data_list = List[DepositData, 2**32](*leaves[:i+1])`
/// then takes its hash_tree_root. This is a mix_in_length of a merkleize_padded of
/// the deposit data hash roots, with the list length mixed in.
fn compute_deposit_data_root(data: &[&DepositData]) -> Hash256 {
    use pharos_ssz::{merkleize_padded, mix_in_length};

    // 2^DEPOSIT_CONTRACT_TREE_DEPTH = 2^32 chunks limit for DepositData (composite).
    const DEPOSIT_CONTRACT_TREE_DEPTH: u64 = 32;
    const LIST_LIMIT: u64 = 1u64 << DEPOSIT_CONTRACT_TREE_DEPTH;

    let leaves: Vec<Hash256> = data.iter().map(|d| d.tree_hash_root()).collect();
    let root = merkleize_padded(&leaves, LIST_LIMIT as usize);
    mix_in_length(root, data.len() as u64)
}

// ── Mutable state abstraction (avoids exposing concrete BeaconState fields) ───

/// Mutation interface used only by genesis.rs.
///
/// Implemented for the concrete `BeaconState` generic struct.
/// Provides genesis-specific helpers that `BeaconStateWrite` does not expose.
pub trait BeaconStateMut: pharos_types::BeaconStateView {
    fn genesis_time_val(&self) -> u64;
    fn set_eth1_deposit_root(&mut self, root: Hash256);
    fn validators_len(&self) -> usize;
    fn validator_pubkey_at(&self, idx: usize) -> pharos_utils::BLSPubkey;
    fn balance_at(&self, idx: usize) -> u64;
    fn set_balance_at(&mut self, idx: usize, val: u64);
    fn set_validator_effective_balance(&mut self, idx: usize, val: Gwei);
    fn set_validator_activation_eligibility_epoch(&mut self, idx: usize, epoch: Epoch);
    fn set_validator_activation_epoch(&mut self, idx: usize, epoch: Epoch);
    fn validators_tree_hash(&self) -> Hash256;
    fn set_genesis_validators_root(&mut self, root: Hash256);

    /// Build the genesis state with the given fields.
    fn genesis_state(
        genesis_time: u64,
        fork: Fork,
        eth1_data: Eth1Data,
        body_root: Hash256,
        eth1_block_hash: Hash256,
    ) -> Self;
}

// ── Blanket impl of BeaconStateMut for BeaconState<…> ────────────────────────

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
> BeaconStateMut
    for pharos_types::phase0::BeaconState<
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
    pharos_utils::Hash256: Default + Clone,
    pharos_types::phase0::Root: Default + Clone,
    Gwei: Default + Clone,
{
    fn genesis_time_val(&self) -> u64 {
        self.genesis_time
    }

    fn set_eth1_deposit_root(&mut self, root: Hash256) {
        self.eth1_data.deposit_root = root;
    }

    fn validators_len(&self) -> usize {
        self.validators.len()
    }

    fn validator_pubkey_at(&self, idx: usize) -> pharos_utils::BLSPubkey {
        self.validators.get(idx).unwrap().pubkey
    }

    fn balance_at(&self, idx: usize) -> u64 {
        self.balances.get(idx).unwrap().0
    }

    fn set_balance_at(&mut self, idx: usize, val: u64) {
        self.balances = self
            .balances
            .with_set(idx, Gwei(val))
            .expect("balance index in range");
    }

    fn set_validator_effective_balance(&mut self, idx: usize, val: Gwei) {
        let mut v = self.validators.get(idx).unwrap().clone();
        v.effective_balance = val;
        v.invalidate_cache();
        self.validators = self
            .validators
            .with_set(idx, v)
            .expect("validator index in range");
    }

    fn set_validator_activation_eligibility_epoch(&mut self, idx: usize, epoch: Epoch) {
        let mut v = self.validators.get(idx).unwrap().clone();
        v.activation_eligibility_epoch = epoch;
        v.invalidate_cache();
        self.validators = self
            .validators
            .with_set(idx, v)
            .expect("validator index in range");
    }

    fn set_validator_activation_epoch(&mut self, idx: usize, epoch: Epoch) {
        let mut v = self.validators.get(idx).unwrap().clone();
        v.activation_epoch = epoch;
        v.invalidate_cache();
        self.validators = self
            .validators
            .with_set(idx, v)
            .expect("validator index in range");
    }

    fn validators_tree_hash(&self) -> Hash256 {
        self.validators.tree_hash_root()
    }

    fn set_genesis_validators_root(&mut self, root: Hash256) {
        self.genesis_validators_root = root;
    }

    fn genesis_state(
        genesis_time: u64,
        fork: Fork,
        eth1_data: Eth1Data,
        body_root: Hash256,
        eth1_block_hash: Hash256,
    ) -> Self {
        let mut state = Self {
            genesis_time,
            fork,
            eth1_data,
            latest_block_header: BeaconBlockHeader {
                slot: GENESIS_SLOT,
                proposer_index: ValidatorIndex(0),
                parent_root: Hash256::default(),
                state_root: Hash256::default(),
                body_root,
            },
            ..Self::default()
        };

        // Seed randao_mixes with eth1_block_hash (all entries).
        let mut mixes = state.randao_mixes;
        for i in 0..(EPOCHS_PER_HISTORICAL_VECTOR as usize) {
            mixes = mixes.with_set(i, eth1_block_hash).expect("within bounds");
        }
        state.randao_mixes = mixes;

        state
    }
}

// ── BeaconStateMut for fork-enum BeaconState ─────────────────────────────────
//
// Task 1.12: Implements genesis construction on the fork-enum `BeaconState`.
// Genesis always starts in Phase0, so `genesis_state()` returns `Phase0(...)`.
// All other methods delegate to the inner Phase0 state; the Altair variant is
// guarded by `unreachable!()` per project conventions.

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> BeaconStateMut
    for ForkBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        2048, // MAX_VALIDATORS_PER_COMMITTEE
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
where
    pharos_utils::Hash256: Default + Clone,
    pharos_types::phase0::Root: Default + Clone,
    Gwei: Default + Clone,
{
    fn genesis_time_val(&self) -> u64 {
        match self {
            ForkBeaconState::Phase0(s) => s.genesis_time_val(),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis query called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis query called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis query called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis query called on Deneb BeaconState")
            }
        }
    }

    fn set_eth1_deposit_root(&mut self, root: Hash256) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_eth1_deposit_root(root),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis mutation called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis mutation called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis mutation called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis mutation called on Deneb BeaconState")
            }
        }
    }

    fn validators_len(&self) -> usize {
        match self {
            ForkBeaconState::Phase0(s) => s.validators_len(),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis query called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis query called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis query called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis query called on Deneb BeaconState")
            }
        }
    }

    fn validator_pubkey_at(&self, idx: usize) -> pharos_utils::BLSPubkey {
        match self {
            ForkBeaconState::Phase0(s) => s.validator_pubkey_at(idx),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis query called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis query called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis query called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis query called on Deneb BeaconState")
            }
        }
    }

    fn balance_at(&self, idx: usize) -> u64 {
        match self {
            ForkBeaconState::Phase0(s) => s.balance_at(idx),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis query called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis query called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis query called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis query called on Deneb BeaconState")
            }
        }
    }

    fn set_balance_at(&mut self, idx: usize, val: u64) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_balance_at(idx, val),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis mutation called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis mutation called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis mutation called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis mutation called on Deneb BeaconState")
            }
        }
    }

    fn set_validator_effective_balance(&mut self, idx: usize, val: Gwei) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_validator_effective_balance(idx, val),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis mutation called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis mutation called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis mutation called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis mutation called on Deneb BeaconState")
            }
        }
    }

    fn set_validator_activation_eligibility_epoch(&mut self, idx: usize, epoch: Epoch) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_validator_activation_eligibility_epoch(idx, epoch),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis mutation called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis mutation called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis mutation called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis mutation called on Deneb BeaconState")
            }
        }
    }

    fn set_validator_activation_epoch(&mut self, idx: usize, epoch: Epoch) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_validator_activation_epoch(idx, epoch),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis mutation called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis mutation called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis mutation called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis mutation called on Deneb BeaconState")
            }
        }
    }

    fn validators_tree_hash(&self) -> Hash256 {
        match self {
            ForkBeaconState::Phase0(s) => s.validators_tree_hash(),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis query called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis query called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis query called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis query called on Deneb BeaconState")
            }
        }
    }

    fn set_genesis_validators_root(&mut self, root: Hash256) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_genesis_validators_root(root),
            ForkBeaconState::Altair(_) => {
                unreachable!("genesis mutation called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("genesis mutation called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("genesis mutation called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("genesis mutation called on Deneb BeaconState")
            }
        }
    }

    /// Construct a genesis (Phase0) BeaconState.
    ///
    /// Genesis always starts in Phase0; the returned state wraps the
    /// inner `phase0::BeaconState` in `BeaconState::Phase0(...)`.
    fn genesis_state(
        genesis_time: u64,
        fork: Fork,
        eth1_data: Eth1Data,
        body_root: Hash256,
        eth1_block_hash: Hash256,
    ) -> Self {
        ForkBeaconState::Phase0(pharos_types::phase0::BeaconState::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_PENDING_ATTESTATIONS,
            JUSTIFICATION_BITS_LENGTH,
            2048,
        >::genesis_state(
            genesis_time, fork, eth1_data, body_root, eth1_block_hash
        ))
    }
}

/// Marker trait for BeaconBlock types that support genesis construction.
pub trait BeaconBlockMut {
    fn with_state_root(state_root: Hash256) -> Self;
}

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
> BeaconBlockMut
    for pharos_types::phase0::BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
    >
{
    fn with_state_root(state_root: Hash256) -> Self {
        Self {
            state_root,
            ..Self::default()
        }
    }
}
