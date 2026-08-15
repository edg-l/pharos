//! Read-only beacon-state accessors.
//!
//! Per `specs/phase0/beacon-chain.md` "Beacon state accessors" (lines 985-1197)
//! and "Misc" / "Crypto" subsections (lines 905-984).
//!
//! All functions are generic over `<E: EthSpec>` and take `&E::BeaconState`.
//! State fields are accessed via the `BeaconStateView` trait. None mutate state.

use pharos_ssz::TreeHash;
use pharos_types::phase0::{
    Attestation, AttestationData, Domain, Epoch, IndexedAttestation, Root, SigningData, Slot,
    ValidatorIndex,
};
use pharos_types::{BeaconStateView, EthSpec, views::BeaconBlockBodyView};
use pharos_utils::hash::hash;
use pharos_utils::{Bytes4, Gwei, Hash256};

pub use pharos_types::fork::compute_fork_data_root;

use crate::error::StateTransitionError;
use crate::phase0::helpers::{GENESIS_EPOCH, uint_to_bytes};
use crate::phase0::predicates::is_active_validator;
use crate::phase0::shuffling::compute_shuffled_index;

// ── Slot / epoch helpers ──────────────────────────────────────────────────────

/// `compute_epoch_at_slot` per `specs/phase0/beacon-chain.md:908-912`.
pub fn compute_epoch_at_slot(slot: Slot, slots_per_epoch: u64) -> Epoch {
    slot.epoch(slots_per_epoch)
}

/// `compute_start_slot_at_epoch` per `specs/phase0/beacon-chain.md:916-920`.
pub fn compute_start_slot_at_epoch(epoch: Epoch, slots_per_epoch: u64) -> Slot {
    epoch.start_slot(slots_per_epoch)
}

/// `compute_activation_exit_epoch` per `specs/phase0/beacon-chain.md:925-930`.
pub fn compute_activation_exit_epoch(epoch: Epoch, max_seed_lookahead: u64) -> Epoch {
    Epoch(epoch.0 + 1 + max_seed_lookahead)
}

// ── State accessors ───────────────────────────────────────────────────────────

/// `get_current_epoch` per `specs/phase0/beacon-chain.md:990-994`.
pub fn get_current_epoch<E: EthSpec>(state: &E::BeaconState) -> Epoch {
    compute_epoch_at_slot(state.slot(), E::SLOTS_PER_EPOCH)
}

/// `get_previous_epoch` per `specs/phase0/beacon-chain.md:999-1005`.
pub fn get_previous_epoch<E: EthSpec>(state: &E::BeaconState) -> Epoch {
    let current = get_current_epoch::<E>(state);
    if current.0 == GENESIS_EPOCH {
        Epoch(GENESIS_EPOCH)
    } else {
        Epoch(current.0 - 1)
    }
}

/// `get_block_root_at_slot` per `specs/phase0/beacon-chain.md:1021-1026`.
pub fn get_block_root_at_slot<E: EthSpec>(
    state: &E::BeaconState,
    slot: Slot,
) -> Result<Root, StateTransitionError> {
    if !(slot < state.slot() && state.slot().0 <= slot.0 + E::SLOTS_PER_HISTORICAL_ROOT) {
        return Err(StateTransitionError::SlotOutOfRange);
    }
    let idx = (slot.0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
    state
        .block_root_at(idx)
        .ok_or(StateTransitionError::SlotOutOfRange)
}

/// `get_block_root` per `specs/phase0/beacon-chain.md:1011-1015`.
pub fn get_block_root<E: EthSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
) -> Result<Root, StateTransitionError> {
    get_block_root_at_slot::<E>(
        state,
        compute_start_slot_at_epoch(epoch, E::SLOTS_PER_EPOCH),
    )
}

/// `get_randao_mix` per `specs/phase0/beacon-chain.md:1030-1035`.
pub fn get_randao_mix<E: EthSpec>(state: &E::BeaconState, epoch: Epoch) -> Hash256 {
    let idx = (epoch.0 % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    state.randao_mix_at(idx).unwrap_or_default()
}

/// `get_active_validator_indices` per `specs/phase0/beacon-chain.md:1042-1047`.
pub fn get_active_validator_indices<E: EthSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
) -> Vec<ValidatorIndex> {
    state
        .validators_iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if is_active_validator(v, epoch.0) {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect()
}

/// `get_validator_churn_limit` per `specs/phase0/beacon-chain.md:1054-1061`.
pub fn get_validator_churn_limit<E: EthSpec>(state: &E::BeaconState) -> u64 {
    let active = get_active_validator_indices::<E>(state, get_current_epoch::<E>(state));
    (active.len() as u64 / E::CHURN_LIMIT_QUOTIENT).max(E::MIN_PER_EPOCH_CHURN_LIMIT)
}

/// `get_seed` per `specs/phase0/beacon-chain.md:1067-1074`.
pub fn get_seed<E: EthSpec>(state: &E::BeaconState, epoch: Epoch, domain_type: Bytes4) -> Hash256 {
    // Modular arithmetic to avoid underflow (spec: epoch + EPOCHS_PER_HISTORICAL_VECTOR
    // - MIN_SEED_LOOKAHEAD - 1).
    let mix_epoch_raw = epoch
        .0
        .wrapping_add(E::EPOCHS_PER_HISTORICAL_VECTOR)
        .wrapping_sub(E::MIN_SEED_LOOKAHEAD)
        .wrapping_sub(1);
    let mix = get_randao_mix::<E>(state, Epoch(mix_epoch_raw));
    let epoch_bytes = uint_to_bytes(epoch.0);
    let mut input = [0u8; 4 + 8 + 32];
    input[..4].copy_from_slice(domain_type.as_slice());
    input[4..12].copy_from_slice(&epoch_bytes);
    input[12..].copy_from_slice(mix.as_slice());
    hash(&input)
}

/// `get_committee_count_per_slot` per `specs/phase0/beacon-chain.md:1080-1092`.
pub fn get_committee_count_per_slot<E: EthSpec>(state: &E::BeaconState, epoch: Epoch) -> u64 {
    let active = get_active_validator_indices::<E>(state, epoch);
    (active.len() as u64 / E::SLOTS_PER_EPOCH / E::TARGET_COMMITTEE_SIZE)
        .max(1)
        .min(E::MAX_COMMITTEES_PER_SLOT)
}

/// `compute_committee` per `specs/phase0/beacon-chain.md:882-892`.
pub fn compute_committee(
    indices: &[ValidatorIndex],
    seed: &Hash256,
    index: u64,
    count: u64,
    round_count: u64,
) -> Vec<ValidatorIndex> {
    let n = indices.len() as u64;
    let start = (n * index / count) as usize;
    let end = (n * (index + 1) / count) as usize;
    (start..end)
        .map(|i| {
            let shuffled = compute_shuffled_index(i as u64, n, seed, round_count);
            indices[shuffled as usize]
        })
        .collect()
}

/// `get_beacon_committee` per `specs/phase0/beacon-chain.md:1098-1111`.
pub fn get_beacon_committee<E: EthSpec>(
    state: &E::BeaconState,
    slot: Slot,
    index: u64,
) -> Vec<ValidatorIndex> {
    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let committees_per_slot = get_committee_count_per_slot::<E>(state, epoch);
    let active = get_active_validator_indices::<E>(state, epoch);
    let seed = get_seed::<E>(
        state,
        epoch,
        Bytes4::from_array(crate::phase0::helpers::DOMAIN_BEACON_ATTESTER),
    );
    let committee_index = (slot.0 % E::SLOTS_PER_EPOCH) * committees_per_slot + index;
    let committee_count = committees_per_slot * E::SLOTS_PER_EPOCH;
    compute_committee(
        &active,
        &seed,
        committee_index,
        committee_count,
        E::SHUFFLE_ROUND_COUNT,
    )
}

/// `compute_proposer_index` per `specs/phase0/beacon-chain.md:859-875`.
pub fn compute_proposer_index<E: EthSpec>(
    state: &E::BeaconState,
    indices: &[ValidatorIndex],
    seed: &Hash256,
) -> ValidatorIndex {
    assert!(!indices.is_empty());
    let max_random_byte: u64 = 255;
    let total = indices.len() as u64;
    let mut i: u64 = 0;
    loop {
        let shuffled_i = compute_shuffled_index(i % total, total, seed, E::SHUFFLE_ROUND_COUNT);
        let candidate_index = indices[shuffled_i as usize];
        let mut hash_input = seed.as_slice().to_vec();
        hash_input.extend_from_slice(&uint_to_bytes(i / 32));
        let random_byte = hash(&hash_input).as_slice()[(i % 32) as usize] as u64;
        let effective_balance = state
            .validators()
            .get(candidate_index.0 as usize)
            .unwrap()
            .effective_balance
            .0;
        if effective_balance * max_random_byte >= E::MAX_EFFECTIVE_BALANCE * random_byte {
            return candidate_index;
        }
        i += 1;
    }
}

/// `get_beacon_proposer_index` per `specs/phase0/beacon-chain.md:1117-1124`.
pub fn get_beacon_proposer_index<E: EthSpec>(state: &E::BeaconState) -> ValidatorIndex {
    let epoch = get_current_epoch::<E>(state);
    let seed_base = get_seed::<E>(
        state,
        epoch,
        Bytes4::from_array(crate::phase0::helpers::DOMAIN_BEACON_PROPOSER),
    );
    let slot_bytes = uint_to_bytes(state.slot().0);
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed_base.as_slice());
    input[32..].copy_from_slice(&slot_bytes);
    let seed = hash(&input);
    let indices = get_active_validator_indices::<E>(state, epoch);
    compute_proposer_index::<E>(state, &indices, &seed)
}

/// `get_total_balance` per `specs/phase0/beacon-chain.md:1130-1141`.
pub fn get_total_balance<E: EthSpec>(state: &E::BeaconState, indices: &[ValidatorIndex]) -> Gwei {
    let sum: u64 = indices
        .iter()
        .map(|i| {
            state
                .validator(i.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0)
        })
        .sum();
    Gwei(sum.max(E::EFFECTIVE_BALANCE_INCREMENT))
}

/// `get_total_active_balance` per `specs/phase0/beacon-chain.md:1147-1154`.
pub fn get_total_active_balance<E: EthSpec>(state: &E::BeaconState) -> Gwei {
    let active = get_active_validator_indices::<E>(state, get_current_epoch::<E>(state));
    get_total_balance::<E>(state, &active)
}

// ── Domain / crypto helpers ───────────────────────────────────────────────────

/// `compute_domain` per `specs/phase0/beacon-chain.md:951-967`.
pub fn compute_domain(
    domain_type: [u8; 4],
    fork_version: [u8; 4],
    genesis_validators_root: &Root,
) -> Domain {
    use pharos_utils::Bytes32;
    let fork_data_root =
        compute_fork_data_root(Bytes4::from_array(fork_version), genesis_validators_root);
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&domain_type);
    out[4..32].copy_from_slice(&fork_data_root.as_slice()[..28]);
    Bytes32::from_array(out)
}

/// `get_domain` per `specs/phase0/beacon-chain.md:1161-1170`.
pub fn get_domain<E: EthSpec>(
    state: &E::BeaconState,
    domain_type: [u8; 4],
    epoch: Option<Epoch>,
) -> Domain {
    let epoch = epoch.unwrap_or_else(|| get_current_epoch::<E>(state));
    let fork_version = if epoch < state.fork().epoch {
        state.fork().previous_version.into_inner()
    } else {
        state.fork().current_version.into_inner()
    };
    compute_domain(domain_type, fork_version, &state.genesis_validators_root())
}

/// `compute_signing_root` per `specs/phase0/beacon-chain.md:973-982`.
pub fn compute_signing_root<T: TreeHash>(ssz_object: &T, domain: Domain) -> Root {
    SigningData {
        object_root: ssz_object.tree_hash_root(),
        domain,
    }
    .tree_hash_root()
}

/// `get_attesting_indices` per `specs/phase0/beacon-chain.md:1192-1197`.
///
/// Uses the D8 associated-type pattern: the `Attestation` type is drawn from
/// `<E::BeaconBlockBody as BeaconBlockBodyView>::Attestation`, which binds to
/// `phase0::Attestation<2048>` in all current presets. The `Bitlist<2048>`
/// parameter is the concrete capacity from that binding; no
/// `generic_const_exprs` is required.
pub fn get_attesting_indices<E: EthSpec>(
    state: &E::BeaconState,
    data: &AttestationData,
    aggregation_bits: &pharos_ssz::Bitlist<2048>,
) -> Vec<ValidatorIndex>
where
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let committee = get_beacon_committee::<E>(state, data.slot, data.index.0);
    committee
        .into_iter()
        .enumerate()
        .filter_map(|(i, idx)| {
            if aggregation_bits.get(i).unwrap_or(false) {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

/// `get_indexed_attestation` per `specs/phase0/beacon-chain.md:1176-1186`.
///
/// Accepts `&Attestation<2048>` directly; the concrete attestation type used
/// in all current presets.
pub fn get_indexed_attestation<E: EthSpec>(
    state: &E::BeaconState,
    attestation: &Attestation<2048>,
) -> IndexedAttestation<2048>
where
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use pharos_ssz::SszList;
    let mut attesting =
        get_attesting_indices::<E>(state, &attestation.data, &attestation.aggregation_bits);
    attesting.sort();
    IndexedAttestation {
        attesting_indices: SszList::from_vec(attesting)
            .expect("attesting indices within MAX_VALIDATORS_PER_COMMITTEE"),
        data: attestation.data.clone(),
        signature: attestation.signature,
    }
}
