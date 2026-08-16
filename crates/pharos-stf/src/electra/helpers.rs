//! Electra beacon-state helper functions.
//!
//! Per `specs/electra/beacon-chain.md` — Helpers / Misc / accessors / mutators
//! (lines 480-865). Electra (EIP-7549/7251/6110/7002) reshapes attestation
//! attesting-index derivation and introduces churn-as-balance accounting; the
//! state-projection helpers convert an electra `BeaconState` to its deneb /
//! altair siblings so unchanged logic can be reused.

use pharos_ssz::{Bitvector, Encode, SszSequence};
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    deneb::BeaconState as DenebBeaconState,
    electra::{BeaconState, attestation::Attestation, attestation::IndexedAttestation},
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32, Gwei, Hash256};

use crate::capella::helpers::has_eth1_withdrawal_credential;
use crate::error::StateTransitionError;
use crate::phase0::accessors::{
    compute_domain, compute_epoch_at_slot, compute_signing_root, get_active_validator_indices,
    get_beacon_committee, get_current_epoch, get_seed,
};
use crate::phase0::helpers::{
    DOMAIN_BEACON_PROPOSER, DOMAIN_DEPOSIT, FAR_FUTURE_EPOCH, bytes_to_uint64, uint_to_bytes,
};
use crate::phase0::predicates::is_active_validator;
use crate::phase0::shuffling::compute_shuffled_index;

// ── State-projection helpers ──────────────────────────────────────────────────

/// Project an `electra::BeaconState` into an `altair::BeaconState` by cloning
/// the shared fields. Electra-only fields are dropped.
pub fn electra_state_to_altair<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &BeaconState<
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
) -> AltairBeaconState<
    SLOTS_PER_HISTORICAL_ROOT,
    HISTORICAL_ROOTS_LIMIT,
    ETH1_DATA_VOTES_LIMIT,
    VALIDATOR_REGISTRY_LIMIT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    JUSTIFICATION_BITS_LENGTH,
    SYNC_COMMITTEE_SIZE,
> {
    AltairBeaconState {
        genesis_time: state.genesis_time,
        genesis_validators_root: state.genesis_validators_root,
        slot: state.slot,
        fork: state.fork.clone(),
        latest_block_header: state.latest_block_header.clone(),
        block_roots: state.block_roots.clone(),
        state_roots: state.state_roots.clone(),
        historical_roots: state.historical_roots.clone(),
        eth1_data: state.eth1_data.clone(),
        eth1_data_votes: state.eth1_data_votes.clone(),
        eth1_deposit_index: state.eth1_deposit_index,
        validators: state.validators.clone(),
        balances: state.balances.clone(),
        randao_mixes: state.randao_mixes.clone(),
        slashings: state.slashings.clone(),
        previous_epoch_participation: state.previous_epoch_participation.clone(),
        current_epoch_participation: state.current_epoch_participation.clone(),
        justification_bits: state.justification_bits.clone(),
        previous_justified_checkpoint: state.previous_justified_checkpoint.clone(),
        current_justified_checkpoint: state.current_justified_checkpoint.clone(),
        finalized_checkpoint: state.finalized_checkpoint.clone(),
        inactivity_scores: state.inactivity_scores.clone(),
        current_sync_committee: state.current_sync_committee.clone(),
        next_sync_committee: state.next_sync_committee.clone(),
        cached_root: pharos_utils::CachedRoot::default(),
    }
}

/// Copy the shared fields from an `altair::BeaconState` back into an
/// `electra::BeaconState`. The electra-only fields (pending queues, churn
/// balances) and the execution-payload header / withdrawal fields /
/// `historical_summaries` are preserved.
///
/// Used to sync back altair-projected block-processing steps (`process_randao`,
/// `process_eth1_data`, `process_sync_aggregate`).
#[allow(clippy::type_complexity)]
pub fn update_electra_from_altair<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &mut BeaconState<
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
    altair: AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) {
    state.genesis_time = altair.genesis_time;
    state.genesis_validators_root = altair.genesis_validators_root;
    state.slot = altair.slot;
    state.fork = altair.fork;
    state.latest_block_header = altair.latest_block_header;
    state.block_roots = altair.block_roots;
    state.state_roots = altair.state_roots;
    state.historical_roots = altair.historical_roots;
    state.eth1_data = altair.eth1_data;
    state.eth1_data_votes = altair.eth1_data_votes;
    state.eth1_deposit_index = altair.eth1_deposit_index;
    state.validators = altair.validators;
    state.balances = altair.balances;
    state.randao_mixes = altair.randao_mixes;
    state.slashings = altair.slashings;
    state.previous_epoch_participation = altair.previous_epoch_participation;
    state.current_epoch_participation = altair.current_epoch_participation;
    state.justification_bits = altair.justification_bits;
    state.previous_justified_checkpoint = altair.previous_justified_checkpoint;
    state.current_justified_checkpoint = altair.current_justified_checkpoint;
    state.finalized_checkpoint = altair.finalized_checkpoint;
    state.inactivity_scores = altair.inactivity_scores;
    state.current_sync_committee = altair.current_sync_committee;
    state.next_sync_committee = altair.next_sync_committee;
    // electra-only fields + execution payload header + withdrawal fields +
    // historical_summaries intentionally NOT overwritten.
}

/// Project an `electra::BeaconState` into a `deneb::BeaconState`.
///
/// The execution-payload header is byte-identical between Electra and Deneb, so
/// it is cloned directly. Electra-only fields (pending queues, churn balances)
/// are dropped. Used to reuse deneb helpers that operate on the deneb state type.
pub fn electra_state_to_deneb<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &BeaconState<
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
) -> DenebBeaconState<
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
> {
    DenebBeaconState {
        genesis_time: state.genesis_time,
        genesis_validators_root: state.genesis_validators_root,
        slot: state.slot,
        fork: state.fork.clone(),
        latest_block_header: state.latest_block_header.clone(),
        block_roots: state.block_roots.clone(),
        state_roots: state.state_roots.clone(),
        historical_roots: state.historical_roots.clone(),
        eth1_data: state.eth1_data.clone(),
        eth1_data_votes: state.eth1_data_votes.clone(),
        eth1_deposit_index: state.eth1_deposit_index,
        validators: state.validators.clone(),
        balances: state.balances.clone(),
        randao_mixes: state.randao_mixes.clone(),
        slashings: state.slashings.clone(),
        previous_epoch_participation: state.previous_epoch_participation.clone(),
        current_epoch_participation: state.current_epoch_participation.clone(),
        justification_bits: state.justification_bits.clone(),
        previous_justified_checkpoint: state.previous_justified_checkpoint.clone(),
        current_justified_checkpoint: state.current_justified_checkpoint.clone(),
        finalized_checkpoint: state.finalized_checkpoint.clone(),
        inactivity_scores: state.inactivity_scores.clone(),
        current_sync_committee: state.current_sync_committee.clone(),
        next_sync_committee: state.next_sync_committee.clone(),
        latest_execution_payload_header: state.latest_execution_payload_header.clone(),
        next_withdrawal_index: state.next_withdrawal_index,
        next_withdrawal_validator_index: state.next_withdrawal_validator_index,
        historical_summaries: state.historical_summaries.clone(),
        cached_root: pharos_utils::CachedRoot::default(),
    }
}

/// Copy the shared fields from a `deneb::BeaconState` back into an
/// `electra::BeaconState`. The electra-only fields are preserved.
///
/// The deneb-shared `latest_execution_payload_header` IS overwritten (byte
/// identical between forks). Call sites that mutated electra-only fields via the
/// deneb projection must update them separately.
pub fn update_electra_from_deneb<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &mut BeaconState<
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
    deneb: DenebBeaconState<
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
) {
    state.genesis_time = deneb.genesis_time;
    state.genesis_validators_root = deneb.genesis_validators_root;
    state.slot = deneb.slot;
    state.fork = deneb.fork;
    state.latest_block_header = deneb.latest_block_header;
    state.block_roots = deneb.block_roots;
    state.state_roots = deneb.state_roots;
    state.historical_roots = deneb.historical_roots;
    state.eth1_data = deneb.eth1_data;
    state.eth1_data_votes = deneb.eth1_data_votes;
    state.eth1_deposit_index = deneb.eth1_deposit_index;
    state.validators = deneb.validators;
    state.balances = deneb.balances;
    state.randao_mixes = deneb.randao_mixes;
    state.slashings = deneb.slashings;
    state.previous_epoch_participation = deneb.previous_epoch_participation;
    state.current_epoch_participation = deneb.current_epoch_participation;
    state.justification_bits = deneb.justification_bits;
    state.previous_justified_checkpoint = deneb.previous_justified_checkpoint;
    state.current_justified_checkpoint = deneb.current_justified_checkpoint;
    state.finalized_checkpoint = deneb.finalized_checkpoint;
    state.inactivity_scores = deneb.inactivity_scores;
    state.current_sync_committee = deneb.current_sync_committee;
    state.next_sync_committee = deneb.next_sync_committee;
    state.latest_execution_payload_header = deneb.latest_execution_payload_header;
    state.next_withdrawal_index = deneb.next_withdrawal_index;
    state.next_withdrawal_validator_index = deneb.next_withdrawal_validator_index;
    state.historical_summaries = deneb.historical_summaries;
    // electra-only: pending queues + churn balances intentionally NOT overwritten.
}

// ── Epoch / balance helpers (concrete electra state) ──────────────────────────

/// Return the current epoch for an electra `BeaconState`.
#[allow(dead_code)]
pub(crate) fn get_current_epoch_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Epoch {
    compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH)
}

/// `get_total_active_balance` for a concrete electra `BeaconState`.
pub(crate) fn get_total_active_balance_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Gwei {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let sum: u64 = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, current_epoch.0))
        .map(|v| v.effective_balance.0)
        .sum();
    Gwei(sum.max(E::EFFECTIVE_BALANCE_INCREMENT))
}

/// `decrease_balance` for an electra `BeaconState`.
pub(crate) fn decrease_balance_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &mut BeaconState<
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
    index: ValidatorIndex,
    delta: Gwei,
) {
    let cur = state
        .balances
        .as_slice()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    let new_val = if delta.0 > cur.0 {
        Gwei(0)
    } else {
        Gwei(cur.0 - delta.0)
    };
    state.balances = state
        .balances
        .with_set(index.0 as usize, new_val)
        .expect("balance index in range");
}

/// `increase_balance` for an electra `BeaconState`.
pub(crate) fn increase_balance_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &mut BeaconState<
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
    index: ValidatorIndex,
    delta: Gwei,
) {
    let cur = state
        .balances
        .as_slice()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    state.balances = state
        .balances
        .with_set(index.0 as usize, Gwei(cur.0.saturating_add(delta.0)))
        .expect("balance index in range");
}

// ── Task 2a.1: electra compute_proposer_index / get_beacon_proposer_index ──────

/// `compute_proposer_index` for Electra per `specs/electra/beacon-chain.md:450-470`.
///
/// Differs from the phase0/altair impl in two ways (EIP-7251):
/// 1. The effective-balance filter uses a **16-bit** random value
///    (`bytes_to_uint64(random_bytes[offset..offset+2])`, `MAX_RANDOM_VALUE =
///    2**16 - 1`) instead of an 8-bit single byte (`MAX_RANDOM_BYTE = 255`).
///    The seed re-hash advances every 16 candidates (`hash(seed + i // 16)`).
/// 2. The balance ceiling is `MAX_EFFECTIVE_BALANCE_ELECTRA` instead of
///    `MAX_EFFECTIVE_BALANCE`.
///
/// Generic over `E::BeaconState` via the `BeaconStateView` trait, mirroring the
/// phase0 helper.
pub fn compute_proposer_index_electra<E: EthSpec>(
    state: &E::BeaconState,
    indices: &[ValidatorIndex],
    seed: &Hash256,
) -> ValidatorIndex {
    use pharos_types::BeaconStateView;

    assert!(!indices.is_empty());
    const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;
    let total = indices.len() as u64;
    let mut i: u64 = 0;
    loop {
        let shuffled_i = compute_shuffled_index(i % total, total, seed, E::SHUFFLE_ROUND_COUNT);
        let candidate_index = indices[shuffled_i as usize];
        // [Modified in Electra] 16-bit random value.
        let mut hash_input = seed.as_slice().to_vec();
        hash_input.extend_from_slice(&uint_to_bytes(i / 16));
        let random_bytes = pharos_utils::hash::hash(&hash_input);
        let offset = ((i % 16) * 2) as usize;
        let random_value = bytes_to_uint64(&random_bytes.as_slice()[offset..offset + 2]);
        let effective_balance = state
            .validator(candidate_index.0 as usize)
            .unwrap()
            .effective_balance
            .0;
        if effective_balance * MAX_RANDOM_VALUE >= E::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value {
            return candidate_index;
        }
        i += 1;
    }
}

/// `get_beacon_proposer_index` for Electra.
///
/// Identical to the phase0 derivation of the seed (DOMAIN_BEACON_PROPOSER +
/// slot) but uses the electra `compute_proposer_index_electra`.
pub fn get_beacon_proposer_index_electra<E: EthSpec>(state: &E::BeaconState) -> ValidatorIndex {
    use pharos_types::BeaconStateView;

    let epoch = get_current_epoch::<E>(state);
    let seed_base = get_seed::<E>(
        state,
        epoch,
        pharos_utils::Bytes4::from_array(DOMAIN_BEACON_PROPOSER),
    );
    let slot_bytes = uint_to_bytes(state.slot().0);
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed_base.as_slice());
    input[32..].copy_from_slice(&slot_bytes);
    let seed = pharos_utils::hash::hash(&input);
    let indices = get_active_validator_indices::<E>(state, epoch);
    compute_proposer_index_electra::<E>(state, &indices, &seed)
}

// ── Task 2a.4: effective-balance / withdrawal-credential accessors ─────────────

/// `is_compounding_withdrawal_credential` per `specs/electra/beacon-chain.md:493-495`.
///
/// Returns `true` when `withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX (0x02)`.
pub fn is_compounding_withdrawal_credential<E: EthSpec>(withdrawal_credentials: &Bytes32) -> bool {
    withdrawal_credentials.as_slice()[0] == E::COMPOUNDING_WITHDRAWAL_PREFIX as u8
}

/// `has_compounding_withdrawal_credential` per `specs/electra/beacon-chain.md:500-505`.
pub fn has_compounding_withdrawal_credential<E: EthSpec>(
    validator: &pharos_types::phase0::Validator,
) -> bool {
    is_compounding_withdrawal_credential::<E>(&validator.withdrawal_credentials)
}

/// `has_execution_withdrawal_credential` per `specs/electra/beacon-chain.md:510-518`.
///
/// Returns `true` when the validator has a `0x01` or `0x02` prefixed credential.
pub fn has_execution_withdrawal_credential<E: EthSpec>(
    validator: &pharos_types::phase0::Validator,
) -> bool {
    has_eth1_withdrawal_credential(validator)
        || has_compounding_withdrawal_credential::<E>(validator)
}

/// `get_max_effective_balance` per `specs/electra/beacon-chain.md:593-600`.
///
/// Compounding validators get `MAX_EFFECTIVE_BALANCE_ELECTRA`; everyone else
/// gets `MIN_ACTIVATION_BALANCE`.
pub fn get_max_effective_balance<E: EthSpec>(validator: &pharos_types::phase0::Validator) -> Gwei {
    if has_compounding_withdrawal_credential::<E>(validator) {
        Gwei(E::MAX_EFFECTIVE_BALANCE_ELECTRA)
    } else {
        Gwei(E::MIN_ACTIVATION_BALANCE)
    }
}

/// `get_balance_churn_limit` per `specs/electra/beacon-chain.md:608-615`.
pub fn get_balance_churn_limit_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Gwei {
    let total_active = get_total_active_balance_electra::<
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
        E,
    >(state);
    let churn = E::MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA.max(total_active.0 / E::CHURN_LIMIT_QUOTIENT);
    Gwei(churn - churn % E::EFFECTIVE_BALANCE_INCREMENT)
}

/// `get_activation_exit_churn_limit` per `specs/electra/beacon-chain.md:620-625`.
pub fn get_activation_exit_churn_limit_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Gwei {
    let balance_churn = get_balance_churn_limit_electra::<
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
        E,
    >(state);
    Gwei(E::MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT.min(balance_churn.0))
}

/// `get_consolidation_churn_limit` per `specs/electra/beacon-chain.md:630-632`.
pub fn get_consolidation_churn_limit_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Gwei {
    let balance_churn = get_balance_churn_limit_electra::<
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
        E,
    >(state);
    let activation_exit_churn = get_activation_exit_churn_limit_electra::<
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
        E,
    >(state);
    Gwei(balance_churn.0 - activation_exit_churn.0)
}

/// `get_pending_balance_to_withdraw` per `specs/electra/beacon-chain.md:638-643`.
pub fn get_pending_balance_to_withdraw_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>(
    state: &BeaconState<
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
    validator_index: ValidatorIndex,
) -> Gwei {
    let sum: u64 = state
        .pending_partial_withdrawals
        .iter()
        .filter(|w| w.validator_index == validator_index)
        .map(|w| w.amount.0)
        .sum();
    Gwei(sum)
}

/// `compute_exit_epoch_and_update_churn` per `specs/electra/beacon-chain.md:770-792`.
///
/// Mutates `state.exit_balance_to_consume` and `state.earliest_exit_epoch` and
/// returns the resulting `earliest_exit_epoch`.
pub fn compute_exit_epoch_and_update_churn_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &mut BeaconState<
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
    exit_balance: Gwei,
) -> Epoch {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let activation_exit_epoch = current_epoch.0 + 1 + E::MAX_SEED_LOOKAHEAD;
    let mut earliest_exit_epoch = state.earliest_exit_epoch.0.max(activation_exit_epoch);
    let per_epoch_churn = get_activation_exit_churn_limit_electra::<
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
        E,
    >(state)
    .0;

    let mut exit_balance_to_consume = if state.earliest_exit_epoch.0 < earliest_exit_epoch {
        per_epoch_churn
    } else {
        state.exit_balance_to_consume.0
    };

    if exit_balance.0 > exit_balance_to_consume {
        let balance_to_process = exit_balance.0 - exit_balance_to_consume;
        let additional_epochs = (balance_to_process - 1) / per_epoch_churn + 1;
        earliest_exit_epoch += additional_epochs;
        exit_balance_to_consume += additional_epochs * per_epoch_churn;
    }

    state.exit_balance_to_consume = Gwei(exit_balance_to_consume - exit_balance.0);
    state.earliest_exit_epoch = Epoch(earliest_exit_epoch);

    state.earliest_exit_epoch
}

/// `compute_consolidation_epoch_and_update_churn` per
/// `specs/electra/beacon-chain.md:798-824`.
pub fn compute_consolidation_epoch_and_update_churn_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &mut BeaconState<
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
    consolidation_balance: Gwei,
) -> Epoch {
    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let activation_exit_epoch = current_epoch.0 + 1 + E::MAX_SEED_LOOKAHEAD;
    let mut earliest_consolidation_epoch = state
        .earliest_consolidation_epoch
        .0
        .max(activation_exit_epoch);
    let per_epoch_consolidation_churn = get_consolidation_churn_limit_electra::<
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
        E,
    >(state)
    .0;

    let mut consolidation_balance_to_consume =
        if state.earliest_consolidation_epoch.0 < earliest_consolidation_epoch {
            per_epoch_consolidation_churn
        } else {
            state.consolidation_balance_to_consume.0
        };

    if consolidation_balance.0 > consolidation_balance_to_consume {
        let balance_to_process = consolidation_balance.0 - consolidation_balance_to_consume;
        let additional_epochs = (balance_to_process - 1) / per_epoch_consolidation_churn + 1;
        earliest_consolidation_epoch += additional_epochs;
        consolidation_balance_to_consume += additional_epochs * per_epoch_consolidation_churn;
    }

    state.consolidation_balance_to_consume =
        Gwei(consolidation_balance_to_consume - consolidation_balance.0);
    state.earliest_consolidation_epoch = Epoch(earliest_consolidation_epoch);

    state.earliest_consolidation_epoch
}

/// `queue_excess_active_balance` per `specs/electra/beacon-chain.md:748-764`.
///
/// If the validator's balance exceeds `MIN_ACTIVATION_BALANCE`, the excess is
/// removed from `balances[index]` and appended as a `PendingDeposit` with the
/// `G2_POINT_AT_INFINITY` signature placeholder and `GENESIS_SLOT` (`0`).
pub fn queue_excess_active_balance_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &mut BeaconState<
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
    index: ValidatorIndex,
) -> Result<(), StateTransitionError> {
    use pharos_ssz::SszVector;
    use pharos_types::electra::requests::PendingDeposit;

    let balance = state
        .balances
        .as_slice()
        .get(index.0 as usize)
        .copied()
        .unwrap_or(Gwei(0));
    if balance.0 > E::MIN_ACTIVATION_BALANCE {
        let excess_balance = balance.0 - E::MIN_ACTIVATION_BALANCE;
        state.balances = state
            .balances
            .with_set(index.0 as usize, Gwei(E::MIN_ACTIVATION_BALANCE))
            .map_err(StateTransitionError::Ssz)?;
        let validator = state
            .validators
            .get(index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?
            .clone();
        // bls.G2_POINT_AT_INFINITY signature placeholder (0xc0 || zeros).
        let mut sig_bytes = [0u8; 96];
        sig_bytes[0] = 0xc0;
        let pending = PendingDeposit {
            pubkey: SszVector::from_vec(validator.pubkey.as_slice().to_vec())
                .expect("pubkey is 48 bytes"),
            withdrawal_credentials: validator.withdrawal_credentials.into_inner(),
            amount: Gwei(excess_balance),
            signature: SszVector::from_vec(sig_bytes.to_vec()).expect("signature is 96 bytes"),
            slot: pharos_types::phase0::Slot(0),
        };
        state.pending_deposits = state
            .pending_deposits
            .with_push(pending)
            .map_err(StateTransitionError::Ssz)?;
    }
    Ok(())
}

/// `switch_to_compounding_validator` per `specs/electra/beacon-chain.md:737-742`.
///
/// Rewrites the validator's credential prefix to `COMPOUNDING_WITHDRAWAL_PREFIX`
/// and queues any excess active balance.
pub fn switch_to_compounding_validator_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &mut BeaconState<
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
    index: ValidatorIndex,
) -> Result<(), StateTransitionError> {
    let mut validator = state
        .validators
        .get(index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();
    let mut creds = validator.withdrawal_credentials.into_inner();
    creds[0] = E::COMPOUNDING_WITHDRAWAL_PREFIX as u8;
    validator.withdrawal_credentials = Bytes32::from_array(creds);
    validator.invalidate_cache();
    state.validators = state
        .validators
        .with_set(index.0 as usize, validator)
        .map_err(StateTransitionError::Ssz)?;
    queue_excess_active_balance_electra::<
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
        E,
    >(state, index)
}

// ── Task 2a.2: electra initiate_validator_exit / slash_validator ──────────────

/// `initiate_validator_exit` for Electra per `specs/electra/beacon-chain.md:717-731`.
///
/// Uses `compute_exit_epoch_and_update_churn` (churn-as-balance) instead of the
/// phase0 active-validator-count churn limit.
pub fn initiate_validator_exit_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &mut BeaconState<
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
    index: ValidatorIndex,
) -> Result<(), StateTransitionError> {
    let effective_balance = {
        let v = state
            .validators
            .get(index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
        if v.exit_epoch.0 != FAR_FUTURE_EPOCH {
            return Ok(());
        }
        v.effective_balance
    };

    let exit_queue_epoch = compute_exit_epoch_and_update_churn_electra::<
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
        E,
    >(state, effective_balance);

    let withdrawable_epoch = exit_queue_epoch
        .0
        .checked_add(E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
        .ok_or(StateTransitionError::SlotOutOfRange)?;

    let mut v = state
        .validators
        .get(index.0 as usize)
        .ok_or(StateTransitionError::SlotOutOfRange)?
        .clone();
    v.exit_epoch = exit_queue_epoch;
    v.withdrawable_epoch = Epoch(withdrawable_epoch);
    v.invalidate_cache();
    state.validators = state
        .validators
        .with_set(index.0 as usize, v)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}

/// `slash_validator` for Electra per `specs/electra/beacon-chain.md:834-865`.
///
/// EIP-7251 changes vs. bellatrix/deneb: the slashing penalty uses
/// `MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA` and the whistleblower reward uses
/// `WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA`. The proposer is derived from the
/// electra `get_beacon_proposer_index`.
#[allow(clippy::too_many_arguments)]
pub fn slash_validator_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E,
>(
    state: &mut BeaconState<
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
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
        ElectraBeaconState = BeaconState<
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
    >,
{
    use crate::altair::helpers::PROPOSER_WEIGHT;

    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    initiate_validator_exit_electra::<
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
        E,
    >(state, slashed_index)?;

    let (effective_balance, current_withdrawable_epoch) = {
        let v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?;
        (v.effective_balance, v.withdrawable_epoch)
    };

    let new_withdrawable_epoch = Epoch(
        current_withdrawable_epoch
            .0
            .max(epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR),
    );

    {
        let mut v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(StateTransitionError::SlotOutOfRange)?
            .clone();
        v.slashed = true;
        v.withdrawable_epoch = new_withdrawable_epoch;
        v.invalidate_cache();
        state.validators = state
            .validators
            .with_set(slashed_index.0 as usize, v)
            .map_err(StateTransitionError::Ssz)?;
    }

    let slashing_slot = (epoch.0 % E::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
    let cur_slashing = state
        .slashings
        .as_slice()
        .get(slashing_slot)
        .copied()
        .unwrap_or(Gwei(0));
    state.slashings = state
        .slashings
        .with_set(
            slashing_slot,
            Gwei(cur_slashing.0.saturating_add(effective_balance.0)),
        )
        .map_err(StateTransitionError::Ssz)?;

    // [Modified in Electra:EIP7251] penalty quotient.
    let penalty = Gwei(effective_balance.0 / E::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA);
    decrease_balance_electra::<
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
    >(state, slashed_index, penalty);

    // Proposer via electra get_beacon_proposer_index over the enum state.
    let proposer_index =
        get_beacon_proposer_index_electra::<E>(&E::electra_into_state(state.clone()));

    let whistleblower_idx = whistleblower_index.unwrap_or(proposer_index);
    // [Modified in Electra:EIP7251] whistleblower reward quotient.
    let whistleblower_reward = Gwei(effective_balance.0 / E::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA);
    let proposer_reward = Gwei(whistleblower_reward.0 * PROPOSER_WEIGHT / E::WEIGHT_DENOMINATOR);

    increase_balance_electra::<
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
    >(state, proposer_index, proposer_reward);
    increase_balance_electra::<
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
    >(
        state,
        whistleblower_idx,
        Gwei(whistleblower_reward.0 - proposer_reward.0),
    );

    Ok(())
}

// ── Task 2a.3: EIP-7549 attesting-index helpers ───────────────────────────────

/// `get_committee_indices` per `specs/electra/beacon-chain.md:583-588`.
///
/// Returns the indices of set bits in `committee_bits`, in ascending order.
pub fn get_committee_indices<const MAX_COMMITTEES_PER_SLOT: u64>(
    committee_bits: &Bitvector<MAX_COMMITTEES_PER_SLOT>,
) -> Vec<u64> {
    committee_bits
        .iter()
        .enumerate()
        .filter_map(|(i, bit)| if bit { Some(i as u64) } else { None })
        .collect()
}

/// `get_attesting_indices` for Electra per `specs/electra/beacon-chain.md:646-669`.
///
/// EIP-7549: iterate committees in `committee_bits` order, accumulating a
/// `committee_offset` into the flat `aggregation_bits`. Returns the deduplicated,
/// unsorted set of attesting validator indices.
pub fn get_attesting_indices_electra<
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    E: EthSpec,
>(
    state: &E::BeaconState,
    attestation: &Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
) -> Vec<ValidatorIndex> {
    let committee_indices = get_committee_indices(&attestation.committee_bits);
    let mut output: Vec<ValidatorIndex> = Vec::new();
    let mut committee_offset = 0usize;
    for committee_index in committee_indices {
        let committee = get_beacon_committee::<E>(state, attestation.data.slot, committee_index);
        for (i, attester_index) in committee.iter().enumerate() {
            if attestation
                .aggregation_bits
                .get(committee_offset + i)
                .unwrap_or(false)
                && !output.contains(attester_index)
            {
                output.push(*attester_index);
            }
        }
        committee_offset += committee.len();
    }
    output
}

/// `get_indexed_attestation` for Electra.
///
/// Builds an electra `IndexedAttestation` with `attesting_indices` sorted
/// ascending, derived from the electra `get_attesting_indices`.
pub fn get_indexed_attestation_electra<
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    E: EthSpec,
>(
    state: &E::BeaconState,
    attestation: &Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
) -> IndexedAttestation<MAX_AGGREGATION_BITS> {
    use pharos_ssz::SszList;

    let mut attesting = get_attesting_indices_electra::<
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        E,
    >(state, attestation);
    attesting.sort();
    IndexedAttestation {
        attesting_indices: SszList::from_vec(attesting)
            .expect("attesting indices within MAX_AGGREGATION_BITS"),
        data: attestation.data.clone(),
        signature: attestation.signature,
    }
}

// ── Task 2a.5: modified withdrawal predicates + deposit signature ─────────────

/// `is_fully_withdrawable_validator` for Electra per
/// `specs/electra/beacon-chain.md:528-537`.
///
/// EIP-7251: uses `has_execution_withdrawal_credential` (0x01 or 0x02) instead
/// of `has_eth1_withdrawal_credential`.
pub fn is_fully_withdrawable_validator_electra<E: EthSpec>(
    validator: &pharos_types::phase0::Validator,
    balance: Gwei,
    epoch: Epoch,
) -> bool {
    has_execution_withdrawal_credential::<E>(validator)
        && validator.withdrawable_epoch.0 <= epoch.0
        && balance.0 > 0
}

/// `is_partially_withdrawable_validator` for Electra per
/// `specs/electra/beacon-chain.md:548-562`.
///
/// EIP-7251: uses `get_max_effective_balance` (compounding-aware) and
/// `has_execution_withdrawal_credential`.
pub fn is_partially_withdrawable_validator_electra<E: EthSpec>(
    validator: &pharos_types::phase0::Validator,
    balance: Gwei,
) -> bool {
    let max_effective_balance = get_max_effective_balance::<E>(validator);
    let has_max_effective_balance = validator.effective_balance.0 == max_effective_balance.0;
    let has_excess_balance = balance.0 > max_effective_balance.0;
    has_execution_withdrawal_credential::<E>(validator)
        && has_max_effective_balance
        && has_excess_balance
}

/// `is_eligible_for_partial_withdrawals` per `specs/electra/beacon-chain.md:568-578`.
pub fn is_eligible_for_partial_withdrawals_electra<E: EthSpec>(
    validator: &pharos_types::phase0::Validator,
    balance: Gwei,
) -> bool {
    let has_sufficient_effective_balance =
        validator.effective_balance.0 >= E::MIN_ACTIVATION_BALANCE;
    let has_excess_balance = balance.0 > E::MIN_ACTIVATION_BALANCE;
    validator.exit_epoch.0 == FAR_FUTURE_EPOCH
        && has_sufficient_effective_balance
        && has_excess_balance
}

/// `is_valid_deposit_signature` per `specs/electra/beacon-chain.md:1654-1665`.
///
/// Standalone fork-agnostic BLS proof-of-possession check (domain uses
/// `GENESIS_FORK_VERSION` and a zero `genesis_validators_root`). NOT shared with
/// the phase0 `apply_deposit`; electra `process_deposit_request` /
/// `apply_deposit` call this directly.
pub fn is_valid_deposit_signature<E: EthSpec>(
    pubkey: &BLSPubkey,
    withdrawal_credentials: &Bytes32,
    amount: u64,
    signature: &BLSSignature,
) -> bool {
    use pharos_types::phase0::DepositMessage;

    let deposit_message = DepositMessage {
        pubkey: *pubkey,
        withdrawal_credentials: *withdrawal_credentials,
        amount: Gwei(amount),
    };
    let domain = compute_domain(DOMAIN_DEPOSIT, E::GENESIS_FORK_VERSION, &Hash256::default());
    let signing_root = compute_signing_root(&deposit_message, domain);
    pharos_utils::bls::verify(pubkey, signing_root.as_slice(), signature).unwrap_or(false)
}

// ── Task 4c.2: electra get_next_sync_committee_indices / get_next_sync_committee ─

/// `get_next_sync_committee_indices` for Electra per
/// `specs/electra/beacon-chain.md:679-706`.
///
/// `[Modified in Electra:EIP7251]` vs. altair in two ways:
/// 1. The effective-balance filter uses a **16-bit** random value
///    (`bytes_to_uint64(random_bytes[offset..offset+2])`, `MAX_RANDOM_VALUE =
///    2**16 - 1`) instead of an 8-bit single byte. The seed re-hash advances
///    every 16 candidates (`hash(seed + i // 16)`), and the byte offset within
///    the hash is `(i % 16) * 2`.
/// 2. The balance ceiling is `MAX_EFFECTIVE_BALANCE_ELECTRA`.
///
/// Mirrors `compute_proposer_index_electra` byte logic.
#[allow(clippy::type_complexity)]
pub fn get_next_sync_committee_indices_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Vec<ValidatorIndex> {
    use crate::altair::helpers::DOMAIN_SYNC_COMMITTEE;

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let epoch = Epoch(current_epoch.0 + 1);

    let active_indices: Vec<ValidatorIndex> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if is_active_validator(v, epoch.0) {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect();

    let active_count = active_indices.len() as u64;
    if active_count == 0 {
        return Vec::new();
    }

    let seed = get_seed_electra::<
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
        E,
    >(state, epoch, DOMAIN_SYNC_COMMITTEE);

    const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;
    let mut sync_committee_indices: Vec<ValidatorIndex> = Vec::new();
    let mut i: u64 = 0;

    while (sync_committee_indices.len() as u64) < E::SYNC_COMMITTEE_SIZE {
        let shuffled_index = compute_shuffled_index(
            i % active_count,
            active_count,
            &seed,
            E::SHUFFLE_ROUND_COUNT,
        );
        let candidate_index = active_indices[shuffled_index as usize];
        // [Modified in Electra] 16-bit random value.
        let mut hash_input = seed.as_slice().to_vec();
        hash_input.extend_from_slice(&uint_to_bytes(i / 16));
        let random_bytes = pharos_utils::hash::hash(&hash_input);
        let offset = ((i % 16) * 2) as usize;
        let random_value = bytes_to_uint64(&random_bytes.as_slice()[offset..offset + 2]);
        let effective_balance = state
            .validators
            .get(candidate_index.0 as usize)
            .map(|v| v.effective_balance.0)
            .unwrap_or(0);
        if effective_balance * MAX_RANDOM_VALUE >= E::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value {
            sync_committee_indices.push(candidate_index);
        }
        i += 1;
    }

    sync_committee_indices
}

/// `get_seed` for a concrete electra `BeaconState`.
///
/// Mirrors `get_seed` from phase0 accessors but operates on the concrete electra
/// `BeaconState.randao_mixes` directly (no `BeaconStateView` bound needed).
#[allow(clippy::type_complexity)]
fn get_seed_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
    epoch: Epoch,
    domain_type: [u8; 4],
) -> Hash256 {
    let mix_epoch_raw = epoch
        .0
        .wrapping_add(E::EPOCHS_PER_HISTORICAL_VECTOR)
        .wrapping_sub(E::MIN_SEED_LOOKAHEAD)
        .wrapping_sub(1);
    let mix_idx = (mix_epoch_raw % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    let mix = state.randao_mixes.get(mix_idx).copied().unwrap_or_default();
    let epoch_bytes = uint_to_bytes(epoch.0);
    let mut input = [0u8; 4 + 8 + 32];
    input[..4].copy_from_slice(&domain_type);
    input[4..12].copy_from_slice(&epoch_bytes);
    input[12..].copy_from_slice(mix.as_slice());
    pharos_utils::hash::hash(&input)
}

/// `get_next_sync_committee` for Electra per `specs/altair/beacon-chain.md:297-304`,
/// using the electra `get_next_sync_committee_indices`.
#[allow(clippy::type_complexity)]
pub fn get_next_sync_committee_electra<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    E: EthSpec,
>(
    state: &BeaconState<
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
) -> Result<pharos_types::altair::SyncCommittee<SYNC_COMMITTEE_SIZE>, StateTransitionError>
where
    BLSPubkey: Default + Clone,
{
    let indices = get_next_sync_committee_indices_electra::<
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
        E,
    >(state);

    let pubkeys: Vec<BLSPubkey> = indices
        .iter()
        .map(|idx| {
            state
                .validators
                .get(idx.0 as usize)
                .map(|v| v.pubkey)
                .unwrap_or_default()
        })
        .collect();

    let aggregate_pubkey = pharos_utils::bls::aggregate_pubkeys(&pubkeys)
        .map_err(|_| StateTransitionError::InvalidBlockSignature)?;

    let pubkeys_vec: pharos_ssz::SszVector<BLSPubkey, SYNC_COMMITTEE_SIZE> =
        pharos_ssz::SszVector::from_vec(pubkeys).map_err(StateTransitionError::Ssz)?;

    Ok(pharos_types::altair::SyncCommittee {
        pubkeys: pubkeys_vec,
        aggregate_pubkey,
    })
}

// ── EIP-7685 execution request encoding ──────────────────────────────────────

/// `get_execution_requests_list` per `specs/electra/beacon-chain.md:1390-1401`.
///
/// Encodes execution requests per EIP-7685: for each NON-EMPTY request type,
/// emit `request_type_byte || ssz_serialize(request_list)`, in canonical order:
/// deposit (0x00) / withdrawal (0x01) / consolidation (0x02).
/// Empty lists are OMITTED (skip-empty rule).
///
/// Returns a `Vec<Vec<u8>>` suitable for conversion to hex strings for the
/// Engine API V4 `executionRequests` parameter.
pub fn get_execution_requests_list<
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
>(
    execution_requests: &pharos_types::electra::requests::ExecutionRequests<
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >,
) -> Vec<Vec<u8>> {
    let mut result: Vec<Vec<u8>> = Vec::new();

    // 0x00: deposit requests
    if !execution_requests.deposits.is_empty() {
        let mut entry = vec![0x00u8];
        entry.extend_from_slice(&execution_requests.deposits.as_ssz_bytes());
        result.push(entry);
    }

    // 0x01: withdrawal requests
    if !execution_requests.withdrawals.is_empty() {
        let mut entry = vec![0x01u8];
        entry.extend_from_slice(&execution_requests.withdrawals.as_ssz_bytes());
        result.push(entry);
    }

    // 0x02: consolidation requests
    if !execution_requests.consolidations.is_empty() {
        let mut entry = vec![0x02u8];
        entry.extend_from_slice(&execution_requests.consolidations.as_ssz_bytes());
        result.push(entry);
    }

    result
}

/// Inverse of [`get_execution_requests_list`]: decode the Engine API V4
/// `executionRequests` parameter (one entry per non-empty request type, each
/// `request_type_byte || ssz_serialize(request_list)`, in canonical order
/// 0x00/0x01/0x02 with empty lists OMITTED) back into an `ExecutionRequests`.
///
/// Used by block production: `engine_getPayloadV4` returns the requests as a
/// list of byte strings and the proposer must reconstruct the typed
/// `ExecutionRequests` to put in the electra `BeaconBlockBody`. Per EIP-7685.
///
/// Returns `None` if any entry has an unknown type byte, an empty body, or an
/// SSZ list that fails to decode (the engine is trusted to produce well-formed
/// requests; a malformed entry must not silently produce a wrong block body).
pub fn parse_execution_requests_list<
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
>(
    entries: &[Vec<u8>],
) -> Option<
    pharos_types::electra::requests::ExecutionRequests<
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >,
> {
    use pharos_ssz::{Decode, SszList};
    use pharos_types::electra::requests::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest,
    };

    let mut requests = ExecutionRequests::<
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >::default();

    for entry in entries {
        // Each entry is `type_byte || ssz_serialize(list)`. A bare type byte
        // (empty body) is not emitted by the encoder (skip-empty rule), so an
        // entry shorter than 1 byte or carrying no payload is malformed.
        let (&type_byte, body) = entry.split_first()?;
        match type_byte {
            0x00 => {
                let list =
                    SszList::<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>::from_ssz_bytes(
                        body,
                    )
                    .ok()?;
                requests.deposits = list;
            }
            0x01 => {
                let list = SszList::<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>::from_ssz_bytes(body).ok()?;
                requests.withdrawals = list;
            }
            0x02 => {
                let list = SszList::<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>::from_ssz_bytes(body).ok()?;
                requests.consolidations = list;
            }
            _ => return None,
        }
    }

    Some(requests)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use pharos_ssz::Decode;
    use pharos_types::MinimalEthSpec;
    use pharos_types::electra::{
        BeaconState as ElectraConcreteState, MinimalBeaconBlock, MinimalBeaconState,
    };
    use pharos_types::phase0::AttestationData;

    use super::*;
    use crate::phase0::accessors::get_committee_count_per_slot;

    // ── Fixture loading (matches the conformance / epoch_determinism skip rule) ──

    fn fixtures_root() -> Option<PathBuf> {
        let path = if let Ok(val) = std::env::var("PHAROS_SPEC_TESTS") {
            PathBuf::from(val)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".cache/pharos-spec-tests")
        };
        if path.is_dir() && std::fs::read_dir(&path).ok()?.next().is_some() {
            Some(path)
        } else {
            None
        }
    }

    fn load_ssz_snappy<S: Decode>(path: &Path) -> S {
        let compressed =
            std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut decoder = snap::raw::Decoder::new();
        let raw = decoder
            .decompress_vec(&compressed)
            .unwrap_or_else(|e| panic!("snappy decompress {}: {e}", path.display()));
        S::from_ssz_bytes(&raw).unwrap_or_else(|e| panic!("ssz decode {}: {e:?}", path.display()))
    }

    /// Task 2a.1 oracle: the electra `get_beacon_proposer_index` must reproduce
    /// the `proposer_index` recorded in a real `operations/block_header` fixture
    /// block (the op runs at `pre.slot == block.slot`).
    #[test]
    fn compute_proposer_index_matches_block_header_fixture() {
        let root = match fixtures_root() {
            Some(r) => r,
            None => {
                eprintln!("electra helpers: no fixtures found; skipping proposer-index test");
                return;
            }
        };
        let case_dir =
            root.join("minimal/electra/operations/block_header/pyspec_tests/basic_block_header");
        if !case_dir.is_dir() {
            eprintln!("electra helpers: basic_block_header case absent; skipping");
            return;
        }

        let pre: MinimalBeaconState = load_ssz_snappy(&case_dir.join("pre.ssz_snappy"));
        let block: MinimalBeaconBlock = load_ssz_snappy(&case_dir.join("block.ssz_snappy"));

        let enum_state = MinimalEthSpec::electra_into_state(pre);
        let computed = get_beacon_proposer_index_electra::<MinimalEthSpec>(&enum_state);

        assert_eq!(
            computed, block.proposer_index,
            "electra compute_proposer_index ({computed:?}) != fixture block.proposer_index \
             ({:?})",
            block.proposer_index
        );
        eprintln!(
            "electra proposer-index fixture matched: proposer_index = {}",
            computed.0
        );
    }

    /// Task 2a.3 oracle: cross-committee `get_attesting_indices`. Build an
    /// attestation over the pre-state of a block_header fixture with the first
    /// two committee bits set and every aggregation bit in those two committees
    /// set; the result must equal the deduplicated union of both beacon
    /// committees, exercising the `committee_offset` accumulation.
    #[test]
    fn get_attesting_indices_cross_committee() {
        let root = match fixtures_root() {
            Some(r) => r,
            None => {
                eprintln!("electra helpers: no fixtures found; skipping attesting-indices test");
                return;
            }
        };
        let case_dir =
            root.join("minimal/electra/operations/block_header/pyspec_tests/basic_block_header");
        if !case_dir.is_dir() {
            eprintln!("electra helpers: basic_block_header case absent; skipping");
            return;
        }
        let pre: MinimalBeaconState = load_ssz_snappy(&case_dir.join("pre.ssz_snappy"));
        let enum_state = MinimalEthSpec::electra_into_state(pre);

        let slot = {
            use pharos_types::BeaconStateView;
            enum_state.slot()
        };

        let committees_per_slot = get_committee_count_per_slot::<MinimalEthSpec>(
            &enum_state,
            compute_epoch_at_slot(slot, MinimalEthSpec::SLOTS_PER_EPOCH),
        );
        // Need at least two committees for a meaningful cross-committee test.
        if committees_per_slot < 2 {
            eprintln!(
                "electra helpers: only {committees_per_slot} committee(s) this slot; \
                 skipping cross-committee assertion"
            );
            return;
        }

        let committee0 = get_beacon_committee::<MinimalEthSpec>(&enum_state, slot, 0);
        let committee1 = get_beacon_committee::<MinimalEthSpec>(&enum_state, slot, 1);
        let total_bits = committee0.len() + committee1.len();

        // committee_bits: bits 0 and 1 set.
        let mut committee_bits =
            Bitvector::<{ MinimalEthSpec::MAX_COMMITTEES_PER_SLOT }>::default();
        committee_bits.set(0, true);
        committee_bits.set(1, true);

        // aggregation_bits: all `total_bits` bits set (both committees fully attest).
        let mut agg =
            pharos_ssz::Bitlist::<{ MinimalEthSpec::MAX_AGGREGATION_BITS_ELECTRA }>::with_capacity(
                total_bits,
            );
        for _ in 0..total_bits {
            agg.push(true).unwrap();
        }

        let attestation: Attestation<
            { MinimalEthSpec::MAX_AGGREGATION_BITS_ELECTRA },
            { MinimalEthSpec::MAX_COMMITTEES_PER_SLOT },
        > = Attestation {
            aggregation_bits: agg,
            data: AttestationData {
                slot,
                ..Default::default()
            },
            signature: BLSSignature::default(),
            committee_bits,
        };

        let attesters = get_attesting_indices_electra::<
            { MinimalEthSpec::MAX_AGGREGATION_BITS_ELECTRA },
            { MinimalEthSpec::MAX_COMMITTEES_PER_SLOT },
            MinimalEthSpec,
        >(&enum_state, &attestation);

        let mut expected: Vec<ValidatorIndex> = committee0.clone();
        for v in &committee1 {
            if !expected.contains(v) {
                expected.push(*v);
            }
        }
        let mut got_sorted = attesters.clone();
        got_sorted.sort();
        let mut exp_sorted = expected.clone();
        exp_sorted.sort();
        assert_eq!(
            got_sorted, exp_sorted,
            "cross-committee attesting indices mismatch"
        );
        assert!(
            committee1.iter().any(|v| !committee0.contains(v)) || committee0 == committee1,
            "second committee should contribute attesters across the committee_offset boundary"
        );
    }

    /// Synthetic minimal electra state with two compounding validators, used to
    /// exercise the churn-as-balance accessors.
    fn synthetic_state() -> MinimalBeaconState {
        use pharos_ssz::SszSequence;
        use pharos_types::phase0::{Epoch as PEpoch, Validator};

        // `slot` defaults to 0, which is the value this synthetic state needs.
        let mut state = MinimalBeaconState::default();
        // Two active validators with 32 ETH effective balance each.
        for _ in 0..2 {
            let mut creds = [0u8; 32];
            creds[0] = 0x01;
            let v = Validator {
                withdrawal_credentials: Bytes32::from_array(creds),
                effective_balance: Gwei(32_000_000_000),
                activation_epoch: PEpoch(0),
                exit_epoch: PEpoch(FAR_FUTURE_EPOCH),
                withdrawable_epoch: PEpoch(FAR_FUTURE_EPOCH),
                ..Validator::default()
            };
            state.validators = state.validators.with_push(v).unwrap();
            state.balances = state.balances.with_push(Gwei(32_000_000_000)).unwrap();
        }
        state.earliest_exit_epoch = pharos_types::phase0::Epoch(0);
        state.exit_balance_to_consume = Gwei(0);
        state.earliest_consolidation_epoch = pharos_types::phase0::Epoch(0);
        state.consolidation_balance_to_consume = Gwei(0);
        state
    }

    /// Task 2a.4 oracle: churn-as-balance accessors against hand-computed minimal
    /// preset values. total_active = 64 ETH, total_active/CHURN_LIMIT_QUOTIENT(32)
    /// = 2 ETH < MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA (64 ETH), so balance churn =
    /// 64 ETH; activation_exit = min(128 ETH, 64 ETH) = 64 ETH; consolidation = 0.
    #[test]
    fn churn_accessors_minimal() {
        type C = ElectraConcreteState<
            { MinimalEthSpec::SLOTS_PER_HISTORICAL_ROOT },
            { MinimalEthSpec::HISTORICAL_ROOTS_LIMIT },
            { MinimalEthSpec::ETH1_DATA_VOTES_LIMIT },
            { MinimalEthSpec::VALIDATOR_REGISTRY_LIMIT },
            { MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR },
            { MinimalEthSpec::EPOCHS_PER_SLASHINGS_VECTOR },
            { MinimalEthSpec::JUSTIFICATION_BITS_LENGTH },
            { MinimalEthSpec::SYNC_COMMITTEE_SIZE },
            { MinimalEthSpec::BYTES_PER_LOGS_BLOOM },
            { MinimalEthSpec::MAX_EXTRA_DATA_BYTES },
            { MinimalEthSpec::MAX_PENDING_DEPOSITS_LIMIT },
            { MinimalEthSpec::MAX_PENDING_PARTIAL_WITHDRAWALS_LIMIT },
            { MinimalEthSpec::MAX_PENDING_CONSOLIDATIONS_LIMIT },
        >;

        fn balance_churn(state: &C) -> u64 {
            get_balance_churn_limit_electra::<
                { MinimalEthSpec::SLOTS_PER_HISTORICAL_ROOT },
                { MinimalEthSpec::HISTORICAL_ROOTS_LIMIT },
                { MinimalEthSpec::ETH1_DATA_VOTES_LIMIT },
                { MinimalEthSpec::VALIDATOR_REGISTRY_LIMIT },
                { MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR },
                { MinimalEthSpec::EPOCHS_PER_SLASHINGS_VECTOR },
                { MinimalEthSpec::JUSTIFICATION_BITS_LENGTH },
                { MinimalEthSpec::SYNC_COMMITTEE_SIZE },
                { MinimalEthSpec::BYTES_PER_LOGS_BLOOM },
                { MinimalEthSpec::MAX_EXTRA_DATA_BYTES },
                { MinimalEthSpec::MAX_PENDING_DEPOSITS_LIMIT },
                { MinimalEthSpec::MAX_PENDING_PARTIAL_WITHDRAWALS_LIMIT },
                { MinimalEthSpec::MAX_PENDING_CONSOLIDATIONS_LIMIT },
                MinimalEthSpec,
            >(state)
            .0
        }
        fn activation_exit_churn(state: &C) -> u64 {
            get_activation_exit_churn_limit_electra::<
                { MinimalEthSpec::SLOTS_PER_HISTORICAL_ROOT },
                { MinimalEthSpec::HISTORICAL_ROOTS_LIMIT },
                { MinimalEthSpec::ETH1_DATA_VOTES_LIMIT },
                { MinimalEthSpec::VALIDATOR_REGISTRY_LIMIT },
                { MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR },
                { MinimalEthSpec::EPOCHS_PER_SLASHINGS_VECTOR },
                { MinimalEthSpec::JUSTIFICATION_BITS_LENGTH },
                { MinimalEthSpec::SYNC_COMMITTEE_SIZE },
                { MinimalEthSpec::BYTES_PER_LOGS_BLOOM },
                { MinimalEthSpec::MAX_EXTRA_DATA_BYTES },
                { MinimalEthSpec::MAX_PENDING_DEPOSITS_LIMIT },
                { MinimalEthSpec::MAX_PENDING_PARTIAL_WITHDRAWALS_LIMIT },
                { MinimalEthSpec::MAX_PENDING_CONSOLIDATIONS_LIMIT },
                MinimalEthSpec,
            >(state)
            .0
        }
        fn consolidation_churn(state: &C) -> u64 {
            get_consolidation_churn_limit_electra::<
                { MinimalEthSpec::SLOTS_PER_HISTORICAL_ROOT },
                { MinimalEthSpec::HISTORICAL_ROOTS_LIMIT },
                { MinimalEthSpec::ETH1_DATA_VOTES_LIMIT },
                { MinimalEthSpec::VALIDATOR_REGISTRY_LIMIT },
                { MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR },
                { MinimalEthSpec::EPOCHS_PER_SLASHINGS_VECTOR },
                { MinimalEthSpec::JUSTIFICATION_BITS_LENGTH },
                { MinimalEthSpec::SYNC_COMMITTEE_SIZE },
                { MinimalEthSpec::BYTES_PER_LOGS_BLOOM },
                { MinimalEthSpec::MAX_EXTRA_DATA_BYTES },
                { MinimalEthSpec::MAX_PENDING_DEPOSITS_LIMIT },
                { MinimalEthSpec::MAX_PENDING_PARTIAL_WITHDRAWALS_LIMIT },
                { MinimalEthSpec::MAX_PENDING_CONSOLIDATIONS_LIMIT },
                MinimalEthSpec,
            >(state)
            .0
        }

        let state = synthetic_state();
        assert_eq!(balance_churn(&state), 64_000_000_000, "balance churn limit");
        assert_eq!(
            activation_exit_churn(&state),
            64_000_000_000,
            "activation/exit churn limit"
        );
        assert_eq!(consolidation_churn(&state), 0, "consolidation churn limit");

        // compute_exit_epoch_and_update_churn: exit a 32 ETH validator.
        let mut state = synthetic_state();
        let exit_epoch = compute_exit_epoch_and_update_churn_electra::<
            { MinimalEthSpec::SLOTS_PER_HISTORICAL_ROOT },
            { MinimalEthSpec::HISTORICAL_ROOTS_LIMIT },
            { MinimalEthSpec::ETH1_DATA_VOTES_LIMIT },
            { MinimalEthSpec::VALIDATOR_REGISTRY_LIMIT },
            { MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR },
            { MinimalEthSpec::EPOCHS_PER_SLASHINGS_VECTOR },
            { MinimalEthSpec::JUSTIFICATION_BITS_LENGTH },
            { MinimalEthSpec::SYNC_COMMITTEE_SIZE },
            { MinimalEthSpec::BYTES_PER_LOGS_BLOOM },
            { MinimalEthSpec::MAX_EXTRA_DATA_BYTES },
            { MinimalEthSpec::MAX_PENDING_DEPOSITS_LIMIT },
            { MinimalEthSpec::MAX_PENDING_PARTIAL_WITHDRAWALS_LIMIT },
            { MinimalEthSpec::MAX_PENDING_CONSOLIDATIONS_LIMIT },
            MinimalEthSpec,
        >(&mut state, Gwei(32_000_000_000));
        // earliest_exit_epoch = max(0, current_epoch+1+MAX_SEED_LOOKAHEAD)
        //                     = 0 + 1 + 4 = 5; 32 ETH < 64 ETH churn so fits.
        assert_eq!(
            exit_epoch.0,
            1 + MinimalEthSpec::MAX_SEED_LOOKAHEAD,
            "exit queue epoch"
        );
        assert_eq!(
            state.exit_balance_to_consume.0,
            64_000_000_000 - 32_000_000_000,
            "exit_balance_to_consume after consuming 32 ETH from a fresh 64 ETH epoch"
        );
    }

    /// Task 2a.4/2a.5 oracle: withdrawal-credential predicates + max effective
    /// balance, exercised with both 0x01 (eth1) and 0x02 (compounding) creds.
    #[test]
    fn withdrawal_credential_predicates() {
        use pharos_types::phase0::Validator;

        let mut eth1_creds = [0u8; 32];
        eth1_creds[0] = 0x01;
        let eth1_v = Validator {
            withdrawal_credentials: Bytes32::from_array(eth1_creds),
            effective_balance: Gwei(32_000_000_000),
            ..Validator::default()
        };

        let mut comp_creds = [0u8; 32];
        comp_creds[0] = 0x02;
        let comp_v = Validator {
            withdrawal_credentials: Bytes32::from_array(comp_creds),
            effective_balance: Gwei(2_048_000_000_000),
            ..Validator::default()
        };

        assert!(!has_compounding_withdrawal_credential::<MinimalEthSpec>(
            &eth1_v
        ));
        assert!(has_compounding_withdrawal_credential::<MinimalEthSpec>(
            &comp_v
        ));
        assert!(has_execution_withdrawal_credential::<MinimalEthSpec>(
            &eth1_v
        ));
        assert!(has_execution_withdrawal_credential::<MinimalEthSpec>(
            &comp_v
        ));

        assert_eq!(
            get_max_effective_balance::<MinimalEthSpec>(&eth1_v).0,
            MinimalEthSpec::MIN_ACTIVATION_BALANCE
        );
        assert_eq!(
            get_max_effective_balance::<MinimalEthSpec>(&comp_v).0,
            MinimalEthSpec::MAX_EFFECTIVE_BALANCE_ELECTRA
        );
    }

    /// Task 2a.1 unit: the 16-bit random-value path must accept a max-balance
    /// candidate immediately (effective_balance == MAX_EFFECTIVE_BALANCE_ELECTRA
    /// makes `eff * MAX_RANDOM_VALUE >= MAX_EB_ELECTRA * random_value` hold for
    /// every random_value <= MAX_RANDOM_VALUE).
    #[test]
    fn compute_proposer_index_single_max_balance_validator() {
        use pharos_ssz::SszSequence;
        use pharos_types::phase0::Validator;

        let mut state = MinimalBeaconState::default();
        let mut creds = [0u8; 32];
        creds[0] = 0x02;
        let v = Validator {
            withdrawal_credentials: Bytes32::from_array(creds),
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE_ELECTRA),
            activation_epoch: pharos_types::phase0::Epoch(0),
            exit_epoch: pharos_types::phase0::Epoch(FAR_FUTURE_EPOCH),
            ..Validator::default()
        };
        state.validators = state.validators.with_push(v).unwrap();
        state.balances = state
            .balances
            .with_push(Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE_ELECTRA))
            .unwrap();

        let enum_state = MinimalEthSpec::electra_into_state(state);
        let idx = get_beacon_proposer_index_electra::<MinimalEthSpec>(&enum_state);
        assert_eq!(idx.0, 0, "only validator must be the proposer");
    }

    // ── get_execution_requests_list ───────────────────────────────────────────

    type TestExecRequests = pharos_types::electra::requests::ExecutionRequests<
        { MinimalEthSpec::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD },
        { MinimalEthSpec::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD },
        { MinimalEthSpec::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD },
    >;

    #[test]
    fn execution_requests_all_empty_yields_empty_list() {
        let reqs = TestExecRequests::default();
        let list = get_execution_requests_list(&reqs);
        assert!(
            list.is_empty(),
            "all-empty execution_requests must produce []"
        );
    }

    #[test]
    fn execution_requests_one_deposit_encodes_correctly() {
        use pharos_ssz::{Encode, SszList};
        use pharos_types::electra::requests::DepositRequest;

        let mut reqs = TestExecRequests::default();
        let deposit = DepositRequest::default(); // all-zero, 192 SSZ bytes
        reqs.deposits = SszList::from_vec(vec![deposit.clone()]).unwrap();

        let list = get_execution_requests_list(&reqs);

        // Only the deposit entry (0x00) should appear; withdrawal + consolidation empty.
        assert_eq!(list.len(), 1, "one non-empty request type");
        let entry = &list[0];
        assert_eq!(
            entry[0], 0x00u8,
            "request type byte must be 0x00 for deposits"
        );

        // Payload bytes must be SSZ of a one-element list of DepositRequest.
        let expected_payload = {
            let tmp: SszList<DepositRequest, { MinimalEthSpec::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD }> =
                SszList::from_vec(vec![deposit]).unwrap();
            tmp.as_ssz_bytes()
        };
        assert_eq!(
            &entry[1..],
            expected_payload.as_slice(),
            "payload bytes must be SSZ-serialized deposit list"
        );
        // DepositRequest is 192 fixed bytes; one-element list has no offset table.
        assert_eq!(
            entry[1..].len(),
            192,
            "single DepositRequest = 192 SSZ bytes"
        );
    }

    #[test]
    fn execution_requests_all_types_correct_order() {
        use pharos_ssz::SszList;
        use pharos_types::electra::requests::{
            ConsolidationRequest, DepositRequest, WithdrawalRequest,
        };

        let reqs = TestExecRequests {
            deposits: SszList::from_vec(vec![DepositRequest::default()]).unwrap(),
            withdrawals: SszList::from_vec(vec![WithdrawalRequest::default()]).unwrap(),
            consolidations: SszList::from_vec(vec![ConsolidationRequest::default()]).unwrap(),
        };

        let list = get_execution_requests_list(&reqs);
        assert_eq!(list.len(), 3, "all three request types present");
        assert_eq!(list[0][0], 0x00u8, "deposits first");
        assert_eq!(list[1][0], 0x01u8, "withdrawals second");
        assert_eq!(list[2][0], 0x02u8, "consolidations third");
    }

    #[test]
    fn execution_requests_skip_empty_preserves_order() {
        use pharos_ssz::SszList;
        use pharos_types::electra::requests::ConsolidationRequest;

        // Only consolidations non-empty (deposits + withdrawals empty → skipped).
        let reqs = TestExecRequests {
            consolidations: SszList::from_vec(vec![ConsolidationRequest::default()]).unwrap(),
            ..TestExecRequests::default()
        };

        let list = get_execution_requests_list(&reqs);
        assert_eq!(list.len(), 1, "only consolidation entry");
        assert_eq!(list[0][0], 0x02u8, "type byte must be 0x02");
    }
}
