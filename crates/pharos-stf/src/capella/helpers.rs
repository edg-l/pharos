//! Capella beacon-state helper functions.
//!
//! Per `specs/capella/beacon-chain.md` — Helpers / Predicates section.
//!
//! Capella adds three withdrawal-credential predicates.  Beyond those,
//! it inherits all Bellatrix / Altair helpers.  This module also provides
//! state/block projection helpers that convert between the capella and
//! bellatrix / altair inner state types (capella state is a strict superset
//! of bellatrix state: same fields plus the three new withdrawal fields).

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    bellatrix::BeaconState as BellatrixBeaconState,
    capella::BeaconState,
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::phase0::{accessors::compute_epoch_at_slot, predicates::is_active_validator};

// ── Withdrawal-credential predicates ─────────────────────────────────────────

// ── Domain constants ──────────────────────────────────────────────────────────

/// `DOMAIN_BLS_TO_EXECUTION_CHANGE` per `specs/capella/beacon-chain.md`
/// (value `0x0A000000`). Single source of truth lives in `pharos_types::fork`;
/// re-exported here so the `pharos-stf` crate root can surface every `DOMAIN_*`.
pub use pharos_types::fork::DOMAIN_BLS_TO_EXECUTION_CHANGE;

// ── Withdrawal-credential predicates ─────────────────────────────────────────

/// First byte of an ETH1 ("0x01") withdrawal credential.
///
/// Per `specs/phase0/beacon-chain.md:203`:
///   `ETH1_ADDRESS_WITHDRAWAL_PREFIX = Bytes1('0x01')`.
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;

/// First byte of a BLS ("0x00") withdrawal credential.
///
/// Per `specs/phase0/beacon-chain.md:202`:
///   `BLS_WITHDRAWAL_PREFIX = Bytes1('0x00')`.
pub const BLS_WITHDRAWAL_PREFIX: u8 = 0x00;

/// `has_eth1_withdrawal_credential` per `specs/capella/beacon-chain.md`.
///
/// Returns `true` when `validator.withdrawal_credentials[0] == 0x01`.
pub fn has_eth1_withdrawal_credential(validator: &pharos_types::phase0::Validator) -> bool {
    validator.withdrawal_credentials.as_slice()[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
}

/// `is_fully_withdrawable_validator` per `specs/capella/beacon-chain.md`.
///
/// Returns `true` when the validator has ETH1 credentials, its
/// `withdrawable_epoch <= epoch`, and its `balance > 0`.
pub fn is_fully_withdrawable_validator(
    validator: &pharos_types::phase0::Validator,
    balance: Gwei,
    epoch: Epoch,
) -> bool {
    has_eth1_withdrawal_credential(validator)
        && validator.withdrawable_epoch.0 <= epoch.0
        && balance.0 > 0
}

/// `is_partially_withdrawable_validator` per `specs/capella/beacon-chain.md`.
///
/// Returns `true` when the validator has ETH1 credentials, its effective
/// balance equals `MAX_EFFECTIVE_BALANCE`, and its balance exceeds
/// `MAX_EFFECTIVE_BALANCE`.
pub fn is_partially_withdrawable_validator<E: EthSpec>(
    validator: &pharos_types::phase0::Validator,
    balance: Gwei,
) -> bool {
    has_eth1_withdrawal_credential(validator)
        && validator.effective_balance.0 == E::MAX_EFFECTIVE_BALANCE
        && balance.0 > E::MAX_EFFECTIVE_BALANCE
}

// ── Epoch helpers ─────────────────────────────────────────────────────────────

/// Return the current epoch for a capella `BeaconState`.
pub(crate) fn get_current_epoch_capella<
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
    >,
) -> Epoch {
    compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH)
}

/// `get_total_active_balance` for a capella `BeaconState`.
pub(crate) fn get_total_active_balance_capella<
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

/// `decrease_balance` for a capella `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:679-681`.
pub(crate) fn decrease_balance_capella<
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

/// `increase_balance` for a capella `BeaconState`.
///
/// Per `specs/phase0/beacon-chain.md:677-678`.
pub(crate) fn increase_balance_capella<
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

// ── State-projection helpers ──────────────────────────────────────────────────

/// Project a `capella::BeaconState` into an `altair::BeaconState` by
/// cloning the shared fields.
///
/// `latest_execution_payload_header`, `next_withdrawal_index`,
/// `next_withdrawal_validator_index`, and `historical_summaries` are
/// capella-only and not present in the altair state.
pub fn capella_state_to_altair<
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

/// Copy the shared fields from an `altair::BeaconState` back into a
/// `capella::BeaconState`. The capella-only fields are preserved.
pub fn update_capella_from_altair<
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
}

/// Partial update: copy by reference.
pub(crate) fn update_capella_from_altair_ref<
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
    >,
    altair: &AltairBeaconState<
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
    state.fork = altair.fork.clone();
    state.latest_block_header = altair.latest_block_header.clone();
    state.block_roots = altair.block_roots.clone();
    state.state_roots = altair.state_roots.clone();
    state.historical_roots = altair.historical_roots.clone();
    state.eth1_data = altair.eth1_data.clone();
    state.eth1_data_votes = altair.eth1_data_votes.clone();
    state.eth1_deposit_index = altair.eth1_deposit_index;
    state.validators = altair.validators.clone();
    state.balances = altair.balances.clone();
    state.randao_mixes = altair.randao_mixes.clone();
    state.slashings = altair.slashings.clone();
    state.previous_epoch_participation = altair.previous_epoch_participation.clone();
    state.current_epoch_participation = altair.current_epoch_participation.clone();
    state.justification_bits = altair.justification_bits.clone();
    state.previous_justified_checkpoint = altair.previous_justified_checkpoint.clone();
    state.current_justified_checkpoint = altair.current_justified_checkpoint.clone();
    state.finalized_checkpoint = altair.finalized_checkpoint.clone();
    state.inactivity_scores = altair.inactivity_scores.clone();
    state.current_sync_committee = altair.current_sync_committee.clone();
    state.next_sync_committee = altair.next_sync_committee.clone();
}

/// Project a `capella::BeaconState` to a `bellatrix::BeaconState` by
/// cloning the shared fields (including `latest_execution_payload_header`
/// converted from capella to bellatrix type by copying shared sub-fields).
///
/// Used to reuse bellatrix epoch sub-routines (slashings, rewards, etc.).
pub fn capella_state_to_bellatrix<
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
    >,
) -> BellatrixBeaconState<
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
    use pharos_types::bellatrix::ExecutionPayloadHeader as BellatrixHeader;

    // Convert capella ExecutionPayloadHeader → bellatrix ExecutionPayloadHeader
    // by copying all shared fields (bellatrix header has no `withdrawals_root`).
    let bel_header = BellatrixHeader {
        parent_hash: state.latest_execution_payload_header.parent_hash,
        fee_recipient: state.latest_execution_payload_header.fee_recipient,
        state_root: state.latest_execution_payload_header.state_root,
        receipts_root: state.latest_execution_payload_header.receipts_root,
        logs_bloom: state.latest_execution_payload_header.logs_bloom.clone(),
        prev_randao: state.latest_execution_payload_header.prev_randao,
        block_number: state.latest_execution_payload_header.block_number,
        gas_limit: state.latest_execution_payload_header.gas_limit,
        gas_used: state.latest_execution_payload_header.gas_used,
        timestamp: state.latest_execution_payload_header.timestamp,
        extra_data: state.latest_execution_payload_header.extra_data.clone(),
        base_fee_per_gas: state.latest_execution_payload_header.base_fee_per_gas,
        block_hash: state.latest_execution_payload_header.block_hash,
        transactions_root: state.latest_execution_payload_header.transactions_root,
    };

    BellatrixBeaconState {
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
        latest_execution_payload_header: bel_header,
        cached_root: pharos_utils::CachedRoot::default(),
    }
}

/// Copy the shared fields from a `bellatrix::BeaconState` back into a
/// `capella::BeaconState`. The capella-only fields and
/// `latest_execution_payload_header` are preserved in the capella state.
pub fn update_capella_from_bellatrix<
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
    >,
    bel: BellatrixBeaconState<
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
    state.genesis_time = bel.genesis_time;
    state.genesis_validators_root = bel.genesis_validators_root;
    state.slot = bel.slot;
    state.fork = bel.fork;
    state.latest_block_header = bel.latest_block_header;
    state.block_roots = bel.block_roots;
    state.state_roots = bel.state_roots;
    state.historical_roots = bel.historical_roots;
    state.eth1_data = bel.eth1_data;
    state.eth1_data_votes = bel.eth1_data_votes;
    state.eth1_deposit_index = bel.eth1_deposit_index;
    state.validators = bel.validators;
    state.balances = bel.balances;
    state.randao_mixes = bel.randao_mixes;
    state.slashings = bel.slashings;
    state.previous_epoch_participation = bel.previous_epoch_participation;
    state.current_epoch_participation = bel.current_epoch_participation;
    state.justification_bits = bel.justification_bits;
    state.previous_justified_checkpoint = bel.previous_justified_checkpoint;
    state.current_justified_checkpoint = bel.current_justified_checkpoint;
    state.finalized_checkpoint = bel.finalized_checkpoint;
    state.inactivity_scores = bel.inactivity_scores;
    state.current_sync_committee = bel.current_sync_committee;
    state.next_sync_committee = bel.next_sync_committee;
    // capella-only fields (latest_execution_payload_header, next_withdrawal_*,
    // historical_summaries) are intentionally NOT overwritten here — the bellatrix
    // projection does not carry them.
}

// ── initiate_validator_exit (capella) ─────────────────────────────────────────

/// `initiate_validator_exit` for a capella `BeaconState`.
///
/// Mirrors the bellatrix implementation; the capella state shares all
/// relevant validator-registry fields.
pub(crate) fn initiate_validator_exit_capella<
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
    >,
    index: ValidatorIndex,
) -> Result<(), crate::error::StateTransitionError> {
    use crate::phase0::helpers::FAR_FUTURE_EPOCH;

    {
        let exit_epoch_val = state
            .validators
            .get(index.0 as usize)
            .map(|v| v.exit_epoch.0);
        match exit_epoch_val {
            None => return Err(crate::error::StateTransitionError::SlotOutOfRange),
            Some(ep) if ep != FAR_FUTURE_EPOCH => return Ok(()),
            _ => {}
        }
    }

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let activation_exit_epoch =
        pharos_types::phase0::Epoch(current_epoch.0 + 1 + E::MAX_SEED_LOOKAHEAD);

    let exit_queue_epoch = {
        let max_existing = state
            .validators
            .iter()
            .filter(|v| v.exit_epoch.0 != FAR_FUTURE_EPOCH)
            .map(|v| v.exit_epoch.0)
            .max()
            .unwrap_or(0)
            .max(activation_exit_epoch.0);
        pharos_types::phase0::Epoch(max_existing)
    };

    let churn_limit = {
        let active_count = state
            .validators
            .iter()
            .filter(|v| is_active_validator(v, current_epoch.0))
            .count() as u64;
        (active_count / E::CHURN_LIMIT_QUOTIENT).max(E::MIN_PER_EPOCH_CHURN_LIMIT)
    };

    let exit_queue_churn = state
        .validators
        .iter()
        .filter(|v| v.exit_epoch == exit_queue_epoch)
        .count() as u64;

    let final_exit_epoch = if exit_queue_churn >= churn_limit {
        pharos_types::phase0::Epoch(exit_queue_epoch.0 + 1)
    } else {
        exit_queue_epoch
    };

    let withdrawable_epoch_raw = final_exit_epoch
        .0
        .checked_add(E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
        .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?;

    let mut v = state
        .validators
        .get(index.0 as usize)
        .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?
        .clone();
    v.exit_epoch = final_exit_epoch;
    v.withdrawable_epoch = pharos_types::phase0::Epoch(withdrawable_epoch_raw);
    v.invalidate_cache();
    state.validators = state
        .validators
        .with_set(index.0 as usize, v)
        .map_err(crate::error::StateTransitionError::Ssz)?;

    Ok(())
}

// ── slash_validator (capella) ─────────────────────────────────────────────────

/// `slash_validator` for Capella.
///
/// Identical to the bellatrix version (uses `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`).
/// Capella makes no changes to the slashing logic.
pub(crate) fn slash_validator_capella<
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
    >,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
) -> Result<(), crate::error::StateTransitionError>
where
    E: EthSpec<
        CapellaBeaconState = BeaconState<
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
    >,
{
    use crate::altair::helpers::{PROPOSER_WEIGHT, get_proposer_index_altair};

    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    initiate_validator_exit_capella::<
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
        E,
    >(state, slashed_index)?;

    let (effective_balance, current_withdrawable_epoch) = {
        let v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?;
        (v.effective_balance, v.withdrawable_epoch)
    };

    let new_withdrawable_epoch = pharos_types::phase0::Epoch(
        current_withdrawable_epoch
            .0
            .max(epoch.0 + E::EPOCHS_PER_SLASHINGS_VECTOR),
    );

    {
        let mut v = state
            .validators
            .get(slashed_index.0 as usize)
            .ok_or(crate::error::StateTransitionError::SlotOutOfRange)?
            .clone();
        v.slashed = true;
        v.withdrawable_epoch = new_withdrawable_epoch;
        v.invalidate_cache();
        state.validators = state
            .validators
            .with_set(slashed_index.0 as usize, v)
            .map_err(crate::error::StateTransitionError::Ssz)?;
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
        .map_err(crate::error::StateTransitionError::Ssz)?;

    // Capella inherits bellatrix's penalty quotient.
    let penalty = Gwei(effective_balance.0 / E::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX);
    decrease_balance_capella::<
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
    >(state, slashed_index, penalty);

    // Proposer reward via altair projection (reads only shared fields).
    let altair_state = capella_state_to_altair(state);
    let proposer_index = get_proposer_index_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair_state);

    let whistleblower_idx = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = Gwei(effective_balance.0 / E::WHISTLEBLOWER_REWARD_QUOTIENT);
    let proposer_reward = Gwei(whistleblower_reward.0 * PROPOSER_WEIGHT / E::WEIGHT_DENOMINATOR);

    increase_balance_capella::<
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
    >(state, proposer_index, proposer_reward);
    increase_balance_capella::<
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
    >(
        state,
        whistleblower_idx,
        Gwei(whistleblower_reward.0 - proposer_reward.0),
    );

    Ok(())
}

// ── get_inactivity_penalty_deltas (capella) ───────────────────────────────────

/// `get_inactivity_penalty_deltas` for Capella.
///
/// Capella uses `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` (unchanged from
/// Bellatrix). Delegates to the altair implementation via projection.
pub fn get_inactivity_penalty_deltas_capella<
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
    E,
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
    >,
) -> (Vec<Gwei>, Vec<Gwei>)
where
    E: EthSpec<
            AltairBeaconState = AltairBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            CapellaBeaconState = BeaconState<
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
        >,
{
    use pharos_types::altair::constants::TIMELY_TARGET_FLAG_INDEX;

    use crate::altair::helpers::{
        get_eligible_validator_indices, get_unslashed_participating_indices,
    };

    let altair = capella_state_to_altair(state);
    let n = state.validators.len();
    let rewards = vec![Gwei(0); n];
    let mut penalties = vec![Gwei(0); n];

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let previous_epoch = if current_epoch.0 == 0 {
        Epoch(0)
    } else {
        Epoch(current_epoch.0 - 1)
    };

    let matching_target = get_unslashed_participating_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair, TIMELY_TARGET_FLAG_INDEX, previous_epoch);

    let matching_set: std::collections::HashSet<u64> =
        matching_target.iter().map(|v| v.0).collect();

    let eligible = get_eligible_validator_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair);

    for index in &eligible {
        if !matching_set.contains(&index.0) {
            let effective_balance = state
                .validators
                .get(index.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0);
            let inactivity_score = state
                .inactivity_scores
                .as_slice()
                .get(index.0 as usize)
                .copied()
                .unwrap_or(0);
            let penalty_numerator = effective_balance * inactivity_score;
            let penalty_denominator =
                E::INACTIVITY_SCORE_BIAS * E::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
            penalties[index.0 as usize].0 += penalty_numerator / penalty_denominator;
        }
    }

    (rewards, penalties)
}
