//! `upgrade_to_electra` fork transition.
//!
//! Per `specs/electra/fork.md:42-143` → `upgrade_to_electra`.
//!
//! Converts a deneb `BeaconState` into an electra `BeaconState`:
//!
//! 1. Copy all shared fields verbatim (execution-payload header is byte-identical).
//! 2. Seed the EIP-7251 electra-only scalars: `deposit_requests_start_index =
//!    UNSET`, `deposit_balance_to_consume = 0`, `earliest_exit_epoch` (max of
//!    `compute_activation_exit_epoch(epoch)` and any existing validator exit
//!    epoch, plus one), `earliest_consolidation_epoch =
//!    compute_activation_exit_epoch(epoch)`, empty pending queues.
//! 3. **R10 ordering**: seed `exit_balance_to_consume` /
//!    `consolidation_balance_to_consume` from the churn limits (which read
//!    `get_total_active_balance(post)`) BEFORE the pre-activation queue walk.
//! 4. Queue pre-activation validators (sorted by `(activation_eligibility_epoch,
//!    index)`) as `PendingDeposit`s, zeroing their balance / effective balance /
//!    activation_eligibility_epoch.
//! 5. Queue any compounding-credential validators' excess balance as
//!    `PendingDeposit`s (`queue_excess_active_balance`).

use pharos_ssz::{SszSequence, SszVector};
use pharos_types::{
    EthSpec,
    config::RuntimeConfig,
    deneb::BeaconState as DenebBeaconState,
    electra::{BeaconState as ElectraBeaconState, requests::PendingDeposit},
    phase0::{Epoch, Fork, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::electra::helpers::{
    get_activation_exit_churn_limit_electra, get_consolidation_churn_limit_electra,
    has_compounding_withdrawal_credential, queue_excess_active_balance_electra,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::{compute_activation_exit_epoch, compute_epoch_at_slot};
use crate::phase0::helpers::FAR_FUTURE_EPOCH;

/// `upgrade_to_electra` per `specs/electra/fork.md:42-143`.
#[allow(clippy::type_complexity)]
pub fn upgrade_to_electra<
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
    pre: DenebBeaconState<
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
    runtime_cfg: &RuntimeConfig,
) -> Result<
    ElectraBeaconState<
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
    StateTransitionError,
>
where
    E: EthSpec<
            DenebBeaconState = DenebBeaconState<
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
            ElectraBeaconState = ElectraBeaconState<
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
    pharos_utils::BLSPubkey: Default + Clone,
{
    let epoch = compute_epoch_at_slot(pre.slot, E::SLOTS_PER_EPOCH);

    // earliest_exit_epoch = max(compute_activation_exit_epoch(epoch), max
    // existing validator exit_epoch) + 1.
    let mut earliest_exit_epoch = compute_activation_exit_epoch(epoch, E::MAX_SEED_LOOKAHEAD);
    for validator in pre.validators.iter() {
        if validator.exit_epoch.0 != FAR_FUTURE_EPOCH && validator.exit_epoch > earliest_exit_epoch
        {
            earliest_exit_epoch = validator.exit_epoch;
        }
    }
    earliest_exit_epoch = Epoch(earliest_exit_epoch.0 + 1);

    let earliest_consolidation_epoch = compute_activation_exit_epoch(epoch, E::MAX_SEED_LOOKAHEAD);

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: pharos_utils::Bytes4::from_array(runtime_cfg.electra_fork_version),
        epoch,
    };

    let mut post = ElectraBeaconState {
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork,
        latest_block_header: pre.latest_block_header,
        block_roots: pre.block_roots,
        state_roots: pre.state_roots,
        historical_roots: pre.historical_roots,
        eth1_data: pre.eth1_data,
        eth1_data_votes: pre.eth1_data_votes,
        eth1_deposit_index: pre.eth1_deposit_index,
        validators: pre.validators,
        balances: pre.balances,
        randao_mixes: pre.randao_mixes,
        slashings: pre.slashings,
        previous_epoch_participation: pre.previous_epoch_participation,
        current_epoch_participation: pre.current_epoch_participation,
        justification_bits: pre.justification_bits,
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: pre.inactivity_scores,
        current_sync_committee: pre.current_sync_committee,
        next_sync_committee: pre.next_sync_committee,
        latest_execution_payload_header: pre.latest_execution_payload_header,
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries,
        // [New in Electra:EIP6110]
        deposit_requests_start_index: E::UNSET_DEPOSIT_REQUESTS_START_INDEX,
        // [New in Electra:EIP7251] — seeded to 0 here, filled below (R10).
        deposit_balance_to_consume: Gwei(0),
        exit_balance_to_consume: Gwei(0),
        earliest_exit_epoch,
        consolidation_balance_to_consume: Gwei(0),
        earliest_consolidation_epoch,
        pending_deposits: pharos_ssz::SszList::default(),
        pending_partial_withdrawals: pharos_ssz::SszList::default(),
        pending_consolidations: pharos_ssz::SszList::default(),
        cached_root: pharos_utils::CachedRoot::default(),
    };

    // R10: seed churn balances from the churn limits BEFORE the queue walk.
    // The churn limits read `get_total_active_balance(post)`, which must reflect
    // the still-untouched validator balances.
    post.exit_balance_to_consume = get_activation_exit_churn_limit_electra::<
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
    >(&post);
    post.consolidation_balance_to_consume = get_consolidation_churn_limit_electra::<
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
    >(&post);

    // [New in Electra:EIP7251] queue pre-activation validators sorted by
    // (activation_eligibility_epoch, index).
    let mut pre_activation: Vec<usize> = post
        .validators
        .iter()
        .enumerate()
        .filter(|(_, v)| v.activation_epoch.0 == FAR_FUTURE_EPOCH)
        .map(|(idx, _)| idx)
        .collect();
    pre_activation.sort_by_key(|&idx| {
        let v = post.validators.get(idx).expect("index in range");
        (v.activation_eligibility_epoch.0, idx)
    });

    // bls.G2_POINT_AT_INFINITY signature placeholder (0xc0 || zeros).
    let mut sig_bytes = [0u8; 96];
    sig_bytes[0] = 0xc0;

    for index in pre_activation {
        let balance = post
            .balances
            .as_slice()
            .get(index)
            .copied()
            .unwrap_or(Gwei(0));
        post.balances = post
            .balances
            .with_set(index, Gwei(0))
            .map_err(StateTransitionError::Ssz)?;

        let mut validator = post
            .validators
            .get(index)
            .ok_or(StateTransitionError::SlotOutOfRange)?
            .clone();
        let (pubkey, withdrawal_credentials) = (validator.pubkey, validator.withdrawal_credentials);
        validator.effective_balance = Gwei(0);
        validator.activation_eligibility_epoch = Epoch(FAR_FUTURE_EPOCH);
        validator.invalidate_cache();
        post.validators = post
            .validators
            .with_set(index, validator)
            .map_err(StateTransitionError::Ssz)?;

        let pending = PendingDeposit {
            pubkey: SszVector::from_vec(pubkey.as_slice().to_vec()).expect("pubkey is 48 bytes"),
            withdrawal_credentials: withdrawal_credentials.into_inner(),
            amount: balance,
            signature: SszVector::from_vec(sig_bytes.to_vec()).expect("signature is 96 bytes"),
            slot: pharos_types::phase0::Slot(0),
        };
        post.pending_deposits = post
            .pending_deposits
            .with_push(pending)
            .map_err(StateTransitionError::Ssz)?;
    }

    // [New in Electra:EIP7251] early adopters of compounding credentials go
    // through the activation churn.
    let compounding_indices: Vec<usize> = post
        .validators
        .iter()
        .enumerate()
        .filter(|(_, v)| has_compounding_withdrawal_credential::<E>(v))
        .map(|(idx, _)| idx)
        .collect();
    for index in compounding_indices {
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
        >(&mut post, ValidatorIndex(index as u64))?;
    }

    Ok(post)
}
