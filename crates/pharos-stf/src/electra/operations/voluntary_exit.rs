//! `process_voluntary_exit` for Electra (EIP-7251 + EIP-7044).
//!
//! Per `specs/electra/beacon-chain.md:1706-1727`.
//!
//! EIP-7251 adds an assertion that the validator has no pending balance to
//! withdraw (`get_pending_balance_to_withdraw(state, index) == 0`). EIP-7044
//! (carried from Deneb) computes the signing domain with a fixed
//! `CAPELLA_FORK_VERSION` regardless of the current state fork. Exit initiation
//! routes through `initiate_validator_exit_electra` (churn-as-balance).

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec, config::RuntimeConfig, electra::BeaconState, phase0::SignedVoluntaryExit,
};

use crate::electra::helpers::{
    get_pending_balance_to_withdraw_electra, initiate_validator_exit_electra,
};
use crate::error::{StateTransitionError, VoluntaryExitInvalidReason};
use crate::phase0::{
    accessors::{compute_domain, compute_epoch_at_slot},
    helpers::{DOMAIN_VOLUNTARY_EXIT, FAR_FUTURE_EPOCH},
    predicates::is_active_validator,
};

/// `process_voluntary_exit` for Electra (EIP-7251 + EIP-7044).
///
/// Per `specs/electra/beacon-chain.md:1706-1727`.
#[allow(clippy::too_many_arguments)]
pub fn process_voluntary_exit_electra<
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
    signed_exit: &SignedVoluntaryExit,
    verify_signatures: bool,
    runtime_cfg: &RuntimeConfig,
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
    let exit = &signed_exit.message;
    let validator = state
        .validators
        .get(exit.validator_index.0 as usize)
        .ok_or(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::ValidatorNotActive,
        })?
        .clone();

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // Verify validator is active.
    if !is_active_validator(&validator, current_epoch.0) {
        return Err(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::ValidatorNotActive,
        });
    }

    // Verify exit has not been initiated.
    if validator.exit_epoch.0 != FAR_FUTURE_EPOCH {
        return Err(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::ExitAlreadyInitiated,
        });
    }

    // Exits must specify an epoch when they become valid.
    if current_epoch < exit.epoch {
        return Err(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::EpochTooEarly,
        });
    }

    // Verify the validator has been active long enough.
    if current_epoch.0 < validator.activation_epoch.0 + E::SHARD_COMMITTEE_PERIOD {
        return Err(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::InsufficientActiveEpochs,
        });
    }

    // [New in Electra:EIP7251] Only exit validator if it has no pending
    // withdrawals in the queue.
    let pending_balance = get_pending_balance_to_withdraw_electra::<
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
    >(state, exit.validator_index);
    if pending_balance.0 != 0 {
        return Err(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::ValidatorNotActive,
        });
    }

    // EIP-7044: Verify signature with CAPELLA_FORK_VERSION regardless of state fork.
    if verify_signatures {
        let domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            runtime_cfg.capella_fork_version,
            &state.genesis_validators_root,
        );
        use pharos_ssz::TreeHash;
        use pharos_types::phase0::SigningData;
        let signing_root = SigningData {
            object_root: exit.tree_hash_root(),
            domain,
        }
        .tree_hash_root();
        let valid = pharos_utils::bls::verify(
            &validator.pubkey,
            signing_root.as_slice(),
            &signed_exit.signature,
        )
        .unwrap_or(false);
        if !valid {
            return Err(StateTransitionError::InvalidVoluntaryExit {
                reason: VoluntaryExitInvalidReason::InvalidSignature,
            });
        }
    }

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
    >(state, exit.validator_index)
}
