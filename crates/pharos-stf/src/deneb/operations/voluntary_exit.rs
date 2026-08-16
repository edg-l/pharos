//! `process_voluntary_exit` for Deneb (EIP-7044).
//!
//! Per `specs/deneb/beacon-chain.md:510-513`.
//!
//! EIP-7044: voluntary exits use a fixed signing domain computed with
//! `CAPELLA_FORK_VERSION` regardless of the current state fork. This makes
//! exits signed during Capella valid forever in subsequent forks.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec, config::RuntimeConfig, deneb::BeaconState, phase0::SignedVoluntaryExit,
};

use crate::deneb::helpers::initiate_validator_exit_deneb;
use crate::error::{StateTransitionError, VoluntaryExitInvalidReason};
use crate::phase0::{
    accessors::{compute_domain, compute_epoch_at_slot},
    helpers::{DOMAIN_VOLUNTARY_EXIT, FAR_FUTURE_EPOCH},
    predicates::is_active_validator,
};

/// `process_voluntary_exit` for Deneb (EIP-7044).
///
/// Identical to the Capella version except the signing domain is always
/// computed with `CAPELLA_FORK_VERSION` per EIP-7044, making exits signed
/// during Capella valid across all subsequent forks.
#[allow(clippy::too_many_arguments)]
pub fn process_voluntary_exit<
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
    signed_exit: &SignedVoluntaryExit,
    verify_signatures: bool,
    runtime_cfg: &RuntimeConfig,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
        DenebBeaconState = BeaconState<
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

    initiate_validator_exit_deneb::<
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
    >(state, exit.validator_index)
}
