//! `process_voluntary_exit` per `specs/phase0/beacon-chain.md:2114-2130`.

use pharos_types::{BeaconSpec, BeaconStateView, phase0::SignedVoluntaryExit};

use crate::error::{StateTransitionError, VoluntaryExitInvalidReason};
use crate::phase0::{
    accessors::{compute_signing_root, get_current_epoch, get_domain},
    helpers::{DOMAIN_VOLUNTARY_EXIT, FAR_FUTURE_EPOCH},
    mutators::initiate_validator_exit,
    predicates::is_active_validator,
    state_write::BeaconStateWrite,
};

/// `process_voluntary_exit` per `specs/phase0/beacon-chain.md:2114-2130`.
pub fn process_voluntary_exit<E: BeaconSpec>(
    state: &mut E::BeaconState,
    signed_exit: &SignedVoluntaryExit,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    let exit = &signed_exit.message;
    let validator = state
        .validator(exit.validator_index.0 as usize)
        .ok_or(StateTransitionError::InvalidVoluntaryExit {
            reason: VoluntaryExitInvalidReason::ValidatorNotActive,
        })?
        .clone();

    let current_epoch = get_current_epoch::<E>(state);

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

    // Verify signature.
    if verify_signatures {
        let domain = get_domain::<E>(state, DOMAIN_VOLUNTARY_EXIT, Some(exit.epoch));
        let signing_root = compute_signing_root(exit, domain);
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

    initiate_validator_exit::<E>(state, exit.validator_index)
}
