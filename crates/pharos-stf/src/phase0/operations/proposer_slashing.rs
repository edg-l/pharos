//! `process_proposer_slashing` per `specs/phase0/beacon-chain.md:1958-1983`.

use pharos_types::{BeaconStateView, EthSpec, phase0::ProposerSlashing};

use crate::error::{ProposerSlashingInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::{compute_epoch_at_slot, compute_signing_root, get_current_epoch, get_domain},
    helpers::DOMAIN_BEACON_PROPOSER,
    mutators::slash_validator,
    predicates::is_slashable_validator,
    state_write::BeaconStateWrite,
};

/// `process_proposer_slashing` per `specs/phase0/beacon-chain.md:1958-1983`.
pub fn process_proposer_slashing<E: EthSpec>(
    state: &mut E::BeaconState,
    slashing: &ProposerSlashing,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    let header_1 = &slashing.signed_header_1.message;
    let header_2 = &slashing.signed_header_2.message;

    // Verify header slots match.
    if header_1.slot != header_2.slot {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::SlotMismatch,
        });
    }

    // Verify header proposer indices match.
    if header_1.proposer_index != header_2.proposer_index {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::ProposerIndexMismatch,
        });
    }

    // Verify headers are different.
    if header_1 == header_2 {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::HeadersIdentical,
        });
    }

    // Verify proposer is slashable.
    let proposer_idx = header_1.proposer_index;
    let proposer = state
        .validators()
        .get(proposer_idx.0 as usize)
        .ok_or(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::ValidatorNotSlashable,
        })?
        .clone();

    let epoch = get_current_epoch::<E>(state);
    if !is_slashable_validator(&proposer, epoch.0) {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::ValidatorNotSlashable,
        });
    }

    // Verify signatures on both headers.
    if verify_signatures {
        for signed_header in [&slashing.signed_header_1, &slashing.signed_header_2] {
            let slot_epoch = compute_epoch_at_slot(signed_header.message.slot, E::SLOTS_PER_EPOCH);
            let domain = get_domain::<E>(state, DOMAIN_BEACON_PROPOSER, Some(slot_epoch));
            let signing_root = compute_signing_root(&signed_header.message, domain);
            let valid = pharos_utils::bls::verify(
                &proposer.pubkey,
                signing_root.as_slice(),
                &signed_header.signature,
            )
            .unwrap_or(false);
            if !valid {
                return Err(StateTransitionError::InvalidProposerSlashing {
                    reason: ProposerSlashingInvalidReason::InvalidSignature,
                });
            }
        }
    }

    slash_validator::<E>(state, proposer_idx, None)
}
