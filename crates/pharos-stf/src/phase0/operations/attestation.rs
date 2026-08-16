//! `process_attestation` per `specs/phase0/beacon-chain.md:2004-2086`.

use pharos_types::{
    BeaconSpec, BeaconStateView,
    phase0::{Attestation, PendingAttestation},
    views::BeaconBlockBodyView,
};

use pharos_ssz::SszSequence;

use crate::error::{AttestationInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::{
        compute_epoch_at_slot, get_beacon_committee, get_beacon_proposer_index,
        get_committee_count_per_slot, get_current_epoch, get_indexed_attestation,
        get_previous_epoch,
    },
    predicates::is_valid_indexed_attestation,
    state_write::BeaconStateWrite,
};

/// `process_attestation` per `specs/phase0/beacon-chain.md:2004-2086`.
pub fn process_attestation<E: BeaconSpec>(
    state: &mut E::BeaconState,
    attestation: &Attestation<2048>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let data = &attestation.data;

    let current_epoch = get_current_epoch::<E>(state);
    let previous_epoch = get_previous_epoch::<E>(state);

    // Slot must be within [previous epoch start, current epoch end).
    let min_slot = previous_epoch.start_slot(E::SLOTS_PER_EPOCH);
    let max_slot_incl = current_epoch
        .start_slot(E::SLOTS_PER_EPOCH)
        .0
        .saturating_add(E::SLOTS_PER_EPOCH - 1);

    if data.slot < min_slot {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooOld,
        });
    }
    if data.slot.0 > max_slot_incl {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooNew,
        });
    }

    // Inclusion delay: MIN_ATTESTATION_INCLUSION_DELAY <= state.slot - data.slot <= SLOTS_PER_EPOCH.
    if state.slot().0 < data.slot.0 + E::MIN_ATTESTATION_INCLUSION_DELAY {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooNew,
        });
    }
    if state.slot().0 > data.slot.0 + E::SLOTS_PER_EPOCH {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooOld,
        });
    }

    // Target epoch must match data.slot's epoch.
    let slot_epoch = compute_epoch_at_slot(data.slot, E::SLOTS_PER_EPOCH);
    if data.target.epoch != slot_epoch {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::TargetEpochMismatch,
        });
    }

    // Target epoch must be current or previous.
    if data.target.epoch != current_epoch && data.target.epoch != previous_epoch {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::TargetEpochMismatch,
        });
    }

    // Committee index must be in range.
    let committee_count = get_committee_count_per_slot::<E>(state, data.target.epoch);
    if data.index.0 >= committee_count {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::CommitteeIndexOutOfRange,
        });
    }

    // Aggregation bits length must match committee size.
    let committee = get_beacon_committee::<E>(state, data.slot, data.index.0);
    if attestation.aggregation_bits.len() != committee.len() {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::AggregationBitsLengthMismatch,
        });
    }

    // Source must match justified checkpoint for target epoch.
    if data.target.epoch == current_epoch {
        if data.source != *state.current_justified_checkpoint() {
            return Err(StateTransitionError::InvalidAttestation {
                reason: AttestationInvalidReason::InvalidSourceCheckpoint,
            });
        }
    } else if data.source != *state.previous_justified_checkpoint() {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::InvalidSourceCheckpoint,
        });
    }

    // Verify signature via indexed attestation.
    let indexed = get_indexed_attestation::<E>(state, attestation);
    if indexed.attesting_indices.is_empty() {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::EmptyAttestingIndices,
        });
    }
    if !is_valid_indexed_attestation::<E>(state, &indexed, verify_signatures) {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::InvalidSignature,
        });
    }

    let proposer_index = get_beacon_proposer_index::<E>(state);
    let inclusion_delay = pharos_types::phase0::Slot(state.slot().0 - data.slot.0);

    let pending = PendingAttestation {
        aggregation_bits: attestation.aggregation_bits.clone(),
        data: data.clone(),
        inclusion_delay,
        proposer_index,
    };

    if data.target.epoch == current_epoch {
        state.push_current_epoch_attestation(pending)?;
    } else {
        state.push_previous_epoch_attestation(pending)?;
    }

    Ok(())
}
