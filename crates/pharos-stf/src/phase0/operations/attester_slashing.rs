//! `process_attester_slashing` per `specs/phase0/beacon-chain.md:1985-2002`.

use pharos_types::{BeaconStateView, EthSpec, phase0::AttesterSlashing};

use crate::error::{AttesterSlashingInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::get_current_epoch,
    mutators::slash_validator,
    predicates::{
        is_slashable_attestation_data, is_slashable_validator, is_valid_indexed_attestation,
    },
    state_write::BeaconStateWrite,
};

/// `process_attester_slashing` per `specs/phase0/beacon-chain.md:1985-2002`.
pub fn process_attester_slashing<E: EthSpec>(
    state: &mut E::BeaconState,
    slashing: &AttesterSlashing<2048>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    let att1 = &slashing.attestation_1;
    let att2 = &slashing.attestation_2;

    // Verify attestations are slashable.
    if !is_slashable_attestation_data(&att1.data, &att2.data) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::AttestationsNotSlashable,
        });
    }

    // Verify both indexed attestations are valid.
    if !is_valid_indexed_attestation::<E>(state, att1, verify_signatures) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::InvalidIndexedAttestation,
        });
    }
    if !is_valid_indexed_attestation::<E>(state, att2, verify_signatures) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::InvalidIndexedAttestation,
        });
    }

    // Intersect attesting indices and slash each slashable one.
    let indices1 = att1.attesting_indices.as_slice();
    let indices2 = att2.attesting_indices.as_slice();

    let epoch = get_current_epoch::<E>(state);

    // Both index lists are sorted (validated by is_valid_indexed_attestation).
    let mut intersection: Vec<pharos_types::phase0::ValidatorIndex> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < indices1.len() && j < indices2.len() {
        match indices1[i].0.cmp(&indices2[j].0) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                intersection.push(indices1[i]);
                i += 1;
                j += 1;
            }
        }
    }

    let mut slashed_any = false;
    for index in &intersection {
        let is_slashable = state
            .validators()
            .get(index.0 as usize)
            .map(|v| is_slashable_validator(v, epoch.0))
            .unwrap_or(false);
        if is_slashable {
            slash_validator::<E>(state, *index, None)?;
            slashed_any = true;
        }
    }

    if !slashed_any {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::NoSlashableIndices,
        });
    }

    Ok(())
}
