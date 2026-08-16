//! `process_proposer_slashing` for Capella.
//!
//! Identical logic to Bellatrix; calls `slash_validator_capella` which uses
//! `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`.

use pharos_ssz::SszSequence;
use pharos_types::{BeaconSpec, capella::BeaconState, phase0::ProposerSlashing};

use crate::capella::helpers::slash_validator_capella;
use crate::error::{ProposerSlashingInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::compute_epoch_at_slot, helpers::DOMAIN_BEACON_PROPOSER,
    predicates::is_slashable_validator,
};

/// `process_proposer_slashing` for Capella.
pub fn process_proposer_slashing_capella<
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
    slashing: &ProposerSlashing,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
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
    let header_1 = &slashing.signed_header_1.message;
    let header_2 = &slashing.signed_header_2.message;

    if header_1.slot != header_2.slot {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::SlotMismatch,
        });
    }

    if header_1.proposer_index != header_2.proposer_index {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::ProposerIndexMismatch,
        });
    }

    if header_1 == header_2 {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::HeadersIdentical,
        });
    }

    let proposer_idx = header_1.proposer_index;
    let proposer = state
        .validators
        .get(proposer_idx.0 as usize)
        .ok_or(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::ValidatorNotSlashable,
        })?
        .clone();

    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    if !is_slashable_validator(&proposer, epoch.0) {
        return Err(StateTransitionError::InvalidProposerSlashing {
            reason: ProposerSlashingInvalidReason::ValidatorNotSlashable,
        });
    }

    if verify_signatures {
        for signed_header in [&slashing.signed_header_1, &slashing.signed_header_2] {
            let slot_epoch = compute_epoch_at_slot(signed_header.message.slot, E::SLOTS_PER_EPOCH);
            let domain = {
                use crate::phase0::accessors::compute_domain;
                let fork_version = if slot_epoch < state.fork.epoch {
                    state.fork.previous_version.into_inner()
                } else {
                    state.fork.current_version.into_inner()
                };
                compute_domain(
                    DOMAIN_BEACON_PROPOSER,
                    fork_version,
                    &state.genesis_validators_root,
                )
            };
            use pharos_ssz::TreeHash;
            use pharos_types::phase0::SigningData;
            let signing_root = SigningData {
                object_root: signed_header.message.tree_hash_root(),
                domain,
            }
            .tree_hash_root();
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

    slash_validator_capella::<
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
    >(state, proposer_idx, None)
}
