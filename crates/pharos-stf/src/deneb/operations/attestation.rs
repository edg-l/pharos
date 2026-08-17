//! `process_attestation` for Deneb (EIP-7045).
//!
//! Per `specs/deneb/beacon-chain.md` Block processing.
//!
//! EIP-7045: the upper slot bound
//! `state.slot <= data.slot + SLOTS_PER_EPOCH` is dropped. Attestations are
//! valid as long as they reference the previous or current epoch target,
//! regardless of inclusion distance.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    deneb::BeaconState,
    phase0::{Attestation, Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::altair::helpers::{
    PROPOSER_WEIGHT, get_attestation_participation_flag_indices, get_base_reward_per_increment,
    get_proposer_index_altair,
};
use crate::altair::operations::attestation::{
    accumulate_attestation_participation_altair, get_beacon_committee_altair,
    get_committee_count_per_slot_altair,
};
use crate::deneb::helpers::{
    deneb_state_to_altair, increase_balance_deneb, update_deneb_from_altair_ref,
};
use crate::error::{AttestationInvalidReason, StateTransitionError};
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_attestation` (modified in Deneb, EIP-7045) per
/// `specs/deneb/beacon-chain.md`.
///
/// Same as Altair/Capella except the upper slot bound
/// `state.slot <= data.slot + SLOTS_PER_EPOCH` is removed (EIP-7045):
/// any attestation for the previous or current epoch target is valid
/// regardless of inclusion delay.
pub fn process_attestation<
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
    attestation: &Attestation<2048>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
            AltairBeaconState = pharos_types::altair::BeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
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
    let data = &attestation.data;

    let current_epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);
    let previous_epoch = if current_epoch.0 == 0 {
        Epoch(0)
    } else {
        Epoch(current_epoch.0 - 1)
    };

    // Target epoch must be current or previous.
    if data.target.epoch != current_epoch && data.target.epoch != previous_epoch {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::TargetEpochMismatch,
        });
    }

    // data.slot epoch must match data.target.epoch.
    let slot_epoch = compute_epoch_at_slot(data.slot, E::SLOTS_PER_EPOCH);
    if data.target.epoch != slot_epoch {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::TargetEpochMismatch,
        });
    }

    // MIN_ATTESTATION_INCLUSION_DELAY lower bound.
    if state.slot.0 < data.slot.0 + E::MIN_ATTESTATION_INCLUSION_DELAY {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooNew,
        });
    }
    // EIP-7045: upper bound `state.slot <= data.slot + SLOTS_PER_EPOCH` is intentionally REMOVED.

    // Project to altair state for helpers that operate on the altair type.
    let mut altair = deneb_state_to_altair::<
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
    >(state);

    // Committee index in range.
    let committee_count = get_committee_count_per_slot_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair, data.target.epoch);
    if data.index.0 >= committee_count {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::CommitteeIndexOutOfRange,
        });
    }

    // Aggregation bits length == committee size.
    let committee = get_beacon_committee_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair, data.slot, data.index.0);
    if attestation.aggregation_bits.len() != committee.len() {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::AggregationBitsLengthMismatch,
        });
    }

    // Participation flag indices.
    let inclusion_delay = state.slot.0 - data.slot.0;
    let participation_flag_indices = get_attestation_participation_flag_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair, data, inclusion_delay, true)?;

    if verify_signatures {
        // Build sorted attesting indices.
        let mut attesting_sorted: Vec<ValidatorIndex> = committee
            .iter()
            .enumerate()
            .filter_map(|(i, &vi)| {
                if attestation.aggregation_bits.get(i).unwrap_or(false) {
                    Some(vi)
                } else {
                    None
                }
            })
            .collect();
        attesting_sorted.sort();

        if attesting_sorted.is_empty() {
            return Err(StateTransitionError::InvalidAttestation {
                reason: AttestationInvalidReason::EmptyAttestingIndices,
            });
        }

        let pubkeys: Vec<pharos_utils::BLSPubkey> = attesting_sorted
            .iter()
            .map(|vi| {
                state
                    .validators
                    .get(vi.0 as usize)
                    .map(|v| v.pubkey)
                    .unwrap_or_default()
            })
            .collect();

        let domain = get_domain_deneb::<
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
        >(
            state,
            crate::phase0::helpers::DOMAIN_BEACON_ATTESTER,
            Some(data.target.epoch),
        );

        use pharos_ssz::{SszList, TreeHash};
        use pharos_types::phase0::{IndexedAttestation, SigningData};
        let indexed = IndexedAttestation::<2048> {
            attesting_indices: SszList::from_vec(attesting_sorted)
                .expect("indices within capacity"),
            data: data.clone(),
            signature: attestation.signature,
        };
        let msg = SigningData {
            object_root: indexed.data.tree_hash_root(),
            domain,
        }
        .tree_hash_root();

        let valid = pharos_utils::bls::fast_aggregate_verify(
            &pubkeys,
            msg.as_slice(),
            &attestation.signature,
        )
        .unwrap_or(false);

        if !valid {
            return Err(StateTransitionError::InvalidAttestation {
                reason: AttestationInvalidReason::InvalidSignature,
            });
        }
    }

    // Get attesting indices for participation update.
    let attesting_indices: Vec<ValidatorIndex> = committee
        .iter()
        .enumerate()
        .filter_map(|(i, &vi)| {
            if attestation.aggregation_bits.get(i).unwrap_or(false) {
                Some(vi)
            } else {
                None
            }
        })
        .collect();

    // Hoist BRPI outside the participation loop (loop-invariant: active-balance
    // total does not change within a single attestation).
    let brpi = get_base_reward_per_increment::<
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
    let is_current = data.target.epoch == current_epoch;
    let proposer_reward_numerator = accumulate_attestation_participation_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(
        &mut altair,
        &attesting_indices,
        &participation_flag_indices,
        is_current,
        brpi,
    )?;

    // Reward proposer.
    let proposer_reward_denominator =
        (E::WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * E::WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
    let proposer_reward = Gwei(proposer_reward_numerator / proposer_reward_denominator);
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
    >(&altair);

    // Sync participation changes back to deneb state, then apply proposer reward.
    update_deneb_from_altair_ref::<
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
    >(state, &altair);

    increase_balance_deneb::<
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
    >(state, proposer_index, proposer_reward)?;

    Ok(())
}

fn get_domain_deneb<
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
    E: BeaconSpec,
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
    domain_type: [u8; 4],
    epoch: Option<Epoch>,
) -> pharos_types::phase0::Domain {
    use crate::phase0::accessors::compute_domain;
    let epoch = epoch.unwrap_or_else(|| compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH));
    let fork_version = if epoch < state.fork.epoch {
        state.fork.previous_version.into_inner()
    } else {
        state.fork.current_version.into_inner()
    };
    compute_domain(domain_type, fork_version, &state.genesis_validators_root)
}
