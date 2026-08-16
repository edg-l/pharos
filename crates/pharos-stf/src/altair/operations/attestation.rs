//! Altair `process_attestation` per `specs/altair/beacon-chain.md:508-547`.
//!
//! Key difference from phase0: instead of appending a `PendingAttestation`,
//! this sets participation flags on the relevant epoch participation array
//! and rewards the proposer directly.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::BeaconState,
    phase0::{Attestation, Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::altair::helpers::{
    PROPOSER_WEIGHT, add_flag, get_attestation_participation_flag_indices, get_base_reward,
    get_proposer_index_altair, has_flag, increase_balance_altair,
};
use crate::error::{AttestationInvalidReason, StateTransitionError};
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_attestation` (modified in Altair) per `specs/altair/beacon-chain.md:508-547`.
///
/// Updates epoch participation flags and directly rewards the block proposer.
/// Does NOT append a `PendingAttestation` (that was removed in Altair).
pub fn process_attestation<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    attestation: &Attestation<2048>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
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

    // Inclusion delay constraints: MIN_ATTESTATION_INCLUSION_DELAY <= delay <= SLOTS_PER_EPOCH.
    if state.slot.0 < data.slot.0 + E::MIN_ATTESTATION_INCLUSION_DELAY {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooNew,
        });
    }
    if state.slot.0 > data.slot.0 + E::SLOTS_PER_EPOCH {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::SlotTooOld,
        });
    }

    // Committee index in range.
    // NOTE: get_committee_count_per_slot needs E::BeaconState. We build a
    // mini accessor from the altair state fields.
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
    >(state, data.target.epoch);
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
    >(state, data.slot, data.index.0);
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
    >(state, data, inclusion_delay, false)?;

    // Verify signature via indexed attestation.
    // The indexed attestation functions require E::BeaconState — we wrap the
    // altair state check inline using the phase0 is_valid_indexed_attestation
    // by calling the predicate via the fork-enum approach.
    if verify_signatures {
        // Build attesting indices from aggregation_bits + committee.
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

        // Verify BLS signature of the indexed attestation.
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

        let domain = get_domain_altair::<
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
            state,
            crate::phase0::helpers::DOMAIN_BEACON_ATTESTER,
            Some(data.target.epoch),
        );

        use pharos_ssz::SszList;
        let indexed = pharos_types::phase0::IndexedAttestation::<2048> {
            attesting_indices: SszList::from_vec(attesting_sorted)
                .expect("indices within capacity"),
            data: data.clone(),
            signature: attestation.signature,
        };

        let msg = {
            use pharos_ssz::TreeHash;
            use pharos_types::phase0::SigningData;
            let signing_data = SigningData {
                object_root: indexed.data.tree_hash_root(),
                domain,
            };
            signing_data.tree_hash_root()
        };

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

    // Get attesting indices (sorted for participation update).
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

    // Update epoch participation flags and accumulate proposer reward numerator.
    let is_current = data.target.epoch == current_epoch;
    let mut proposer_reward_numerator: u64 = 0;

    for validator_index in &attesting_indices {
        let ep_flags: u8 = if is_current {
            state
                .current_epoch_participation
                .as_slice()
                .get(validator_index.0 as usize)
                .copied()
                .unwrap_or(0)
        } else {
            state
                .previous_epoch_participation
                .as_slice()
                .get(validator_index.0 as usize)
                .copied()
                .unwrap_or(0)
        };

        let base_reward = get_base_reward::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, *validator_index);

        let mut new_flags = ep_flags;
        for (flag_index, weight) in E::PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
            if participation_flag_indices.contains(&flag_index) && !has_flag(new_flags, flag_index)
            {
                new_flags = add_flag(new_flags, flag_index);
                proposer_reward_numerator += base_reward.0 * weight;
            }
        }
        if new_flags != ep_flags {
            if is_current {
                state.current_epoch_participation = state
                    .current_epoch_participation
                    .with_set(validator_index.0 as usize, new_flags)
                    .map_err(StateTransitionError::Ssz)?;
            } else {
                state.previous_epoch_participation = state
                    .previous_epoch_participation
                    .with_set(validator_index.0 as usize, new_flags)
                    .map_err(StateTransitionError::Ssz)?;
            }
        }
    }

    // Reward proposer.
    // proposer_reward_denominator = (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT
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
    >(state);
    increase_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >(state, proposer_index, proposer_reward)?;

    Ok(())
}

// ── Altair-local accessors ─────────────────────────────────────────────────────
//
// These mirror phase0 accessors but work on the concrete altair BeaconState.

pub(crate) fn get_committee_count_per_slot_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    epoch: Epoch,
) -> u64 {
    use crate::phase0::predicates::is_active_validator;
    let active_count = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, epoch.0))
        .count() as u64;
    (active_count / E::SLOTS_PER_EPOCH / E::TARGET_COMMITTEE_SIZE)
        .max(1)
        .min(E::MAX_COMMITTEES_PER_SLOT)
}

pub(crate) fn get_beacon_committee_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    >,
    slot: pharos_types::phase0::Slot,
    index: u64,
) -> Vec<ValidatorIndex> {
    use crate::altair::helpers::get_seed_altair_pub;
    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let committees_per_slot = get_committee_count_per_slot_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, epoch);

    use crate::phase0::predicates::is_active_validator;
    let active: Vec<ValidatorIndex> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            if is_active_validator(v, epoch.0) {
                Some(ValidatorIndex(i as u64))
            } else {
                None
            }
        })
        .collect();

    let seed = get_seed_altair_pub::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, epoch, crate::phase0::helpers::DOMAIN_BEACON_ATTESTER);

    let committee_index = (slot.0 % E::SLOTS_PER_EPOCH) * committees_per_slot + index;
    let committee_count = committees_per_slot * E::SLOTS_PER_EPOCH;

    crate::phase0::accessors::compute_committee(
        &active,
        &seed,
        committee_index,
        committee_count,
        E::SHUFFLE_ROUND_COUNT,
    )
}

fn get_domain_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
