//! `process_attestation` and `process_attester_slashing` for Electra (EIP-7549).
//!
//! Per `specs/electra/beacon-chain.md` Block processing (lines 1511-1564).
//!
//! EIP-7549 changes:
//! - `data.index` must be 0 (committee index is in `committee_bits`).
//! - `aggregation_bits` covers ALL committees in `committee_bits` order, with a
//!   running `committee_offset` accumulation.
//! - `assert len(aggregation_bits) == committee_offset` (total across committees).
//!
//! `process_attester_slashing` uses the electra `AttesterSlashing` type (widened
//! `IndexedAttestation`) with `slash_validator_electra` for EIP-7251 penalties.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    electra::{
        BeaconState,
        attestation::{AttesterSlashing, IndexedAttestation},
    },
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::altair::helpers::{
    PROPOSER_WEIGHT, add_flag, get_attestation_participation_flag_indices,
    get_base_reward_per_increment, has_flag,
};
use crate::altair::operations::attestation::get_committee_count_per_slot_altair;
use crate::electra::helpers::{
    electra_state_to_altair, get_attesting_indices_electra, get_beacon_proposer_index_electra,
    get_committee_indices, increase_balance_electra, slash_validator_electra,
};
use crate::error::{AttestationInvalidReason, AttesterSlashingInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::{
        compute_domain, compute_epoch_at_slot, compute_signing_root, get_beacon_committee,
    },
    helpers::DOMAIN_BEACON_ATTESTER,
    predicates::{is_slashable_attestation_data, is_slashable_validator},
};

/// `process_attestation` for Electra (EIP-7549/EIP-7045).
///
/// Per `specs/electra/beacon-chain.md:1511-1564`.
///
/// Key changes vs. Deneb:
/// - `data.index == 0` assertion.
/// - per-committee attester loop with `committee_offset` accumulation.
/// - `len(aggregation_bits) == committee_offset` assertion.
/// - proposer index from `get_beacon_proposer_index_electra`.
pub fn process_attestation_electra<
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
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
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
    attestation: &pharos_types::electra::Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
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

    // [Modified in Electra:EIP7549] data.index must be 0.
    if data.index.0 != 0 {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::CommitteeIndexOutOfRange,
        });
    }

    // Project to altair state for helpers that operate on the altair type.
    let mut altair = electra_state_to_altair::<
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
    >(state);

    // Build the enum state once — used for committee lookups and attesting indices.
    let enum_state = E::electra_into_state(state.clone());

    // [Modified in Electra:EIP7549] per-committee attester loop with committee_offset.
    let committee_indices = get_committee_indices(&attestation.committee_bits);
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

    let mut committee_offset = 0usize;
    for committee_index in &committee_indices {
        if *committee_index >= committee_count {
            return Err(StateTransitionError::InvalidAttestation {
                reason: AttestationInvalidReason::CommitteeIndexOutOfRange,
            });
        }
        let committee = get_beacon_committee::<E>(&enum_state, data.slot, *committee_index);
        // Must have at least one attester from this committee.
        let has_attester = committee.iter().enumerate().any(|(i, _)| {
            attestation
                .aggregation_bits
                .get(committee_offset + i)
                .unwrap_or(false)
        });
        if !has_attester {
            return Err(StateTransitionError::InvalidAttestation {
                reason: AttestationInvalidReason::EmptyAttestingIndices,
            });
        }
        committee_offset += committee.len();
    }

    // [Electra:EIP7549] aggregation_bits length == total committee_offset.
    if attestation.aggregation_bits.len() != committee_offset {
        return Err(StateTransitionError::InvalidAttestation {
            reason: AttestationInvalidReason::AggregationBitsLengthMismatch,
        });
    }

    // Participation flag indices (EIP-7045: eip7045_target_flag = true).
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
        // Build indexed attestation and verify signature.
        let indexed = get_indexed_attestation_electra_inner::<
            MAX_AGGREGATION_BITS,
            MAX_COMMITTEES_PER_SLOT,
            E,
        >(&enum_state, attestation);

        if !is_valid_indexed_attestation_electra(state, &indexed, verify_signatures) {
            return Err(StateTransitionError::InvalidAttestation {
                reason: AttestationInvalidReason::InvalidSignature,
            });
        }
    }

    // Get attesting indices for participation update.
    let attesting_indices = get_attesting_indices_electra::<
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        E,
    >(&enum_state, attestation);

    let is_current = data.target.epoch == current_epoch;
    let mut proposer_reward_numerator: u64 = 0;

    // `base_reward_per_increment` is loop-invariant across the attester loop
    // (the altair projection's effective balances / total active balance are not
    // mutated here, only participation flags), so compute it once instead of
    // having `get_base_reward` rescan all validators per attester.
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

    for validator_index in &attesting_indices {
        let ep_flags: u8 = if is_current {
            altair
                .current_epoch_participation
                .as_slice()
                .get(validator_index.0 as usize)
                .copied()
                .unwrap_or(0)
        } else {
            altair
                .previous_epoch_participation
                .as_slice()
                .get(validator_index.0 as usize)
                .copied()
                .unwrap_or(0)
        };

        // Inline `get_base_reward` using the hoisted `brpi`: identical to
        // `Gwei((effective_balance / EFFECTIVE_BALANCE_INCREMENT) * brpi.0)`.
        let effective_balance_increments = altair
            .validators
            .get(validator_index.0 as usize)
            .map(|v| v.effective_balance.0 / E::EFFECTIVE_BALANCE_INCREMENT)
            .unwrap_or(0);
        let base_reward = Gwei(effective_balance_increments * brpi.0);

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
                altair.current_epoch_participation = altair
                    .current_epoch_participation
                    .with_set(validator_index.0 as usize, new_flags)
                    .map_err(StateTransitionError::Ssz)?;
            } else {
                altair.previous_epoch_participation = altair
                    .previous_epoch_participation
                    .with_set(validator_index.0 as usize, new_flags)
                    .map_err(StateTransitionError::Ssz)?;
            }
        }
    }

    // Sync participation changes back into electra state.
    state.previous_epoch_participation = altair.previous_epoch_participation;
    state.current_epoch_participation = altair.current_epoch_participation;

    // Reward proposer via electra get_beacon_proposer_index.
    let proposer_reward_denominator =
        (E::WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * E::WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
    let proposer_reward = Gwei(proposer_reward_numerator / proposer_reward_denominator);
    let proposer_index =
        get_beacon_proposer_index_electra::<E>(&E::electra_into_state(state.clone()));

    increase_balance_electra::<
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
    >(state, proposer_index, proposer_reward)?;

    Ok(())
}

/// `process_attester_slashing` for Electra.
///
/// Uses the electra `AttesterSlashing` type (EIP-7549 widened `IndexedAttestation`)
/// and `slash_validator_electra` for EIP-7251 penalties.
pub fn process_attester_slashing_electra<
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
    const MAX_AGGREGATION_BITS: u64,
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
    slashing: &AttesterSlashing<MAX_AGGREGATION_BITS>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
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
    let att1 = &slashing.attestation_1;
    let att2 = &slashing.attestation_2;

    if !is_slashable_attestation_data(&att1.data, &att2.data) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::AttestationsNotSlashable,
        });
    }

    if !is_valid_indexed_attestation_electra(state, att1, verify_signatures) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::InvalidIndexedAttestation,
        });
    }
    if !is_valid_indexed_attestation_electra(state, att2, verify_signatures) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::InvalidIndexedAttestation,
        });
    }

    let indices1 = att1.attesting_indices.as_slice();
    let indices2 = att2.attesting_indices.as_slice();
    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    // Sorted intersection.
    let mut intersection: Vec<ValidatorIndex> = Vec::new();
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
            .validators
            .get(index.0 as usize)
            .map(|v| is_slashable_validator(v, epoch.0))
            .unwrap_or(false);
        if is_slashable {
            slash_validator_electra::<
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
            >(state, *index, None)?;
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

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Verify an electra `IndexedAttestation` (sorted indices, non-empty, optional BLS).
fn is_valid_indexed_attestation_electra<
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
    const MAX_AGGREGATION_BITS: u64,
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    indexed_att: &IndexedAttestation<MAX_AGGREGATION_BITS>,
    verify_signatures: bool,
) -> bool {
    let indices = indexed_att.attesting_indices.as_slice();

    if indices.is_empty() {
        return false;
    }
    for w in indices.windows(2) {
        if w[0] >= w[1] {
            return false;
        }
    }

    if !verify_signatures {
        return true;
    }

    let pubkeys: Vec<pharos_utils::BLSPubkey> = indices
        .iter()
        .filter_map(|i| state.validators.get(i.0 as usize).map(|v| v.pubkey))
        .collect();

    if pubkeys.len() != indices.len() {
        return false;
    }

    let domain = {
        let target_epoch = indexed_att.data.target.epoch;
        let fork_version = if target_epoch < state.fork.epoch {
            state.fork.previous_version.into_inner()
        } else {
            state.fork.current_version.into_inner()
        };
        compute_domain(
            DOMAIN_BEACON_ATTESTER,
            fork_version,
            &state.genesis_validators_root,
        )
    };

    let msg = compute_signing_root(&indexed_att.data, domain);

    pharos_utils::bls::fast_aggregate_verify(&pubkeys, msg.as_slice(), &indexed_att.signature)
        .unwrap_or(false)
}

/// Build an electra `IndexedAttestation` from an electra `Attestation`.
///
/// Used internally for BLS verification in `process_attestation_electra`.
fn get_indexed_attestation_electra_inner<
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    E: BeaconSpec,
>(
    state: &E::BeaconState,
    attestation: &pharos_types::electra::Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
) -> IndexedAttestation<MAX_AGGREGATION_BITS> {
    crate::electra::helpers::get_indexed_attestation_electra::<
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        E,
    >(state, attestation)
}
