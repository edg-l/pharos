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
use pharos_utils::bls::{SignatureSet, aggregate_pubkeys, verify_signature_sets};

use crate::altair::helpers::{
    PROPOSER_WEIGHT, get_attestation_participation_flag_indices, get_base_reward_per_increment,
};
use crate::altair::operations::attestation::{
    accumulate_attestation_participation_altair, get_committee_count_per_slot_altair,
};
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
///
/// Compute-once batched-BLS contract (matches deneb): when `verify_signatures`,
/// this builds the indexed attestation's [`SignatureSet`] and returns
/// `Ok(Some(set))` WITHOUT verifying it inline — the caller batches every
/// attestation into one `verify_signature_sets` call
/// (`process_operations_electra`) or verifies the single returned set (the
/// `operations` conformance runner). Structural validity (non-empty, strictly
/// sorted indices, all pubkeys present) is still checked here and surfaces as an
/// immediate `Err`. Returns `Ok(None)` when `!verify_signatures`. Apply-before-
/// verify is safe: a block/op failure discards the state.
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
    proposer_override: Option<ValidatorIndex>,
) -> Result<Option<SignatureSet>, StateTransitionError>
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

    // Build the batched signature set once (no inline verify): the caller batches
    // it. Structural validity (non-empty, strictly sorted, pubkeys present) is
    // still enforced here. See the function doc.
    let sig_set = if verify_signatures {
        let indexed = get_indexed_attestation_electra_inner::<
            MAX_AGGREGATION_BITS,
            MAX_COMMITTEES_PER_SLOT,
            E,
        >(&enum_state, attestation);

        match indexed_attestation_signature_set_electra(state, &indexed) {
            Some(set) => Some(set),
            None => {
                return Err(StateTransitionError::InvalidAttestation {
                    reason: AttestationInvalidReason::InvalidSignature,
                });
            }
        }
    } else {
        None
    };

    // Get attesting indices for participation update.
    let attesting_indices = get_attesting_indices_electra::<
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        E,
    >(&enum_state, attestation);

    // Hoist BRPI outside the per-attester loop (active-balance total is
    // loop-invariant within a single attestation).
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

    // Sync participation changes back into electra state.
    state.previous_epoch_participation = altair.previous_epoch_participation;
    state.current_epoch_participation = altair.current_epoch_participation;

    // Reward proposer via electra get_beacon_proposer_index.
    let proposer_reward_denominator =
        (E::WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * E::WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
    let proposer_reward = Gwei(proposer_reward_numerator / proposer_reward_denominator);
    // Fulu (EIP-7917) supplies the locked-in proposer; electra elects on-demand.
    let proposer_index = proposer_override.unwrap_or_else(|| {
        get_beacon_proposer_index_electra::<E>(&E::electra_into_state(state.clone()))
    });

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

    Ok(sig_set)
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
    proposer_override: Option<ValidatorIndex>,
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
            >(state, *index, None, proposer_override)?;
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

    // Shares the signing-root/aggregate-pubkey construction with the batched
    // `process_attestation_electra` path via the helper below.
    match indexed_attestation_signature_set_electra(state, indexed_att) {
        Some(set) => verify_signature_sets(std::slice::from_ref(&set)).unwrap_or(false),
        None => false,
    }
}

/// Build the batched BLS [`SignatureSet`] for an electra `IndexedAttestation`:
/// structural validity (non-empty, strictly sorted indices, every index resolves
/// to a validator pubkey) then the aggregate signer pubkey + signing root.
/// Returns `None` if the attestation is structurally invalid (the caller maps
/// that to a rejection). Verification itself is performed by the caller via
/// `verify_signature_sets`, so this same construction backs both the inline
/// `is_valid_indexed_attestation_electra` check and the batched
/// `process_attestation_electra` path.
#[allow(clippy::type_complexity)]
fn indexed_attestation_signature_set_electra<
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
) -> Option<SignatureSet> {
    let indices = indexed_att.attesting_indices.as_slice();

    if indices.is_empty() {
        return None;
    }
    for w in indices.windows(2) {
        if w[0] >= w[1] {
            return None;
        }
    }

    let pubkeys: Vec<pharos_utils::BLSPubkey> = indices
        .iter()
        .filter_map(|i| state.validators.get(i.0 as usize).map(|v| v.pubkey))
        .collect();
    if pubkeys.len() != indices.len() {
        return None;
    }
    let agg_pubkey = aggregate_pubkeys(&pubkeys).ok()?;

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

    Some(SignatureSet {
        pubkey: agg_pubkey,
        message: msg.as_slice().to_vec(),
        signature: indexed_att.signature,
    })
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
