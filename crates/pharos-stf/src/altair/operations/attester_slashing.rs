//! `process_attester_slashing` for Altair.
//!
//! Verification logic (slashable attestation check, indexed attestation validity)
//! is identical to phase0. The only Altair-specific change is calling altair's
//! `slash_validator` (which uses `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR`).
//!
//! Per `specs/altair/beacon-chain.md:459-487` (modified `slash_validator`).

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    altair::BeaconState,
    phase0::{AttesterSlashing, IndexedAttestation, ValidatorIndex},
};

use crate::altair::helpers::slash_validator;
use crate::error::{AttesterSlashingInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::compute_epoch_at_slot,
    helpers::DOMAIN_BEACON_ATTESTER,
    predicates::{is_slashable_attestation_data, is_slashable_validator},
};

/// `process_attester_slashing` for Altair.
///
/// Calls altair's `slash_validator` which uses `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR`.
pub fn process_attester_slashing<
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
    slashing: &AttesterSlashing<2048>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
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
    let att1 = &slashing.attestation_1;
    let att2 = &slashing.attestation_2;

    // Verify attestations are slashable.
    if !is_slashable_attestation_data(&att1.data, &att2.data) {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::AttestationsNotSlashable,
        });
    }

    // Verify both indexed attestations.
    if !is_valid_indexed_attestation_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >(state, att1, verify_signatures)
    {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::InvalidIndexedAttestation,
        });
    }
    if !is_valid_indexed_attestation_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >(state, att2, verify_signatures)
    {
        return Err(StateTransitionError::InvalidAttesterSlashing {
            reason: AttesterSlashingInvalidReason::InvalidIndexedAttestation,
        });
    }

    // Intersect attesting indices and slash slashable ones.
    let indices1 = att1.attesting_indices.as_slice();
    let indices2 = att2.attesting_indices.as_slice();

    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

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
            slash_validator::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
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

/// Validate an `IndexedAttestation` against the altair state.
///
/// Mirrors `is_valid_indexed_attestation` from phase0 predicates but reads
/// validators and domain from the concrete altair state.
fn is_valid_indexed_attestation_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
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
    indexed_att: &IndexedAttestation<2048>,
    verify_signatures: bool,
) -> bool {
    let indices = indexed_att.attesting_indices.as_slice();

    if indices.is_empty() {
        return false;
    }
    // Must be sorted and unique.
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
        use crate::phase0::accessors::compute_domain;
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

    use pharos_ssz::TreeHash;
    use pharos_types::phase0::SigningData;
    let signing_root = SigningData {
        object_root: indexed_att.data.tree_hash_root(),
        domain,
    }
    .tree_hash_root();

    pharos_utils::bls::fast_aggregate_verify(
        &pubkeys,
        signing_root.as_slice(),
        &indexed_att.signature,
    )
    .unwrap_or(false)
}
