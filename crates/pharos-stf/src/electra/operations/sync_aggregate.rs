//! `process_sync_aggregate` for Electra.
//!
//! Per `specs/altair/beacon-chain.md:574-635` — unchanged in logic since Altair,
//! EXCEPT the proposer index for the proposer reward MUST be computed with the
//! Electra effective-balance-weighted shuffle (`get_beacon_proposer_index_electra`).
//! The altair impl uses `get_proposer_index_altair` (8-bit proposer), which fails
//! Electra `sync_aggregate` fixtures.
//!
//! The reward arithmetic and BLS verification are reused from the altair helpers
//! over an `electra → altair` state projection; only balances are written back
//! into the electra state (the only fields this op mutates).

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::SyncAggregate,
    electra::BeaconState,
    phase0::{Slot, ValidatorIndex},
};
use pharos_utils::{BLSPubkey, Gwei};

use crate::altair::helpers::{
    DOMAIN_SYNC_COMMITTEE, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, decrease_balance_altair,
    get_base_reward_per_increment, get_total_active_balance_altair, increase_balance_altair,
};
use crate::electra::helpers::{electra_state_to_altair, get_beacon_proposer_index_electra};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_sync_aggregate` for Electra.
///
/// Proposer index comes from `get_beacon_proposer_index_electra`; everything else
/// mirrors the altair implementation over an altair state projection.
#[allow(clippy::too_many_arguments)]
pub fn process_sync_aggregate_electra<
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
    sync_aggregate: &SyncAggregate<SYNC_COMMITTEE_SIZE>,
    verify_signatures: bool,
    proposer_override: Option<ValidatorIndex>,
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
    BLSPubkey: Default + Clone,
{
    // Proposer index over the enum state (before mutation). Fulu (EIP-7917)
    // passes the precomputed lookahead proposer via `proposer_override`; electra
    // re-elects on demand.
    let proposer_index = match proposer_override {
        Some(p) => p,
        None => get_beacon_proposer_index_electra::<E>(&E::electra_into_state(state.clone())),
    };

    // Project to altair for the reward arithmetic + BLS verification.
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

    // ── Verify BLS aggregate signature ───────────────────────────────────────
    let committee_pubkeys: Vec<BLSPubkey> =
        altair.current_sync_committee.pubkeys.as_slice().to_vec();
    let bits = &sync_aggregate.sync_committee_bits;

    let participant_pubkeys: Vec<BLSPubkey> = committee_pubkeys
        .iter()
        .enumerate()
        .filter_map(|(i, pk)| {
            if bits.get(i).unwrap_or(false) {
                Some(*pk)
            } else {
                None
            }
        })
        .collect();

    if verify_signatures {
        // `eth_fast_aggregate_verify` per specs/altair/bls.md.
        // G2_POINT_AT_INFINITY = b'\xc0' + b'\x00' * 95.
        const G2_POINT_AT_INFINITY: [u8; 96] = {
            let mut b = [0u8; 96];
            b[0] = 0xc0;
            b
        };

        if participant_pubkeys.is_empty() {
            if sync_aggregate.sync_committee_signature
                != pharos_utils::BLSSignature::from_array(G2_POINT_AT_INFINITY)
            {
                return Err(StateTransitionError::InvalidBlockSignature);
            }
        } else {
            let previous_slot = if altair.slot.0 == 0 {
                Slot(0)
            } else {
                Slot(altair.slot.0 - 1)
            };

            let previous_slot_root = {
                if !(previous_slot < altair.slot
                    && altair.slot.0 <= previous_slot.0 + E::SLOTS_PER_HISTORICAL_ROOT)
                {
                    return Err(StateTransitionError::SlotOutOfRange);
                }
                let idx = (previous_slot.0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
                altair
                    .block_roots
                    .get(idx)
                    .copied()
                    .ok_or(StateTransitionError::SlotOutOfRange)?
            };

            let epoch = compute_epoch_at_slot(previous_slot, E::SLOTS_PER_EPOCH);
            let domain = {
                use crate::phase0::accessors::compute_domain;
                let fork_version = if epoch < altair.fork.epoch {
                    altair.fork.previous_version.into_inner()
                } else {
                    altair.fork.current_version.into_inner()
                };
                compute_domain(
                    DOMAIN_SYNC_COMMITTEE,
                    fork_version,
                    &altair.genesis_validators_root,
                )
            };

            use pharos_ssz::TreeHash;
            use pharos_types::phase0::SigningData;
            let signing_root_value = SigningData {
                object_root: previous_slot_root,
                domain,
            }
            .tree_hash_root();

            let valid = pharos_utils::bls::fast_aggregate_verify(
                &participant_pubkeys,
                signing_root_value.as_slice(),
                &sync_aggregate.sync_committee_signature,
            )
            .unwrap_or(false);

            if !valid {
                return Err(StateTransitionError::InvalidBlockSignature);
            }
        }
    }

    // ── Compute rewards (spec lines 611-635) ─────────────────────────────────
    let total_active_increments = get_total_active_balance_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&altair)
    .0 / E::EFFECTIVE_BALANCE_INCREMENT;

    let base_reward_per_increment = get_base_reward_per_increment::<
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

    let total_base_rewards = Gwei(base_reward_per_increment.0 * total_active_increments);

    let max_participant_rewards = Gwei(
        total_base_rewards.0 * SYNC_REWARD_WEIGHT / E::WEIGHT_DENOMINATOR / E::SLOTS_PER_EPOCH,
    );

    let participant_reward = Gwei(max_participant_rewards.0 / E::SYNC_COMMITTEE_SIZE);

    let proposer_reward =
        Gwei(participant_reward.0 * PROPOSER_WEIGHT / (E::WEIGHT_DENOMINATOR - PROPOSER_WEIGHT));

    // Build pubkey -> validator index map once (O(N)).
    let pubkey_to_index: std::collections::HashMap<BLSPubkey, ValidatorIndex> = altair
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| (v.pubkey, ValidatorIndex(i as u64)))
        .collect();

    let committee_indices: Vec<ValidatorIndex> = altair
        .current_sync_committee
        .pubkeys
        .as_slice()
        .iter()
        .map(|pk| {
            pubkey_to_index
                .get(pk)
                .copied()
                .ok_or(StateTransitionError::InvalidSyncCommittee)
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (i, participant_index) in committee_indices.iter().enumerate() {
        let participation_bit = bits.get(i).unwrap_or(false);
        if participation_bit {
            increase_balance_altair::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >(&mut altair, *participant_index, participant_reward)?;
            increase_balance_altair::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >(&mut altair, proposer_index, proposer_reward)?;
        } else {
            decrease_balance_altair::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >(&mut altair, *participant_index, participant_reward)?;
        }
    }

    // Write the only mutated field (balances) back into the electra state.
    state.balances = altair.balances;

    Ok(())
}
