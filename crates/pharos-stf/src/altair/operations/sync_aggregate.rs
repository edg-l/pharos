//! `process_sync_aggregate` per `specs/altair/beacon-chain.md:574-635`.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::{BeaconState, SyncAggregate},
    phase0::{Slot, ValidatorIndex},
};
use pharos_utils::{BLSPubkey, Gwei};

use crate::altair::helpers::{
    DOMAIN_SYNC_COMMITTEE, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, decrease_balance_altair,
    get_base_reward_per_increment, get_proposer_index_altair, get_total_active_balance_altair,
    increase_balance_altair,
};
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_sync_aggregate` (new in Altair) per `specs/altair/beacon-chain.md:574-635`.
///
/// BLS path: `D-sync-aggregate-bls` — uses `fast_aggregate_verify` only. Batched
/// verify is deferred to M11. Signing root is
/// `compute_signing_root(get_block_root_at_slot(state, state.slot - 1), domain)`.
pub fn process_sync_aggregate<
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
    sync_aggregate: &SyncAggregate<SYNC_COMMITTEE_SIZE>,
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
    BLSPubkey: Default + Clone,
{
    // ── Verify BLS aggregate signature ───────────────────────────────────────

    // Collect committee pubkeys and participant subset.
    let committee_pubkeys: Vec<BLSPubkey> =
        state.current_sync_committee.pubkeys.as_slice().to_vec();
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
        // `eth_fast_aggregate_verify` per specs/altair/bls.md:
        //   - empty pubkeys + G2_POINT_AT_INFINITY → accept
        //   - empty pubkeys + anything else → reject
        //   - non-empty pubkeys → delegate to fast_aggregate_verify
        //
        // G2_POINT_AT_INFINITY = b'\xc0' + b'\x00' * 95 (specs/altair/bls.md)
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
            // empty committee + infinity signature → valid per eth_fast_aggregate_verify
        } else {
            let previous_slot = if state.slot.0 == 0 {
                Slot(0)
            } else {
                Slot(state.slot.0 - 1)
            };

            let previous_slot_root = {
                if !(previous_slot < state.slot
                    && state.slot.0 <= previous_slot.0 + E::SLOTS_PER_HISTORICAL_ROOT)
                {
                    return Err(StateTransitionError::SlotOutOfRange);
                }
                let idx = (previous_slot.0 % E::SLOTS_PER_HISTORICAL_ROOT) as usize;
                state
                    .block_roots
                    .get(idx)
                    .copied()
                    .ok_or(StateTransitionError::SlotOutOfRange)?
            };

            let epoch = compute_epoch_at_slot(previous_slot, E::SLOTS_PER_EPOCH);
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
            >(state, DOMAIN_SYNC_COMMITTEE, Some(epoch));

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

    // ── Compute rewards ───────────────────────────────────────────────────────
    // spec: lines 611-635

    let (participant_reward, proposer_reward) = sync_aggregate_rewards_altair::<
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

    // Build pubkey -> validator index map once (O(N)) to avoid O(N) per committee member.
    // Per spec invariant every sync committee pubkey MUST appear in state.validators.
    let pubkey_to_index: std::collections::HashMap<BLSPubkey, ValidatorIndex> = state
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| (v.pubkey, ValidatorIndex(i as u64)))
        .collect();

    let committee_indices: Vec<ValidatorIndex> = state
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
            >(state, *participant_index, participant_reward)?;
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
            >(state, *participant_index, participant_reward)?;
        }
    }

    Ok(())
}

/// Compute `(participant_reward, proposer_reward)` for `process_sync_aggregate`
/// per `specs/altair/beacon-chain.md:611-635`, without mutating balances.
///
/// Factored out of `process_sync_aggregate` so the Beacon API
/// `sync_committee_rewards` and `block_rewards` endpoints can reuse the exact
/// reward magnitudes (computed against a parent state) without duplicating the
/// math. `participant_reward` is the per-member reward (added when the member's
/// sync bit is set, subtracted when it is not); `proposer_reward` is the
/// proposer's share added once per participating member.
///
/// `altair/rewards` / `*/sanity` conformance gate that this factoring is
/// behaviour-preserving.
pub fn sync_aggregate_rewards_altair<
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
) -> (Gwei, Gwei)
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
    >(state)
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
    >(state);

    let total_base_rewards = Gwei(base_reward_per_increment.0 * total_active_increments);

    let max_participant_rewards = Gwei(
        total_base_rewards.0 * SYNC_REWARD_WEIGHT / E::WEIGHT_DENOMINATOR / E::SLOTS_PER_EPOCH,
    );

    let participant_reward = Gwei(max_participant_rewards.0 / E::SYNC_COMMITTEE_SIZE);

    let proposer_reward =
        Gwei(participant_reward.0 * PROPOSER_WEIGHT / (E::WEIGHT_DENOMINATOR - PROPOSER_WEIGHT));

    (participant_reward, proposer_reward)
}

// ── Domain helper ─────────────────────────────────────────────────────────────

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
    epoch: Option<pharos_types::phase0::Epoch>,
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
