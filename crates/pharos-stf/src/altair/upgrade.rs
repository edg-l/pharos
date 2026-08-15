//! `upgrade_to_altair` fork transition.
//!
//! Per `specs/altair/fork.md:69-111`.
//!
//! Converts a phase0 `BeaconState` into an altair `BeaconState` by:
//! 1. Copying all shared fields.
//! 2. Setting the altair fork version.
//! 3. Zeroing `inactivity_scores`.
//! 4. Zeroing `previous_epoch_participation` / `current_epoch_participation`.
//! 5. Translating `previous_epoch_attestations` into participation flags.
//! 6. Computing `current_sync_committee` and `next_sync_committee`.

use pharos_ssz::SszSequence;
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    config::RuntimeConfig,
    phase0::{BeaconState as Phase0BeaconState, Fork, ValidatorIndex},
};

use crate::altair::helpers::{
    add_flag, get_attestation_participation_flag_indices, get_next_sync_committee,
};
use crate::altair::operations::attestation::get_beacon_committee_altair;
use crate::error::StateTransitionError;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `upgrade_to_altair` per `specs/altair/fork.md:69-111`.
///
/// Converts a phase0 beacon state into an altair beacon state.
pub fn upgrade_to_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
>(
    pre: Phase0BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
    >,
    runtime_cfg: &RuntimeConfig,
) -> Result<
    AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    StateTransitionError,
>
where
    E: EthSpec<
            Phase0BeaconState = Phase0BeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                MAX_PENDING_ATTESTATIONS,
                JUSTIFICATION_BITS_LENGTH,
                MAX_VALIDATORS_PER_COMMITTEE,
            >,
            AltairBeaconState = AltairBeaconState<
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
    pharos_utils::BLSPubkey: Default + Clone,
{
    let epoch = compute_epoch_at_slot(pre.slot, E::SLOTS_PER_EPOCH);

    // Build the fork field: previous_version = pre.fork.current_version,
    // current_version = ALTAIR_FORK_VERSION, epoch = current epoch.
    // spec: fork.md:73-78
    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: pharos_utils::Bytes4::from_array(runtime_cfg.altair_fork_version),
        epoch,
    };

    let validator_count = pre.validators.len();

    // Zero-fill participation lists (length = number of validators).
    // spec: fork.md:91-96
    let previous_epoch_participation = {
        let mut list = pharos_ssz::SszList::default();
        for _ in 0..validator_count {
            list = list.with_push(0u8).map_err(StateTransitionError::Ssz)?;
        }
        list
    };
    let current_epoch_participation = {
        let mut list = pharos_ssz::SszList::default();
        for _ in 0..validator_count {
            list = list.with_push(0u8).map_err(StateTransitionError::Ssz)?;
        }
        list
    };

    // Zero-fill inactivity_scores. spec: fork.md:101
    let inactivity_scores = {
        let mut list = pharos_ssz::SszList::default();
        for _ in 0..validator_count {
            list = list.with_push(0u64).map_err(StateTransitionError::Ssz)?;
        }
        list
    };

    // Assemble the post state with all shared fields from pre.
    // spec: fork.md:71-102
    let mut post = AltairBeaconState {
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork,
        latest_block_header: pre.latest_block_header,
        block_roots: pre.block_roots,
        state_roots: pre.state_roots,
        historical_roots: pre.historical_roots,
        eth1_data: pre.eth1_data,
        eth1_data_votes: pre.eth1_data_votes,
        eth1_deposit_index: pre.eth1_deposit_index,
        validators: pre.validators,
        balances: pre.balances,
        randao_mixes: pre.randao_mixes,
        slashings: pre.slashings,
        previous_epoch_participation,
        current_epoch_participation,
        justification_bits: pre.justification_bits,
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores,
        current_sync_committee: pharos_types::altair::SyncCommittee::default(),
        next_sync_committee: pharos_types::altair::SyncCommittee::default(),
    };

    // Translate previous_epoch_attestations into participation flags.
    // spec: fork.md:104-114 (`translate_participation`)
    for attestation in pre.previous_epoch_attestations.as_slice() {
        let data = &attestation.data;
        let inclusion_delay = attestation.inclusion_delay.0;

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
        >(&post, data, inclusion_delay)?;

        // Compute attesting indices for this attestation.
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
        >(&post, data.slot, data.index.0);

        let attesting_indices: Vec<ValidatorIndex> = committee
            .into_iter()
            .enumerate()
            .filter_map(|(i, idx)| {
                if attestation.aggregation_bits.get(i).unwrap_or(false) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        // Apply flags to all attesting validators in previous_epoch_participation.
        // spec: fork.md:109-113
        for index in &attesting_indices {
            let i = index.0 as usize;
            let current_flags = post
                .previous_epoch_participation
                .as_slice()
                .get(i)
                .copied()
                .unwrap_or(0);
            let mut new_flags = current_flags;
            for &flag_index in &participation_flag_indices {
                new_flags = add_flag(new_flags, flag_index);
            }
            if new_flags != current_flags {
                post.previous_epoch_participation = post
                    .previous_epoch_participation
                    .with_set(i, new_flags)
                    .map_err(StateTransitionError::Ssz)?;
            }
        }
    }

    // Compute sync committees. At the fork boundary the same committee is
    // assigned for current and next. spec: fork.md:122-128
    let current_sync_committee = get_next_sync_committee::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&post)?;
    post.current_sync_committee = current_sync_committee;

    let next_sync_committee = get_next_sync_committee::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&post)?;
    post.next_sync_committee = next_sync_committee;

    Ok(post)
}
