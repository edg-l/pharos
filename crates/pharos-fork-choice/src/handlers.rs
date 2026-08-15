//! Fork-choice handlers and pull-up tip helpers.
//!
//! Implements `on_tick`, `on_block`, `on_attestation`, `on_attester_slashing`,
//! and all supporting helpers.
//!
//! Per `specs/phase0/fork-choice.md:695-933`.

use pharos_ssz::TreeHash;
use pharos_types::{
    BeaconStateView, EthSpec,
    phase0::{Attestation, AttesterSlashing, Checkpoint, IndexedAttestation, Root, Slot},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use crate::error::ForkChoiceError;
use crate::get_head::{
    compute_slots_since_epoch_start, get_checkpoint_block, get_current_slot,
    get_current_store_epoch, get_slot_component_duration_ms, slot_from_time, slot_start_time,
    time_into_current_slot_ms,
};
use crate::store::{LatestMessage, Store};

// ── Checkpoint update helpers ─────────────────────────────────────────────────

/// `update_checkpoints` per `specs/phase0/fork-choice.md:439-455`.
///
/// Promotes `justified_checkpoint` and/or `finalized_checkpoint` only when
/// the new epoch strictly exceeds the current one.
pub fn update_checkpoints<E: EthSpec>(
    store: &mut Store<E>,
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
) {
    if justified_checkpoint.epoch > store.justified_checkpoint.epoch {
        store.justified_checkpoint = justified_checkpoint;
    }
    if finalized_checkpoint.epoch > store.finalized_checkpoint.epoch {
        store.finalized_checkpoint = finalized_checkpoint;
    }
}

/// `update_unrealized_checkpoints` per `specs/phase0/fork-choice.md:458-474`.
///
/// Same promotion rule for the unrealized variants.
pub fn update_unrealized_checkpoints<E: EthSpec>(
    store: &mut Store<E>,
    unrealized_justified: Checkpoint,
    unrealized_finalized: Checkpoint,
) {
    if unrealized_justified.epoch > store.unrealized_justified_checkpoint.epoch {
        store.unrealized_justified_checkpoint = unrealized_justified;
    }
    if unrealized_finalized.epoch > store.unrealized_finalized_checkpoint.epoch {
        store.unrealized_finalized_checkpoint = unrealized_finalized;
    }
}

// ── Pull-up tip ───────────────────────────────────────────────────────────────

/// `compute_pulled_up_tip` per `specs/phase0/fork-choice.md:675-693`.
///
/// Clones the post-state for `block_root`, runs
/// `process_justification_and_finalization` on the clone, writes the result
/// into `store.unrealized_justifications`, then promotes the unrealized
/// checkpoints and, when the block is from a prior epoch, the realized
/// checkpoints too.
pub fn compute_pulled_up_tip<E: EthSpec>(
    store: &mut Store<E>,
    block_root: Root,
) -> Result<(), ForkChoiceError>
where
    E::BeaconState: BeaconStateWrite + Clone,
    E::BeaconBlock: BeaconBlockView,
    E::Phase0BeaconBlockBody:
        BeaconBlockBodyView<Attestation = pharos_types::phase0::Attestation<2048>>,
{
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    use pharos_stf::process_justification_and_finalization;

    let mut state = store
        .block_states
        .get(&block_root)
        .ok_or(ForkChoiceError::MissingBlock { root: block_root })?
        .clone();

    // `process_justification_and_finalization` is called on the clone to
    // compute the unrealized checkpoints.  Per the spec: "Pull up the
    // post-state of the block to the next epoch boundary".
    process_justification_and_finalization::<E>(&mut state)?;

    let unrealized_justified = state.current_justified_checkpoint().clone();
    let unrealized_finalized = state.finalized_checkpoint().clone();

    store
        .unrealized_justifications
        .insert(block_root, unrealized_justified.clone());

    update_unrealized_checkpoints(
        store,
        unrealized_justified.clone(),
        unrealized_finalized.clone(),
    );

    // If the block is from a prior epoch, apply to the realized checkpoints too.
    let block_epoch = store
        .blocks
        .get(&block_root)
        .map(|b| compute_epoch_at_slot(b.slot(), E::SLOTS_PER_EPOCH))
        .unwrap_or_default();
    let current_epoch = get_current_store_epoch::<E>(store);

    if block_epoch < current_epoch {
        update_checkpoints(store, unrealized_justified, unrealized_finalized);
    }

    Ok(())
}

// ── on_tick ───────────────────────────────────────────────────────────────────

/// `on_tick_per_slot` per `specs/phase0/fork-choice.md:699-717`.
///
/// Updates `store.time`, resets `proposer_boost_root` on slot boundaries,
/// and applies unrealized checkpoints at epoch boundaries.
pub fn on_tick_per_slot<E: EthSpec>(store: &mut Store<E>, time: u64) {
    let previous_slot = get_current_slot(store);
    store.time = time;
    let current_slot = get_current_slot(store);

    if current_slot > previous_slot {
        store.proposer_boost_root = Root::default();
    }

    if current_slot > previous_slot && compute_slots_since_epoch_start::<E>(current_slot) == 0 {
        let unrealized_justified = store.unrealized_justified_checkpoint.clone();
        let unrealized_finalized = store.unrealized_finalized_checkpoint.clone();
        update_checkpoints(store, unrealized_justified, unrealized_finalized);
    }
}

/// `on_tick` per `specs/phase0/fork-choice.md:832-843`.
///
/// Catches up slot-by-slot to `time`, calling `on_tick_per_slot` for each
/// intermediate slot, then once more for the final `time`.
pub fn on_tick<E: EthSpec>(store: &mut Store<E>, time: u64) {
    let tick_slot = slot_from_time::<E>(time, store.genesis_time);

    while get_current_slot(store).0 < tick_slot {
        let previous_time = slot_start_time::<E>(get_current_slot(store).0 + 1, store.genesis_time);
        on_tick_per_slot(store, previous_time);
    }
    on_tick_per_slot(store, time);
}

// ── on_block helpers ──────────────────────────────────────────────────────────

/// `record_block_timeliness` per `specs/phase0/fork-choice.md:799-807`.
fn record_block_timeliness<E: EthSpec>(store: &mut Store<E>, root: Root)
where
    E::BeaconBlock: BeaconBlockView,
{
    let block_slot = store.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0));
    let time_into_slot_ms = time_into_current_slot_ms::<E>(store);
    let attestation_threshold_ms = get_slot_component_duration_ms::<E>(E::ATTESTATION_DUE_BPS);
    let is_before_attesting_interval = time_into_slot_ms < attestation_threshold_ms;
    let is_timely = get_current_slot(store) == block_slot && is_before_attesting_interval;
    store.block_timeliness.insert(root, is_timely);
}

/// `update_proposer_boost_root` per `specs/phase0/fork-choice.md:810-827`.
fn update_proposer_boost_root<E: EthSpec>(store: &mut Store<E>, root: Root)
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateWrite + Clone,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use crate::get_head::get_head;
    use pharos_stf::phase0::accessors::get_beacon_proposer_index;
    use pharos_stf::process_slots;

    let is_first_block = store.proposer_boost_root == Root::default();
    let is_timely = store.block_timeliness.get(&root).copied().unwrap_or(false);

    if is_timely && is_first_block {
        // Clone and advance the head state to the current slot.
        let head_root = get_head(store);
        let mut head_state = match store.block_states.get(&head_root) {
            Some(s) => s.clone(),
            None => return,
        };
        let slot = get_current_slot(store);
        if head_state.slot() < slot && process_slots::<E>(&mut head_state, slot).is_err() {
            return;
        }

        let block = match store.blocks.get(&root) {
            Some(b) => b,
            None => return,
        };
        if block.proposer_index() == get_beacon_proposer_index::<E>(&head_state) {
            store.proposer_boost_root = root;
        }
    }
}

// ── on_block ──────────────────────────────────────────────────────────────────

/// `on_block` per `specs/phase0/fork-choice.md:846-885`.
///
/// Validates the block, runs state transition, inserts into the store, and
/// eagerly computes unrealized justification via `compute_pulled_up_tip`.
pub fn on_block<E: EthSpec>(
    store: &mut Store<E>,
    signed_block: &E::SignedBeaconBlock,
) -> Result<(), ForkChoiceError>
where
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::BeaconState: BeaconStateWrite + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
{
    use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
    use pharos_stf::state_transition;

    let block = signed_block.message();

    // Parent block must be known.
    let pre_state = store
        .block_states
        .get(&block.parent_root())
        .ok_or(ForkChoiceError::MissingBlock {
            root: block.parent_root(),
        })?
        .clone();

    // Blocks cannot be in the future.
    let current_slot = get_current_slot(store);
    if current_slot < block.slot() {
        return Err(ForkChoiceError::FutureSlot {
            current: current_slot,
            block_slot: block.slot(),
        });
    }

    // Block must be strictly after the finalized epoch slot.
    let finalized_slot =
        compute_start_slot_at_epoch(store.finalized_checkpoint.epoch, E::SLOTS_PER_EPOCH);
    if block.slot() <= finalized_slot {
        return Err(ForkChoiceError::BeforeFinalized {
            slot: block.slot(),
            finalized_slot,
        });
    }

    // Check block is a descendant of the finalized block.
    let finalized_checkpoint_block =
        get_checkpoint_block::<E>(store, block.parent_root(), store.finalized_checkpoint.epoch);
    if store.finalized_checkpoint.root != finalized_checkpoint_block {
        return Err(ForkChoiceError::InvalidBlock {
            reason: "block is not a descendant of the finalized checkpoint".to_owned(),
        });
    }

    // Compute post-state via state transition.
    let block_root: Root = block.tree_hash_root();
    let post_state = state_transition::<E>(pre_state, signed_block, true)?;

    // Insert block and state.
    store.blocks.insert(block_root, block.clone());
    store.block_states.insert(block_root, post_state.clone());

    record_block_timeliness::<E>(store, block_root);
    update_proposer_boost_root::<E>(store, block_root);

    // Update realized checkpoints.
    let justified = post_state.current_justified_checkpoint().clone();
    let finalized = post_state.finalized_checkpoint().clone();
    update_checkpoints(store, justified, finalized);

    // Eagerly compute unrealized justification.
    compute_pulled_up_tip::<E>(store, block_root)?;

    Ok(())
}

// ── on_attestation helpers ────────────────────────────────────────────────────

/// `validate_target_epoch_against_current_time`
/// per `specs/phase0/fork-choice.md:722-733`.
fn validate_target_epoch_against_current_time<E: EthSpec>(
    store: &Store<E>,
    attestation: &Attestation<2048>,
) -> Result<(), ForkChoiceError> {
    use pharos_stf::phase0::helpers::GENESIS_EPOCH;

    let target = &attestation.data.target;
    let current_epoch = get_current_store_epoch::<E>(store);
    let previous_epoch = if current_epoch.0 > GENESIS_EPOCH {
        pharos_types::phase0::Epoch(current_epoch.0 - 1)
    } else {
        pharos_types::phase0::Epoch(GENESIS_EPOCH)
    };

    if target.epoch != current_epoch && target.epoch != previous_epoch {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: format!(
                "target epoch {} is neither current ({}) nor previous ({})",
                target.epoch.0, current_epoch.0, previous_epoch.0
            ),
        });
    }

    Ok(())
}

/// `validate_on_attestation` per `specs/phase0/fork-choice.md:736-764`.
pub fn validate_on_attestation<E: EthSpec>(
    store: &Store<E>,
    attestation: &Attestation<2048>,
    is_from_block: bool,
) -> Result<(), ForkChoiceError>
where
    E::BeaconBlock: BeaconBlockView,
{
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;

    let target = &attestation.data.target;

    if !is_from_block {
        validate_target_epoch_against_current_time::<E>(store, attestation)?;
    }

    // Epoch number and slot must match.
    let expected_epoch = compute_epoch_at_slot(attestation.data.slot, E::SLOTS_PER_EPOCH);
    if target.epoch != expected_epoch {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: format!(
                "target epoch {} != epoch at attestation slot {} (expected {})",
                target.epoch.0, attestation.data.slot.0, expected_epoch.0
            ),
        });
    }

    // Target root must be in the store.
    if !store.blocks.contains_key(&target.root) {
        return Err(ForkChoiceError::MissingBlock { root: target.root });
    }

    // Attested block root must be in the store.
    if !store
        .blocks
        .contains_key(&attestation.data.beacon_block_root)
    {
        return Err(ForkChoiceError::MissingBlock {
            root: attestation.data.beacon_block_root,
        });
    }

    // Attested block must not be from the future relative to the attestation.
    let attested_slot = store
        .blocks
        .get(&attestation.data.beacon_block_root)
        .map(|b| b.slot())
        .unwrap_or(Slot(0));
    if attested_slot > attestation.data.slot {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: format!(
                "attested block slot {} > attestation slot {}",
                attested_slot.0, attestation.data.slot.0
            ),
        });
    }

    // LMD vote must be consistent with FFG vote target.
    let checkpoint_block =
        get_checkpoint_block::<E>(store, attestation.data.beacon_block_root, target.epoch);
    if target.root != checkpoint_block {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: "target root is not the checkpoint block for the target epoch".to_owned(),
        });
    }

    // Attestation must be for a past slot.
    let current_slot = get_current_slot(store);
    if current_slot < attestation.data.slot + Slot(1) {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: format!(
                "attestation slot {} is not in the past (current {})",
                attestation.data.slot.0, current_slot.0
            ),
        });
    }

    Ok(())
}

/// `store_target_checkpoint_state` per `specs/phase0/fork-choice.md:767-775`.
pub fn store_target_checkpoint_state<E: EthSpec>(
    store: &mut Store<E>,
    target: &Checkpoint,
) -> Result<(), ForkChoiceError>
where
    E::BeaconState: BeaconStateWrite + Clone,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
    use pharos_stf::process_slots;

    if store.checkpoint_states.contains_key(target) {
        return Ok(());
    }

    let base_state_opt = store.block_states.get(&target.root).cloned();
    let mut base_state =
        base_state_opt.ok_or(ForkChoiceError::MissingBlock { root: target.root })?;

    let target_slot = compute_start_slot_at_epoch(target.epoch, E::SLOTS_PER_EPOCH);
    if base_state.slot() < target_slot {
        process_slots::<E>(&mut base_state, target_slot)?;
    }
    store.checkpoint_states.insert(target.clone(), base_state);

    Ok(())
}

/// `update_latest_messages` per `specs/phase0/fork-choice.md:778-791`.
pub fn update_latest_messages<E: EthSpec>(
    store: &mut Store<E>,
    attesting_indices: &[pharos_types::phase0::ValidatorIndex],
    attestation: &Attestation<2048>,
) {
    let target = &attestation.data.target;
    let beacon_block_root = attestation.data.beacon_block_root;
    for i in attesting_indices {
        if store.equivocating_indices.contains(i) {
            continue;
        }
        let should_update = store
            .latest_messages
            .get(i)
            .map(|msg| target.epoch > msg.epoch)
            .unwrap_or(true);
        if should_update {
            store.latest_messages.insert(
                *i,
                LatestMessage {
                    epoch: target.epoch,
                    root: beacon_block_root,
                },
            );
        }
    }
}

// ── on_attestation ────────────────────────────────────────────────────────────

/// `on_attestation` per `specs/phase0/fork-choice.md:888-909`.
///
/// Validates and processes a received attestation.  `is_from_block` is `true`
/// when the attestation was included in a beacon block (skips epoch-time check).
pub fn on_attestation<E: EthSpec>(
    store: &mut Store<E>,
    attestation: &Attestation<2048>,
    is_from_block: bool,
) -> Result<(), ForkChoiceError>
where
    E::BeaconBlock: BeaconBlockView,
    E::BeaconState: BeaconStateWrite + Clone,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use pharos_stf::phase0::accessors::get_attesting_indices;
    use pharos_stf::phase0::predicates::is_valid_indexed_attestation;

    validate_on_attestation::<E>(store, attestation, is_from_block)?;
    store_target_checkpoint_state::<E>(store, &attestation.data.target)?;

    // Get state at target checkpoint to validate attestation.
    let target_state = store
        .checkpoint_states
        .get(&attestation.data.target)
        .ok_or(ForkChoiceError::MissingBlock {
            root: attestation.data.target.root,
        })?;

    // Build indexed attestation and validate signature.
    let indexed = {
        use pharos_ssz::SszList;
        let mut attesting = get_attesting_indices::<E>(
            target_state,
            &attestation.data,
            &attestation.aggregation_bits,
        );
        attesting.sort();
        IndexedAttestation::<2048> {
            attesting_indices: SszList::from_vec(attesting)
                .expect("attesting indices within MAX_VALIDATORS_PER_COMMITTEE"),
            data: attestation.data.clone(),
            signature: attestation.signature,
        }
    };

    if !is_valid_indexed_attestation::<E>(target_state, &indexed, true) {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: "invalid indexed attestation signature".to_owned(),
        });
    }

    let attesting_indices: Vec<_> = indexed.attesting_indices.as_slice().to_vec();
    update_latest_messages(store, &attesting_indices, attestation);

    Ok(())
}

// ── on_attester_slashing ──────────────────────────────────────────────────────

/// `on_attester_slashing` per `specs/phase0/fork-choice.md:912-933`.
///
/// Validates both indexed attestations and adds the intersection of their
/// attesting indices to `store.equivocating_indices`.
pub fn on_attester_slashing<E: EthSpec>(
    store: &mut Store<E>,
    attester_slashing: &AttesterSlashing<2048>,
) -> Result<(), ForkChoiceError>
where
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::predicates::{
        is_slashable_attestation_data, is_valid_indexed_attestation,
    };

    let att1 = &attester_slashing.attestation_1;
    let att2 = &attester_slashing.attestation_2;

    if !is_slashable_attestation_data(&att1.data, &att2.data) {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: "attestation data is not slashable".to_owned(),
        });
    }

    let state = store
        .block_states
        .get(&store.justified_checkpoint.root)
        .ok_or(ForkChoiceError::MissingBlock {
            root: store.justified_checkpoint.root,
        })?;

    if !is_valid_indexed_attestation::<E>(state, att1, true) {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: "attestation_1 is not a valid indexed attestation".to_owned(),
        });
    }
    if !is_valid_indexed_attestation::<E>(state, att2, true) {
        return Err(ForkChoiceError::InvalidAttestation {
            reason: "attestation_2 is not a valid indexed attestation".to_owned(),
        });
    }

    // Add the intersection to the equivocating set.
    let indices1: std::collections::HashSet<_> =
        att1.attesting_indices.as_slice().iter().copied().collect();
    let indices2: std::collections::HashSet<_> =
        att2.attesting_indices.as_slice().iter().copied().collect();

    for index in indices1.intersection(&indices2) {
        store.equivocating_indices.insert(*index);
    }

    Ok(())
}

// ── BeaconStateWrite bound helper ─────────────────────────────────────────────

// Re-export the BeaconStateWrite trait so that callers of this module's
// functions have access to it without an extra import.
pub use pharos_stf::phase0::state_write::BeaconStateWrite;
