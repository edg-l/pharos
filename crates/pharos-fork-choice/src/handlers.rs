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
use crate::pow_block::{PowBlockProvider, ValidateMergeBlockError, validate_merge_block};
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
    E::AltairBeaconState: pharos_stf::AltairJaFDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixJaFDispatch<E>,
    E::CapellaBeaconState: pharos_stf::CapellaJaFDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebJaFDispatch<E>,
    E::BeaconBlock: BeaconBlockView,
    E::Phase0BeaconBlockBody:
        BeaconBlockBodyView<Attestation = pharos_types::phase0::Attestation<2048>>,
{
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    use pharos_stf::process_justification_and_finalization_fork;

    let mut state = store
        .block_states
        .get(&block_root)
        .ok_or(ForkChoiceError::MissingBlock { root: block_root })?
        .clone();

    // `process_justification_and_finalization` is called on the clone to
    // compute the unrealized checkpoints.  Per the spec: "Pull up the
    // post-state of the block to the next epoch boundary".
    // Dispatches to the phase0 or altair implementation based on the state's
    // fork variant.
    process_justification_and_finalization_fork::<E>(&mut state)?;

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
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState:
        pharos_stf::CapellaProcessSlotsDispatch<E> + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use crate::get_head::get_head;
    use pharos_stf::phase0::accessors::get_beacon_proposer_index;
    use pharos_stf::process_slots_fork;

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
        let fork_epochs = store.fork_epochs();
        let runtime_cfg = store.runtime_cfg.clone();
        if head_state.slot() < slot
            && process_slots_fork::<E>(&mut head_state, slot, fork_epochs, &runtime_cfg).is_err()
        {
            return;
        }

        let block = match store.blocks.get(&root) {
            Some(b) => b,
            None => return,
        };
        let block_proposer = block.proposer_index();
        let computed_proposer = get_beacon_proposer_index::<E>(&head_state);
        if block_proposer == computed_proposer {
            store.proposer_boost_root = root;
        }
    }
}

// ── on_block ──────────────────────────────────────────────────────────────────

/// `on_block` per `specs/phase0/fork-choice.md:846-885` with Bellatrix merge-transition
/// guard per `specs/bellatrix/fork-choice.md:303-304`.
///
/// Validates the block (slot bounds, finalized-chain ancestry), inserts it and
/// its precomputed `post_state` into the store, and eagerly computes unrealized
/// justification via `compute_pulled_up_tip`.
///
/// The caller is responsible for running `state_transition` and supplying
/// `post_state` **before** calling `on_block`. This separation ensures the
/// production block-ingestion loop can use a real `ExecutionEngine` for STF
/// while fork-choice itself remains engine-agnostic.
///
/// `now` is the current unix timestamp (seconds); it is used only to record
/// block timeliness for proposer-boost purposes.
///
/// For Bellatrix merge-transition blocks, calls `validate_merge_block` via
/// `pow_provider` before inserting into the store. Non-Bellatrix blocks ignore
/// `pow_provider`. The merge guard reads the pre-state from
/// `store.block_states[block.parent_root]`, which must already be present.
///
/// Per `specs/bellatrix/fork-choice.md:303-304` (merge-transition guard) and
/// `specs/bellatrix/fork-choice.md:200-260` (validate_merge_block body).
pub fn on_block<E: EthSpec, P: PowBlockProvider>(
    store: &mut Store<E>,
    signed_block: &E::SignedBeaconBlock,
    post_state: E::BeaconState,
    now: u64,
    pow_provider: &P,
) -> Result<(), ForkChoiceError>
where
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::BeaconState: BeaconStateWrite + Clone,
    E::AltairBeaconState: pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebJaFDispatch<E> + pharos_stf::DenebProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconBlock: BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView + Clone,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
{
    use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;

    // Extract the inner `E::BeaconBlock` (fork-enum) via the exhaustive-match
    // dispatch on `EthSpec`; `signed_block.message()` panics on the fork-enum and
    // a per-fork `if let` chain has no exhaustiveness check (a missing fork arm
    // would wrongly reject the block as invalid).
    let block: E::BeaconBlock = E::signed_block_message(signed_block);

    // Parent block must be known; read pre_state for the merge-transition guard.
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

    let block_root: Root = block.tree_hash_root();

    // [New in Bellatrix] Merge-transition guard per
    // `specs/bellatrix/fork-choice.md:303-304`.
    //
    // `is_merge_transition_block` checks whether this is the first Bellatrix
    // block with a non-default execution payload against a pre-state that has
    // not yet completed the merge. For Phase0/Altair blocks this returns false
    // immediately.
    if E::is_merge_transition_block(&pre_state, &block) {
        use pharos_stf::phase0::accessors::compute_epoch_at_slot;
        let current_epoch = compute_epoch_at_slot(block.slot(), E::SLOTS_PER_EPOCH).0;
        // Extract the execution payload's parent_hash from the block.
        // `is_merge_transition_block` returned true → block is Bellatrix.
        let payload_parent_hash = E::get_execution_payload_parent_hash(&block).unwrap_or_default();
        // TTD / TERMINAL_BLOCK_HASH constants come from the store's runtime config.
        // For conformance / test uses the defaults (zero TTD, zero TBH) are fine;
        // the production ingestion loop sets these from `RuntimeConfig`.
        // Optimistic relaxation per `consensus-specs/sync/optimistic.md:169-174`:
        //
        // > The `validate_merge_block` function MUST NOT raise an assertion if
        // > both the `pow_block` and `pow_parent` are unknown to the execution
        // > engine.
        // > All other assertions in `validate_merge_block` (e.g.,
        // > `TERMINAL_BLOCK_HASH`) MUST prevent an optimistic import.
        //
        // `PowBlockNotFound` means the terminal PoW block (pow_block) itself
        // is absent from the provider.  When pow_block is absent it is never
        // queried for its parent, so both pow_block and pow_parent are unknown
        // per `consensus-specs/sync/optimistic.md` (~line 170): "both unknown"
        // → MUST NOT raise; import optimistically.
        //
        // `PowParentNotFound` can ONLY occur when pow_block WAS found (known
        // pow_block, unknown parent).  That is "known pow_block / unknown
        // pow_parent", NOT "both unknown", so it does NOT qualify for the
        // optimistic relaxation and still rejects the block.
        //
        // The block is inserted and marked `NotValidated` below; the EL
        // re-validates via `newPayload`, and `promote_valid_ancestors` /
        // `apply_invalid_payload` resolve its status later.
        match validate_merge_block(
            payload_parent_hash,
            current_epoch,
            store.terminal_block_hash,
            store.terminal_block_hash_activation_epoch,
            store.terminal_total_difficulty,
            pow_provider,
        ) {
            Ok(()) => {}
            Err(ValidateMergeBlockError::PowBlockNotFound { hash }) => {
                // `consensus-specs/sync/optimistic.md:170-171`: both pow_block
                // and pow_parent unknown → MUST NOT raise; import optimistically.
                tracing::warn!(
                    ?hash,
                    "merge-transition block: terminal PoW unavailable; \
                     importing optimistically (NotValidated)"
                );
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Insert block and post-state (supplied by the caller after running STF).
    store.blocks.insert(block_root, block.clone());
    store.block_states.insert(block_root, post_state.clone());

    // Default-mark the EL payload as `NotValidated`; the engine driver loop
    // (M4a Phase 4) updates this to `Valid`/`Invalid` once the EL responds
    // to `engine_newPayloadV1`. Pre-Bellatrix blocks also get an entry, but
    // the engine driver only emits `newPayload` for Bellatrix+ payloads, so
    // their status stays `NotValidated` for the lifetime of the entry.
    //
    // Uses `mark_payload_status_if_absent` so a `Valid`/`Invalid` verdict the
    // async engine driver may have already written for a block that raced
    // through the newPayload path before the persist worker is not clobbered.
    store.mark_payload_status_if_absent(block_root, pharos_types::PayloadStatus::NotValidated);

    // Record timeliness using the caller-supplied `now` timestamp.
    // Saves `store.time` from being mutated by on_block (time is managed by on_tick).
    let saved_time = store.time;
    store.time = now;
    record_block_timeliness::<E>(store, block_root);
    store.time = saved_time;

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
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState:
        pharos_stf::CapellaProcessSlotsDispatch<E> + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
    use pharos_stf::process_slots_fork;

    if store.checkpoint_states.contains_key(target) {
        return Ok(());
    }

    let base_state_opt = store.block_states.get(&target.root).cloned();
    let mut base_state =
        base_state_opt.ok_or(ForkChoiceError::MissingBlock { root: target.root })?;

    let target_slot = compute_start_slot_at_epoch(target.epoch, E::SLOTS_PER_EPOCH);
    if base_state.slot() < target_slot {
        let fork_epochs = store.fork_epochs();
        let runtime_cfg = store.runtime_cfg.clone();
        process_slots_fork::<E>(&mut base_state, target_slot, fork_epochs, &runtime_cfg)?;
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
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState:
        pharos_stf::CapellaProcessSlotsDispatch<E> + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
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

// ── should_override_forkchoice_update ────────────────────────────────────────

/// `should_override_forkchoice_update` per `specs/bellatrix/fork-choice.md`.
///
/// Returns `true` when the proposer should withhold the forkchoice-updated call
/// to avoid triggering a re-org of its own proposal (proposer-boost re-org
/// prevention). Full implementation is deferred to M11 (proposer-boost
/// re-orgs). For M4a this always returns `false`.
///
/// The conformance runner gates assertions on the YAML expecting `false`.
pub fn should_override_forkchoice_update<E: EthSpec>(_store: &Store<E>) -> bool {
    false
}

// ── BeaconStateWrite bound helper ─────────────────────────────────────────────

// Re-export the BeaconStateWrite trait so that callers of this module's
// functions have access to it without an extra import.
pub use pharos_stf::phase0::state_write::BeaconStateWrite;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use pharos_ssz::TreeHash;
    use pharos_stf::{
        NullExecutionEngine,
        phase0::{genesis::BeaconStateMut as _, state_write::BeaconStateWrite as _},
        state_transition,
    };
    use pharos_types::{
        EthSpec, MinimalEthSpec,
        phase0::{Epoch, Gwei, Root, Slot, ValidatorIndex},
        state::{
            MinimalBeaconBlock as ForkMinBlock, MinimalBeaconState as ForkMinState,
            MinimalSignedBeaconBlock as ForkMinSignedBlock,
        },
    };
    use pharos_utils::BLSSignature;

    use crate::pow_block::NoopPowBlockProvider;
    use crate::store::get_forkchoice_store;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal genesis (state + anchor block) suitable for fork-choice
    /// idempotency testing.  Uses Phase0 blocks/states to avoid Bellatrix merge
    /// transition complexity.
    fn build_phase0_genesis() -> (ForkMinState, ForkMinBlock) {
        use pharos_types::phase0::{Fork, MinimalBeaconState, Validator};
        use pharos_utils::{BLSPubkey, Bytes4, Bytes32, Hash256};

        let genesis_time = 1_000_000u64;
        let eth1_data = pharos_types::phase0::Eth1Data::default();
        let body_root = pharos_types::phase0::MinimalBeaconBlockBody::default().tree_hash_root();
        let fork = Fork {
            previous_version: Bytes4::from_array([0; 4]),
            current_version: Bytes4::from_array([0; 4]),
            epoch: Epoch(0),
        };
        let mut state = MinimalBeaconState::genesis_state(
            genesis_time,
            fork,
            eth1_data,
            body_root,
            Hash256::default(),
        );

        // One validator; required for get_beacon_proposer_index.
        let v = Validator {
            pubkey: BLSPubkey::from_array([0u8; 48]),
            withdrawal_credentials: Bytes32::default(),
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            slashed: false,
            activation_eligibility_epoch: Epoch(0),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            ..Validator::default()
        };
        state.push_validator(v).unwrap();
        state
            .push_balance(Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE))
            .unwrap();

        let state_root = state.tree_hash_root();
        let anchor_block_inner = pharos_types::phase0::MinimalBeaconBlock {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: pharos_types::phase0::MinimalBeaconBlockBody::default(),
        };

        (
            ForkMinState::Phase0(state),
            ForkMinBlock::Phase0(anchor_block_inner),
        )
    }

    /// Build a signed Phase0 block at `slot` with `parent_root`, signed with
    /// a zero BLS signature (validate_result = false bypasses verification).
    fn make_signed_block(slot: u64, parent_root: Root) -> ForkMinSignedBlock {
        use pharos_types::phase0::MinimalSignedBeaconBlock as P0Signed;

        let block = pharos_types::phase0::MinimalBeaconBlock {
            slot: Slot(slot),
            proposer_index: ValidatorIndex(0),
            parent_root,
            state_root: Root::default(),
            body: pharos_types::phase0::MinimalBeaconBlockBody::default(),
        };
        ForkMinSignedBlock::Phase0(P0Signed {
            message: block,
            signature: BLSSignature::from_array([0u8; 96]),
        })
    }

    // ── Test ─────────────────────────────────────────────────────────────────

    /// Verify that calling `on_block` with the same block twice is idempotent:
    /// the second call returns `Ok(())` and `store.blocks` still contains exactly
    /// one entry for `block_a.tree_hash_root()`.
    ///
    /// This pins the property that `HashMap::insert` (used at handlers.rs:351-352)
    /// is a plain overwrite with no "already known" guard.  If a future refactor
    /// adds a `BlockKnown` guard that returns `Err(...)` on re-insertion, this
    /// test will fail and force re-review of the backfill loop design.
    #[test]
    fn on_block_is_idempotent_on_reapplication() {
        use pharos_types::config::RuntimeConfig;

        let (genesis_state, anchor_block) = build_phase0_genesis();
        let anchor_root: Root = anchor_block.tree_hash_root();
        let genesis_state_clone = genesis_state.clone();

        let mut store = get_forkchoice_store::<MinimalEthSpec>(genesis_state.clone(), anchor_block);
        // Advance store.time well past genesis so on_block's "future slot" guard
        // doesn't reject block at slot 1.
        store.time = 10_000_000;

        // Build and apply block A (slot 1) via STF to get the post-state.
        let cfg = RuntimeConfig {
            seconds_per_slot: 6, // MinimalEthSpec slot duration
            ..RuntimeConfig::default()
        };
        let signed_a = make_signed_block(1, anchor_root);
        let (post_a, _) = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            genesis_state_clone,
            &signed_a,
            &NullExecutionEngine,
            false,
            &cfg,
        )
        .expect("STF for block A must succeed");

        // First application: must succeed.
        super::on_block::<MinimalEthSpec, NoopPowBlockProvider>(
            &mut store,
            &signed_a,
            post_a.clone(),
            10_000_000,
            &NoopPowBlockProvider,
        )
        .expect("first on_block must return Ok(())");

        let block_a_root: Root = match &signed_a {
            ForkMinSignedBlock::Phase0(s) => s.message.tree_hash_root(),
            _ => panic!("expected Phase0 block"),
        };
        assert!(
            store.blocks.contains_key(&block_a_root),
            "block A must be in store after first on_block"
        );

        // Second application with identical arguments: must also return Ok(()).
        let result = super::on_block::<MinimalEthSpec, NoopPowBlockProvider>(
            &mut store,
            &signed_a,
            post_a,
            10_000_000,
            &NoopPowBlockProvider,
        );
        assert!(
            result.is_ok(),
            "second on_block (re-application) must return Ok(()), got: {result:?}"
        );

        // Store must still contain exactly one entry for block_a_root.
        assert!(
            store.blocks.contains_key(&block_a_root),
            "block A root must still be in store after re-application"
        );

        // Verify no spurious extra entries were created (anchor + block A = 2).
        assert_eq!(
            store.blocks.len(),
            2,
            "store must contain exactly anchor + block A after two on_block calls, got {}",
            store.blocks.len()
        );
    }
}
