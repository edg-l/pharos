//! Node startup helpers — warm-restart rehydration of the in-memory fork-choice
//! store from persisted RocksDB data.
//!
//! # Warm-restart contract (`D-rocksdb` snapshot-rehydration) — Phase 4 update
//!
//! After the Phase-3 freezer migrates finalized blocks/states to cold CFs, the
//! hot region only holds epoch-boundary states in `[split_slot, head_slot]`.
//! Intermediate-slot states are NOT stored; the old walk that silently skipped
//! stateless blocks (`if let Some(state) = get_state`) would produce a sparse
//! `block_states` map with holes in the parent→child chain (CRITICAL-3).
//!
//! `rehydrate_fork_choice_store` fixes this by:
//!
//! 1. Reading `metadata[b"split_slot"]` to determine the hot window start.
//!    Pre-split data lives in cold CFs and is NOT rehydrated into in-memory maps
//!    (served on demand by `StateRegenService`).
//! 2. Loading the anchor block at `snapshot.finalized_checkpoint.root`, falling
//!    through `get_block` → `get_cold_block` when the block has been migrated.
//!    The anchor state falls through similarly: hot `states` → cold restore-point
//!    + replay.
//! 3. Forward-walking `slot_to_block_root` from `split_slot` to `head_slot`,
//!    loading each canonical block AND regenerating its post-state for every
//!    slot where a full state was NOT stored (non-epoch-boundary slots) via
//!    `inline_replay_to`, so `block_states` is DENSE over `[split_slot, head_slot]`.
//! 4. Re-deriving `checkpoint_states` and rehydrating `payload_statuses`.
//!
//! # Why dense `[split_slot, head_slot]` suffices for `filter_block_tree`/`get_head`
//!
//! `get_filtered_block_tree` (`get_head.rs:329-338`) seeds its walk at
//! `store.justified_checkpoint.root` (line 334) and `filter_block_tree`
//! (`get_head.rs:253-326`) recurses only over blocks that are children of that
//! base via `parent_root` child-enumeration over `store.blocks` (lines 280-296).
//! `get_head` (`get_head.rs:346-375`) descends GHOST likewise from
//! `justified_checkpoint.root`.  Since `justified_checkpoint.epoch ≥
//! finalized_checkpoint.epoch ≥ split_slot / SLOTS_PER_EPOCH`, the walk base is
//! always at or above `split_slot`, so a dense `[split_slot, head_slot]` window
//! fully covers the reachable set.  Pre-split blocks are never reached from the
//! walk base, so not rehydrating them is correct (CRITICAL-3 fix).
//!
//! After this function returns, the caller MUST call
//! `pharos_fork_choice::on_tick(&mut store, SystemTime::now()...)` to advance
//! the time cursor from `snapshot.last_known_time` to wall-clock.

use std::collections::{HashMap, HashSet};

use pharos_ssz::TreeHash;
use pharos_stf::phase0::state_write::BeaconStateWrite;
use pharos_stf::{
    AltairDispatch, AltairProcessSlotsDispatch, AltairUpgradeDispatch, BellatrixDispatch,
    BellatrixProcessSlotsDispatch, BellatrixUpgradeDispatch, CapellaDispatch,
    CapellaProcessSlotsDispatch, CapellaUpgradeDispatch, DenebDispatch, DenebProcessSlotsDispatch,
    ForkEpochs, NullExecutionEngine, Phase0UpgradeDispatch, process_slots_fork, state_transition,
};
use pharos_storage::{ForkChoiceSnapshot, RocksStore, StorageError, Store};
use pharos_types::PayloadStatus;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::Checkpoint;
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::views::BeaconBlockBodyView;
use pharos_types::{BeaconBlockView, BeaconSpec, SignedBeaconBlockView};
use pharos_utils::{Hash256, Uint256};
use tracing::warn;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the inner `E::BeaconBlock` from a fork-enum `E::SignedBeaconBlock`.
///
/// Infallible: `BeaconSpec::signed_block_message` dispatches over an exhaustive
/// match, so every fork variant is handled (a new fork is a compile error
/// there). The `Option` return is retained for caller ergonomics.
fn extract_block<E: BeaconSpec>(signed: &E::SignedBeaconBlock) -> Option<E::BeaconBlock> {
    Some(E::signed_block_message(signed))
}

/// Load a beacon state by root, falling through to cold restore-point + replay
/// when the hot `states` CF does not contain it.
///
/// Used for the anchor state during rehydration where the finalized state may
/// have been pruned from hot storage by Phase-3 migration.
fn load_state_hot_or_cold<E: BeaconSpec>(
    store: &RocksStore,
    state_root: Root,
    search_up_to: Slot,
    runtime_cfg: &RuntimeConfig,
) -> Result<Option<E::BeaconState>, StorageError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState:
        AltairDispatch<E> + AltairProcessSlotsDispatch<E> + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixDispatch<E, NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + TreeHash,
    E::CapellaBeaconState: CapellaDispatch<E, NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: DenebDispatch<E, NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, NullExecutionEngine>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_stf::ElectraUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::FuluBeaconState: pharos_stf::FuluDispatch<E, NullExecutionEngine>
        + pharos_stf::FuluProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
{
    // 1. Hot states CF.
    if let Some(state) = <RocksStore as Store<E>>::get_state(store, &state_root)? {
        return Ok(Some(state));
    }

    // 2. Cold restore-points: find the nearest restore point at or before
    //    `search_up_to`, load the cold state, replay forward to find the state
    //    matching `state_root`.
    let Some((rp_slot, _)) = <RocksStore as Store<E>>::nearest_restore_point(store, search_up_to)?
    else {
        return Ok(None);
    };
    let Some(cold_state) = <RocksStore as Store<E>>::get_cold_state(store, rp_slot)? else {
        return Ok(None);
    };

    // Scan [rp_slot, search_up_to] to find which slot has `state_root` as its
    // post-state, then replay forward.
    for s in rp_slot.0..=search_up_to.0 {
        let slot = Slot(s);
        let block_root = match store.block_root_at_slot(slot)? {
            Some(r) => r,
            None => continue,
        };
        if let Ok(Some(summary)) = <RocksStore as Store<E>>::get_state_summary(store, &block_root) {
            if summary.state_root == state_root {
                // Replay from the cold restore point to this slot.
                return match inline_replay_to::<E>(store, cold_state, rp_slot, slot, runtime_cfg) {
                    Ok(replayed) => Ok(Some(replayed)),
                    Err(e) => {
                        warn!(
                            state_root = ?state_root,
                            error = %e,
                            "rehydrate: cold restore-point replay failed"
                        );
                        Ok(None)
                    }
                };
            }
        }
    }
    Ok(None)
}

/// Replay blocks from `start_slot+1` to `target_slot` using the slot-index and
/// stored blocks (hot then cold), applying the STF.
///
/// Equivalent to `StateRegenService::replay_to` but operates directly on
/// `&RocksStore` without requiring `Arc` wrapping, making it usable during the
/// early startup phase before `Arc`s are allocated.
///
/// Threads the caller-supplied `runtime_cfg` (the real fork schedule loaded from
/// `--config-dir`) through `state_transition` / `process_slots_fork` so a replay
/// that crosses a fork boundary (e.g. electra→fulu) upgrades live rather than
/// freezing on `UnsupportedFork` (the M6 `D-runtime-cfg-threading-live-loops`
/// lesson).  `validate_result = false` — stored blocks are trusted.
fn inline_replay_to<E: BeaconSpec>(
    store: &RocksStore,
    mut state: E::BeaconState,
    start_slot: Slot,
    target_slot: Slot,
    runtime_cfg: &RuntimeConfig,
) -> Result<E::BeaconState, StorageError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState:
        AltairDispatch<E> + AltairProcessSlotsDispatch<E> + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixDispatch<E, NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + TreeHash,
    E::CapellaBeaconState: CapellaDispatch<E, NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: DenebDispatch<E, NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, NullExecutionEngine>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_stf::ElectraUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::FuluBeaconState: pharos_stf::FuluDispatch<E, NullExecutionEngine>
        + pharos_stf::FuluProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
{
    if start_slot >= target_slot {
        return Ok(state);
    }

    let null_engine = NullExecutionEngine;
    // Use the REAL loaded fork schedule + slot duration. If the hot window being
    // replayed crosses a fork epoch (e.g. Bellatrix→Capella), `process_slots_fork`
    // must upgrade the state at that boundary — using `ForkEpochs::never()` here
    // would leave the state on the old fork and make the next-fork block fail
    // `UnsupportedFork`, leaving a hole in `block_states` (the CRITICAL-3 bug this
    // walk exists to prevent). The fork epochs are NETWORK config, not compile-time
    // (e.g. our devnet sets CAPELLA_FORK_EPOCH=1), so they must come from the
    // loaded `runtime_cfg`, not `E::*_FORK_EPOCH`.
    let fork_epochs = ForkEpochs::from_runtime_cfg(runtime_cfg);

    let mut current_slot = Slot(start_slot.0 + 1);

    while current_slot <= target_slot {
        let block_root_opt = store
            .block_root_at_slot(current_slot)
            .map_err(|_| StorageError::KeyNotFound)?;

        if let Some(block_root) = block_root_opt {
            // Load from hot CF first, then cold.
            let signed_block = match <RocksStore as Store<E>>::get_block(store, &block_root)? {
                Some(b) => b,
                None => match <RocksStore as Store<E>>::get_cold_block(store, &block_root)? {
                    Some(b) => b,
                    None => {
                        // Block missing from both — advance as empty slot.
                        process_slots_fork::<E>(&mut state, current_slot, fork_epochs, runtime_cfg)
                            .map_err(|_| StorageError::KeyNotFound)?;
                        current_slot = Slot(current_slot.0 + 1);
                        continue;
                    }
                },
            };

            let (new_state, _) = state_transition::<E, NullExecutionEngine>(
                state,
                &signed_block,
                &null_engine,
                false,
                runtime_cfg,
            )
            .map_err(|e| {
                warn!(slot = current_slot.0, error = %e, "inline_replay_to: state_transition failed");
                StorageError::KeyNotFound
            })?;
            state = new_state;
            current_slot = Slot(current_slot.0 + 1);
        } else {
            // Empty slot — advance via process_slots_fork.
            process_slots_fork::<E>(&mut state, current_slot, fork_epochs, runtime_cfg)
                .map_err(|e| {
                    warn!(slot = current_slot.0, error = %e, "inline_replay_to: process_slots_fork failed");
                    StorageError::KeyNotFound
                })?;
            current_slot = Slot(current_slot.0 + 1);
        }
    }

    Ok(state)
}

// ── rehydrate_fork_choice_store ───────────────────────────────────────────────

/// Rebuild the in-memory `pharos_fork_choice::Store<E>` from persisted data.
///
/// Handles both the legacy (pre-split) case and the Phase-4 hot/cold case where
/// the freezer has migrated finalized data below `split_slot` to cold CFs and
/// pruned non-epoch-boundary states from hot storage.
///
/// # CRITICAL-3 fix
///
/// The pre-Phase-4 walk used `if let Some(state) = get_state(state_root)` and
/// silently skipped blocks with no stored state.  After the freezer prunes
/// non-epoch-boundary states, this would produce a sparse `blocks` map with
/// holes in the parent→child chain that `filter_block_tree`/`get_head` walk.
/// This version regenerates intermediate post-states via `inline_replay_to` so
/// `block_states` is DENSE over `[split_slot, head_slot]`.
///
/// Returns `Err(StorageError::KeyNotFound)` when the anchor block cannot be
/// found in either hot or cold storage.
pub fn rehydrate_fork_choice_store<E: BeaconSpec>(
    store: &RocksStore,
    snapshot: &ForkChoiceSnapshot,
    runtime_cfg: &RuntimeConfig,
) -> Result<pharos_fork_choice::Store<E>, StorageError>
where
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState:
        AltairDispatch<E> + AltairProcessSlotsDispatch<E> + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixDispatch<E, NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + TreeHash,
    E::CapellaBeaconState: CapellaDispatch<E, NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: DenebDispatch<E, NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, NullExecutionEngine>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_stf::ElectraUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::FuluBeaconState: pharos_stf::FuluDispatch<E, NullExecutionEngine>
        + pharos_stf::FuluProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
{
    // ── Step 1: Determine the hot window start (split_slot) ───────────────────
    //
    // Everything strictly below `split_slot` lives in cold CFs and is NOT
    // rehydrated into the in-memory maps (served on demand by regen).
    // Default to 0 when the key is absent (genesis or pre-Phase-4 node).
    let split_slot: Slot = <RocksStore as Store<E>>::get_metadata(store, b"split_slot")
        .unwrap_or(None)
        .and_then(|v| {
            v.try_into()
                .ok()
                .map(|arr: [u8; 8]| Slot(u64::from_be_bytes(arr)))
        })
        .unwrap_or(Slot(0));

    // ── Step 2: Load the anchor block + state (hot or cold) ──────────────────
    let anchor_root = snapshot.finalized_checkpoint.root;

    // Try hot blocks first; fall through to cold when migrated.
    let anchor_signed = match <RocksStore as Store<E>>::get_block(store, &anchor_root)? {
        Some(b) => b,
        None => <RocksStore as Store<E>>::get_cold_block(store, &anchor_root)?
            .ok_or(StorageError::KeyNotFound)?,
    };

    let anchor_block = extract_block::<E>(&anchor_signed).ok_or(StorageError::KeyNotFound)?;
    let anchor_state_root = anchor_block.state_root();
    let anchor_slot = anchor_block.slot();

    // Try hot states CF first; fall through to cold restore-point + replay.
    let anchor_state = load_state_hot_or_cold::<E>(
        store,
        anchor_state_root,
        split_slot.max(anchor_slot),
        runtime_cfg,
    )?
    .ok_or(StorageError::KeyNotFound)?;

    // Seed the maps with the anchor.
    let mut blocks: HashMap<Root, E::BeaconBlock> = HashMap::new();
    blocks.insert(anchor_root, anchor_block);

    let mut block_states: HashMap<Root, E::BeaconState> = HashMap::new();
    block_states.insert(anchor_root, anchor_state);

    // ── Step 3: Forward-walk [split_slot, head_slot] ──────────────────────────
    //
    // Walk `slot_to_block_root` from `split_slot` (the hot window start) up to
    // `head_slot` (inclusive) via `get_blocks_by_range`.
    //
    // For each canonical block in range:
    //   - Insert the block into `blocks`.
    //   - Try loading its post-state from the hot `states` CF (epoch boundaries).
    //   - For intermediate slots with no stored state, regenerate via
    //     `inline_replay_to` from the last loaded state so `block_states` is
    //     DENSE.  This is the NORMAL path; the `if let Some` guard is only
    //     defensive (never the normal code path after Phase-4).
    //
    // VERIFY (CRITICAL-3 filter_block_tree/get_head invariant):
    //   `filter_block_tree` (get_head.rs:253-326) is called with base =
    //   `store.justified_checkpoint.root` (get_head.rs:334).  It recurses only
    //   over blocks whose `parent_root` == the current node (lines 280-296), so
    //   it only visits entries in `store.blocks`.  `get_head` (get_head.rs:346-375)
    //   likewise descends from `justified_checkpoint.root`.
    //   Since `justified ≥ finalized ≥ split_slot`, a dense [split_slot, head_slot]
    //   window fully covers every block reachable from the walk base.  Pre-split
    //   blocks are in cold CFs (not in `store.blocks`) and are never reached.
    let end_slot = snapshot.head_slot;
    if end_slot >= split_slot {
        let count = end_slot.0.saturating_sub(split_slot.0).saturating_add(1);
        let range_blocks = <RocksStore as Store<E>>::get_blocks_by_range(store, split_slot, count)?;

        // Track the most recently loaded (root, state, slot) for replay.
        let mut replay_anchor: Option<(Root, E::BeaconState, Slot)> = {
            block_states
                .get(&anchor_root)
                .cloned()
                .map(|s| (anchor_root, s, anchor_slot))
        };

        for signed in range_blocks {
            let block = match extract_block::<E>(&signed) {
                Some(b) => b,
                None => continue,
            };
            let block_root = block.tree_hash_root();
            let block_slot = block.slot();
            let state_root = block.state_root();

            // Skip anchor — already inserted.
            if block_root == anchor_root {
                continue;
            }

            // Insert the block.
            blocks.insert(block_root, block);

            // Try the hot states CF first (epoch-boundary states).
            match <RocksStore as Store<E>>::get_state(store, &state_root)? {
                Some(state) => {
                    block_states.insert(block_root, state.clone());
                    replay_anchor = Some((block_root, state, block_slot));
                }
                None => {
                    // Intermediate slot: no stored state.  Regenerate via replay
                    // from the last loaded state.  This is the NORMAL path for
                    // non-epoch-boundary slots; the guard above is only defensive.
                    if let Some((_, ref anchor_s, anchor_s_slot)) = replay_anchor {
                        match inline_replay_to::<E>(
                            store,
                            anchor_s.clone(),
                            anchor_s_slot,
                            block_slot,
                            runtime_cfg,
                        ) {
                            Ok(replayed) => {
                                block_states.insert(block_root, replayed.clone());
                                replay_anchor = Some((block_root, replayed, block_slot));
                            }
                            Err(e) => {
                                warn!(
                                    root = ?block_root,
                                    slot = block_slot.0,
                                    error = %e,
                                    "rehydrate: inline replay failed for intermediate slot; skipping (CRITICAL-3 guard)"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Step 4: re-derive checkpoint_states ──────────────────────────────────
    let mut checkpoint_states: HashMap<Checkpoint, E::BeaconState> = HashMap::new();

    if let Some(just_state) = block_states
        .get(&snapshot.justified_checkpoint.root)
        .cloned()
    {
        checkpoint_states.insert(snapshot.justified_checkpoint.clone(), just_state);
    }
    if let Some(fin_state) = block_states
        .get(&snapshot.finalized_checkpoint.root)
        .cloned()
    {
        checkpoint_states.insert(snapshot.finalized_checkpoint.clone(), fin_state);
    }

    // ── Step 5: rehydrate payload_statuses ───────────────────────────────────
    let mut payload_statuses: HashMap<Root, PayloadStatus> = {
        let raw = <RocksStore as Store<E>>::payload_statuses_iter(store)?;
        raw.into_iter().collect()
    };
    // Per `specs/sync/optimistic.md` "Checkpoint Sync (Weak Subjectivity Sync)":
    // the anchor is a trusted weak-subjectivity root; its payload is VALID.
    // `or_insert` preserves an explicit Valid already written by `apply_anchor`
    // (via the BlockTransition payload_status field) while also covering any
    // older DB that predates that write.
    payload_statuses
        .entry(anchor_root)
        .or_insert(PayloadStatus::Valid);

    // ── Step 6: build the Store ───────────────────────────────────────────────
    // Terminal-block constants are zeroed here; the caller (main.rs) sets them
    // via `Store::set_terminal_config` using the loaded `RuntimeConfig`.
    Ok(pharos_fork_choice::Store {
        time: snapshot.last_known_time,
        genesis_time: snapshot.genesis_time,
        justified_checkpoint: snapshot.justified_checkpoint.clone(),
        finalized_checkpoint: snapshot.finalized_checkpoint.clone(),
        unrealized_justified_checkpoint: snapshot.unrealized_justified_checkpoint.clone(),
        unrealized_finalized_checkpoint: snapshot.unrealized_finalized_checkpoint.clone(),
        proposer_boost_root: snapshot.proposer_boost_root,
        equivocating_indices: HashSet::new(),
        blocks,
        block_states,
        block_timeliness: HashMap::new(),
        checkpoint_states,
        latest_messages: HashMap::new(),
        unrealized_justifications: HashMap::new(),
        payload_statuses,
        terminal_total_difficulty: Uint256::ZERO,
        terminal_block_hash: Hash256::default(),
        terminal_block_hash_activation_epoch: u64::MAX,
        altair_fork_epoch: u64::MAX,
        bellatrix_fork_epoch: u64::MAX,
        capella_fork_epoch: u64::MAX,
        runtime_cfg: runtime_cfg.clone(),
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_fork_choice::get_forkchoice_store;
    use pharos_storage::{BlockTransition, RocksStoreConfig};
    use pharos_types::MainnetBeaconSpec;
    use pharos_types::phase0::primitives::Root;
    use pharos_types::state::BeaconBlock as ForkBeaconBlock;

    fn make_store_with_snapshot(dir: &tempfile::TempDir) -> (RocksStore, ForkChoiceSnapshot) {
        let rocks = RocksStore::open::<MainnetBeaconSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store");

        let genesis_state = <MainnetBeaconSpec as BeaconSpec>::BeaconState::default();
        let state_root = genesis_state.tree_hash_root();
        let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
            state_root,
            ..pharos_types::phase0::MainnetBeaconBlock::default()
        });
        let fc =
            get_forkchoice_store::<MainnetBeaconSpec>(genesis_state.clone(), anchor_block.clone());

        let block_root: Root = anchor_block.tree_hash_root();

        let snap = ForkChoiceSnapshot {
            genesis_time: fc.genesis_time,
            justified_checkpoint: fc.justified_checkpoint.clone(),
            finalized_checkpoint: fc.finalized_checkpoint.clone(),
            unrealized_justified_checkpoint: fc.unrealized_justified_checkpoint.clone(),
            unrealized_finalized_checkpoint: fc.unrealized_finalized_checkpoint.clone(),
            proposer_boost_root: fc.proposer_boost_root,
            head_root: block_root,
            head_slot: pharos_types::phase0::Slot(0),
            last_known_time: fc.genesis_time,
        };

        {
            use pharos_types::phase0::MainnetSignedBeaconBlock;
            use pharos_types::state::SignedBeaconBlock;
            <RocksStore as Store<MainnetBeaconSpec>>::put_block(
                &rocks,
                block_root,
                &SignedBeaconBlock::Phase0(MainnetSignedBeaconBlock {
                    message: pharos_types::phase0::MainnetBeaconBlock {
                        state_root,
                        ..Default::default()
                    },
                    signature: Default::default(),
                }),
            )
            .expect("put block");
        }
        <RocksStore as Store<MainnetBeaconSpec>>::put_state(&rocks, state_root, &genesis_state)
            .expect("put state");

        (rocks, snap)
    }

    #[test]
    fn rehydrate_seeds_payload_statuses() {
        let dir = tempfile::TempDir::new().unwrap();
        let (rocks, snap) = make_store_with_snapshot(&dir);

        let root_a = Root::from([0x01u8; 32]);
        let root_b = Root::from([0x02u8; 32]);
        let root_c = Root::from([0x03u8; 32]);

        for (root, status) in [
            (root_a, PayloadStatus::Valid),
            (root_b, PayloadStatus::Invalid),
            (root_c, PayloadStatus::NotValidated),
        ] {
            let mut bt = BlockTransition::<MainnetBeaconSpec>::new();
            bt.payload_status = Some((root, status));
            <RocksStore as Store<MainnetBeaconSpec>>::write_block_transition(&rocks, bt)
                .expect("write");
        }

        let fc_store = rehydrate_fork_choice_store::<MainnetBeaconSpec>(
            &rocks,
            &snap,
            &RuntimeConfig::default(),
        )
        .expect("rehydrate");

        assert_eq!(
            fc_store.payload_statuses.get(&root_a),
            Some(&PayloadStatus::Valid)
        );
        assert_eq!(
            fc_store.payload_statuses.get(&root_b),
            Some(&PayloadStatus::Invalid)
        );
        assert_eq!(
            fc_store.payload_statuses.get(&root_c),
            Some(&PayloadStatus::NotValidated)
        );
        // Fix 1c: anchor root is seeded as Valid by rehydrate_fork_choice_store.
        let anchor_root = snap.finalized_checkpoint.root;
        assert_eq!(
            fc_store.payload_statuses.get(&anchor_root),
            Some(&PayloadStatus::Valid),
            "rehydrate must seed anchor root as Valid"
        );
        assert_eq!(fc_store.payload_statuses.len(), 4);
    }
}
