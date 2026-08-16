//! State regeneration service — replay-on-read for arbitrary historical states.
//!
//! `StateRegenService<E>` resolves an arbitrary `(slot | state_root)` query by:
//!   1. Finding the nearest stored state at-or-before the target (hot epoch-boundary
//!      state or cold restore point, whichever is highest and ≤ target).
//!   2. Replaying persisted blocks from that boundary up to the target via
//!      `process_slots_fork` (empty-slot advance) and `state_transition`
//!      (block-applying), using the same STF primitives as `import_block`.
//!
//! Per `D-replay-on-read` (M-Storage). The service is sync; callers wrap in
//! `tokio::task::spawn_blocking`.

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;

use pharos_fork_choice::Store as FcStore;
use pharos_ssz::TreeHash;
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::{
    EthSpec,
    config::RuntimeConfig,
    phase0::primitives::{Root, Slot},
};

// ── RegenError ────────────────────────────────────────────────────────────────

/// Errors from the state-regeneration service.
#[derive(Debug, Error)]
pub enum RegenError {
    /// No suitable anchor state exists at or before the target slot.
    #[error("missing anchor state for replay (no stored state at or before target)")]
    MissingAnchorState,

    /// A block required for replay is absent from the store.
    #[error("missing block {root:?} required for replay")]
    MissingBlock { root: Root },

    /// State-transition failed during replay.
    #[error("STF error during replay: {0}")]
    Stf(#[from] pharos_stf::StateTransitionError),

    /// Storage/DB read error during regeneration.
    #[error("storage error during regen: {0}")]
    Storage(#[from] pharos_storage::StorageError),

    /// Requested slot or root not found anywhere.
    #[error("state not found: {0}")]
    NotFound(String),
}

// (Phase-3: cold-CF reads are implemented directly on `Store<E>` in
// pharos-storage/src/store.rs + db.rs. The Phase-2 `RocksStoreColdExt` stub
// is removed; `nearest_cold_restore_point` now calls the real trait methods.)

// ── StateRegenService ─────────────────────────────────────────────────────────

/// Service that resolves historical states by nearest-boundary + replay.
///
/// Held by `NodeChainState` (behind `Option<Arc<...>>`) when the HTTP server is
/// active. Constructed once in `main.rs` and injected at startup.
pub struct StateRegenService<E: EthSpec> {
    /// Persistent block + state + state-summary store.
    store: Arc<RocksStore>,
    /// In-memory fork-choice store (hot `block_states` map).
    fork_choice: Arc<RwLock<FcStore<E>>>,
    /// Runtime configuration (fork schedule, preset constants).
    runtime_cfg: Arc<RuntimeConfig>,
    /// Fork epoch schedule extracted from `runtime_cfg` at construction time.
    fork_epochs: ForkEpochs,
}

impl<E: EthSpec> StateRegenService<E> {
    /// Construct a new `StateRegenService`.
    pub fn new(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<FcStore<E>>>,
        runtime_cfg: Arc<RuntimeConfig>,
    ) -> Self {
        let fork_epochs = ForkEpochs::from_runtime_cfg(&runtime_cfg);
        Self {
            store,
            fork_choice,
            runtime_cfg,
            fork_epochs,
        }
    }

    /// Return a reference to the underlying `RocksStore`.
    ///
    /// Used by the `main.rs` regen-closure to look up state-summaries by block
    /// root when dispatching `RegenTarget::BlockRoot`.
    pub fn store_ref(&self) -> &RocksStore {
        &self.store
    }

    // ── nearest_stored_state ──────────────────────────────────────────────────

    /// Find the nearest stored state at-or-before `target_slot`.
    ///
    /// Search order (highest-slot-wins):
    /// 1. Hot `block_states` map (in-memory fork-choice store).
    /// 2. Hot `states` CF in RocksDB — epoch-boundary states stored by state-root.
    ///    Scans the `slot_to_block_root` index backward from the nearest epoch
    ///    boundary ≤ `target_slot`, resolving each boundary via `state-summary`.
    /// 3. Cold restore-points CF (written by Phase-3 freezer; empty until then).
    ///
    /// Returns `(block_root, state, state_slot)` where `state_slot` is the slot
    /// of the block whose post-state is returned.
    pub fn nearest_stored_state(&self, target_slot: Slot) -> Option<(Root, E::BeaconState, Slot)> {
        // ── 1. Hot in-memory block_states map ────────────────────────────────
        let in_memory_best: Option<(Root, E::BeaconState, Slot)> = {
            use pharos_types::BeaconStateView as _;
            let fc = self.fork_choice.read();
            let mut best: Option<(Root, E::BeaconState, Slot)> = None;
            for (root, state) in &fc.block_states {
                let state_slot = state.slot();
                if state_slot > target_slot {
                    continue;
                }
                match best {
                    None => {
                        best = Some((*root, state.clone(), state_slot));
                    }
                    Some((_, _, best_slot)) if state_slot > best_slot => {
                        best = Some((*root, state.clone(), state_slot));
                    }
                    _ => {}
                }
            }
            best
        };

        // ── 2. Epoch-boundary states in the `states` CF ───────────────────────
        let disk_best: Option<(Root, E::BeaconState, Slot)> =
            self.nearest_epoch_boundary_state_on_disk(target_slot);

        // ── 3. Cold restore-points (Phase 3, empty until then) ───────────────
        let cold_best: Option<(Root, E::BeaconState, Slot)> =
            self.nearest_cold_restore_point(target_slot);

        // Pick the best (highest slot) among the three sources.
        let mut result: Option<(Root, E::BeaconState, Slot)> = None;
        for candidate in [in_memory_best, disk_best, cold_best].into_iter().flatten() {
            match result {
                None => result = Some(candidate),
                Some((_, _, best_slot)) if candidate.2 > best_slot => {
                    result = Some(candidate);
                }
                _ => {}
            }
        }
        result
    }

    /// Scan epoch-boundary slots downward from `target_slot`, looking for
    /// the nearest stored epoch-boundary state.
    ///
    /// Uses `RocksStore::block_root_at_slot` (slot → block_root via the
    /// `slot_to_block_root` CF) then `get_state_summary` + `get_state` —
    /// no per-fork block decoding required.
    fn nearest_epoch_boundary_state_on_disk(
        &self,
        target_slot: Slot,
    ) -> Option<(Root, E::BeaconState, Slot)> {
        let spe = E::SLOTS_PER_EPOCH;
        // Highest epoch boundary <= target_slot.
        let boundary_start = (target_slot.0 / spe) * spe;
        let mut boundary = boundary_start;

        loop {
            let boundary_slot = Slot(boundary);

            // Look up the canonical block root at this slot from the slot-index.
            // `block_root_at_slot` reads directly from `slot_to_block_root` CF,
            // no block decoding required.
            let block_root = match self.store.block_root_at_slot(boundary_slot) {
                Ok(Some(r)) => r,
                _ => {
                    if boundary == 0 {
                        break;
                    }
                    boundary = boundary.saturating_sub(spe);
                    continue;
                }
            };

            // Look up the state_root from the state-summary CF.
            let state_root =
                match <RocksStore as DbStore<E>>::get_state_summary(&self.store, &block_root) {
                    Ok(Some(summary)) => summary.state_root,
                    _ => {
                        if boundary == 0 {
                            break;
                        }
                        boundary = boundary.saturating_sub(spe);
                        continue;
                    }
                };

            // Try to load the state from the `states` CF.
            if let Ok(Some(state)) = <RocksStore as DbStore<E>>::get_state(&self.store, &state_root)
            {
                return Some((block_root, state, boundary_slot));
            }

            if boundary == 0 {
                break;
            }
            boundary = boundary.saturating_sub(spe);
        }
        None
    }

    /// Query the cold `restore-points` CF for the nearest restore point ≤ `target_slot`.
    ///
    /// Returns `None` when no restore points have been written yet (pre-Phase-3
    /// or a node that has not yet finalized past the split slot).
    fn nearest_cold_restore_point(
        &self,
        target_slot: Slot,
    ) -> Option<(Root, E::BeaconState, Slot)> {
        let (restore_slot, _state_root) =
            <RocksStore as DbStore<E>>::nearest_restore_point(&self.store, target_slot)
                .ok()
                .flatten()?;
        let state = <RocksStore as DbStore<E>>::get_cold_state(&self.store, restore_slot)
            .ok()
            .flatten()?;
        // Map restore slot → block root via the hot slot-index (written during
        // import and not deleted by migration — only the `blocks` CF entry moves
        // to cold). A missing slot-index entry means we have no block at that
        // slot; return None rather than fabricating a root.
        let block_root = self.store.block_root_at_slot(restore_slot).ok().flatten()?;
        Some((block_root, state, restore_slot))
    }

    // ── replay_to ─────────────────────────────────────────────────────────────

    /// Replay persisted blocks from `start_slot+1` to `target_slot`.
    ///
    /// For each slot in `[start_slot+1, target_slot]`:
    /// - If a persisted block exists at that slot, apply `state_transition`.
    /// - Otherwise, batch-advance through empty slots via `process_slots_fork`.
    ///
    /// `validate_result = false` — we trust our own stored blocks; BLS
    /// re-verification is not needed for historical replay reads.
    ///
    /// The method is sync; async callers must wrap in `spawn_blocking`.
    pub fn replay_to(
        &self,
        mut state: E::BeaconState,
        start_slot: Slot,
        target_slot: Slot,
    ) -> Result<E::BeaconState, RegenError>
    where
        E::BeaconState:
            pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash + Clone,
        E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
        E::SignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
            + Clone,
        E::Phase0BeaconBlock:
            pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
        E::Phase0SignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
        E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
            + pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
                AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
                Deposit = pharos_types::phase0::Deposit<33>,
            >,
        E::AltairBeaconState: pharos_stf::AltairDispatch<E>
            + pharos_stf::AltairJaFDispatch<E>
            + pharos_stf::AltairProcessSlotsDispatch<E>
            + pharos_stf::AltairUpgradeDispatch<E>,
        E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
        E::AltairSignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
        E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, NullExecutionEngine>
            + pharos_stf::BellatrixJaFDispatch<E>
            + pharos_stf::BellatrixProcessSlotsDispatch<E>
            + pharos_stf::BellatrixUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, NullExecutionEngine>
            + pharos_stf::CapellaJaFDispatch<E>
            + pharos_stf::CapellaProcessSlotsDispatch<E>
            + pharos_stf::CapellaUpgradeDispatch<E>,
        E::DenebBeaconState: pharos_stf::DenebDispatch<E, NullExecutionEngine>
            + pharos_stf::DenebProcessSlotsDispatch<E>
            + pharos_ssz::TreeHash,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    {
        if start_slot >= target_slot {
            return Ok(state);
        }

        let null_engine = NullExecutionEngine;
        let mut current_slot = Slot(start_slot.0 + 1);

        while current_slot <= target_slot {
            // Check if there is a canonical block at `current_slot`.
            let block_root_opt = self
                .store
                .block_root_at_slot(current_slot)
                .map_err(RegenError::Storage)?;

            if let Some(block_root) = block_root_opt {
                // A block exists at this slot: load it from the hot CF, falling
                // through to the cold CF when the block has been migrated by the
                // Phase-3 freezer (Task 3.6).
                let hot = <RocksStore as DbStore<E>>::get_block(&self.store, &block_root)
                    .map_err(RegenError::Storage)?;
                let signed_block = if let Some(b) = hot {
                    b
                } else {
                    <RocksStore as DbStore<E>>::get_cold_block(&self.store, &block_root)
                        .map_err(RegenError::Storage)?
                        .ok_or(RegenError::MissingBlock { root: block_root })?
                };

                // `validate_result = false` — skip BLS + state-root check for replay.
                let (new_state, _) = state_transition::<E, NullExecutionEngine>(
                    state,
                    &signed_block,
                    &null_engine,
                    false,
                    &self.runtime_cfg,
                )
                .map_err(RegenError::Stf)?;
                state = new_state;
                current_slot = Slot(current_slot.0 + 1);
            } else {
                // No block at this slot: batch-advance empty slots via process_slots_fork.
                // Find the next block to know how far to advance.
                let advance_to = self
                    .find_next_block_slot(current_slot, target_slot)?
                    .map(|s| Slot(s.0 - 1)) // stop one slot before the next block
                    .unwrap_or(target_slot); // no more blocks: advance all the way

                let advance_to = advance_to.max(current_slot);

                process_slots_fork::<E>(
                    &mut state,
                    advance_to,
                    self.fork_epochs,
                    &self.runtime_cfg,
                )
                .map_err(RegenError::Stf)?;
                current_slot = Slot(advance_to.0 + 1);
            }
        }

        Ok(state)
    }

    /// Find the next slot in `[from_slot, max_slot]` that has a canonical block.
    ///
    /// Uses the `slot_to_block_root` CF scan to find the next occupied slot
    /// without decoding any blocks.
    fn find_next_block_slot(
        &self,
        from_slot: Slot,
        max_slot: Slot,
    ) -> Result<Option<Slot>, RegenError> {
        // Scan the slot_to_block_root CF forward from `from_slot` until we find a
        // slot ≤ max_slot that has a block_root entry. Point lookups only — no
        // block decoding.
        let mut scan_slot = from_slot;
        while scan_slot <= max_slot {
            match self
                .store
                .block_root_at_slot(scan_slot)
                .map_err(RegenError::Storage)?
            {
                Some(_) => return Ok(Some(scan_slot)),
                None => {
                    if scan_slot.0 == max_slot.0 {
                        break;
                    }
                    scan_slot = Slot(scan_slot.0 + 1);
                }
            }
        }
        Ok(None)
    }

    // ── state_at_slot ─────────────────────────────────────────────────────────

    /// Return the post-state at `slot`: nearest stored boundary + replay.
    pub fn state_at_slot(&self, slot: Slot) -> Result<E::BeaconState, RegenError>
    where
        E::BeaconState:
            pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash + Clone,
        E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
        E::SignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
            + Clone,
        E::Phase0BeaconBlock:
            pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
        E::Phase0SignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
        E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
            + pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
                AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
                Deposit = pharos_types::phase0::Deposit<33>,
            >,
        E::AltairBeaconState: pharos_stf::AltairDispatch<E>
            + pharos_stf::AltairJaFDispatch<E>
            + pharos_stf::AltairProcessSlotsDispatch<E>
            + pharos_stf::AltairUpgradeDispatch<E>,
        E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
        E::AltairSignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
        E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, NullExecutionEngine>
            + pharos_stf::BellatrixJaFDispatch<E>
            + pharos_stf::BellatrixProcessSlotsDispatch<E>
            + pharos_stf::BellatrixUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, NullExecutionEngine>
            + pharos_stf::CapellaJaFDispatch<E>
            + pharos_stf::CapellaProcessSlotsDispatch<E>
            + pharos_stf::CapellaUpgradeDispatch<E>,
        E::DenebBeaconState: pharos_stf::DenebDispatch<E, NullExecutionEngine>
            + pharos_stf::DenebProcessSlotsDispatch<E>
            + pharos_ssz::TreeHash,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    {
        let (_, start_state, start_slot) = self
            .nearest_stored_state(slot)
            .ok_or(RegenError::MissingAnchorState)?;

        if start_slot == slot {
            // The nearest stored state IS the target; no replay needed.
            return Ok(start_state);
        }

        self.replay_to(start_state, start_slot, slot)
    }

    // ── state_at_root ─────────────────────────────────────────────────────────

    /// Return the post-state for a state root: search stores, then replay if
    /// the state is not directly stored.
    ///
    /// Walks the `state-summary` CF to find the block whose post-state has the
    /// given `state_root`, then regenerates that block's post-state via
    /// `state_at_slot`.
    pub fn state_at_root(&self, state_root: Root) -> Result<E::BeaconState, RegenError>
    where
        E::BeaconState:
            pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash + Clone,
        E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
        E::SignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
            + Clone,
        E::Phase0BeaconBlock:
            pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
        E::Phase0SignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
        E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
            + pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
                AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
                Deposit = pharos_types::phase0::Deposit<33>,
            >,
        E::AltairBeaconState: pharos_stf::AltairDispatch<E>
            + pharos_stf::AltairJaFDispatch<E>
            + pharos_stf::AltairProcessSlotsDispatch<E>
            + pharos_stf::AltairUpgradeDispatch<E>,
        E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
        E::AltairSignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
        E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, NullExecutionEngine>
            + pharos_stf::BellatrixJaFDispatch<E>
            + pharos_stf::BellatrixProcessSlotsDispatch<E>
            + pharos_stf::BellatrixUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, NullExecutionEngine>
            + pharos_stf::CapellaJaFDispatch<E>
            + pharos_stf::CapellaProcessSlotsDispatch<E>
            + pharos_stf::CapellaUpgradeDispatch<E>,
        E::DenebBeaconState: pharos_stf::DenebDispatch<E, NullExecutionEngine>
            + pharos_stf::DenebProcessSlotsDispatch<E>
            + pharos_ssz::TreeHash,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
            + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    {
        // 1. Check in-memory block_states for a direct hit. Clone the candidates
        //    out and release the read lock BEFORE merkleizing — `tree_hash_root()`
        //    on a full state is O(validators) and must not block fork-choice
        //    writers (the import path). Same pattern as `state_by_state_root`.
        let candidates: Vec<E::BeaconState> = {
            let fc = self.fork_choice.read();
            fc.block_states.values().cloned().collect()
        };
        for state in candidates {
            if state.tree_hash_root() == state_root {
                return Ok(state);
            }
        }

        // 2. Check the hot `states` CF directly (epoch-boundary states stored by root).
        if let Ok(Some(state)) = <RocksStore as DbStore<E>>::get_state(&self.store, &state_root) {
            return Ok(state);
        }

        // 3. Walk the `state-summary` CF to find a block whose stored `state_root`
        //    field matches the target, then regenerate via `state_at_slot`.
        let target_block_root = self.find_block_root_by_state_root(&state_root)?;

        if let Some(block_root) = target_block_root {
            let summary = <RocksStore as DbStore<E>>::get_state_summary(&self.store, &block_root)
                .map_err(RegenError::Storage)?
                .ok_or_else(|| {
                    RegenError::NotFound(format!("no state-summary for block root {block_root:?}"))
                })?;

            let state = self.state_at_slot(summary.slot)?;

            // Verify the regenerated state has the requested root.
            if state.tree_hash_root() == state_root {
                return Ok(state);
            }

            return Err(RegenError::NotFound(format!(
                "regenerated state root mismatch for state_root {state_root:?}"
            )));
        }

        Err(RegenError::NotFound(format!(
            "state root {state_root:?} not found in any store"
        )))
    }

    /// Walk the slot-index and state-summary CF to find the block_root whose
    /// `state_summary.state_root` matches `target_state_root`.
    ///
    /// Scans slots in ascending order in batches. Uses `block_root_at_slot` to
    /// get block roots (no block decoding required).
    fn find_block_root_by_state_root(
        &self,
        target_state_root: &Root,
    ) -> Result<Option<Root>, RegenError> {
        const BATCH_SIZE: u64 = 256;
        // Lower-bound the scan at the anchor slot: on a checkpoint-synced node the
        // canonical chain starts at the anchor, so scanning from slot 0 would walk
        // millions of empty pre-anchor slots. Default to 0 when the anchor key is
        // absent (genesis-from-scratch).
        let anchor_slot = <RocksStore as DbStore<E>>::get_metadata(&self.store, b"anchor_slot")
            .ok()
            .flatten()
            .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);
        let mut slot = Slot(anchor_slot);

        loop {
            // Scan a batch of slots for their state-summary entries.
            let mut found_any = false;
            let mut last_slot = slot;

            for s in slot.0..slot.0.saturating_add(BATCH_SIZE) {
                let scan_slot = Slot(s);
                let block_root = match self
                    .store
                    .block_root_at_slot(scan_slot)
                    .map_err(RegenError::Storage)?
                {
                    Some(r) => {
                        found_any = true;
                        last_slot = scan_slot;
                        r
                    }
                    None => continue,
                };

                if let Ok(Some(summary)) =
                    <RocksStore as DbStore<E>>::get_state_summary(&self.store, &block_root)
                {
                    if &summary.state_root == target_state_root {
                        return Ok(Some(block_root));
                    }
                }
            }

            if !found_any {
                break;
            }
            slot = Slot(last_slot.0 + 1);
        }
        Ok(None)
    }
}
