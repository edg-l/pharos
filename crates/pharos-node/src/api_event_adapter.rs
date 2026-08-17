//! API event adapter: translates `HeadChange` watch updates into `ApiEvent`s
//! on the SSE broadcast bus.
//!
//! `run_api_event_adapter` subscribes to the ingestion `head_tx` watch channel
//! (clone of the same sender used by the engine driver). On each head change it:
//!
//! 1. Emits a `block` event (block root + slot).
//! 2. Emits a `head` event (slot, block root, state root, duty-dependent roots,
//!    epoch_transition flag, execution_optimistic).
//! 3. Reads `fork_choice.finalized_checkpoint` and, when it has advanced since
//!    the last emit, emits a `finalized_checkpoint` event.
//! 4. When the new head is NOT a descendant of the previous head (reorg),
//!    emits a `chain_reorg` event.
//!
//! The adapter runs as an independent `tokio::spawn`-ed task so it never
//! blocks the block-ingestion loop or the engine driver.

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_api::events::{
    ApiEvent, BlockEventDto, ChainReorgEventDto, EventBus, FinalizedCheckpointEventDto,
    HeadEventDto,
};
use pharos_fork_choice::Store as FcStore;
use pharos_types::{
    BeaconSpec, BeaconStateView as _, PayloadStatus,
    phase0::{Root, Slot},
    views::BeaconBlockView as _,
};
use tokio::sync::watch;
use tracing::debug;

use crate::engine_driver::HeadChange;

// ── PreviousHead ──────────────────────────────────────────────────────────────

/// Tracks the previous head state for reorg detection.
#[derive(Clone)]
struct PreviousHead {
    root: [u8; 32],
    slot: u64,
    state_root: [u8; 32],
}

// ── run_api_event_adapter ─────────────────────────────────────────────────────

/// Async task that drives the SSE broadcast bus from `HeadChange` notifications.
///
/// `head_rx`: clone of the watch channel that ingestion publishes `HeadChange`
/// values onto.  The initial `None` value is skipped.
///
/// `fork_choice`: shared fork-choice store, read under a short read-lock per
/// head change to obtain finalized checkpoint and block/state roots.
///
/// `bus`: the SSE broadcast bus to push events onto.
///
/// The task exits when `head_rx` is closed (i.e. the ingestion loop shut down).
pub async fn run_api_event_adapter<E>(
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    fork_choice: Arc<RwLock<FcStore<E>>>,
    bus: Arc<EventBus>,
) where
    E: BeaconSpec,
    E::BeaconBlock: pharos_types::views::BeaconBlockView,
    E::BeaconState: pharos_types::BeaconStateView,
{
    let tx = bus.sender();
    let mut prev_finalized_epoch: Option<u64> = None;
    let mut prev_head: Option<PreviousHead> = None;

    loop {
        // Wait for the next head change notification.
        if head_rx.changed().await.is_err() {
            debug!("api_event_adapter: head_rx closed; exiting");
            break;
        }

        let change = match head_rx.borrow().clone() {
            Some(c) => c,
            None => continue, // Initial None value; skip.
        };

        let head_root_typed: Root = change.head_root;
        let head_root_bytes: [u8; 32] = head_root_typed.into();
        let head_slot_u64: u64 = change.head_slot.into();

        // Read the fork-choice store once under a brief read-lock.
        // Also performs reorg detection (if there was a previous head) in the
        // same lock acquisition so we never hold the lock across an await.
        let (
            head_state_root,
            head_epoch,
            finalized_epoch,
            finalized_root,
            finalized_state_root,
            is_optimistic,
            fin_optimistic,
            previous_duty_dep_root,
            current_duty_dep_root,
            reorg_depth,
        ) = {
            let fc = fork_choice.read();

            // State root from the stored block.
            let head_state_root_bytes: [u8; 32] = fc
                .blocks
                .get(&head_root_typed)
                .map(|b| b.state_root().into())
                .unwrap_or([0u8; 32]);

            // Epoch for duty-dependent root computation.
            let epoch_val: u64 = head_slot_u64 / E::SLOTS_PER_EPOCH;

            // Finalized checkpoint.
            let fin_ep: u64 = fc.finalized_checkpoint.epoch.into();
            let fin_root: [u8; 32] = fc.finalized_checkpoint.root.into();
            let fin_state_root: [u8; 32] = fc
                .blocks
                .get(&fc.finalized_checkpoint.root)
                .map(|b| b.state_root().into())
                .unwrap_or([0u8; 32]);

            // Execution-optimistic flag for head events.
            let optimistic = matches!(
                fc.payload_statuses.get(&head_root_typed),
                Some(PayloadStatus::NotValidated)
            );

            // Execution-optimistic flag for the finalized_checkpoint event:
            // must reflect the finalized block's payload status, not the head's.
            let fin_opt = matches!(
                fc.payload_statuses.get(&fc.finalized_checkpoint.root),
                Some(PayloadStatus::NotValidated)
            );

            let (prev_dep, curr_dep) =
                compute_duty_dependent_roots::<E>(&fc, head_root_typed, epoch_val);

            // Reorg detection and depth calculation (done here to avoid a
            // second lock acquisition later).
            let reorg = if let Some(ref old) = prev_head {
                let old_root = Root::from(old.root);
                let lca_root = pharos_fork_choice::get_head::get_ancestor::<E>(
                    &fc,
                    head_root_typed,
                    Slot(old.slot),
                );
                if lca_root != old_root {
                    // Walk the old chain from old head back to lca_root,
                    // counting hops (blocks reverted from the old chain).
                    let mut depth: u64 = 0;
                    let mut cursor = old_root;
                    loop {
                        if cursor == lca_root {
                            break;
                        }
                        match fc.blocks.get(&cursor) {
                            Some(b) => {
                                depth += 1;
                                cursor = b.parent_root();
                            }
                            // Block missing/pruned: stop counting.
                            None => break,
                        }
                    }
                    Some(depth.max(1))
                } else {
                    None // No reorg.
                }
            } else {
                None
            };

            (
                head_state_root_bytes,
                epoch_val,
                fin_ep,
                fin_root,
                fin_state_root,
                optimistic,
                fin_opt,
                prev_dep,
                curr_dep,
                reorg,
            )
        };

        // Determine epoch_transition: did this block's slot start a new epoch?
        let epoch_transition = head_slot_u64.is_multiple_of(E::SLOTS_PER_EPOCH);

        // ── block event ──────────────────────────────────────────────────────
        let block_event = ApiEvent::Block(BlockEventDto {
            slot: head_slot_u64,
            block: head_root_bytes,
            execution_optimistic: is_optimistic,
        });
        if tx.send(block_event).is_err() {
            debug!("api_event_adapter: no SSE subscribers for block event");
        }

        // ── head event ───────────────────────────────────────────────────────
        let head_event = ApiEvent::Head(HeadEventDto {
            slot: head_slot_u64,
            block: head_root_bytes,
            state: head_state_root,
            epoch_transition,
            previous_duty_dependent_root: previous_duty_dep_root,
            current_duty_dependent_root: current_duty_dep_root,
            execution_optimistic: is_optimistic,
        });
        if tx.send(head_event).is_err() {
            debug!("api_event_adapter: no SSE subscribers for head event");
        }

        // ── finalized_checkpoint event (only on advance) ──────────────────
        let emit_finalized = prev_finalized_epoch.is_none_or(|ep| finalized_epoch > ep);
        if emit_finalized {
            let fc_event = ApiEvent::FinalizedCheckpoint(FinalizedCheckpointEventDto {
                block: finalized_root,
                state: finalized_state_root,
                epoch: finalized_epoch,
                // Use the finalized block's payload status, not the head's.
                execution_optimistic: fin_optimistic,
            });
            if tx.send(fc_event).is_err() {
                debug!("api_event_adapter: no SSE subscribers for finalized_checkpoint event");
            }
            prev_finalized_epoch = Some(finalized_epoch);
        }

        // ── chain_reorg event ─────────────────────────────────────────────
        if let Some(depth) = reorg_depth
            && let Some(ref old) = prev_head
        {
            let reorg_event = ApiEvent::ChainReorg(ChainReorgEventDto {
                slot: head_slot_u64,
                depth,
                old_head_block: old.root,
                new_head_block: head_root_bytes,
                old_head_state: old.state_root,
                new_head_state: head_state_root,
                epoch: head_epoch,
                execution_optimistic: is_optimistic,
            });
            if tx.send(reorg_event).is_err() {
                debug!("api_event_adapter: no SSE subscribers for chain_reorg event");
            }
        }

        // Update tracked state for the next iteration.
        prev_head = Some(PreviousHead {
            root: head_root_bytes,
            slot: head_slot_u64,
            state_root: head_state_root,
        });
    }
}

// ── Duty-dependent root computation ──────────────────────────────────────────

/// Compute `(previous_duty_dependent_root, current_duty_dependent_root)` for the
/// given head block root and its epoch.
///
/// Per the spec:
/// - `previous = get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch-1) - 1)`
/// - `current  = get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`
///
/// Both use the genesis root (all-zeros) on slot underflow (epoch 0).
///
/// `get_block_root_at_slot(state, slot) = state.block_roots[slot % SLOTS_PER_HISTORICAL_ROOT]`.
fn compute_duty_dependent_roots<E: BeaconSpec>(
    fc: &FcStore<E>,
    head_root: Root,
    head_epoch: u64,
) -> ([u8; 32], [u8; 32])
where
    E::BeaconState: pharos_types::BeaconStateView,
{
    let state = match fc.block_states.get(&head_root) {
        Some(s) => s,
        None => return ([0u8; 32], [0u8; 32]),
    };

    let spe = E::SLOTS_PER_EPOCH;
    let sphr = E::SLOTS_PER_HISTORICAL_ROOT;

    // current_duty_dependent_root: slot = compute_start_slot_at_epoch(epoch) - 1.
    let current_dep_root = if head_epoch == 0 {
        [0u8; 32] // epoch 0: underflow → genesis root placeholder
    } else {
        let target_slot = head_epoch * spe - 1;
        let idx = (target_slot % sphr) as usize;
        state
            .block_root_at(idx)
            .map(|r| r.into())
            .unwrap_or([0u8; 32])
    };

    // previous_duty_dependent_root: slot = compute_start_slot_at_epoch(epoch-1) - 1.
    let prev_dep_root = if head_epoch <= 1 {
        [0u8; 32] // epoch 0 or 1: underflow → genesis root placeholder
    } else {
        let target_slot = (head_epoch - 1) * spe - 1;
        let idx = (target_slot % sphr) as usize;
        state
            .block_root_at(idx)
            .map(|r| r.into())
            .unwrap_or([0u8; 32])
    };

    (prev_dep_root, current_dep_root)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use pharos_fork_choice::Store as FcStore;
    use pharos_ssz::TreeHash;
    use pharos_types::{
        MinimalBeaconSpec,
        phase0::{Checkpoint, Root, Slot},
        state::{MinimalBeaconBlock, MinimalBeaconState},
    };
    use pharos_utils::{Hash256, Uint256};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn empty_store() -> FcStore<MinimalBeaconSpec> {
        let cp = Checkpoint::default();
        FcStore {
            time: 0,
            genesis_time: 0,
            justified_checkpoint: cp.clone(),
            finalized_checkpoint: cp.clone(),
            unrealized_justified_checkpoint: cp.clone(),
            unrealized_finalized_checkpoint: cp,
            proposer_boost_root: Root::default(),
            equivocating_indices: HashSet::new(),
            blocks: HashMap::new(),
            block_states: HashMap::new(),
            block_timeliness: HashMap::new(),
            checkpoint_states: HashMap::new(),
            latest_messages: HashMap::new(),
            unrealized_justifications: HashMap::new(),
            payload_statuses: HashMap::new(),
            terminal_total_difficulty: Uint256::ZERO,
            terminal_block_hash: Hash256::default(),
            terminal_block_hash_activation_epoch: u64::MAX,
            altair_fork_epoch: u64::MAX,
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_epoch: u64::MAX,
            runtime_cfg: pharos_types::config::RuntimeConfig::default(),
        }
    }

    /// Insert a bare phase0 block at `slot` with `parent_root` into `store`.
    /// Returns its tree-hash root.
    fn insert_block(store: &mut FcStore<MinimalBeaconSpec>, slot: u64, parent_root: Root) -> Root {
        use pharos_types::phase0::MinimalBeaconBlock as Phase0Block;
        let block = Phase0Block {
            slot: Slot(slot),
            parent_root,
            ..Default::default()
        };
        let root: Root = block.tree_hash_root();
        store.blocks.insert(root, MinimalBeaconBlock::Phase0(block));
        store
            .block_states
            .insert(root, MinimalBeaconState::Phase0(Default::default()));
        root
    }

    /// Run the same depth-walk logic used in `run_api_event_adapter`:
    /// walk from `old_root` back to `lca_root`, counting hops.
    fn depth_walk(store: &FcStore<MinimalBeaconSpec>, old_root: Root, lca_root: Root) -> u64 {
        let mut depth: u64 = 0;
        let mut cursor = old_root;
        loop {
            if cursor == lca_root {
                break;
            }
            match store.blocks.get(&cursor) {
                Some(b) => {
                    use pharos_types::views::BeaconBlockView as _;
                    depth += 1;
                    cursor = b.parent_root();
                }
                None => break,
            }
        }
        depth.max(1)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Reorg depth = 1: old head has no extra blocks between it and the LCA.
    ///
    /// Chain:  genesis ── A (slot 1)   [old head = A]
    ///                └── B (slot 1)   [new head = B, LCA = genesis]
    ///
    /// The old chain from A back to genesis is exactly one hop, so depth == 1.
    #[test]
    fn reorg_depth_single_block() {
        let mut store = empty_store();
        let genesis_root = Root::default();
        let a_root = insert_block(&mut store, 1, genesis_root);
        // LCA is genesis (ancestor of B at slot 1 would be B itself if B is a
        // sibling; just use genesis as the agreed LCA for the walk).
        let depth = depth_walk(&store, a_root, genesis_root);
        assert_eq!(depth, 1, "one block reverted → depth 1");
    }

    /// Reorg depth = 3: old chain has three blocks above the LCA.
    ///
    /// Chain:  genesis ── A1 ── A2 ── A3   [old head = A3]
    ///                └── B1              [new head diverged at genesis]
    ///
    /// Walking A3 → A2 → A1 → genesis = 3 hops → depth 3.
    #[test]
    fn reorg_depth_multi_block() {
        let mut store = empty_store();
        let genesis_root = Root::default();
        let a1 = insert_block(&mut store, 1, genesis_root);
        let a2 = insert_block(&mut store, 2, a1);
        let a3 = insert_block(&mut store, 3, a2);

        let depth = depth_walk(&store, a3, genesis_root);
        assert_eq!(depth, 3, "three blocks reverted → depth 3");
    }

    /// `ChainReorgEventDto` serializes `depth` as a quoted decimal string,
    /// matching the beacon-APIs spec shape.
    #[test]
    fn chain_reorg_dto_depth_serialized_as_quoted_decimal() {
        use pharos_api::events::ChainReorgEventDto;

        let dto = ChainReorgEventDto {
            slot: 200,
            depth: 5,
            old_head_block: [0xaa; 32],
            new_head_block: [0xbb; 32],
            old_head_state: [0xcc; 32],
            new_head_state: [0xdd; 32],
            epoch: 2,
            execution_optimistic: false,
        };
        let json = serde_json::to_string(&dto).expect("serialization must succeed");
        let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");

        // depth must be a quoted string "5", not a bare integer 5.
        assert_eq!(
            val["depth"].as_str(),
            Some("5"),
            "depth must serialize as quoted string \"5\""
        );
        // slot must also be a quoted string per spec.
        assert_eq!(
            val["slot"].as_str(),
            Some("200"),
            "slot must serialize as quoted string"
        );
    }
}
