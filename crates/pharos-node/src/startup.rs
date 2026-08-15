//! Node startup helpers — warm-restart rehydration of the in-memory fork-choice
//! store from persisted RocksDB data.
//!
//! # Warm-restart contract (`D-rocksdb` snapshot-rehydration)
//!
//! The `forkchoice` column family holds only checkpoint cursors and head
//! pointers. On restart, `rehydrate_fork_choice_store` rebuilds the in-memory
//! `pharos_fork_choice::Store<E>` by:
//!
//! 1. Reading the anchor block at `snapshot.finalized_checkpoint.root` from
//!    CF `blocks`.
//! 2. Walking forward in CF `slot_to_block_root` from
//!    `finalized_checkpoint.epoch * SLOTS_PER_EPOCH` up to `snapshot.head_slot`,
//!    loading each block + post-state into `blocks` / `block_states`.
//! 3. Re-deriving `checkpoint_states` for `justified_checkpoint` and
//!    `finalized_checkpoint` by looking up the corresponding states.
//! 4. Leaving `latest_messages`, `equivocating_indices`, `block_timeliness`,
//!    and `unrealized_justifications` at empty/default values; they repopulate
//!    from incoming attestations after restart.
//!
//! After this function returns, the caller MUST call
//! `pharos_fork_choice::on_tick(&mut store, SystemTime::now()...)` to advance
//! the time cursor from `snapshot.last_known_time` to wall-clock.

use std::collections::{HashMap, HashSet};

use pharos_ssz::TreeHash;
use pharos_storage::{ForkChoiceSnapshot, RocksStore, StorageError, Store};
use pharos_types::phase0::primitives::Slot;
use pharos_types::{BeaconBlockView, EthSpec, SignedBeaconBlockView};

/// Rebuild the in-memory `pharos_fork_choice::Store<E>` from persisted data.
///
/// Performs steps 2-5 of the `D-rocksdb` snapshot-rehydration walk.
/// The caller is responsible for the subsequent `on_tick` call (step 5+).
///
/// Returns `Err(StorageError::KeyNotFound)` if the anchor block at
/// `snapshot.finalized_checkpoint.root` is not found in the `blocks` CF.
pub fn rehydrate_fork_choice_store<E: EthSpec>(
    store: &RocksStore,
    snapshot: &ForkChoiceSnapshot,
) -> Result<pharos_fork_choice::Store<E>, StorageError>
where
    // Relate the SignedBeaconBlock's inner Message type to E::BeaconBlock so
    // the compiler can accept insertion into `blocks: HashMap<Root, E::BeaconBlock>`.
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    use pharos_fork_choice::Store as FcStore;
    use pharos_types::phase0::Checkpoint;

    // Step 2: load the anchor block (finalized_checkpoint.root).
    let anchor_root = snapshot.finalized_checkpoint.root;
    let anchor_signed = <RocksStore as Store<E>>::get_block(store, &anchor_root)?
        .ok_or(StorageError::KeyNotFound)?;

    let anchor_state_root = anchor_signed.message().state_root();
    let anchor_state = <RocksStore as Store<E>>::get_state(store, &anchor_state_root)?
        .ok_or(StorageError::KeyNotFound)?;

    // Seed the maps with the anchor.
    let mut blocks: HashMap<_, E::BeaconBlock> = HashMap::new();
    blocks.insert(anchor_root, anchor_signed.message().clone());

    let mut block_states: HashMap<_, E::BeaconState> = HashMap::new();
    block_states.insert(anchor_root, anchor_state);

    // Step 3: walk forward from finalized epoch start up to head_slot (inclusive).
    let start_slot = Slot(snapshot.finalized_checkpoint.epoch.0 * E::SLOTS_PER_EPOCH);
    let end_slot = snapshot.head_slot;

    if end_slot > start_slot {
        // count = number of slots to scan; +1 to include head_slot itself.
        let count = end_slot.0.saturating_sub(start_slot.0).saturating_add(1);
        let range_blocks = <RocksStore as Store<E>>::get_blocks_by_range(store, start_slot, count)?;

        for signed in range_blocks {
            let block = signed.message().clone();
            let block_root = block.tree_hash_root();
            let state_root = block.state_root();

            // Skip anchor — already inserted.
            if block_root == anchor_root {
                continue;
            }

            if let Some(state) = <RocksStore as Store<E>>::get_state(store, &state_root)? {
                blocks.insert(block_root, block);
                block_states.insert(block_root, state);
            }
        }
    }

    // Step 4: re-derive checkpoint_states for justified and finalized checkpoints.
    let mut checkpoint_states: HashMap<Checkpoint, E::BeaconState> = HashMap::new();

    if let Some(just_state) = block_states
        .get(&snapshot.justified_checkpoint.root)
        .cloned()
    {
        checkpoint_states.insert(snapshot.justified_checkpoint.clone(), just_state);
    }

    // Finalized may equal justified; insert even if so (idempotent).
    if let Some(fin_state) = block_states
        .get(&snapshot.finalized_checkpoint.root)
        .cloned()
    {
        checkpoint_states.insert(snapshot.finalized_checkpoint.clone(), fin_state);
    }

    // Step 5: build the Store with empty volatile collections.
    Ok(FcStore {
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
    })
}
