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
use pharos_types::PayloadStatus;
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::{BeaconBlockView, EthSpec, SignedBeaconBlockView};
use pharos_utils::{Hash256, Uint256};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the inner `E::BeaconBlock` from a fork-enum `E::SignedBeaconBlock`
/// without calling the panicking `message()` on the fork-enum variant.
///
/// Returns `None` only if the signed block variant is unrecognised (should
/// never happen in a well-typed system).
fn extract_block<E: EthSpec>(signed: &E::SignedBeaconBlock) -> Option<E::BeaconBlock>
where
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
{
    if let Some(inner) = E::unwrap_phase0_signed_block(signed) {
        Some(E::phase0_into_block(inner.message().clone()))
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed) {
        Some(E::altair_into_block(inner.message().clone()))
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed) {
        Some(E::bellatrix_into_block(inner.message().clone()))
    } else {
        E::unwrap_capella_signed_block(signed)
            .map(|inner| E::capella_into_block(inner.message().clone()))
    }
}

// ── rehydrate_fork_choice_store ───────────────────────────────────────────────

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
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
{
    use pharos_fork_choice::Store as FcStore;
    use pharos_types::phase0::Checkpoint;

    // Step 2: load the anchor block (finalized_checkpoint.root).
    let anchor_root = snapshot.finalized_checkpoint.root;
    let anchor_signed = <RocksStore as Store<E>>::get_block(store, &anchor_root)?
        .ok_or(StorageError::KeyNotFound)?;

    let anchor_block = extract_block::<E>(&anchor_signed).ok_or(StorageError::KeyNotFound)?;
    let anchor_state_root = anchor_block.state_root();
    let anchor_state = <RocksStore as Store<E>>::get_state(store, &anchor_state_root)?
        .ok_or(StorageError::KeyNotFound)?;

    // Seed the maps with the anchor.
    let mut blocks: HashMap<_, E::BeaconBlock> = HashMap::new();
    blocks.insert(anchor_root, anchor_block);

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
            let block = match extract_block::<E>(&signed) {
                Some(b) => b,
                None => continue,
            };
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

    // Step 5: rehydrate payload_statuses from the `payload-status` CF.
    //
    // On warm restart, the persisted discriminant bytes are decoded back to
    // `PayloadStatus` variants and inserted into the in-memory map so that
    // `filter_block_tree` continues to skip `Invalid` payloads after restart.
    let payload_statuses: HashMap<Root, PayloadStatus> = {
        let raw = <RocksStore as Store<E>>::payload_statuses_iter(store)?;
        raw.into_iter().collect()
    };

    // Step 6: build the Store with the rehydrated payload_statuses and empty volatile collections.
    // Terminal-block constants are zeroed here; the caller (main.rs) sets them
    // via `Store::set_terminal_config` using the loaded `RuntimeConfig`.
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
        payload_statuses,
        terminal_total_difficulty: Uint256::ZERO,
        terminal_block_hash: Hash256::default(),
        terminal_block_hash_activation_epoch: u64::MAX,
        // Fork epoch schedule and runtime config default to "never upgrade".
        // main.rs sets these via `Store::set_fork_epochs` + direct assignment
        // after loading the `RuntimeConfig`.
        altair_fork_epoch: u64::MAX,
        bellatrix_fork_epoch: u64::MAX,
        capella_fork_epoch: u64::MAX,
        runtime_cfg: pharos_types::config::RuntimeConfig::default(),
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_fork_choice::get_forkchoice_store;
    use pharos_ssz::TreeHash;
    use pharos_storage::{BlockTransition, RocksStoreConfig};
    use pharos_types::MainnetEthSpec;
    use pharos_types::phase0::primitives::Root;
    use pharos_types::state::BeaconBlock as ForkBeaconBlock;

    fn make_store_with_snapshot(dir: &tempfile::TempDir) -> (RocksStore, ForkChoiceSnapshot) {
        let rocks = RocksStore::open::<MainnetEthSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store");

        let genesis_state = <MainnetEthSpec as EthSpec>::BeaconState::default();
        let state_root = genesis_state.tree_hash_root();
        let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
            state_root,
            ..pharos_types::phase0::MainnetBeaconBlock::default()
        });
        let fc =
            get_forkchoice_store::<MainnetEthSpec>(genesis_state.clone(), anchor_block.clone());

        // Compute block_root before building snapshot so we can reference it.
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

        // Persist the anchor block and its state so rehydrate can load them.
        {
            use pharos_types::phase0::MainnetSignedBeaconBlock;
            use pharos_types::state::SignedBeaconBlock;
            <RocksStore as Store<MainnetEthSpec>>::put_block(
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
        <RocksStore as Store<MainnetEthSpec>>::put_state(&rocks, state_root, &genesis_state)
            .expect("put state");

        (rocks, snap)
    }

    #[test]
    fn rehydrate_seeds_payload_statuses() {
        let dir = tempfile::TempDir::new().unwrap();
        let (rocks, snap) = make_store_with_snapshot(&dir);

        // Write three payload statuses.
        let root_a = Root::from([0x01u8; 32]);
        let root_b = Root::from([0x02u8; 32]);
        let root_c = Root::from([0x03u8; 32]);

        for (root, status) in [
            (root_a, PayloadStatus::Valid),
            (root_b, PayloadStatus::Invalid),
            (root_c, PayloadStatus::NotValidated),
        ] {
            let mut bt = BlockTransition::<MainnetEthSpec>::new();
            bt.payload_status = Some((root, status));
            <RocksStore as Store<MainnetEthSpec>>::write_block_transition(&rocks, bt)
                .expect("write");
        }

        // Rehydrate and assert in-memory map matches.
        let fc_store =
            rehydrate_fork_choice_store::<MainnetEthSpec>(&rocks, &snap).expect("rehydrate");

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
        assert_eq!(fc_store.payload_statuses.len(), 3);
    }
}
