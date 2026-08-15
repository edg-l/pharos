//! `BlockTransition<E>` — batched write unit for atomic fork-choice transitions.
//!
//! Per `D-store-trait`: `write_block_transition` accepts a `BlockTransition<E>`
//! that collects all writes for one transition. The `RocksStore` implementation
//! (Phase 1) translates this into a single `rocksdb::WriteBatch` call so that
//! block, state, fork-choice snapshot, and slot-index updates are either all
//! committed or all absent.

use pharos_types::EthSpec;
use pharos_types::phase0::primitives::{Root, Slot};

use crate::forkchoice::ForkChoiceSnapshot;

/// Collects all RocksDB writes that must be committed atomically for a single
/// block-processing transition.
///
/// Build one per `on_block` call; pass to `Store::write_block_transition`.
/// The `RocksStore` impl translates each non-`None` field into a `WriteBatch`
/// entry before issuing a single `db.write(batch)`.
pub struct BlockTransition<E: EthSpec> {
    /// Optional block to store: `(block_root, SignedBeaconBlock)`.
    pub block: Option<(Root, E::SignedBeaconBlock)>,

    /// Optional post-state to store: `(state_root, BeaconState)`.
    pub state: Option<(Root, E::BeaconState)>,

    /// Optional updated fork-choice snapshot to persist.
    pub forkchoice: Option<ForkChoiceSnapshot>,

    /// Optional slot-index entry to write: `(slot, block_root)`.
    ///
    /// Written to both `slot_to_block_root` and `block_root_to_slot` CFs.
    pub slot_index: Option<(Slot, Root)>,
}

impl<E: EthSpec> BlockTransition<E> {
    /// Returns an all-`None` transition.
    ///
    /// Populate fields as needed before passing to `Store::write_block_transition`.
    pub fn new() -> Self {
        Self {
            block: None,
            state: None,
            forkchoice: None,
            slot_index: None,
        }
    }
}

impl<E: EthSpec> Default for BlockTransition<E> {
    fn default() -> Self {
        Self::new()
    }
}
