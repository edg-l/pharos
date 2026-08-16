//! `BlockTransition<E>` — batched write unit for atomic fork-choice transitions.
//!
//! Per `D-store-trait`: `write_block_transition` accepts a `BlockTransition<E>`
//! that collects all writes for one transition. The `RocksStore` implementation
//! (Phase 1) translates this into a single `rocksdb::WriteBatch` call so that
//! block, state, fork-choice snapshot, slot-index, state-summary, metadata,
//! and payload-status updates are either all committed or all absent.

use pharos_types::BeaconSpec;
use pharos_types::PayloadStatus;
use pharos_types::deneb::BlobSidecar;
use pharos_types::phase0::primitives::{Root, Slot};

use crate::forkchoice::ForkChoiceSnapshot;
use crate::state_summary::StateSummary;

/// Collects all RocksDB writes that must be committed atomically for a single
/// block-processing transition.
///
/// Build one per `on_block` call; pass to `Store::write_block_transition`.
/// The `RocksStore` impl translates each non-`None` field into a `WriteBatch`
/// entry before issuing a single `db.write(batch)`.
pub struct BlockTransition<E: BeaconSpec> {
    /// Optional block to store: `(block_root, SignedBeaconBlock)`.
    pub block: Option<(Root, E::SignedBeaconBlock)>,

    /// Optional post-state to store: `(state_root, BeaconState)`.
    ///
    /// Written only at epoch boundaries (`slot % SLOTS_PER_EPOCH == 0`)
    /// on the live import path. Always written for anchor blocks.
    pub state: Option<(Root, E::BeaconState)>,

    /// Optional updated fork-choice snapshot to persist.
    pub forkchoice: Option<ForkChoiceSnapshot>,

    /// Optional slot-index entry to write: `(slot, block_root)`.
    ///
    /// Written to both `slot_to_block_root` and `block_root_to_slot` CFs.
    pub slot_index: Option<(Slot, Root)>,

    /// Optional payload-status entry to persist: `(block_root, PayloadStatus)`.
    ///
    /// Written to the `payload-status` CF as `Root → u8` discriminant.
    /// `0 = Valid, 1 = Invalid, 2 = NotValidated`.
    /// Read at startup by `rehydrate_fork_choice_store` to seed the in-memory
    /// `pharos_fork_choice::Store::payload_statuses` map.
    pub payload_status: Option<(Root, PayloadStatus)>,

    /// Optional state-summary entry to persist: `(block_root, StateSummary)`.
    ///
    /// Written to the `state-summary` CF on every block import.
    /// Used by Phase-2 `StateRegenService` to walk the persisted block chain
    /// for replay-on-read (parent walk + nearest stored state lookup).
    pub state_summary: Option<(Root, StateSummary)>,

    /// Arbitrary metadata key/value pairs to write to the `metadata` CF.
    ///
    /// Each `(&'static [u8], Vec<u8>)` is written as a separate row in the
    /// `metadata` CF inside the same `WriteBatch`, preserving atomicity.
    ///
    /// Required by:
    /// - Task 1.1: `b"head_state_root"` (32 B) on every head advance.
    /// - Task 3.3 (Phase 3): `b"split_slot"` advancement.
    /// - Task 4.3 (Phase 4): `b"split_slot"` / `b"anchor_slot"` init in
    ///   `apply_anchor`.
    ///
    /// Never bypassed with a separate `put_metadata` call on the live import
    /// path; all metadata writes ride the atomic batch.
    pub metadata: Vec<(&'static [u8], Vec<u8>)>,

    /// Blob sidecars to write atomically with the block.
    ///
    /// Per `D-blob-store-cf-keyed-by-root-index` (M10-DA Phase 4, Task 4.3):
    /// each `(block_root, index, BlobSidecar)` triple is written to the
    /// `blob-sidecars` CF in the same `WriteBatch` as the block so that
    /// block + blobs are either both present or both absent after a crash.
    ///
    /// Empty for all pre-Deneb blocks and Deneb blocks with no blob commitments.
    /// Populated by the Deneb import path when blob sidecars arrive.
    pub blob_sidecars: Vec<(Root, u64, BlobSidecar)>,
}

impl<E: BeaconSpec> BlockTransition<E> {
    /// Returns an all-`None` / empty transition.
    ///
    /// Populate fields as needed before passing to `Store::write_block_transition`.
    pub fn new() -> Self {
        Self {
            block: None,
            state: None,
            forkchoice: None,
            slot_index: None,
            payload_status: None,
            state_summary: None,
            metadata: Vec::new(),
            blob_sidecars: Vec::new(),
        }
    }
}

impl<E: BeaconSpec> Default for BlockTransition<E> {
    fn default() -> Self {
        Self::new()
    }
}
