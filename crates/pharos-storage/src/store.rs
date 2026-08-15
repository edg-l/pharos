//! `Store<E>` — the synchronous storage trait for the Pharos chain database.
//!
//! Per `D-store-trait`: the trait is **sync** because RocksDB is sync and
//! STF + fork-choice are sync. Async callers wrap with
//! `tokio::task::spawn_blocking` at the call site. The `Send + Sync + 'static`
//! bound allows `Arc<dyn Store<E>>` to be shared across the network task and
//! the (future) STF executor thread pool.

use pharos_types::EthSpec;
use pharos_types::phase0::primitives::{Root, Slot};

use crate::error::StorageError;
use crate::forkchoice::ForkChoiceSnapshot;
use crate::transition::BlockTransition;

/// Synchronous storage trait for the Pharos chain database.
///
/// All methods take `&self` (interior mutability via RocksDB's `Send + Sync`
/// handle). Implementors must be `Send + Sync + 'static` for use behind `Arc`.
///
/// Per `D-store-trait`.
pub trait Store<E: EthSpec>: Send + Sync + 'static {
    /// Stores an SSZ-encoded signed beacon block, keyed by `root`.
    ///
    /// The block and its slot-index entry should be written atomically via
    /// `write_block_transition` rather than individual `put_block` calls.
    fn put_block(&self, root: Root, block: &E::SignedBeaconBlock) -> Result<(), StorageError>;

    /// Retrieves and SSZ-decodes the signed beacon block for `root`, if any.
    fn get_block(&self, root: &Root) -> Result<Option<E::SignedBeaconBlock>, StorageError>;

    /// Returns all blocks whose slot falls in `[start_slot, start_slot + count)`,
    /// ordered by ascending slot.
    ///
    /// Implemented via an iterator over the `slot_to_block_root` CF (big-endian
    /// slot keys) so that blocks are returned in slot order without sorting.
    ///
    /// Spec cite: `specs/phase0/p2p-interface.md:1413-1417`
    /// (`BeaconBlocksByRange` response ordering requirement).
    fn get_blocks_by_range(
        &self,
        start_slot: Slot,
        count: u64,
    ) -> Result<Vec<E::SignedBeaconBlock>, StorageError>;

    /// Stores an SSZ-encoded beacon state, keyed by `state_root`.
    fn put_state(&self, state_root: Root, state: &E::BeaconState) -> Result<(), StorageError>;

    /// Retrieves and SSZ-decodes the beacon state for `state_root`, if any.
    fn get_state(&self, state_root: &Root) -> Result<Option<E::BeaconState>, StorageError>;

    /// Writes the fork-choice cursor snapshot to the `forkchoice` CF.
    ///
    /// Overwrites any existing row atomically (via `write_block_transition`
    /// in normal operation; direct call is for testing).
    fn put_forkchoice_snapshot(&self, snapshot: &ForkChoiceSnapshot) -> Result<(), StorageError>;

    /// Reads the fork-choice cursor snapshot from the `forkchoice` CF.
    ///
    /// Returns `None` on a fresh (empty) database; `Some` on warm restart.
    fn get_forkchoice_snapshot(&self) -> Result<Option<ForkChoiceSnapshot>, StorageError>;

    /// Writes a raw key/value pair to the `metadata` CF.
    ///
    /// Used for the schema-version sentinel (`b"schema_version"`) and other
    /// migration anchors.
    fn put_metadata(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Reads a raw value from the `metadata` CF, if the key exists.
    fn get_metadata(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Commits all non-`None` fields of `batch` as a single `WriteBatch`.
    ///
    /// This is the preferred write path for block-processing transitions; it
    /// guarantees atomicity across block, state, fork-choice snapshot, and
    /// slot-index updates. Per `D-rocksdb` atomic-writes requirement:
    /// "never split a logical state update across two un-batched writes."
    fn write_block_transition(&self, batch: BlockTransition<E>) -> Result<(), StorageError>;
}
