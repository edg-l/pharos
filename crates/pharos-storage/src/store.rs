//! `Store<E>` — the synchronous storage trait for the Pharos chain database.
//!
//! Per `D-store-trait`: the trait is **sync** because RocksDB is sync and
//! STF + fork-choice are sync. Async callers wrap with
//! `tokio::task::spawn_blocking` at the call site. The `Send + Sync + 'static`
//! bound allows `Arc<dyn Store<E>>` to be shared across the network task and
//! the (future) STF executor thread pool.

use pharos_types::EthSpec;
use pharos_types::PayloadStatus;
use pharos_types::phase0::primitives::{Root, Slot};

use crate::error::StorageError;
use crate::forkchoice::ForkChoiceSnapshot;
use crate::state_summary::StateSummary;
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

    // ── Payload status ────────────────────────────────────────────────────────

    /// Retrieve the stored `PayloadStatus` for `root`, if any.
    ///
    /// Returns `None` when the block is not present in the `payload-status` CF.
    /// Per `D-payload-status-store` (M4a Phase 4): the discriminant byte maps
    /// `0 = Valid, 1 = Invalid, 2 = NotValidated`.
    fn payload_status(&self, root: Root) -> Result<Option<PayloadStatus>, StorageError>;

    /// Iterate all `(Root, PayloadStatus)` entries in the `payload-status` CF.
    ///
    /// Used at startup by `rehydrate_fork_choice_store` to seed the in-memory
    /// `pharos_fork_choice::Store::payload_statuses` map.
    fn payload_statuses_iter(&self) -> Result<Vec<(Root, PayloadStatus)>, StorageError>;

    // ── State-summary store ───────────────────────────────────────────────────

    /// Write a `StateSummary` for `block_root` to the `state-summary` CF.
    ///
    /// Per schema v3 (`D-schema-v3-migration`): called for every imported block.
    /// Prefer using `write_block_transition` (which sets `batch.state_summary`)
    /// rather than calling this directly, to preserve the atomic-write invariant.
    fn put_state_summary(
        &self,
        block_root: Root,
        summary: &StateSummary,
    ) -> Result<(), StorageError>;

    /// Retrieve the `StateSummary` for `block_root` from the `state-summary` CF.
    ///
    /// Returns `None` when the block has not been imported (or was imported before
    /// schema v3 — those blocks lack a summary row).
    fn get_state_summary(&self, block_root: &Root) -> Result<Option<StateSummary>, StorageError>;

    // ── Light-client snapshot store ───────────────────────────────────────────
    //
    // Four typed put/get pairs for the four light-client column families defined
    // in `cf.rs`. Per `D-light-client-server-only` (Task 6.9).

    /// Store an SSZ-encoded `LightClientBootstrap`, keyed by `block_root`.
    ///
    /// Per `Q-light-client-storage-keying` (LOCKED): bootstrap is keyed by block
    /// root (not sync-committee period) because the request carries a block root.
    fn put_light_client_bootstrap(
        &self,
        block_root: Root,
        bootstrap: &E::AltairLightClientBootstrap,
    ) -> Result<(), StorageError>;

    /// Retrieve the `LightClientBootstrap` for `block_root`, if stored.
    fn get_light_client_bootstrap(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::AltairLightClientBootstrap>, StorageError>;

    /// Store an SSZ-encoded `LightClientUpdate` for `period` (sync-committee period).
    ///
    /// Overwrites any existing update for the same period (keeps the best one;
    /// caller is responsible for `is_better_update` comparison before calling).
    fn put_light_client_update(
        &self,
        period: u64,
        update: &E::AltairLightClientUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the `LightClientUpdate` for `period`, if stored.
    fn get_light_client_update(
        &self,
        period: u64,
    ) -> Result<Option<E::AltairLightClientUpdate>, StorageError>;

    /// Retrieve all stored `LightClientUpdate` objects whose period falls in
    /// `[start_period, start_period + count)`, ordered by ascending period.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md:29-35` response ordering.
    fn get_light_client_updates_by_range(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<E::AltairLightClientUpdate>, StorageError>;

    /// Overwrite the single-row latest `LightClientFinalityUpdate`.
    fn put_light_client_finality_update(
        &self,
        update: &E::AltairLightClientFinalityUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored `LightClientFinalityUpdate`, if any.
    fn get_light_client_finality_update(
        &self,
    ) -> Result<Option<E::AltairLightClientFinalityUpdate>, StorageError>;

    /// Overwrite the single-row latest `LightClientOptimisticUpdate`.
    fn put_light_client_optimistic_update(
        &self,
        update: &E::AltairLightClientOptimisticUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored `LightClientOptimisticUpdate`, if any.
    fn get_light_client_optimistic_update(
        &self,
    ) -> Result<Option<E::AltairLightClientOptimisticUpdate>, StorageError>;

    // ── Capella light-client snapshot store ───────────────────────────────────
    //
    // Separate CFs for capella LC types, which have a different SSZ layout
    // (LightClientHeader includes execution + execution_branch fields).

    /// Store an SSZ-encoded Capella `LightClientBootstrap`, keyed by `block_root`.
    fn put_light_client_bootstrap_capella(
        &self,
        block_root: Root,
        bootstrap: &E::CapellaLightClientBootstrap,
    ) -> Result<(), StorageError>;

    /// Retrieve the Capella `LightClientBootstrap` for `block_root`, if stored.
    fn get_light_client_bootstrap_capella(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::CapellaLightClientBootstrap>, StorageError>;

    /// Store an SSZ-encoded Capella `LightClientUpdate` for `period`.
    fn put_light_client_update_capella(
        &self,
        period: u64,
        update: &E::CapellaLightClientUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the Capella `LightClientUpdate` for `period`, if stored.
    fn get_light_client_update_capella(
        &self,
        period: u64,
    ) -> Result<Option<E::CapellaLightClientUpdate>, StorageError>;

    /// Overwrite the single-row latest Capella `LightClientFinalityUpdate`.
    fn put_light_client_finality_update_capella(
        &self,
        update: &E::CapellaLightClientFinalityUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored Capella `LightClientFinalityUpdate`, if any.
    fn get_light_client_finality_update_capella(
        &self,
    ) -> Result<Option<E::CapellaLightClientFinalityUpdate>, StorageError>;

    /// Overwrite the single-row latest Capella `LightClientOptimisticUpdate`.
    fn put_light_client_optimistic_update_capella(
        &self,
        update: &E::CapellaLightClientOptimisticUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored Capella `LightClientOptimisticUpdate`, if any.
    fn get_light_client_optimistic_update_capella(
        &self,
    ) -> Result<Option<E::CapellaLightClientOptimisticUpdate>, StorageError>;
}
