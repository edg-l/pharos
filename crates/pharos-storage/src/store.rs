//! `Store<E>` — the synchronous storage trait for the Pharos chain database.
//!
//! Per `D-store-trait`: the trait is **sync** because RocksDB is sync and
//! STF + fork-choice are sync. Async callers wrap with
//! `tokio::task::spawn_blocking` at the call site. The `Send + Sync + 'static`
//! bound allows `Arc<dyn Store<E>>` to be shared across the network task and
//! the (future) STF executor thread pool.

use pharos_types::BeaconSpec;
use pharos_types::PayloadStatus;
use pharos_types::deneb::BlobSidecar;
use pharos_types::phase0::operations::SignedBeaconBlockHeader;
use pharos_types::phase0::primitives::{Root, Slot};

use crate::error::StorageError;
use crate::forkchoice::ForkChoiceSnapshot;
use crate::state_summary::StateSummary;
use crate::transition::BlockTransition;

// ── ColdMigrationBatch ────────────────────────────────────────────────────────

/// Parameters for one atomic hot→cold migration step.
///
/// Passed to `Store::migrate_to_cold`; all writes and deletes execute in a
/// single `WriteBatch` so neither the copy nor the delete is visible
/// independently. Per `D-freezer-in-rocksdb`.
pub struct ColdMigrationBatch<E: BeaconSpec> {
    /// Finalized blocks to copy into `cold-blocks` CF.
    pub cold_blocks: Vec<(Root, E::SignedBeaconBlock)>,

    /// Restore-point states to write: `(restore_slot, state_root, BeaconState)`.
    ///
    /// Each is written to `cold-states` (keyed by `restore_slot`) and the
    /// `restore-points` index (`restore_slot → state_root`) in the same batch.
    /// ALL interval-multiple boundaries in the migration window are written (not
    /// just the highest) so the replay-cost bound holds across finalization gaps.
    pub cold_states: Vec<(Slot, Root, E::BeaconState)>,

    /// Block roots to delete from `CF_BLOCKS` (hot blocks now in cold).
    pub prune_block_roots: Vec<Root>,

    /// State roots to delete from `CF_STATES` (hot epoch-boundary states now cold).
    pub prune_state_roots: Vec<Root>,

    /// Orphan block roots to delete from `CF_BLOCKS` AND `CF_BLOCK_ROOT_TO_SLOT`.
    ///
    /// Orphans are non-canonical blocks (competing forks below the finalized slot)
    /// identified in Task 4.1 by comparing hot block roots against the authoritative
    /// `slot_to_block_root` canonical index. Per `D-prune-behind-finalized`:
    /// orphan's `blocks` CF entry and its reverse-index `block_root_to_slot` entry
    /// are deleted; the canonical `slot_to_block_root[slot]` entry is NOT deleted
    /// (it is the navigational index cold regen + network depend on indefinitely).
    pub prune_orphan_block_roots: Vec<Root>,

    /// The new hot/cold boundary: written to `metadata[b"split_slot"]`.
    ///
    /// NOTE: the `slot_to_block_root` / `block_root_to_slot` index CFs are
    /// deliberately NOT pruned for canonical migrated blocks — they are append-only
    /// navigational indexes that cold regen (`block_root_at_slot`) and the network
    /// `BeaconBlocksByRange` path require for migrated history indefinitely.
    pub split_slot: Slot,
}

/// Synchronous storage trait for the Pharos chain database.
///
/// All methods take `&self` (interior mutability via RocksDB's `Send + Sync`
/// handle). Implementors must be `Send + Sync + 'static` for use behind `Arc`.
///
/// Per `D-store-trait`.
pub trait Store<E: BeaconSpec>: Send + Sync + 'static {
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

    // ── Cold-CF accessors (Phase 3 freezer) ──────────────────────────────────

    /// Write an SSZ-encoded `SignedBeaconBlock` to the `cold-blocks` CF, keyed
    /// by block root.
    ///
    /// Per schema v3 (`D-freezer-in-rocksdb`): finalized blocks are migrated
    /// here by `migrate_to_cold`; called as part of the atomic migration batch.
    fn put_cold_block(&self, root: Root, block: &E::SignedBeaconBlock) -> Result<(), StorageError>;

    /// Retrieve an SSZ `SignedBeaconBlock` from the `cold-blocks` CF.
    ///
    /// Returns `None` when the block has not been migrated (pre-Phase-3 or
    /// hot-only database).
    fn get_cold_block(&self, root: &Root) -> Result<Option<E::SignedBeaconBlock>, StorageError>;

    /// Write an SSZ `BeaconState` to the `cold-states` CF, keyed by the
    /// restore-point slot (big-endian `u64`).
    ///
    /// Per schema v3 (`D-restore-point-interval`): only restore-point-cadence
    /// epoch-boundary states are stored; intermediate states are reconstructed
    /// by replay.
    fn put_cold_state(
        &self,
        restore_slot: Slot,
        state: &E::BeaconState,
    ) -> Result<(), StorageError>;

    /// Retrieve the cold `BeaconState` at exact `restore_slot`.
    ///
    /// Returns `None` when no restore point was written at that slot.
    fn get_cold_state(&self, restore_slot: Slot) -> Result<Option<E::BeaconState>, StorageError>;

    /// Write a restore-point index entry: `restore-points[slot] = state_root`.
    ///
    /// Per schema v3 (`D-restore-point-interval`): the `restore-points` CF maps
    /// a restore-point slot to its state root for quick lookup.
    fn put_restore_point(&self, slot: Slot, state_root: Root) -> Result<(), StorageError>;

    /// Reverse-iterate the `restore-points` CF from `target_slot` downward to
    /// find the nearest restore point ≤ `target_slot`.
    ///
    /// Returns `(restore_slot, state_root)` or `None` when the CF is empty.
    fn nearest_restore_point(
        &self,
        target_slot: Slot,
    ) -> Result<Option<(Slot, Root)>, StorageError>;

    /// Execute one hot→cold migration atomically.
    ///
    /// Writes all `cold_blocks` into `CF_COLD_BLOCKS`, optionally writes a
    /// `cold_state` into `CF_COLD_STATES` + `CF_RESTORE_POINTS`, then deletes
    /// all `prune_block_roots` from `CF_BLOCKS`, `prune_state_roots` from
    /// `CF_STATES`, `prune_slots` from the slot-index CFs, and advances
    /// `metadata[b"split_slot"]` — all in one atomic `WriteBatch`.
    ///
    /// Per `D-freezer-in-rocksdb` + `D-prune-behind-finalized`.
    fn migrate_to_cold(&self, batch: ColdMigrationBatch<E>) -> Result<(), StorageError>;

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

    // ── Deneb light-client snapshot put/get (schema v5, D-deneb-lc-header) ────
    //
    // Separate CFs for deneb LC types, which have a different SSZ layout than
    // Capella (deneb ExecutionPayloadHeader adds blob_gas_used / excess_blob_gas).

    /// Store an SSZ-encoded Deneb `LightClientBootstrap`, keyed by `block_root`.
    fn put_light_client_bootstrap_deneb(
        &self,
        block_root: Root,
        bootstrap: &E::DenebLightClientBootstrap,
    ) -> Result<(), StorageError>;

    /// Retrieve the Deneb `LightClientBootstrap` for `block_root`, if stored.
    fn get_light_client_bootstrap_deneb(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::DenebLightClientBootstrap>, StorageError>;

    /// Store an SSZ-encoded Deneb `LightClientUpdate` for `period`.
    fn put_light_client_update_deneb(
        &self,
        period: u64,
        update: &E::DenebLightClientUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the Deneb `LightClientUpdate` for `period`, if stored.
    fn get_light_client_update_deneb(
        &self,
        period: u64,
    ) -> Result<Option<E::DenebLightClientUpdate>, StorageError>;

    /// Overwrite the single-row latest Deneb `LightClientFinalityUpdate`.
    fn put_light_client_finality_update_deneb(
        &self,
        update: &E::DenebLightClientFinalityUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored Deneb `LightClientFinalityUpdate`, if any.
    fn get_light_client_finality_update_deneb(
        &self,
    ) -> Result<Option<E::DenebLightClientFinalityUpdate>, StorageError>;

    /// Overwrite the single-row latest Deneb `LightClientOptimisticUpdate`.
    fn put_light_client_optimistic_update_deneb(
        &self,
        update: &E::DenebLightClientOptimisticUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored Deneb `LightClientOptimisticUpdate`, if any.
    fn get_light_client_optimistic_update_deneb(
        &self,
    ) -> Result<Option<E::DenebLightClientOptimisticUpdate>, StorageError>;

    // ── Electra light-client snapshot put/get (schema v6) ────────────────────
    //
    // Separate CFs for electra LC types. Electra BeaconState has additional
    // fields from EIP-7251, which deepens the merkle branches used in
    // LightClientBootstrap/Update/FinalityUpdate.

    /// Store an SSZ-encoded Electra `LightClientBootstrap`, keyed by `block_root`.
    fn put_light_client_bootstrap_electra(
        &self,
        block_root: Root,
        bootstrap: &E::ElectraLightClientBootstrap,
    ) -> Result<(), StorageError>;

    /// Retrieve the Electra `LightClientBootstrap` for `block_root`, if stored.
    fn get_light_client_bootstrap_electra(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::ElectraLightClientBootstrap>, StorageError>;

    /// Store an SSZ-encoded Electra `LightClientUpdate` for `period`.
    fn put_light_client_update_electra(
        &self,
        period: u64,
        update: &E::ElectraLightClientUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the Electra `LightClientUpdate` for `period`, if stored.
    fn get_light_client_update_electra(
        &self,
        period: u64,
    ) -> Result<Option<E::ElectraLightClientUpdate>, StorageError>;

    /// Overwrite the single-row latest Electra `LightClientFinalityUpdate`.
    fn put_light_client_finality_update_electra(
        &self,
        update: &E::ElectraLightClientFinalityUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored Electra `LightClientFinalityUpdate`, if any.
    fn get_light_client_finality_update_electra(
        &self,
    ) -> Result<Option<E::ElectraLightClientFinalityUpdate>, StorageError>;

    /// Overwrite the single-row latest Electra `LightClientOptimisticUpdate`.
    fn put_light_client_optimistic_update_electra(
        &self,
        update: &E::ElectraLightClientOptimisticUpdate,
    ) -> Result<(), StorageError>;

    /// Retrieve the latest stored Electra `LightClientOptimisticUpdate`, if any.
    fn get_light_client_optimistic_update_electra(
        &self,
    ) -> Result<Option<E::ElectraLightClientOptimisticUpdate>, StorageError>;

    // ── Blob sidecar store (schema v4, D-blob-store-cf-keyed-by-root-index) ───

    /// Store an SSZ-encoded `BlobSidecar` keyed by `(block_root, index)`.
    ///
    /// Key layout: `block_root` (32 B) `||` `index` (8 B big-endian u64).
    /// Big-endian index ensures sidecars are returned in ascending index order
    /// by the prefix-scan `get_blob_sidecars_by_root`.
    ///
    /// Per `D-blob-store-cf-keyed-by-root-index`.
    fn put_blob_sidecar(
        &self,
        block_root: Root,
        index: u64,
        sidecar: &BlobSidecar,
    ) -> Result<(), StorageError>;

    /// Retrieve the `BlobSidecar` for `(block_root, index)`, if stored.
    fn get_blob_sidecar(
        &self,
        block_root: &Root,
        index: u64,
    ) -> Result<Option<BlobSidecar>, StorageError>;

    /// Retrieve all `BlobSidecar`s for `block_root`, ordered by ascending index.
    ///
    /// Implemented via a RocksDB prefix iterator on the 32-byte `block_root`
    /// prefix of the `blob-sidecars` CF keys. Returns an empty vec when no
    /// sidecars have been stored for this root.
    fn get_blob_sidecars_by_root(
        &self,
        block_root: &Root,
    ) -> Result<Vec<BlobSidecar>, StorageError>;

    /// Delete all `BlobSidecar`s whose block slot is strictly below `prune_slot`.
    ///
    /// Implemented by scanning the `blob-sidecars` CF, decoding the
    /// `signed_block_header.message.slot` from each sidecar, and deleting
    /// entries whose slot falls below the prune horizon.
    ///
    /// Called from `run_blob_prune_loop` when
    /// `current_epoch - epoch_of(blob) > MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`.
    /// The `slot_to_block_root` index is NOT pruned (it is navigational and
    /// must persist indefinitely per `D-blob-store-cf-keyed-by-root-index`).
    fn prune_blob_sidecars_below_slot(&self, prune_slot: Slot) -> Result<(), StorageError>;

    // ── Slasher proposer index (Phase B, --slasher) ─────────────────────────────

    /// Store one `SignedBeaconBlockHeader` in the proposer index, keyed by
    /// `(slot, proposer_index, header_root)`.
    ///
    /// `header_root` is the `tree_hash_root()` of the `message` field. Two
    /// distinct headers a proposer signed at the same slot land under the same
    /// `slot || proposer_index` prefix with different `header_root` suffixes, so
    /// both survive and `slasher_proposer_headers_at` can return them together.
    ///
    /// Per `D-slasher-proposer-index-cf`.
    fn put_slasher_proposer_header(
        &self,
        slot: Slot,
        proposer_index: u64,
        header_root: Root,
        header: &SignedBeaconBlockHeader,
    ) -> Result<(), StorageError>;

    /// Return every `SignedBeaconBlockHeader` stored for `(slot, proposer_index)`.
    ///
    /// Implemented via a RocksDB prefix iterator on the 16-byte
    /// `slot || proposer_index` key prefix. Returns an empty vec when the
    /// proposer signed no (recorded) block at this slot. Two or more results
    /// with distinct `message` roots are a slashable proposer double-block.
    ///
    /// Per `D-slasher-proposer-index-cf`.
    fn slasher_proposer_headers_at(
        &self,
        slot: Slot,
        proposer_index: u64,
    ) -> Result<Vec<SignedBeaconBlockHeader>, StorageError>;
}
