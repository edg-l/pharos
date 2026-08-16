//! RocksDB-backed `Store<E>` implementation.
//!
//! Per `D-rocksdb`: single DB file with the schema-v3 column-family set
//! (see `cf::all_cfs`), big-endian slot keys, Lz4 compression on `blocks` and
//! `states` CFs, schema-version sentinel in the `metadata` CF.

use std::path::PathBuf;

use pharos_ssz::{Decode, Encode};
use pharos_types::deneb::BlobSidecar;
use pharos_types::phase0::operations::SignedBeaconBlockHeader;
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::{BeaconStateView, EthSpec, PayloadStatus};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, Direction, IteratorMode, Options,
    WriteBatch,
};
use tracing::warn;

use crate::cf::{
    CF_BLOB_SIDECARS, CF_BLOCK_ROOT_TO_SLOT, CF_BLOCKS, CF_COLD_BLOCKS, CF_COLD_STATES,
    CF_FORKCHOICE, CF_LC_BOOTSTRAP, CF_LC_BOOTSTRAP_CAPELLA, CF_LC_BOOTSTRAP_DENEB,
    CF_LC_BOOTSTRAP_ELECTRA, CF_LC_FINALITY_UPDATE, CF_LC_FINALITY_UPDATE_CAPELLA,
    CF_LC_FINALITY_UPDATE_DENEB, CF_LC_FINALITY_UPDATE_ELECTRA, CF_LC_OPTIMISTIC_UPDATE,
    CF_LC_OPTIMISTIC_UPDATE_CAPELLA, CF_LC_OPTIMISTIC_UPDATE_DENEB,
    CF_LC_OPTIMISTIC_UPDATE_ELECTRA, CF_LC_UPDATE, CF_LC_UPDATE_CAPELLA, CF_LC_UPDATE_DENEB,
    CF_LC_UPDATE_ELECTRA, CF_METADATA, CF_PAYLOAD_STATUS, CF_RESTORE_POINTS, CF_SLASHER_PROPOSERS,
    CF_SLOT_TO_BLOCK_ROOT, CF_STATE_SUMMARY, CF_STATES, LC_LATEST_KEY, all_cfs,
};
use crate::error::StorageError;
use crate::forkchoice::ForkChoiceSnapshot;
use crate::keys::{
    blob_sidecar_key, parse_slot_key, root_key, slasher_proposer_key, slasher_proposer_prefix,
    slot_key,
};
use crate::migrations::{MIGRATION_BASELINE, run_migrations};
use crate::state_summary::StateSummary;
use crate::store::{ColdMigrationBatch, Store};
use crate::transition::BlockTransition;

/// Schema version written to `metadata[b"schema_version"]` at DB creation.
///
/// History:
/// - v1 (M3a): initial schema (11 column families).
/// - v2 (M4a): added `payload-status` column family for Bellatrix EL
///   payload validation state. Opening a v1 database returns
///   `StorageError::SchemaMismatch`; the operator must delete the chain DB
///   and resync from a checkpoint.
/// - v3 (M-Storage): added four schema-v3 CFs — `state-summary`,
///   `cold-blocks`, `cold-states`, `restore-points` — per
///   `D-schema-v3-migration`. Opening a v2 database returns
///   `StorageError::SchemaMismatch`; the operator must resync from checkpoint
///   (no in-place migration: the live node had no post-startup block/state
///   persistence to preserve before this milestone).
/// - v4 (M10-DA Phase 4): added `blob-sidecars` CF for Deneb blob sidecar
///   storage per `D-blob-store-cf-keyed-by-root-index` and
///   `D-schema-v4-migration`. Opening a v3 database returns
///   `StorageError::SchemaMismatch`; the operator must resync from checkpoint
///   (no in-place migration).
/// - v5 (M10-Deneb Phase 1): added four Deneb LC CFs —
///   `deneb-light-client-bootstrap`, `deneb-light-client-update`,
///   `deneb-latest-finality-update`, `deneb-latest-optimistic-update` — per
///   `D-deneb-lc-header`. Deneb LC headers include a deneb `ExecutionPayloadHeader`
///   (adds `blob_gas_used`/`excess_blob_gas`) so they cannot share CFs with Capella.
///   Opening a v4 database returns `StorageError::SchemaMismatch`; the operator
///   must resync from checkpoint (no in-place migration).
/// - v6 (M12-Electra Phase 6e): added four Electra LC CFs —
///   `electra-light-client-bootstrap`, `electra-light-client-update`,
///   `electra-latest-finality-update`, `electra-latest-optimistic-update`.
///   Electra LC branches are deeper than Deneb (EIP-7251 enlarged BeaconState),
///   so electra types cannot share CFs with Deneb. Opening a v5 database returns
///   `StorageError::SchemaMismatch`; the operator must resync from checkpoint.
///   v6 is also the [`MIGRATION_BASELINE`](crate::migrations::MIGRATION_BASELINE):
///   versions below v6 (v1..=v5) are resync-only (no migration path); v6 and
///   above are migrated forward in place by the [`crate::migrations`] framework.
/// - v7 (M11 Phase 4): seed of the forward-only migration framework. Identity /
///   version-bump-only migration (no new CFs, no data move) — proves the
///   migration walk with a real registry entry. Opening a v6 database now
///   MIGRATES forward to v7 in place instead of erroring.
/// - v8 (M11 Phase 9): added the `slasher-proposers` CF for the opt-in
///   (`--slasher`) chain-history replay slasher's proposer double-block index,
///   per `D-slasher-proposer-index-cf`. Opening a v7 database MIGRATES forward
///   to v8 in place: the new CF is auto-created by
///   `create_missing_column_families` and the v7→v8 migration bumps the version
///   stamp (no data move). The proposer index is rebuilt from scratch on each
///   `--slasher` replay, so an empty CF after migration is correct.
pub(crate) const SCHEMA_VERSION: u32 = 8;

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for opening a `RocksStore`.
pub struct RocksStoreConfig {
    /// Path to the RocksDB directory.
    pub path: PathBuf,
    /// Whether to create the database if it does not already exist.
    pub create_if_missing: bool,
}

// ── RocksStore ────────────────────────────────────────────────────────────────

/// RocksDB-backed implementation of `Store<E>`.
///
/// Thread-safe (`Send + Sync`) via `rocksdb::DB`'s own interior mutability.
/// Open one `RocksStore` per process and share it behind `Arc`.
#[derive(Debug)]
pub struct RocksStore {
    db: DB,
}

impl RocksStore {
    /// Open (or create) the RocksDB database at `cfg.path` with the full
    /// schema-v7 column-family set registered (`cf::all_cfs`).
    ///
    /// Steps per `D-rocksdb`:
    /// 1. Build global `Options` with `create_if_missing` / `create_missing_column_families`.
    /// 2. Per-CF options: Lz4 compression on `blocks` and `states`; defaults elsewhere.
    /// 3. Open via `DB::open_cf_descriptors`.
    /// 4. Read / initialise the `schema_version` sentinel.
    pub fn open<E: EthSpec>(cfg: RocksStoreConfig) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(cfg.create_if_missing);
        opts.create_missing_column_families(true);

        let descriptors: Vec<ColumnFamilyDescriptor> = all_cfs()
            .iter()
            .map(|&name| ColumnFamilyDescriptor::new(name, per_cf_opts(name)))
            .collect();

        let db = DB::open_cf_descriptors(&opts, &cfg.path, descriptors)?;
        let store = Self { db };

        // Step 4: schema-version sentinel.
        let cf = store.cf_handle(CF_METADATA)?;
        match store.db.get_cf(cf, b"schema_version")? {
            None => {
                // Fresh DB — write current schema version.
                store
                    .db
                    .put_cf(cf, b"schema_version", SCHEMA_VERSION.to_le_bytes())?;
            }
            Some(bytes) => {
                if bytes.len() != 4 {
                    return Err(StorageError::InvalidKeyLength {
                        got: bytes.len(),
                        expected: 4,
                    });
                }
                let found = u32::from_le_bytes(bytes[..4].try_into().expect("length checked"));
                if (MIGRATION_BASELINE..SCHEMA_VERSION).contains(&found) {
                    // `MIGRATION_BASELINE <= found < SCHEMA_VERSION`: walk the
                    // forward migrations in place, each step atomic.
                    warn!(
                        from = found,
                        to = SCHEMA_VERSION,
                        "migrating chain DB schema forward"
                    );
                    run_migrations(&store.db, found, SCHEMA_VERSION)?;
                } else if found != SCHEMA_VERSION {
                    // Either a future version (`found > SCHEMA_VERSION`, no
                    // down-migration) or a pre-baseline version
                    // (`found < MIGRATION_BASELINE`, no migration path). Both are
                    // resync-only.
                    return Err(StorageError::SchemaMismatch {
                        found,
                        expected: SCHEMA_VERSION,
                    });
                }
                // else: `found == SCHEMA_VERSION` — current, nothing to do.
            }
        }

        Ok(store)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Returns the `ColumnFamily` handle for `name`, or `ColumnFamilyNotFound`.
    fn cf_handle(&self, name: &'static str) -> Result<&ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or(StorageError::ColumnFamilyNotFound(name))
    }

    // ── Public inherent helpers (not on Store<E> trait) ───────────────────────

    /// Enumerate all block roots in the hot `blocks` CF whose slot falls in
    /// `[from_slot, below_slot)`.
    ///
    /// Used by the Phase-4 orphan-pruning pass in `run_freezer_loop`: iterates
    /// the `block_root_to_slot` reverse-index (which is not deleted by migration
    /// — only the `blocks` CF entry moves cold) to find every hot block root at
    /// a slot below the new split and returns `(root, slot)` pairs.  The caller
    /// then compares each root against `slot_to_block_root[slot]` (the
    /// authoritative canonical index) to identify orphans without using
    /// `get_ancestor` (CRITICAL-4).
    pub fn hot_block_roots_in_range(
        &self,
        from_slot: Slot,
        below_slot: Slot,
    ) -> Result<Vec<(Root, Slot)>, StorageError> {
        // Only roots still present in the hot `blocks` CF are orphan candidates;
        // roots already migrated cold are no longer in `blocks` and must be
        // skipped (they were canonical and already cold-copied by Task 3.3).
        let blocks_cf = self.cf_handle(CF_BLOCKS)?;
        let root_to_slot_cf = self.cf_handle(CF_BLOCK_ROOT_TO_SLOT)?;

        let mut result = Vec::new();
        // Iterate the entire `block_root_to_slot` CF (keys are 32-byte roots in
        // arbitrary order, not sorted by slot).  For each entry, check if the
        // slot is in the target range and the block still exists in the hot CF.
        let iter = self.db.iterator_cf(root_to_slot_cf, IteratorMode::Start);

        for item in iter {
            let (k, v) = item?;
            if k.len() != 32 {
                continue;
            }
            if v.len() != 8 {
                continue;
            }
            // `block_root_to_slot` values are little-endian u64 (written by
            // `write_block_transition` at `db.rs:326`).
            let slot_u64 = u64::from_le_bytes(v[..8].try_into().expect("length 8 checked"));
            let slot = Slot(slot_u64);
            if slot < from_slot || slot >= below_slot {
                continue;
            }
            // Only include roots still present in the hot `blocks` CF.
            let mut root_bytes = [0u8; 32];
            root_bytes.copy_from_slice(&k);
            let root = Root::from(root_bytes);
            if self.db.get_cf(blocks_cf, root_key(&root))?.is_some() {
                result.push((root, slot));
            }
        }
        Ok(result)
    }

    /// Flush the WAL and all live memtables to SST files.
    ///
    /// Called as the final step of the graceful-shutdown sequence
    /// (`D-graceful-shutdown-order`, M11 Phase 17) to ensure every
    /// buffered write reaches durable storage before the process exits.
    ///
    /// Steps:
    /// 1. `flush_wal(sync=true)` — syncs the WAL file to disk, making all
    ///    recent writes durable even before memtable flush.
    /// 2. `flush()` — flushes all live memtables across all CFs, converting
    ///    in-memory writes to immutable SST files.
    ///
    /// Both calls return `rocksdb::Error` on failure, mapped to
    /// `StorageError::RocksDb` via the `#[from]` impl.
    pub fn fsync(&self) -> Result<(), StorageError> {
        self.db.flush_wal(true)?;
        self.db.flush()?;
        Ok(())
    }

    /// Count the number of entries in the `cold-states` CF.
    ///
    /// Each entry corresponds to one restore-point state written by the freezer.
    /// Used by Phase 3 verification (M11) to assert that cold-region density
    /// equals the restore-point count (never dense per-slot states).
    /// Per `D-cold-granularity-restore-points-only`.
    pub fn count_cold_state_entries(&self) -> Result<u64, StorageError> {
        let cf = self.cf_handle(CF_COLD_STATES)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut count = 0u64;
        for item in iter {
            item?;
            count += 1;
        }
        Ok(count)
    }

    /// Look up the canonical block root at `slot` from the `slot_to_block_root` CF.
    ///
    /// Returns `None` when no block was imported at this slot (e.g. missed slot
    /// or a slot before the checkpoint-sync anchor). Used by the Phase-2
    /// `StateRegenService` to map boundary slots to block roots without decoding
    /// the full `SignedBeaconBlock`.
    pub fn block_root_at_slot(&self, slot: Slot) -> Result<Option<Root>, StorageError> {
        let cf = self.cf_handle(CF_SLOT_TO_BLOCK_ROOT)?;
        match self.db.get_cf(cf, slot_key(slot))? {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(StorageError::InvalidKeyLength {
                        got: bytes.len(),
                        expected: 32,
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(Root::from(arr)))
            }
        }
    }
}

/// Returns per-CF `Options` pre-populated per `D-block-encoding-on-disk`.
///
/// `blocks` and `states` get Lz4 block-level compression; other CFs use the
/// RocksDB default (no per-row compression; rows are too small to benefit).
fn per_cf_opts(name: &str) -> Options {
    let mut opts = Options::default();
    if name == CF_BLOCKS || name == CF_STATES {
        opts.set_compression_type(DBCompressionType::Lz4);
    }
    opts
}

// ── PayloadStatus encoding ────────────────────────────────────────────────────

/// Encode a `PayloadStatus` to its `u8` discriminant.
///
/// `0 = Valid, 1 = Invalid, 2 = NotValidated` per `D-payload-status-store`.
fn encode_payload_status(status: PayloadStatus) -> u8 {
    match status {
        PayloadStatus::Valid => 0,
        PayloadStatus::Invalid => 1,
        PayloadStatus::NotValidated => 2,
    }
}

/// Decode a `u8` discriminant back to `PayloadStatus`.
fn decode_payload_status(byte: u8) -> Result<PayloadStatus, StorageError> {
    match byte {
        0 => Ok(PayloadStatus::Valid),
        1 => Ok(PayloadStatus::Invalid),
        2 => Ok(PayloadStatus::NotValidated),
        other => Err(StorageError::CorruptedData(format!(
            "invalid PayloadStatus discriminant: {other} (expected 0, 1, or 2)"
        ))),
    }
}

// ── Store<E> impl ─────────────────────────────────────────────────────────────

impl<E: EthSpec> Store<E> for RocksStore {
    fn put_block(&self, root: Root, block: &E::SignedBeaconBlock) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_BLOCKS)?;
        let encoded = block.as_ssz_bytes();
        self.db.put_cf(cf, root_key(&root), encoded)?;
        Ok(())
    }

    fn get_block(&self, root: &Root) -> Result<Option<E::SignedBeaconBlock>, StorageError> {
        let cf = self.cf_handle(CF_BLOCKS)?;
        match self.db.get_cf(cf, root_key(root))? {
            None => Ok(None),
            Some(bytes) => {
                let block = E::SignedBeaconBlock::from_ssz_bytes(&bytes)?;
                Ok(Some(block))
            }
        }
    }

    fn get_blocks_by_range(
        &self,
        start_slot: Slot,
        count: u64,
    ) -> Result<Vec<E::SignedBeaconBlock>, StorageError> {
        let cf = self.cf_handle(CF_SLOT_TO_BLOCK_ROOT)?;
        let start_key = slot_key(start_slot);
        let end_slot = Slot(start_slot.0.saturating_add(count));

        let mut blocks = Vec::new();
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&start_key, Direction::Forward));

        for item in iter {
            let (k, v) = item?;
            let slot = parse_slot_key(&k)?;
            if slot >= end_slot {
                break;
            }
            if v.len() != 32 {
                warn!(
                    slot = slot.0,
                    "slot_to_block_root value has wrong length; skipping"
                );
                continue;
            }
            let mut root_bytes = [0u8; 32];
            root_bytes.copy_from_slice(&v);
            let root = Root::from(root_bytes);
            if let Some(block) = <RocksStore as Store<E>>::get_block(self, &root)? {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    fn put_state(&self, state_root: Root, state: &E::BeaconState) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_STATES)?;
        let encoded = state.as_ssz_bytes();
        self.db.put_cf(cf, root_key(&state_root), encoded)?;
        Ok(())
    }

    fn get_state(&self, state_root: &Root) -> Result<Option<E::BeaconState>, StorageError> {
        let cf = self.cf_handle(CF_STATES)?;
        match self.db.get_cf(cf, root_key(state_root))? {
            None => Ok(None),
            Some(bytes) => {
                // Decode lands `Backend::Naive` per `D-no-tree-backend-on-decode`;
                // flip the seven hot fields to `Backend::Tree` here so live-node
                // consumers (fork-choice, STF, Beacon API) get per-node hash
                // caching and CoW path-copy writes amortised across calls.
                let state = E::BeaconState::from_ssz_bytes(&bytes)?.into_tree_backend()?;
                Ok(Some(state))
            }
        }
    }

    fn put_forkchoice_snapshot(&self, snapshot: &ForkChoiceSnapshot) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_FORKCHOICE)?;
        let encoded = snapshot.as_ssz_bytes();
        self.db.put_cf(cf, b"forkchoice", encoded)?;
        Ok(())
    }

    fn get_forkchoice_snapshot(&self) -> Result<Option<ForkChoiceSnapshot>, StorageError> {
        let cf = self.cf_handle(CF_FORKCHOICE)?;
        match self.db.get_cf(cf, b"forkchoice")? {
            None => Ok(None),
            Some(bytes) => {
                let snapshot = ForkChoiceSnapshot::from_ssz_bytes(&bytes)?;
                Ok(Some(snapshot))
            }
        }
    }

    fn put_metadata(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_METADATA)?;
        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    fn get_metadata(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.cf_handle(CF_METADATA)?;
        let result = self.db.get_cf(cf, key)?;
        Ok(result.map(|v| v.to_vec()))
    }

    fn write_block_transition(&self, batch: BlockTransition<E>) -> Result<(), StorageError> {
        let mut wb = WriteBatch::default();

        if let Some((root, block)) = &batch.block {
            let cf = self.cf_handle(CF_BLOCKS)?;
            wb.put_cf(cf, root_key(root), block.as_ssz_bytes());
        }

        if let Some((state_root, state)) = &batch.state {
            let cf = self.cf_handle(CF_STATES)?;
            wb.put_cf(cf, root_key(state_root), state.as_ssz_bytes());
        }

        if let Some(snapshot) = &batch.forkchoice {
            let cf = self.cf_handle(CF_FORKCHOICE)?;
            wb.put_cf(cf, b"forkchoice", snapshot.as_ssz_bytes());
        }

        if let Some((slot, root)) = &batch.slot_index {
            let slot_cf = self.cf_handle(CF_SLOT_TO_BLOCK_ROOT)?;
            let root_cf = self.cf_handle(CF_BLOCK_ROOT_TO_SLOT)?;
            wb.put_cf(slot_cf, slot_key(*slot), root_key(root));
            wb.put_cf(root_cf, root_key(root), slot.0.to_le_bytes());
        }

        if let Some((root, status)) = &batch.payload_status {
            let cf = self.cf_handle(CF_PAYLOAD_STATUS)?;
            wb.put_cf(cf, root_key(root), [encode_payload_status(*status)]);
        }

        if let Some((block_root, summary)) = &batch.state_summary {
            let cf = self.cf_handle(CF_STATE_SUMMARY)?;
            wb.put_cf(cf, root_key(block_root), summary.as_ssz_bytes());
        }

        if !batch.metadata.is_empty() {
            let cf = self.cf_handle(CF_METADATA)?;
            for (key, value) in &batch.metadata {
                wb.put_cf(cf, *key, value);
            }
        }

        if !batch.blob_sidecars.is_empty() {
            let cf = self.cf_handle(CF_BLOB_SIDECARS)?;
            for (block_root, index, sidecar) in &batch.blob_sidecars {
                let key = blob_sidecar_key(block_root, *index);
                wb.put_cf(cf, key, sidecar.as_ssz_bytes());
            }
        }

        self.db.write(wb)?;
        Ok(())
    }

    fn put_state_summary(
        &self,
        block_root: Root,
        summary: &StateSummary,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_STATE_SUMMARY)?;
        self.db
            .put_cf(cf, root_key(&block_root), summary.as_ssz_bytes())?;
        Ok(())
    }

    fn get_state_summary(&self, block_root: &Root) -> Result<Option<StateSummary>, StorageError> {
        let cf = self.cf_handle(CF_STATE_SUMMARY)?;
        match self.db.get_cf(cf, root_key(block_root))? {
            None => Ok(None),
            Some(bytes) => {
                let summary = StateSummary::from_ssz_bytes(&bytes)?;
                Ok(Some(summary))
            }
        }
    }

    fn payload_status(&self, root: Root) -> Result<Option<PayloadStatus>, StorageError> {
        let cf = self.cf_handle(CF_PAYLOAD_STATUS)?;
        match self.db.get_cf(cf, root_key(&root))? {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 1 {
                    return Err(StorageError::InvalidKeyLength {
                        got: bytes.len(),
                        expected: 1,
                    });
                }
                Ok(Some(decode_payload_status(bytes[0])?))
            }
        }
    }

    fn payload_statuses_iter(&self) -> Result<Vec<(Root, PayloadStatus)>, StorageError> {
        let cf = self.cf_handle(CF_PAYLOAD_STATUS)?;
        let mut out = Vec::new();
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&[], Direction::Forward));
        for item in iter {
            let (k, v) = item?;
            if k.len() != 32 {
                warn!(
                    len = k.len(),
                    "payload-status CF: unexpected key length; skipping"
                );
                continue;
            }
            if v.len() != 1 {
                warn!(
                    len = v.len(),
                    "payload-status CF: unexpected value length; skipping"
                );
                continue;
            }
            let mut root_bytes = [0u8; 32];
            root_bytes.copy_from_slice(&k);
            let root = Root::from(root_bytes);
            let status = decode_payload_status(v[0])?;
            out.push((root, status));
        }
        Ok(out)
    }

    // ── Cold-CF accessors (Phase 3 freezer) ──────────────────────────────────

    fn put_cold_block(&self, root: Root, block: &E::SignedBeaconBlock) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_COLD_BLOCKS)?;
        self.db.put_cf(cf, root_key(&root), block.as_ssz_bytes())?;
        Ok(())
    }

    fn get_cold_block(&self, root: &Root) -> Result<Option<E::SignedBeaconBlock>, StorageError> {
        let cf = self.cf_handle(CF_COLD_BLOCKS)?;
        match self.db.get_cf(cf, root_key(root))? {
            None => Ok(None),
            Some(bytes) => {
                let block = E::SignedBeaconBlock::from_ssz_bytes(&bytes)?;
                Ok(Some(block))
            }
        }
    }

    fn put_cold_state(
        &self,
        restore_slot: Slot,
        state: &E::BeaconState,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_COLD_STATES)?;
        self.db
            .put_cf(cf, slot_key(restore_slot), state.as_ssz_bytes())?;
        Ok(())
    }

    fn get_cold_state(&self, restore_slot: Slot) -> Result<Option<E::BeaconState>, StorageError> {
        let cf = self.cf_handle(CF_COLD_STATES)?;
        match self.db.get_cf(cf, slot_key(restore_slot))? {
            None => Ok(None),
            Some(bytes) => {
                // Per `D-no-tree-backend-on-decode` live-node carveout: flip to
                // tree backend so structural sharing applies on restore.
                let state = E::BeaconState::from_ssz_bytes(&bytes)?.into_tree_backend()?;
                Ok(Some(state))
            }
        }
    }

    fn put_restore_point(&self, slot: Slot, state_root: Root) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_RESTORE_POINTS)?;
        self.db.put_cf(cf, slot_key(slot), root_key(&state_root))?;
        Ok(())
    }

    fn nearest_restore_point(
        &self,
        target_slot: Slot,
    ) -> Result<Option<(Slot, Root)>, StorageError> {
        let cf = self.cf_handle(CF_RESTORE_POINTS)?;
        // Reverse-iterate from target_slot (inclusive). With big-endian keys
        // (lexicographic == numeric order), `From(key, Reverse)` positions at the
        // last key ≤ start_key and iterates downward, so the first non-skipped
        // entry is the highest restore-point slot ≤ target_slot.
        let start_key = slot_key(target_slot);
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&start_key, Direction::Reverse));

        for item in iter {
            let (k, v) = item?;
            let rp_slot = parse_slot_key(&k)?;
            if rp_slot > target_slot {
                // The reverse iterator landed on a key strictly above target
                // (can happen when the seek key is between two keys).
                continue;
            }
            if v.len() != 32 {
                return Err(StorageError::InvalidKeyLength {
                    got: v.len(),
                    expected: 32,
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            return Ok(Some((rp_slot, Root::from(arr))));
        }
        Ok(None)
    }

    fn migrate_to_cold(&self, batch: ColdMigrationBatch<E>) -> Result<(), StorageError> {
        let mut wb = WriteBatch::default();

        // ── 1. Copy finalized blocks into cold-blocks CF ──────────────────────
        let cold_blocks_cf = self.cf_handle(CF_COLD_BLOCKS)?;
        for (root, block) in &batch.cold_blocks {
            wb.put_cf(cold_blocks_cf, root_key(root), block.as_ssz_bytes());
        }

        // ── 2. Write restore-point states + index entries ────────────────────
        // ALL interval-multiple boundaries in the window (not just the highest)
        // so cold regen never replays more than the restore-point interval.
        let cold_states_cf = self.cf_handle(CF_COLD_STATES)?;
        let rp_cf = self.cf_handle(CF_RESTORE_POINTS)?;
        for (restore_slot, state_root, state) in &batch.cold_states {
            wb.put_cf(
                cold_states_cf,
                slot_key(*restore_slot),
                state.as_ssz_bytes(),
            );
            wb.put_cf(rp_cf, slot_key(*restore_slot), root_key(state_root));
        }

        // ── 3. Delete pruned hot blocks ───────────────────────────────────────
        let hot_blocks_cf = self.cf_handle(CF_BLOCKS)?;
        for root in &batch.prune_block_roots {
            wb.delete_cf(hot_blocks_cf, root_key(root));
        }

        // ── 3b. Delete orphan blocks + their reverse-index entries ────────────
        //
        // Orphans are non-canonical blocks identified by Task 4.1 (CRITICAL-4):
        // their `blocks` CF entry AND their `block_root_to_slot` reverse-index
        // entry are deleted.  The canonical `slot_to_block_root[slot]` entries
        // are NOT deleted (they are the navigational index cold regen and network
        // require indefinitely).  Also delete the `state-summary` CF entry for
        // the orphan so the replay walk does not follow a stale parent chain.
        let root_to_slot_cf = self.cf_handle(CF_BLOCK_ROOT_TO_SLOT)?;
        let state_summary_cf = self.cf_handle(CF_STATE_SUMMARY)?;
        for root in &batch.prune_orphan_block_roots {
            wb.delete_cf(hot_blocks_cf, root_key(root));
            wb.delete_cf(root_to_slot_cf, root_key(root));
            wb.delete_cf(state_summary_cf, root_key(root));
        }

        // ── 4. Delete pruned hot states ───────────────────────────────────────
        let hot_states_cf = self.cf_handle(CF_STATES)?;
        for state_root in &batch.prune_state_roots {
            wb.delete_cf(hot_states_cf, root_key(state_root));
        }

        // NOTE: the `slot_to_block_root` index CF is intentionally NOT pruned.
        // It is an append-only navigational index that cold regen
        // (`block_root_at_slot` → nearest restore point + replay) and the
        // network `BeaconBlocksByRange` serving path require for migrated history.
        // Orphan block roots' `block_root_to_slot` reverse entries ARE pruned
        // (see step 3b) so RAM / disk is reclaimed for non-canonical history.

        // ── 5. Advance metadata[b"split_slot"] ───────────────────────────────
        let meta_cf = self.cf_handle(CF_METADATA)?;
        wb.put_cf(meta_cf, b"split_slot", batch.split_slot.0.to_be_bytes());

        self.db.write(wb)?;
        Ok(())
    }

    // ── Light-client snapshot put/get ─────────────────────────────────────────

    fn put_light_client_bootstrap(
        &self,
        block_root: Root,
        bootstrap: &E::AltairLightClientBootstrap,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP)?;
        self.db
            .put_cf(cf, root_key(&block_root), bootstrap.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_bootstrap(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::AltairLightClientBootstrap>, StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP)?;
        match self.db.get_cf(cf, root_key(block_root))? {
            None => Ok(None),
            Some(bytes) => {
                let bootstrap = E::AltairLightClientBootstrap::from_ssz_bytes(&bytes)?;
                Ok(Some(bootstrap))
            }
        }
    }

    fn put_light_client_update(
        &self,
        period: u64,
        update: &E::AltairLightClientUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE)?;
        self.db
            .put_cf(cf, period.to_be_bytes(), update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_update(
        &self,
        period: u64,
    ) -> Result<Option<E::AltairLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE)?;
        match self.db.get_cf(cf, period.to_be_bytes())? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::AltairLightClientUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn get_light_client_updates_by_range(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<E::AltairLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE)?;
        let mut updates = Vec::new();
        for period in start_period..start_period.saturating_add(count) {
            match self.db.get_cf(cf, period.to_be_bytes())? {
                None => {}
                Some(bytes) => {
                    let update = E::AltairLightClientUpdate::from_ssz_bytes(&bytes)?;
                    updates.push(update);
                }
            }
        }
        Ok(updates)
    }

    fn put_light_client_finality_update(
        &self,
        update: &E::AltairLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_finality_update(
        &self,
    ) -> Result<Option<E::AltairLightClientFinalityUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::AltairLightClientFinalityUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_optimistic_update(
        &self,
        update: &E::AltairLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_optimistic_update(
        &self,
    ) -> Result<Option<E::AltairLightClientOptimisticUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::AltairLightClientOptimisticUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    // ── Capella light-client snapshot put/get ─────────────────────────────────

    fn put_light_client_bootstrap_capella(
        &self,
        block_root: Root,
        bootstrap: &E::CapellaLightClientBootstrap,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP_CAPELLA)?;
        self.db
            .put_cf(cf, root_key(&block_root), bootstrap.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_bootstrap_capella(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::CapellaLightClientBootstrap>, StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP_CAPELLA)?;
        match self.db.get_cf(cf, root_key(block_root))? {
            None => Ok(None),
            Some(bytes) => {
                let bootstrap = E::CapellaLightClientBootstrap::from_ssz_bytes(&bytes)?;
                Ok(Some(bootstrap))
            }
        }
    }

    fn put_light_client_update_capella(
        &self,
        period: u64,
        update: &E::CapellaLightClientUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_CAPELLA)?;
        self.db
            .put_cf(cf, period.to_be_bytes(), update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_update_capella(
        &self,
        period: u64,
    ) -> Result<Option<E::CapellaLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_CAPELLA)?;
        match self.db.get_cf(cf, period.to_be_bytes())? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::CapellaLightClientUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_finality_update_capella(
        &self,
        update: &E::CapellaLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE_CAPELLA)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_finality_update_capella(
        &self,
    ) -> Result<Option<E::CapellaLightClientFinalityUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE_CAPELLA)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::CapellaLightClientFinalityUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_optimistic_update_capella(
        &self,
        update: &E::CapellaLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE_CAPELLA)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_optimistic_update_capella(
        &self,
    ) -> Result<Option<E::CapellaLightClientOptimisticUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE_CAPELLA)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::CapellaLightClientOptimisticUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    // ── Deneb light-client snapshot put/get (schema v5) ──────────────────────

    fn put_light_client_bootstrap_deneb(
        &self,
        block_root: Root,
        bootstrap: &E::DenebLightClientBootstrap,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP_DENEB)?;
        self.db
            .put_cf(cf, root_key(&block_root), bootstrap.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_bootstrap_deneb(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::DenebLightClientBootstrap>, StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP_DENEB)?;
        match self.db.get_cf(cf, root_key(block_root))? {
            None => Ok(None),
            Some(bytes) => {
                let bootstrap = E::DenebLightClientBootstrap::from_ssz_bytes(&bytes)?;
                Ok(Some(bootstrap))
            }
        }
    }

    fn put_light_client_update_deneb(
        &self,
        period: u64,
        update: &E::DenebLightClientUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_DENEB)?;
        self.db
            .put_cf(cf, period.to_be_bytes(), update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_update_deneb(
        &self,
        period: u64,
    ) -> Result<Option<E::DenebLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_DENEB)?;
        match self.db.get_cf(cf, period.to_be_bytes())? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::DenebLightClientUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_finality_update_deneb(
        &self,
        update: &E::DenebLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE_DENEB)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_finality_update_deneb(
        &self,
    ) -> Result<Option<E::DenebLightClientFinalityUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE_DENEB)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::DenebLightClientFinalityUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_optimistic_update_deneb(
        &self,
        update: &E::DenebLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE_DENEB)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_optimistic_update_deneb(
        &self,
    ) -> Result<Option<E::DenebLightClientOptimisticUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE_DENEB)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::DenebLightClientOptimisticUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    // ── Electra light-client snapshot put/get (schema v6) ────────────────────

    fn put_light_client_bootstrap_electra(
        &self,
        block_root: Root,
        bootstrap: &E::ElectraLightClientBootstrap,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP_ELECTRA)?;
        self.db
            .put_cf(cf, root_key(&block_root), bootstrap.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_bootstrap_electra(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::ElectraLightClientBootstrap>, StorageError> {
        let cf = self.cf_handle(CF_LC_BOOTSTRAP_ELECTRA)?;
        match self.db.get_cf(cf, root_key(block_root))? {
            None => Ok(None),
            Some(bytes) => {
                let bootstrap = E::ElectraLightClientBootstrap::from_ssz_bytes(&bytes)?;
                Ok(Some(bootstrap))
            }
        }
    }

    fn put_light_client_update_electra(
        &self,
        period: u64,
        update: &E::ElectraLightClientUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_ELECTRA)?;
        self.db
            .put_cf(cf, period.to_be_bytes(), update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_update_electra(
        &self,
        period: u64,
    ) -> Result<Option<E::ElectraLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_ELECTRA)?;
        match self.db.get_cf(cf, period.to_be_bytes())? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::ElectraLightClientUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_finality_update_electra(
        &self,
        update: &E::ElectraLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE_ELECTRA)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_finality_update_electra(
        &self,
    ) -> Result<Option<E::ElectraLightClientFinalityUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_FINALITY_UPDATE_ELECTRA)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::ElectraLightClientFinalityUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    fn put_light_client_optimistic_update_electra(
        &self,
        update: &E::ElectraLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE_ELECTRA)?;
        self.db.put_cf(cf, LC_LATEST_KEY, update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_optimistic_update_electra(
        &self,
    ) -> Result<Option<E::ElectraLightClientOptimisticUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_OPTIMISTIC_UPDATE_ELECTRA)?;
        match self.db.get_cf(cf, LC_LATEST_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let update = E::ElectraLightClientOptimisticUpdate::from_ssz_bytes(&bytes)?;
                Ok(Some(update))
            }
        }
    }

    // ── Blob sidecar store (schema v4) ────────────────────────────────────────

    fn put_blob_sidecar(
        &self,
        block_root: Root,
        index: u64,
        sidecar: &BlobSidecar,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_BLOB_SIDECARS)?;
        let key = blob_sidecar_key(&block_root, index);
        self.db.put_cf(cf, key, sidecar.as_ssz_bytes())?;
        Ok(())
    }

    fn get_blob_sidecar(
        &self,
        block_root: &Root,
        index: u64,
    ) -> Result<Option<BlobSidecar>, StorageError> {
        let cf = self.cf_handle(CF_BLOB_SIDECARS)?;
        let key = blob_sidecar_key(block_root, index);
        match self.db.get_cf(cf, key)? {
            None => Ok(None),
            Some(bytes) => {
                let sidecar = BlobSidecar::from_ssz_bytes(&bytes)?;
                Ok(Some(sidecar))
            }
        }
    }

    fn get_blob_sidecars_by_root(
        &self,
        block_root: &Root,
    ) -> Result<Vec<BlobSidecar>, StorageError> {
        let cf = self.cf_handle(CF_BLOB_SIDECARS)?;
        // Prefix scan: all keys starting with the 32-byte block_root, in
        // lexicographic order (= ascending blob index order, big-endian suffix).
        let prefix = root_key(block_root);
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));

        let mut sidecars = Vec::new();
        for item in iter {
            let (k, v) = item?;
            // Stop when the key no longer starts with block_root (32 bytes).
            if k.len() < 32 || &k[..32] != prefix {
                break;
            }
            let sidecar = BlobSidecar::from_ssz_bytes(&v)?;
            sidecars.push(sidecar);
        }
        Ok(sidecars)
    }

    fn prune_blob_sidecars_below_slot(&self, prune_slot: Slot) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_BLOB_SIDECARS)?;
        // Collect keys to delete — cannot delete while iterating the same CF.
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut to_delete: Vec<Vec<u8>> = Vec::new();

        for item in iter {
            let (k, v) = item?;
            let sidecar = match BlobSidecar::from_ssz_bytes(&v) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        key_len = k.len(),
                        val_len = v.len(),
                        error = ?e,
                        "blob-sidecars CF: corrupt sidecar value; skipping"
                    );
                    continue;
                }
            };
            let slot = sidecar.signed_block_header.message.slot;
            if slot < prune_slot {
                to_delete.push(k.to_vec());
            }
        }

        if !to_delete.is_empty() {
            let mut wb = WriteBatch::default();
            let cf = self.cf_handle(CF_BLOB_SIDECARS)?;
            for key in &to_delete {
                wb.delete_cf(cf, key);
            }
            self.db.write(wb)?;
        }
        Ok(())
    }

    // ── Slasher proposer index (Phase B) ──────────────────────────────────────

    fn put_slasher_proposer_header(
        &self,
        slot: Slot,
        proposer_index: u64,
        header_root: Root,
        header: &SignedBeaconBlockHeader,
    ) -> Result<(), StorageError> {
        let cf = self.cf_handle(CF_SLASHER_PROPOSERS)?;
        let key = slasher_proposer_key(slot, proposer_index, &header_root);
        self.db.put_cf(cf, key, header.as_ssz_bytes())?;
        Ok(())
    }

    fn slasher_proposer_headers_at(
        &self,
        slot: Slot,
        proposer_index: u64,
    ) -> Result<Vec<SignedBeaconBlockHeader>, StorageError> {
        let cf = self.cf_handle(CF_SLASHER_PROPOSERS)?;
        let prefix = slasher_proposer_prefix(slot, proposer_index);
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));

        let mut headers = Vec::new();
        for item in iter {
            let (k, v) = item?;
            // Stop when the key no longer carries the 16-byte (slot || proposer) prefix.
            if k.len() < 16 || k[..16] != prefix {
                break;
            }
            let header = SignedBeaconBlockHeader::from_ssz_bytes(&v)?;
            headers.push(header);
        }
        Ok(headers)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_slot_key_invalid_length_in_db_mod() {
        // `parse_slot_key` is already tested in `keys::tests`; this test
        // verifies the error type is accessible from this module.
        let result = parse_slot_key(&[0xAA, 0xBB]);
        assert!(matches!(
            result,
            Err(StorageError::InvalidKeyLength {
                got: 2,
                expected: 8
            })
        ));
    }

    #[test]
    fn create_if_missing_false_on_nonexistent_path_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent = dir.path().join("does_not_exist");

        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: nonexistent,
            create_if_missing: false,
        });

        assert!(
            matches!(result, Err(StorageError::RocksDb(_))),
            "expected RocksDb error, got {result:?}"
        );
    }

    /// Opening a database written with schema v1 (before the `payload-status` CF was added)
    /// must return `SchemaMismatch { found: 1, expected: 8 }` — v1 is below the
    /// migration baseline, so it stays on the resync path.
    #[test]
    fn schema_v1_returns_mismatch() {
        use rocksdb::{ColumnFamilyDescriptor, DB, Options};

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("chain_db_v1");

        // Simulate a v1 database: open without the payload-status CF and write v1 sentinel.
        let v1_cfs = [
            "default",
            "blocks",
            "block_root_to_slot",
            "slot_to_block_root",
            "states",
            "forkchoice",
            "metadata",
            "light-client-bootstrap",
            "light-client-update",
            "latest-finality-update",
            "latest-optimistic-update",
        ];
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let descriptors: Vec<ColumnFamilyDescriptor> = v1_cfs
                .iter()
                .map(|&n| ColumnFamilyDescriptor::new(n, Options::default()))
                .collect();
            let db = DB::open_cf_descriptors(&opts, &db_path, descriptors).expect("open v1 db");
            let meta_cf = db.cf_handle("metadata").expect("metadata cf");
            db.put_cf(meta_cf, b"schema_version", 1u32.to_le_bytes())
                .expect("write v1 sentinel");
        }

        // Now open with the current `RocksStore::open` which expects v7.
        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        });

        assert!(
            matches!(
                result,
                Err(StorageError::SchemaMismatch {
                    found: 1,
                    expected: 8
                })
            ),
            "expected SchemaMismatch{{found:1,expected:8}}, got {result:?}"
        );
    }

    /// Opening a database written with schema v2 (before the v3 CFs were added)
    /// must return `SchemaMismatch { found: 2, expected: 8 }` — v2 is below the
    /// migration baseline, so it stays on the resync path.
    #[test]
    fn schema_v2_returns_mismatch() {
        use rocksdb::{ColumnFamilyDescriptor, DB, Options};

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("chain_db_v2");

        // Simulate a v2 database: open with the 16 v2 CFs and write v2 sentinel.
        let v2_cfs = [
            "default",
            "blocks",
            "block_root_to_slot",
            "slot_to_block_root",
            "states",
            "forkchoice",
            "metadata",
            "light-client-bootstrap",
            "light-client-update",
            "latest-finality-update",
            "latest-optimistic-update",
            "payload-status",
            "capella-light-client-bootstrap",
            "capella-light-client-update",
            "capella-latest-finality-update",
            "capella-latest-optimistic-update",
        ];
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let descriptors: Vec<ColumnFamilyDescriptor> = v2_cfs
                .iter()
                .map(|&n| ColumnFamilyDescriptor::new(n, Options::default()))
                .collect();
            let db = DB::open_cf_descriptors(&opts, &db_path, descriptors).expect("open v2 db");
            let meta_cf = db.cf_handle("metadata").expect("metadata cf");
            db.put_cf(meta_cf, b"schema_version", 2u32.to_le_bytes())
                .expect("write v2 sentinel");
        }

        // Now open with the current `RocksStore::open` which expects v7.
        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        });

        assert!(
            matches!(
                result,
                Err(StorageError::SchemaMismatch {
                    found: 2,
                    expected: 8
                })
            ),
            "expected SchemaMismatch{{found:2,expected:8}}, got {result:?}"
        );
    }

    /// Opening a fresh v6 database must allow reading/writing the `payload-status` and
    /// `state-summary` CFs.
    #[test]
    fn fresh_db_payload_status_cf_queryable() {
        use pharos_types::phase0::primitives::Root;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open fresh v5 store");

        let root = Root::from([0x42u8; 32]);

        // Initially absent.
        let status =
            <RocksStore as Store<pharos_types::MainnetEthSpec>>::payload_status(&store, root)
                .expect("payload_status lookup");
        assert!(status.is_none(), "fresh db: expected no entry for root");

        // Write via a `BlockTransition`.
        let mut bt = crate::transition::BlockTransition::<pharos_types::MainnetEthSpec>::new();
        bt.payload_status = Some((root, PayloadStatus::Invalid));
        <RocksStore as Store<pharos_types::MainnetEthSpec>>::write_block_transition(&store, bt)
            .expect("write_block_transition");

        // Now it must be readable.
        let status =
            <RocksStore as Store<pharos_types::MainnetEthSpec>>::payload_status(&store, root)
                .expect("payload_status lookup after write");
        assert_eq!(
            status,
            Some(PayloadStatus::Invalid),
            "expected Invalid after write"
        );

        // And show up in the iterator.
        let all =
            <RocksStore as Store<pharos_types::MainnetEthSpec>>::payload_statuses_iter(&store)
                .expect("payload_statuses_iter");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], (root, PayloadStatus::Invalid));
    }

    /// Open a RocksDB at `path` with the full current CF set and stamp the given
    /// `schema_version` sentinel. Used to fabricate a DB at an arbitrary version
    /// for the migration-walk tests. v7 adds no CFs over v6, so the current
    /// `all_cfs()` set is layout-compatible with a v6 DB.
    fn stamp_db_version(path: &std::path::Path, version: u32) {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let descriptors: Vec<ColumnFamilyDescriptor> = all_cfs()
            .iter()
            .map(|&n| ColumnFamilyDescriptor::new(n, per_cf_opts(n)))
            .collect();
        let db = DB::open_cf_descriptors(&opts, path, descriptors).expect("open db to stamp");
        let meta_cf = db.cf_handle(CF_METADATA).expect("metadata cf");
        db.put_cf(meta_cf, b"schema_version", version.to_le_bytes())
            .expect("write schema_version sentinel");
    }

    /// Read back the stored `schema_version` sentinel from `store`.
    fn read_db_version(store: &RocksStore) -> u32 {
        let cf = store.cf_handle(CF_METADATA).expect("metadata cf");
        let bytes = store
            .db
            .get_cf(cf, b"schema_version")
            .expect("get schema_version")
            .expect("schema_version present");
        u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"))
    }

    /// A v6-stamped DB must migrate forward across the whole registry: `open`
    /// succeeds and the stored version is bumped to the current
    /// `SCHEMA_VERSION` (8, via v6→v7→v8).
    #[test]
    fn migration_walk_v6_to_v8() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("chain_db_v6");

        stamp_db_version(&db_path, 6);

        let store = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        })
        .expect("v6 db must migrate forward and open");

        assert_eq!(
            read_db_version(&store),
            8,
            "after migrating a v6 DB the stamped version must be 8"
        );
        assert_eq!(SCHEMA_VERSION, 8, "SCHEMA_VERSION must be 8");
    }

    /// A v7-stamped DB must migrate forward one step to v8 (the slasher CF is
    /// auto-created on open; the migration only bumps the version stamp).
    #[test]
    fn migration_walk_v7_to_v8() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("chain_db_v7");

        stamp_db_version(&db_path, 7);

        let store = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        })
        .expect("v7 db must migrate forward and open");

        assert_eq!(
            read_db_version(&store),
            8,
            "after migrating a v7 DB the stamped version must be 8"
        );
    }

    /// The migration registry must start at the baseline and be contiguous:
    /// `pairs[0].from == MIGRATION_BASELINE`, `pairs[i+1].from == pairs[i].to`,
    /// each step is `+1`, and the last `to` equals the current `SCHEMA_VERSION`.
    #[test]
    fn migration_registry_contiguous_from_baseline() {
        use crate::migrations::{MIGRATION_BASELINE, migration_pairs};

        let pairs = migration_pairs();
        assert!(!pairs.is_empty(), "migration registry must not be empty");
        assert_eq!(
            pairs[0].0, MIGRATION_BASELINE,
            "first migration must start at MIGRATION_BASELINE"
        );
        for w in pairs.windows(2) {
            assert_eq!(
                w[1].0, w[0].1,
                "migrations must be contiguous: from[i+1] == to[i]"
            );
        }
        for &(from, to) in &pairs {
            assert_eq!(to, from + 1, "each migration must bump by exactly one");
        }
        assert_eq!(
            pairs.last().expect("non-empty").1,
            SCHEMA_VERSION,
            "last migration must reach the current SCHEMA_VERSION"
        );
    }

    /// A v5-stamped DB is below the migration baseline (6) and must hard-error
    /// with `SchemaMismatch` (resync required), NOT migrate.
    #[test]
    fn pre_baseline_still_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("chain_db_v5");

        stamp_db_version(&db_path, 5);

        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        });

        assert!(
            matches!(
                result,
                Err(StorageError::SchemaMismatch {
                    found: 5,
                    expected: 8
                })
            ),
            "v5 is pre-baseline: expected SchemaMismatch{{found:5,expected:8}}, got {result:?}"
        );
    }

    /// A future-version DB (v999, above the current `SCHEMA_VERSION`) must
    /// hard-error: there is no down-migration.
    #[test]
    fn future_version_still_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("chain_db_v999");

        stamp_db_version(&db_path, 999);

        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        });

        assert!(
            matches!(
                result,
                Err(StorageError::SchemaMismatch {
                    found: 999,
                    expected: 8
                })
            ),
            "future version must hard-error: expected SchemaMismatch{{found:999,expected:8}}, got {result:?}"
        );
    }
}
