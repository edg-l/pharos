//! RocksDB-backed `Store<E>` implementation.
//!
//! Per `D-rocksdb`: single DB file with 7 column families, big-endian slot
//! keys, Lz4 compression on `blocks` and `states` CFs, schema-version
//! sentinel in the `metadata` CF.

use std::path::PathBuf;

use pharos_ssz::{Decode, Encode};
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::{BeaconStateView, EthSpec, PayloadStatus};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, Direction, IteratorMode, Options,
    WriteBatch,
};
use tracing::warn;

use crate::cf::{
    CF_BLOCK_ROOT_TO_SLOT, CF_BLOCKS, CF_FORKCHOICE, CF_LC_BOOTSTRAP, CF_LC_BOOTSTRAP_CAPELLA,
    CF_LC_FINALITY_UPDATE, CF_LC_FINALITY_UPDATE_CAPELLA, CF_LC_OPTIMISTIC_UPDATE,
    CF_LC_OPTIMISTIC_UPDATE_CAPELLA, CF_LC_UPDATE, CF_LC_UPDATE_CAPELLA, CF_METADATA,
    CF_PAYLOAD_STATUS, CF_SLOT_TO_BLOCK_ROOT, CF_STATE_SUMMARY, CF_STATES, LC_LATEST_KEY, all_cfs,
};
use crate::error::StorageError;
use crate::forkchoice::ForkChoiceSnapshot;
use crate::keys::{parse_slot_key, root_key, slot_key};
use crate::state_summary::StateSummary;
use crate::store::Store;
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
const SCHEMA_VERSION: u32 = 3;

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
    /// Open (or create) the RocksDB database at `cfg.path` with all seven
    /// column families registered.
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
                if found != SCHEMA_VERSION {
                    return Err(StorageError::SchemaMismatch {
                        found,
                        expected: SCHEMA_VERSION,
                    });
                }
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
            .put_cf(cf, period.to_le_bytes(), update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_update(
        &self,
        period: u64,
    ) -> Result<Option<E::AltairLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE)?;
        match self.db.get_cf(cf, period.to_le_bytes())? {
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
            match self.db.get_cf(cf, period.to_le_bytes())? {
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
            .put_cf(cf, period.to_le_bytes(), update.as_ssz_bytes())?;
        Ok(())
    }

    fn get_light_client_update_capella(
        &self,
        period: u64,
    ) -> Result<Option<E::CapellaLightClientUpdate>, StorageError> {
        let cf = self.cf_handle(CF_LC_UPDATE_CAPELLA)?;
        match self.db.get_cf(cf, period.to_le_bytes())? {
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
    /// must return `SchemaMismatch { found: 1, expected: 3 }`.
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

        // Now open with the current `RocksStore::open` which expects v3.
        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        });

        assert!(
            matches!(
                result,
                Err(StorageError::SchemaMismatch {
                    found: 1,
                    expected: 3
                })
            ),
            "expected SchemaMismatch{{found:1,expected:3}}, got {result:?}"
        );
    }

    /// Opening a database written with schema v2 (before the v3 CFs were added)
    /// must return `SchemaMismatch { found: 2, expected: 3 }`.
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

        // Now open with the current `RocksStore::open` which expects v3.
        let result = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: db_path,
            create_if_missing: false,
        });

        assert!(
            matches!(
                result,
                Err(StorageError::SchemaMismatch {
                    found: 2,
                    expected: 3
                })
            ),
            "expected SchemaMismatch{{found:2,expected:3}}, got {result:?}"
        );
    }

    /// Opening a fresh v3 database must allow reading/writing the `payload-status` and
    /// `state-summary` CFs.
    #[test]
    fn fresh_db_payload_status_cf_queryable() {
        use pharos_types::phase0::primitives::Root;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = RocksStore::open::<pharos_types::MainnetEthSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open fresh v2 store");

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
}
