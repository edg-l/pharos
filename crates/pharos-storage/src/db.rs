//! RocksDB-backed `Store<E>` implementation.
//!
//! Per `D-rocksdb`: single DB file with 7 column families, big-endian slot
//! keys, Lz4 compression on `blocks` and `states` CFs, schema-version
//! sentinel in the `metadata` CF.

use std::path::PathBuf;

use pharos_ssz::{Decode, Encode};
use pharos_types::EthSpec;
use pharos_types::phase0::primitives::{Root, Slot};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, Direction, IteratorMode, Options,
    WriteBatch,
};
use tracing::warn;

use crate::cf::{
    CF_BLOCK_ROOT_TO_SLOT, CF_BLOCKS, CF_FORKCHOICE, CF_LC_BOOTSTRAP, CF_LC_FINALITY_UPDATE,
    CF_LC_OPTIMISTIC_UPDATE, CF_LC_UPDATE, CF_METADATA, CF_SLOT_TO_BLOCK_ROOT, CF_STATES,
    LC_LATEST_KEY, all_cfs,
};
use crate::error::StorageError;
use crate::forkchoice::ForkChoiceSnapshot;
use crate::keys::{parse_slot_key, root_key, slot_key};
use crate::store::Store;
use crate::transition::BlockTransition;

/// Schema version written to `metadata[b"schema_version"]` at DB creation.
const SCHEMA_VERSION: u32 = 1;

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
                // Fresh DB — write schema version 1.
                store.db.put_cf(cf, b"schema_version", 1u32.to_le_bytes())?;
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
                let state = E::BeaconState::from_ssz_bytes(&bytes)?;
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
}
