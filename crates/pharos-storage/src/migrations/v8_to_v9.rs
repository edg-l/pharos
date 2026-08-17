//! Schema v8 → v9: add the `data-column-sidecars` CF for EIP-7594 PeerDAS.
//!
//! v9 introduces the `data-column-sidecars` column family (
//! data-column sidecar storage keyed `block_root || index_be`). The CF itself
//! is created by RocksDB's `create_missing_column_families(true)` when the
//! database is opened with the full v9 CF set (`cf::all_cfs`), so this migration
//! moves no data: data-column sidecars are re-fetched over the p2p network
//! within `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` epochs, so an empty CF
//! immediately after migration is correct. The migration is a single atomic
//! `WriteBatch` carrying only the `schema_version` bump to `9`.

use rocksdb::{DB, WriteBatch};

use crate::error::StorageError;
use crate::migrations::{Migration, commit_step};

/// v8 → v9 migration: adds the `data-column-sidecars` CF (auto-created on open).
#[derive(Default)]
pub struct V8ToV9;

impl Migration for V8ToV9 {
    const FROM: u32 = 8;
    const TO: u32 = 9;

    fn migrate(&self, db: &DB) -> Result<(), StorageError> {
        // No data move: the new CF is auto-created by
        // `create_missing_column_families` on open, and sidecars are re-fetched
        // over p2p. The empty batch carries only the version bump appended by
        // `commit_step`, written atomically.
        let batch = WriteBatch::default();
        commit_step(db, batch, Self::TO)
    }
}
