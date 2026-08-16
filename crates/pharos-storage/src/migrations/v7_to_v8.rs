//! Schema v7 → v8: add the `slasher-proposers` CF for the Phase B slasher.
//!
//! v8 introduces the `slasher-proposers` column family (M11 Phase 9, opt-in
//! `--slasher` chain-history replay). The CF itself is created by RocksDB's
//! `create_missing_column_families(true)` when the database is opened with the
//! full v8 CF set (`cf::all_cfs`), so this migration moves no data: the
//! proposer-header index is rebuilt from scratch on each `--slasher` replay, so
//! an empty CF immediately after migration is correct. The migration is a
//! single atomic `WriteBatch` carrying only the `schema_version` bump to `8`.

use rocksdb::{DB, WriteBatch};

use crate::error::StorageError;
use crate::migrations::{Migration, commit_step};

/// v7 → v8 migration: adds the `slasher-proposers` CF (auto-created on open).
#[derive(Default)]
pub struct V7ToV8;

impl Migration for V7ToV8 {
    const FROM: u32 = 7;
    const TO: u32 = 8;

    fn migrate(&self, db: &DB) -> Result<(), StorageError> {
        // No data move: the new CF is auto-created by
        // `create_missing_column_families` on open, and the proposer index is
        // rebuilt by the replay scanner. The empty batch carries only the
        // version bump appended by `commit_step`, written atomically.
        let batch = WriteBatch::default();
        commit_step(db, batch, Self::TO)
    }
}
