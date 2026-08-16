//! Seed migration: schema v6 → v7 (identity / version-bump only).
//!
//! v7 introduces no new column families and moves no data; it exists to
//! exercise the forward-migration walk machinery with a REAL registry entry
//! (not a stub) and to establish the framework on the DB-open critical path.
//! The migration is a single atomic `WriteBatch` carrying only the
//! `schema_version` bump to `7`.

use rocksdb::{DB, WriteBatch};

use crate::error::StorageError;
use crate::migrations::{Migration, commit_step};

/// v6 → v7 identity migration.
#[derive(Default)]
pub struct V6ToV7;

impl Migration for V6ToV7 {
    const FROM: u32 = 6;
    const TO: u32 = 7;

    fn migrate(&self, db: &DB) -> Result<(), StorageError> {
        // Identity migration: no data move. The empty batch carries only the
        // version bump appended by `commit_step`, written atomically.
        let batch = WriteBatch::default();
        commit_step(db, batch, Self::TO)
    }
}
