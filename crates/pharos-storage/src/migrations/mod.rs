//! Forward-only schema migration framework for the RocksDB chain store.
//!
//! On `RocksStore::open`, when the on-disk `schema_version` sentinel is BELOW
//! the compiled [`crate::db::SCHEMA_VERSION`], the open path walks the
//! [`MIGRATIONS`] registry from the found version up to the current version,
//! applying each migration in order. Every migration writes its data changes
//! AND the bumped `schema_version` sentinel in a SINGLE atomic `WriteBatch`,
//! so a crash mid-walk always leaves a consistent stamped version: either the
//! step fully applied (and the version advanced) or it did not (and the version
//! is unchanged). Re-opening after a crash resumes the walk from wherever the
//! stamp landed; each migration is therefore idempotent at the step granularity.
//!
//! ## Baseline boundary
//!
//! [`MIGRATION_BASELINE`] is the OLDEST version the forward walk can start from.
//! Versions BELOW the baseline predate this framework and have no migration
//! path: opening such a database returns
//! [`StorageError::SchemaMismatch`](crate::error::StorageError::SchemaMismatch)
//! and the operator must resync from a checkpoint. Versions at or above the
//! baseline (and below the current `SCHEMA_VERSION`) are migrated forward in
//! place. The baseline is `6` because the pre-v6 schemas (v1..=v5) were all
//! resync-only at the time they were superseded (no live post-startup
//! persistence to preserve, per the per-version notes in `db.rs`).

use rocksdb::{DB, WriteBatch};

use crate::cf::CF_METADATA;
use crate::error::StorageError;

mod v6_to_v7;
mod v7_to_v8;

use v6_to_v7::V6ToV7;
use v7_to_v8::V7ToV8;

/// Oldest on-disk schema version the forward migration walk can start from.
///
/// Versions strictly below this value have no migration path and are
/// resync-only (`SchemaMismatch`). See the module docs for the rationale.
pub const MIGRATION_BASELINE: u32 = 6;

/// A single forward-only schema migration from version [`FROM`](Self::FROM) to
/// version [`TO`](Self::TO).
///
/// Implementations MUST apply ALL their changes (including the new
/// `schema_version` stamp) atomically. The framework provides
/// [`commit_step`] to do this in one `WriteBatch`; a migration's
/// [`migrate`](Self::migrate) body builds the batch and hands it to
/// `commit_step`, which appends the version bump and writes atomically.
pub trait Migration: Sync {
    /// The schema version this migration upgrades FROM.
    const FROM: u32;
    /// The schema version this migration upgrades TO (must be `FROM + 1`).
    const TO: u32;

    /// Apply the migration against `db`. Must commit atomically (data changes
    /// plus the `schema_version` bump to `TO`) via [`commit_step`].
    fn migrate(&self, db: &DB) -> Result<(), StorageError>;
}

/// Append the `schema_version = to` stamp to `batch` and commit it atomically.
///
/// A migration body collects all of its data mutations into `batch`, then calls
/// this to seal the step: the version bump rides the same `WriteBatch` as the
/// data, so the step is all-or-nothing.
fn commit_step(db: &DB, mut batch: WriteBatch, to: u32) -> Result<(), StorageError> {
    let cf = db
        .cf_handle(CF_METADATA)
        .ok_or(StorageError::ColumnFamilyNotFound(CF_METADATA))?;
    batch.put_cf(cf, b"schema_version", to.to_le_bytes());
    db.write(batch)?;
    Ok(())
}

/// Type-erased migration step: a `(from, to)` pair and a runner closure.
///
/// `MIGRATIONS` is a contiguous, ascending list of these; the open path walks
/// it and runs every step whose `from` is at or above the found version.
struct Step {
    from: u32,
    to: u32,
    run: fn(&DB) -> Result<(), StorageError>,
}

impl Step {
    const fn of<M: Migration + Default>() -> Self {
        Self {
            from: M::FROM,
            to: M::TO,
            run: |db| M::default().migrate(db),
        }
    }
}

/// Ordered, contiguous registry of forward migrations.
///
/// The first entry's `from` MUST equal [`MIGRATION_BASELINE`], and each entry's
/// `from` MUST equal the previous entry's `to` (contiguity). Both invariants are
/// asserted by [`migration_registry_contiguous_from_baseline`] in `db.rs`.
static MIGRATIONS: &[Step] = &[Step::of::<V6ToV7>(), Step::of::<V7ToV8>()];

/// Returns the `(from, to)` version pairs of the registered migrations, in
/// order. Used by the contiguity/baseline assertion test in `db.rs`.
pub fn migration_pairs() -> Vec<(u32, u32)> {
    MIGRATIONS.iter().map(|s| (s.from, s.to)).collect()
}

/// Walk the migration registry from `found` up to `target`, applying each step
/// atomically and bumping the stored `schema_version` after each.
///
/// Precondition (enforced by the caller in `db.rs::open`):
/// `MIGRATION_BASELINE <= found < target`. Steps whose `from` is below `found`
/// are skipped (already applied in a prior open); steps from `found` upward run
/// in order. After the walk the stamped version equals `target`.
pub fn run_migrations(db: &DB, found: u32, target: u32) -> Result<(), StorageError> {
    let mut current = found;
    for step in MIGRATIONS {
        if step.from < current {
            continue;
        }
        if step.from != current {
            return Err(StorageError::CorruptedData(format!(
                "migration registry gap: at version {current} but next step starts at {}",
                step.from
            )));
        }
        if step.to > target {
            break;
        }
        (step.run)(db)?;
        current = step.to;
    }

    if current != target {
        return Err(StorageError::CorruptedData(format!(
            "migration walk ended at version {current}, expected {target}"
        )));
    }
    Ok(())
}
