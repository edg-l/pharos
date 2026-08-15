//! EIP-3076 slashing protection database.
//!
//! Implements `SlashingProtection` trait backed by a `rusqlite` database at
//! `<vc-data-dir>/slashing_protection.sqlite`.
//!
//! Schema:
//! - `signed_block(pubkey TEXT, slot INTEGER, signing_root TEXT, PRIMARY KEY(pubkey, slot))`
//! - `signed_attestation(pubkey TEXT, source_epoch INTEGER, target_epoch INTEGER,
//!     signing_root TEXT, PRIMARY KEY(pubkey, target_epoch))`
//!
//! Safety invariant: the sqlite row is **committed (fsync-durably) BEFORE** the
//! caller's signing path runs, per `D-commit-before-sign`. If the commit fails the
//! error is returned and the caller must NOT sign.
//!
//! SQLite stores integers as i64; u64 slot/epoch values are cast via `as i64` on
//! write and `as u64` on read. Slots/epochs fit in 63 bits for all practical
//! purposes (Ethereum slot numbers will not reach 2^63 in the current network).
//!
//! Rules per EIP-3076 §Conditions:
//!
//! **Block proposals:**
//! - REJECT if a block at the same `slot` exists for this pubkey AND the stored
//!   `signing_root` differs (double proposal).
//! - REJECT if `slot` < the minimum slot stored for this pubkey (below low watermark).
//! - ACCEPT (and record) otherwise. Repeat signing with the same `signing_root` is ACCEPTED.
//!
//! **Attestations:**
//! - REJECT if target_epoch < minimum target_epoch stored (below low watermark).
//! - REJECT if source_epoch < minimum source_epoch stored (surround source).
//! - REJECT surround vote: `new.source < existing.source AND new.target > existing.target`.
//! - REJECT surrounded vote: `new.source > existing.source AND new.target < existing.target`.
//! - REJECT double vote: same target_epoch but different signing_root.
//! - ACCEPT (and record) otherwise. Repeat signing with the same signing_root is ACCEPTED.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

/// Rejection reason returned when signing is disallowed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SlashingError {
    #[error("double block proposal: slot {slot} already signed with a different root")]
    DoubleBlockProposal { slot: u64 },

    #[error("block slot {slot} is below low watermark {min_slot}")]
    BlockBelowLowWatermark { slot: u64, min_slot: u64 },

    #[error(
        "double attestation vote: target epoch {target_epoch} already signed with a different root"
    )]
    DoubleAttestation { target_epoch: u64 },

    #[error("attestation target epoch {target_epoch} is at or below low watermark {min_target}")]
    AttestationTargetBelowLowWatermark { target_epoch: u64, min_target: u64 },

    #[error("attestation source epoch {source_epoch} is below low watermark {min_source}")]
    AttestationSourceBelowLowWatermark { source_epoch: u64, min_source: u64 },

    #[error("surround vote: new ({new_src},{new_tgt}) surrounds existing ({ex_src},{ex_tgt})")]
    SurroundVote {
        new_src: u64,
        new_tgt: u64,
        ex_src: u64,
        ex_tgt: u64,
    },

    #[error("surrounded vote: existing ({ex_src},{ex_tgt}) surrounds new ({new_src},{new_tgt})")]
    SurroundedVote {
        new_src: u64,
        new_tgt: u64,
        ex_src: u64,
        ex_tgt: u64,
    },

    #[error("sqlite error: {0}")]
    Sqlite(String),
}

impl From<rusqlite::Error> for SlashingError {
    fn from(e: rusqlite::Error) -> Self {
        SlashingError::Sqlite(e.to_string())
    }
}

/// Trait for slashing protection implementations.
pub trait SlashingProtection: Send + Sync {
    /// Check and record a block proposal.
    ///
    /// Commits to durable storage BEFORE returning `Ok(())`.
    /// Returns `Err(SlashingError)` if the proposal would be slashable.
    fn check_and_record_block_proposal(
        &self,
        pubkey_hex: &str,
        slot: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError>;

    /// Check and record an attestation.
    ///
    /// Commits to durable storage BEFORE returning `Ok(())`.
    /// Returns `Err(SlashingError)` if the attestation would be slashable.
    fn check_and_record_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError>;
}

/// SQLite-backed slashing protection database.
pub struct SqliteSlashingProtection {
    conn: std::sync::Mutex<Connection>,
}

impl SqliteSlashingProtection {
    /// Open (or create) the slashing protection database at `path`.
    ///
    /// Runs schema migrations synchronously on open. Thread-safe via `Mutex<Connection>`.
    pub fn open(path: &Path) -> Result<Self, SlashingError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Enable WAL mode for better durability + concurrent reads.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS signed_block (
                pubkey       TEXT    NOT NULL,
                slot         INTEGER NOT NULL,
                signing_root TEXT,
                PRIMARY KEY (pubkey, slot)
            );
            CREATE TABLE IF NOT EXISTS signed_attestation (
                pubkey        TEXT    NOT NULL,
                source_epoch  INTEGER NOT NULL,
                target_epoch  INTEGER NOT NULL,
                signing_root  TEXT,
                PRIMARY KEY (pubkey, target_epoch)
            );",
        )?;

        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }
}

impl SlashingProtection for SqliteSlashingProtection {
    fn check_and_record_block_proposal(
        &self,
        pubkey_hex: &str,
        slot: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SlashingError::Sqlite("mutex poisoned".into()))?;
        let slot_i = slot as i64;

        // BEGIN IMMEDIATE: all checks and the INSERT run in one atomic transaction.
        // With PRAGMA synchronous=FULL + WAL, commit() is the durable fsync point
        // per the D-commit-before-sign invariant.
        let tx = conn.unchecked_transaction()?;

        // Check the low watermark: reject if slot < min stored slot.
        let min_slot: Option<i64> = tx
            .query_row(
                "SELECT MIN(slot) FROM signed_block WHERE pubkey = ?1",
                params![pubkey_hex],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(min_i) = min_slot {
            let min = min_i as u64;
            if slot < min {
                return Err(SlashingError::BlockBelowLowWatermark {
                    slot,
                    min_slot: min,
                });
            }
        }

        // Check for an existing record at this slot.
        let existing_root: Option<Option<String>> = tx
            .query_row(
                "SELECT signing_root FROM signed_block WHERE pubkey = ?1 AND slot = ?2",
                params![pubkey_hex, slot_i],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(stored_root_opt) = existing_root {
            // A record exists at this slot.
            match (stored_root_opt.as_deref(), signing_root) {
                // Same signing_root (or both null): repeat signing → ACCEPT without re-inserting.
                (Some(stored), Some(new)) if stored == new => return Ok(()),
                (None, None) => return Ok(()),
                // Different roots or one is null: double proposal → REJECT.
                _ => {
                    return Err(SlashingError::DoubleBlockProposal { slot });
                }
            }
        }

        // Record the proposal and commit durably before returning Ok.
        tx.execute(
            "INSERT INTO signed_block (pubkey, slot, signing_root) VALUES (?1, ?2, ?3)",
            params![pubkey_hex, slot_i, signing_root],
        )?;
        tx.commit()?;

        Ok(())
    }

    fn check_and_record_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Option<&str>,
    ) -> Result<(), SlashingError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SlashingError::Sqlite("mutex poisoned".into()))?;
        let src_i = source_epoch as i64;
        let tgt_i = target_epoch as i64;

        // BEGIN IMMEDIATE: all checks and the INSERT run in one atomic transaction.
        let tx = conn.unchecked_transaction()?;

        // Check low watermarks.
        let row: Option<(Option<i64>, Option<i64>)> = tx
            .query_row(
                "SELECT MIN(source_epoch), MIN(target_epoch) FROM signed_attestation WHERE pubkey = ?1",
                params![pubkey_hex],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (min_src_opt, min_tgt_opt) = row.unwrap_or((None, None));
        let min_src = min_src_opt.map(|v| v as u64);
        let min_tgt = min_tgt_opt.map(|v| v as u64);

        if let Some(min) = min_src {
            if source_epoch < min {
                return Err(SlashingError::AttestationSourceBelowLowWatermark {
                    source_epoch,
                    min_source: min,
                });
            }
        }
        if let Some(min) = min_tgt {
            if target_epoch <= min {
                // Check for exact-same-target repeat signing.
                let existing: Option<(i64, Option<String>)> = tx
                    .query_row(
                        "SELECT target_epoch, signing_root FROM signed_attestation \
                         WHERE pubkey = ?1 AND target_epoch = ?2",
                        params![pubkey_hex, tgt_i],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;

                if let Some((_, stored_root_opt)) = existing {
                    match (stored_root_opt.as_deref(), signing_root) {
                        (Some(stored), Some(new)) if stored == new => return Ok(()),
                        (None, None) => return Ok(()),
                        _ => {
                            return Err(SlashingError::DoubleAttestation { target_epoch });
                        }
                    }
                }

                return Err(SlashingError::AttestationTargetBelowLowWatermark {
                    target_epoch,
                    min_target: min,
                });
            }
        }

        // Check for double vote at this target_epoch.
        let existing_at_target: Option<(i64, Option<String>)> = tx
            .query_row(
                "SELECT source_epoch, signing_root FROM signed_attestation \
                 WHERE pubkey = ?1 AND target_epoch = ?2",
                params![pubkey_hex, tgt_i],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((_ex_src_i, stored_root_opt)) = existing_at_target {
            // Same target_epoch exists.
            match (stored_root_opt.as_deref(), signing_root) {
                (Some(stored), Some(new)) if stored == new => return Ok(()),
                (None, None) => return Ok(()),
                _ => {
                    return Err(SlashingError::DoubleAttestation { target_epoch });
                }
            }
        }

        // Check surround / surrounded votes against all existing attestations.
        // Surround: new.source < existing.source AND new.target > existing.target
        // Surrounded: new.source > existing.source AND new.target < existing.target
        let surround: Option<(i64, i64)> = tx
            .query_row(
                "SELECT source_epoch, target_epoch FROM signed_attestation \
                 WHERE pubkey = ?1 \
                   AND ((?2 < source_epoch AND ?3 > target_epoch) \
                     OR (?2 > source_epoch AND ?3 < target_epoch)) \
                 LIMIT 1",
                params![pubkey_hex, src_i, tgt_i],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((ex_src_i, ex_tgt_i)) = surround {
            let ex_src = ex_src_i as u64;
            let ex_tgt = ex_tgt_i as u64;
            // Determine which direction.
            if source_epoch < ex_src && target_epoch > ex_tgt {
                return Err(SlashingError::SurroundVote {
                    new_src: source_epoch,
                    new_tgt: target_epoch,
                    ex_src,
                    ex_tgt,
                });
            } else {
                return Err(SlashingError::SurroundedVote {
                    new_src: source_epoch,
                    new_tgt: target_epoch,
                    ex_src,
                    ex_tgt,
                });
            }
        }

        // Record the attestation and commit durably before returning Ok.
        tx.execute(
            "INSERT INTO signed_attestation \
             (pubkey, source_epoch, target_epoch, signing_root) \
             VALUES (?1, ?2, ?3, ?4)",
            params![pubkey_hex, src_i, tgt_i, signing_root],
        )?;
        tx.commit()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn open_tmp_db() -> (SqliteSlashingProtection, NamedTempFile) {
        let tmp = NamedTempFile::new().expect("create tmp file");
        let db = SqliteSlashingProtection::open(tmp.path()).expect("open db");
        (db, tmp)
    }

    // ── Block proposal tests ──────────────────────────────────────────────────

    #[test]
    fn block_first_proposal_accepted() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_block_proposal("0xaaa", 100, Some("0xroot1"))
            .expect("first proposal must be accepted");
    }

    #[test]
    fn block_double_proposal_rejected() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_block_proposal("0xaaa", 100, Some("0xroot1"))
            .expect("first proposal");
        let err = db
            .check_and_record_block_proposal("0xaaa", 100, Some("0xroot2"))
            .expect_err("double proposal must be rejected");
        assert!(
            matches!(err, SlashingError::DoubleBlockProposal { slot: 100 }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn block_repeat_signing_accepted() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_block_proposal("0xaaa", 100, Some("0xroot1"))
            .expect("first proposal");
        // Same slot + same root = repeat signing = ACCEPT.
        db.check_and_record_block_proposal("0xaaa", 100, Some("0xroot1"))
            .expect("repeat signing must be accepted");
    }

    #[test]
    fn block_below_low_watermark_rejected() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_block_proposal("0xaaa", 100, Some("0xroot1"))
            .expect("proposal at slot 100");
        let err = db
            .check_and_record_block_proposal("0xaaa", 50, Some("0xroot2"))
            .expect_err("slot < min must be rejected");
        assert!(
            matches!(
                err,
                SlashingError::BlockBelowLowWatermark {
                    slot: 50,
                    min_slot: 100,
                }
            ),
            "unexpected error: {err}"
        );
    }

    // ── Attestation tests ─────────────────────────────────────────────────────

    #[test]
    fn attestation_first_accepted() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_attestation("0xbbb", 1, 10, Some("0xatroot1"))
            .expect("first attestation must be accepted");
    }

    #[test]
    fn attestation_double_vote_rejected() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_attestation("0xbbb", 1, 10, Some("0xatroot1"))
            .expect("first attestation");
        let err = db
            .check_and_record_attestation("0xbbb", 1, 10, Some("0xatroot2"))
            .expect_err("double vote must be rejected");
        assert!(
            matches!(err, SlashingError::DoubleAttestation { target_epoch: 10 }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn attestation_repeat_signing_accepted() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_attestation("0xbbb", 1, 10, Some("0xatroot1"))
            .expect("first attestation");
        db.check_and_record_attestation("0xbbb", 1, 10, Some("0xatroot1"))
            .expect("repeat signing must be accepted");
    }

    #[test]
    fn attestation_surround_vote_rejected() {
        let (db, _tmp) = open_tmp_db();
        // To avoid the low-watermark check firing before the surround check, we need
        // new.source > min_source. We establish min_source=1 with a first attestation
        // at (1, 5), then add an inner attestation at (5, 15). A surround attempt at
        // (3, 20) has new.source=3 > min_source=1 and new.target=20 > all existing
        // targets, so it passes the watermark check but fails the surround check
        // (3 < 5 AND 20 > 15).
        db.check_and_record_attestation("0xbbb", 1, 5, Some("0xroot_low"))
            .expect("low baseline attestation");
        db.check_and_record_attestation("0xbbb", 5, 15, Some("0xroot_inner"))
            .expect("inner attestation");
        let err = db
            .check_and_record_attestation("0xbbb", 3, 20, Some("0xroot_surround"))
            .expect_err("surround vote must be rejected");
        assert!(
            matches!(err, SlashingError::SurroundVote { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn attestation_surrounded_vote_rejected() {
        let (db, _tmp) = open_tmp_db();
        // Establish min_target=5 with a first attestation. Then insert an outer span
        // at (1, 20). An inner attempt at (5, 15) has target=15 > min_target=5, so it
        // passes the watermark check but fails the surrounded check
        // (existing: source=1 < 5 AND target=20 > 15).
        db.check_and_record_attestation("0xbbb", 1, 5, Some("0xroot_low"))
            .expect("low baseline attestation");
        db.check_and_record_attestation("0xbbb", 1, 20, Some("0xroot_outer"))
            .expect("outer attestation");
        let err = db
            .check_and_record_attestation("0xbbb", 5, 15, Some("0xroot_inner"))
            .expect_err("surrounded vote must be rejected");
        assert!(
            matches!(err, SlashingError::SurroundedVote { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn attestation_target_below_watermark_rejected() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_attestation("0xbbb", 1, 10, Some("0xroot1"))
            .expect("first attestation");
        let err = db
            .check_and_record_attestation("0xbbb", 1, 9, Some("0xroot2"))
            .expect_err("target <= min_target must be rejected");
        assert!(
            matches!(
                err,
                SlashingError::AttestationTargetBelowLowWatermark {
                    target_epoch: 9,
                    min_target: 10
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn different_pubkeys_are_independent() {
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_block_proposal("0xaaa", 100, Some("0xroot1"))
            .expect("aaa proposal");
        // A different pubkey at the same slot must be independent.
        db.check_and_record_block_proposal("0xbbb", 100, Some("0xroot1"))
            .expect("bbb proposal at same slot must succeed");
    }

    #[test]
    fn block_proposal_is_committed_transactionally() {
        // Verify that after a successful check_and_record_block_proposal the row is
        // durably visible in a subsequent independent read (same connection under the lock).
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_block_proposal("0xccc", 200, Some("0xroot_tx"))
            .expect("proposal must be recorded");

        // The same proposal with a different root must now be rejected — proving the
        // first row was committed (not rolled back).
        let err = db
            .check_and_record_block_proposal("0xccc", 200, Some("0xroot_other"))
            .expect_err("double proposal after transactional commit must be rejected");
        assert!(
            matches!(err, SlashingError::DoubleBlockProposal { slot: 200 }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn attestation_is_committed_transactionally() {
        // Verify that after a successful check_and_record_attestation the row is
        // durably visible so that a subsequent double-vote attempt is rejected.
        let (db, _tmp) = open_tmp_db();
        db.check_and_record_attestation("0xddd", 1, 10, Some("0xatroot_tx"))
            .expect("attestation must be recorded");

        let err = db
            .check_and_record_attestation("0xddd", 1, 10, Some("0xatroot_other"))
            .expect_err("double vote after transactional commit must be rejected");
        assert!(
            matches!(err, SlashingError::DoubleAttestation { target_epoch: 10 }),
            "unexpected error: {err}"
        );
    }
}
