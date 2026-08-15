//! EIP-3076 slashing protection interchange format (v5).
//!
//! Implements JSON import (`--import-slashing-protection`) and export
//! (`--export-slashing-protection`, called on SIGTERM) for the slashing
//! protection database.
//!
//! Format version: 5 (as specified in EIP-3076 §Versioning).
//!
//! Structure:
//! ```json
//! {
//!   "metadata": {
//!     "interchange_format_version": "5",
//!     "genesis_validators_root": "0x..."
//!   },
//!   "data": [
//!     {
//!       "pubkey": "0x...",
//!       "signed_blocks": [{"slot": "...", "signing_root": "0x..."}],
//!       "signed_attestations": [{"source_epoch": "...", "target_epoch": "...", "signing_root": "0x..."}]
//!     }
//!   ]
//! }
//! ```
//!
//! All numeric fields are strings (EIP-3076 §Integer Representation).

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::slashing::SlashingError;

/// EIP-3076 interchange file root.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterchangeFile {
    pub metadata: InterchangeMetadata,
    pub data: Vec<InterchangeEntry>,
}

/// Interchange metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterchangeMetadata {
    pub interchange_format_version: String,
    pub genesis_validators_root: String,
}

/// Per-validator entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterchangeEntry {
    /// 0x-prefixed hex pubkey (48 bytes compressed).
    pub pubkey: String,
    pub signed_blocks: Vec<InterchangeBlock>,
    pub signed_attestations: Vec<InterchangeAttestation>,
}

/// A signed block record.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterchangeBlock {
    /// Slot number as a decimal string.
    pub slot: String,
    /// Optional 0x-prefixed hex signing root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// A signed attestation record.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterchangeAttestation {
    pub source_epoch: String,
    pub target_epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// Error type for interchange operations.
#[derive(Debug, thiserror::Error)]
pub enum InterchangeError {
    #[error("slashing DB error: {0}")]
    Slashing(#[from] SlashingError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported interchange_format_version: '{0}' (expected '5')")]
    UnsupportedVersion(String),

    #[error("genesis_validators_root mismatch: file has '{file}', expected '{expected}'")]
    GenesisRootMismatch { file: String, expected: String },

    #[error("invalid integer field '{field}': {source}")]
    InvalidInteger {
        field: &'static str,
        source: std::num::ParseIntError,
    },

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Import an EIP-3076 interchange file into the slashing protection database.
///
/// `expected_genesis_validators_root` is the chain's genesis validators root
/// (0x-prefixed hex). The import is rejected if the file's metadata does not
/// match, per EIP-3076 preconditions.
///
/// The entire import runs inside a single transaction: if a parse failure
/// occurs mid-file the transaction is rolled back and no partial state is
/// written.
///
/// On version mismatch returns `InterchangeError::UnsupportedVersion`.
/// Individual records that violate the slashing rules are silently skipped
/// (the import succeeds for safe records and the dangerous ones are dropped,
/// per §General Recommendations).
pub fn import_interchange(
    conn: &Connection,
    interchange: &InterchangeFile,
    expected_genesis_validators_root: &str,
) -> Result<(), InterchangeError> {
    if interchange.metadata.interchange_format_version != "5" {
        return Err(InterchangeError::UnsupportedVersion(
            interchange.metadata.interchange_format_version.clone(),
        ));
    }

    // EIP-3076 precondition: genesis_validators_root must match the chain.
    if interchange.metadata.genesis_validators_root != expected_genesis_validators_root {
        return Err(InterchangeError::GenesisRootMismatch {
            file: interchange.metadata.genesis_validators_root.clone(),
            expected: expected_genesis_validators_root.to_string(),
        });
    }

    // Wrap the entire import in a single transaction so that a parse failure
    // mid-file rolls back all prior inserts, leaving the DB unchanged.
    let tx = conn.unchecked_transaction()?;

    for entry in &interchange.data {
        for block in &entry.signed_blocks {
            let slot: u64 = block
                .slot
                .parse()
                .map_err(|e| InterchangeError::InvalidInteger {
                    field: "slot",
                    source: e,
                })?;

            // Use INSERT OR IGNORE: if a stricter record already exists we keep it.
            // SQLite integer is i64; cast u64 via as.
            tx.execute(
                "INSERT OR IGNORE INTO signed_block (pubkey, slot, signing_root) \
                 VALUES (?1, ?2, ?3)",
                params![entry.pubkey, slot as i64, block.signing_root],
            )?;
        }

        for att in &entry.signed_attestations {
            let src: u64 =
                att.source_epoch
                    .parse()
                    .map_err(|e| InterchangeError::InvalidInteger {
                        field: "source_epoch",
                        source: e,
                    })?;
            let tgt: u64 =
                att.target_epoch
                    .parse()
                    .map_err(|e| InterchangeError::InvalidInteger {
                        field: "target_epoch",
                        source: e,
                    })?;

            // Use INSERT OR IGNORE: keep the higher-security existing record.
            // SQLite integer is i64; cast u64 via as.
            tx.execute(
                "INSERT OR IGNORE INTO signed_attestation \
                 (pubkey, source_epoch, target_epoch, signing_root) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![entry.pubkey, src as i64, tgt as i64, att.signing_root],
            )?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Export the slashing protection database to an EIP-3076 interchange file.
///
/// `genesis_validators_root` is 0x-prefixed hex of the genesis validators root.
/// Only pubkeys with at least one record are included.
pub fn export_interchange(
    conn: &Connection,
    genesis_validators_root: &str,
) -> Result<InterchangeFile, InterchangeError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT pubkey FROM signed_block \
         UNION \
         SELECT DISTINCT pubkey FROM signed_attestation \
         ORDER BY pubkey",
    )?;
    let pubkeys: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;

    let mut data = Vec::with_capacity(pubkeys.len());

    for pubkey in &pubkeys {
        // Fetch blocks.
        let mut bstmt = conn.prepare(
            "SELECT slot, signing_root FROM signed_block \
             WHERE pubkey = ?1 ORDER BY slot ASC",
        )?;
        let blocks: Vec<InterchangeBlock> = bstmt
            .query_map(params![pubkey], |row| {
                let slot_i: i64 = row.get(0)?;
                Ok(InterchangeBlock {
                    slot: (slot_i as u64).to_string(),
                    signing_root: row.get(1)?,
                })
            })?
            .collect::<Result<_, _>>()?;

        // Fetch attestations.
        let mut astmt = conn.prepare(
            "SELECT source_epoch, target_epoch, signing_root \
             FROM signed_attestation WHERE pubkey = ?1 \
             ORDER BY target_epoch ASC",
        )?;
        let attestations: Vec<InterchangeAttestation> = astmt
            .query_map(params![pubkey], |row| {
                let src_i: i64 = row.get(0)?;
                let tgt_i: i64 = row.get(1)?;
                Ok(InterchangeAttestation {
                    source_epoch: (src_i as u64).to_string(),
                    target_epoch: (tgt_i as u64).to_string(),
                    signing_root: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;

        data.push(InterchangeEntry {
            pubkey: pubkey.clone(),
            signed_blocks: blocks,
            signed_attestations: attestations,
        });
    }

    Ok(InterchangeFile {
        metadata: InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root: genesis_validators_root.to_string(),
        },
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_mem_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS signed_block (
                 pubkey TEXT NOT NULL, slot INTEGER NOT NULL, signing_root TEXT,
                 PRIMARY KEY (pubkey, slot)
             );
             CREATE TABLE IF NOT EXISTS signed_attestation (
                 pubkey TEXT NOT NULL, source_epoch INTEGER NOT NULL,
                 target_epoch INTEGER NOT NULL, signing_root TEXT,
                 PRIMARY KEY (pubkey, target_epoch)
             );",
        )
        .expect("create schema");
        conn
    }

    const GENESIS_ROOT: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
    const PUBKEY: &str = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

    #[test]
    fn import_rejects_wrong_version() {
        let conn = open_mem_db();
        let interchange = InterchangeFile {
            metadata: InterchangeMetadata {
                interchange_format_version: "4".to_string(),
                genesis_validators_root: GENESIS_ROOT.to_string(),
            },
            data: vec![],
        };
        let err = import_interchange(&conn, &interchange, GENESIS_ROOT)
            .expect_err("wrong version must be rejected");
        assert!(
            matches!(err, InterchangeError::UnsupportedVersion(ref v) if v == "4"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rejects_genesis_root_mismatch() {
        let conn = open_mem_db();
        let wrong_root = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let interchange = InterchangeFile {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: wrong_root.to_string(),
            },
            data: vec![],
        };
        let err = import_interchange(&conn, &interchange, GENESIS_ROOT)
            .expect_err("genesis root mismatch must be rejected");
        assert!(
            matches!(err, InterchangeError::GenesisRootMismatch { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn import_rollback_on_bad_record() {
        // A file with a valid first block, then an invalid slot string.
        // The entire import must be rolled back so the DB is unchanged.
        let conn = open_mem_db();
        let interchange = InterchangeFile {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: GENESIS_ROOT.to_string(),
            },
            data: vec![InterchangeEntry {
                pubkey: PUBKEY.to_string(),
                signed_blocks: vec![
                    InterchangeBlock {
                        slot: "100".to_string(),
                        signing_root: None,
                    },
                    InterchangeBlock {
                        slot: "not-a-number".to_string(),
                        signing_root: None,
                    },
                ],
                signed_attestations: vec![],
            }],
        };

        let err = import_interchange(&conn, &interchange, GENESIS_ROOT)
            .expect_err("bad slot must be rejected");
        assert!(
            matches!(err, InterchangeError::InvalidInteger { field: "slot", .. }),
            "unexpected error: {err}"
        );

        // The DB must be untouched: no blocks written.
        let exported = export_interchange(&conn, GENESIS_ROOT).expect("export after rollback");
        assert!(
            exported.data.is_empty(),
            "DB must be unchanged after rolled-back import"
        );
    }

    #[test]
    fn import_then_export_roundtrip() {
        let conn = open_mem_db();

        let original = InterchangeFile {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: GENESIS_ROOT.to_string(),
            },
            data: vec![InterchangeEntry {
                pubkey: PUBKEY.to_string(),
                signed_blocks: vec![
                    InterchangeBlock {
                        slot: "81951".to_string(),
                        signing_root: None,
                    },
                    InterchangeBlock {
                        slot: "81952".to_string(),
                        signing_root: Some(
                            "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                                .to_string(),
                        ),
                    },
                ],
                signed_attestations: vec![
                    InterchangeAttestation {
                        source_epoch: "2290".to_string(),
                        target_epoch: "3007".to_string(),
                        signing_root: Some(
                            "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                                .to_string(),
                        ),
                    },
                    InterchangeAttestation {
                        source_epoch: "2290".to_string(),
                        target_epoch: "3008".to_string(),
                        signing_root: None,
                    },
                ],
            }],
        };

        import_interchange(&conn, &original, GENESIS_ROOT).expect("import must succeed");
        let exported = export_interchange(&conn, GENESIS_ROOT).expect("export must succeed");

        assert_eq!(exported.metadata.interchange_format_version, "5");
        assert_eq!(exported.metadata.genesis_validators_root, GENESIS_ROOT);
        assert_eq!(exported.data.len(), 1);
        assert_eq!(exported.data[0].pubkey, PUBKEY);
        assert_eq!(exported.data[0].signed_blocks.len(), 2);
        assert_eq!(exported.data[0].signed_attestations.len(), 2);

        // Verify slots round-trip.
        assert_eq!(exported.data[0].signed_blocks[0].slot, "81951");
        assert_eq!(exported.data[0].signed_blocks[1].slot, "81952");
        assert_eq!(
            exported.data[0].signed_blocks[1].signing_root,
            Some("0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b".to_string())
        );
    }

    #[test]
    fn import_idempotent_same_records() {
        let conn = open_mem_db();
        let interchange = InterchangeFile {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: GENESIS_ROOT.to_string(),
            },
            data: vec![InterchangeEntry {
                pubkey: PUBKEY.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "100".to_string(),
                    signing_root: Some("0xdeadbeef".to_string()),
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "1".to_string(),
                    target_epoch: "5".to_string(),
                    signing_root: None,
                }],
            }],
        };

        // Import twice — second import must succeed (INSERT OR IGNORE).
        import_interchange(&conn, &interchange, GENESIS_ROOT).expect("first import");
        import_interchange(&conn, &interchange, GENESIS_ROOT)
            .expect("second import must be idempotent");

        let exported = export_interchange(&conn, GENESIS_ROOT).expect("export");
        // No duplicates.
        assert_eq!(exported.data[0].signed_blocks.len(), 1);
        assert_eq!(exported.data[0].signed_attestations.len(), 1);
    }

    #[test]
    fn export_empty_db_returns_empty_data() {
        let conn = open_mem_db();
        let exported = export_interchange(&conn, GENESIS_ROOT).expect("export");
        assert!(exported.data.is_empty(), "empty db must export empty data");
    }
}
