//! Storage error type.
//!
//! Follows the `D-storage-error-strategy` ADR: one `StorageError` enum with
//! `#[from]` from upstream error types, mirroring M1 `D2`.

/// Errors returned by all `pharos-storage` operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A RocksDB operation failed.
    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    /// An SSZ decode operation failed.
    #[error("ssz decode error: {0}")]
    SszDecode(#[from] pharos_ssz::SszError),

    /// The on-disk schema version does not match the expected version.
    #[error("schema mismatch: found={found} expected={expected}")]
    SchemaMismatch { found: u32, expected: u32 },

    /// A requested column family is not open.
    #[error("column family not found: {0}")]
    ColumnFamilyNotFound(&'static str),

    /// A key was not found (used for mandatory singleton rows).
    #[error("key not found")]
    KeyNotFound,

    /// A key slice has the wrong byte length.
    #[error("invalid key length: got {got} expected {expected}")]
    InvalidKeyLength { got: usize, expected: usize },

    /// An I/O error (e.g. reading the genesis state file).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
