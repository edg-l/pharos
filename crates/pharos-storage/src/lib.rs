//! Storage abstraction for Pharos.
//!
//! `Store` trait + rocksdb-backed implementation for the main chain DB. The
//! trait is designed for the future hot/cold split (recent unfinalized vs
//! finalized state diffs).
//!
//! Slashing protection storage lives in `pharos-validator` (separate
//! `rusqlite` DB).
