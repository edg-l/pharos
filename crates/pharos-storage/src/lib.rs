//! Storage abstraction for Pharos.
//!
//! `Store` trait + rocksdb-backed implementation for the main chain DB. The
//! trait is designed for the future hot/cold split (recent unfinalized vs
//! finalized state diffs).
//!
//! Slashing protection storage lives in `pharos-validator` (separate
//! `rusqlite` DB).

pub mod cf;
pub mod db;
pub mod error;
pub mod forkchoice;
pub mod keys;
pub mod state_summary;
pub mod store;
pub mod transition;

pub use db::{RocksStore, RocksStoreConfig};
pub use error::StorageError;
pub use forkchoice::ForkChoiceSnapshot;
pub use state_summary::StateSummary;
pub use store::Store;
pub use transition::BlockTransition;
