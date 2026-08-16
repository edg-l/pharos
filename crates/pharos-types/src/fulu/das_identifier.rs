//! Fulu `DataColumnsByRootIdentifier` container.
//!
//! Per `specs/fulu/p2p-interface.md` (Containers: `DataColumnsByRootIdentifier`).

use pharos_ssz::{Decode, Encode, SszList, TreeHash};

use crate::fulu::data_column_sidecar::ColumnIndex;
use crate::phase0::primitives::Root;

/// `DataColumnsByRootIdentifier` per `specs/fulu/p2p-interface.md`.
///
/// Const parameter:
/// 1. `NUMBER_OF_COLUMNS` — `presets/*/fulu.yaml` (128).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct DataColumnsByRootIdentifier<const NUMBER_OF_COLUMNS: u64> {
    /// `block_root: Root`.
    pub block_root: Root,
    /// `columns: List[ColumnIndex, NUMBER_OF_COLUMNS]`.
    pub columns: SszList<ColumnIndex, NUMBER_OF_COLUMNS>,
}

impl<const NUMBER_OF_COLUMNS: u64> Default for DataColumnsByRootIdentifier<NUMBER_OF_COLUMNS> {
    fn default() -> Self {
        Self {
            block_root: Root::default(),
            columns: SszList::default(),
        }
    }
}

/// Mainnet `DataColumnsByRootIdentifier` (`NUMBER_OF_COLUMNS=128`).
pub type MainnetDataColumnsByRootIdentifier = DataColumnsByRootIdentifier<128>;
/// Minimal `DataColumnsByRootIdentifier` (`NUMBER_OF_COLUMNS=128`).
pub type MinimalDataColumnsByRootIdentifier = DataColumnsByRootIdentifier<128>;
