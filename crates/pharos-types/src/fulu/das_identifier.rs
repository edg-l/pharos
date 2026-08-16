//! Fulu `DataColumnsByRootIdentifier` container.
//!
//! Per `specs/fulu/p2p-interface.md` (Containers: `DataColumnsByRootIdentifier`).

use pharos_ssz::{Decode, Encode, SszError, SszList, TreeHash};

use crate::fulu::data_column_sidecar::ColumnIndex;
use crate::phase0::primitives::{Root, Slot};

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

// ── DataColumnSidecarsByRangeRequest ──────────────────────────────────────────

/// `DataColumnSidecarsByRange` request per `specs/fulu/p2p-interface.md`
/// (`DataColumnSidecarsByRange v1`).
///
/// SSZ-encoded as a container (the spec: "The request MUST be encoded as an
/// SSZ-container"). The `columns` list is variable-length so the derived SSZ
/// emits a 4-byte offset for it — this is correct container encoding (NOT the
/// bare-list trap, which applies only to single-list-field requests).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct DataColumnSidecarsByRangeRequest<const NUMBER_OF_COLUMNS: u64> {
    /// `start_slot: Slot` — first slot to return sidecars for.
    pub start_slot: Slot,
    /// `count: uint64` — number of slots to return sidecars for.
    pub count: u64,
    /// `columns: List[ColumnIndex, NUMBER_OF_COLUMNS]`.
    pub columns: SszList<ColumnIndex, NUMBER_OF_COLUMNS>,
}

impl<const NUMBER_OF_COLUMNS: u64> Default for DataColumnSidecarsByRangeRequest<NUMBER_OF_COLUMNS> {
    fn default() -> Self {
        Self {
            start_slot: Slot::default(),
            count: 0,
            columns: SszList::default(),
        }
    }
}

/// Mainnet `DataColumnSidecarsByRangeRequest` (`NUMBER_OF_COLUMNS=128`).
pub type MainnetDataColumnSidecarsByRangeRequest = DataColumnSidecarsByRangeRequest<128>;
/// Minimal `DataColumnSidecarsByRangeRequest` (`NUMBER_OF_COLUMNS=128`).
pub type MinimalDataColumnSidecarsByRangeRequest = DataColumnSidecarsByRangeRequest<128>;

// ── DataColumnSidecarsByRootRequest ───────────────────────────────────────────

/// `DataColumnSidecarsByRoot` request per `specs/fulu/p2p-interface.md`
/// (`DataColumnSidecarsByRoot v1`).
///
/// The request is `List[DataColumnsByRootIdentifier, MAX_REQUEST_BLOCKS_DENEB]`
/// — a CONTAINER list, standard offset-prefixed SSZ. This is NOT the
/// `D-blocksbyroot-bare-list` trap (that trap is for a `List[Root, N]` request
/// where the request IS the list). Here the element is a variable-size
/// container, so the list serializes with the usual offset table; the
/// single-list-field transparency rule still applies (the request IS the list),
/// but a list of variable-size elements is itself offset-prefixed, so a wire
/// observer sees the 4-byte offset prefix. The wire-byte fixture test
/// `data_columns_by_root_request_is_container_list_no_offset` asserts this.
#[derive(TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct DataColumnSidecarsByRootRequest<
    const MAX_REQUEST_BLOCKS_DENEB: u64,
    const NUMBER_OF_COLUMNS: u64,
> {
    /// The list of `(block_root, columns)` identifiers requested.
    pub ids: SszList<DataColumnsByRootIdentifier<NUMBER_OF_COLUMNS>, MAX_REQUEST_BLOCKS_DENEB>,
}

impl<const MAX_REQUEST_BLOCKS_DENEB: u64, const NUMBER_OF_COLUMNS: u64> Default
    for DataColumnSidecarsByRootRequest<MAX_REQUEST_BLOCKS_DENEB, NUMBER_OF_COLUMNS>
{
    fn default() -> Self {
        Self {
            ids: SszList::default(),
        }
    }
}

impl<const MAX_REQUEST_BLOCKS_DENEB: u64, const NUMBER_OF_COLUMNS: u64> Encode
    for DataColumnSidecarsByRootRequest<MAX_REQUEST_BLOCKS_DENEB, NUMBER_OF_COLUMNS>
{
    // Transparent over `ids`: the request IS the list (single-field rule). The
    // list of variable-size containers serializes offset-prefixed per SSZ rules.
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        <SszList<DataColumnsByRootIdentifier<NUMBER_OF_COLUMNS>, MAX_REQUEST_BLOCKS_DENEB> as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.ids.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.ids.ssz_append(buf);
    }
}

impl<const MAX_REQUEST_BLOCKS_DENEB: u64, const NUMBER_OF_COLUMNS: u64> Decode
    for DataColumnSidecarsByRootRequest<MAX_REQUEST_BLOCKS_DENEB, NUMBER_OF_COLUMNS>
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        <SszList<DataColumnsByRootIdentifier<NUMBER_OF_COLUMNS>, MAX_REQUEST_BLOCKS_DENEB> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        Ok(Self {
            ids: SszList::from_ssz_bytes(bytes)?,
        })
    }
}

/// Mainnet `DataColumnSidecarsByRootRequest`
/// (`MAX_REQUEST_BLOCKS_DENEB=128`, `NUMBER_OF_COLUMNS=128`).
pub type MainnetDataColumnSidecarsByRootRequest = DataColumnSidecarsByRootRequest<128, 128>;
/// Minimal `DataColumnSidecarsByRootRequest`
/// (`MAX_REQUEST_BLOCKS_DENEB=128`, `NUMBER_OF_COLUMNS=128`).
pub type MinimalDataColumnSidecarsByRootRequest = DataColumnSidecarsByRootRequest<128, 128>;
