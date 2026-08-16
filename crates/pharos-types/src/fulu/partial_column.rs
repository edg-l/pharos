//! Fulu partial-column containers.
//!
//! Per `specs/fulu/partial-columns/p2p-interface.md`.
//!
//! **Type definitions + SSZ derive ONLY; NO gossip wiring** (deferred per OQ2
//! in `docs/m13-fulu-plan.md` task 1.4).

use pharos_ssz::{Bitlist, Decode, Encode, SszList, SszVector, TreeHash};

use crate::deneb::blob::KZGCommitment;
use crate::fulu::data_column_sidecar::Cell;
use crate::phase0::operations::SignedBeaconBlockHeader;

// ── PartialDataColumnHeader ───────────────────────────────────────────────────

/// `PartialDataColumnHeader` per `specs/fulu/partial-columns/p2p-interface.md`.
///
/// The header common to all columns for a given block. Lets a peer identify
/// which blobs are included in a block, as well as validate cells and proofs.
///
/// Const parameters:
/// 1. `MAX_BLOB_COMMITMENTS_PER_BLOCK` — `presets/*/deneb.yaml` (4096).
/// 2. `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH` — `presets/*/fulu.yaml` (4).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct PartialDataColumnHeader<
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
> {
    /// `kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub kzg_commitments: SszList<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `signed_block_header: SignedBeaconBlockHeader`.
    pub signed_block_header: SignedBeaconBlockHeader,
    /// `kzg_commitments_inclusion_proof: Vector[Bytes32, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH]`.
    pub kzg_commitments_inclusion_proof:
        SszVector<pharos_utils::FixedBytes<32>, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>,
}

impl<const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64, const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64>
    Default
    for PartialDataColumnHeader<
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    >
{
    fn default() -> Self {
        Self {
            kzg_commitments: SszList::default(),
            signed_block_header: SignedBeaconBlockHeader::default(),
            kzg_commitments_inclusion_proof: SszVector::default(),
        }
    }
}

// ── PartialDataColumnSidecar ─────────────────────────────────────────────────

/// `PartialDataColumnSidecar` per `specs/fulu/partial-columns/p2p-interface.md`.
///
/// Similar to `DataColumnSidecar`, except only the cells and proofs identified
/// by the bitmap are present. The column index is inferred from the gossipsub
/// topic subnet.
///
/// Const parameter:
/// 1. `MAX_BLOB_COMMITMENTS_PER_BLOCK` — `presets/*/deneb.yaml` (4096).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct PartialDataColumnSidecar<
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
> {
    /// `cells_present_bitmap: Bitlist[MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub cells_present_bitmap: Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `partial_column: List[Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub partial_column: SszList<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `kzg_proofs: List[KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub kzg_proofs: SszList<crate::deneb::blob::KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `header: List[PartialDataColumnHeader, 1]` — optional, only sent on eager pushes.
    pub header: SszList<
        PartialDataColumnHeader<
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
        >,
        1,
    >,
}

impl<const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64, const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64>
    Default
    for PartialDataColumnSidecar<
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    >
{
    fn default() -> Self {
        Self {
            cells_present_bitmap: Bitlist::default(),
            partial_column: SszList::default(),
            kzg_proofs: SszList::default(),
            header: SszList::default(),
        }
    }
}

// ── PartialDataColumnPartsMetadata ────────────────────────────────────────────

/// `PartialDataColumnPartsMetadata` per `specs/fulu/partial-columns/p2p-interface.md`.
///
/// Peers communicate the cells available with a bitmap. A set bit (`1`) at
/// index `i` means that the peer has the cell at index `i`. Peers explicitly
/// request cells with a second request bitmap of the same length that is set
/// to `1` if the peer would like to receive or provide this cell.
///
/// Const parameter:
/// 1. `MAX_BLOB_COMMITMENTS_PER_BLOCK` — `presets/*/deneb.yaml` (4096).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct PartialDataColumnPartsMetadata<const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64> {
    /// `available: Bitlist[MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub available: Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `requests: Bitlist[MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub requests: Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

// ── Preset-specific aliases ───────────────────────────────────────────────────

/// Mainnet `PartialDataColumnHeader` (`MAX_BLOB_COMMITMENTS_PER_BLOCK=4096`,
/// `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH=4`).
pub type MainnetPartialDataColumnHeader = PartialDataColumnHeader<4096, 4>;
/// Minimal `PartialDataColumnHeader` (same preset values as mainnet).
pub type MinimalPartialDataColumnHeader = PartialDataColumnHeader<4096, 4>;
/// Mainnet `PartialDataColumnSidecar`.
pub type MainnetPartialDataColumnSidecar = PartialDataColumnSidecar<4096, 4>;
/// Minimal `PartialDataColumnSidecar`.
pub type MinimalPartialDataColumnSidecar = PartialDataColumnSidecar<4096, 4>;
/// Mainnet `PartialDataColumnPartsMetadata`.
pub type MainnetPartialDataColumnPartsMetadata = PartialDataColumnPartsMetadata<4096>;
/// Minimal `PartialDataColumnPartsMetadata`.
pub type MinimalPartialDataColumnPartsMetadata = PartialDataColumnPartsMetadata<4096>;
