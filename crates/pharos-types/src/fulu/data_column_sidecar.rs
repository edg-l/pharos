//! Fulu data-availability sidecar and cell types.
//!
//! Per `specs/fulu/das-core.md` (Containers: `DataColumnSidecar`) and
//! `specs/fulu/polynomial-commitments-sampling.md` (Preset: `BYTES_PER_CELL`).
//!
//! `Cell` is defined here (not in `pharos-kzg`) because it is an SSZ wire type
//! owned by `pharos-types`, matching the existing `KZGCommitment`/`KZGProof`/
//! `Blob` pattern in `pharos-types/src/deneb/blob.rs`. `pharos-types` does NOT
//! depend on `pharos-kzg`; the KZG crate wraps `&[u8; BYTES_PER_CELL]`.

use pharos_ssz::{Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::FixedBytes;

use crate::deneb::blob::{KZGCommitment, KZGProof};
use crate::phase0::operations::SignedBeaconBlockHeader;

// ── Cell ───────────────────────────────────────────────────────────────────────

/// `BYTES_PER_CELL = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT = 64 * 32 = 2048`.
///
/// Per `specs/fulu/polynomial-commitments-sampling.md`.
pub const BYTES_PER_CELL: u64 = 2048;

/// `Cell` — a fixed-length vector of 2048 bytes.
///
/// Spec type: `ByteVector[BYTES_PER_CELL]` per `specs/fulu/das-core.md`.
pub type Cell = SszVector<u8, BYTES_PER_CELL>;

// ── Index aliases ──────────────────────────────────────────────────────────────

/// `ColumnIndex = uint64` per `specs/fulu/das-core.md`.
pub type ColumnIndex = u64;
/// `RowIndex = uint64` per `specs/fulu/das-core.md`.
pub type RowIndex = u64;
/// `CustodyIndex = uint64` per `specs/fulu/das-core.md`.
pub type CustodyIndex = u64;

// ── DataColumnSidecar ─────────────────────────────────────────────────────────

/// `DataColumnSidecar` per `specs/fulu/das-core.md`.
///
/// `kzg_commitments_inclusion_proof` is a `Vector[Bytes32, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH]`
/// (= `Vector[Bytes32, 4]`; fixed-size, no length prefix).
///
/// Const parameters:
/// 1. `MAX_BLOB_COMMITMENTS_PER_BLOCK` — `presets/*/deneb.yaml` (4096).
/// 2. `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH` — `presets/*/fulu.yaml` (4).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct DataColumnSidecar<
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
> {
    /// `index: ColumnIndex`.
    pub index: ColumnIndex,
    /// `column: List[Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub column: SszList<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub kzg_commitments: SszList<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `kzg_proofs: List[KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK]`.
    pub kzg_proofs: SszList<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `signed_block_header: SignedBeaconBlockHeader`.
    pub signed_block_header: SignedBeaconBlockHeader,
    /// `kzg_commitments_inclusion_proof: Vector[Bytes32, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH]`.
    pub kzg_commitments_inclusion_proof:
        SszVector<FixedBytes<32>, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>,
}

impl<const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64, const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64>
    Default
    for DataColumnSidecar<MAX_BLOB_COMMITMENTS_PER_BLOCK, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>
{
    fn default() -> Self {
        Self {
            index: 0,
            column: SszList::default(),
            kzg_commitments: SszList::default(),
            kzg_proofs: SszList::default(),
            signed_block_header: SignedBeaconBlockHeader::default(),
            kzg_commitments_inclusion_proof: SszVector::default(),
        }
    }
}

// ── Borrowing accessors (*View) ──────────────────────────────────────────────

/// Read-only accessors for `DataColumnSidecar` fields.
pub trait DataColumnSidecarView {
    /// `index: ColumnIndex`.
    fn index(&self) -> ColumnIndex;
    /// Borrowing iterator over `column: List[Cell, ...]`.
    fn column_iter(&self) -> std::slice::Iter<'_, Cell>;
    /// `kzg_commitments` slice.
    fn kzg_commitments(&self) -> &[KZGCommitment];
    /// `kzg_proofs` slice.
    fn kzg_proofs(&self) -> &[KZGProof];
    /// `signed_block_header` reference.
    fn signed_block_header(&self) -> &SignedBeaconBlockHeader;
    /// Borrowing iterator over `kzg_commitments_inclusion_proof`.
    fn inclusion_proof_iter(&self) -> std::slice::Iter<'_, FixedBytes<32>>;
}

impl<const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64, const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64>
    DataColumnSidecarView
    for DataColumnSidecar<MAX_BLOB_COMMITMENTS_PER_BLOCK, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>
{
    fn index(&self) -> ColumnIndex {
        self.index
    }
    fn column_iter(&self) -> std::slice::Iter<'_, Cell> {
        self.column.as_slice().iter()
    }
    fn kzg_commitments(&self) -> &[KZGCommitment] {
        self.kzg_commitments.as_slice()
    }
    fn kzg_proofs(&self) -> &[KZGProof] {
        self.kzg_proofs.as_slice()
    }
    fn signed_block_header(&self) -> &SignedBeaconBlockHeader {
        &self.signed_block_header
    }
    fn inclusion_proof_iter(&self) -> std::slice::Iter<'_, FixedBytes<32>> {
        self.kzg_commitments_inclusion_proof.as_slice().iter()
    }
}

// ── Preset-specific aliases ───────────────────────────────────────────────────

/// Mainnet `DataColumnSidecar` (`MAX_BLOB_COMMITMENTS_PER_BLOCK=4096`,
/// `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH=4`).
pub type MainnetDataColumnSidecar = DataColumnSidecar<4096, 4>;
/// Minimal `DataColumnSidecar` (same preset values as mainnet).
pub type MinimalDataColumnSidecar = DataColumnSidecar<4096, 4>;
