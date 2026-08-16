//! Fulu `MatrixEntry` container.
//!
//! Per `specs/fulu/das-core.md` (Containers: `MatrixEntry`, lines 89-94).
//!
//! `MatrixEntry` holds 4 scalar fields (one per cell). The `compute_matrix`
//! helper flattens blobs into one `MatrixEntry` per cell; it is NOT an
//! aggregated list.

use pharos_ssz::{Decode, Encode, TreeHash};

use crate::deneb::blob::KZGProof;
use crate::fulu::data_column_sidecar::{Cell, ColumnIndex, RowIndex};

/// `MatrixEntry` per `specs/fulu/das-core.md:89-94`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct MatrixEntry {
    /// `cell: Cell`.
    pub cell: Cell,
    /// `kzg_proof: KZGProof`.
    pub kzg_proof: KZGProof,
    /// `column_index: ColumnIndex`.
    pub column_index: ColumnIndex,
    /// `row_index: RowIndex`.
    pub row_index: RowIndex,
}
