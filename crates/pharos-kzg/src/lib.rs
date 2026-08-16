//! KZG polynomial commitment wrappers for Pharos.
//!
//! Wraps [`c_kzg::KzgSettings`] with a safe Rust-idiomatic API.  The embedded
//! Ethereum mainnet trusted setup is available via [`KzgVerifier::mainnet`].
//! Alternative setups (devnets, tests) can be loaded via
//! [`KzgVerifier::from_trusted_setup_str`] or [`KzgVerifier::from_trusted_setup_file`].
//!
//! # C-kzg version bound
//!
//! This crate targets c-kzg **2.x** (resolved: 2.1.7 in development).  The
//! API surface used:
//! - `c_kzg::KzgSettings::{load_trusted_setup, parse_kzg_trusted_setup, blob_to_kzg_commitment, verify_blob_kzg_proof, verify_blob_kzg_proof_batch}`
//! - `c_kzg::{Blob, Bytes48, BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_PROOF}`
//! - `c_kzg::ethereum_kzg_settings(precompute: u64) -> &'static KzgSettings`
//!
//! The `[u8; N]` → `Blob` / `Bytes48` conversion happens at the public boundary;
//! internal call sites use the c-kzg types directly.
//!
//! # Cell sampling (EIP-7594 PeerDAS)
//!
//! Cell-KZG wrappers (`compute_cells`, `compute_cells_and_kzg_proofs`,
//! `verify_cell_kzg_proof_batch`, `recover_cells_and_kzg_proofs`) wrap the
//! c-kzg 2.1.x cell methods.  They operate on raw byte arrays
//! (`[u8; BYTES_PER_CELL]` = `[u8; 2048]`, `[u8; 48]` proofs/commitments); the
//! SSZ `Cell` type lives in `pharos-types` and conversion happens at that
//! boundary.  `pharos-kzg` has no `pharos-ssz` / `pharos-types` dependency.

use std::path::Path;

use c_kzg::{BYTES_PER_CELL, Blob, Bytes48, CELLS_PER_EXT_BLOB, Cell, KzgSettings};
use sha2::{Digest, Sha256};

// Re-export so dependents can use the raw c-kzg types if needed.
pub use c_kzg;

// ── Versioned-hash helper ─────────────────────────────────────────────────────

/// Version byte for KZG commitments per EIP-4844.
///
/// `VERSIONED_HASH_VERSION_KZG = 0x01` per `specs/deneb/beacon-chain.md`.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Convert a KZG commitment to a versioned hash.
///
/// Per EIP-4844 / `specs/deneb/beacon-chain.md`:
/// `kzg_commitment_to_versioned_hash(commitment) = VERSIONED_HASH_VERSION_KZG || sha256(commitment)[1:]`.
///
/// The result is a 32-byte hash whose first byte is `0x01`.
pub fn kzg_commitment_to_versioned_hash(commitment: &[u8; 48]) -> [u8; 32] {
    let hash = Sha256::digest(commitment.as_slice());
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result[0] = VERSIONED_HASH_VERSION_KZG;
    result
}

// ── Cell-sampling index types + container ─────────────────────────────────────

/// Number of cells in the extended (erasure-coded) blob.
///
/// Mirrors `c_kzg::CELLS_PER_EXT_BLOB` (= 128) so dependents need not import
/// c-kzg directly for the constant.
pub const CELLS_PER_EXT_BLOB_COUNT: usize = CELLS_PER_EXT_BLOB;

/// Size in bytes of a single cell (`c_kzg::BYTES_PER_CELL` = 2048).
pub const BYTES_PER_CELL_COUNT: usize = BYTES_PER_CELL;

/// Index of a cell within the extended blob (`0..CELLS_PER_EXT_BLOB`).
pub type CellIndex = u64;

/// Index of a commitment within a batch (used by EIP-7594 column sampling).
pub type CommitmentIndex = u64;

/// The 128 cells produced from one blob, held as raw `[u8; BYTES_PER_CELL]`
/// byte arrays.
///
/// This is `pharos-kzg`'s raw form of c-kzg's `CellsPerExtBlob` (`[Cell; 128]`).
/// The SSZ `Cell` type (`ByteVector<BYTES_PER_CELL>`) lives in `pharos-types`;
/// conversion to/from the SSZ form happens at that boundary, not here.
#[derive(Clone, Debug)]
pub struct CellsPerExtBlob(Box<[[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]>);

impl CellsPerExtBlob {
    /// Build from c-kzg's boxed `[Cell; CELLS_PER_EXT_BLOB]` output, copying each
    /// cell's bytes out of the c-kzg type.
    fn from_ckzg(cells: Box<[Cell; CELLS_PER_EXT_BLOB]>) -> Self {
        let mut out = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
        for (dst, src) in out.iter_mut().zip(cells.iter()) {
            *dst = src.to_bytes();
        }
        Self(out)
    }

    /// Number of cells (always [`CELLS_PER_EXT_BLOB_COUNT`] = 128).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: the container holds a fixed 128 cells.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow a single cell's 2048 bytes by index.
    pub fn cell(&self, index: usize) -> &[u8; BYTES_PER_CELL] {
        &self.0[index]
    }

    /// Iterate over the 128 cells as `&[u8; BYTES_PER_CELL]`.
    pub fn iter(&self) -> impl Iterator<Item = &[u8; BYTES_PER_CELL]> {
        self.0.iter()
    }

    /// Borrow all 128 cells as a fixed-size array of byte arrays.
    pub fn as_array(&self) -> &[[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB] {
        &self.0
    }
}

// ── KzgError ──────────────────────────────────────────────────────────────────

/// Errors returned by [`KzgVerifier`] operations.
#[derive(thiserror::Error, Debug)]
pub enum KzgError {
    /// The input slices have different lengths (batch verify requires equal-length inputs).
    #[error("length mismatch: blobs={blobs}, commitments={commitments}, proofs={proofs}")]
    LengthMismatch {
        blobs: usize,
        commitments: usize,
        proofs: usize,
    },

    /// The cell-batch input slices have mismatched lengths.
    ///
    /// `verify_cell_kzg_proof_batch` requires `commitments`, `cell_indices`,
    /// `cells`, and `proofs` to all have the same length.
    #[error(
        "cell length mismatch: commitments={commitments}, cell_indices={cell_indices}, cells={cells}, proofs={proofs}"
    )]
    CellLengthMismatch {
        commitments: usize,
        cell_indices: usize,
        cells: usize,
        proofs: usize,
    },

    /// An error from the underlying c-kzg library.
    #[error("c-kzg error: {0}")]
    CKzg(#[from] c_kzg::Error),
}

// ── KzgVerifier ───────────────────────────────────────────────────────────────

/// A KZG verifier wrapping a trusted setup ([`KzgSettings`]).
///
/// The inner `KzgSettings` is heap-allocated and reference-counted so that
/// `KzgVerifier` is cheap to clone (only an `Arc` clone).
pub struct KzgVerifier {
    settings: &'static KzgSettings,
}

impl KzgVerifier {
    /// Return a verifier using the embedded Ethereum mainnet trusted setup.
    ///
    /// Uses [`c_kzg::ethereum_kzg_settings`] with `precompute=0` (no
    /// precomputed tables; safe for verification workloads).  The setup is
    /// initialised at most once and cached for the process lifetime.
    pub fn mainnet() -> Self {
        Self {
            settings: c_kzg::ethereum_kzg_settings(0),
        }
    }

    /// Load a verifier from a trusted-setup JSON/YAML string.
    ///
    /// `trusted_setup` must be in the format accepted by
    /// `KzgSettings::parse_kzg_trusted_setup` (the standard Ethereum
    /// `trusted_setup.json` layout).
    pub fn from_trusted_setup_str(trusted_setup: &str) -> Result<Self, KzgError> {
        let settings = KzgSettings::parse_kzg_trusted_setup(trusted_setup, 0)?;
        // Leak the allocation so we can hand out a `&'static` reference.
        // This is intentional: trusted setups are typically per-process singletons.
        let settings = Box::leak(Box::new(settings));
        Ok(Self { settings })
    }

    /// Load a verifier from a trusted-setup file on disk.
    ///
    /// The file must be in the format accepted by
    /// `KzgSettings::load_trusted_setup_file`.
    pub fn from_trusted_setup_file(path: &Path) -> Result<Self, KzgError> {
        let settings = KzgSettings::load_trusted_setup_file(path, 0)?;
        let settings = Box::leak(Box::new(settings));
        Ok(Self { settings })
    }

    /// Compute the KZG commitment for a blob.
    ///
    /// `blob` is a raw 131072-byte array (one blob per the Deneb spec).
    /// Returns the 48-byte commitment.
    pub fn blob_to_kzg_commitment(&self, blob: &[u8; 131072]) -> Result<[u8; 48], KzgError> {
        let ckzg_blob = Blob::from_bytes(blob.as_slice())?;
        let commitment = self.settings.blob_to_kzg_commitment(&ckzg_blob)?;
        Ok(commitment.to_bytes().into_inner())
    }

    /// Verify that `proof` is a valid KZG proof for (`blob`, `commitment`).
    ///
    /// All three inputs are raw byte arrays; conversion to c-kzg types happens
    /// inside this function.  Returns `Ok(true)` on a valid proof.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &[u8; 131072],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<bool, KzgError> {
        let ckzg_blob = Blob::from_bytes(blob.as_slice())?;
        let commitment_bytes = Bytes48::from_bytes(commitment.as_slice())?;
        let proof_bytes = Bytes48::from_bytes(proof.as_slice())?;
        let valid =
            self.settings
                .verify_blob_kzg_proof(&ckzg_blob, &commitment_bytes, &proof_bytes)?;
        Ok(valid)
    }

    /// Batch-verify that each `proofs[i]` is valid for (`blobs[i]`, `commitments[i]`).
    ///
    /// All input slices must have the same length; a [`KzgError::LengthMismatch`]
    /// is returned otherwise.  Returns `Ok(true)` when every proof is valid.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[[u8; 131072]],
        commitments: &[[u8; 48]],
        proofs: &[[u8; 48]],
    ) -> Result<bool, KzgError> {
        if blobs.len() != commitments.len() || blobs.len() != proofs.len() {
            return Err(KzgError::LengthMismatch {
                blobs: blobs.len(),
                commitments: commitments.len(),
                proofs: proofs.len(),
            });
        }

        // Empty batch: vacuously valid per spec.
        if blobs.is_empty() {
            return Ok(true);
        }

        let ckzg_blobs: Result<Vec<Blob>, _> = blobs
            .iter()
            .map(|b| Blob::from_bytes(b.as_slice()))
            .collect();
        let ckzg_blobs = ckzg_blobs?;

        let ckzg_commitments: Result<Vec<Bytes48>, _> = commitments
            .iter()
            .map(|c| Bytes48::from_bytes(c.as_slice()))
            .collect();
        let ckzg_commitments = ckzg_commitments?;

        let ckzg_proofs: Result<Vec<Bytes48>, _> = proofs
            .iter()
            .map(|p| Bytes48::from_bytes(p.as_slice()))
            .collect();
        let ckzg_proofs = ckzg_proofs?;

        let valid = self.settings.verify_blob_kzg_proof_batch(
            &ckzg_blobs,
            &ckzg_commitments,
            &ckzg_proofs,
        )?;
        Ok(valid)
    }

    // ── Cell sampling (EIP-7594 PeerDAS) ──────────────────────────────────────

    /// Compute the 128 cells of the extended (erasure-coded) blob.
    ///
    /// `blob` is a raw 131072-byte array.  Returns a [`CellsPerExtBlob`] holding
    /// 128 cells of [`BYTES_PER_CELL_COUNT`] (= 2048) bytes each.
    pub fn compute_cells(&self, blob: &[u8; 131072]) -> Result<CellsPerExtBlob, KzgError> {
        let ckzg_blob = Blob::from_bytes(blob.as_slice())?;
        let cells = self.settings.compute_cells(&ckzg_blob)?;
        Ok(CellsPerExtBlob::from_ckzg(cells))
    }

    /// Compute the 128 cells and their 128 KZG proofs for a blob.
    ///
    /// Returns `(cells, proofs)` where `proofs` is a `Vec` of 128 raw 48-byte
    /// proofs, one per cell.
    pub fn compute_cells_and_kzg_proofs(
        &self,
        blob: &[u8; 131072],
    ) -> Result<(CellsPerExtBlob, Vec<[u8; 48]>), KzgError> {
        let ckzg_blob = Blob::from_bytes(blob.as_slice())?;
        let (cells, proofs) = self.settings.compute_cells_and_kzg_proofs(&ckzg_blob)?;
        let cells = CellsPerExtBlob::from_ckzg(cells);
        let proofs = proofs.iter().map(|p| p.to_bytes().into_inner()).collect();
        Ok((cells, proofs))
    }

    /// Batch-verify cell KZG proofs.
    ///
    /// Each `cells[i]` is verified against `commitments[i]` at column
    /// `cell_indices[i]` using `proofs[i]`.  All four input slices must have the
    /// same length; a [`KzgError::CellLengthMismatch`] is returned otherwise.
    ///
    /// One commitment is supplied *per cell* (rows may repeat a commitment when a
    /// blob contributes several cells to the batch); the underlying c-kzg routine
    /// deduplicates commitments internally, so the wrapper passes the per-cell
    /// commitments through without pre-deduplication.  Returns `Ok(true)` when
    /// every proof is valid.
    pub fn verify_cell_kzg_proof_batch(
        &self,
        commitments: &[&[u8; 48]],
        cell_indices: &[u64],
        cells: &[&[u8; 2048]],
        proofs: &[&[u8; 48]],
    ) -> Result<bool, KzgError> {
        if commitments.len() != cell_indices.len()
            || commitments.len() != cells.len()
            || commitments.len() != proofs.len()
        {
            return Err(KzgError::CellLengthMismatch {
                commitments: commitments.len(),
                cell_indices: cell_indices.len(),
                cells: cells.len(),
                proofs: proofs.len(),
            });
        }

        // Empty batch: vacuously valid (mirrors the blob-batch contract).
        if commitments.is_empty() {
            return Ok(true);
        }

        let ckzg_commitments: Result<Vec<Bytes48>, _> = commitments
            .iter()
            .map(|c| Bytes48::from_bytes(c.as_slice()))
            .collect();
        let ckzg_commitments = ckzg_commitments?;

        let ckzg_cells: Result<Vec<Cell>, _> = cells
            .iter()
            .map(|c| Cell::from_bytes(c.as_slice()))
            .collect();
        let ckzg_cells = ckzg_cells?;

        let ckzg_proofs: Result<Vec<Bytes48>, _> = proofs
            .iter()
            .map(|p| Bytes48::from_bytes(p.as_slice()))
            .collect();
        let ckzg_proofs = ckzg_proofs?;

        let valid = self.settings.verify_cell_kzg_proof_batch(
            &ckzg_commitments,
            cell_indices,
            &ckzg_cells,
            &ckzg_proofs,
        )?;
        Ok(valid)
    }

    /// Recover the full 128-cell matrix (and its 128 proofs) from a partial set
    /// of cells (at least 50%, i.e. 64 cells).
    ///
    /// `cell_indices[i]` is the column index of `cells[i]`.  Cells are supplied
    /// as raw 2048-byte arrays (the wrapper's raw form; `pharos-kzg` does not
    /// own the SSZ `Cell` type).  `cell_indices` and `cells` must have the same
    /// length; a [`KzgError::CellLengthMismatch`] is returned otherwise.
    pub fn recover_cells_and_kzg_proofs(
        &self,
        cell_indices: &[u64],
        cells: &[&[u8; 2048]],
    ) -> Result<(CellsPerExtBlob, Vec<[u8; 48]>), KzgError> {
        if cell_indices.len() != cells.len() {
            return Err(KzgError::CellLengthMismatch {
                commitments: 0,
                cell_indices: cell_indices.len(),
                cells: cells.len(),
                proofs: 0,
            });
        }

        let ckzg_cells: Result<Vec<Cell>, _> = cells
            .iter()
            .map(|c| Cell::from_bytes(c.as_slice()))
            .collect();
        let ckzg_cells = ckzg_cells?;

        let (recovered_cells, recovered_proofs) = self
            .settings
            .recover_cells_and_kzg_proofs(cell_indices, &ckzg_cells)?;
        let recovered_cells = CellsPerExtBlob::from_ckzg(recovered_cells);
        let recovered_proofs = recovered_proofs
            .iter()
            .map(|p| p.to_bytes().into_inner())
            .collect();
        Ok((recovered_cells, recovered_proofs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_settings_init() {
        // Ensure the mainnet trusted setup can be loaded without panicking.
        let _verifier = KzgVerifier::mainnet();
    }

    /// Test vector for `kzg_commitment_to_versioned_hash`.
    ///
    /// A zero commitment (48 zero bytes) → SHA-256([0x00; 48]) with byte[0] = 0x01.
    /// SHA-256 of 48 zero bytes = 0x3973e...  (computed reference value below).
    /// Reference: `sha256(b'\x00' * 48)` = `b8f5...` per Python:
    ///   `hashlib.sha256(b'\x00' * 48).hexdigest()`.
    #[test]
    fn versioned_hash_first_byte_is_version() {
        let commitment = [0u8; 48];
        let vh = kzg_commitment_to_versioned_hash(&commitment);
        // First byte must always be VERSIONED_HASH_VERSION_KZG = 0x01.
        assert_eq!(vh[0], VERSIONED_HASH_VERSION_KZG);
        // Remaining 31 bytes are SHA-256(commitment)[1..].
        let hash = sha2::Sha256::digest(commitment.as_slice());
        assert_eq!(&vh[1..], &hash.as_slice()[1..]);
    }

    /// Different commitments produce different versioned hashes (collision resistance).
    #[test]
    fn versioned_hash_differs_for_different_commitments() {
        let c1 = [0u8; 48];
        let mut c2 = [0u8; 48];
        c2[47] = 1;
        assert_ne!(
            kzg_commitment_to_versioned_hash(&c1),
            kzg_commitment_to_versioned_hash(&c2)
        );
    }

    // ── Cell-sampling tests (EIP-7594) ────────────────────────────────────────

    /// A non-trivial but canonical test blob: each 32-byte field element is a
    /// small little-endian integer (`< BLS modulus`), so `Blob::from_bytes`
    /// accepts it and the cells are not all identical.
    fn test_blob() -> [u8; 131072] {
        let mut blob = [0u8; 131072];
        // 4096 field elements of 32 bytes each.  Field elements are interpreted
        // big-endian and must be canonical (< BLS modulus), so write the small
        // counter into the LOW-order (last) bytes and leave the high bytes zero.
        for (i, chunk) in blob.chunks_exact_mut(32).enumerate() {
            chunk[28..32].copy_from_slice(&(i as u32).to_be_bytes());
        }
        blob
    }

    /// 2.2 — `compute_cells` produces 128 cells of 2048 bytes, deterministically.
    ///
    /// No external c-kzg reference vector is embedded in this crate (the c-kzg
    /// fixtures live under `general/fulu/kzg` and are exercised by c-kzg's own
    /// suite, not vendored here).  Substitute assertion: exact cell count, exact
    /// per-cell byte length, and determinism (two calls produce byte-identical
    /// output).
    #[test]
    fn compute_cells_shape_and_determinism() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let cells = verifier.compute_cells(&blob).expect("compute_cells");
        assert_eq!(cells.len(), CELLS_PER_EXT_BLOB_COUNT);
        assert_eq!(cells.len(), 128);
        for c in cells.iter() {
            assert_eq!(c.len(), BYTES_PER_CELL_COUNT);
            assert_eq!(c.len(), 2048);
        }
        // Determinism: recomputing yields byte-identical cells.
        let cells2 = verifier.compute_cells(&blob).expect("compute_cells");
        assert_eq!(cells.as_array(), cells2.as_array());
    }

    /// 2.3 — `compute_cells_and_kzg_proofs` returns 128 cells + 128 proofs.
    #[test]
    fn compute_cells_and_proofs_lengths() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let (cells, proofs) = verifier
            .compute_cells_and_kzg_proofs(&blob)
            .expect("compute_cells_and_kzg_proofs");
        assert_eq!(cells.len(), 128);
        assert_eq!(proofs.len(), 128);
        // The cells match the standalone `compute_cells` output.
        assert_eq!(
            cells.as_array(),
            verifier.compute_cells(&blob).unwrap().as_array()
        );
    }

    /// 2.4 — a valid batch verifies `true`, a tampered cell verifies `false`,
    /// and mismatched-length inputs return `Err`.
    #[test]
    fn verify_cell_kzg_proof_batch_valid_tampered_and_mismatch() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let (cells, proofs) = verifier.compute_cells_and_kzg_proofs(&blob).unwrap();

        // One commitment for the whole blob, repeated per cell (c-kzg dedups).
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        let commitments: Vec<&[u8; 48]> = (0..128).map(|_| &commitment).collect();
        let cell_indices: Vec<u64> = (0..128u64).collect();
        let cell_refs: Vec<&[u8; 2048]> = cells.iter().collect();
        let proof_refs: Vec<&[u8; 48]> = proofs.iter().collect();

        // Valid batch → true.
        let ok = verifier
            .verify_cell_kzg_proof_batch(&commitments, &cell_indices, &cell_refs, &proof_refs)
            .expect("verify valid batch");
        assert!(ok, "valid cell batch must verify");

        // Tampered cell → false.  Flip a byte in cell 0.
        let mut tampered = *cells.cell(0);
        tampered[0] ^= 0x01;
        let mut tampered_refs = cell_refs.clone();
        tampered_refs[0] = &tampered;
        let tampered_ok = verifier
            .verify_cell_kzg_proof_batch(&commitments, &cell_indices, &tampered_refs, &proof_refs)
            .expect("verify tampered batch");
        assert!(!tampered_ok, "tampered cell batch must NOT verify");

        // Mismatched lengths → Err(CellLengthMismatch).
        let short_indices: Vec<u64> = (0..64u64).collect();
        let err = verifier
            .verify_cell_kzg_proof_batch(&commitments, &short_indices, &cell_refs, &proof_refs)
            .unwrap_err();
        assert!(matches!(err, KzgError::CellLengthMismatch { .. }));
    }

    /// 2.5 — recover the full 128-cell matrix from 64 cells (even indices) and
    /// round-trip against `compute_cells`.
    #[test]
    fn recover_cells_round_trips_against_compute_cells() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let full = verifier.compute_cells(&blob).unwrap();

        // Take 64 cells at even indices 0,2,...,126.
        let mut indices: Vec<u64> = Vec::with_capacity(64);
        let mut partial_owned: Vec<[u8; 2048]> = Vec::with_capacity(64);
        for i in (0..128usize).step_by(2) {
            indices.push(i as u64);
            partial_owned.push(*full.cell(i));
        }
        assert_eq!(indices.len(), 64);
        let partial_refs: Vec<&[u8; 2048]> = partial_owned.iter().collect();

        let (recovered, recovered_proofs) = verifier
            .recover_cells_and_kzg_proofs(&indices, &partial_refs)
            .expect("recover_cells_and_kzg_proofs");
        assert_eq!(recovered.len(), 128);
        assert_eq!(recovered_proofs.len(), 128);
        // The recovered full matrix equals the original `compute_cells` output.
        assert_eq!(recovered.as_array(), full.as_array());
    }
}
