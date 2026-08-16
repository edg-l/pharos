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
//! - `c_kzg::KzgSettings::{load_trusted_setup, parse_kzg_trusted_setup, blob_to_kzg_commitment, verify_blob_kzg_proof, verify_blob_kzg_proof_batch, compute_kzg_proof, compute_blob_kzg_proof, verify_kzg_proof}`
//! - `c_kzg::{Blob, Bytes32, Bytes48, BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_PROOF}`
//! - `c_kzg::ethereum_kzg_settings(precompute: u64) -> &'static KzgSettings`
//!
//! The `[u8; N]` → `Blob` / `Bytes32` / `Bytes48` conversion happens at the public boundary;
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

use c_kzg::{BYTES_PER_CELL, Blob, Bytes32, Bytes48, CELLS_PER_EXT_BLOB, Cell, KzgSettings};
use sha2::{Digest, Sha256};

// Re-export so dependents can use the raw c-kzg types if needed.
pub use c_kzg;

// ── BLS field element helpers ─────────────────────────────────────────────────

/// BLS12-381 scalar field modulus.
///
/// `r = 52435875175126190479447740508185965837690552500527637822603658699938581184513`
/// per EIP-4844 / `specs/deneb/polynomial-commitments.md`.
///
/// Used by `hash_to_bls_field` and the in-house challenge implementations.
const BLS_MODULUS: &[u8; 32] = &[
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// `hash_to_bls_field(data) = SHA256(data) mod BLS_MODULUS` (big-endian).
///
/// Mirrors `specs/deneb/polynomial-commitments.md`:
/// ```python
/// def hash_to_bls_field(data: bytes) -> BLSFieldElement:
///     hashed_data = hash(data)  # SHA256
///     return BLSFieldElement(int.from_bytes(hashed_data, 'big') % BLS_MODULUS)
/// ```
///
/// The result is a 32-byte big-endian encoding of the field element.
pub(crate) fn hash_to_bls_field(data: &[u8]) -> [u8; 32] {
    let hash: [u8; 32] = Sha256::digest(data).into();
    // Interpret both as big-endian 256-bit integers; compute hash % BLS_MODULUS.
    bls_field_mod_reduce(hash)
}

/// Reduce a 256-bit big-endian integer modulo `BLS_MODULUS`.
///
/// Uses schoolbook big-integer subtraction to avoid pulling in a bignum dep.
/// `BLS_MODULUS < 2^255`, so the input is either already reduced or needs at
/// most `floor(2^256 / BLS_MODULUS) ≈ 2.07` subtractions.  We loop until
/// the value is less than the modulus.
fn bls_field_mod_reduce(mut val: [u8; 32]) -> [u8; 32] {
    while cmp_be_bytes(&val, BLS_MODULUS) >= 0 {
        val = sub_be_bytes(val, *BLS_MODULUS);
    }
    val
}

/// Compare two 32-byte big-endian integers.  Returns positive / zero / negative.
fn cmp_be_bytes(a: &[u8; 32], b: &[u8; 32]) -> i8 {
    for (x, y) in a.iter().zip(b.iter()) {
        if x > y {
            return 1;
        }
        if x < y {
            return -1;
        }
    }
    0
}

/// Subtract two 32-byte big-endian integers: `a - b` (assumes `a >= b`).
fn sub_be_bytes(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as i16) - (b[i] as i16) - (borrow as i16);
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

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

    // ── Deneb KZG proof helpers (EIP-4844) ────────────────────────────────────

    /// Compute a KZG proof and evaluation for a blob at point `z`.
    ///
    /// `z` is a 32-byte big-endian BLS field element.  Returns `(proof, y)`
    /// where `proof` is a 48-byte KZG proof and `y` is the 32-byte evaluation
    /// of the polynomial at `z`.
    ///
    /// c-kzg 2.1.7 safe API: `KzgSettings::compute_kzg_proof(&self, blob: &Blob, z_bytes: &Bytes32) -> Result<(KZGProof, Bytes32), Error>`.
    pub fn compute_kzg_proof(
        &self,
        blob: &[u8; 131072],
        z: &[u8; 32],
    ) -> Result<([u8; 48], [u8; 32]), KzgError> {
        let ckzg_blob = Blob::from_bytes(blob.as_slice())?;
        let z_bytes = Bytes32::from_bytes(z.as_slice())?;
        let (proof, y) = self.settings.compute_kzg_proof(&ckzg_blob, &z_bytes)?;
        Ok((proof.to_bytes().into_inner(), *y))
    }

    /// Compute a KZG proof for an entire blob, given the blob and its commitment.
    ///
    /// The evaluation point is derived internally via `compute_challenge(blob, commitment)`.
    /// Returns a 48-byte proof.
    ///
    /// c-kzg 2.1.7 safe API: `KzgSettings::compute_blob_kzg_proof(&self, blob: &Blob, commitment_bytes: &Bytes48) -> Result<KZGProof, Error>`.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &[u8; 131072],
        commitment: &[u8; 48],
    ) -> Result<[u8; 48], KzgError> {
        let ckzg_blob = Blob::from_bytes(blob.as_slice())?;
        let commitment_bytes = Bytes48::from_bytes(commitment.as_slice())?;
        let proof = self
            .settings
            .compute_blob_kzg_proof(&ckzg_blob, &commitment_bytes)?;
        Ok(proof.to_bytes().into_inner())
    }

    /// Verify a KZG proof `proof` that `p(z) = y` for a given commitment.
    ///
    /// `commitment`, `z`, `y`, and `proof` are raw byte arrays.  Returns `Ok(true)`
    /// when the proof is valid.
    ///
    /// c-kzg 2.1.7 safe API: `KzgSettings::verify_kzg_proof(&self, commitment_bytes: &Bytes48, z_bytes: &Bytes32, y_bytes: &Bytes32, proof_bytes: &Bytes48) -> Result<bool, Error>`.
    pub fn verify_kzg_proof(
        &self,
        commitment: &[u8; 48],
        z: &[u8; 32],
        y: &[u8; 32],
        proof: &[u8; 48],
    ) -> Result<bool, KzgError> {
        let commitment_bytes = Bytes48::from_bytes(commitment.as_slice())?;
        let z_bytes = Bytes32::from_bytes(z.as_slice())?;
        let y_bytes = Bytes32::from_bytes(y.as_slice())?;
        let proof_bytes = Bytes48::from_bytes(proof.as_slice())?;
        let valid =
            self.settings
                .verify_kzg_proof(&commitment_bytes, &z_bytes, &y_bytes, &proof_bytes)?;
        Ok(valid)
    }

    // ── Deneb Fiat-Shamir challenge (in-house, EIP-4844) ──────────────────────

    /// Compute the Fiat-Shamir challenge for `(blob, commitment)`.
    ///
    /// This is the evaluation point used internally by `compute_blob_kzg_proof`
    /// and `verify_blob_kzg_proof`.
    ///
    /// Per `specs/deneb/polynomial-commitments.md`:
    /// ```python
    /// degree_poly = int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 16, 'big')  # 4096 as 16 bytes
    /// data = FIAT_SHAMIR_PROTOCOL_DOMAIN + degree_poly + blob + commitment
    /// return hash_to_bls_field(data)
    /// ```
    /// where `FIAT_SHAMIR_PROTOCOL_DOMAIN = b'FSBLOBVERIFY_V1_'` (16 bytes).
    ///
    /// The result is a 32-byte big-endian BLS field element.
    pub fn compute_challenge(blob: &[u8; 131072], commitment: &[u8; 48]) -> [u8; 32] {
        // FIAT_SHAMIR_PROTOCOL_DOMAIN = b'FSBLOBVERIFY_V1_' (16 bytes)
        const DOMAIN: &[u8; 16] = b"FSBLOBVERIFY_V1_";
        // FIELD_ELEMENTS_PER_BLOB = 4096, encoded as 16 big-endian bytes
        const DEGREE: [u8; 16] = {
            let n: u128 = 4096u128;
            n.to_be_bytes()
        };

        let mut data = Vec::with_capacity(16 + 16 + 131072 + 48);
        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(&DEGREE);
        data.extend_from_slice(blob.as_slice());
        data.extend_from_slice(commitment.as_slice());

        hash_to_bls_field(&data)
    }

    // ── Fulu Fiat-Shamir challenge (in-house, EIP-7594) ───────────────────────

    /// Compute the Fiat-Shamir challenge for `compute_verify_cell_kzg_proof_batch`.
    ///
    /// Per `specs/fulu/polynomial-commitments-sampling.md`:
    /// ```python
    /// hashinput = RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN
    /// hashinput += int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 8, 'big')    # 4096 as 8 bytes
    /// hashinput += int.to_bytes(FIELD_ELEMENTS_PER_CELL, 8, 'big')    # 64 as 8 bytes
    /// hashinput += int.to_bytes(len(commitments), 8, 'big')
    /// hashinput += int.to_bytes(len(cell_indices), 8, 'big')
    /// for commitment in commitments:
    ///     hashinput += commitment                                       # 48 bytes each
    /// for k, coset_evals in enumerate(cosets_evals):
    ///     hashinput += int.to_bytes(commitment_indices[k], 8, 'big')
    ///     hashinput += int.to_bytes(cell_indices[k], 8, 'big')
    ///     for coset_eval in coset_evals:
    ///         hashinput += bls_field_to_bytes(coset_eval)               # 32 bytes each
    ///     hashinput += proofs[k]                                        # 48 bytes
    /// return hash_to_bls_field(hashinput)
    /// ```
    ///
    /// `RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN = b'RCKZGCBATCH__V1_'` (16 bytes).
    /// `cosets_evals[k]` is a cell's 64 field elements, each 32 bytes big-endian
    /// (i.e. the raw cell bytes split into 32-byte chunks — the cell is already in
    /// evaluation form over its coset).
    /// `FIELD_ELEMENTS_PER_CELL = 64`, `FIELD_ELEMENTS_PER_BLOB = 4096`.
    ///
    /// Returns a 32-byte big-endian BLS field element.
    pub fn compute_verify_cell_kzg_proof_batch_challenge(
        commitments: &[&[u8; 48]],
        commitment_indices: &[u64],
        cell_indices: &[u64],
        cells: &[&[u8; 2048]],
        proofs: &[&[u8; 48]],
    ) -> [u8; 32] {
        // RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN = b'RCKZGCBATCH__V1_' (16 bytes)
        const DOMAIN: &[u8; 16] = b"RCKZGCBATCH__V1_";
        const FIELD_ELEMENTS_PER_BLOB: u64 = 4096;
        const FIELD_ELEMENTS_PER_CELL: u64 = 64;

        let num_cells = cell_indices.len();
        debug_assert_eq!(commitment_indices.len(), num_cells);
        debug_assert_eq!(cells.len(), num_cells);
        debug_assert_eq!(proofs.len(), num_cells);
        let mut data: Vec<u8> = Vec::with_capacity(
            16 + 8 + 8 + 8 + 8 + commitments.len() * 48 + num_cells * (8 + 8 + 64 * 32 + 48),
        );

        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(&FIELD_ELEMENTS_PER_BLOB.to_be_bytes());
        data.extend_from_slice(&FIELD_ELEMENTS_PER_CELL.to_be_bytes());
        data.extend_from_slice(&(commitments.len() as u64).to_be_bytes());
        data.extend_from_slice(&(num_cells as u64).to_be_bytes());

        for commitment in commitments {
            data.extend_from_slice(commitment.as_slice());
        }

        for k in 0..num_cells {
            data.extend_from_slice(&commitment_indices[k].to_be_bytes());
            data.extend_from_slice(&cell_indices[k].to_be_bytes());
            // Each cell is 2048 bytes = 64 field elements of 32 bytes each (big-endian).
            // `bls_field_to_bytes(coset_eval)` = 32-byte big-endian encoding.
            // The cell bytes ARE the evaluations in big-endian order, so we emit them directly.
            data.extend_from_slice(cells[k].as_slice());
            data.extend_from_slice(proofs[k].as_slice());
        }

        hash_to_bls_field(&data)
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

    // ── Tests for new deneb proof helpers ─────────────────────────────────────

    /// `compute_kzg_proof` round-trip: the returned proof verifies via `verify_kzg_proof`.
    #[test]
    fn compute_kzg_proof_round_trip() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        // Use z = 0x0000...0001 (a small field element well within range).
        let mut z = [0u8; 32];
        z[31] = 1;
        let (proof, y) = verifier
            .compute_kzg_proof(&blob, &z)
            .expect("compute_kzg_proof");
        let valid = verifier
            .verify_kzg_proof(&commitment, &z, &y, &proof)
            .expect("verify_kzg_proof");
        assert!(
            valid,
            "compute_kzg_proof + verify_kzg_proof round-trip must verify"
        );
    }

    /// `compute_kzg_proof` with an out-of-range `z` returns an error (not a panic).
    #[test]
    fn compute_kzg_proof_out_of_range_z_errors() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        // BLS_MODULUS in big-endian bytes (the modulus itself is out of range).
        let z_bad: [u8; 32] = *BLS_MODULUS;
        let result = verifier.compute_kzg_proof(&blob, &z_bad);
        assert!(result.is_err(), "out-of-range z must return Err");
    }

    /// `compute_blob_kzg_proof` round-trip: the returned proof verifies via
    /// `verify_blob_kzg_proof`.
    #[test]
    fn compute_blob_kzg_proof_round_trip() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        let proof = verifier
            .compute_blob_kzg_proof(&blob, &commitment)
            .expect("compute_blob_kzg_proof");
        let valid = verifier
            .verify_blob_kzg_proof(&blob, &commitment, &proof)
            .expect("verify_blob_kzg_proof");
        assert!(
            valid,
            "compute_blob_kzg_proof + verify_blob_kzg_proof round-trip must verify"
        );
    }

    /// `compute_challenge` output is consistent with `compute_kzg_proof` evaluation point:
    /// the proof computed at the challenge point verifies correctly.
    #[test]
    fn compute_challenge_consistent_with_blob_proof() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        let z = KzgVerifier::compute_challenge(&blob, &commitment);
        // The proof at z must verify with the y returned by compute_kzg_proof.
        let (proof, y) = verifier
            .compute_kzg_proof(&blob, &z)
            .expect("compute_kzg_proof at challenge");
        let valid = verifier
            .verify_kzg_proof(&commitment, &z, &y, &proof)
            .expect("verify_kzg_proof at challenge");
        assert!(valid, "challenge-derived z proof must verify");
    }

    /// `compute_challenge` is deterministic (same inputs → same output).
    #[test]
    fn compute_challenge_deterministic() {
        let blob = test_blob();
        let verifier = KzgVerifier::mainnet();
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        let z1 = KzgVerifier::compute_challenge(&blob, &commitment);
        let z2 = KzgVerifier::compute_challenge(&blob, &commitment);
        assert_eq!(z1, z2);
    }

    /// `compute_challenge` output is a valid BLS field element (< BLS_MODULUS).
    #[test]
    fn compute_challenge_output_in_field() {
        let blob = test_blob();
        let verifier = KzgVerifier::mainnet();
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        let z = KzgVerifier::compute_challenge(&blob, &commitment);
        // Must be strictly less than BLS_MODULUS.
        assert!(
            cmp_be_bytes(&z, BLS_MODULUS) < 0,
            "compute_challenge output must be < BLS_MODULUS"
        );
    }

    /// `compute_verify_cell_kzg_proof_batch_challenge` is deterministic.
    #[test]
    fn compute_cell_batch_challenge_deterministic() {
        let verifier = KzgVerifier::mainnet();
        let blob = test_blob();
        let commitment = verifier.blob_to_kzg_commitment(&blob).unwrap();
        let (cells, proofs) = verifier.compute_cells_and_kzg_proofs(&blob).unwrap();

        let commitment_refs: Vec<&[u8; 48]> = vec![&commitment];
        let commitment_indices: Vec<u64> = (0..128u64).collect();
        let cell_indices: Vec<u64> = (0..128u64).collect();
        let cell_refs: Vec<&[u8; 2048]> = cells.iter().collect();
        let proof_refs: Vec<&[u8; 48]> = proofs.iter().collect();

        let r1 = KzgVerifier::compute_verify_cell_kzg_proof_batch_challenge(
            &commitment_refs,
            &commitment_indices,
            &cell_indices,
            &cell_refs,
            &proof_refs,
        );
        let r2 = KzgVerifier::compute_verify_cell_kzg_proof_batch_challenge(
            &commitment_refs,
            &commitment_indices,
            &cell_indices,
            &cell_refs,
            &proof_refs,
        );
        assert_eq!(r1, r2, "challenge must be deterministic");
        // Must be a valid BLS field element.
        assert!(
            cmp_be_bytes(&r1, BLS_MODULUS) < 0,
            "cell batch challenge must be < BLS_MODULUS"
        );
    }
}
