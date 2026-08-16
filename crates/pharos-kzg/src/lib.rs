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

use std::path::Path;

use c_kzg::{Blob, Bytes48, KzgSettings};

// Re-export so dependents can use the raw c-kzg types if needed.
pub use c_kzg;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_settings_init() {
        // Ensure the mainnet trusted setup can be loaded without panicking.
        let _verifier = KzgVerifier::mainnet();
    }
}
