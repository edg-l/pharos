//! Snappy decompression for `.ssz_snappy` files.
//!
//! consensus-spec-tests uses the **raw** (non-framed) snappy format for
//! `serialized.ssz_snappy` files. Framed snappy is used elsewhere in the
//! Ethereum protocol (libp2p req-resp), but the test fixtures are raw.
//! Verified by inspecting fixtures from `consensus-specs` release v1.6.1.

use crate::error::ConformanceError;

/// Decompress raw (non-framed) snappy bytes.
pub fn decompress_raw(bytes: &[u8]) -> Result<Vec<u8>, ConformanceError> {
    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(bytes)
        .map_err(|e| ConformanceError::Snappy(e.to_string()))
}
