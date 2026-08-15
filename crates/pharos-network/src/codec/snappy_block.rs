//! SSZ-snappy **block** (raw) compression for gossipsub payloads.
//!
//! The gossip encoding uses snappy block compression, not frame compression.
//! Per `specs/phase0/p2p-interface.md:1038-1048`:
//!
//! > Snappy has two formats: "block" and "frames" (streaming). Gossip messages
//! > remain relatively small (100s of bytes to 100s of kilobytes) so **basic
//! > snappy block compression** is used to avoid the additional overhead
//! > associated with snappy frames.
//!
//! Req/resp uses the frame format (see `snappy_frame.rs`).
//! Gossip encode/decode MUST use the raw block format in this module.

use snap::raw::{Decoder, Encoder, decompress_len};

use crate::error::NetworkError;

/// Compress `uncompressed` using snappy block (raw) compression.
///
/// Per `specs/phase0/p2p-interface.md:1038-1044`.
pub fn encode_snappy_block(uncompressed: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let mut encoder = Encoder::new();
    encoder
        .compress_vec(uncompressed)
        .map_err(|e| NetworkError::Snappy(e.to_string()))
}

/// Decompress snappy-block-compressed `compressed` bytes.
///
/// Returns `NetworkError::PayloadTooLarge` if the decompressed result would
/// exceed `max_uncompressed` bytes.
///
/// The decompressed length is read from the snappy block header
/// (`snap::raw::decompress_len`) and checked against `max_uncompressed`
/// before any output buffer is allocated. A hostile peer cannot trigger a
/// `max_uncompressed`-sized allocation by sending a small compressed
/// payload that claims to expand into a larger one.
///
/// Per `specs/phase0/p2p-interface.md:1038-1048`.
pub fn decode_snappy_block(
    compressed: &[u8],
    max_uncompressed: usize,
) -> Result<Vec<u8>, NetworkError> {
    let claimed_len =
        decompress_len(compressed).map_err(|e| NetworkError::Snappy(e.to_string()))?;
    if claimed_len > max_uncompressed {
        return Err(NetworkError::PayloadTooLarge {
            got: claimed_len,
            max: max_uncompressed,
        });
    }

    let mut decoder = Decoder::new();
    decoder
        .decompress_vec(compressed)
        .map_err(|e| NetworkError::Snappy(e.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MAX_PAYLOAD_SIZE;

    /// A small payload survives a round-trip through block compression.
    #[test]
    fn roundtrip_small() {
        let payload = b"hello, ethereum gossip";
        let encoded = encode_snappy_block(payload).expect("encode failed");
        let decoded = decode_snappy_block(&encoded, MAX_PAYLOAD_SIZE).expect("decode failed");
        assert_eq!(decoded, payload);
    }

    /// A 1 MiB deterministic payload round-trips.
    #[test]
    fn roundtrip_1_mib() {
        let payload: Vec<u8> = (0..1024 * 1024)
            .map(|i: usize| (i.wrapping_mul(0x9e3779b1) >> 17) as u8)
            .collect();
        let encoded = encode_snappy_block(&payload).expect("encode failed");
        let decoded = decode_snappy_block(&encoded, MAX_PAYLOAD_SIZE).expect("decode failed");
        assert_eq!(decoded, payload);
    }

    /// Empty payload round-trips without error.
    #[test]
    fn roundtrip_empty() {
        let encoded = encode_snappy_block(&[]).expect("encode of empty failed");
        let decoded = decode_snappy_block(&encoded, MAX_PAYLOAD_SIZE).expect("decode failed");
        assert!(decoded.is_empty());
    }

    /// Decoding a payload that exceeds the cap returns `PayloadTooLarge`.
    #[test]
    fn decode_rejects_oversize() {
        let big: Vec<u8> = vec![0xAB; 11 * 1024 * 1024];
        let encoded = encode_snappy_block(&big).expect("encode failed");
        let result = decode_snappy_block(&encoded, MAX_PAYLOAD_SIZE);
        assert!(
            matches!(result, Err(NetworkError::PayloadTooLarge { .. })),
            "expected PayloadTooLarge, got: {result:?}"
        );
    }

    /// Frame-encoded data is NOT valid block-compressed data and should error.
    #[test]
    fn frame_data_is_not_block_data() {
        let payload = b"test gossip payload";
        // Encode as frame (the wrong format for gossip).
        let frame_encoded =
            crate::codec::snappy_frame::encode_snappy_frame(payload).expect("frame encode failed");
        // Decoding as block should fail.
        let result = decode_snappy_block(&frame_encoded, MAX_PAYLOAD_SIZE);
        assert!(
            result.is_err(),
            "frame-encoded data must not decode as block-compressed data"
        );
    }
}
