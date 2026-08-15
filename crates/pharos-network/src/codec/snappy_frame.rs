//! SSZ-snappy framing encode/decode for gossipsub payloads.
//!
//! Ethereum uses the snappy *framing* format (not raw snappy) for gossipsub
//! messages, per `specs/phase0/p2p-interface.md:218-227`.
//!
//! Maximum uncompressed gossip payload size: 10 MiB
//! (`p2p-interface.md:227`).

use std::io::{Read as _, Write as _};

use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

use crate::error::NetworkError;

/// Maximum uncompressed gossip payload size (10 MiB).
///
/// Per `specs/phase0/p2p-interface.md:227`.
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Compress `uncompressed` using snappy framing and return the encoded bytes.
///
/// Uses `snap::write::FrameEncoder` per `p2p-interface.md:218-224`.
pub fn encode_snappy_frame(uncompressed: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let buf = Vec::new();
    let mut encoder = FrameEncoder::new(buf);
    encoder
        .write_all(uncompressed)
        .map_err(|e| NetworkError::Snappy(e.to_string()))?;
    let buf = encoder
        .into_inner()
        .map_err(|e| NetworkError::Snappy(e.into_error().to_string()))?;
    Ok(buf)
}

/// Decompress snappy-framed `compressed` bytes.
///
/// Reads at most `max_uncompressed` bytes.  If the decompressed data would
/// exceed that limit, returns `NetworkError::PayloadTooLarge`.
///
/// Per `specs/phase0/p2p-interface.md:218-227`.
pub fn decode_snappy_frame(
    compressed: &[u8],
    max_uncompressed: usize,
) -> Result<Vec<u8>, NetworkError> {
    // Read up to `max_uncompressed + 1` bytes; if we end up with more than
    // `max_uncompressed`, the payload exceeded the cap.
    let decoder = FrameDecoder::new(compressed);
    let mut limited = decoder.take(max_uncompressed as u64 + 1);
    let mut buf = Vec::with_capacity(max_uncompressed.min(64 * 1024));
    limited
        .read_to_end(&mut buf)
        .map_err(|e| NetworkError::Snappy(e.to_string()))?;

    if buf.len() > max_uncompressed {
        return Err(NetworkError::PayloadTooLarge {
            got: buf.len(),
            max: max_uncompressed,
        });
    }

    Ok(buf)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic pseudo-random byte sequence without any
    /// external RNG dependency.
    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(0x9e3779b1_usize) >> 17) as u8)
            .collect()
    }

    /// A 1 MiB deterministic payload survives a roundtrip.
    #[test]
    fn roundtrip_1_mib() {
        let payload = pseudo_random_bytes(1024 * 1024);
        let encoded = encode_snappy_frame(&payload).expect("encode failed");
        let decoded = decode_snappy_frame(&encoded, MAX_PAYLOAD_SIZE).expect("decode failed");
        assert_eq!(decoded, payload);
    }

    /// Empty payload roundtrips without error.
    #[test]
    fn roundtrip_empty() {
        let encoded = encode_snappy_frame(&[]).expect("encode of empty failed");
        let decoded =
            decode_snappy_frame(&encoded, MAX_PAYLOAD_SIZE).expect("decode of empty failed");
        assert!(decoded.is_empty());
    }

    /// Decoding a payload that exceeds the cap returns `PayloadTooLarge`.
    #[test]
    fn decode_rejects_oversize() {
        // Encode 11 MiB payload.
        let oversize = pseudo_random_bytes(11 * 1024 * 1024);
        let encoded = encode_snappy_frame(&oversize).expect("encode of oversize failed");
        // Decode with a 10 MiB cap.
        let result = decode_snappy_frame(&encoded, MAX_PAYLOAD_SIZE);
        assert!(
            matches!(result, Err(NetworkError::PayloadTooLarge { .. })),
            "expected PayloadTooLarge, got: {result:?}"
        );
    }
}
