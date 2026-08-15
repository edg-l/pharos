//! Protobuf-style unsigned varint (LEB128) for req-resp length prefixes.
//!
//! Per `specs/phase0/p2p-interface.md:1264-1267`:
//! - MUST be minimally encoded (no redundant continuation bytes).
//! - MUST NOT exceed 10 bytes.
//! - MUST decode as a `u64`.

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::NetworkError;

/// Read a protobuf varint from an async reader.
///
/// Constraints (per `p2p-interface.md:1264-1267`):
/// - At most 10 bytes.
/// - Minimally encoded — the final byte in a multi-byte encoding must be
///   non-zero.
/// - Decodes as `u64`; bit-overflow returns an error.
pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64, NetworkError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut byte_count: usize = 0;

    loop {
        if byte_count == 10 {
            // We already consumed 10 bytes and none was terminal.
            return Err(NetworkError::Io(std::io::Error::other(
                "varint exceeds 10 bytes",
            )));
        }
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf).await?;
        let byte = buf[0];
        byte_count += 1;

        // For the 10th byte (shift = 63), only bit 0 may be set to stay within
        // u64. Bits 1-6 of the last 7-bit group (positions 64-69) must be zero.
        if shift == 63 && (byte & 0xFE) != 0 {
            return Err(NetworkError::Io(std::io::Error::other(
                "varint overflows u64",
            )));
        }

        let low7 = (byte & 0x7F) as u64;
        value |= low7 << shift;

        if byte & 0x80 == 0 {
            // Terminal byte. For multi-byte encodings the terminal byte must
            // be non-zero (otherwise the previous continuation byte was
            // unnecessary — non-minimal encoding).
            if byte_count > 1 && byte == 0 {
                return Err(NetworkError::Io(std::io::Error::other(
                    "varint is not minimally encoded",
                )));
            }
            return Ok(value);
        }

        shift += 7;
    }
}

/// Write a protobuf varint to an async writer.
///
/// The encoding is minimal: the smallest number of bytes that represent the
/// value is always used.
pub async fn write_varint<W: AsyncWrite + Unpin>(
    w: &mut W,
    mut value: u64,
) -> Result<(), NetworkError> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80; // more bytes follow
        }
        w.write_all(&[byte]).await?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    async fn roundtrip(v: u64) -> u64 {
        let mut buf: Vec<u8> = Vec::new();
        write_varint(&mut buf, v)
            .await
            .expect("write_varint failed");
        let mut reader = Cursor::new(buf);
        read_varint(&mut reader).await.expect("read_varint failed")
    }

    #[tokio::test]
    async fn roundtrip_boundary_values() {
        for &v in &[0u64, 1, 127, 128, 16383, 16384, 1u64 << 32, u64::MAX] {
            assert_eq!(roundtrip(v).await, v, "roundtrip failed for {v}");
        }
    }

    #[tokio::test]
    async fn reject_non_minimal() {
        // [0x80, 0x00] encodes 0 with a redundant continuation byte.
        let bytes = vec![0x80u8, 0x00];
        let mut reader = Cursor::new(bytes);
        let result = read_varint(&mut reader).await;
        assert!(result.is_err(), "non-minimal [0x80, 0x00] must be rejected");
    }

    #[tokio::test]
    async fn reject_11_byte_overflow() {
        // 11 bytes — one past the 10-byte limit.
        let bytes = vec![0xFFu8; 11];
        let mut reader = Cursor::new(bytes);
        let result = read_varint(&mut reader).await;
        assert!(result.is_err(), "11-byte varint must be rejected");
    }

    #[tokio::test]
    async fn reject_u64_overflow() {
        // 10 bytes where bits 64+ would be set.
        // The 10th byte (shift=63) with value 0x02 sets bit 64 — overflow.
        let mut bytes = vec![0xFFu8; 9];
        bytes.push(0x02); // 10th byte, bit 1 set → overflow
        let mut reader = Cursor::new(bytes);
        let result = read_varint(&mut reader).await;
        assert!(result.is_err(), "u64 overflow must be rejected");
    }

    #[tokio::test]
    async fn u64_max_roundtrip() {
        // u64::MAX encodes as [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        // The 10th byte (shift=63) carries bit 63 only (value 0x01) — valid.
        assert_eq!(roundtrip(u64::MAX).await, u64::MAX);
    }
}
