//! Fixed-length byte arrays (`FixedBytes<N>`) and type aliases used throughout
//! the Pharos workspace.

use std::fmt;
use std::str::FromStr;

/// A fixed-length byte array of `N` bytes.
///
/// `Copy` is implemented unconditionally for all `N` because `[u8; N]` is
/// `Copy` for all `N` on stable Rust (S6).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the inner byte array.
    pub fn into_inner(self) -> [u8; N] {
        self.0
    }

    /// Creates a `FixedBytes<N>` from a byte array.
    pub fn from_array(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for FixedBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    fn from(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> From<FixedBytes<N>> for [u8; N] {
    fn from(fb: FixedBytes<N>) -> Self {
        fb.0
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes<{}>(0x{})", N, hex::encode(self.0))
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<const N: usize> fmt::LowerHex for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Error returned when parsing a hex string into a `FixedBytes<N>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedBytesParseError(String);

impl fmt::Display for FixedBytesParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes parse error: {}", self.0)
    }
}

impl std::error::Error for FixedBytesParseError {}

impl<const N: usize> FromStr for FixedBytes<N> {
    type Err = FixedBytesParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let bytes =
            hex::decode(stripped).map_err(|e| FixedBytesParseError(format!("hex decode: {e}")))?;
        if bytes.len() != N {
            return Err(FixedBytesParseError(format!(
                "expected {N} bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// 4-byte fixed blob.
pub type Bytes4 = FixedBytes<4>;
/// 32-byte fixed blob (general purpose).
pub type Bytes32 = FixedBytes<32>;
/// 48-byte fixed blob.
pub type Bytes48 = FixedBytes<48>;
/// 96-byte fixed blob.
pub type Bytes96 = FixedBytes<96>;

/// 32-byte Merkle root / hash digest.
pub type Hash256 = FixedBytes<32>;

/// Compressed BLS12-381 G1 public key (48 bytes).
pub type BLSPubkey = FixedBytes<48>;

/// BLS12-381 G2 signature (96 bytes).
pub type BLSSignature = FixedBytes<96>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_bytes_default_is_zero() {
        let fb: FixedBytes<32> = FixedBytes::default();
        assert_eq!(fb.0, [0u8; 32]);
    }

    #[test]
    fn fixed_bytes_copy() {
        let a = FixedBytes::<4>([1, 2, 3, 4]);
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn fixed_bytes_roundtrip_hex() {
        let original = FixedBytes::<4>([0xde, 0xad, 0xbe, 0xef]);
        let hex_str = format!("{original}");
        assert_eq!(hex_str, "0xdeadbeef");
        let parsed: FixedBytes<4> = hex_str.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn fixed_bytes_parse_with_0x_prefix() {
        let fb: FixedBytes<4> = "0x01020304".parse().unwrap();
        assert_eq!(fb.0, [1, 2, 3, 4]);
    }

    #[test]
    fn fixed_bytes_parse_wrong_length_errors() {
        let result: Result<FixedBytes<4>, _> = "0x0102".parse();
        assert!(result.is_err());
    }

    #[test]
    fn fixed_bytes_equality_and_hash() {
        use std::collections::HashSet;
        let a = FixedBytes::<32>::default();
        let b = FixedBytes::<32>::default();
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn type_aliases_have_correct_size() {
        assert_eq!(size_of::<Bytes4>(), 4);
        assert_eq!(size_of::<Bytes32>(), 32);
        assert_eq!(size_of::<Bytes48>(), 48);
        assert_eq!(size_of::<Bytes96>(), 96);
        assert_eq!(size_of::<Hash256>(), 32);
        assert_eq!(size_of::<BLSPubkey>(), 48);
        assert_eq!(size_of::<BLSSignature>(), 96);
    }
}
