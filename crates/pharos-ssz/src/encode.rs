//! SSZ `Encode` trait and primitive implementations.
//!
//! The SSZ serialization contract:
//! - Fixed-size types know their byte length at compile time (`ssz_fixed_len()`).
//! - Variable-size types report `BYTES_PER_LENGTH_OFFSET` (4) for their
//!   fixed-slot contribution and the actual length via `ssz_bytes_len`.
//! - `ssz_append` writes the type's serialized bytes into the provided buffer.
//!   For containers and vectors the caller manages offsets; this method only
//!   writes the value's own bytes.

use pharos_utils::{FixedBytes, Uint256};

/// Number of bytes in an SSZ length offset field.
pub const BYTES_PER_LENGTH_OFFSET: usize = 4;

/// SSZ serialization trait.
///
/// Implemented for all types that can be SSZ-encoded. The derive macro
/// `#[derive(Encode)]` generates an implementation for structs with named fields.
///
/// # Fixed vs variable
///
/// - If `IS_FIXED_SIZE == true`, `ssz_fixed_len()` returns the number of bytes
///   that this type serializes to, and that value is constant across all instances.
/// - If `IS_FIXED_SIZE == false`, `ssz_fixed_len()` returns
///   `BYTES_PER_LENGTH_OFFSET` (4), which is the space reserved for the offset
///   pointer in a containing container. The actual byte count is `ssz_bytes_len`.
pub trait Encode {
    /// `true` iff every instance of this type serializes to exactly the same
    /// number of bytes.
    const IS_FIXED_SIZE: bool;

    /// For fixed-size types: the byte length of the serialized form.
    /// For variable-size types: `BYTES_PER_LENGTH_OFFSET` (4) — the size of
    /// the offset slot reserved in a containing container's fixed region.
    fn ssz_fixed_len() -> usize;

    /// The exact number of bytes that `ssz_append` will write for this value.
    fn ssz_bytes_len(&self) -> usize;

    /// Append the SSZ serialization of this value to `buf`.
    fn ssz_append(&self, buf: &mut Vec<u8>);

    /// Return the SSZ serialization of this value as a new `Vec<u8>`.
    ///
    /// Allocates a buffer of `ssz_bytes_len()` capacity and calls `ssz_append`.
    fn as_ssz_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.ssz_bytes_len());
        self.ssz_append(&mut buf);
        buf
    }
}

// ── bool ─────────────────────────────────────────────────────────────────────

impl Encode for bool {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        1
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.push(u8::from(*self));
    }
}

// ── unsigned integers ─────────────────────────────────────────────────────────

macro_rules! impl_encode_uint {
    ($t:ty, $bytes:expr) => {
        impl Encode for $t {
            const IS_FIXED_SIZE: bool = true;

            fn ssz_fixed_len() -> usize {
                $bytes
            }

            fn ssz_bytes_len(&self) -> usize {
                $bytes
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.to_le_bytes());
            }
        }
    };
}

impl_encode_uint!(u8, 1);
impl_encode_uint!(u16, 2);
impl_encode_uint!(u32, 4);
impl_encode_uint!(u64, 8);
impl_encode_uint!(u128, 16);

// ── Uint256 ───────────────────────────────────────────────────────────────────

impl Encode for Uint256 {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

// ── FixedBytes<N> ─────────────────────────────────────────────────────────────

/// `FixedBytes<N>` serializes as its raw bytes (= `ByteVector[N]` in SSZ).
///
/// `Hash256`, `BLSPubkey`, `BLSSignature`, `Bytes4`, `Bytes32`, etc. are all
/// covered by this blanket impl.
impl<const N: usize> Encode for FixedBytes<N> {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        N
    }

    fn ssz_bytes_len(&self) -> usize {
        N
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_utils::{BLSPubkey, BLSSignature, Hash256};

    #[test]
    fn bool_encode_false() {
        assert_eq!(false.as_ssz_bytes(), vec![0x00]);
    }

    #[test]
    fn bool_encode_true() {
        assert_eq!(true.as_ssz_bytes(), vec![0x01]);
    }

    #[test]
    fn u8_encode() {
        assert_eq!(42u8.as_ssz_bytes(), vec![42]);
    }

    #[test]
    fn u16_encode_le() {
        assert_eq!(0x0102u16.as_ssz_bytes(), vec![0x02, 0x01]);
    }

    #[test]
    fn u32_encode_le() {
        assert_eq!(1u32.as_ssz_bytes(), vec![1, 0, 0, 0]);
    }

    #[test]
    fn u64_encode_le() {
        assert_eq!(1u64.as_ssz_bytes(), [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn u128_encode_le() {
        let b = 1u128.as_ssz_bytes();
        assert_eq!(b.len(), 16);
        assert_eq!(b[0], 1);
        assert!(b[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn uint256_encode() {
        let v = Uint256::from(1u64);
        let b = v.as_ssz_bytes();
        assert_eq!(b.len(), 32);
        assert_eq!(b[0], 1);
        assert!(b[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn hash256_encode() {
        let h = Hash256::default();
        assert_eq!(h.as_ssz_bytes(), vec![0u8; 32]);
    }

    #[test]
    fn bls_pubkey_encode_len() {
        let pk = BLSPubkey::default();
        assert_eq!(pk.as_ssz_bytes().len(), 48);
    }

    #[test]
    fn bls_signature_encode_len() {
        let sig = BLSSignature::default();
        assert_eq!(sig.as_ssz_bytes().len(), 96);
    }

    #[test]
    fn fixed_size_constants() {
        assert_eq!(<bool as Encode>::ssz_fixed_len(), 1);
        assert_eq!(<u8 as Encode>::ssz_fixed_len(), 1);
        assert_eq!(<u16 as Encode>::ssz_fixed_len(), 2);
        assert_eq!(<u32 as Encode>::ssz_fixed_len(), 4);
        assert_eq!(<u64 as Encode>::ssz_fixed_len(), 8);
        assert_eq!(<u128 as Encode>::ssz_fixed_len(), 16);
        assert_eq!(<Uint256 as Encode>::ssz_fixed_len(), 32);
        assert_eq!(<Hash256 as Encode>::ssz_fixed_len(), 32);
    }
}
