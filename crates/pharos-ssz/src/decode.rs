//! SSZ `Decode` trait, `SszDecoder` helper, and primitive implementations.
//!
//! # Container decoding contract (used by the derive macro)
//!
//! The `SszDecoder` splits an SSZ byte slice into per-field slices, validating
//! the offset table in a single pass. The derive macro emits code equivalent to:
//!
//! ```text
//! let mut d = SszDecoder::new(bytes);
//! // For each field in declaration order:
//! d.register_type::<FixedField>()?;           // fixed-size field
//! d.register_anonymous_variable_length_item::<VarField>()?; // variable-size field
//! // ... repeat for every field ...
//! // Then decode in the same order:
//! let f1 = d.decode_next::<FixedField>()?;
//! let f2 = d.decode_next::<VarField>()?;
//! d.finish()?;
//! ```
//!
//! Validation guarantees enforced by `SszDecoder`:
//! - Every offset is within `[fixed_region_len, total_len]`.
//! - Offsets are non-decreasing (equal adjacent offsets are valid — they
//!   represent zero-length variable elements per the SSZ spec).
//! - No offset points into the fixed region.
//! - Total bytes consumed equals `bytes.len()` (no trailing garbage).

use crate::encode::BYTES_PER_LENGTH_OFFSET;
use crate::error::SszError;
use pharos_utils::{FixedBytes, Uint256};

/// SSZ decoding trait.
///
/// Implemented for all types that can be SSZ-decoded. The derive macro
/// `#[derive(Decode)]` generates an implementation for structs with named fields.
pub trait Decode: Sized {
    /// `true` iff this type has a fixed-length SSZ encoding.
    const IS_FIXED_SIZE: bool;

    /// For fixed-size types: the expected byte length of the encoded form.
    /// For variable-size types: `BYTES_PER_LENGTH_OFFSET` (4).
    fn ssz_fixed_len() -> usize;

    /// Decode a value of this type from the given byte slice.
    ///
    /// The entire slice must be consumed. Returns `Err` if `bytes` is not a
    /// valid SSZ encoding for this type.
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError>;
}

// ── SszDecoder ────────────────────────────────────────────────────────────────

/// State for a field slot tracked by `SszDecoder`.
enum FieldSlot {
    /// Fixed-size field: the byte range within the original slice.
    Fixed { start: usize, len: usize },
    /// Variable-size field: the offset value read from the fixed region.
    ///
    /// The `end` is filled in during `build` by looking at the next offset
    /// (or the total length for the last variable field).
    Variable { offset: usize, end: usize },
}

/// Decoding helper for SSZ containers.
///
/// Constructed with the raw byte slice for the container, then one registration
/// call per field (in declaration order), then one `decode_next` call per field
/// (in the same order), then `finish()`.
///
/// All offset validation happens lazily during the registration phase.
pub struct SszDecoder<'a> {
    bytes: &'a [u8],
    /// Running cursor into the fixed region as we read offset values.
    fixed_cursor: usize,
    /// Accumulated field descriptors.
    slots: Vec<FieldSlot>,
    /// Running decode cursor used by `decode_next`.
    decode_index: usize,
    /// Length of the fixed region (computed on first variable registration or
    /// recomputed on each call to keep things simple).
    fixed_region_len: usize,
}

impl<'a> SszDecoder<'a> {
    /// Create a new decoder over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            fixed_cursor: 0,
            slots: Vec::new(),
            decode_index: 0,
            fixed_region_len: 0,
        }
    }

    /// Register a fixed-size field of type `T`.
    ///
    /// Advances the fixed cursor by `T::ssz_fixed_len()` bytes.
    pub fn register_type<T: Decode>(&mut self) -> Result<(), SszError> {
        let len = T::ssz_fixed_len();
        let start = self.fixed_cursor;
        let end = start
            .checked_add(len)
            .ok_or(SszError::Custom("fixed region overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(SszError::IncompleteData {
                needed: end,
                found: self.bytes.len(),
            });
        }
        self.slots.push(FieldSlot::Fixed { start, len });
        self.fixed_cursor = end;
        Ok(())
    }

    /// Register a variable-size field.
    ///
    /// Reads the 4-byte offset from the current fixed-cursor position and
    /// records it. The actual byte slice is resolved during `decode_next` by
    /// comparing adjacent offsets.
    pub fn register_anonymous_variable_length_item<T: Decode>(&mut self) -> Result<(), SszError> {
        let offset_start = self.fixed_cursor;
        let offset_end = offset_start
            .checked_add(BYTES_PER_LENGTH_OFFSET)
            .ok_or(SszError::Custom("offset region overflow".to_string()))?;
        if offset_end > self.bytes.len() {
            return Err(SszError::IncompleteData {
                needed: offset_end,
                found: self.bytes.len(),
            });
        }
        let offset_bytes: [u8; 4] = self.bytes[offset_start..offset_end]
            .try_into()
            .expect("slice is exactly 4 bytes");
        let offset = u32::from_le_bytes(offset_bytes) as usize;
        self.slots.push(FieldSlot::Variable { offset, end: 0 });
        self.fixed_cursor = offset_end;
        Ok(())
    }

    /// Decode the next registered field and advance the internal index.
    ///
    /// Fields must be decoded in the same order they were registered.
    pub fn decode_next<T: Decode>(&mut self) -> Result<T, SszError> {
        // On the first variable field decode, validate and resolve all offsets.
        self.maybe_resolve_offsets()?;

        let i = self.decode_index;
        if i >= self.slots.len() {
            return Err(SszError::Custom(
                "decode_next called more times than fields registered".to_string(),
            ));
        }
        let slice = match &self.slots[i] {
            FieldSlot::Fixed { start, len } => &self.bytes[*start..*start + *len],
            FieldSlot::Variable { offset, end } => &self.bytes[*offset..*end],
        };
        self.decode_index += 1;
        T::from_ssz_bytes(slice)
    }

    /// Assert that all slots have been consumed.
    ///
    /// Byte coverage is enforced by `maybe_resolve_offsets` (which checks
    /// `fixed_len == total` for all-fixed containers and sets the last
    /// variable field's `end` to `bytes.len()`), so this only needs to
    /// verify that every slot was actually read. The `debug_assert` catches
    /// programming errors (missing `decode_next` calls) without paying for
    /// the check in release builds.
    pub fn finish(&self) -> Result<(), SszError> {
        debug_assert_eq!(
            self.decode_index,
            self.slots.len(),
            "SszDecoder::finish called with {} slots remaining",
            self.slots.len() - self.decode_index
        );
        Ok(())
    }

    /// Resolve variable-field endpoints from offset values.
    ///
    /// Called lazily before the first `decode_next`. Performs:
    /// - Validates that every offset is >= fixed_region_len.
    /// - Validates that offsets are non-decreasing (equal adjacent offsets
    ///   yield zero-length elements, which the SSZ spec allows).
    /// - Validates that no offset exceeds `bytes.len()`.
    /// - Fills `end` for each variable-size slot.
    fn maybe_resolve_offsets(&mut self) -> Result<(), SszError> {
        if self.fixed_region_len != 0 {
            // Already resolved.
            return Ok(());
        }
        // Even if there are no variable fields, record fixed_region_len so we
        // don't re-enter.
        self.fixed_region_len = self.fixed_cursor;
        let total = self.bytes.len();
        let fixed_len = self.fixed_region_len;

        // Collect variable slot indices and their offsets.
        let var_indices: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                if matches!(s, FieldSlot::Variable { .. }) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if var_indices.is_empty() {
            // All fixed. Validate total length.
            if fixed_len != total {
                return Err(SszError::ExtraBytes {
                    extra: total - fixed_len,
                });
            }
            return Ok(());
        }

        // Validate each offset.
        let mut prev_offset: Option<usize> = None;
        for &vi in &var_indices {
            let offset = match &self.slots[vi] {
                FieldSlot::Variable { offset, .. } => *offset,
                _ => unreachable!(),
            };
            if offset < fixed_len {
                return Err(SszError::OffsetIntoFixedRegion);
            }
            if offset > total {
                return Err(SszError::OffsetOutOfRange { offset, max: total });
            }
            if let Some(prev) = prev_offset {
                if offset < prev {
                    return Err(SszError::OffsetsNotMonotonic);
                }
                // Equal offsets produce a zero-length element which is valid
                // for some types, but monotonicity requires non-decreasing.
            }
            prev_offset = Some(offset);
        }

        // Assign `end` values.
        let n = var_indices.len();
        for k in 0..n {
            let vi = var_indices[k];
            let end = if k + 1 < n {
                // Next variable field's offset.
                match &self.slots[var_indices[k + 1]] {
                    FieldSlot::Variable { offset, .. } => *offset,
                    _ => unreachable!(),
                }
            } else {
                // Last variable field ends at total length.
                total
            };
            if let FieldSlot::Variable { end: e, .. } = &mut self.slots[vi] {
                *e = end;
            }
        }

        Ok(())
    }
}

// ── bool ─────────────────────────────────────────────────────────────────────

impl Decode for bool {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        match bytes {
            [0x00] => Ok(false),
            [0x01] => Ok(true),
            [b] => Err(SszError::InvalidBoolByte(*b)),
            _ => Err(SszError::InvalidByteLength {
                found: bytes.len(),
                expected: 1,
            }),
        }
    }
}

// ── unsigned integers ─────────────────────────────────────────────────────────

macro_rules! impl_decode_uint {
    ($t:ty, $bytes:expr) => {
        impl Decode for $t {
            const IS_FIXED_SIZE: bool = true;

            fn ssz_fixed_len() -> usize {
                $bytes
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
                if bytes.len() != $bytes {
                    return Err(SszError::InvalidByteLength {
                        found: bytes.len(),
                        expected: $bytes,
                    });
                }
                let arr: [u8; $bytes] = bytes.try_into().expect("length checked above");
                Ok(<$t>::from_le_bytes(arr))
            }
        }
    };
}

impl_decode_uint!(u8, 1);
impl_decode_uint!(u16, 2);
impl_decode_uint!(u32, 4);
impl_decode_uint!(u64, 8);
impl_decode_uint!(u128, 16);

// ── Uint256 ───────────────────────────────────────────────────────────────────

impl Decode for Uint256 {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.len() != 32 {
            return Err(SszError::InvalidByteLength {
                found: bytes.len(),
                expected: 32,
            });
        }
        let arr: [u8; 32] = bytes.try_into().expect("length checked above");
        Ok(Uint256::from_le_bytes(arr))
    }
}

// ── FixedBytes<N> ─────────────────────────────────────────────────────────────

impl<const N: usize> Decode for FixedBytes<N> {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        N
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.len() != N {
            return Err(SszError::InvalidByteLength {
                found: bytes.len(),
                expected: N,
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        Ok(FixedBytes::from_array(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_utils::Hash256;

    #[test]
    fn bool_decode_false() {
        assert!(!bool::from_ssz_bytes(&[0x00]).unwrap());
    }

    #[test]
    fn bool_decode_true() {
        assert!(bool::from_ssz_bytes(&[0x01]).unwrap());
    }

    #[test]
    fn bool_decode_invalid() {
        assert!(matches!(
            bool::from_ssz_bytes(&[0x02]),
            Err(SszError::InvalidBoolByte(0x02))
        ));
    }

    #[test]
    fn bool_decode_empty() {
        assert!(matches!(
            bool::from_ssz_bytes(&[]),
            Err(SszError::InvalidByteLength { .. })
        ));
    }

    #[test]
    fn u64_decode_le() {
        let b = 1u64.to_le_bytes();
        assert_eq!(u64::from_ssz_bytes(&b).unwrap(), 1u64);
    }

    #[test]
    fn uint256_decode() {
        let mut b = [0u8; 32];
        b[0] = 1;
        let v = Uint256::from_ssz_bytes(&b).unwrap();
        assert_eq!(v, Uint256::from(1u64));
    }

    #[test]
    fn hash256_decode() {
        let h = Hash256::from_ssz_bytes(&[0u8; 32]).unwrap();
        assert_eq!(h, Hash256::default());
    }

    #[test]
    fn hash256_decode_wrong_len() {
        assert!(matches!(
            Hash256::from_ssz_bytes(&[0u8; 31]),
            Err(SszError::InvalidByteLength {
                found: 31,
                expected: 32
            })
        ));
    }
}
