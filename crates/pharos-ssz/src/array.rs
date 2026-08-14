//! SSZ `Encode`, `Decode`, and `TreeHash` for fixed-length arrays `[T; N]`.
//!
//! `[T; N]` maps to `Vector[T, N]` in the SSZ spec when `T` is a fixed-size
//! type, and is only legal when `T: Encode + Decode`. Variable-element arrays
//! are not supported by this blanket impl (it requires `T::IS_FIXED_SIZE`).
//!
//! # Merkleization (B5 — no limit for vectors)
//!
//! Per the spec, vectors do NOT have a limit when merkleizing:
//! - `Basic` elements: `merkleize(pack(values))` — no limit.
//! - Any other variant: `merkleize([e.tree_hash_root() for e in self])` — no limit.

use crate::{
    decode::Decode,
    encode::Encode,
    error::SszError,
    tree_hash::{TreeHash, TreeHashType, merkleize, pack_basic_elems_bytes, pack_bytes_to_chunks},
};
use pharos_utils::Hash256;

impl<T, const N: usize> Encode for [T; N]
where
    T: Encode,
{
    /// Arrays are fixed-size iff their element type is fixed-size.
    const IS_FIXED_SIZE: bool = T::IS_FIXED_SIZE;

    fn ssz_fixed_len() -> usize {
        if T::IS_FIXED_SIZE {
            T::ssz_fixed_len() * N
        } else {
            crate::encode::BYTES_PER_LENGTH_OFFSET
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        self.iter().map(|e| e.ssz_bytes_len()).sum()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if T::IS_FIXED_SIZE {
            for elem in self.iter() {
                elem.ssz_append(buf);
            }
        } else {
            // Variable-element encoding: write offsets first, then variable data.
            // Compute offset base (total fixed region = N * BYTES_PER_LENGTH_OFFSET).
            let fixed_region_len = N * crate::encode::BYTES_PER_LENGTH_OFFSET;
            let mut variable_parts: Vec<Vec<u8>> = Vec::with_capacity(N);
            for elem in self.iter() {
                variable_parts.push(elem.as_ssz_bytes());
            }
            // Write offsets.
            let mut running_offset = fixed_region_len;
            for part in &variable_parts {
                buf.extend_from_slice(&(running_offset as u32).to_le_bytes());
                running_offset += part.len();
            }
            // Write variable parts.
            for part in variable_parts {
                buf.extend_from_slice(&part);
            }
        }
    }
}

impl<T, const N: usize> Decode for [T; N]
where
    T: Decode + Default + Copy,
{
    const IS_FIXED_SIZE: bool = T::IS_FIXED_SIZE;

    fn ssz_fixed_len() -> usize {
        if T::IS_FIXED_SIZE {
            T::ssz_fixed_len() * N
        } else {
            crate::encode::BYTES_PER_LENGTH_OFFSET
        }
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if T::IS_FIXED_SIZE {
            let elem_len = T::ssz_fixed_len();
            if N == 0 {
                if bytes.is_empty() {
                    // Zero-length array with no bytes — return default array.
                    return Ok([T::default(); N]);
                }
                return Err(SszError::ExtraBytes { extra: bytes.len() });
            }
            let expected = elem_len
                .checked_mul(N)
                .ok_or(SszError::Custom("array byte length overflow".to_string()))?;
            if bytes.len() != expected {
                return Err(SszError::VectorLengthMismatch {
                    found: bytes.len() / elem_len,
                    expected: N,
                });
            }
            let mut arr = [T::default(); N];
            for (i, elem) in arr.iter_mut().enumerate() {
                let start = i * elem_len;
                *elem = T::from_ssz_bytes(&bytes[start..start + elem_len])?;
            }
            Ok(arr)
        } else {
            // Variable-element array decode.
            if bytes.is_empty() && N == 0 {
                return Ok([T::default(); N]);
            }
            if bytes.len() < crate::encode::BYTES_PER_LENGTH_OFFSET {
                return Err(SszError::IncompleteData {
                    needed: crate::encode::BYTES_PER_LENGTH_OFFSET,
                    found: bytes.len(),
                });
            }
            // Read the first offset to determine N (it must equal N * 4).
            let first_offset =
                u32::from_le_bytes(bytes[..4].try_into().expect("checked above")) as usize;
            let fixed_len = N * crate::encode::BYTES_PER_LENGTH_OFFSET;
            if first_offset != fixed_len {
                return Err(SszError::OffsetIntoFixedRegion);
            }
            // Collect all offsets.
            let mut offsets = Vec::with_capacity(N);
            for i in 0..N {
                let start = i * 4;
                let off =
                    u32::from_le_bytes(bytes[start..start + 4].try_into().expect("bounds checked"))
                        as usize;
                offsets.push(off);
            }
            // Validate monotonicity.
            for w in offsets.windows(2) {
                if w[1] < w[0] {
                    return Err(SszError::OffsetsNotMonotonic);
                }
            }
            // Decode each element.
            let mut arr = [T::default(); N];
            for (i, elem) in arr.iter_mut().enumerate() {
                let start = offsets[i];
                let end = if i + 1 < N {
                    offsets[i + 1]
                } else {
                    bytes.len()
                };
                if start > bytes.len() || end > bytes.len() {
                    return Err(SszError::OffsetOutOfRange {
                        offset: start,
                        max: bytes.len(),
                    });
                }
                *elem = T::from_ssz_bytes(&bytes[start..end])?;
            }
            Ok(arr)
        }
    }
}

impl<T, const N: usize> TreeHash for [T; N]
where
    T: TreeHash,
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Vector;

    fn tree_hash_root(&self) -> Hash256 {
        match T::TREE_HASH_TYPE {
            TreeHashType::Basic => {
                // Pack all packed encodings into a byte stream, then merkleize without limit.
                let bytes = pack_basic_elems_bytes(self);
                let chunks = pack_bytes_to_chunks(&bytes);
                merkleize(&chunks)
            }
            _ => {
                // Composite elements: merkleize per-element roots, no limit.
                let roots: Vec<Hash256> = self.iter().map(|e| e.tree_hash_root()).collect();
                merkleize(&roots)
            }
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("array is not a basic type and is never packed as a single value")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode::Decode, encode::Encode, tree_hash::TreeHash};

    #[test]
    fn array_u8_roundtrip() {
        let arr: [u8; 4] = [1, 2, 3, 4];
        let encoded = arr.as_ssz_bytes();
        assert_eq!(encoded, vec![1, 2, 3, 4]);
        let decoded: [u8; 4] = Decode::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(decoded, arr);
    }

    #[test]
    fn array_u64_encode_len() {
        let arr: [u64; 4] = [1, 2, 3, 4];
        assert_eq!(arr.as_ssz_bytes().len(), 32);
    }

    #[test]
    fn array_u64_roundtrip() {
        let arr: [u64; 4] = [0, u64::MAX, 1, 42];
        let encoded = arr.as_ssz_bytes();
        let decoded: [u64; 4] = Decode::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(decoded, arr);
    }

    #[test]
    fn array_tree_hash_basic() {
        // [u64; 4] merkleization: pack all u64s into bytes, then merkleize.
        let arr = [1u64, 0, 0, 0];
        let root = arr.tree_hash_root();
        // Pack: [0x01, 0x00...x63 bytes] = 4*8 = 32 bytes = one chunk
        let mut packed = [0u8; 32];
        packed[0] = 1;
        let chunks = pack_bytes_to_chunks(&packed);
        let expected = merkleize(&chunks);
        assert_eq!(root, expected);
    }

    #[test]
    fn array_wrong_length_error() {
        assert!(matches!(
            <[u64; 4]>::from_ssz_bytes(&[0u8; 31]),
            Err(SszError::VectorLengthMismatch { .. })
        ));
    }
}
