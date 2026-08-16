//! EIP-7916 `ProgressiveList[T]` and `ProgressiveBitlist`.
//!
//! # Serialization / Deserialization
//!
//! `ProgressiveList[T]` serializes identically to `List[T, N]`: the elements
//! are encoded in declaration order. `ProgressiveBitlist` serializes
//! identically to `Bitlist[N]`: bits in little-endian bit order, with a
//! trailing sentinel `1` bit.
//!
//! # Merkleization
//!
//! EIP-7916 introduces `merkleize_progressive(chunks, num_leaves=1)`:
//!
//! ```text
//! fn merkleize_progressive(chunks, num_leaves=1):
//!     if len(chunks) == 0: return Bytes32()
//!     a = merkleize(chunks[:num_leaves], limit=num_leaves)
//!     b = merkleize_progressive(chunks[num_leaves:], num_leaves * 4)
//!     return hash(a, b)
//! ```
//!
//! This grows the tree geometrically: subtrees hold 1, 4, 16, 64, … leaves.
//!
//! Merkle roots:
//! - `ProgressiveList[basic T]`:
//!   `mix_in_length(merkleize_progressive(pack(value)), len(value))`
//! - `ProgressiveList[composite T]`:
//!   `mix_in_length(merkleize_progressive([hash_tree_root(e) for e in value]), len(value))`
//! - `ProgressiveBitlist`:
//!   `mix_in_length(merkleize_progressive(pack_bits(value)), len(value))`
//!
//! # ProgressiveContainer (EIP-7495)
//!
//! Progressive containers use the same serialization as regular containers, but
//! Merkleize as:
//!   `mix_in_active_fields(merkleize_progressive([hash_tree_root(field) for field in value]),
//!                         active_fields)`
//!
//! The `mix_in_active_fields` helper is exported from this module for use by
//! progressive container implementations.

use pharos_utils::{Hash256, hash::hash_concat};

use crate::{
    Bitlist, Decode, Encode,
    encode::BYTES_PER_LENGTH_OFFSET,
    error::SszError,
    tree_hash::{
        TreeHash, TreeHashType, merkleize_padded, mix_in_length, pack_basic_elems_bytes,
        pack_bytes_to_chunks,
    },
};

// ── merkleize_progressive ─────────────────────────────────────────────────────

/// EIP-7916 progressive merkleization.
///
/// `merkleize_progressive(chunks, num_leaves=1)`:
/// - If `chunks` is empty: return `Bytes32()` (zero root).
/// - Otherwise: `hash(merkleize(chunks[:num_leaves], limit=num_leaves),
///                    merkleize_progressive(chunks[num_leaves:], num_leaves*4))`
pub fn merkleize_progressive(chunks: &[Hash256], num_leaves: usize) -> Hash256 {
    if chunks.is_empty() {
        return Hash256::default();
    }
    let first_count = num_leaves.min(chunks.len());
    let a = merkleize_padded(&chunks[..first_count], num_leaves);
    let b = merkleize_progressive(&chunks[first_count..], num_leaves * 4);
    hash_concat(a.as_ref(), b.as_ref())
}

// ── mix_in_active_fields ─────────────────────────────────────────────────────

/// EIP-7495 `mix_in_active_fields(root, active_fields)`.
///
/// `hash(root, pack_bits(active_fields))` where `active_fields` is packed into
/// 32 bytes (≤ 256 bits, so always one chunk). Bit `i` of `active_fields` is
/// packed as the `(i % 8)` bit of byte `i / 8`.
pub fn mix_in_active_fields(root: Hash256, active_fields: &[bool]) -> Hash256 {
    debug_assert!(
        active_fields.len() <= 256,
        "active_fields must be ≤ 256 bits"
    );
    let mut bytes = [0u8; 32];
    for (i, &bit) in active_fields.iter().enumerate() {
        if bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    hash_concat(root.as_ref(), &bytes)
}

// ── ProgressiveList<T> ────────────────────────────────────────────────────────

/// `ProgressiveList[T]` — an unbounded variable-length list of `T`.
///
/// Serialization is identical to `List[T, N]`. Merkleization uses the
/// progressive tree shape (EIP-7916).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressiveList<T> {
    items: Vec<T>,
}

impl<T> ProgressiveList<T> {
    /// Construct an empty list.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Construct from a `Vec<T>`.
    pub fn from_vec(v: Vec<T>) -> Self {
        Self { items: v }
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate over elements.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// Access the underlying slice.
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }
}

impl<T> Default for ProgressiveList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Encode> Encode for ProgressiveList<T> {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        if T::IS_FIXED_SIZE {
            T::ssz_fixed_len() * self.items.len()
        } else {
            let mut len = BYTES_PER_LENGTH_OFFSET * self.items.len();
            for item in &self.items {
                len += item.ssz_bytes_len();
            }
            len
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if T::IS_FIXED_SIZE {
            for item in &self.items {
                item.ssz_append(buf);
            }
        } else {
            // Variable-length elements: write offsets then bodies.
            let fixed_len = BYTES_PER_LENGTH_OFFSET * self.items.len();
            let mut offset: usize = fixed_len;
            for item in &self.items {
                buf.extend_from_slice(&(offset as u32).to_le_bytes());
                offset += item.ssz_bytes_len();
            }
            for item in &self.items {
                item.ssz_append(buf);
            }
        }
    }
}

impl<T: Decode> Decode for ProgressiveList<T> {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if T::IS_FIXED_SIZE {
            let elem_size = T::ssz_fixed_len();
            if elem_size == 0 {
                return Err(SszError::Custom("ProgressiveList element size is 0".into()));
            }
            if bytes.len() % elem_size != 0 {
                return Err(SszError::InvalidByteLength {
                    found: bytes.len(),
                    expected: (bytes.len() / elem_size) * elem_size,
                });
            }
            let count = bytes.len() / elem_size;
            let mut items = Vec::with_capacity(count);
            for i in 0..count {
                let start = i * elem_size;
                let end = start + elem_size;
                items.push(T::from_ssz_bytes(&bytes[start..end])?);
            }
            Ok(Self { items })
        } else {
            // Variable-length elements: read offsets, then decode each body.
            if bytes.len() < BYTES_PER_LENGTH_OFFSET {
                return Err(SszError::InvalidByteLength {
                    found: bytes.len(),
                    expected: BYTES_PER_LENGTH_OFFSET,
                });
            }
            // The first offset tells us how many elements there are.
            let first_offset = u32::from_le_bytes(
                bytes[..4]
                    .try_into()
                    .map_err(|_| SszError::Custom("offset slice conversion failed".into()))?,
            ) as usize;
            if first_offset % BYTES_PER_LENGTH_OFFSET != 0 {
                return Err(SszError::Custom(format!(
                    "ProgressiveList: first offset {first_offset} is not offset-aligned"
                )));
            }
            if first_offset > bytes.len() {
                return Err(SszError::OffsetOutOfRange {
                    offset: first_offset,
                    max: bytes.len(),
                });
            }
            let count = first_offset / BYTES_PER_LENGTH_OFFSET;
            if bytes.len() < count * BYTES_PER_LENGTH_OFFSET {
                return Err(SszError::InvalidByteLength {
                    found: bytes.len(),
                    expected: count * BYTES_PER_LENGTH_OFFSET,
                });
            }
            // Read all offsets.
            let mut offsets = Vec::with_capacity(count);
            for i in 0..count {
                let start = i * BYTES_PER_LENGTH_OFFSET;
                let o = u32::from_le_bytes(
                    bytes[start..start + 4]
                        .try_into()
                        .map_err(|_| SszError::Custom("offset slice failed".into()))?,
                ) as usize;
                offsets.push(o);
            }
            // Validate and decode each element.
            let mut items = Vec::with_capacity(count);
            for i in 0..count {
                let start = offsets[i];
                let end = if i + 1 < count {
                    offsets[i + 1]
                } else {
                    bytes.len()
                };
                if start > end || end > bytes.len() {
                    return Err(SszError::OffsetOutOfRange {
                        offset: start,
                        max: bytes.len(),
                    });
                }
                items.push(T::from_ssz_bytes(&bytes[start..end])?);
            }
            Ok(Self { items })
        }
    }
}

impl<T: TreeHash> TreeHash for ProgressiveList<T> {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::List;

    fn tree_hash_root(&self) -> Hash256 {
        if self.items.is_empty() {
            // merkleize_progressive([]) = Bytes32(); mix_in_length(zero, 0)
            return mix_in_length(Hash256::default(), 0);
        }
        let chunks: Vec<Hash256> = match T::TREE_HASH_TYPE {
            TreeHashType::Basic => {
                let bytes = pack_basic_elems_bytes(&self.items);
                pack_bytes_to_chunks(&bytes)
            }
            _ => self.items.iter().map(|e| e.tree_hash_root()).collect(),
        };
        let root = merkleize_progressive(&chunks, 1);
        mix_in_length(root, self.items.len() as u64)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("ProgressiveList is not a basic type and is never packed")
    }
}

// ── ProgressiveBitlist ────────────────────────────────────────────────────────

/// `ProgressiveBitlist` — an unbounded variable-length bitlist.
///
/// Serialization is identical to `Bitlist[N]`: bits in little-endian bit order,
/// with a trailing sentinel `1` bit to encode the length. Merkleization uses
/// the progressive tree shape (EIP-7916).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveBitlist {
    data: Vec<u8>,
    bit_len: usize,
}

impl ProgressiveBitlist {
    /// Construct an empty bitlist.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            bit_len: 0,
        }
    }

    /// Number of bits.
    pub fn len(&self) -> usize {
        self.bit_len
    }

    /// True if the bitlist is empty.
    pub fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// Push a bit.
    pub fn push(&mut self, value: bool) {
        if self.bit_len % 8 == 0 {
            self.data.push(0);
        }
        let i = self.bit_len;
        if value {
            self.data[i / 8] |= 1 << (i % 8);
        }
        self.bit_len += 1;
    }

    /// Get bit `i`. Returns `None` if `i >= bit_len`.
    pub fn get(&self, i: usize) -> Option<bool> {
        if i >= self.bit_len {
            return None;
        }
        Some((self.data[i / 8] >> (i % 8)) & 1 == 1)
    }

    /// The raw byte slice (without sentinel).
    pub fn as_raw_bytes(&self) -> &[u8] {
        let data_bytes = self.bit_len.div_ceil(8);
        &self.data[..data_bytes]
    }
}

impl Encode for ProgressiveBitlist {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        (self.bit_len / 8) + 1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let byte_len = self.ssz_bytes_len();
        let start = buf.len();
        buf.resize(start + byte_len, 0);
        let out = &mut buf[start..start + byte_len];
        let data_bytes = self.bit_len.div_ceil(8);
        out[..data_bytes].copy_from_slice(&self.data[..data_bytes]);
        // Append sentinel bit at position `bit_len`.
        out[self.bit_len / 8] |= 1 << (self.bit_len % 8);
    }
}

impl Decode for ProgressiveBitlist {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.is_empty() {
            return Err(SszError::BitlistMissingLengthBit);
        }
        let last = *bytes.last().expect("non-empty");
        if last == 0 {
            return Err(SszError::BitlistMissingLengthBit);
        }
        let highest_bit_pos = 7 - last.leading_zeros() as usize;
        let bit_len = (bytes.len() - 1) * 8 + highest_bit_pos;

        let data_bytes = bit_len.div_ceil(8);
        let mut data = vec![0u8; data_bytes];
        if data_bytes > 0 {
            data.copy_from_slice(&bytes[..data_bytes]);
            // Clear the sentinel bit if it shares a byte with real data.
            if bit_len % 8 != 0 {
                data[data_bytes - 1] &= !(1u8 << highest_bit_pos);
            }
        }
        Ok(Self { data, bit_len })
    }
}

impl TreeHash for ProgressiveBitlist {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::List;

    fn tree_hash_root(&self) -> Hash256 {
        let data_bytes = self.bit_len.div_ceil(8);
        let chunks = pack_bytes_to_chunks(&self.data[..data_bytes]);
        if chunks.is_empty() {
            return mix_in_length(Hash256::default(), 0);
        }
        let root = merkleize_progressive(&chunks, 1);
        mix_in_length(root, self.bit_len as u64)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("ProgressiveBitlist is not a basic type and is never packed")
    }
}

// ── Conversion from Bitlist<N> ────────────────────────────────────────────────

impl<const N: u64> From<Bitlist<N>> for ProgressiveBitlist {
    fn from(bl: Bitlist<N>) -> Self {
        let mut pbl = ProgressiveBitlist::new();
        for i in 0..bl.len() {
            pbl.push(bl.get(i).unwrap_or(false));
        }
        pbl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TreeHash;
    use pharos_utils::hash::hash_concat;

    /// EIP-7916 spec example: empty progressive list root = Bytes32() with mix_in_length(0).
    #[test]
    fn progressive_list_empty_root() {
        let list: ProgressiveList<u64> = ProgressiveList::new();
        let root = list.tree_hash_root();
        // merkleize_progressive([]) = zero, mix_in_length(zero, 0) = hash(zero, zero)
        let expected = mix_in_length(Hash256::default(), 0);
        assert_eq!(root, expected);
    }

    /// Single bool=true element should match fixture proglist_bool_max_1 root.
    ///
    /// Fixture: `general/phase0/ssz_generic/basic_progressive_list/valid/proglist_bool_max_1/meta.yaml`
    /// root: 0x905efb51c2764c2c7a4efb0548e372569df06db82115c3b1896c186632f3fe5b
    ///
    /// Derivation:
    ///   pack([true]) = [0x01 padded to 32 bytes] = one chunk
    ///   merkleize_progressive([chunk], 1):
    ///     a = merkleize_padded([chunk], 1) = chunk
    ///     b = merkleize_progressive([], 4) = Bytes32()
    ///     = hash(chunk, Bytes32())
    ///   mix_in_length(hash(chunk, zero), 1)
    #[test]
    fn progressive_list_single_bool_true() {
        let list = ProgressiveList::from_vec(vec![true]);
        let root = list.tree_hash_root();
        // Compute manually:
        let mut chunk_bytes = [0u8; 32];
        chunk_bytes[0] = 0x01; // bool true packed
        let chunk = Hash256::from_array(chunk_bytes);
        let a = chunk; // merkleize_padded([chunk], 1) = chunk
        let b = Hash256::default(); // merkleize_progressive([], 4) = zero
        let prog_root = hash_concat(a.as_ref(), b.as_ref());
        let expected = mix_in_length(prog_root, 1);
        assert_eq!(root, expected);
    }

    /// Empty progressive bitlist root should match empty progressive list root.
    #[test]
    fn progressive_bitlist_empty_root() {
        let pbl = ProgressiveBitlist::new();
        let root = pbl.tree_hash_root();
        // mix_in_length(zero, 0) = hash(Bytes32(), Bytes32())
        let expected = mix_in_length(Hash256::default(), 0);
        assert_eq!(root, expected);
    }

    /// Single bit=true progressive bitlist root must equal single-bool list root.
    ///
    /// Both pack to the same single chunk of 0x01 (bit 0 = true), so the
    /// progressive merkle root and final `mix_in_length` are identical.
    #[test]
    fn progressive_bitlist_single_bit_true() {
        let mut pbl = ProgressiveBitlist::new();
        pbl.push(true);
        let root = pbl.tree_hash_root();
        // Same calculation as single-bool progressive list.
        let mut chunk_bytes = [0u8; 32];
        chunk_bytes[0] = 0x01;
        let chunk = Hash256::from_array(chunk_bytes);
        let prog_root = hash_concat(chunk.as_ref(), Hash256::default().as_ref());
        let expected = mix_in_length(prog_root, 1);
        assert_eq!(root, expected);
    }

    /// Invalid: empty bytes for ProgressiveBitlist must fail.
    #[test]
    fn progressive_bitlist_empty_decode_fails() {
        let result = ProgressiveBitlist::from_ssz_bytes(&[]);
        assert!(result.is_err());
    }

    /// Invalid: last byte = 0 (missing sentinel) must fail.
    #[test]
    fn progressive_bitlist_zero_last_byte_fails() {
        let result = ProgressiveBitlist::from_ssz_bytes(&[0x00]);
        assert!(result.is_err());
    }

    /// Round-trip: encode then decode must give the same list.
    #[test]
    fn progressive_list_roundtrip_uint64() {
        let items = vec![1u64, 2, 3, 100];
        let list = ProgressiveList::from_vec(items.clone());
        let encoded = list.as_ssz_bytes();
        let decoded: ProgressiveList<u64> = ProgressiveList::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(decoded.items, items);
    }
}
