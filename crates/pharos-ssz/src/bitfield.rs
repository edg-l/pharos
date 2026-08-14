//! `Bitvector<N>` and `Bitlist<N>` — SSZ bit-collection types.
//!
//! Both use `u64` const-generic parameters (B4 resolution) so they align with
//! `EthSpec` associated constants.
//!
//! # Bitvector\[N\]
//!
//! Fixed-length: always serializes to `ceil(N / 8)` bytes with no sentinel bit.
//! `Bitvector<0>` is rejected at compile time.
//!
//! # Bitlist\[N\]
//!
//! Variable-length: serializes with a sentinel `1` bit appended after the last
//! real bit to encode the bit-length in the byte stream. The limit `N` is the
//! maximum number of bits (not bytes). An empty `Bitlist` encodes as `[0x01]`.
//!
//! # Merkleization
//!
//! Both types pack bits into 32-byte chunks (without the sentinel bit) and
//! merkleize with `limit = (N + 255) / 256` chunks.
//! `Bitlist` additionally mixes in the length.

use crate::{
    decode::Decode,
    encode::Encode,
    error::SszError,
    tree_hash::{TreeHash, TreeHashType, merkleize_padded, pack_bytes_to_chunks},
};
use pharos_utils::Hash256;

// ── Bitvector<N> ──────────────────────────────────────────────────────────────

/// A fixed-length collection of `N` boolean values.
///
/// Corresponds to `Bitvector[N]` in the SSZ spec. `Bitvector<0>` is rejected
/// at compile time via a `const { assert!(N > 0) }` guard.
///
/// Bits are stored in little-endian bit order: bit `i` is the `(i % 8)`-th
/// bit of byte `i / 8`, with bit 0 being the LSB of byte 0.
pub struct Bitvector<const N: u64> {
    /// Raw storage. Always exactly `ceil(N / 8)` bytes.
    data: Vec<u8>,
}

impl<const N: u64> Bitvector<N> {
    /// The number of bytes needed to store `N` bits.
    const BYTE_LEN: usize = {
        assert!(N > 0, "Bitvector<0> is illegal per the SSZ spec");
        (N as usize).div_ceil(8)
    };

    /// Construct a `Bitvector<N>` with all bits cleared.
    pub fn new() -> Self {
        Self {
            data: vec![0u8; Self::BYTE_LEN],
        }
    }

    /// Construct a `Bitvector<N>` with pre-allocated capacity (same as `new`
    /// since size is fixed).
    pub fn with_capacity() -> Self {
        Self::new()
    }

    /// Get bit `i`. Returns `None` if `i >= N`.
    pub fn get(&self, i: usize) -> Option<bool> {
        if i as u64 >= N {
            return None;
        }
        Some((self.data[i / 8] >> (i % 8)) & 1 == 1)
    }

    /// Set bit `i` to `value`. Does nothing if `i >= N`.
    pub fn set(&mut self, i: usize, value: bool) {
        if (i as u64) >= N {
            return;
        }
        if value {
            self.data[i / 8] |= 1 << (i % 8);
        } else {
            self.data[i / 8] &= !(1 << (i % 8));
        }
    }

    /// The number of bits in this bitvector (always `N`).
    pub fn len(&self) -> u64 {
        N
    }

    /// Always returns `false` because `Bitvector<0>` is illegal.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Iterator over the bits in order (LSB of byte 0 first).
    pub fn iter(&self) -> impl Iterator<Item = bool> + '_ {
        (0..N as usize).map(move |i| (self.data[i / 8] >> (i % 8)) & 1 == 1)
    }

    /// Count the number of set bits.
    pub fn num_set_bits(&self) -> usize {
        self.data.iter().map(|b| b.count_ones() as usize).sum()
    }
}

impl<const N: u64> Default for Bitvector<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: u64> Clone for Bitvector<N> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl<const N: u64> PartialEq for Bitvector<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: u64> Eq for Bitvector<N> {}

impl<const N: u64> std::fmt::Debug for Bitvector<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bitvector<{N}>(")?;
        for i in 0..N as usize {
            write!(f, "{}", (self.data[i / 8] >> (i % 8)) & 1)?;
        }
        write!(f, ")")
    }
}

impl<const N: u64> Encode for Bitvector<N> {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        Self::BYTE_LEN
    }

    fn ssz_bytes_len(&self) -> usize {
        Self::BYTE_LEN
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.data);
    }
}

impl<const N: u64> Decode for Bitvector<N> {
    const IS_FIXED_SIZE: bool = true;

    fn ssz_fixed_len() -> usize {
        Self::BYTE_LEN
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(SszError::InvalidByteLength {
                found: bytes.len(),
                expected: Self::BYTE_LEN,
            });
        }
        let mut bv = Self::new();
        bv.data.copy_from_slice(bytes);
        // Reject any bits in the last byte that are beyond N. Per
        // `simple-serialize.md`, decoding must fail on out-of-range bits;
        // silently masking them away accepts otherwise-invalid inputs.
        let remainder = (N as usize) % 8;
        if remainder != 0 {
            let mask = (1u8 << remainder) - 1;
            let last = *bv.data.last().expect("BYTE_LEN > 0");
            if last & !mask != 0 {
                return Err(SszError::InvalidBitvector);
            }
        }
        Ok(bv)
    }
}

impl<const N: u64> TreeHash for Bitvector<N> {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Vector;

    fn tree_hash_root(&self) -> Hash256 {
        // pack_bits then merkleize with limit = (N + 255) / 256.
        // pack_bits: serialize the bits into bytes (same as SSZ encode, no sentinel).
        let chunks = pack_bytes_to_chunks(&self.data);
        let limit = chunk_count_bits(N);
        merkleize_padded(&chunks, limit)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Bitvector is not a basic type and is never packed")
    }
}

// ── Bitlist<N> ────────────────────────────────────────────────────────────────

/// A variable-length collection of boolean values with a maximum of `N` bits.
///
/// Corresponds to `Bitlist[N]` in the SSZ spec. The SSZ encoding appends a
/// mandatory sentinel `1` bit so the bit-length can be recovered from the byte
/// stream. An empty `Bitlist` encodes as `[0x01]`.
///
/// Bits are stored in the same little-endian bit order as `Bitvector`.
pub struct Bitlist<const N: u64> {
    /// Raw bit storage (no sentinel bit). Length in bits is `bit_len`.
    data: Vec<u8>,
    /// Number of bits currently stored (≤ N).
    bit_len: usize,
}

impl<const N: u64> Bitlist<N> {
    /// Construct an empty `Bitlist<N>`.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            bit_len: 0,
        }
    }

    /// Construct an empty `Bitlist<N>` with byte-level pre-allocation.
    pub fn with_capacity(bits: usize) -> Self {
        Self {
            data: Vec::with_capacity(bits.div_ceil(8)),
            bit_len: 0,
        }
    }

    /// Get bit `i`. Returns `None` if `i >= bit_len`.
    pub fn get(&self, i: usize) -> Option<bool> {
        if i >= self.bit_len {
            return None;
        }
        Some((self.data[i / 8] >> (i % 8)) & 1 == 1)
    }

    /// Set bit `i` to `value`. Does nothing if `i >= bit_len`.
    pub fn set(&mut self, i: usize, value: bool) {
        if i >= self.bit_len {
            return;
        }
        if value {
            self.data[i / 8] |= 1 << (i % 8);
        } else {
            self.data[i / 8] &= !(1 << (i % 8));
        }
    }

    /// Push a bit onto the end. Returns `Err` if this would exceed the limit.
    pub fn push(&mut self, value: bool) -> Result<(), SszError> {
        if self.bit_len as u64 >= N {
            return Err(SszError::BitlistOverflow { limit: N });
        }
        if self.bit_len % 8 == 0 {
            self.data.push(0);
        }
        let i = self.bit_len;
        if value {
            self.data[i / 8] |= 1 << (i % 8);
        }
        self.bit_len += 1;
        Ok(())
    }

    /// The current number of bits.
    pub fn len(&self) -> usize {
        self.bit_len
    }

    /// `true` iff the bitlist is empty.
    pub fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// Iterator over the bits in order.
    pub fn iter(&self) -> impl Iterator<Item = bool> + '_ {
        (0..self.bit_len).map(move |i| (self.data[i / 8] >> (i % 8)) & 1 == 1)
    }

    /// Count the number of set bits.
    pub fn num_set_bits(&self) -> usize {
        if self.bit_len == 0 {
            return 0;
        }
        let full_bytes = self.bit_len / 8;
        let mut count: usize = self.data[..full_bytes]
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum();
        let rem = self.bit_len % 8;
        if rem > 0 {
            let mask = (1u8 << rem) - 1;
            count += (self.data[full_bytes] & mask).count_ones() as usize;
        }
        count
    }
}

impl<const N: u64> Default for Bitlist<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: u64> Clone for Bitlist<N> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            bit_len: self.bit_len,
        }
    }
}

impl<const N: u64> PartialEq for Bitlist<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bit_len == other.bit_len && self.data == other.data
    }
}

impl<const N: u64> Eq for Bitlist<N> {}

impl<const N: u64> std::fmt::Debug for Bitlist<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bitlist<{N}>(len={}, ", self.bit_len)?;
        for i in 0..self.bit_len {
            write!(f, "{}", (self.data[i / 8] >> (i % 8)) & 1)?;
        }
        write!(f, ")")
    }
}

impl<const N: u64> Encode for Bitlist<N> {
    /// Bitlist is variable-size because its length depends on the number of bits.
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        crate::encode::BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        // The encoded form is `ceil((bit_len + 1) / 8)` bytes:
        // one extra bit (the sentinel) is appended.
        (self.bit_len / 8) + 1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Clone the data bytes, then append the sentinel bit.
        let byte_len = self.ssz_bytes_len();
        let start = buf.len();
        buf.resize(start + byte_len, 0);
        let out = &mut buf[start..start + byte_len];
        // Copy existing data bytes.
        let data_bytes = self.bit_len.div_ceil(8);
        out[..data_bytes].copy_from_slice(&self.data[..data_bytes]);
        // Append sentinel bit at position `bit_len`.
        out[self.bit_len / 8] |= 1 << (self.bit_len % 8);
    }
}

impl<const N: u64> Decode for Bitlist<N> {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        crate::encode::BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.is_empty() {
            return Err(SszError::BitlistMissingLengthBit);
        }
        // Find the sentinel bit: the highest set bit in the last byte.
        let last = *bytes.last().expect("non-empty");
        if last == 0 {
            return Err(SszError::BitlistMissingLengthBit);
        }
        // Position of the highest set bit in `last`.
        let highest_bit_pos = 7 - last.leading_zeros() as usize;
        // bit_len = (bytes.len() - 1) * 8 + highest_bit_pos
        let bit_len = (bytes.len() - 1) * 8 + highest_bit_pos;

        if bit_len as u64 > N {
            return Err(SszError::BitlistOverflow { limit: N });
        }

        let mut bl = Bitlist::<N>::with_capacity(bit_len);
        bl.bit_len = bit_len;
        if bit_len == 0 {
            // Empty bitlist — nothing to copy.
            return Ok(bl);
        }
        let data_bytes = bit_len.div_ceil(8);
        bl.data.resize(data_bytes, 0);
        bl.data.copy_from_slice(&bytes[..data_bytes]);
        // The sentinel bit position within `bytes[bytes.len()-1]` is `highest_bit_pos`.
        // If `bit_len % 8 != 0`, the sentinel shares a byte with real data bits;
        // clear it so it is not counted as a data bit.
        // If `bit_len % 8 == 0`, the sentinel is in a separate byte beyond the data
        // bytes and was not copied, so no clearing needed.
        if bit_len % 8 != 0 {
            bl.data[data_bytes - 1] &= !(1u8 << highest_bit_pos);
        }
        Ok(bl)
    }
}

impl<const N: u64> TreeHash for Bitlist<N> {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::List;

    fn tree_hash_root(&self) -> Hash256 {
        // pack_bits (excluding sentinel), merkleize with limit, mix in length.
        let chunks = pack_bytes_to_chunks(&self.data[..self.bit_len.div_ceil(8)]);
        let limit = chunk_count_bits(N);
        let root = merkleize_padded(&chunks, limit);
        crate::tree_hash::mix_in_length(root, self.bit_len as u64)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Bitlist is not a basic type and is never packed")
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// `chunk_count` for a bit-collection type: `ceil(N / 256)`.
const fn chunk_count_bits(n: u64) -> usize {
    n.div_ceil(256) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode::Decode, encode::Encode};

    // ── Bitvector tests ──────────────────────────────────────────────────────

    #[test]
    fn bitvector_new_all_zero() {
        let bv = Bitvector::<8>::new();
        for i in 0..8 {
            assert_eq!(bv.get(i), Some(false));
        }
    }

    #[test]
    fn bitvector_set_get() {
        let mut bv = Bitvector::<8>::new();
        bv.set(0, true);
        bv.set(7, true);
        assert_eq!(bv.get(0), Some(true));
        assert_eq!(bv.get(1), Some(false));
        assert_eq!(bv.get(7), Some(true));
        assert_eq!(bv.get(8), None);
    }

    #[test]
    fn bitvector_encode_decode_roundtrip() {
        let mut bv = Bitvector::<8>::new();
        bv.set(0, true);
        bv.set(3, true);
        let encoded = bv.as_ssz_bytes();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], 0b00001001);
        let decoded = Bitvector::<8>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(bv, decoded);
    }

    #[test]
    fn bitvector_9_bits_encodes_to_2_bytes() {
        let mut bv = Bitvector::<9>::new();
        bv.set(8, true);
        let encoded = bv.as_ssz_bytes();
        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 1);
    }

    #[test]
    fn bitvector_tree_hash_known_root() {
        // Bitvector<8> with all bits zero should produce a specific root.
        // pack([0x00]) padded to 32 bytes = zero chunk.
        // merkleize with limit = (8+255)/256 = 1.
        // Result: merkleize_padded([zerochunk], 1) = zerochunk = zero_hash(0).
        let bv = Bitvector::<8>::new();
        let root = bv.tree_hash_root();
        // A single zero chunk merkleized with limit 1 (padded to pow2(1)=1) is the chunk itself.
        assert_eq!(root, Hash256::default());
    }

    #[test]
    fn bitvector_num_set_bits() {
        let mut bv = Bitvector::<16>::new();
        bv.set(0, true);
        bv.set(5, true);
        bv.set(15, true);
        assert_eq!(bv.num_set_bits(), 3);
    }

    // ── Bitlist tests ────────────────────────────────────────────────────────

    #[test]
    fn bitvector_decode_rejects_trailing_bits_set() {
        // Bitvector<5> fits in one byte; bits 5,6,7 must be zero.
        // 0b00111111 has bits 5 set — must reject.
        let err = Bitvector::<5>::from_ssz_bytes(&[0b0011_1111]).unwrap_err();
        assert_eq!(err, SszError::InvalidBitvector);

        // Bit 7 set alone — must also reject.
        let err = Bitvector::<5>::from_ssz_bytes(&[0b1000_0000]).unwrap_err();
        assert_eq!(err, SszError::InvalidBitvector);

        // 0b0001_1111 has only bits 0..4 set — accepted.
        let bv = Bitvector::<5>::from_ssz_bytes(&[0b0001_1111]).unwrap();
        for i in 0..5 {
            assert_eq!(bv.get(i), Some(true));
        }
    }

    #[test]
    fn bitvector_byte_aligned_accepts_full_last_byte() {
        // N=8 has no remainder; last byte may be 0xFF without rejection.
        let bv = Bitvector::<8>::from_ssz_bytes(&[0xFF]).unwrap();
        for i in 0..8 {
            assert_eq!(bv.get(i), Some(true));
        }
    }

    #[test]
    fn bitlist_empty_encodes_to_sentinel_byte() {
        let bl = Bitlist::<8>::new();
        let encoded = bl.as_ssz_bytes();
        assert_eq!(encoded, vec![0x01]);
    }

    #[test]
    fn bitlist_empty_decodes_from_sentinel_byte() {
        let bl = Bitlist::<8>::from_ssz_bytes(&[0x01]).unwrap();
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn bitlist_roundtrip_8_bits() {
        let mut bl = Bitlist::<16>::new();
        for i in 0..8 {
            bl.push(i % 2 == 0).unwrap();
        }
        let encoded = bl.as_ssz_bytes();
        let decoded = Bitlist::<16>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(bl, decoded);
    }

    #[test]
    fn bitlist_sentinel_bit_not_counted() {
        // Bitlist with 1 bit set to true.
        // Encoded: bit0 is the data bit, bit1 is the sentinel.
        // Byte 0: bit0=1, bit1=1(sentinel) → 0b00000011 = 0x03
        let mut bl = Bitlist::<8>::new();
        bl.push(true).unwrap();
        let encoded = bl.as_ssz_bytes();
        assert_eq!(encoded, vec![0x03]);
        let decoded = Bitlist::<8>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.get(0), Some(true));
    }

    #[test]
    fn bitlist_length_overflow_rejected() {
        // Create a bitlist with N bits (at the limit), and try to decode one with N+1.
        // Manually craft: 8 bits + sentinel = 2 bytes.
        // byte0 = 0xFF (bits 0..7 all set), byte1 = 0x01 (sentinel at bit 8)
        let bytes = vec![0xFF, 0x01];
        // N=8: bit_len would be 8, which equals N, so ok.
        let decoded8 = Bitlist::<8>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded8.len(), 8);

        // N=7: bit_len=8 > 7, rejected.
        assert!(matches!(
            Bitlist::<7>::from_ssz_bytes(&bytes),
            Err(SszError::BitlistOverflow { limit: 7 })
        ));
    }

    #[test]
    fn bitlist_missing_sentinel_rejected() {
        assert!(matches!(
            Bitlist::<8>::from_ssz_bytes(&[0x00]),
            Err(SszError::BitlistMissingLengthBit)
        ));
    }

    #[test]
    fn bitlist_empty_bytes_rejected() {
        assert!(matches!(
            Bitlist::<8>::from_ssz_bytes(&[]),
            Err(SszError::BitlistMissingLengthBit)
        ));
    }

    #[test]
    fn bitlist_tree_hash_empty() {
        // Empty bitlist: pack_bits = [], limit = 1, root = zero, mix_in_length(root, 0).
        let bl = Bitlist::<8>::new();
        let root = bl.tree_hash_root();
        // merkleize_padded([], 1) = merkleize([zero_chunk]) = zero_chunk
        // mix_in_length(zero_chunk, 0) = hash(zero, zero_length_bytes)
        let zero_root = crate::tree_hash::merkleize_padded(&[], 1);
        let expected = crate::tree_hash::mix_in_length(zero_root, 0);
        assert_eq!(root, expected);
    }

    #[test]
    fn bitlist_num_set_bits() {
        let mut bl = Bitlist::<32>::new();
        bl.push(true).unwrap();
        bl.push(false).unwrap();
        bl.push(true).unwrap();
        assert_eq!(bl.num_set_bits(), 2);
    }
}
