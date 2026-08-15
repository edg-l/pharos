//! SSZ Merkleization — `TreeHash` trait, `TreeHashType` enum, and helpers.
//!
//! Implements the `hash_tree_root` specification from
//! `consensus-specs/ssz/simple-serialize.md § Merkleization`.
//!
//! # Merkleization rules summary
//!
//! | SSZ type                | Rule                                                          |
//! |-------------------------|---------------------------------------------------------------|
//! | Basic / vector of basic | `merkleize(pack(value))` — **no limit**                      |
//! | Bitvector               | `merkleize(pack_bits(value), limit=chunk_count)`             |
//! | Bitlist                 | `mix_in_length(merkleize(pack_bits, limit=chunk_count), len)`|
//! | List of basic           | `mix_in_length(merkleize(pack, limit=chunk_count), len)`     |
//! | List of composite       | `mix_in_length(merkleize(roots, limit=N), len)`              |
//! | Vector of composite     | `merkleize(roots)` — **no limit**                            |
//! | Container               | `merkleize([field.tree_hash_root() for field in self])`      |
//!
//! # Zero-hash caching
//!
//! The zero hashes for each tree depth (0..64) are computed once and stored in
//! a static `OnceLock`. Each `zero_hash(depth)` is the root of a fully-zeroed
//! subtree of the given height.

use pharos_utils::{FixedBytes, Hash256, Uint256, hash::hash_concat};
use rayon::prelude::*;
use std::sync::OnceLock;

// ── TreeHashType ──────────────────────────────────────────────────────────────

/// Identifies the Merkleization strategy for a type.
///
/// Used as an associated const on `TreeHash` so that collection types can
/// branch on the element's Merkleization rules (e.g. `List` of basic vs.
/// `List` of composite).
///
/// Mapping to spec rules:
/// - `Basic`     — pack LE-encoded bytes, merkleize without limit.
/// - `Container` — merkleize per-field roots, no limit.
/// - `Vector` — basic elements: pack-and-merkleize (no limit);
///   composite elements: merkleize per-element roots (no limit).
/// - `List` — basic elements: pack, merkleize with `chunk_count` limit,
///   mix in length; composite: merkleize roots with limit N, mix in length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeHashType {
    /// Basic SSZ type (`uintN`, `boolean`, `FixedBytes` ≤ 32 bytes).
    Basic,
    /// SSZ container (struct with named fields).
    Container,
    /// Fixed-length homogeneous collection (`Vector[T, N]`).
    Vector,
    /// Variable-length homogeneous collection with a limit (`List[T, N]`).
    List,
}

// ── TreeHash trait ────────────────────────────────────────────────────────────

/// SSZ Merkleization trait.
///
/// Every type that can contribute to an SSZ `hash_tree_root` computation
/// implements this trait. The derive macro `#[derive(TreeHash)]` generates an
/// implementation for structs (containers).
///
/// # Caching note
///
/// The signature `fn tree_hash_root(&self) -> Hash256` is forward-compatible
/// with both interior-mutable per-node caching (planned for the persistent
/// tree) and external cache maps. M0 does not cache; each call recomputes.
pub trait TreeHash {
    /// Identifies the Merkleization strategy for this type.
    const TREE_HASH_TYPE: TreeHashType;

    /// True for `Basic` types whose packed encoding occupies exactly one
    /// 32-byte chunk on its own, and whose `tree_hash_root` equals that chunk.
    ///
    /// Only `FixedBytes<32>` (and its aliases `Hash256` / `Root` / `Bytes32`)
    /// override this to `true`. Other basics (`u64`, `u8`, `bool`,
    /// `FixedBytes<N<32>`) pack multiple-per-chunk and the override stays
    /// `false`.
    ///
    /// Used by the tree-backed `SszList` / `SszVector` to admit `FixedBytes<32>`
    /// element types while still rejecting genuinely packed basics that would
    /// produce divergent roots in the path-copy tree (see `from_vec_tree`).
    const PACKED_AS_FULL_CHUNK: bool = false;

    /// Compute the SSZ `hash_tree_root` of this value.
    fn tree_hash_root(&self) -> Hash256;

    /// Return the packed byte encoding used when this value appears as an
    /// element of a basic-type vector or list.
    ///
    /// Only meaningful when `TREE_HASH_TYPE == TreeHashType::Basic`.
    /// Composite types must mark this `unreachable!()`.
    fn tree_hash_packed_encoding(&self) -> Vec<u8>;
}

// ── zero-hash table ───────────────────────────────────────────────────────────

static ZERO_HASHES: OnceLock<[Hash256; 64]> = OnceLock::new();

/// Return the zero-hash at the given tree depth.
///
/// `zero_hash(0)` is `Hash256::default()` (32 zero bytes).
/// `zero_hash(d)` is `hash(zero_hash(d-1), zero_hash(d-1))`.
pub fn zero_hash(depth: usize) -> Hash256 {
    assert!(depth < 64, "depth must be < 64");
    let table = ZERO_HASHES.get_or_init(|| {
        let mut t = [Hash256::default(); 64];
        for d in 1..64 {
            let prev = t[d - 1];
            t[d] = hash_concat(prev.as_ref(), prev.as_ref());
        }
        t
    });
    table[depth]
}

// ── merkleization helpers ─────────────────────────────────────────────────────

/// Return the smallest power of two ≥ `n`, with `0` mapping to `1`.
///
/// Matches the spec's `next_pow_of_two`. Crate-internal: used by
/// `merkle_proof` and the merkleize helpers.
pub(crate) fn next_pow_of_two(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    n.next_power_of_two()
}

/// Concatenate the packed encodings of each element in `elems` into a single
/// byte buffer.
///
/// Shared between `[T; N]`, `SszVector<T, N>`, and `SszList<T, N>` for the
/// basic-element merkleization path: the result is fed to `pack_bytes_to_chunks`
/// before merkleization.
pub fn pack_basic_elems_bytes<T: TreeHash>(elems: &[T]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for elem in elems {
        bytes.extend_from_slice(&elem.tree_hash_packed_encoding());
    }
    bytes
}

/// Pack a byte slice into 32-byte chunks, right-padding the final chunk with
/// zeros if necessary.
///
/// Corresponds to `pack(values)` in the spec when applied to a pre-serialized
/// byte string.
pub fn pack_bytes_to_chunks(bytes: &[u8]) -> Vec<Hash256> {
    if bytes.is_empty() {
        return vec![];
    }
    bytes
        .chunks(32)
        .map(|chunk| {
            let mut arr = [0u8; 32];
            arr[..chunk.len()].copy_from_slice(chunk);
            Hash256::from_array(arr)
        })
        .collect()
}

/// Merkleize a slice of 32-byte chunks without a limit.
///
/// - Empty input is treated as a single zero chunk (per spec).
/// - Pads to the next power of two with zero hashes, then builds the binary
///   tree bottom-up.
pub fn merkleize(chunks: &[Hash256]) -> Hash256 {
    if chunks.is_empty() {
        return zero_hash(0);
    }
    let n = next_pow_of_two(chunks.len());
    merkleize_padded_inner(chunks, n)
}

/// Merkleize with an explicit limit (max chunk count after padding).
///
/// Used for lists and bitvectors: pads `chunks` up to `next_pow_of_two(limit)`
/// with zero hashes.
///
/// Per `simple-serialize.md`, `chunks.len() > limit` is a programming error in
/// the caller (the caller must validate length before merkleizing). This
/// function panics in that case rather than silently producing a wrong root.
pub fn merkleize_padded(chunks: &[Hash256], limit: usize) -> Hash256 {
    assert!(
        chunks.len() <= limit,
        "merkleize_padded: chunks.len() ({}) exceeds limit ({})",
        chunks.len(),
        limit
    );
    if chunks.is_empty() && limit == 0 {
        return zero_hash(0);
    }
    let n = next_pow_of_two(limit.max(1));
    merkleize_padded_inner(chunks, n)
}

fn merkleize_padded_inner(chunks: &[Hash256], padded_len: usize) -> Hash256 {
    // Efficient implementation using pre-computed zero hashes.
    //
    // Rather than materializing `padded_len` leaf nodes (which can be
    // enormous for large limits like `VALIDATOR_REGISTRY_LIMIT = 2^40`),
    // we process only the chunks that are actually present and fold in
    // the zero-hash subtrees at the appropriate depths.
    //
    // The algorithm:
    // 1. Start with the actual chunks as the leaf layer.
    // 2. At each level, pair adjacent nodes; if an odd node is left over,
    //    pair it with the zero-hash at that level.
    // 3. Repeat until a single root is produced.
    //
    // Depth here means the height of the subtrees represented by
    // zero_hash(depth): zero_hash(0) = zero leaf, zero_hash(1) = two zero
    // leaves combined, etc.
    let total_depth = padded_len.trailing_zeros() as usize; // padded_len is a power of two
    debug_assert!(
        padded_len.is_power_of_two(),
        "padded_len must be a power of two; got {padded_len}"
    );

    if chunks.is_empty() {
        return zero_hash(total_depth);
    }

    // Ping-pong between two buffers across tree levels, reusing the
    // allocations instead of growing a fresh `Vec` per depth.
    //
    // Within a level, pair-hashes are independent → parallelize when the
    // level has enough pairs to overcome rayon scheduling overhead.
    let mut current: Vec<Hash256> = chunks.to_vec();
    let mut next: Vec<Hash256> = Vec::with_capacity(current.len().div_ceil(2));
    const PAR_PAIRS_THRESHOLD: usize = 16;
    for depth in 0..total_depth {
        next.clear();
        let pair_count = current.len() / 2;
        let odd_remainder = current.len() % 2;
        if pair_count >= PAR_PAIRS_THRESHOLD {
            next.resize(pair_count + odd_remainder, Hash256::default());
            next[..pair_count]
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, slot)| {
                    let a = &current[2 * i];
                    let b = &current[2 * i + 1];
                    *slot = hash_concat(a.as_ref(), b.as_ref());
                });
            if odd_remainder == 1 {
                let last = &current[2 * pair_count];
                next[pair_count] = hash_concat(last.as_ref(), zero_hash(depth).as_ref());
            }
        } else {
            let mut iter = current.chunks_exact(2);
            for pair in iter.by_ref() {
                next.push(hash_concat(pair[0].as_ref(), pair[1].as_ref()));
            }
            // If the layer has an odd node, pair it with the zero subtree at this depth.
            if let [last] = iter.remainder() {
                next.push(hash_concat(last.as_ref(), zero_hash(depth).as_ref()));
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    debug_assert_eq!(current.len(), 1, "should have reduced to a single root");
    current[0]
}

/// Mix a Merkle root with a length value (SSZ `mix_in_length`).
///
/// `mix_in_length(root, length) = hash(root, uint256(length).to_le_bytes())`
pub fn mix_in_length(root: Hash256, length: u64) -> Hash256 {
    let mut len_bytes = [0u8; 32];
    len_bytes[0..8].copy_from_slice(&length.to_le_bytes());
    hash_concat(root.as_ref(), &len_bytes)
}

/// Mix a Merkle root with a union type selector (SSZ `mix_in_selector`).
///
/// `mix_in_selector(root, selector) = hash(root, uint8(selector) padded to 32 bytes)`
pub fn mix_in_selector(root: Hash256, selector: u8) -> Hash256 {
    let mut sel_bytes = [0u8; 32];
    sel_bytes[0] = selector;
    hash_concat(root.as_ref(), &sel_bytes)
}

// ── primitive TreeHash impls ──────────────────────────────────────────────────

impl TreeHash for bool {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Basic;

    fn tree_hash_root(&self) -> Hash256 {
        let mut chunk = [0u8; 32];
        chunk[0] = u8::from(*self);
        Hash256::from_array(chunk)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        vec![u8::from(*self)]
    }
}

macro_rules! impl_tree_hash_uint {
    ($t:ty) => {
        impl TreeHash for $t {
            const TREE_HASH_TYPE: TreeHashType = TreeHashType::Basic;

            fn tree_hash_root(&self) -> Hash256 {
                let bytes = self.to_le_bytes();
                let mut chunk = [0u8; 32];
                chunk[..bytes.len()].copy_from_slice(&bytes);
                Hash256::from_array(chunk)
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
        }
    };
}

impl_tree_hash_uint!(u8);
impl_tree_hash_uint!(u16);
impl_tree_hash_uint!(u32);
impl_tree_hash_uint!(u64);
impl_tree_hash_uint!(u128);

impl TreeHash for Uint256 {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Basic;

    fn tree_hash_root(&self) -> Hash256 {
        // Uint256 is exactly 32 bytes in LE — it fills one chunk.
        Hash256::from_array(self.to_le_bytes())
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

/// `FixedBytes<N>` Merkleization.
///
/// - `N <= 32`: fits in a single chunk — `Basic` type (right-padded to 32 bytes).
/// - `N > 32`: pack into multiple chunks, merkleize without limit — treated as
///   a `Vector` of bytes. This covers `BLSPubkey` (48 bytes) and
///   `BLSSignature` (96 bytes).
impl<const N: usize> TreeHash for FixedBytes<N> {
    const TREE_HASH_TYPE: TreeHashType = if N <= 32 {
        TreeHashType::Basic
    } else {
        TreeHashType::Vector
    };

    /// `FixedBytes<32>` (the only basic FixedBytes that occupies a full chunk
    /// on its own) is admissible as a tree-backend leaf type.
    const PACKED_AS_FULL_CHUNK: bool = N == 32;

    fn tree_hash_root(&self) -> Hash256 {
        let chunks = pack_bytes_to_chunks(self.as_ref());
        merkleize(&chunks)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        // Only basic-typed `FixedBytes<N>` (N <= 32) participate in packing
        // when nested inside a parent container. For N > 32 the type is
        // `Vector`-kind and must merkleize directly via `tree_hash_root`.
        if N <= 32 {
            self.as_ref().to_vec()
        } else {
            unreachable!("tree_hash_packed_encoding called on composite FixedBytes<{N}>");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_utils::Hash256;

    #[test]
    fn uint64_one_tree_hash_root() {
        // hash_tree_root(uint64(1)) == 0x0100000000000000000000000000000000000000000000000000000000000000
        let root = 1u64.tree_hash_root();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(root, Hash256::from_array(expected));
    }

    #[test]
    fn bool_false_tree_hash_root() {
        let root = false.tree_hash_root();
        assert_eq!(root, Hash256::default());
    }

    #[test]
    fn bool_true_tree_hash_root() {
        let root = true.tree_hash_root();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(root, Hash256::from_array(expected));
    }

    #[test]
    fn hash256_identity_tree_hash() {
        // For a FixedBytes<32>, tree_hash_root is just the bytes themselves (single chunk).
        let h: Hash256 = Hash256::from_array([1u8; 32]);
        assert_eq!(h.tree_hash_root(), h);
    }

    #[test]
    fn zero_hash_depth_zero_is_default() {
        assert_eq!(zero_hash(0), Hash256::default());
    }

    #[test]
    fn merkleize_empty_is_zero() {
        assert_eq!(merkleize(&[]), zero_hash(0));
    }

    #[test]
    fn merkleize_single_chunk() {
        let chunk = Hash256::from_array([1u8; 32]);
        assert_eq!(merkleize(&[chunk]), chunk);
    }

    #[test]
    fn merkleize_two_chunks() {
        let a = Hash256::from_array([1u8; 32]);
        let b = Hash256::from_array([2u8; 32]);
        let expected = hash_concat(a.as_ref(), b.as_ref());
        assert_eq!(merkleize(&[a, b]), expected);
    }

    #[test]
    fn pack_bytes_empty() {
        assert!(pack_bytes_to_chunks(&[]).is_empty());
    }

    #[test]
    fn pack_bytes_single_partial_chunk() {
        let bytes = [1u8, 2, 3];
        let chunks = pack_bytes_to_chunks(&bytes);
        assert_eq!(chunks.len(), 1);
        let mut expected = [0u8; 32];
        expected[..3].copy_from_slice(&bytes);
        assert_eq!(chunks[0], Hash256::from_array(expected));
    }

    #[test]
    fn mix_in_length_zero() {
        let root = Hash256::default();
        let result = mix_in_length(root, 0);
        // hash(zero_root, zero_length_bytes)
        let len_bytes = [0u8; 32];
        let expected = hash_concat(root.as_ref(), &len_bytes);
        assert_eq!(result, expected);
    }

    #[test]
    fn mix_in_length_nonzero_little_endian() {
        let root = Hash256::from_array([0xAA; 32]);
        let result = mix_in_length(root, 0x0102030405060708u64);
        let mut len_bytes = [0u8; 32];
        len_bytes[..8].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        let expected = hash_concat(root.as_ref(), &len_bytes);
        assert_eq!(result, expected);
        // And confirm the length encoding is LE, not BE.
        assert_eq!(len_bytes[0], 0x08);
        assert_eq!(len_bytes[7], 0x01);
    }

    #[test]
    fn fixed_bytes_48_tree_hash_two_chunks() {
        // BLSPubkey is FixedBytes<48> — packed into 2 chunks (32 + 16+pad),
        // merkleized as hash(chunk0, chunk1).
        use pharos_utils::FixedBytes;
        let bytes = FixedBytes::<48>::from_array([0xCD; 48]);
        let mut c0 = [0u8; 32];
        let mut c1 = [0u8; 32];
        c0.copy_from_slice(&[0xCD; 32]);
        c1[..16].copy_from_slice(&[0xCD; 16]);
        let expected = hash_concat(&c0, &c1);
        assert_eq!(bytes.tree_hash_root(), expected);
    }

    #[test]
    fn fixed_bytes_96_tree_hash_four_chunks() {
        // BLSSignature is FixedBytes<96> — exactly 3 chunks; padded to 4
        // (next power of two), merkleized as a balanced tree.
        use pharos_utils::FixedBytes;
        let bytes = FixedBytes::<96>::from_array([0xEF; 96]);
        let chunk = [0xEF; 32];
        let zero = [0u8; 32];
        let h01 = hash_concat(&chunk, &chunk);
        let h23 = hash_concat(&chunk, &zero);
        let expected = hash_concat(h01.as_ref(), h23.as_ref());
        assert_eq!(bytes.tree_hash_root(), expected);
    }

    // ── merkleize_padded zero-folding correctness ─────────────────────────────

    /// Naive reference implementation: materialize the full padded leaf array
    /// and pair-hash bottom-up. Used to cross-check the optimised version that
    /// folds zero-hash subtrees without materializing them.
    fn naive_merkleize_padded(chunks: &[Hash256], limit: usize) -> Hash256 {
        assert!(chunks.len() <= limit, "naive: chunks.len() exceeds limit");
        let n = next_pow_of_two(limit.max(1));
        let mut layer: Vec<Hash256> = Vec::with_capacity(n);
        layer.extend_from_slice(chunks);
        while layer.len() < n {
            layer.push(zero_hash(0));
        }
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks_exact(2) {
                next.push(hash_concat(pair[0].as_ref(), pair[1].as_ref()));
            }
            layer = next;
        }
        layer[0]
    }

    #[test]
    fn merkleize_padded_some_chunks_limit_larger() {
        // Case (a): 3 chunks present, limit = 8 (some zero-padded).
        let a = Hash256::from_array([0x01; 32]);
        let b = Hash256::from_array([0x02; 32]);
        let c = Hash256::from_array([0x03; 32]);
        let chunks = vec![a, b, c];
        let limit = 8;
        let got = merkleize_padded(&chunks, limit);
        let want = naive_merkleize_padded(&chunks, limit);
        assert_eq!(got, want, "3 chunks, limit=8");
    }

    #[test]
    fn merkleize_padded_limit_much_larger_than_chunks() {
        // Case (b): 3 chunks, limit = 1024.
        let a = Hash256::from_array([0xAA; 32]);
        let b = Hash256::from_array([0xBB; 32]);
        let c = Hash256::from_array([0xCC; 32]);
        let chunks = vec![a, b, c];
        let limit = 1024;
        let got = merkleize_padded(&chunks, limit);
        let want = naive_merkleize_padded(&chunks, limit);
        assert_eq!(got, want, "3 chunks, limit=1024");
    }

    #[test]
    fn merkleize_padded_limit_equals_chunks_len() {
        // Case (c): limit exactly matches chunks.len() (no zero padding needed).
        let a = Hash256::from_array([0x11; 32]);
        let b = Hash256::from_array([0x22; 32]);
        let c = Hash256::from_array([0x33; 32]);
        let d = Hash256::from_array([0x44; 32]);
        let chunks = vec![a, b, c, d];
        let limit = 4;
        let got = merkleize_padded(&chunks, limit);
        let want = naive_merkleize_padded(&chunks, limit);
        assert_eq!(got, want, "4 chunks, limit=4");
    }

    #[test]
    #[should_panic(expected = "merkleize_padded: chunks.len()")]
    fn merkleize_padded_rejects_oversized_input() {
        let chunks = vec![Hash256::default(); 5];
        // limit < chunks.len() must panic, not silently truncate.
        let _ = merkleize_padded(&chunks, 3);
    }

    #[test]
    fn uint256_tree_hash_root() {
        // hash_tree_root(uint256(1)) == 0x0100..00 (LE in one chunk)
        let v = Uint256::from(1u64);
        let root = v.tree_hash_root();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(root, Hash256::from_array(expected));
    }
}
