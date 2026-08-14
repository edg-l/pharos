//! `SszList<T, N>` and `SszVector<T, N>` — SSZ persistent collection types.
//!
//! Both types present a persistent (copy-on-write) API via `with_set` and
//! `with_push`. Phase 3 ships the `Naive(Vec<T>)` backend only; the
//! `Tree(Arc<Node>)` backend slot exists in the internal `Backend` enum and
//! will be filled in a later milestone.
//!
//! # Backend design
//!
//! ```text
//! enum Backend<T> {
//!     Naive(Vec<T>),        // Phase 3: fully implemented
//!     Tree(Arc<Node>),      // Future: unimplemented!() for every method
//! }
//! ```
//!
//! Containers and external callers only see `SszList<T, N>` / `SszVector<T, N>`
//! and the `SszSequence` trait. The `Backend` is a private implementation detail.
//!
//! # `SszList` vs `SszVector`
//!
//! | Type        | Length   | Limit | Mix-in length? |
//! |-------------|----------|-------|----------------|
//! | `SszList`   | variable | N max | yes            |
//! | `SszVector` | fixed=N  | none  | no             |

use std::marker::PhantomData;
use std::sync::Arc;

use crate::{
    decode::Decode,
    encode::{BYTES_PER_LENGTH_OFFSET, Encode},
    error::SszError,
    tree_hash::{
        TreeHash, TreeHashType, merkleize, merkleize_padded, mix_in_length, pack_bytes_to_chunks,
    },
};
use pharos_utils::Hash256;

// ── Backend enum (private) ────────────────────────────────────────────────────

/// Internal storage backend for `SszList` and `SszVector`.
///
/// Only the `Naive` variant is implemented. The `Tree` variant is reserved for
/// the persistent tree-backed implementation that arrives in a later milestone.
enum Backend<T> {
    /// Simple `Vec<T>` storage — clone-on-write.
    Naive(Vec<T>),
    /// Persistent hash-array-mapped trie (not yet implemented).
    #[allow(dead_code)]
    Tree(Arc<Node<T>>),
}

/// Placeholder for the future persistent tree node.
///
/// No methods are implemented; its presence in `Backend::Tree` satisfies the
/// compiler while keeping the enum slot reserved.
struct Node<T> {
    _marker: PhantomData<T>,
}

impl<T: Clone> Clone for Backend<T> {
    fn clone(&self) -> Self {
        match self {
            Backend::Naive(v) => Backend::Naive(v.clone()),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }
}

impl<T: PartialEq> PartialEq for Backend<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Backend::Naive(a), Backend::Naive(b)) => a == b,
            _ => unimplemented!("tree backend lands in a later milestone"),
        }
    }
}

impl<T: Eq> Eq for Backend<T> {}

impl<T: std::fmt::Debug> std::fmt::Debug for Backend<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Naive(v) => f.debug_tuple("Naive").field(v).finish(),
            Backend::Tree(_) => write!(f, "Tree(<unimplemented>)"),
        }
    }
}

// ── SszSequence trait ─────────────────────────────────────────────────────────

/// Persistent-friendly sequence trait shared by `SszList` and `SszVector`.
///
/// All mutating methods return a new instance rather than modifying in place.
/// This matches the copy-on-write semantics required by the persistent tree
/// backend and enables structural sharing in future implementations.
pub trait SszSequence<T, const N: u64>: Sized {
    /// The number of elements currently in the sequence.
    fn len(&self) -> usize;

    /// The maximum number of elements this sequence type can hold.
    fn capacity() -> u64 {
        N
    }

    /// `true` iff the sequence contains no elements.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a reference to the element at index `i`, or `None` if out of bounds.
    fn get(&self, i: usize) -> Option<&T>;

    /// Iterator over all elements in order.
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a
    where
        T: 'a;

    /// Return a new sequence with element `i` replaced by `v`.
    ///
    /// Returns `SszError::OffsetOutOfRange` if `i >= len()`.
    fn with_set(&self, i: usize, v: T) -> Result<Self, SszError>
    where
        T: Clone;

    /// Return a new sequence with `v` appended.
    ///
    /// For `SszList`: returns `SszError::ListLimitExceeded` if the push would
    /// exceed `N`. For `SszVector`: always returns `SszError::ListLimitExceeded`
    /// because the length is fixed.
    fn with_push(&self, v: T) -> Result<Self, SszError>
    where
        T: Clone;
}

// ── SszList<T, N> ─────────────────────────────────────────────────────────────

/// A variable-length SSZ list with a maximum of `N` elements.
///
/// Corresponds to `List[T, N]` in the SSZ spec. The length is validated on
/// decode; encoding is the standard SSZ variable-length encoding.
///
/// # Merkleization
///
/// `SszList::tree_hash_root` = `mix_in_length(merkleize_padded(roots, limit), len)`
/// where `limit` is `N` for composite elements or `chunk_count(T, N)` for basic
/// elements.
pub struct SszList<T, const N: u64> {
    backend: Backend<T>,
}

impl<T, const N: u64> SszList<T, N> {
    /// Construct an empty list.
    pub fn new() -> Self {
        Self {
            backend: Backend::Naive(Vec::new()),
        }
    }

    /// Construct a list from a `Vec<T>`.
    ///
    /// Returns `SszError::ListLimitExceeded` if `v.len() > N`.
    pub fn from_vec(v: Vec<T>) -> Result<Self, SszError> {
        if v.len() as u64 > N {
            return Err(SszError::ListLimitExceeded {
                len: v.len(),
                limit: N,
            });
        }
        Ok(Self {
            backend: Backend::Naive(v),
        })
    }

    /// Construct a list from an iterator.
    ///
    /// Returns `SszError::ListLimitExceeded` if the iterator yields more than `N`
    /// elements.
    pub fn from_items<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, SszError> {
        let v: Vec<T> = iter.into_iter().collect();
        Self::from_vec(v)
    }

    /// Return a reference to the underlying `Vec<T>` (Naive backend only).
    ///
    /// Primarily for merkleization and encoding, where direct slice access avoids
    /// repeated `get()` calls.
    fn as_slice(&self) -> &[T] {
        match &self.backend {
            Backend::Naive(v) => v.as_slice(),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }
}

impl<T, const N: u64> Default for SszList<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone, const N: u64> Clone for SszList<T, N> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
        }
    }
}

impl<T: PartialEq, const N: u64> PartialEq for SszList<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.backend == other.backend
    }
}

impl<T: Eq, const N: u64> Eq for SszList<T, N> {}

impl<T: std::fmt::Debug, const N: u64> std::fmt::Debug for SszList<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SszList<{N}>(")?;
        f.debug_list().entries(self.as_slice().iter()).finish()?;
        write!(f, ")")
    }
}

impl<T, const N: u64> SszSequence<T, N> for SszList<T, N> {
    fn len(&self) -> usize {
        match &self.backend {
            Backend::Naive(v) => v.len(),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn get(&self, i: usize) -> Option<&T> {
        match &self.backend {
            Backend::Naive(v) => v.get(i),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a
    where
        T: 'a,
    {
        // Use a concrete slice iterator for the Naive backend.
        // The Tree backend will supply its own iterator when implemented.
        match &self.backend {
            Backend::Naive(v) => v.iter(),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn with_set(&self, i: usize, v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        match &self.backend {
            Backend::Naive(vec) => {
                if i >= vec.len() {
                    return Err(SszError::OffsetOutOfRange {
                        offset: i,
                        max: vec.len().saturating_sub(1),
                    });
                }
                let mut new_vec = vec.clone();
                new_vec[i] = v;
                Ok(Self {
                    backend: Backend::Naive(new_vec),
                })
            }
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn with_push(&self, v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        match &self.backend {
            Backend::Naive(vec) => {
                if vec.len() as u64 >= N {
                    return Err(SszError::ListLimitExceeded {
                        len: vec.len() + 1,
                        limit: N,
                    });
                }
                let mut new_vec = vec.clone();
                new_vec.push(v);
                Ok(Self {
                    backend: Backend::Naive(new_vec),
                })
            }
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }
}

// ── SszVector<T, N> ───────────────────────────────────────────────────────────

/// A fixed-length SSZ vector of exactly `N` elements.
///
/// Corresponds to `Vector[T, N]` in the SSZ spec. The length is enforced on
/// construction and decode: it is always exactly `N`.
///
/// # Merkleization
///
/// `SszVector::tree_hash_root` uses no limit (vectors are not padded with a
/// size bound):
/// - Basic elements: `merkleize(pack(values))`
/// - Composite elements: `merkleize([e.tree_hash_root() for e in self])`
pub struct SszVector<T, const N: u64> {
    backend: Backend<T>,
}

impl<T, const N: u64> SszVector<T, N> {
    /// Construct a vector from a `Vec<T>`.
    ///
    /// Returns `SszError::VectorLengthMismatch` if `v.len() != N`.
    pub fn from_vec(v: Vec<T>) -> Result<Self, SszError> {
        if v.len() != N as usize {
            return Err(SszError::VectorLengthMismatch {
                found: v.len(),
                expected: N as usize,
            });
        }
        Ok(Self {
            backend: Backend::Naive(v),
        })
    }

    /// Construct a vector from an iterator.
    ///
    /// Returns `SszError::VectorLengthMismatch` if the iterator does not yield
    /// exactly `N` elements.
    pub fn from_items<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, SszError> {
        let v: Vec<T> = iter.into_iter().collect();
        Self::from_vec(v)
    }

    /// Return a reference to the underlying slice.
    fn as_slice(&self) -> &[T] {
        match &self.backend {
            Backend::Naive(v) => v.as_slice(),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }
}

impl<T: Clone + Default, const N: u64> Default for SszVector<T, N> {
    fn default() -> Self {
        Self {
            backend: Backend::Naive(vec![T::default(); N as usize]),
        }
    }
}

impl<T: Clone, const N: u64> Clone for SszVector<T, N> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
        }
    }
}

impl<T: PartialEq, const N: u64> PartialEq for SszVector<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.backend == other.backend
    }
}

impl<T: Eq, const N: u64> Eq for SszVector<T, N> {}

impl<T: std::fmt::Debug, const N: u64> std::fmt::Debug for SszVector<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SszVector<{N}>(")?;
        f.debug_list().entries(self.as_slice().iter()).finish()?;
        write!(f, ")")
    }
}

impl<T, const N: u64> SszSequence<T, N> for SszVector<T, N> {
    fn len(&self) -> usize {
        N as usize
    }

    fn get(&self, i: usize) -> Option<&T> {
        match &self.backend {
            Backend::Naive(v) => v.get(i),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a
    where
        T: 'a,
    {
        match &self.backend {
            Backend::Naive(v) => v.iter(),
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn with_set(&self, i: usize, v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        match &self.backend {
            Backend::Naive(vec) => {
                if i >= N as usize {
                    return Err(SszError::OffsetOutOfRange {
                        offset: i,
                        max: N as usize - 1,
                    });
                }
                let mut new_vec = vec.clone();
                new_vec[i] = v;
                Ok(Self {
                    backend: Backend::Naive(new_vec),
                })
            }
            Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone"),
        }
    }

    fn with_push(&self, _v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        // Vectors have fixed length; push is always an error.
        Err(SszError::ListLimitExceeded {
            len: N as usize + 1,
            limit: N,
        })
    }
}

// ── Encode for SszList<T, N> ──────────────────────────────────────────────────

impl<T, const N: u64> Encode for SszList<T, N>
where
    T: Encode,
{
    /// Lists are always variable-size (their length varies).
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        let elems = self.as_slice();
        if T::IS_FIXED_SIZE {
            elems.len() * T::ssz_fixed_len()
        } else {
            // Each element contributes its own bytes + a 4-byte offset slot.
            let offsets_len = elems.len() * BYTES_PER_LENGTH_OFFSET;
            let data_len: usize = elems.iter().map(|e| e.ssz_bytes_len()).sum();
            offsets_len + data_len
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let elems = self.as_slice();
        if T::IS_FIXED_SIZE {
            for elem in elems {
                elem.ssz_append(buf);
            }
        } else {
            // Variable-element list: offsets then data.
            let fixed_region_len = elems.len() * BYTES_PER_LENGTH_OFFSET;
            let mut variable_parts: Vec<Vec<u8>> = Vec::with_capacity(elems.len());
            for elem in elems {
                variable_parts.push(elem.as_ssz_bytes());
            }
            let mut running_offset = fixed_region_len;
            for part in &variable_parts {
                buf.extend_from_slice(&(running_offset as u32).to_le_bytes());
                running_offset += part.len();
            }
            for part in variable_parts {
                buf.extend_from_slice(&part);
            }
        }
    }
}

// ── Decode for SszList<T, N> ──────────────────────────────────────────────────

impl<T, const N: u64> Decode for SszList<T, N>
where
    T: Decode,
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let items = decode_list_items::<T>(bytes)?;
        let len = items.len();
        if len as u64 > N {
            return Err(SszError::ListLimitExceeded { len, limit: N });
        }
        Ok(Self {
            backend: Backend::Naive(items),
        })
    }
}

// ── Encode for SszVector<T, N> ────────────────────────────────────────────────

impl<T, const N: u64> Encode for SszVector<T, N>
where
    T: Encode,
{
    const IS_FIXED_SIZE: bool = T::IS_FIXED_SIZE;

    fn ssz_fixed_len() -> usize {
        if T::IS_FIXED_SIZE {
            T::ssz_fixed_len() * N as usize
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        let elems = self.as_slice();
        if T::IS_FIXED_SIZE {
            elems.len() * T::ssz_fixed_len()
        } else {
            let offsets_len = elems.len() * BYTES_PER_LENGTH_OFFSET;
            let data_len: usize = elems.iter().map(|e| e.ssz_bytes_len()).sum();
            offsets_len + data_len
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let elems = self.as_slice();
        if T::IS_FIXED_SIZE {
            for elem in elems {
                elem.ssz_append(buf);
            }
        } else {
            let fixed_region_len = elems.len() * BYTES_PER_LENGTH_OFFSET;
            let mut variable_parts: Vec<Vec<u8>> = Vec::with_capacity(elems.len());
            for elem in elems {
                variable_parts.push(elem.as_ssz_bytes());
            }
            let mut running_offset = fixed_region_len;
            for part in &variable_parts {
                buf.extend_from_slice(&(running_offset as u32).to_le_bytes());
                running_offset += part.len();
            }
            for part in variable_parts {
                buf.extend_from_slice(&part);
            }
        }
    }
}

// ── Decode for SszVector<T, N> ────────────────────────────────────────────────

impl<T, const N: u64> Decode for SszVector<T, N>
where
    T: Decode,
{
    const IS_FIXED_SIZE: bool = T::IS_FIXED_SIZE;

    fn ssz_fixed_len() -> usize {
        if T::IS_FIXED_SIZE {
            T::ssz_fixed_len() * N as usize
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        let items = decode_list_items::<T>(bytes)?;
        let found = items.len();
        let expected = N as usize;
        if found != expected {
            return Err(SszError::VectorLengthMismatch { found, expected });
        }
        Ok(Self {
            backend: Backend::Naive(items),
        })
    }
}

// ── TreeHash for SszList<T, N> ────────────────────────────────────────────────

impl<T, const N: u64> TreeHash for SszList<T, N>
where
    T: TreeHash + Encode,
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::List;

    fn tree_hash_root(&self) -> Hash256 {
        let elems = self.as_slice();
        let len = elems.len() as u64;

        let root = match T::TREE_HASH_TYPE {
            TreeHashType::Basic => {
                // Pack all packed encodings then merkleize with basic chunk_count limit.
                // chunk_count(List[B, N]) = ceil(N * size_of(B) / 32)
                // size_of(B) is T::ssz_fixed_len() for basic types.
                let elem_size = T::ssz_fixed_len() as u64;
                let limit = (N * elem_size).div_ceil(32) as usize;
                let mut bytes: Vec<u8> = Vec::new();
                for elem in elems {
                    bytes.extend_from_slice(&elem.tree_hash_packed_encoding());
                }
                let chunks = pack_bytes_to_chunks(&bytes);
                merkleize_padded(&chunks, limit)
            }
            _ => {
                // Composite elements: per-element roots with limit = N.
                let roots: Vec<Hash256> = elems.iter().map(|e| e.tree_hash_root()).collect();
                let limit = N as usize;
                merkleize_padded(&roots, limit)
            }
        };

        mix_in_length(root, len)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("SszList is not a basic type and is never packed")
    }
}

// ── TreeHash for SszVector<T, N> ──────────────────────────────────────────────

impl<T, const N: u64> TreeHash for SszVector<T, N>
where
    T: TreeHash + Encode,
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Vector;

    fn tree_hash_root(&self) -> Hash256 {
        let elems = self.as_slice();

        match T::TREE_HASH_TYPE {
            TreeHashType::Basic => {
                // Pack all packed encodings then merkleize WITHOUT a limit.
                let mut bytes: Vec<u8> = Vec::new();
                for elem in elems {
                    bytes.extend_from_slice(&elem.tree_hash_packed_encoding());
                }
                let chunks = pack_bytes_to_chunks(&bytes);
                merkleize(&chunks)
            }
            _ => {
                // Composite elements: per-element roots, no limit.
                let roots: Vec<Hash256> = elems.iter().map(|e| e.tree_hash_root()).collect();
                merkleize(&roots)
            }
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("SszVector is not a basic type and is never packed")
    }
}

// ── shared decode helper ──────────────────────────────────────────────────────

/// Decode a flat byte slice into a `Vec<T>`, handling both fixed and variable
/// element sizes.
///
/// Used by both `SszList::from_ssz_bytes` and `SszVector::from_ssz_bytes`.
/// Length validation (limit check for list, exact check for vector) is done by
/// the caller.
fn decode_list_items<T: Decode>(bytes: &[u8]) -> Result<Vec<T>, SszError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    if T::IS_FIXED_SIZE {
        let elem_len = T::ssz_fixed_len();
        if elem_len == 0 {
            return Err(SszError::Custom(
                "zero-size element type in list/vector".to_string(),
            ));
        }
        if bytes.len() % elem_len != 0 {
            return Err(SszError::InvalidByteLength {
                found: bytes.len(),
                expected: (bytes.len() / elem_len) * elem_len,
            });
        }
        let count = bytes.len() / elem_len;
        let mut items = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * elem_len;
            items.push(T::from_ssz_bytes(&bytes[start..start + elem_len])?);
        }
        Ok(items)
    } else {
        // Variable-element decoding: read offset table, validate, slice regions.
        if bytes.len() < BYTES_PER_LENGTH_OFFSET {
            return Err(SszError::IncompleteData {
                needed: BYTES_PER_LENGTH_OFFSET,
                found: bytes.len(),
            });
        }
        // First offset tells us the length of the fixed (offset) region.
        let first_offset =
            u32::from_le_bytes(bytes[..4].try_into().expect("checked above")) as usize;

        if first_offset % BYTES_PER_LENGTH_OFFSET != 0 {
            return Err(SszError::OffsetIntoFixedRegion);
        }
        if first_offset > bytes.len() {
            return Err(SszError::OffsetOutOfRange {
                offset: first_offset,
                max: bytes.len(),
            });
        }

        let count = first_offset / BYTES_PER_LENGTH_OFFSET;
        if count == 0 {
            // A legitimately empty variable-element list is encoded as zero
            // bytes; if the buffer is non-empty here the input is malformed
            // (offset table claims zero elements but bytes follow).
            if !bytes.is_empty() {
                return Err(SszError::ExtraBytes { extra: bytes.len() });
            }
            return Ok(Vec::new());
        }

        // Read all offsets.
        let mut offsets = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * BYTES_PER_LENGTH_OFFSET;
            let off =
                u32::from_le_bytes(bytes[start..start + 4].try_into().expect("bounds checked"))
                    as usize;
            offsets.push(off);
        }

        // Validate each offset.
        for (i, &off) in offsets.iter().enumerate() {
            if off < first_offset {
                return Err(SszError::OffsetIntoFixedRegion);
            }
            if off > bytes.len() {
                return Err(SszError::OffsetOutOfRange {
                    offset: off,
                    max: bytes.len(),
                });
            }
            if i > 0 && off < offsets[i - 1] {
                return Err(SszError::OffsetsNotMonotonic);
            }
        }

        // Decode each element.
        let mut items = Vec::with_capacity(count);
        for i in 0..count {
            let start = offsets[i];
            let end = if i + 1 < count {
                offsets[i + 1]
            } else {
                bytes.len()
            };
            items.push(T::from_ssz_bytes(&bytes[start..end])?);
        }
        Ok(items)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_hash::merkleize_padded;

    // ── SszList basic tests ──────────────────────────────────────────────────

    #[test]
    fn list_new_is_empty() {
        let list = SszList::<u64, 1024>::new();
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());
    }

    #[test]
    fn list_from_vec_roundtrip() {
        let items: Vec<u64> = vec![1, 2, 3, 4];
        let list = SszList::<u64, 1024>::from_vec(items.clone()).unwrap();
        assert_eq!(list.len(), 4);
        for (i, &v) in items.iter().enumerate() {
            assert_eq!(list.get(i), Some(&v));
        }
    }

    #[test]
    fn list_from_vec_limit_exceeded() {
        let items: Vec<u64> = vec![0u64; 5];
        let err = SszList::<u64, 4>::from_vec(items).unwrap_err();
        assert!(matches!(
            err,
            SszError::ListLimitExceeded { len: 5, limit: 4 }
        ));
    }

    #[test]
    fn list_with_push_and_set() {
        let list = SszList::<u64, 4>::new();
        let list = list.with_push(10).unwrap();
        let list = list.with_push(20).unwrap();
        assert_eq!(list.len(), 2);
        let list2 = list.with_set(0, 99).unwrap();
        assert_eq!(list2.get(0), Some(&99u64));
        assert_eq!(list2.get(1), Some(&20u64));
        // Original unchanged.
        assert_eq!(list.get(0), Some(&10u64));
    }

    #[test]
    fn list_with_push_at_limit_errors() {
        let list = SszList::<u64, 2>::from_vec(vec![1, 2]).unwrap();
        assert!(matches!(
            list.with_push(3),
            Err(SszError::ListLimitExceeded { .. })
        ));
    }

    #[test]
    fn list_encode_decode_roundtrip_fixed_elem() {
        let list = SszList::<u64, 1024>::from_vec(vec![1u64, 2, 3]).unwrap();
        let encoded = list.as_ssz_bytes();
        assert_eq!(encoded.len(), 3 * 8);
        let decoded = SszList::<u64, 1024>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(list, decoded);
    }

    #[test]
    fn list_decode_limit_exceeded_error() {
        // Encode 5 u64s then try to decode as SszList<u64, 4>
        let raw_list = SszList::<u64, 1024>::from_vec(vec![1u64, 2, 3, 4, 5]).unwrap();
        let encoded = raw_list.as_ssz_bytes();
        let err = SszList::<u64, 4>::from_ssz_bytes(&encoded).unwrap_err();
        assert!(matches!(
            err,
            SszError::ListLimitExceeded { len: 5, limit: 4 }
        ));
    }

    #[test]
    fn list_empty_encodes_to_empty_bytes() {
        let list = SszList::<u64, 1024>::new();
        assert_eq!(list.as_ssz_bytes(), vec![]);
    }

    // ── SszVector basic tests ────────────────────────────────────────────────

    #[test]
    fn vector_from_vec_ok() {
        let v = SszVector::<u64, 4>::from_vec(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v.get(0), Some(&1u64));
        assert_eq!(v.get(3), Some(&4u64));
        assert_eq!(v.get(4), None);
    }

    #[test]
    fn vector_length_mismatch_error() {
        let err = SszVector::<u64, 4>::from_vec(vec![1, 2, 3]).unwrap_err();
        assert!(matches!(
            err,
            SszError::VectorLengthMismatch {
                found: 3,
                expected: 4
            }
        ));
    }

    #[test]
    fn vector_encode_decode_roundtrip() {
        let v = SszVector::<u64, 4>::from_vec(vec![10, 20, 30, 40]).unwrap();
        let encoded = v.as_ssz_bytes();
        assert_eq!(encoded.len(), 4 * 8);
        let decoded = SszVector::<u64, 4>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn vector_decode_wrong_length_errors() {
        // Encode 3 u64s, try to decode as SszVector<u64, 4>
        let bytes = vec![0u8; 3 * 8];
        let err = SszVector::<u64, 4>::from_ssz_bytes(&bytes).unwrap_err();
        assert!(matches!(err, SszError::VectorLengthMismatch { .. }));
    }

    #[test]
    fn vector_with_push_always_errors() {
        let v = SszVector::<u64, 4>::from_vec(vec![1, 2, 3, 4]).unwrap();
        assert!(matches!(
            v.with_push(5),
            Err(SszError::ListLimitExceeded { .. })
        ));
    }

    #[test]
    fn vector_with_set_ok() {
        let v = SszVector::<u64, 4>::from_vec(vec![1, 2, 3, 4]).unwrap();
        let v2 = v.with_set(2, 99).unwrap();
        assert_eq!(v2.get(2), Some(&99u64));
        // Original unchanged.
        assert_eq!(v.get(2), Some(&3u64));
    }

    // ── TreeHash tests ───────────────────────────────────────────────────────

    #[test]
    fn list_tree_hash_empty_basic() {
        // Empty SszList<u64, 1024>: no chunks, limit = ceil(1024 * 8 / 32) = 256.
        let list = SszList::<u64, 1024>::new();
        let root = list.tree_hash_root();
        // Manual: merkleize_padded([], 256) then mix_in_length(root, 0)
        let limit = (1024u64 * 8).div_ceil(32) as usize;
        let manual_root = merkleize_padded(&[], limit);
        let expected = mix_in_length(manual_root, 0);
        assert_eq!(root, expected);
    }

    #[test]
    fn list_tree_hash_basic_matches_manual() {
        let list = SszList::<u64, 1024>::from_vec(vec![1u64, 2, 3]).unwrap();
        let root = list.tree_hash_root();
        // Manual: pack u64 packed encodings, compute chunks, merkleize_padded, mix_in_length.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.tree_hash_packed_encoding());
        bytes.extend_from_slice(&2u64.tree_hash_packed_encoding());
        bytes.extend_from_slice(&3u64.tree_hash_packed_encoding());
        let chunks = pack_bytes_to_chunks(&bytes);
        let limit = (1024u64 * 8).div_ceil(32) as usize;
        let manual_root = merkleize_padded(&chunks, limit);
        let expected = mix_in_length(manual_root, 3);
        assert_eq!(root, expected);
    }

    #[test]
    fn vector_tree_hash_basic_no_limit() {
        let v = SszVector::<u64, 4>::from_vec(vec![1u64, 2, 3, 4]).unwrap();
        let root = v.tree_hash_root();
        // Manual: pack u64 encodings, merkleize WITHOUT limit.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.tree_hash_packed_encoding());
        bytes.extend_from_slice(&2u64.tree_hash_packed_encoding());
        bytes.extend_from_slice(&3u64.tree_hash_packed_encoding());
        bytes.extend_from_slice(&4u64.tree_hash_packed_encoding());
        let chunks = pack_bytes_to_chunks(&bytes);
        let expected = merkleize(&chunks);
        assert_eq!(root, expected);
    }

    #[test]
    fn vector_tree_hash_type_is_vector() {
        assert_eq!(
            <SszVector<u64, 4> as TreeHash>::TREE_HASH_TYPE,
            TreeHashType::Vector
        );
    }

    #[test]
    fn list_tree_hash_type_is_list() {
        assert_eq!(
            <SszList<u64, 1024> as TreeHash>::TREE_HASH_TYPE,
            TreeHashType::List
        );
    }
}
