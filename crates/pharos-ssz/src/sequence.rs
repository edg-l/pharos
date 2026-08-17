//! `SszList<T, N>` and `SszVector<T, N>` — SSZ persistent collection types.
//!
//! Both types present a persistent (copy-on-write) API via `with_set` and
//! `with_push`.  Two backends are available:
//!
//! - `Backend::Flat(Vec<T>)` — clone-on-write `Vec`.  SSZ `Decode` always
//!   lands here.
//! - `Backend::Tree(Arc<Node<T>>)` — path-copy CoW Merkle tree with per-node
//!   `OnceLock<Hash256>` caches.  Reached only via explicit constructors
//!   (`from_vec_tree`, `empty_tree`).
//!
//! # Backend design
//!
//! ```text
//! enum Backend<T> {
//!     Flat(Vec<T>),                         // fast clone, contiguous slice
//!     Tree(Arc<Node<T>>),                    // O(log N) CoW, cached roots
//! }
//!
//! enum Node<T> {
//!     Branch { left: Arc<Node<T>>, right: Arc<Node<T>>, hash: OnceLock<Hash256> },
//!     Leaf(T),
//!     ZeroSubtree(u8),  // depth; root is zero_hash(depth)
//! }
//! ```
//!
//! # `SszList` vs `SszVector`
//!
//! | Type        | Length   | Limit | Mix-in length? |
//! |-------------|----------|-------|----------------|
//! | `SszList`   | variable | N max | yes            |
//! | `SszVector` | fixed=N  | none  | no             |

use std::sync::{Arc, OnceLock};

use rayon::prelude::*;

use crate::{
    decode::Decode,
    encode::{BYTES_PER_LENGTH_OFFSET, Encode},
    error::SszError,
    tree_hash::{
        TreeHash, TreeHashType, merkleize, merkleize_padded, mix_in_length, pack_basic_elems_bytes,
        pack_bytes_to_chunks, zero_hash,
    },
};
use pharos_utils::{Hash256, hash::hash_concat};

// ── depth helper ──────────────────────────────────────────────────────────────

/// Compute the tree depth needed to address `n` leaves.
///
/// `depth_for_limit(1) == 1`, `depth_for_limit(2) == 1`,
/// `depth_for_limit(3) == 2`, `depth_for_limit(4) == 2`, …
///
/// The result is the number of bits required to index into a tree whose leaf
/// capacity is `next_pow_of_two(n)`.
pub(crate) const fn depth_for_limit(n: u64) -> u8 {
    if n <= 1 {
        1
    } else {
        (64 - (n - 1).leading_zeros()) as u8
    }
}

// ── packed-basic helpers ────────────────────────────────────────────────────────

/// Number of basic elements that pack into one 32-byte chunk.
///
/// Returns 1 for composite element types and for `PACKED_AS_FULL_CHUNK` basics
/// (e.g. `FixedBytes<32>`), which occupy a full chunk each and use the
/// element-indexed (`Leaf`) tree. Multi-per-chunk basics (`u64`, `u8`, …) return
/// `32 / size_of_packed` and use the chunk-indexed (`PackedLeaf`) tree.
fn elems_per_chunk<T: TreeHash + Encode>() -> usize {
    if T::TREE_HASH_TYPE == TreeHashType::Basic && !T::PACKED_AS_FULL_CHUNK {
        let sz = T::ssz_fixed_len();
        debug_assert!(sz > 0 && 32 % sz == 0, "packed basic must divide 32 bytes");
        32 / sz
    } else {
        1
    }
}

/// Pack basic elements into a single right-zero-padded 32-byte chunk.
fn pack_chunk<T: TreeHash>(elems: &[T]) -> Hash256 {
    let mut bytes = [0u8; 32];
    let mut off = 0;
    for e in elems {
        let enc = e.tree_hash_packed_encoding();
        bytes[off..off + enc.len()].copy_from_slice(&enc);
        off += enc.len();
    }
    Hash256::from_array(bytes)
}

/// Merkle-tree depth for `n` elements at `epc` elements per chunk.
///
/// The tree holds `chunk_limit = ceil(n * elem_size / 32)` chunk leaves
/// (`elem_size = 32 / epc`; for composite `epc == 1` this is `n` element
/// leaves). The depth is `ceil(log2(chunk_limit))`, i.e. **0 for a single
/// chunk** — a one-chunk sequence merkleises to that chunk with no hashing,
/// matching `merkleize`/`merkleize_padded`. (`depth_for_limit` special-cases
/// `n <= 1` to 1, which is wrong for a single-chunk tree; that path is
/// unreachable for composite fields since they all have `N > 1`.)
fn tree_depth(n: u64, epc: usize) -> u8 {
    let elem_size = 32 / epc as u64;
    let chunk_limit = (n * elem_size).div_ceil(32).max(1);
    if chunk_limit <= 1 {
        0
    } else {
        depth_for_limit(chunk_limit)
    }
}

// ── Node<T> ───────────────────────────────────────────────────────────────────

/// A node in the persistent binary Merkle tree backing `Backend::Tree`.
///
/// - `Branch` — internal node with two children and a lazily-cached hash.
/// - `Leaf(T)` — holds one element.
/// - `ZeroSubtree(depth)` — virtual all-zero subtree whose root is
///   `zero_hash(depth)`.  Avoids materialising empty leaves.
pub(crate) enum Node<T> {
    Branch {
        left: Arc<Node<T>>,
        right: Arc<Node<T>>,
        hash: OnceLock<Hash256>,
    },
    /// Holds one composite element. Used by the element-indexed tree (one
    /// element per leaf); `cached_root` is `t.tree_hash_root()`.
    Leaf(T),
    /// Holds the basic elements packed into one 32-byte chunk (up to
    /// `elements_per_chunk(T)` of them, fewer for the final partial chunk).
    /// Used by the chunk-indexed tree for packed-basic lists/vectors;
    /// `cached_root` is the packed chunk itself (no hashing). The `OnceLock`
    /// memoises that chunk so a re-walk after a CoW update only re-packs the
    /// touched leaf.
    PackedLeaf {
        elems: Vec<T>,
        chunk: OnceLock<Hash256>,
    },
    /// All-zero subtree at the given depth; `cached_root` returns
    /// `zero_hash(depth)` without any hashing.
    ZeroSubtree(u8),
}

// ── Node<T> impl ──────────────────────────────────────────────────────────────

impl<T> Node<T> {
    /// Get a reference to the element at index `i` in a tree of depth `depth`.
    ///
    /// Returns `None` if the path reaches a `ZeroSubtree` (element not present)
    /// or if `i` is out of range.
    pub(crate) fn get(self: &Arc<Self>, i: usize, depth: u8) -> Option<&T> {
        match self.as_ref() {
            Node::Leaf(t) => {
                if depth == 0 {
                    Some(t)
                } else {
                    None
                }
            }
            Node::PackedLeaf { .. } => {
                unreachable!("PackedLeaf in an element-indexed (composite) tree")
            }
            Node::ZeroSubtree(_) => None,
            Node::Branch { left, right, .. } => {
                if depth == 0 {
                    return None;
                }
                let child_depth = depth - 1;
                let mid = 1usize << child_depth;
                if i < mid {
                    left.get(i, child_depth)
                } else {
                    right.get(i - mid, child_depth)
                }
            }
        }
    }

    /// Path-copy CoW update: replace element at index `i` with `v`.
    ///
    /// Only the spine from root to the target leaf is cloned; all off-path
    /// `Arc` references are reused unchanged (`Arc::clone` is O(1)).
    pub(crate) fn with_set(self: &Arc<Self>, i: usize, v: T, depth: u8) -> Arc<Node<T>>
    where
        T: Clone,
    {
        match self.as_ref() {
            Node::Leaf(_) => Arc::new(Node::Leaf(v)),
            Node::PackedLeaf { .. } => {
                unreachable!("PackedLeaf in an element-indexed (composite) tree")
            }
            Node::ZeroSubtree(d) => {
                // Materialise the spine from a zero subtree.
                if depth == 0 {
                    Arc::new(Node::Leaf(v))
                } else {
                    let child_depth = depth - 1;
                    let mid = 1usize << child_depth;
                    let zero_child = Arc::new(Node::ZeroSubtree(*d - 1));
                    if i < mid {
                        let new_left = zero_child.with_set(i, v, child_depth);
                        Arc::new(Node::Branch {
                            left: new_left,
                            right: Arc::new(Node::ZeroSubtree(*d - 1)),
                            hash: OnceLock::new(),
                        })
                    } else {
                        let new_right = zero_child.with_set(i - mid, v, child_depth);
                        Arc::new(Node::Branch {
                            left: Arc::new(Node::ZeroSubtree(*d - 1)),
                            right: new_right,
                            hash: OnceLock::new(),
                        })
                    }
                }
            }
            Node::Branch { left, right, .. } => {
                if depth == 0 {
                    // Shouldn't happen in a well-formed tree; treat as leaf replacement.
                    return Arc::new(Node::Leaf(v));
                }
                let child_depth = depth - 1;
                let mid = 1usize << child_depth;
                if i < mid {
                    Arc::new(Node::Branch {
                        left: left.with_set(i, v, child_depth),
                        right: Arc::clone(right),
                        hash: OnceLock::new(),
                    })
                } else {
                    Arc::new(Node::Branch {
                        left: Arc::clone(left),
                        right: right.with_set(i - mid, v, child_depth),
                        hash: OnceLock::new(),
                    })
                }
            }
        }
    }

    /// Return the cached Merkle root, computing it lazily if needed.
    pub(crate) fn cached_root(&self) -> Hash256
    where
        T: TreeHash,
    {
        match self {
            Node::Leaf(t) => t.tree_hash_root(),
            Node::PackedLeaf { elems, chunk } => *chunk.get_or_init(|| pack_chunk(elems)),
            Node::ZeroSubtree(d) => zero_hash(*d as usize),
            Node::Branch { left, right, hash } => *hash.get_or_init(|| {
                let l = left.cached_root();
                let r = right.cached_root();
                hash_concat(l.as_ref(), r.as_ref())
            }),
        }
    }

    /// Get the packed elements at chunk index `chunk_idx` (chunk-indexed tree).
    ///
    /// Returns `None` if the path reaches a `ZeroSubtree` (all-zero chunk, i.e.
    /// elements are the type default) or the index is out of range.
    pub(crate) fn chunk_at(self: &Arc<Self>, chunk_idx: usize, depth: u8) -> Option<&Vec<T>> {
        match self.as_ref() {
            Node::PackedLeaf { elems, .. } => {
                if depth == 0 {
                    Some(elems)
                } else {
                    None
                }
            }
            Node::ZeroSubtree(_) => None,
            Node::Leaf(_) => unreachable!("Leaf in a chunk-indexed (packed) tree"),
            Node::Branch { left, right, .. } => {
                if depth == 0 {
                    return None;
                }
                let child_depth = depth - 1;
                let mid = 1usize << child_depth;
                if chunk_idx < mid {
                    left.chunk_at(chunk_idx, child_depth)
                } else {
                    right.chunk_at(chunk_idx - mid, child_depth)
                }
            }
        }
    }

    /// Path-copy CoW: replace the chunk at `chunk_idx` with `elems`
    /// (chunk-indexed tree). Materialises the spine from a `ZeroSubtree` for a
    /// freshly-appended chunk.
    pub(crate) fn with_chunk(
        self: &Arc<Self>,
        chunk_idx: usize,
        elems: Vec<T>,
        depth: u8,
    ) -> Arc<Node<T>>
    where
        T: Clone,
    {
        if depth == 0 {
            return Arc::new(Node::PackedLeaf {
                elems,
                chunk: OnceLock::new(),
            });
        }
        let child_depth = depth - 1;
        let mid = 1usize << child_depth;
        match self.as_ref() {
            Node::Branch { left, right, .. } => {
                if chunk_idx < mid {
                    Arc::new(Node::Branch {
                        left: left.with_chunk(chunk_idx, elems, child_depth),
                        right: Arc::clone(right),
                        hash: OnceLock::new(),
                    })
                } else {
                    Arc::new(Node::Branch {
                        left: Arc::clone(left),
                        right: right.with_chunk(chunk_idx - mid, elems, child_depth),
                        hash: OnceLock::new(),
                    })
                }
            }
            Node::ZeroSubtree(d) => {
                let zero_child = Arc::new(Node::ZeroSubtree(*d - 1));
                if chunk_idx < mid {
                    Arc::new(Node::Branch {
                        left: zero_child.with_chunk(chunk_idx, elems, child_depth),
                        right: Arc::new(Node::ZeroSubtree(*d - 1)),
                        hash: OnceLock::new(),
                    })
                } else {
                    Arc::new(Node::Branch {
                        left: Arc::new(Node::ZeroSubtree(*d - 1)),
                        right: zero_child.with_chunk(chunk_idx - mid, elems, child_depth),
                        hash: OnceLock::new(),
                    })
                }
            }
            Node::PackedLeaf { .. } | Node::Leaf(_) => unreachable!("leaf at depth > 0"),
        }
    }

    /// Build a chunk-indexed tree from pre-chunked packed elements.
    pub(crate) fn from_chunks(chunks: &[Vec<T>], depth: u8) -> Arc<Node<T>>
    where
        T: Clone,
    {
        if depth == 0 {
            match chunks.first() {
                Some(c) => Arc::new(Node::PackedLeaf {
                    elems: c.clone(),
                    chunk: OnceLock::new(),
                }),
                None => Arc::new(Node::ZeroSubtree(0)),
            }
        } else {
            let child_depth = depth - 1;
            let mid = 1usize << child_depth;
            let (left_chunks, right_chunks) = if chunks.len() <= mid {
                (chunks, &[][..])
            } else {
                chunks.split_at(mid)
            };
            let left = Node::from_chunks(left_chunks, child_depth);
            let right = if right_chunks.is_empty() {
                Arc::new(Node::ZeroSubtree(child_depth))
            } else {
                Node::from_chunks(right_chunks, child_depth)
            };
            Arc::new(Node::Branch {
                left,
                right,
                hash: OnceLock::new(),
            })
        }
    }

    /// Build a tree from a slice of elements.
    ///
    /// - Each element becomes a `Leaf(t.clone())`.
    /// - Missing right-hand subtrees are filled with `ZeroSubtree(child_depth)`.
    /// - Returns the root `Arc<Node<T>>` for a tree of the given `depth`.
    pub(crate) fn from_slice(elems: &[T], depth: u8) -> Arc<Node<T>>
    where
        T: Clone,
    {
        if depth == 0 {
            // Leaf level.
            if let Some(t) = elems.first() {
                Arc::new(Node::Leaf(t.clone()))
            } else {
                Arc::new(Node::ZeroSubtree(0))
            }
        } else {
            let child_depth = depth - 1;
            let mid = 1usize << child_depth;
            let (left_elems, right_elems) = if elems.len() <= mid {
                (elems, &[][..])
            } else {
                elems.split_at(mid)
            };

            let left = Node::from_slice(left_elems, child_depth);
            let right = if right_elems.is_empty() {
                Arc::new(Node::ZeroSubtree(child_depth))
            } else {
                Node::from_slice(right_elems, child_depth)
            };
            Arc::new(Node::Branch {
                left,
                right,
                hash: OnceLock::new(),
            })
        }
    }
}

// ── Backend enum (private) ────────────────────────────────────────────────────

/// Internal storage backend for `SszList` and `SszVector`.
enum Backend<T> {
    /// Simple `Vec<T>` storage — clone-on-write.
    Flat(Vec<T>),
    /// Persistent path-copy CoW binary Merkle tree.
    Tree(Arc<Node<T>>),
}

impl<T: Clone> Clone for Backend<T> {
    fn clone(&self) -> Self {
        match self {
            Backend::Flat(v) => Backend::Flat(v.clone()),
            // Arc::clone is O(1): increments the reference count.
            Backend::Tree(arc) => Backend::Tree(Arc::clone(arc)),
        }
    }
}

impl<T: PartialEq> PartialEq for Backend<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Backend::Flat(a), Backend::Flat(b)) => a == b,
            // Cross-backend equality is handled at the SszList/SszVector level
            // via iter() comparison.  Two Tree backends are only compared by
            // SszList/SszVector::eq which routes non-Flat pairs through iter().
            _ => false,
        }
    }
}

impl<T: Eq> Eq for Backend<T> {}

impl<T: std::fmt::Debug + Clone> std::fmt::Debug for Backend<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Flat(v) => f.debug_tuple("Flat").field(v).finish(),
            Backend::Tree(_) => write!(f, "Tree(<node>)"),
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

    /// Collect all elements into an owned `Vec<T>`.
    ///
    /// For the `Flat` backend this clones the underlying `Vec`; for the `Tree`
    /// backend it performs an in-order traversal.
    fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.iter().cloned().collect()
    }
}

// ── Tree-backed iterator ──────────────────────────────────────────────────────

/// An in-order iterator over the leaves of a tree-backed `SszList` or
/// `SszVector`.  Carries the element count so it stops at `len`.
struct TreeIter<'a, T> {
    /// Pending (node, depth) pairs in DFS order, rightmost first.
    stack: Vec<(&'a Node<T>, u8)>,
    /// Elements of the current `PackedLeaf` being drained (empty otherwise).
    pending: std::slice::Iter<'a, T>,
    remaining: usize,
}

impl<'a, T> TreeIter<'a, T> {
    fn new(root: &'a Arc<Node<T>>, depth: u8, len: usize) -> Self {
        let mut stack = Vec::new();
        if len > 0 {
            stack.push((root.as_ref(), depth));
        }
        Self {
            stack,
            pending: [].iter(),
            remaining: len,
        }
    }
}

impl<'a, T> Iterator for TreeIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            // Drain the current packed chunk first.
            if let Some(t) = self.pending.next() {
                self.remaining -= 1;
                return Some(t);
            }
            let (node, depth) = self.stack.pop()?;
            match node {
                Node::Leaf(t) => {
                    self.remaining -= 1;
                    return Some(t);
                }
                Node::PackedLeaf { elems, .. } => {
                    // Drain its elements on the next loop iterations.
                    self.pending = elems.iter();
                    continue;
                }
                Node::ZeroSubtree(_) => {
                    // No real elements here; skip.
                    continue;
                }
                Node::Branch { left, right, .. } => {
                    if depth == 0 {
                        continue;
                    }
                    let child_depth = depth - 1;
                    // Push right first so left is processed first (LIFO).
                    self.stack.push((right.as_ref(), child_depth));
                    self.stack.push((left.as_ref(), child_depth));
                }
            }
        }
    }
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
    /// Length: tracked separately for the `Tree` backend (tree capacity ≥ len).
    len: usize,
    /// Elements per 32-byte chunk for the `Tree` backend: 1 for composite/
    /// full-chunk elements (element-indexed `Leaf` tree), `>1` for packed basics
    /// (chunk-indexed `PackedLeaf` tree). Always 1 for the `Flat` backend.
    epc: u8,
}

impl<T, const N: u64> SszList<T, N> {
    /// Construct an empty list (Flat backend).
    pub fn new() -> Self {
        Self {
            backend: Backend::Flat(Vec::new()),
            len: 0,
            epc: 1,
        }
    }

    /// Construct a list from a `Vec<T>` (Flat backend).
    ///
    /// Returns `SszError::ListLimitExceeded` if `v.len() > N`.
    pub fn from_vec(v: Vec<T>) -> Result<Self, SszError> {
        if v.len() as u64 > N {
            return Err(SszError::ListLimitExceeded {
                len: v.len(),
                limit: N,
            });
        }
        let len = v.len();
        Ok(Self {
            backend: Backend::Flat(v),
            len,
            epc: 1,
        })
    }

    /// Construct a list from an iterator (Flat backend).
    ///
    /// Returns `SszError::ListLimitExceeded` if the iterator yields more than `N`
    /// elements.
    pub fn from_items<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, SszError> {
        let v: Vec<T> = iter.into_iter().collect();
        Self::from_vec(v)
    }

    /// Construct a tree-backed list from a `Vec<T>`.
    ///
    /// Composite (and `PACKED_AS_FULL_CHUNK`) elements use the element-indexed
    /// `Leaf` tree; multi-per-chunk basics use the chunk-indexed `PackedLeaf`
    /// tree. Returns `SszError::ListLimitExceeded` if `v.len() > N`.
    pub fn from_vec_tree(v: Vec<T>) -> Result<Self, SszError>
    where
        T: Clone + TreeHash + Encode,
    {
        if v.len() as u64 > N {
            return Err(SszError::ListLimitExceeded {
                len: v.len(),
                limit: N,
            });
        }
        let len = v.len();
        let epc = elems_per_chunk::<T>();
        let depth = tree_depth(N, epc);
        let root = if epc == 1 {
            Node::from_slice(&v, depth)
        } else {
            let chunks: Vec<Vec<T>> = v.chunks(epc).map(<[T]>::to_vec).collect();
            Node::from_chunks(&chunks, depth)
        };
        Ok(Self {
            backend: Backend::Tree(root),
            len,
            epc: epc as u8,
        })
    }

    /// Construct an empty tree-backed list (root is a `ZeroSubtree`).
    pub fn empty_tree() -> Self
    where
        T: TreeHash + Encode,
    {
        let epc = elems_per_chunk::<T>();
        let depth = tree_depth(N, epc);
        let root = Arc::new(Node::ZeroSubtree(depth));
        Self {
            backend: Backend::Tree(root),
            len: 0,
            epc: epc as u8,
        }
    }

    /// Return a reference to the underlying `Vec<T>` (Flat backend only).
    ///
    /// Callers that need to work across both backends should use `iter()` or
    /// `to_vec()` instead.
    pub fn as_slice(&self) -> &[T] {
        match &self.backend {
            Backend::Flat(v) => v.as_slice(),
            Backend::Tree(_) => {
                panic!(
                    "as_slice() is not available on tree-backed SszList; \
                     use iter() or to_vec() instead"
                )
            }
        }
    }

    /// Whether the underlying storage uses the tree backend.
    pub fn backend_is_tree(&self) -> bool {
        matches!(self.backend, Backend::Tree(_))
    }

    /// Convert a Flat-backed list to tree-backed.
    ///
    /// If already tree-backed, returns `Ok(self)` unchanged.
    /// Returns `SszError` if the element type does not admit the tree backend
    /// (multi-per-chunk packed basics).
    pub fn into_tree(self) -> Result<Self, SszError>
    where
        T: Clone + TreeHash + Encode,
    {
        match self.backend {
            Backend::Tree(_) => Ok(self),
            Backend::Flat(v) => Self::from_vec_tree(v),
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
            len: self.len,
            epc: self.epc,
        }
    }
}

impl<T: PartialEq, const N: u64> PartialEq for SszList<T, N> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        match (&self.backend, &other.backend) {
            (Backend::Flat(a), Backend::Flat(b)) => a == b,
            _ => self.iter().eq(other.iter()),
        }
    }
}

impl<T: Eq, const N: u64> Eq for SszList<T, N> {}

impl<T: std::fmt::Debug, const N: u64> std::fmt::Debug for SszList<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SszList<{N}>(")?;
        f.debug_list().entries(self.iter()).finish()?;
        write!(f, ")")
    }
}

impl<T, const N: u64> SszSequence<T, N> for SszList<T, N> {
    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, i: usize) -> Option<&T> {
        match &self.backend {
            Backend::Flat(v) => v.get(i),
            Backend::Tree(arc) => {
                if i >= self.len {
                    return None;
                }
                let epc = self.epc as usize;
                let depth = tree_depth(N, epc);
                if epc == 1 {
                    arc.get(i, depth)
                } else {
                    arc.chunk_at(i / epc, depth).and_then(|c| c.get(i % epc))
                }
            }
        }
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a
    where
        T: 'a,
    {
        SszListIter::new(self)
    }

    fn with_set(&self, i: usize, v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        if i >= self.len {
            return Err(SszError::OffsetOutOfRange {
                offset: i,
                max: self.len.saturating_sub(1),
            });
        }
        match &self.backend {
            Backend::Flat(vec) => {
                let mut new_vec = vec.clone();
                new_vec[i] = v;
                Ok(Self {
                    backend: Backend::Flat(new_vec),
                    len: self.len,
                    epc: 1,
                })
            }
            Backend::Tree(arc) => {
                let epc = self.epc as usize;
                let depth = tree_depth(N, epc);
                let new_root = if epc == 1 {
                    arc.with_set(i, v, depth)
                } else {
                    // i < len, so the containing chunk is materialised and
                    // `i % epc` is within it.
                    let chunk_idx = i / epc;
                    let mut chunk = arc.chunk_at(chunk_idx, depth).cloned().unwrap_or_default();
                    chunk[i % epc] = v;
                    arc.with_chunk(chunk_idx, chunk, depth)
                };
                Ok(Self {
                    backend: Backend::Tree(new_root),
                    len: self.len,
                    epc: self.epc,
                })
            }
        }
    }

    fn with_push(&self, v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        if self.len as u64 >= N {
            return Err(SszError::ListLimitExceeded {
                len: self.len + 1,
                limit: N,
            });
        }
        match &self.backend {
            Backend::Flat(vec) => {
                let mut new_vec = vec.clone();
                new_vec.push(v);
                let new_len = new_vec.len();
                Ok(Self {
                    backend: Backend::Flat(new_vec),
                    len: new_len,
                    epc: 1,
                })
            }
            Backend::Tree(arc) => {
                let epc = self.epc as usize;
                let depth = tree_depth(N, epc);
                let new_root = if epc == 1 {
                    arc.with_set(self.len, v, depth)
                } else {
                    let chunk_idx = self.len / epc;
                    if self.len.is_multiple_of(epc) {
                        // Start a fresh chunk.
                        arc.with_chunk(chunk_idx, vec![v], depth)
                    } else {
                        // Append to the current partial chunk.
                        let mut chunk = arc.chunk_at(chunk_idx, depth).cloned().unwrap_or_default();
                        chunk.push(v);
                        arc.with_chunk(chunk_idx, chunk, depth)
                    }
                };
                Ok(Self {
                    backend: Backend::Tree(new_root),
                    len: self.len + 1,
                    epc: self.epc,
                })
            }
        }
    }
}

/// Iterator over `SszList<T, N>` that works for both backends.
enum SszListIter<'a, T, const N: u64> {
    Flat(std::slice::Iter<'a, T>),
    Tree(TreeIter<'a, T>),
}

impl<'a, T, const N: u64> SszListIter<'a, T, N> {
    fn new(list: &'a SszList<T, N>) -> Self {
        match &list.backend {
            Backend::Flat(v) => SszListIter::Flat(v.iter()),
            Backend::Tree(arc) => {
                let depth = tree_depth(N, list.epc as usize);
                SszListIter::Tree(TreeIter::new(arc, depth, list.len))
            }
        }
    }
}

impl<'a, T, const N: u64> Iterator for SszListIter<'a, T, N> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        match self {
            SszListIter::Flat(it) => it.next(),
            SszListIter::Tree(it) => it.next(),
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
    /// Elements per 32-byte chunk for the `Tree` backend (see `SszList::epc`).
    /// Always 1 for the `Flat` backend.
    epc: u8,
}

impl<T, const N: u64> SszVector<T, N> {
    /// Whether the underlying storage uses the tree backend.
    pub fn backend_is_tree(&self) -> bool {
        matches!(self.backend, Backend::Tree(_))
    }

    /// Construct a vector from a `Vec<T>` (Flat backend).
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
            backend: Backend::Flat(v),
            epc: 1,
        })
    }

    /// Construct a vector from an iterator (Flat backend).
    ///
    /// Returns `SszError::VectorLengthMismatch` if the iterator does not yield
    /// exactly `N` elements.
    pub fn from_items<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, SszError> {
        let v: Vec<T> = iter.into_iter().collect();
        Self::from_vec(v)
    }

    /// Construct a tree-backed vector from a `Vec<T>`.
    ///
    /// Composite (and `PACKED_AS_FULL_CHUNK`) elements use the element-indexed
    /// `Leaf` tree; multi-per-chunk basics use the chunk-indexed `PackedLeaf`
    /// tree. Returns `SszError::VectorLengthMismatch` if `v.len() != N`.
    pub fn from_vec_tree(v: Vec<T>) -> Result<Self, SszError>
    where
        T: Clone + TreeHash + Encode,
    {
        if v.len() != N as usize {
            return Err(SszError::VectorLengthMismatch {
                found: v.len(),
                expected: N as usize,
            });
        }
        let epc = elems_per_chunk::<T>();
        let depth = tree_depth(N, epc);
        let root = if epc == 1 {
            Node::from_slice(&v, depth)
        } else {
            let chunks: Vec<Vec<T>> = v.chunks(epc).map(<[T]>::to_vec).collect();
            Node::from_chunks(&chunks, depth)
        };
        Ok(Self {
            backend: Backend::Tree(root),
            epc: epc as u8,
        })
    }

    /// Return a reference to the underlying slice (Flat backend only).
    pub fn as_slice(&self) -> &[T] {
        match &self.backend {
            Backend::Flat(v) => v.as_slice(),
            Backend::Tree(_) => {
                panic!(
                    "as_slice() is not available on tree-backed SszVector; \
                     use iter() or to_vec() instead"
                )
            }
        }
    }

    /// Convert a Flat-backed vector to tree-backed.
    ///
    /// If already tree-backed, returns `Ok(self)` unchanged.
    /// Returns `SszError` if the element type does not admit the tree backend
    /// (multi-per-chunk packed basics).
    pub fn into_tree(self) -> Result<Self, SszError>
    where
        T: Clone + TreeHash + Encode,
    {
        match self.backend {
            Backend::Tree(_) => Ok(self),
            Backend::Flat(v) => Self::from_vec_tree(v),
        }
    }
}

impl<T: Clone + Default, const N: u64> Default for SszVector<T, N> {
    fn default() -> Self {
        Self {
            backend: Backend::Flat(vec![T::default(); N as usize]),
            epc: 1,
        }
    }
}

impl<T: Clone, const N: u64> Clone for SszVector<T, N> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            epc: self.epc,
        }
    }
}

impl<T: PartialEq, const N: u64> PartialEq for SszVector<T, N> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.backend, &other.backend) {
            (Backend::Flat(a), Backend::Flat(b)) => a == b,
            _ => self.iter().eq(other.iter()),
        }
    }
}

impl<T: Eq, const N: u64> Eq for SszVector<T, N> {}

impl<T: std::fmt::Debug, const N: u64> std::fmt::Debug for SszVector<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SszVector<{N}>(")?;
        f.debug_list().entries(self.iter()).finish()?;
        write!(f, ")")
    }
}

impl<T, const N: u64> SszSequence<T, N> for SszVector<T, N> {
    fn len(&self) -> usize {
        N as usize
    }

    fn get(&self, i: usize) -> Option<&T> {
        match &self.backend {
            Backend::Flat(v) => v.get(i),
            Backend::Tree(arc) => {
                if i >= N as usize {
                    return None;
                }
                let epc = self.epc as usize;
                let depth = tree_depth(N, epc);
                if epc == 1 {
                    arc.get(i, depth)
                } else {
                    arc.chunk_at(i / epc, depth).and_then(|c| c.get(i % epc))
                }
            }
        }
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a
    where
        T: 'a,
    {
        SszVectorIter::new(self)
    }

    fn with_set(&self, i: usize, v: T) -> Result<Self, SszError>
    where
        T: Clone,
    {
        if i >= N as usize {
            return Err(SszError::OffsetOutOfRange {
                offset: i,
                max: N as usize - 1,
            });
        }
        match &self.backend {
            Backend::Flat(vec) => {
                let mut new_vec = vec.clone();
                new_vec[i] = v;
                Ok(Self {
                    backend: Backend::Flat(new_vec),
                    epc: 1,
                })
            }
            Backend::Tree(arc) => {
                let epc = self.epc as usize;
                let depth = tree_depth(N, epc);
                let new_root = if epc == 1 {
                    arc.with_set(i, v, depth)
                } else {
                    let chunk_idx = i / epc;
                    let mut chunk = arc.chunk_at(chunk_idx, depth).cloned().unwrap_or_default();
                    chunk[i % epc] = v;
                    arc.with_chunk(chunk_idx, chunk, depth)
                };
                Ok(Self {
                    backend: Backend::Tree(new_root),
                    epc: self.epc,
                })
            }
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

/// Iterator over `SszVector<T, N>` that works for both backends.
enum SszVectorIter<'a, T, const N: u64> {
    Flat(std::slice::Iter<'a, T>),
    Tree(TreeIter<'a, T>),
}

impl<'a, T, const N: u64> SszVectorIter<'a, T, N> {
    fn new(vec: &'a SszVector<T, N>) -> Self {
        match &vec.backend {
            Backend::Flat(v) => SszVectorIter::Flat(v.iter()),
            Backend::Tree(arc) => {
                let depth = tree_depth(N, vec.epc as usize);
                SszVectorIter::Tree(TreeIter::new(arc, depth, N as usize))
            }
        }
    }
}

impl<'a, T, const N: u64> Iterator for SszVectorIter<'a, T, N> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        match self {
            SszVectorIter::Flat(it) => it.next(),
            SszVectorIter::Tree(it) => it.next(),
        }
    }
}

// ── Encode for SszList<T, N> ──────────────────────────────────────────────────

impl<T, const N: u64> Encode for SszList<T, N>
where
    T: Encode + Clone,
{
    /// Lists are always variable-size (their length varies).
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        match &self.backend {
            Backend::Flat(elems) => {
                if T::IS_FIXED_SIZE {
                    elems.len() * T::ssz_fixed_len()
                } else {
                    variable_elems_ssz_bytes_len(elems.as_slice())
                }
            }
            Backend::Tree(_) => {
                // Materialise to Vec for encoding; tree backend is for hashing.
                let elems: Vec<T> = self.iter().cloned().collect();
                if T::IS_FIXED_SIZE {
                    elems.len() * T::ssz_fixed_len()
                } else {
                    variable_elems_ssz_bytes_len(&elems)
                }
            }
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match &self.backend {
            Backend::Flat(elems) => {
                if T::IS_FIXED_SIZE {
                    for elem in elems {
                        elem.ssz_append(buf);
                    }
                } else {
                    encode_variable_elems(elems.as_slice(), buf);
                }
            }
            Backend::Tree(_) => {
                let elems: Vec<T> = self.iter().cloned().collect();
                if T::IS_FIXED_SIZE {
                    for elem in &elems {
                        elem.ssz_append(buf);
                    }
                } else {
                    encode_variable_elems(&elems, buf);
                }
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
        // Decode always lands in Flat; tree backend reached only via explicit constructors.
        Ok(Self {
            backend: Backend::Flat(items),
            len,
            epc: 1,
        })
    }
}

// ── Encode for SszVector<T, N> ────────────────────────────────────────────────

impl<T, const N: u64> Encode for SszVector<T, N>
where
    T: Encode + Clone,
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
        match &self.backend {
            Backend::Flat(elems) => {
                if T::IS_FIXED_SIZE {
                    elems.len() * T::ssz_fixed_len()
                } else {
                    variable_elems_ssz_bytes_len(elems.as_slice())
                }
            }
            Backend::Tree(_) => {
                let elems: Vec<T> = self.iter().cloned().collect();
                if T::IS_FIXED_SIZE {
                    elems.len() * T::ssz_fixed_len()
                } else {
                    variable_elems_ssz_bytes_len(&elems)
                }
            }
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match &self.backend {
            Backend::Flat(elems) => {
                if T::IS_FIXED_SIZE {
                    for elem in elems {
                        elem.ssz_append(buf);
                    }
                } else {
                    encode_variable_elems(elems.as_slice(), buf);
                }
            }
            Backend::Tree(_) => {
                let elems: Vec<T> = self.iter().cloned().collect();
                if T::IS_FIXED_SIZE {
                    for elem in &elems {
                        elem.ssz_append(buf);
                    }
                } else {
                    encode_variable_elems(&elems, buf);
                }
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
        // Vector<T, 0> is illegal per the SSZ spec.
        if N == 0 {
            return Err(SszError::Custom(
                "Vector[T, 0] is not a valid SSZ type".into(),
            ));
        }
        let items = decode_list_items::<T>(bytes)?;
        let found = items.len();
        let expected = N as usize;
        if found != expected {
            return Err(SszError::VectorLengthMismatch { found, expected });
        }
        // Decode always lands in Flat.
        Ok(Self {
            backend: Backend::Flat(items),
            epc: 1,
        })
    }
}

// ── TreeHash for SszList<T, N> ────────────────────────────────────────────────

impl<T, const N: u64> TreeHash for SszList<T, N>
where
    T: TreeHash + Encode + Sync + Clone,
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::List;

    fn tree_hash_root(&self) -> Hash256 {
        let len = self.len as u64;

        let root = match (&self.backend, T::TREE_HASH_TYPE) {
            (Backend::Tree(arc), _) => {
                // Both backings fold their `OnceLock` caches up the tree in
                // O(log N) amortised (only uncached nodes are re-hashed):
                // composite leaves hold per-element roots; packed `PackedLeaf`
                // leaves hold per-chunk roots merkleised to the chunk limit
                // (the tree depth is `tree_depth(N, epc)`).
                arc.cached_root()
            }
            (Backend::Flat(elems), TreeHashType::Basic) => {
                let elem_size = T::ssz_fixed_len() as u64;
                let limit = (N * elem_size).div_ceil(32) as usize;
                let bytes = pack_basic_elems_bytes(elems);
                let chunks = pack_bytes_to_chunks(&bytes);
                merkleize_padded(&chunks, limit)
            }
            (Backend::Flat(elems), _) => {
                // Composite elements: per-element roots with limit = N.
                const PAR_THRESHOLD: usize = 1024;
                let roots: Vec<Hash256> = if elems.len() >= PAR_THRESHOLD {
                    elems.par_iter().map(|e| e.tree_hash_root()).collect()
                } else {
                    elems.iter().map(|e| e.tree_hash_root()).collect()
                };
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
    T: TreeHash + Encode + Sync + Clone,
{
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Vector;

    fn tree_hash_root(&self) -> Hash256 {
        match (&self.backend, T::TREE_HASH_TYPE) {
            (Backend::Tree(arc), _) => {
                // Both backings fold their `OnceLock` caches up the tree: composite
                // leaves hold per-element roots; packed `PackedLeaf` leaves hold
                // per-chunk roots. The tree depth (`tree_depth(N, epc)`) gives the
                // same padding as `merkleize` over the natural chunk count.
                arc.cached_root()
            }
            (Backend::Flat(elems), TreeHashType::Basic) => {
                let bytes = pack_basic_elems_bytes(elems);
                let chunks = pack_bytes_to_chunks(&bytes);
                merkleize(&chunks)
            }
            (Backend::Flat(elems), _) => {
                const PAR_THRESHOLD: usize = 1024;
                let roots: Vec<Hash256> = if elems.len() >= PAR_THRESHOLD {
                    elems.par_iter().map(|e| e.tree_hash_root()).collect()
                } else {
                    elems.iter().map(|e| e.tree_hash_root()).collect()
                };
                merkleize(&roots)
            }
        }
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("SszVector is not a basic type and is never packed")
    }
}

// ── shared encode helpers ─────────────────────────────────────────────────────

/// SSZ byte length of a variable-element sequence: per-element offsets plus
/// the sum of each element's serialized length.
fn variable_elems_ssz_bytes_len<T: Encode>(elems: &[T]) -> usize {
    let offsets_len = elems.len() * BYTES_PER_LENGTH_OFFSET;
    let data_len: usize = elems.iter().map(|e| e.ssz_bytes_len()).sum();
    offsets_len + data_len
}

/// Encode a slice of variable-size elements into `buf` using two passes:
///
/// 1. Walk `elems` and write each element's offset, computed from
///    `ssz_bytes_len()`, into the fixed region.
/// 2. Walk `elems` again and stream each element's bytes directly into `buf`
///    via `ssz_append`, avoiding the per-element intermediate `Vec<u8>`
///    that an `as_ssz_bytes` round would allocate.
///
/// On a `BeaconBlockBody` with 128 attestations this removes 128 intermediate
/// heap allocations per encode call.
fn encode_variable_elems<T: Encode>(elems: &[T], buf: &mut Vec<u8>) {
    let fixed_region_len = elems.len() * BYTES_PER_LENGTH_OFFSET;
    let mut running_offset = fixed_region_len;
    for elem in elems {
        buf.extend_from_slice(&(running_offset as u32).to_le_bytes());
        running_offset += elem.ssz_bytes_len();
    }
    for elem in elems {
        elem.ssz_append(buf);
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
        if !bytes.len().is_multiple_of(elem_len) {
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

        if !first_offset.is_multiple_of(BYTES_PER_LENGTH_OFFSET) {
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
        assert_eq!(list.as_ssz_bytes(), Vec::<u8>::new());
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

    // ── depth helper tests ───────────────────────────────────────────────────

    #[test]
    fn depth_for_limit_values() {
        assert_eq!(depth_for_limit(1), 1);
        assert_eq!(depth_for_limit(2), 1);
        assert_eq!(depth_for_limit(3), 2);
        assert_eq!(depth_for_limit(4), 2);
        assert_eq!(depth_for_limit(5), 3);
        assert_eq!(depth_for_limit(8), 3);
        assert_eq!(depth_for_limit(9), 4);
        assert_eq!(depth_for_limit(1024), 10);
        assert_eq!(depth_for_limit(8192), 13);
    }

    // ── Tree-backend basic operations ────────────────────────────────────────

    /// Composite-element wrapper for tree-backend tests.
    /// Manual impls avoid the `pharos_ssz::` path issue inside the crate.
    #[derive(Clone, Debug, PartialEq)]
    struct Leaf {
        val: u64,
    }

    impl Encode for Leaf {
        const IS_FIXED_SIZE: bool = true;
        fn ssz_fixed_len() -> usize {
            8
        }
        fn ssz_bytes_len(&self) -> usize {
            8
        }
        fn ssz_append(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.val.to_le_bytes());
        }
    }

    impl Decode for Leaf {
        const IS_FIXED_SIZE: bool = true;
        fn ssz_fixed_len() -> usize {
            8
        }
        fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
            if bytes.len() != 8 {
                return Err(SszError::InvalidByteLength {
                    found: bytes.len(),
                    expected: 8,
                });
            }
            Ok(Leaf {
                val: u64::from_le_bytes(bytes.try_into().unwrap()),
            })
        }
    }

    impl TreeHash for Leaf {
        const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;
        fn tree_hash_root(&self) -> Hash256 {
            // Single-field container: merkleize([val.tree_hash_root()]) = val.tree_hash_root()
            // (single chunk, no padding needed).
            self.val.tree_hash_root()
        }
        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            unreachable!("Leaf is a container, not a basic type")
        }
    }

    fn leaf(val: u64) -> Leaf {
        Leaf { val }
    }

    #[test]
    fn tree_list_from_vec_tree_get() {
        let v: Vec<Leaf> = (0u64..8).map(leaf).collect();
        let list = SszList::<Leaf, 1024>::from_vec_tree(v.clone()).unwrap();
        assert_eq!(list.len(), 8);
        for (i, val) in v.iter().enumerate() {
            assert_eq!(list.get(i), Some(val));
        }
    }

    #[test]
    fn tree_list_with_set_cow() {
        let v: Vec<Leaf> = (0u64..4).map(leaf).collect();
        let list = SszList::<Leaf, 1024>::from_vec_tree(v).unwrap();
        let list2 = list.with_set(2, leaf(99)).unwrap();
        // New list updated.
        assert_eq!(list2.get(2), Some(&leaf(99)));
        // Old list unchanged.
        assert_eq!(list.get(2), Some(&leaf(2)));
    }

    #[test]
    fn tree_list_with_push() {
        let list = SszList::<Leaf, 1024>::empty_tree();
        let list = list.with_push(leaf(1)).unwrap();
        let list = list.with_push(leaf(2)).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0), Some(&leaf(1)));
        assert_eq!(list.get(1), Some(&leaf(2)));
    }

    #[test]
    fn tree_list_iter() {
        let v: Vec<Leaf> = (0u64..5).map(leaf).collect();
        let list = SszList::<Leaf, 1024>::from_vec_tree(v.clone()).unwrap();
        let collected: Vec<&Leaf> = list.iter().collect();
        assert_eq!(collected.len(), 5);
        for (i, val) in v.iter().enumerate() {
            assert_eq!(collected[i], val);
        }
    }

    #[test]
    fn tree_list_tree_hash_matches_naive() {
        let v: Vec<Leaf> = (0u64..16).map(leaf).collect();
        let naive = SszList::<Leaf, 1024>::from_vec(v.clone()).unwrap();
        let tree = SszList::<Leaf, 1024>::from_vec_tree(v).unwrap();
        assert_eq!(naive.tree_hash_root(), tree.tree_hash_root());
    }

    #[test]
    fn tree_vector_from_vec_tree_matches_naive() {
        let v: Vec<Leaf> = (0u64..4).map(leaf).collect();
        let naive = SszVector::<Leaf, 4>::from_vec(v.clone()).unwrap();
        let tree = SszVector::<Leaf, 4>::from_vec_tree(v).unwrap();
        assert_eq!(naive.tree_hash_root(), tree.tree_hash_root());
    }

    #[test]
    fn tree_list_empty_tree_hash_matches_naive() {
        let naive = SszList::<Leaf, 1024>::new();
        let tree = SszList::<Leaf, 1024>::empty_tree();
        assert_eq!(naive.tree_hash_root(), tree.tree_hash_root());
    }

    #[test]
    fn from_vec_tree_accepts_packed_basic_list() {
        // PackedLeaf: a `List[u64]` is now tree-backed and must hash identically
        // to the Flat merkleisation.
        let v: Vec<u64> = (0..10).collect();
        let tree = SszList::<u64, 16>::from_vec_tree(v.clone()).unwrap();
        let naive = SszList::<u64, 16>::from_vec(v).unwrap();
        assert!(tree.backend_is_tree());
        assert_eq!(tree.tree_hash_root(), naive.tree_hash_root());
    }

    #[test]
    fn from_vec_tree_accepts_packed_basic_vector() {
        // `Vector[u64, 4]` (one full 32-byte chunk).
        let v: Vec<u64> = vec![7, 8, 9, 10];
        let tree = SszVector::<u64, 4>::from_vec_tree(v.clone()).unwrap();
        let naive = SszVector::<u64, 4>::from_vec(v).unwrap();
        assert!(tree.backend_is_tree());
        assert_eq!(tree.tree_hash_root(), naive.tree_hash_root());
    }

    #[test]
    fn empty_tree_accepts_packed_basic() {
        let tree = SszList::<u64, 16>::empty_tree();
        let naive: SszList<u64, 16> = SszList::new();
        assert!(tree.backend_is_tree());
        assert_eq!(tree.tree_hash_root(), naive.tree_hash_root());
    }

    // ── FixedBytes<32> carveout: PACKED_AS_FULL_CHUNK admits Root/Hash256 ───

    #[test]
    fn from_vec_tree_accepts_fixed_bytes_32_list() {
        use pharos_utils::Hash256;
        let v: Vec<Hash256> = (0u8..8).map(|i| Hash256::from_array([i; 32])).collect();
        let tree = SszList::<Hash256, 1024>::from_vec_tree(v.clone()).unwrap();
        let naive = SszList::<Hash256, 1024>::from_vec(v).unwrap();
        assert_eq!(tree.tree_hash_root(), naive.tree_hash_root());
    }

    #[test]
    fn from_vec_tree_accepts_fixed_bytes_32_vector() {
        use pharos_utils::Hash256;
        let v: Vec<Hash256> = (0u8..8).map(|i| Hash256::from_array([i; 32])).collect();
        let tree = SszVector::<Hash256, 8>::from_vec_tree(v.clone()).unwrap();
        let naive = SszVector::<Hash256, 8>::from_vec(v).unwrap();
        assert_eq!(tree.tree_hash_root(), naive.tree_hash_root());
    }

    #[test]
    fn empty_tree_accepts_fixed_bytes_32() {
        use pharos_utils::Hash256;
        let tree = SszList::<Hash256, 1024>::empty_tree();
        let naive: SszList<Hash256, 1024> = SszList::new();
        assert_eq!(tree.tree_hash_root(), naive.tree_hash_root());
    }

    // ── Task 1.10: with_set path-copy preserves shared subtrees ─────────────

    #[test]
    fn with_set_path_copy_preserves_shared_subtrees() {
        // Build a tree-backed SszList<Leaf, 1024> with 1024 elements.
        // depth_for_limit(1024) = 10.
        let v: Vec<Leaf> = (0u64..1024).map(leaf).collect();
        let list = SszList::<Leaf, 1024>::from_vec_tree(v).unwrap();

        // Extract the left.left child Arc from the root.
        // Root is at depth 10; its children are at depth 9.
        // left.left is at depth 8.
        let root_arc = match &list.backend {
            Backend::Tree(arc) => Arc::clone(arc),
            _ => panic!("expected tree backend"),
        };

        let left_arc = match root_arc.as_ref() {
            Node::Branch { left, .. } => Arc::clone(left),
            _ => panic!("expected branch at root"),
        };

        let left_left_arc = match left_arc.as_ref() {
            Node::Branch { left, .. } => Arc::clone(left),
            _ => panic!("expected branch at left"),
        };

        // Capture the strong count before the write.
        // At this point: root_arc holds left, left_arc holds left_left, we hold left_left_arc.
        let count_before = Arc::strong_count(&left_left_arc);

        // with_set(1023, ...) mutates index 1023 (the rightmost element).
        // Index 1023 is in the RIGHT half of the root (root.right subtree).
        // Therefore root.left subtree is entirely off-path and its Arc is
        // reused unchanged by CoW path-copy.
        let new_list = list.with_set(1023, leaf(0xdead)).unwrap();

        let new_root_arc = match &new_list.backend {
            Backend::Tree(arc) => Arc::clone(arc),
            _ => panic!("expected tree backend"),
        };

        let new_left_arc = match new_root_arc.as_ref() {
            Node::Branch { left, .. } => Arc::clone(left),
            _ => panic!("expected branch at new root"),
        };

        let new_left_left_arc = match new_left_arc.as_ref() {
            Node::Branch { left, .. } => Arc::clone(left),
            _ => panic!("expected branch at new left"),
        };

        let count_after = Arc::strong_count(&left_left_arc);

        // The new tree's left.left MUST be the same Arc (ptr_eq proves structural sharing).
        // Reported values: count_before = 2 (root->left->left + our clone),
        //                  count_after  = 4 (root->left->left + our clone + new_root->left->left + new_left_left_arc).
        assert!(
            Arc::ptr_eq(&left_left_arc, &new_left_left_arc),
            "off-path subtree must be shared (ptr_eq); count_before={count_before}, count_after={count_after}"
        );

        // Strong count grew because the new tree holds an additional reference
        // to the shared subtree.
        assert!(
            count_after > count_before,
            "strong count must grow after with_set shares off-path subtree; \
             before={count_before}, after={count_after}"
        );

        // Verify the mutation was correct.
        assert_eq!(new_list.get(1023), Some(&leaf(0xdead)));
        // Original unchanged.
        assert_eq!(list.get(1023), Some(&leaf(1023)));
    }
}
