//! Property tests comparing the `Naive` and `Tree` backends of `SszList` and
//! `SszVector` in lockstep.
//!
//! After each random operation (`set`, `push`, `from_vec`) applied to both
//! backends simultaneously, the test asserts that:
//!
//! - `tree_hash_root()` is byte-identical between backends.
//! - `len()` is identical.
//! - `get(i)` is identical for all `i` in `0..len`.
//! - `as_ssz_bytes()` is identical.
//!
//! This pins the tree-backend implementation against R1 (tree root divergence).
//!
//! Element type: a composite wrapper struct `LeafU64 { val: u64 }` so that the
//! tree backend's `cached_root()` path is exercised (composite elements).
//! Basic-element lists stay on `Naive` per `D-tree-leaf-packing`.

#![cfg(test)]

use pharos_ssz::{
    Decode, Encode, SszList, SszSequence, SszVector, TreeHash, error::SszError,
    tree_hash::TreeHashType,
};
use pharos_utils::Hash256;
use proptest::prelude::*;

// ── composite element wrapper ─────────────────────────────────────────────────

/// Composite wrapper around `u64`.  Implements `Encode`, `Decode`, and
/// `TreeHash` manually to avoid the `pharos_ssz::` path issue when inside the
/// crate, and to guarantee the `Container` tree-hash type so that the tree
/// backend's `cached_root()` path is exercised.
#[derive(Clone, Debug, PartialEq)]
struct LeafU64 {
    val: u64,
}

impl LeafU64 {
    fn new(val: u64) -> Self {
        Self { val }
    }
}

impl Encode for LeafU64 {
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

impl Decode for LeafU64 {
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
        Ok(LeafU64 {
            val: u64::from_le_bytes(bytes.try_into().unwrap()),
        })
    }
}

impl TreeHash for LeafU64 {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        // Single-field container: root == merkleize([val.tree_hash_root()])
        // = val.tree_hash_root() (a single chunk, no padding needed).
        self.val.tree_hash_root()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("LeafU64 is a container, not a basic type")
    }
}

// ── constants ─────────────────────────────────────────────────────────────────

/// Maximum list capacity.  Large enough to exercise multi-level tree paths.
const MAX_N: u64 = 8192;

/// Number of proptest cases.
const CASES: u32 = 256;

// ── operation enum ────────────────────────────────────────────────────────────

/// Operations that can be applied to both backends in lockstep.
#[derive(Debug, Clone)]
enum Op {
    /// Push a value (if `len < N`).
    Push(u64),
    /// Set element at index (clamped to current length).
    Set(usize, u64),
    /// Reset both backends to a fresh `from_vec` / `from_vec_tree`.
    FromVec(Vec<u64>),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u64..0x1000u64).prop_map(Op::Push),
        (0usize..(MAX_N as usize), 0u64..0x1000u64).prop_map(|(i, v)| Op::Set(i, v)),
        prop::collection::vec(0u64..0x1000u64, 0..=(MAX_N as usize)).prop_map(Op::FromVec),
    ]
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Assert that both backends agree on all observable outputs.
///
/// Returns `Ok(())` on success, or a proptest `TestCaseError` on mismatch.
/// The caller must propagate the error via `?`.
fn assert_backends_agree(
    naive: &SszList<LeafU64, MAX_N>,
    tree: &SszList<LeafU64, MAX_N>,
    step: &str,
) -> Result<(), proptest::test_runner::TestCaseError> {
    let naive_len = naive.len();
    let tree_len = tree.len();
    prop_assert_eq!(naive_len, tree_len, "len mismatch at {}", step);

    for i in 0..naive_len {
        prop_assert_eq!(naive.get(i), tree.get(i), "get({}) mismatch at {}", i, step);
    }

    let naive_root = naive.tree_hash_root();
    let tree_root = tree.tree_hash_root();
    prop_assert_eq!(naive_root, tree_root, "tree_hash_root mismatch at {}", step);

    let naive_bytes = naive.as_ssz_bytes();
    let tree_bytes = tree.as_ssz_bytes();
    prop_assert_eq!(naive_bytes, tree_bytes, "as_ssz_bytes mismatch at {}", step);

    Ok(())
}

// ── proptest ──────────────────────────────────────────────────────────────────

proptest! {
    // 256 cases, MAX_N = 8192, composite Leaf element.
    #![proptest_config(ProptestConfig { cases: CASES, ..Default::default() })]

    /// Lockstep transcript: apply each operation to both the Naive and Tree
    /// backends, asserting byte-identical outputs after every step.
    ///
    /// This pins R1 (tree root divergence from Vec backend) and the CoW
    /// path-copy correctness for `SszList<LeafU64, MAX_N>`.
    #[test]
    fn tree_and_naive_backends_agree_on_list(
        ops in prop::collection::vec(op_strategy(), 1..=50)
    ) {
        let mut naive = SszList::<LeafU64, MAX_N>::new();
        let mut tree = SszList::<LeafU64, MAX_N>::empty_tree();

        for (step_idx, op) in ops.iter().enumerate() {
            let step = format!("step {step_idx}");
            match op {
                Op::Push(v) => {
                    if naive.len() < MAX_N as usize {
                        naive = naive.with_push(LeafU64::new(*v)).unwrap();
                        tree = tree.with_push(LeafU64::new(*v)).unwrap();
                    }
                }
                Op::Set(i, v) => {
                    let len = naive.len();
                    if len > 0 {
                        let idx = i % len;
                        naive = naive.with_set(idx, LeafU64::new(*v)).unwrap();
                        tree = tree.with_set(idx, LeafU64::new(*v)).unwrap();
                    }
                }
                Op::FromVec(values) => {
                    // Clamp to MAX_N.
                    let clamped: Vec<LeafU64> = values
                        .iter()
                        .take(MAX_N as usize)
                        .map(|&v| LeafU64::new(v))
                        .collect();
                    naive = SszList::<LeafU64, MAX_N>::from_vec(clamped.clone())
                        .expect("from_vec always succeeds within limit");
                    tree = SszList::<LeafU64, MAX_N>::from_vec_tree(clamped)
                        .expect("from_vec_tree always succeeds within limit");
                }
            }

            assert_backends_agree(&naive, &tree, &step)?;
        }
    }

    /// Spot-check: a single `from_vec` / `from_vec_tree` of a random slice
    /// produces identical roots and bytes.
    #[test]
    fn tree_and_naive_from_vec_agree(
        values in prop::collection::vec(0u64..0x1000u64, 0..=64usize)
    ) {
        let elems: Vec<LeafU64> = values.iter().map(|&v| LeafU64::new(v)).collect();
        let naive = SszList::<LeafU64, MAX_N>::from_vec(elems.clone()).unwrap();
        let tree = SszList::<LeafU64, MAX_N>::from_vec_tree(elems).unwrap();
        assert_backends_agree(&naive, &tree, "from_vec")?;
    }

    /// Spot-check: `SszVector` tree vs naive backend agreement.
    #[test]
    fn tree_and_naive_vector_agree(
        v0 in 0u64..0x1000u64,
        v1 in 0u64..0x1000u64,
        v2 in 0u64..0x1000u64,
        v3 in 0u64..0x1000u64,
    ) {
        let elems = vec![
            LeafU64::new(v0),
            LeafU64::new(v1),
            LeafU64::new(v2),
            LeafU64::new(v3),
        ];
        let naive = SszVector::<LeafU64, 4>::from_vec(elems.clone()).unwrap();
        let tree = SszVector::<LeafU64, 4>::from_vec_tree(elems).unwrap();

        prop_assert_eq!(naive.tree_hash_root(), tree.tree_hash_root());
        prop_assert_eq!(naive.as_ssz_bytes(), tree.as_ssz_bytes());
        for i in 0..4 {
            prop_assert_eq!(naive.get(i), tree.get(i));
        }
    }
}

// ── PackedLeaf: raw `u64` is a multi-per-chunk basic (4 per 32-byte chunk) ──────

proptest! {
    #![proptest_config(ProptestConfig { cases: CASES, ..Default::default() })]

    /// Lockstep transcript for a packed-basic `SszList<u64, MAX_N>`: every
    /// `push`/`set`/`from_vec` must keep the chunk-indexed `PackedLeaf` tree
    /// byte-identical to the Naive backend (root, ssz bytes, and per-element
    /// reads). Exercises partial final chunks, cross-chunk sets, and CoW.
    #[test]
    fn packed_tree_and_naive_agree_on_list(
        ops in prop::collection::vec(op_strategy(), 1..=60)
    ) {
        let mut naive = SszList::<u64, MAX_N>::new();
        let mut tree = SszList::<u64, MAX_N>::empty_tree();

        for (step_idx, op) in ops.iter().enumerate() {
            match op {
                Op::Push(v) => {
                    if naive.len() < MAX_N as usize {
                        naive = naive.with_push(*v).unwrap();
                        tree = tree.with_push(*v).unwrap();
                    }
                }
                Op::Set(i, v) => {
                    let len = naive.len();
                    if len > 0 {
                        let idx = i % len;
                        naive = naive.with_set(idx, *v).unwrap();
                        tree = tree.with_set(idx, *v).unwrap();
                    }
                }
                Op::FromVec(values) => {
                    let clamped: Vec<u64> =
                        values.iter().take(MAX_N as usize).copied().collect();
                    naive = SszList::<u64, MAX_N>::from_vec(clamped.clone()).unwrap();
                    tree = SszList::<u64, MAX_N>::from_vec_tree(clamped).unwrap();
                }
            }

            prop_assert_eq!(naive.len(), tree.len(), "len mismatch at step {}", step_idx);
            prop_assert_eq!(
                naive.tree_hash_root(),
                tree.tree_hash_root(),
                "root mismatch at step {}",
                step_idx
            );
            prop_assert_eq!(naive.as_ssz_bytes(), tree.as_ssz_bytes());
            for i in 0..naive.len() {
                prop_assert_eq!(naive.get(i), tree.get(i), "get({}) mismatch", i);
            }
        }
    }

    /// Packed `SszVector` at sizes that stress chunk boundaries: N=5 spans two
    /// chunks with a partial final chunk; N=8 is exactly two full chunks.
    #[test]
    fn packed_tree_and_naive_agree_on_vectors(
        a in prop::collection::vec(0u64..u64::MAX, 5),
        b in prop::collection::vec(0u64..u64::MAX, 8),
    ) {
        let n5 = SszVector::<u64, 5>::from_vec(a.clone()).unwrap();
        let t5 = SszVector::<u64, 5>::from_vec_tree(a).unwrap();
        prop_assert_eq!(n5.tree_hash_root(), t5.tree_hash_root());
        prop_assert_eq!(n5.as_ssz_bytes(), t5.as_ssz_bytes());

        let n8 = SszVector::<u64, 8>::from_vec(b.clone()).unwrap();
        let t8 = SszVector::<u64, 8>::from_vec_tree(b).unwrap();
        prop_assert_eq!(n8.tree_hash_root(), t8.tree_hash_root());
        prop_assert_eq!(n8.as_ssz_bytes(), t8.as_ssz_bytes());
    }
}
