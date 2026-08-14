//! Single-leaf Merkle proofs.
//!
//! Implements proof generation and verification following
//! `consensus-specs/ssz/merkle-proofs.md`.
//!
//! # Generalized index usage
//!
//! A proof is identified by the **generalized index** of the leaf within the
//! tree. Verification walks the index bits from root to leaf, hashing siblings
//! at each level, and checks that the reconstructed root matches the expected
//! value.
//!
//! # Leaf indexing for `build_single_proof_from_leaves`
//!
//! When given a flat slice of leaves `[l0, l1, ..., l_{n-1}]`, the caller
//! provides a generalized index identifying the specific leaf in the
//! power-of-two–padded tree. Leaf 0 is at gindex `next_pow2(n)`, leaf 1 at
//! `next_pow2(n) + 1`, etc.

use crate::{
    gindex::{GeneralizedIndex, get_generalized_index_length},
    tree_hash::{next_pow_of_two, zero_hash},
};
use pharos_utils::{Hash256, hash::hash_concat};

// ── MerkleProof ───────────────────────────────────────────────────────────────

/// A single-leaf Merkle proof.
///
/// Proves that `leaf` is the node at position `index` in the tree whose root
/// is reconstructed via `verify_merkle_proof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// The leaf value being proven.
    pub leaf: Hash256,
    /// The sibling hashes along the path from the leaf to the root.
    ///
    /// `branch[0]` is the sibling at the leaf level; `branch[depth-1]` is the
    /// sibling one level below the root. Length equals `depth(index)`.
    pub branch: Vec<Hash256>,
    /// The generalized index of the leaf.
    pub index: GeneralizedIndex,
}

// ── Verification ──────────────────────────────────────────────────────────────

/// Verify a single-leaf Merkle proof against a known root.
///
/// Returns `true` iff `proof.leaf` is correctly positioned at `proof.index`
/// in a tree with the given `root`.
///
/// # Algorithm
///
/// Starting from `proof.leaf`, repeatedly hash with the sibling from
/// `proof.branch`, choosing left/right based on the index bits (LSB first).
/// After consuming all branch elements the result must equal `root`.
pub fn verify_merkle_proof(root: Hash256, proof: &MerkleProof) -> bool {
    let depth = get_generalized_index_length(proof.index);
    if proof.branch.len() != depth {
        return false;
    }

    let mut current = proof.leaf;
    let mut index = proof.index;

    // Process from leaf to root: LSB of index tells us left/right at each step.
    for &sibling in &proof.branch {
        if index & 1 == 1 {
            // Current node is a right child: hash(sibling, current)
            current = hash_concat(sibling.as_ref(), current.as_ref());
        } else {
            // Current node is a left child: hash(current, sibling)
            current = hash_concat(current.as_ref(), sibling.as_ref());
        }
        index /= 2;
    }

    current == root
}

// ── Proof generation ──────────────────────────────────────────────────────────

/// Build a single-leaf Merkle proof from a flat slice of leaves.
///
/// The `leaves` slice is treated as the leaf layer of a perfect binary tree
/// whose size is padded to the next power of two with zero hashes. `index` is
/// the **generalized index** of the leaf to prove.
///
/// The leaf at position `k` (0-based) in the padded tree has generalized index
/// `next_pow2(leaves.len()) + k`.
///
/// # Panics
///
/// Panics if `index` does not correspond to a leaf in the padded tree (i.e. if
/// `index < next_pow2(leaves.len())` or `index - next_pow2(leaves.len()) >=
/// leaves.len()`).
pub fn build_single_proof_from_leaves(leaves: &[Hash256], index: GeneralizedIndex) -> MerkleProof {
    let n = next_pow_of_two(leaves.len().max(1));
    let leaf_base = n as u64;

    assert!(
        index >= leaf_base && (index - leaf_base) < n as u64,
        "generalized index {index} is not a valid leaf in a tree with {n} leaves \
         (valid range [{leaf_base}, {}])",
        leaf_base + n as u64 - 1,
    );

    let leaf_pos = (index - leaf_base) as usize;

    // Build the full padded layer.
    let mut layer: Vec<Hash256> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    while layer.len() < n {
        layer.push(zero_hash(0));
    }

    let leaf = layer[leaf_pos];
    let depth = get_generalized_index_length(index);
    let mut branch = Vec::with_capacity(depth);

    // Walk up from leaf to root, collecting siblings.
    let mut cur_layer = layer;
    let mut cur_pos = leaf_pos;

    while cur_layer.len() > 1 {
        let sibling_pos = cur_pos ^ 1;
        branch.push(cur_layer[sibling_pos]);

        // Reduce layer: hash pairs.
        let next_len = cur_layer.len() / 2;
        let mut next_layer = Vec::with_capacity(next_len);
        for pair in cur_layer.chunks_exact(2) {
            next_layer.push(hash_concat(pair[0].as_ref(), pair[1].as_ref()));
        }
        cur_layer = next_layer;
        cur_pos /= 2;
    }

    MerkleProof {
        leaf,
        branch,
        index,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_hash::{merkleize, zero_hash};
    use pharos_utils::{Hash256, hash::hash_concat};

    fn h(b: u8) -> Hash256 {
        Hash256::from_array([b; 32])
    }

    fn root_of_4_leaves(l0: Hash256, l1: Hash256, l2: Hash256, l3: Hash256) -> Hash256 {
        let parent01 = hash_concat(l0.as_ref(), l1.as_ref());
        let parent23 = hash_concat(l2.as_ref(), l3.as_ref());
        hash_concat(parent01.as_ref(), parent23.as_ref())
    }

    // ── 4-leaf tree ──────────────────────────────────────────────────────────

    #[test]
    fn proof_4_leaf_leaf0() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        // Leaf 0 is at gindex 4.
        let proof = build_single_proof_from_leaves(&leaves, 4);
        assert_eq!(proof.leaf, h(0));
        assert_eq!(proof.branch.len(), 2);
        assert!(verify_merkle_proof(root, &proof));
    }

    #[test]
    fn proof_4_leaf_leaf1() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        // Leaf 1 is at gindex 5.
        let proof = build_single_proof_from_leaves(&leaves, 5);
        assert_eq!(proof.leaf, h(1));
        assert!(verify_merkle_proof(root, &proof));
    }

    #[test]
    fn proof_4_leaf_leaf2() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        let proof = build_single_proof_from_leaves(&leaves, 6);
        assert_eq!(proof.leaf, h(2));
        assert!(verify_merkle_proof(root, &proof));
    }

    #[test]
    fn proof_4_leaf_leaf3() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        let proof = build_single_proof_from_leaves(&leaves, 7);
        assert_eq!(proof.leaf, h(3));
        assert!(verify_merkle_proof(root, &proof));
    }

    #[test]
    fn proof_4_leaf_tampered_branch_fails() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        let mut proof = build_single_proof_from_leaves(&leaves, 4);
        // Corrupt the first branch element.
        proof.branch[0] = h(0xFF);
        assert!(!verify_merkle_proof(root, &proof));
    }

    #[test]
    fn proof_4_leaf_tampered_leaf_fails() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        let mut proof = build_single_proof_from_leaves(&leaves, 4);
        // Corrupt the leaf.
        proof.leaf = h(0xAA);
        assert!(!verify_merkle_proof(root, &proof));
    }

    // ── 8-leaf tree ──────────────────────────────────────────────────────────

    fn root_of_8_leaves(ls: &[Hash256; 8]) -> Hash256 {
        let p01 = hash_concat(ls[0].as_ref(), ls[1].as_ref());
        let p23 = hash_concat(ls[2].as_ref(), ls[3].as_ref());
        let p45 = hash_concat(ls[4].as_ref(), ls[5].as_ref());
        let p67 = hash_concat(ls[6].as_ref(), ls[7].as_ref());
        let p0123 = hash_concat(p01.as_ref(), p23.as_ref());
        let p4567 = hash_concat(p45.as_ref(), p67.as_ref());
        hash_concat(p0123.as_ref(), p4567.as_ref())
    }

    #[test]
    fn proof_8_leaf_all_positions() {
        let leaves: [Hash256; 8] = [h(0), h(1), h(2), h(3), h(4), h(5), h(6), h(7)];
        let root = root_of_8_leaves(&leaves);
        for k in 0..8u64 {
            let gindex = 8 + k;
            let proof = build_single_proof_from_leaves(&leaves, gindex);
            assert_eq!(proof.leaf, leaves[k as usize], "leaf {k}");
            assert_eq!(proof.branch.len(), 3, "depth should be 3 for leaf {k}");
            assert!(
                verify_merkle_proof(root, &proof),
                "proof failed for leaf {k}"
            );
        }
    }

    #[test]
    fn proof_8_leaf_tampered_branch_fails() {
        let leaves: [Hash256; 8] = [h(0), h(1), h(2), h(3), h(4), h(5), h(6), h(7)];
        let root = root_of_8_leaves(&leaves);
        let mut proof = build_single_proof_from_leaves(&leaves, 8);
        proof.branch[1] = h(0xFF);
        assert!(!verify_merkle_proof(root, &proof));
    }

    // ── Single-leaf tree (degenerate) ────────────────────────────────────────

    #[test]
    fn proof_single_leaf() {
        let leaves = [h(42)];
        // Single leaf: next_pow2(1) = 1, gindex = 1. Depth = 0, branch is empty.
        let proof = build_single_proof_from_leaves(&leaves, 1);
        assert_eq!(proof.leaf, h(42));
        assert_eq!(proof.branch.len(), 0);
        let root = merkleize(&leaves);
        assert!(verify_merkle_proof(root, &proof));
    }

    // ── Two-leaf tree ─────────────────────────────────────────────────────────

    #[test]
    fn proof_two_leaves() {
        let leaves = [h(10), h(20)];
        let root = hash_concat(leaves[0].as_ref(), leaves[1].as_ref());
        // Leaf 0 at gindex 2, leaf 1 at gindex 3.
        let proof0 = build_single_proof_from_leaves(&leaves, 2);
        assert_eq!(proof0.leaf, h(10));
        assert_eq!(proof0.branch, vec![h(20)]);
        assert!(verify_merkle_proof(root, &proof0));

        let proof1 = build_single_proof_from_leaves(&leaves, 3);
        assert_eq!(proof1.leaf, h(20));
        assert_eq!(proof1.branch, vec![h(10)]);
        assert!(verify_merkle_proof(root, &proof1));
    }

    // ── Proof with zero-padded leaves ─────────────────────────────────────────

    #[test]
    fn proof_non_power_of_two_padded() {
        // 3 leaves: tree has 4 slots (next_pow2(3)=4), leaf 3 is zero.
        let leaves = [h(1), h(2), h(3)];
        let zero = zero_hash(0);
        let p01 = hash_concat(leaves[0].as_ref(), leaves[1].as_ref());
        let p23 = hash_concat(leaves[2].as_ref(), zero.as_ref());
        let root = hash_concat(p01.as_ref(), p23.as_ref());

        // Prove leaf at gindex 4 (position 0).
        let proof = build_single_proof_from_leaves(&leaves, 4);
        assert!(verify_merkle_proof(root, &proof));

        // Prove leaf at gindex 6 (position 2 = h(3)).
        let proof2 = build_single_proof_from_leaves(&leaves, 6);
        assert_eq!(proof2.leaf, h(3));
        // Its sibling should be the zero pad.
        assert_eq!(proof2.branch[0], zero);
        assert!(verify_merkle_proof(root, &proof2));
    }

    // ── verify_merkle_proof rejects wrong branch length ───────────────────────

    #[test]
    fn verify_wrong_branch_length_fails() {
        let leaves = [h(0), h(1), h(2), h(3)];
        let root = root_of_4_leaves(leaves[0], leaves[1], leaves[2], leaves[3]);
        let proof = MerkleProof {
            leaf: leaves[0],
            // Correct depth is 2 but we supply 1 branch element.
            branch: vec![h(1)],
            index: 4,
        };
        assert!(!verify_merkle_proof(root, &proof));
    }

    // ── sibling helper consistency ────────────────────────────────────────────

    #[test]
    fn sibling_in_proof_matches_gindex_sibling() {
        use crate::gindex::generalized_index_sibling;
        let leaves = [h(0), h(1), h(2), h(3)];
        let proof = build_single_proof_from_leaves(&leaves, 4); // leaf 0
        // The first branch element is the sibling (leaf 1).
        let expected_sibling_gindex = generalized_index_sibling(4); // = 5
        assert_eq!(expected_sibling_gindex, 5);
        assert_eq!(proof.branch[0], leaves[1]);
    }
}
