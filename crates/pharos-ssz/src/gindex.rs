//! Generalized Merkle index arithmetic.
//!
//! Implements the `generalized_index_*` helpers from
//! `consensus-specs/ssz/merkle-proofs.md`.
//!
//! # Generalized index layout
//!
//! A perfect binary tree assigns each node a **generalized index** `g`:
//!
//! ```text
//!         1          (root — depth 0)
//!        / \
//!       2   3        (depth 1)
//!      / \ / \
//!     4  5 6  7      (depth 2)
//! ```
//!
//! - `g = 1` is the root.
//! - Left child of `g` = `2 * g`.
//! - Right child of `g` = `2 * g + 1`.
//! - Parent of `g` = `g / 2`.
//! - Sibling of `g` = `g ^ 1` (flip the lowest bit).
//! - Depth of `g` = `floor(log2(g))`.

/// Type alias for a generalized Merkle index.
pub type GeneralizedIndex = u64;

/// Return the depth of a generalized index in the tree.
///
/// Depth is defined as `floor(log2(g))`. The root (`g = 1`) is at depth 0.
///
/// # Examples
///
/// ```
/// # use pharos_ssz::gindex::get_generalized_index_length;
/// assert_eq!(get_generalized_index_length(1), 0); // root
/// assert_eq!(get_generalized_index_length(2), 1); // left child of root
/// assert_eq!(get_generalized_index_length(3), 1); // right child of root
/// assert_eq!(get_generalized_index_length(4), 2);
/// assert_eq!(get_generalized_index_length(7), 2);
/// ```
pub fn get_generalized_index_length(g: GeneralizedIndex) -> usize {
    assert!(g >= 1, "generalized index must be >= 1");
    (u64::BITS - g.leading_zeros() - 1) as usize
}

/// Return the bit at position `pos` of the generalized index `g`.
///
/// Mirrors the spec's `get_generalized_index_bit(index, position)`:
/// `(index & (1 << position)) > 0`. Bit 0 is the LSB — the branching
/// direction immediately at the leaf — and bit `depth-1` is the
/// most-significant path bit (the first branch from the root).
///
/// A `false` bit means "left child", a `true` bit means "right child".
///
/// # Examples
///
/// ```
/// # use pharos_ssz::gindex::get_generalized_index_bit;
/// // g = 6 (binary 110): LSB is bit 0 = 0, bit 1 = 1, bit 2 = 1.
/// assert_eq!(get_generalized_index_bit(6, 0), false);
/// assert_eq!(get_generalized_index_bit(6, 1), true);
/// assert_eq!(get_generalized_index_bit(6, 2), true);
/// ```
pub fn get_generalized_index_bit(g: GeneralizedIndex, pos: usize) -> bool {
    (g >> pos) & 1 == 1
}

/// Return the sibling of a generalized index.
///
/// The sibling is the node at the same depth sharing the same parent.
/// `sibling(g) = g ^ 1` (flip the lowest bit).
///
/// # Examples
///
/// ```
/// # use pharos_ssz::gindex::generalized_index_sibling;
/// assert_eq!(generalized_index_sibling(2), 3); // left ↔ right
/// assert_eq!(generalized_index_sibling(3), 2);
/// assert_eq!(generalized_index_sibling(4), 5);
/// assert_eq!(generalized_index_sibling(5), 4);
/// ```
pub fn generalized_index_sibling(g: GeneralizedIndex) -> GeneralizedIndex {
    g ^ 1
}

/// Return the parent of a generalized index.
///
/// `parent(g) = g / 2`. The parent of the root (g=1) is 0, which is not a
/// valid index; callers should check `g > 1` before calling.
///
/// # Examples
///
/// ```
/// # use pharos_ssz::gindex::generalized_index_parent;
/// assert_eq!(generalized_index_parent(2), 1); // left child of root
/// assert_eq!(generalized_index_parent(3), 1); // right child of root
/// assert_eq!(generalized_index_parent(4), 2);
/// assert_eq!(generalized_index_parent(7), 3);
/// ```
pub fn generalized_index_parent(g: GeneralizedIndex) -> GeneralizedIndex {
    g / 2
}

/// Return a child of a generalized index.
///
/// `child(g, false) = 2 * g` (left child),
/// `child(g, true)  = 2 * g + 1` (right child).
///
/// # Examples
///
/// ```
/// # use pharos_ssz::gindex::generalized_index_child;
/// assert_eq!(generalized_index_child(1, false), 2); // left child of root
/// assert_eq!(generalized_index_child(1, true),  3); // right child of root
/// assert_eq!(generalized_index_child(2, false), 4);
/// assert_eq!(generalized_index_child(2, true),  5);
/// ```
pub fn generalized_index_child(g: GeneralizedIndex, right_side: bool) -> GeneralizedIndex {
    g * 2 + u64::from(right_side)
}

/// Concatenate two generalized indices into a single index that represents the
/// path obtained by first following `parent`'s path then `child`'s path.
///
/// Implements `concat_generalized_indices(indices)` from the spec for the
/// two-argument case.
///
/// Formula: `parent * next_pow2(child) + (child - next_pow2(child))`
/// which simplifies to: `parent * next_pow2(child) + (child XOR next_pow2(child))`
///
/// More concretely: strip the leading `1` from `child`, then shift `parent` up
/// by the path-length of `child` and OR in the stripped bits.
///
/// # Examples
///
/// ```
/// # use pharos_ssz::gindex::concat_generalized_indices;
/// // concat(root=1, node=1) = 1
/// assert_eq!(concat_generalized_indices(1, 1), 1);
/// // concat(root=1, any) = any
/// assert_eq!(concat_generalized_indices(1, 6), 6);
/// // concat(left-child=2, right-child-of-that=3) = gindex 5 (right child of index 2)
/// assert_eq!(concat_generalized_indices(2, 3), 5);
/// // concat(right-child=3, right-child-of-that=3) = gindex 7
/// assert_eq!(concat_generalized_indices(3, 3), 7);
/// ```
pub fn concat_generalized_indices(
    parent: GeneralizedIndex,
    child: GeneralizedIndex,
) -> GeneralizedIndex {
    assert!(parent >= 1, "parent must be >= 1");
    assert!(child >= 1, "child must be >= 1");
    let child_depth = get_generalized_index_length(child);
    // next power of two at depth = 2^child_depth
    let next_pow: u64 = 1u64 << child_depth;
    // Strip the leading 1 bit from child.
    let child_path_bits = child ^ next_pow;
    parent * next_pow + child_path_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_of_root_is_zero() {
        assert_eq!(get_generalized_index_length(1), 0);
    }

    #[test]
    fn depth_of_depth1_nodes() {
        assert_eq!(get_generalized_index_length(2), 1);
        assert_eq!(get_generalized_index_length(3), 1);
    }

    #[test]
    fn depth_of_depth2_nodes() {
        for g in 4..=7 {
            assert_eq!(get_generalized_index_length(g), 2, "g={g}");
        }
    }

    #[test]
    fn depth_of_depth3_nodes() {
        for g in 8..=15 {
            assert_eq!(get_generalized_index_length(g), 3, "g={g}");
        }
    }

    #[test]
    fn sibling_pairs() {
        assert_eq!(generalized_index_sibling(2), 3);
        assert_eq!(generalized_index_sibling(3), 2);
        assert_eq!(generalized_index_sibling(4), 5);
        assert_eq!(generalized_index_sibling(5), 4);
        assert_eq!(generalized_index_sibling(6), 7);
        assert_eq!(generalized_index_sibling(7), 6);
    }

    #[test]
    fn parent_of_root_children() {
        assert_eq!(generalized_index_parent(2), 1);
        assert_eq!(generalized_index_parent(3), 1);
    }

    #[test]
    fn parent_depth2() {
        assert_eq!(generalized_index_parent(4), 2);
        assert_eq!(generalized_index_parent(5), 2);
        assert_eq!(generalized_index_parent(6), 3);
        assert_eq!(generalized_index_parent(7), 3);
    }

    #[test]
    fn child_from_root() {
        assert_eq!(generalized_index_child(1, false), 2);
        assert_eq!(generalized_index_child(1, true), 3);
    }

    #[test]
    fn child_depth1() {
        assert_eq!(generalized_index_child(2, false), 4);
        assert_eq!(generalized_index_child(2, true), 5);
        assert_eq!(generalized_index_child(3, false), 6);
        assert_eq!(generalized_index_child(3, true), 7);
    }

    #[test]
    fn concat_root_identity() {
        // concat(1, x) = x for any x
        for g in 1u64..=15 {
            assert_eq!(concat_generalized_indices(1, g), g, "g={g}");
        }
    }

    #[test]
    fn concat_examples_from_spec() {
        // concat(2, 3) = right child of node 2 = gindex 5
        assert_eq!(concat_generalized_indices(2, 3), 5);
        // concat(3, 3) = right child of node 3 = gindex 7
        assert_eq!(concat_generalized_indices(3, 3), 7);
        // concat(2, 2) = left child of node 2 = gindex 4
        assert_eq!(concat_generalized_indices(2, 2), 4);
    }

    #[test]
    fn bit_extraction_matches_spec() {
        // Bit i of g is the i-th LSB (spec: `(g & (1 << i)) > 0`).
        // g=6 binary 110: bit0=0, bit1=1, bit2=1.
        assert!(!get_generalized_index_bit(6, 0));
        assert!(get_generalized_index_bit(6, 1));
        assert!(get_generalized_index_bit(6, 2));
        // g=5 binary 101: bit0=1, bit1=0, bit2=1.
        assert!(get_generalized_index_bit(5, 0));
        assert!(!get_generalized_index_bit(5, 1));
        assert!(get_generalized_index_bit(5, 2));
    }
}
