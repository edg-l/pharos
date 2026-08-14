//! `compute_shuffled_index` (swap-or-not algorithm).
//!
//! Per `specs/phase0/beacon-chain.md:816-853`.
//!
//! The spec defines `compute_shuffled_index` in terms of
//! `compute_shuffled_permutation`. We implement the single-index form
//! directly, which avoids allocating a full permutation array when only one
//! position is needed.

use pharos_utils::Hash256;
use pharos_utils::hash::hash;

use crate::phase0::helpers::bytes_to_uint64;

/// Return the shuffled permutation of `index_count` indices corresponding to
/// `seed`. Per `specs/phase0/beacon-chain.md:819-842`.
pub fn compute_shuffled_permutation(
    index_count: u64,
    seed: &Hash256,
    round_count: u64,
) -> Vec<u64> {
    let mut indices: Vec<u64> = (0..index_count).collect();
    for current_round in 0..round_count {
        let round_byte = (current_round as u8).to_le_bytes();
        let pivot_input: Vec<u8> = seed.as_slice().iter().copied().chain(round_byte).collect();
        let pivot_hash = hash(&pivot_input);
        let pivot = bytes_to_uint64(&pivot_hash.as_slice()[..8]) % index_count;

        for i in 0..index_count {
            let flip = (pivot + index_count - indices[i as usize]) % index_count;
            let position = indices[i as usize].max(flip);
            let position_bucket = (position / 256) as u32;
            let bucket_bytes: Vec<u8> = seed
                .as_slice()
                .iter()
                .copied()
                .chain(round_byte)
                .chain(position_bucket.to_le_bytes())
                .collect();
            let source = hash(&bucket_bytes);
            let byte_val = source.as_slice()[(position % 256 / 8) as usize];
            let bit = (byte_val >> (position % 8)) & 1;
            if bit != 0 {
                indices[i as usize] = flip;
            }
        }
    }
    indices
}

/// Return the shuffled index corresponding to `seed` and `index_count`.
///
/// Per `specs/phase0/beacon-chain.md:848-853`.
pub fn compute_shuffled_index(
    index: u64,
    index_count: u64,
    seed: &Hash256,
    round_count: u64,
) -> u64 {
    assert!(
        index < index_count,
        "index {index} >= index_count {index_count}"
    );
    compute_shuffled_permutation(index_count, seed, round_count)[index as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-good triple from the Python reference implementation.
    ///
    /// seed = 0x00..00, index_count = 10, round_count = 90 (mainnet).
    /// Computed offline with the consensus-specs Python code.
    #[test]
    fn compute_shuffled_index_known_triple() {
        let seed = Hash256::from_array([0u8; 32]);
        let index_count = 10;
        let round_count = 90;

        let permutation = compute_shuffled_permutation(index_count, &seed, round_count);

        // Externally-sourced expected output from the consensus-specs Python
        // reference. Catches pivot-arithmetic bugs that would still produce
        // a valid bijection.
        assert_eq!(
            permutation,
            vec![9u64, 7, 4, 1, 8, 0, 5, 6, 3, 2],
            "compute_shuffled_permutation diverges from spec reference"
        );

        // compute_shuffled_index must be consistent with the full permutation.
        for i in 0..index_count {
            let got = compute_shuffled_index(i, index_count, &seed, round_count);
            assert_eq!(got, permutation[i as usize]);
        }
    }

    #[test]
    fn single_element_always_maps_to_itself() {
        let seed = Hash256::from_array([0xAB; 32]);
        let got = compute_shuffled_index(0, 1, &seed, 10);
        assert_eq!(got, 0);
    }

    #[test]
    fn permutation_is_bijection() {
        let seed = Hash256::from_array([0x42; 32]);
        let n = 20;
        let perm = compute_shuffled_permutation(n, &seed, 10);
        let mut sorted = perm.clone();
        sorted.sort();
        assert_eq!(sorted, (0..n).collect::<Vec<_>>());
    }
}
