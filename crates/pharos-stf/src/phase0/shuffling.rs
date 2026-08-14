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
///
/// Batched form: amortises the per-bucket `hash(seed ++ round ++ bucket)`
/// across every index falling into the same 256-element bucket within the
/// same round. Output is bitwise-identical to repeated `compute_shuffled_index`
/// calls but does O(rounds * (1 + ceil(n/256))) hashes instead of O(n*rounds).
pub fn compute_shuffled_permutation(
    index_count: u64,
    seed: &Hash256,
    round_count: u64,
) -> Vec<u64> {
    use std::collections::HashMap;

    if index_count == 0 {
        return Vec::new();
    }

    let mut indices: Vec<u64> = (0..index_count).collect();

    // 37-byte buffer: seed(32) + round(1) + bucket(4).
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed.as_slice());

    for current_round in 0..round_count {
        buf[32] = current_round as u8;

        let pivot_hash = hash(&buf[..33]);
        let pivot = bytes_to_uint64(&pivot_hash.as_slice()[..8]) % index_count;

        let mut source_cache: HashMap<u32, Hash256> = HashMap::new();

        for idx in indices.iter_mut() {
            let flip = (pivot + index_count - *idx) % index_count;
            let position = (*idx).max(flip);
            let bucket = (position / 256) as u32;

            let source = source_cache.entry(bucket).or_insert_with(|| {
                buf[33..37].copy_from_slice(&bucket.to_le_bytes());
                hash(&buf[..37])
            });

            let byte_val = source.as_slice()[(position % 256 / 8) as usize];
            let bit = (byte_val >> (position % 8)) & 1;
            if bit != 0 {
                *idx = flip;
            }
        }
    }

    indices
}

/// Return the shuffled index corresponding to `seed` and `index_count`.
///
/// Per `specs/phase0/beacon-chain.md:848-853`.
///
/// Implements the single-index swap-or-not algorithm from the Swap-or-Not
/// Feistel shuffle paper (Hoang et al., 2012). This is O(round_count) and
/// equivalent to indexing into the full permutation, but avoids allocating
/// the complete permutation array.
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

    // 37-byte buffer: 32-byte seed + 1-byte round + 4-byte bucket.
    let mut buf = [0u8; 37];
    buf[..32].copy_from_slice(seed.as_slice());

    let mut cur = index;
    for current_round in 0..round_count {
        buf[32] = current_round as u8;

        // pivot = hash(seed ++ round)[0:8] % index_count
        let pivot_hash = hash(&buf[..33]);
        let pivot = bytes_to_uint64(&pivot_hash.as_slice()[..8]) % index_count;

        // flip = (pivot + index_count - cur) % index_count
        let flip = (pivot + index_count - cur) % index_count;

        // Swap cur <- flip depending on the bit at position max(cur, flip).
        let position = cur.max(flip);
        let bucket = (position / 256) as u32;
        buf[33..37].copy_from_slice(&bucket.to_le_bytes());

        let source = hash(&buf[..37]);
        let byte_val = source.as_slice()[(position % 256 / 8) as usize];
        let bit = (byte_val >> (position % 8)) & 1;
        if bit != 0 {
            cur = flip;
        }
    }
    cur
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
