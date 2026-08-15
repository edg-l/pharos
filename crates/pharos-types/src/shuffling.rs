//! `compute_shuffled_index` — single-index swap-or-not shuffle.
//!
//! Moved from `pharos-stf::phase0::shuffling` so that `pharos-network` can
//! call it for subnet assignment (`compute_subscribed_subnets`) without
//! creating a cyclic dependency on `pharos-stf`.
//!
//! Per `specs/phase0/beacon-chain.md:848-853`.

use pharos_utils::Hash256;
use pharos_utils::hash::hash;

/// Return the shuffled index corresponding to `seed` and `index_count`.
///
/// Per `specs/phase0/beacon-chain.md:848-853`.
///
/// Implements the single-index swap-or-not algorithm from the Swap-or-Not
/// Feistel shuffle paper (Hoang et al., 2012). This is O(round_count) and
/// equivalent to indexing into the full permutation, but avoids allocating
/// the complete permutation array.
///
/// # Panics
///
/// Panics if `index >= index_count`.
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

/// Interpret the first 8 bytes of `data` as a little-endian `u64`.
fn bytes_to_uint64(data: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    let len = data.len().min(8);
    arr[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(arr)
}
