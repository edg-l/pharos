//! Persistent attestation subnet assignment.
//!
//! Implements `compute_subscribed_subnets` per
//! `specs/phase0/p2p-interface.md:1732-1751`.

use discv5::enr::NodeId;
use pharos_types::EthSpec;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use pharos_types::shuffling::compute_shuffled_index;
use pharos_utils::Hash256;
use pharos_utils::hash::hash;

use crate::types::SubnetId;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of long-lived subnets a beacon node should be subscribed to.
///
/// Source: `specs/phase0/p2p-interface.md` constant table.
pub const SUBNETS_PER_NODE: usize = 2;

/// Extra bits beyond `ceillog2(ATTESTATION_SUBNET_COUNT)` for the node-id
/// prefix. Phase 0 value is 0.
///
/// Source: `specs/phase0/p2p-interface.md` constant table.
pub const ATTESTATION_SUBNET_EXTRA_BITS: u64 = 0;

/// Number of epochs a node remains subscribed to a given set of subnets before
/// rotating.
///
/// Source: `specs/phase0/p2p-interface.md` constant table.
pub const EPOCHS_PER_SUBNET_SUBSCRIPTION: u64 = 256;

// ── compute_subscribed_subnets ────────────────────────────────────────────────

/// Return the two persistent attestation subnets for this node at `epoch`.
///
/// Implements `compute_subscribed_subnets(node_id, epoch)` per
/// `specs/phase0/p2p-interface.md:1732-1751`.
///
/// The number of shuffle rounds is taken from `E::SHUFFLE_ROUND_COUNT` so that
/// both mainnet (90 rounds) and minimal (10 rounds) presets behave correctly.
///
/// Algorithm (Phase 0 constants: prefix_bits = 6, ATTESTATION_SUBNET_COUNT = 64,
/// EPOCHS_PER_SUBNET_SUBSCRIPTION = 256, SUBNETS_PER_NODE = 2):
///
/// 1. `prefix_bits = ceillog2(ATTESTATION_SUBNET_COUNT) + ATTESTATION_SUBNET_EXTRA_BITS` (= 6).
/// 2. `node_id_prefix = node_id >> (256 - prefix_bits)` (top 6 bits of the 256-bit node-id).
/// 3. `node_offset = node_id mod EPOCHS_PER_SUBNET_SUBSCRIPTION` (bottom 8 bits).
/// 4. `permutation_seed = hash(uint64((epoch + node_offset) / EPOCHS_PER_SUBNET_SUBSCRIPTION).to_le_bytes())`.
/// 5. For each `index in 0..SUBNETS_PER_NODE`:
///    `permuted_prefix = compute_shuffled_index(node_id_prefix, 64, seed, E::SHUFFLE_ROUND_COUNT)`.
/// 6. `subnet = (permuted_prefix + index) mod ATTESTATION_SUBNET_COUNT`.
pub fn compute_subscribed_subnets<E: EthSpec>(
    node_id: NodeId,
    epoch: u64,
) -> [SubnetId; SUBNETS_PER_NODE] {
    // The 32-byte big-endian representation of the 256-bit node-id.
    let raw: [u8; 32] = node_id.raw();

    // Step 1: prefix_bits = ceillog2(64) + 0 = 6 (compile-time constant).
    // ceillog2(64) = 6 (since 64 = 2^6, ceil(log2(64)) = 6).
    const PREFIX_BITS: u64 = 6; // ceillog2(ATTESTATION_SUBNET_COUNT=64) + EXTRA_BITS=0

    // Step 2: node_id_prefix = top PREFIX_BITS bits of the 256-bit big-endian node-id.
    // The node-id is stored in `raw` as big-endian: raw[0] is the most-significant byte.
    // Shifting 256-bit integer right by (256 - 6) = 250 bits leaves only the top 6 bits.
    // Those 6 bits are raw[0] >> 2 (bits 7..2 of the first byte).
    let node_id_prefix: u64 = (raw[0] as u64) >> (8 - PREFIX_BITS);

    // Step 3: node_offset = node_id mod EPOCHS_PER_SUBNET_SUBSCRIPTION (= 256).
    // node_id mod 256 = the least-significant byte (raw[31] in big-endian).
    let node_offset: u64 = raw[31] as u64;

    // Step 4: permutation_seed = SHA256(uint64_le((epoch + node_offset) / EPOCHS_PER_SUBNET_SUBSCRIPTION)).
    let epoch_bucket = (epoch.wrapping_add(node_offset)) / EPOCHS_PER_SUBNET_SUBSCRIPTION;
    let seed_input = epoch_bucket.to_le_bytes();
    let seed_bytes: Hash256 = hash(&seed_input);

    // Steps 5 + 6: for each index, compute permuted prefix then derive subnet.
    let mut result = [0u64; SUBNETS_PER_NODE];
    for (i, slot) in result.iter_mut().enumerate() {
        let permuted = compute_shuffled_index(
            node_id_prefix,
            1 << PREFIX_BITS, // = 64 = ATTESTATION_SUBNET_COUNT
            &seed_bytes,
            E::SHUFFLE_ROUND_COUNT,
        );
        *slot = (permuted + i as u64) % ATTESTATION_SUBNET_COUNT;
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use pharos_types::MainnetEthSpec;

    use super::*;

    /// Hard-coded test vectors verified against the consensus-specs Python
    /// reference implementation (eth_consensus_specs, generated from
    /// `specs/phase0/p2p-interface.md` via `pysetup.generate_specs`).
    ///
    /// Python invocation used to produce these vectors
    /// (run from `~/dev/consensus-specs/` with the venv active):
    ///
    /// ```text
    /// python3 -c "
    /// from eth_consensus_specs.phase0 import mainnet as spec
    /// nid1 = spec.NodeID(int.from_bytes(bytes(range(1, 33)), 'big'))
    /// print('Vector 1:', list(spec.compute_subscribed_subnets(nid1, 100)))
    /// nid2 = spec.NodeID(int.from_bytes(b'\xab\xcd' + b'\xef'*30, 'big'))
    /// print('Vector 2:', list(spec.compute_subscribed_subnets(nid2, 42)))
    /// "
    /// ```
    ///
    /// Output:
    ///   Vector 1: [49, 50]
    ///   Vector 2: [0, 1]

    /// Vector 1: node_id = 0x0102...20 (bytes 1..=32), epoch = 100.
    ///
    /// node_id_prefix = raw[0] >> 2 = 0x01 >> 2 = 0.
    /// node_offset = raw[31] = 0x20 = 32.
    /// epoch_bucket = (100 + 32) / 256 = 0.
    /// Expected: [49, 50].
    #[test]
    fn subnet_vector_1() {
        let raw: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8); // 0x01..0x20
        let node_id = NodeId::from(raw);
        let result = compute_subscribed_subnets::<MainnetEthSpec>(node_id, 100);
        assert_eq!(result, [49, 50], "vector 1: expected [49, 50]");
    }

    /// Vector 2: node_id = 0xABCDEF...EF (first two bytes 0xAB 0xCD, rest 0xEF), epoch = 42.
    ///
    /// node_id_prefix = raw[0] >> 2 = 0xAB >> 2 = 42.
    /// node_offset = raw[31] = 0xEF = 239.
    /// epoch_bucket = (42 + 239) / 256 = 1.
    /// Expected: [0, 1].
    #[test]
    fn subnet_vector_2() {
        let mut raw = [0xEFu8; 32];
        raw[0] = 0xAB;
        raw[1] = 0xCD;
        let node_id = NodeId::from(raw);
        let result = compute_subscribed_subnets::<MainnetEthSpec>(node_id, 42);
        assert_eq!(result, [0, 1], "vector 2: expected [0, 1]");
    }
}
