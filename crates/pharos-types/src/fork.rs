//! Fork digest and fork data root helpers.
//!
//! `compute_fork_data_root` is the canonical home for this function;
//! `pharos-stf` re-exports it from here.
//!
//! Spec: `specs/phase0/beacon-chain.md:936-948` (fork data root),
//!       `specs/phase0/p2p-interface.md:269-285` (fork digest).

use pharos_ssz::TreeHash;

use crate::phase0::misc::ForkData;
use crate::phase0::primitives::{ForkDigest, Root, Version};

/// `compute_fork_data_root` per `specs/phase0/beacon-chain.md:936-948`.
///
/// Returns the `hash_tree_root` of a `ForkData` container built from
/// `current_version` and `genesis_validators_root`.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: &Root) -> Root {
    ForkData {
        current_version,
        genesis_validators_root: *genesis_validators_root,
    }
    .tree_hash_root()
}

/// `compute_fork_digest` per `specs/phase0/p2p-interface.md:269-285`.
///
/// Returns the first 4 bytes of `compute_fork_data_root(current_version,
/// genesis_validators_root)` as a `ForkDigest`.
pub fn compute_fork_digest(current_version: Version, genesis_validators_root: &Root) -> ForkDigest {
    let root = compute_fork_data_root(current_version, genesis_validators_root);
    let bytes = root.as_slice();
    ForkDigest::from_array([bytes[0], bytes[1], bytes[2], bytes[3]])
}
