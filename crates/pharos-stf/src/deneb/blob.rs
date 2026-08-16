//! Blob sidecar inclusion proof verification.
//!
//! Per `specs/deneb/beacon-chain.md` and `specs/deneb/p2p-interface.md`.

use pharos_ssz::{SszSequence as _, TreeHash};
use pharos_types::deneb::{BlobSidecar, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH};
use pharos_utils::Hash256;

use crate::phase0::operations::deposit::is_valid_merkle_branch;

/// The positional index base for `blob_kzg_commitments` within `BeaconBlockBody`.
///
/// Field index 11 of `BeaconBlockBody` (0-indexed), with `MAX_BLOB_COMMITMENTS_PER_BLOCK=4096`
/// which requires a list subtree of depth 13 (2^13=8192≥4096). The generalised index
/// of field 11 in the 16-field body tree is `16 + 11 = 27`, but the positional offset
/// for `is_valid_merkle_branch` at depth 17 is `11 * 8192 = 90112`.
///
/// Verified against fixture:
/// `deneb/merkle_proof/single_merkle_proof/BeaconBlockBody/blob_kzg_commitment_merkle_proof__*`
/// which shows `leaf_index: 221184` for blob_index=0; `221184 - 2^17 = 90112 = 11 * 8192`.
const KZG_COMMITMENTS_POSITIONAL_BASE: u64 = 11 * 8192;

/// Verify the KZG commitment inclusion proof in a `BlobSidecar`.
///
/// Per `specs/deneb/p2p-interface.md:497-585` (gossip validation rule set) and
/// `specs/deneb/beacon-chain.md` (inclusion proof definition).
///
/// Checks that `sidecar.kzg_commitment` appears at position `sidecar.index` in
/// `blob_kzg_commitments` of the block body whose Merkle root is
/// `sidecar.signed_block_header.message.body_root`, using the 17-element proof
/// `sidecar.kzg_commitment_inclusion_proof`.
pub fn verify_blob_sidecar_inclusion_proof(sidecar: &BlobSidecar) -> bool {
    // Leaf: hash_tree_root(kzg_commitment)
    let leaf: Hash256 = sidecar.kzg_commitment.tree_hash_root();

    // Branch: the 17-element inclusion proof
    let branch: Vec<Hash256> = sidecar
        .kzg_commitment_inclusion_proof
        .iter()
        .copied()
        .collect();

    // Index: positional index at depth 17
    let index = KZG_COMMITMENTS_POSITIONAL_BASE + sidecar.index;

    // Root: body_root from the block header
    let root: Hash256 = sidecar.signed_block_header.message.body_root;

    is_valid_merkle_branch(
        &leaf,
        &branch,
        KZG_COMMITMENT_INCLUSION_PROOF_DEPTH as u64,
        index,
        &root,
    )
}
