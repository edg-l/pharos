//! Blob sidecar inclusion proof verification and production.
//!
//! Per `specs/deneb/beacon-chain.md` and `specs/deneb/p2p-interface.md`.

use pharos_ssz::{SszSequence as _, TreeHash, build_single_proof_from_leaves};
use pharos_types::deneb::{BlobSidecar, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH, KZGCommitment};
use pharos_utils::Hash256;

use crate::phase0::operations::deposit::is_valid_merkle_branch;

/// The positional index base for `blob_kzg_commitments` within `BeaconBlockBody`.
///
/// Field index 11 of `BeaconBlockBody` (0-indexed), with `MAX_BLOB_COMMITMENTS_PER_BLOCK=4096`
/// which requires a list subtree of depth 12 (2^12=4096 elements) plus 1 mixin level = 13
/// total levels within the list. The generalized index for the list root in the body's
/// 16-leaf (depth-4) field tree is `16 + 11 = 27`. Positional offset for
/// `is_valid_merkle_branch` at depth 17: `11 * 8192 = 90112` (where 8192 = 2 * 4096 =
/// 2^13 accounts for both the data subtree and the length mixin level).
///
/// Verified against fixture:
/// `deneb/merkle_proof/single_merkle_proof/BeaconBlockBody/blob_kzg_commitment_merkle_proof__*`
/// which shows `leaf_index: 221184` for blob_index=0; `221184 - 2^17 = 90112 = 11 * 8192`.
const KZG_COMMITMENTS_POSITIONAL_BASE: u64 = 11 * 8192;

/// Capacity of the `blob_kzg_commitments` list Merkle tree.
///
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096` across all supported presets.
/// Data subtree depth = `log2(4096) = 12`.
const BLOB_COMMITMENTS_CAPACITY: usize = 4096;

/// Number of fields in `BeaconBlockBody` (Deneb), padded to a power of two.
///
/// 12 fields (randao_reveal..blob_kzg_commitments) → next power of two = 16.
const BODY_FIELD_TREE_SIZE: usize = 16;

/// Depth of the list data subtree (`log2(BLOB_COMMITMENTS_CAPACITY) = 12`).
const LIST_DATA_DEPTH: usize = 12;

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

/// Build the 17-element KZG commitment inclusion proof for
/// `blob_kzg_commitments[blob_index]` within the given block body.
///
/// The proof walks from the `KZGCommitment` leaf up 17 levels to the body root:
///
/// ```text
/// Levels  0..11 (12 siblings): within the list's data subtree (capacity=4096, depth=12)
/// Level  12     ( 1 sibling):  length-mixin boundary (sibling = length as Hash256)
/// Levels 13..16 ( 4 siblings): body field tree (field 11 at depth 4 in 16-leaf tree)
/// ```
///
/// `all_commitments` is the ordered slice of ALL commitments in the block body.
/// `all_body_field_hashes` is the array of the 12 body-field `tree_hash_root` values
/// in field order (`randao_reveal=0`, ..., `blob_kzg_commitments=11`).
/// `blob_index` is the 0-based index of the target commitment.
///
/// Panics if `blob_index >= all_commitments.len()` or inputs are inconsistent
/// (programming errors only; production code validates lengths before calling).
pub fn build_blob_sidecar_inclusion_proof(
    all_commitments: &[KZGCommitment],
    all_body_field_hashes: &[Hash256; 12],
    blob_index: usize,
) -> [Hash256; KZG_COMMITMENT_INCLUSION_PROOF_DEPTH] {
    assert!(
        blob_index < all_commitments.len(),
        "blob_index {blob_index} out of range (len={})",
        all_commitments.len()
    );

    // ── Part 1: 12 siblings within the list data subtree ─────────────────────
    //
    // The list's data root = merkleize_padded(element_roots, 4096).
    // build_single_proof_from_leaves uses a padded tree of size next_pow2(n).
    // We supply all 4096 zero-padded roots by passing the actual roots and
    // letting build_single_proof_from_leaves zero-pad to next_pow2 of its input.
    // Since we need EXACTLY capacity 4096 regardless of actual length, we pad
    // to 4096 first.
    let element_roots: Vec<Hash256> = {
        let mut roots: Vec<Hash256> = all_commitments.iter().map(|c| c.tree_hash_root()).collect();
        roots.resize(BLOB_COMMITMENTS_CAPACITY, Hash256::default());
        roots
    };
    // gindex of blob_index in a 4096-leaf tree: 4096 + blob_index.
    let list_gindex = BLOB_COMMITMENTS_CAPACITY as u64 + blob_index as u64;
    let list_proof = build_single_proof_from_leaves(&element_roots, list_gindex);
    debug_assert_eq!(list_proof.branch.len(), LIST_DATA_DEPTH);

    // ── Part 2: 1 sibling at the data/length-mixin level ─────────────────────
    //
    // `mix_in_length(data_root, len) = hash(data_root || len_as_32_bytes)`.
    // The data_root is the LEFT child; the right sibling is the length encoded as
    // a 32-byte little-endian uint256 (upper bytes are zero).
    let len = all_commitments.len() as u64;
    let mut length_as_hash = Hash256::default();
    length_as_hash.as_mut()[..8].copy_from_slice(&len.to_le_bytes());
    let mixin_sibling = length_as_hash;

    // ── Part 3: 4 siblings within the body field tree ────────────────────────
    //
    // The body has 12 fields padded to 16 leaves. Field index 11 =
    // blob_kzg_commitments (its tree_hash_root must equal all_body_field_hashes[11]).
    // gindex of field 11 in a 16-leaf tree: 16 + 11 = 27.
    let body_leaves: Vec<Hash256> = {
        let mut leaves = all_body_field_hashes.to_vec();
        leaves.resize(BODY_FIELD_TREE_SIZE, Hash256::default());
        leaves
    };
    let body_proof = build_single_proof_from_leaves(&body_leaves, 16 + 11);
    debug_assert_eq!(body_proof.branch.len(), 4);

    // ── Assemble the 17-element branch (bottom → top) ────────────────────────
    let mut branch = [Hash256::default(); KZG_COMMITMENT_INCLUSION_PROOF_DEPTH];

    // Levels 0..11: list data subtree siblings.
    branch[..LIST_DATA_DEPTH].copy_from_slice(&list_proof.branch);
    // Level 12: length-mixin sibling.
    branch[LIST_DATA_DEPTH] = mixin_sibling;
    // Levels 13..16: body field tree siblings.
    branch[LIST_DATA_DEPTH + 1..].copy_from_slice(&body_proof.branch);

    branch
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip test: build a proof with `build_blob_sidecar_inclusion_proof` and verify
    /// it passes `verify_blob_sidecar_inclusion_proof`.
    ///
    /// Uses a body with 2 non-zero commitments to exercise both leaf positions and
    /// confirm the length-mixin and body-field-tree path are computed correctly.
    #[test]
    fn blob_sidecar_inclusion_proof_round_trip() {
        use pharos_ssz::{SszList, TreeHash};
        use pharos_types::deneb::body::BeaconBlockBody;
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};

        // Minimal Deneb BeaconBlockBody type matching minimal preset constants.
        type Body = BeaconBlockBody<
            16,         // MAX_PROPOSER_SLASHINGS
            2,          // MAX_ATTESTER_SLASHINGS
            128,        // MAX_ATTESTATIONS
            16,         // MAX_DEPOSITS
            16,         // MAX_VOLUNTARY_EXITS
            2048,       // MAX_VALIDATORS_PER_COMMITTEE
            33,         // DEPOSIT_PROOF_LENGTH
            512,        // SYNC_COMMITTEE_SIZE
            1073741824, // MAX_BYTES_PER_TRANSACTION
            1048576,    // MAX_TRANSACTIONS_PER_PAYLOAD
            256,        // BYTES_PER_LOGS_BLOOM
            32,         // MAX_EXTRA_DATA_BYTES
            16,         // MAX_WITHDRAWALS_PER_PAYLOAD
            16,         // MAX_BLS_TO_EXECUTION_CHANGES
            4096,       // MAX_BLOB_COMMITMENTS_PER_BLOCK
        >;

        let commitment_0 = KZGCommitment::from_array([0x11u8; 48]);
        let commitment_1 = KZGCommitment::from_array([0x22u8; 48]);

        let body = Body {
            blob_kzg_commitments: SszList::from_vec(vec![commitment_0, commitment_1]).unwrap(),
            ..Body::default()
        };
        let body_root = body.tree_hash_root();

        // Extract the 12 body field hashes in field order (matching BeaconBlockBody layout).
        let field_hashes: [Hash256; 12] = [
            body.randao_reveal.tree_hash_root(),
            body.eth1_data.tree_hash_root(),
            body.graffiti.tree_hash_root(),
            body.proposer_slashings.tree_hash_root(),
            body.attester_slashings.tree_hash_root(),
            body.attestations.tree_hash_root(),
            body.deposits.tree_hash_root(),
            body.voluntary_exits.tree_hash_root(),
            body.sync_aggregate.tree_hash_root(),
            body.execution_payload.tree_hash_root(),
            body.bls_to_execution_changes.tree_hash_root(),
            body.blob_kzg_commitments.tree_hash_root(),
        ];

        let all_commitments = &[commitment_0, commitment_1];

        for blob_idx in 0..2usize {
            let proof =
                build_blob_sidecar_inclusion_proof(all_commitments, &field_hashes, blob_idx);
            let inclusion_proof = pharos_ssz::SszVector::from_items(proof.iter().copied()).unwrap();

            let sidecar = BlobSidecar {
                index: blob_idx as u64,
                kzg_commitment: all_commitments[blob_idx],
                signed_block_header: SignedBeaconBlockHeader {
                    message: BeaconBlockHeader {
                        body_root,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                kzg_commitment_inclusion_proof: inclusion_proof,
                ..BlobSidecar::default()
            };

            assert!(
                verify_blob_sidecar_inclusion_proof(&sidecar),
                "inclusion proof round-trip failed for blob_index={blob_idx}"
            );
        }
    }
}
