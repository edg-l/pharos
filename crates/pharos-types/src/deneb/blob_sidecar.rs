//! Deneb blob sidecar types.
//!
//! Per `specs/deneb/p2p-interface.md:75-93` and `specs/deneb/beacon-chain.md`.

use pharos_ssz::{Decode, Encode, SszVector, TreeHash};
use pharos_utils::Hash256;

use crate::deneb::blob::{Blob, BlobIndex, KZGCommitment, KZGProof};
use crate::phase0::operations::SignedBeaconBlockHeader;

/// Inclusion proof depth for `blob_kzg_commitments[index]` in the beacon block body.
///
/// Per `specs/deneb/p2p-interface.md` and the `deneb/merkle_proof` fixtures.
/// The generalised index of `blob_kzg_commitments[i]` in the block body is
/// `2 * MAX_BLOB_COMMITMENTS_PER_BLOCK + i` (= `8192 + i` for mainnet where
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096`), at depth 17.
pub const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: usize = 17;

// ── BlobIdentifier ────────────────────────────────────────────────────────────

/// Identifies a single blob by its beacon block root and position within that block.
///
/// Used as the key in `BlobSidecarsByRoot` requests per
/// `specs/deneb/p2p-interface.md`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BlobIdentifier {
    /// Root of the `SignedBeaconBlock` that carries this blob's commitment.
    pub block_root: Hash256,
    /// Index of the blob within the block's `blob_kzg_commitments` list.
    pub index: BlobIndex,
}

// ── BlobSidecar ───────────────────────────────────────────────────────────────

/// `BlobSidecar` — a blob together with its KZG commitment, proof, and
/// Merkle inclusion proof.
///
/// Per `specs/deneb/p2p-interface.md:75-93`:
/// ```text
/// class BlobSidecar(Container):
///     index: BlobIndex
///     blob: Blob
///     kzg_commitment: KZGCommitment
///     kzg_proof: KZGProof
///     signed_block_header: SignedBeaconBlockHeader
///     kzg_commitment_inclusion_proof: Vector[Bytes32, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH]
/// ```
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BlobSidecar {
    /// Position of this blob in the block's `blob_kzg_commitments` list.
    pub index: BlobIndex,
    /// The 131072-byte blob data.
    pub blob: Blob,
    /// KZG commitment to this blob.
    pub kzg_commitment: KZGCommitment,
    /// KZG proof for the blob–commitment pair.
    pub kzg_proof: KZGProof,
    /// Signed header of the block that includes this blob.
    pub signed_block_header: SignedBeaconBlockHeader,
    /// Merkle branch proving `kzg_commitment` is in the block body.
    pub kzg_commitment_inclusion_proof:
        SszVector<Hash256, { KZG_COMMITMENT_INCLUSION_PROOF_DEPTH as u64 }>,
}

#[cfg(test)]
mod tests {
    use pharos_ssz::{Decode, Encode, TreeHash};

    use super::BlobSidecar;

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(val: T) {
        let encoded = val.as_ssz_bytes();
        let decoded = T::from_ssz_bytes(&encoded).expect("SSZ decode failed");
        assert_eq!(val, decoded, "roundtrip mismatch");
    }

    #[test]
    fn blob_sidecar_ssz_roundtrip() {
        roundtrip(BlobSidecar::default());
    }

    #[test]
    fn blob_sidecar_tree_hash_root_is_stable() {
        let s = BlobSidecar::default();
        // Compute twice; must be identical (tests determinism, not a specific value).
        let r1 = s.tree_hash_root();
        let r2 = s.tree_hash_root();
        assert_eq!(r1, r2, "tree_hash_root is not deterministic");
    }
}
