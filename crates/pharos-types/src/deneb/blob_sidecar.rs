//! Deneb blob sidecar types.
//!
//! Per `specs/deneb/p2p-interface.md:75-93` and `specs/deneb/beacon-chain.md`.

use pharos_ssz::{Decode, Encode, SszError, SszList, SszVector, TreeHash};
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

// ── BlobSidecarsByRangeRequest ────────────────────────────────────────────────

/// `BlobSidecarsByRange` request per `specs/deneb/p2p-interface.md`.
///
/// SSZ-encoded as a container (two fixed-size u64 fields = 16 bytes total).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BlobSidecarsByRangeRequest {
    /// First slot to return sidecars for.
    pub start_slot: u64,
    /// Number of slots to return sidecars for.
    pub count: u64,
}

// ── BlobSidecarsByRootRequest ─────────────────────────────────────────────────

/// `BlobSidecarsByRoot` request per `specs/deneb/p2p-interface.md`.
///
/// SSZ-encoded as the bare `List[BlobIdentifier, N]` (single-field rule).
/// **No container offset.** Using derived SSZ would add a 4-byte offset prefix
/// and earn a -100 Lighthouse ban (the `D-blocksbyroot-bare-list` trap).
///
/// `Encode`/`Decode` are hand-written for the same reason as
/// `BeaconBlocksByRootRequest` in `pharos_types::phase0::operations`.
#[derive(TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BlobSidecarsByRootRequest<const MAX_REQUEST_BLOB_SIDECARS: u64> {
    /// The list of blob identifiers requested.
    pub blob_ids: SszList<BlobIdentifier, MAX_REQUEST_BLOB_SIDECARS>,
}

impl<const MAX_REQUEST_BLOB_SIDECARS: u64> Encode
    for BlobSidecarsByRootRequest<MAX_REQUEST_BLOB_SIDECARS>
{
    // Transparent over `blob_ids`: the request IS the list (single-field rule).
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        <SszList<BlobIdentifier, MAX_REQUEST_BLOB_SIDECARS> as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.blob_ids.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.blob_ids.ssz_append(buf);
    }
}

impl<const MAX_REQUEST_BLOB_SIDECARS: u64> Decode
    for BlobSidecarsByRootRequest<MAX_REQUEST_BLOB_SIDECARS>
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        <SszList<BlobIdentifier, MAX_REQUEST_BLOB_SIDECARS> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        Ok(Self {
            blob_ids: SszList::from_ssz_bytes(bytes)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use pharos_ssz::{Decode, Encode, TreeHash};

    use super::{BlobIdentifier, BlobSidecar, BlobSidecarsByRootRequest};

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

    /// `BlobSidecarsByRootRequest` MUST be the bare `List[BlobIdentifier, N]`
    /// with NO container offset.  Mirrors `blocks_by_root_request_is_bare_list_no_offset`.
    ///
    /// `BlobIdentifier` SSZ: block_root(32) + index(8) = 40 bytes fixed.
    #[test]
    fn blob_sidecars_by_root_request_is_bare_list_no_offset() {
        use pharos_ssz::SszList;
        use pharos_utils::Hash256;

        type Req = BlobSidecarsByRootRequest<768>;

        // Empty request: zero bytes (no offset prefix).
        let empty = Req::default();
        assert_eq!(
            empty.as_ssz_bytes().len(),
            0,
            "empty BlobSidecarsByRoot request must be 0 bytes, not 4"
        );

        // Two blob identifiers: 2 × 40 = 80 bytes, no prefix.
        let id0 = BlobIdentifier {
            block_root: Hash256::from([0x11u8; 32]),
            index: 0,
        };
        let id1 = BlobIdentifier {
            block_root: Hash256::from([0x22u8; 32]),
            index: 1,
        };
        let req = Req {
            blob_ids: SszList::from_vec(vec![id0.clone(), id1.clone()]).unwrap(),
        };
        let encoded = req.as_ssz_bytes();
        assert_eq!(
            encoded.len(),
            80,
            "two BlobIdentifiers must encode to exactly 80 bytes"
        );
        // First 40 bytes must be id0's SSZ (block_root then index).
        assert_eq!(
            &encoded[..32],
            id0.block_root.as_slice(),
            "first 32 bytes must be id0.block_root"
        );
        assert_eq!(
            encoded[32..40],
            id0.index.to_le_bytes(),
            "bytes 32..40 must be id0.index"
        );

        // Roundtrip.
        let decoded = Req::from_ssz_bytes(&encoded).expect("decode failed");
        assert_eq!(req, decoded, "roundtrip must match");
    }
}
