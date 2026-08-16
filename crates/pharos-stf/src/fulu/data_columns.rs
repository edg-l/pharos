//! Fulu data-column sidecar verifiers and DAS custody helpers (EIP-7594).
//!
//! Per `specs/fulu/das-core.md` and `specs/fulu/p2p-interface.md`.
//!
//! The three verifiers mirror the deneb blob-sidecar verifiers in
//! `crate::deneb::blob` (structurally the same machinery: a structural check, a
//! KZG batch-proof check, and a Merkle inclusion-proof check). The custody
//! helpers (`get_custody_groups`, `compute_columns_for_custody_group`) are pure
//! DAS arithmetic over the node id and the preset constants; their conformance
//! runners land in a later phase, but the functions are needed now by the
//! node's `ColumnAvailabilityChecker`.

use pharos_kzg::{KzgError, KzgVerifier};
use pharos_ssz::TreeHash;
use pharos_types::BeaconSpec;
use pharos_types::fulu::data_column_sidecar::{ColumnIndex, CustodyIndex, DataColumnSidecar};
use pharos_utils::Hash256;
use pharos_utils::hash::hash;

use crate::phase0::operations::deposit::is_valid_merkle_branch;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Failure modes of the data-column sidecar verifiers.
///
/// Each variant maps to one of the early-return `False` paths in the spec
/// `verify_data_column_sidecar*` helpers.
#[derive(Debug, thiserror::Error)]
pub enum DataColumnVerifyError {
    /// `sidecar.index >= NUMBER_OF_COLUMNS`.
    #[error("column index {index} out of range (NUMBER_OF_COLUMNS={number_of_columns})")]
    IndexOutOfRange {
        /// The offending column index.
        index: ColumnIndex,
        /// `NUMBER_OF_COLUMNS` for the preset.
        number_of_columns: u64,
    },
    /// `len(sidecar.kzg_commitments) == 0` (a sidecar for zero blobs is invalid).
    #[error("data column sidecar carries zero commitments")]
    NoCommitments,
    /// `len(sidecar.kzg_commitments) > max_blobs_per_block`.
    #[error("commitment count {got} exceeds max_blobs_per_block {max}")]
    TooManyCommitments {
        /// Actual commitment count.
        got: usize,
        /// `get_blob_parameters(epoch).max_blobs_per_block`.
        max: u64,
    },
    /// `len(column) != len(commitments)` or `len(column) != len(proofs)`.
    #[error(
        "length mismatch: column={column}, commitments={commitments}, proofs={proofs} (must be equal)"
    )]
    LengthMismatch {
        /// `len(sidecar.column)`.
        column: usize,
        /// `len(sidecar.kzg_commitments)`.
        commitments: usize,
        /// `len(sidecar.kzg_proofs)`.
        proofs: usize,
    },
    /// The cell KZG proof batch did not verify.
    #[error("cell KZG proof batch verification failed")]
    KzgProofInvalid,
    /// An error surfaced by the KZG library while batch-verifying.
    #[error("KZG verify error: {0}")]
    Kzg(#[from] KzgError),
    /// The `kzg_commitments` inclusion proof did not verify against `body_root`.
    #[error("data column sidecar inclusion proof invalid")]
    InclusionProofInvalid,
}

// ── Inclusion-proof gindex ────────────────────────────────────────────────────

/// Generalized index of `blob_kzg_commitments` within `BeaconBlockBody`.
///
/// `BeaconBlockBody` (deneb..fulu) has at most 13 fields, padded to a 16-leaf
/// (depth-4) field tree; `blob_kzg_commitments` is field index 11, so its
/// generalized index is `16 + 11 = 27`. Per `specs/fulu/p2p-interface.md`,
/// `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = floorlog2(27) = 4`.
const BLOB_KZG_COMMITMENTS_GINDEX: u64 = 16 + 11;

/// `get_subtree_index(gindex) = gindex % 2**floorlog2(gindex)`.
///
/// For gindex 27 (depth 4) this is `27 % 16 = 11`.
const fn get_subtree_index(gindex: u64) -> u64 {
    // floorlog2(27) = 4 → 2**4 = 16.
    gindex % 16
}

// ── verify_data_column_sidecar ────────────────────────────────────────────────

/// `verify_data_column_sidecar(sidecar)` per `specs/fulu/p2p-interface.md`.
///
/// Structural validity only (no KZG, no Merkle proof):
/// - `sidecar.index < NUMBER_OF_COLUMNS`,
/// - `len(kzg_commitments) != 0`,
/// - `len(kzg_commitments) <= max_blobs_per_block`,
/// - `len(column) == len(kzg_commitments) == len(kzg_proofs)`.
///
/// `max_blobs_per_block` is the EIP-7892 epoch-driven limit
/// (`get_blob_parameters(epoch).max_blobs_per_block`); the caller resolves it
/// from `sidecar.signed_block_header.message.slot` and passes it here so this
/// helper stays free of `RuntimeConfig`.
pub fn verify_data_column_sidecar<
    E: BeaconSpec,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
>(
    sidecar: &DataColumnSidecar<
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    >,
    max_blobs_per_block: u64,
) -> Result<(), DataColumnVerifyError> {
    // The sidecar index must be within the valid range.
    if sidecar.index >= E::NUMBER_OF_COLUMNS {
        return Err(DataColumnVerifyError::IndexOutOfRange {
            index: sidecar.index,
            number_of_columns: E::NUMBER_OF_COLUMNS,
        });
    }

    // A sidecar for zero blobs is invalid.
    let commitments = sidecar.kzg_commitments.as_slice();
    if commitments.is_empty() {
        return Err(DataColumnVerifyError::NoCommitments);
    }

    // The sidecar must respect the (epoch-dependent) blob limit.
    if commitments.len() as u64 > max_blobs_per_block {
        return Err(DataColumnVerifyError::TooManyCommitments {
            got: commitments.len(),
            max: max_blobs_per_block,
        });
    }

    // The column length must equal the commitment and proof counts.
    let column_len = sidecar.column.as_slice().len();
    let proofs_len = sidecar.kzg_proofs.as_slice().len();
    if column_len != commitments.len() || column_len != proofs_len {
        return Err(DataColumnVerifyError::LengthMismatch {
            column: column_len,
            commitments: commitments.len(),
            proofs: proofs_len,
        });
    }

    Ok(())
}

// ── verify_data_column_sidecar_kzg_proofs ─────────────────────────────────────

/// `verify_data_column_sidecar_kzg_proofs(sidecar)` per
/// `specs/fulu/p2p-interface.md`.
///
/// The column index also represents the cell index, so the batch is verified
/// with `cell_indices = [sidecar.index] * len(column)`, commitments =
/// `sidecar.kzg_commitments`, cells = `sidecar.column`, proofs =
/// `sidecar.kzg_proofs`.
pub fn verify_data_column_sidecar_kzg_proofs<
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
>(
    sidecar: &DataColumnSidecar<
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    >,
    kzg: &KzgVerifier,
) -> Result<(), DataColumnVerifyError> {
    let cells = sidecar.column.as_slice();
    let commitments = sidecar.kzg_commitments.as_slice();
    let proofs = sidecar.kzg_proofs.as_slice();

    // The column index is the cell index for every cell in this column.
    let cell_indices: Vec<u64> = vec![sidecar.index; cells.len()];

    // Borrow each fixed-size payload as the array shape the KZG wrapper expects.
    let commitment_arrs: Vec<[u8; 48]> = commitments
        .iter()
        .map(|c| <[u8; 48]>::try_from(c.as_slice()).expect("KZGCommitment is exactly 48 bytes"))
        .collect();
    let proof_arrs: Vec<[u8; 48]> = proofs
        .iter()
        .map(|p| <[u8; 48]>::try_from(p.as_slice()).expect("KZGProof is exactly 48 bytes"))
        .collect();
    let cell_arrs: Vec<[u8; 2048]> = cells
        .iter()
        .map(|cell| {
            // `Cell` is `SszVector<u8, BYTES_PER_CELL=2048>`; the slice is always
            // exactly 2048 bytes, so the conversion never fails.
            <[u8; 2048]>::try_from(cell.as_slice()).expect("Cell is exactly 2048 bytes")
        })
        .collect();

    let commitment_refs: Vec<&[u8; 48]> = commitment_arrs.iter().collect();
    let proof_refs: Vec<&[u8; 48]> = proof_arrs.iter().collect();
    let cell_refs: Vec<&[u8; 2048]> = cell_arrs.iter().collect();

    let valid =
        kzg.verify_cell_kzg_proof_batch(&commitment_refs, &cell_indices, &cell_refs, &proof_refs)?;
    if valid {
        Ok(())
    } else {
        Err(DataColumnVerifyError::KzgProofInvalid)
    }
}

// ── verify_data_column_sidecar_inclusion_proof ────────────────────────────────

/// `verify_data_column_sidecar_inclusion_proof(sidecar)` per
/// `specs/fulu/p2p-interface.md`.
///
/// Verifies that the WHOLE `kzg_commitments` list root is included in the block
/// body at `get_subtree_index(get_generalized_index(BeaconBlockBody,
/// "blob_kzg_commitments")) = 11`, depth
/// `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = 4`, against
/// `sidecar.signed_block_header.message.body_root`.
///
/// Unlike the deneb blob-sidecar inclusion proof (which proves a SINGLE
/// commitment leaf at depth 17), the fulu column inclusion proof proves the
/// `blob_kzg_commitments` LIST root as a single body field leaf at depth 4.
pub fn verify_data_column_sidecar_inclusion_proof<
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
>(
    sidecar: &DataColumnSidecar<
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    >,
) -> Result<(), DataColumnVerifyError> {
    // Leaf: hash_tree_root(sidecar.kzg_commitments) — the list root.
    let leaf: Hash256 = sidecar.kzg_commitments.tree_hash_root();

    // Branch: the KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH-element proof. Each
    // element is a `FixedBytes<32>` (= `Hash256`), so it is copied directly.
    let branch: Vec<Hash256> = sidecar.kzg_commitments_inclusion_proof.as_slice().to_vec();

    let index = get_subtree_index(BLOB_KZG_COMMITMENTS_GINDEX);
    let root: Hash256 = sidecar.signed_block_header.message.body_root;

    if is_valid_merkle_branch(
        &leaf,
        &branch,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
        index,
        &root,
    ) {
        Ok(())
    } else {
        Err(DataColumnVerifyError::InclusionProofInvalid)
    }
}

// ── DAS custody helpers ───────────────────────────────────────────────────────

/// `bytes_to_uint64(b) = int.from_bytes(b, ENDIANNESS="little")` per the spec
/// `bytes_to_uint64` helper, applied to the first 8 bytes of a hash.
fn bytes_to_uint64_le(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// `get_custody_groups(node_id, custody_group_count)` per
/// `specs/fulu/das-core.md`.
///
/// `node_id` is the 256-bit `NodeID` as a 32-byte big-endian array. Returns the
/// sorted set of custody-group indices this node is responsible for. The walk
/// hashes `uint_to_bytes(current_id)` (big-endian 32-byte encoding of the
/// uint256) and takes the first 8 bytes (little-endian) mod
/// `NUMBER_OF_CUSTODY_GROUPS`, incrementing `current_id` (with UINT256_MAX
/// wraparound) until `custody_group_count` distinct groups are collected.
///
/// Panics if `custody_group_count > NUMBER_OF_CUSTODY_GROUPS` (a spec `assert`).
pub fn get_custody_groups<E: BeaconSpec>(
    node_id: [u8; 32],
    custody_group_count: u64,
) -> Vec<CustodyIndex> {
    assert!(
        custody_group_count <= E::NUMBER_OF_CUSTODY_GROUPS,
        "custody_group_count {custody_group_count} > NUMBER_OF_CUSTODY_GROUPS {}",
        E::NUMBER_OF_CUSTODY_GROUPS
    );

    // Skip computation if all groups are custodied.
    if custody_group_count == E::NUMBER_OF_CUSTODY_GROUPS {
        return (0..E::NUMBER_OF_CUSTODY_GROUPS).collect();
    }

    // `current_id` is a big-endian uint256 (matches `uint_to_bytes` encoding).
    let mut current_id = node_id;
    let mut custody_groups: Vec<CustodyIndex> = Vec::with_capacity(custody_group_count as usize);

    while (custody_groups.len() as u64) < custody_group_count {
        let digest = hash(&current_id);
        let custody_group = bytes_to_uint64_le(digest.as_slice()) % E::NUMBER_OF_CUSTODY_GROUPS;
        if !custody_groups.contains(&custody_group) {
            custody_groups.push(custody_group);
        }
        increment_uint256_be(&mut current_id);
    }

    custody_groups.sort_unstable();
    custody_groups
}

/// Increment a big-endian uint256, wrapping `UINT256_MAX` back to `0` (matches
/// the spec's explicit overflow-prevention branch).
fn increment_uint256_be(id: &mut [u8; 32]) {
    for byte in id.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            return;
        }
    }
    // All bytes were 0xff (UINT256_MAX): wrapped to 0, which is the desired
    // overflow-prevention behaviour (current_id = uint256(0)).
}

/// `compute_columns_for_custody_group(custody_group)` per
/// `specs/fulu/das-core.md`.
///
/// Returns the column indices for a custody group:
/// `[NUMBER_OF_CUSTODY_GROUPS * i + custody_group for i in range(columns_per_group)]`
/// where `columns_per_group = NUMBER_OF_COLUMNS // NUMBER_OF_CUSTODY_GROUPS`.
///
/// Panics if `custody_group >= NUMBER_OF_CUSTODY_GROUPS` (a spec `assert`).
pub fn compute_columns_for_custody_group<E: BeaconSpec>(
    custody_group: CustodyIndex,
) -> Vec<ColumnIndex> {
    assert!(
        custody_group < E::NUMBER_OF_CUSTODY_GROUPS,
        "custody_group {custody_group} >= NUMBER_OF_CUSTODY_GROUPS {}",
        E::NUMBER_OF_CUSTODY_GROUPS
    );
    let columns_per_group = E::NUMBER_OF_COLUMNS / E::NUMBER_OF_CUSTODY_GROUPS;
    (0..columns_per_group)
        .map(|i| E::NUMBER_OF_CUSTODY_GROUPS * i + custody_group)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_ssz::{SszList, SszVector, build_single_proof_from_leaves, merkleize_padded};
    use pharos_types::MainnetBeaconSpec;
    use pharos_types::deneb::blob::{KZGCommitment, KZGProof};
    use pharos_types::fulu::data_column_sidecar::{Cell, MainnetDataColumnSidecar};
    use pharos_utils::FixedBytes;

    type E = MainnetBeaconSpec;

    /// Build a structurally-valid sidecar with `n` commitments at `index`.
    fn make_sidecar(index: u64, n: usize) -> MainnetDataColumnSidecar {
        let column = SszList::<Cell, 4096>::from_items((0..n).map(|_| Cell::default())).unwrap();
        let kzg_commitments =
            SszList::<KZGCommitment, 4096>::from_items((0..n).map(|_| KZGCommitment::default()))
                .unwrap();
        let kzg_proofs =
            SszList::<KZGProof, 4096>::from_items((0..n).map(|_| KZGProof::default())).unwrap();
        MainnetDataColumnSidecar {
            index,
            column,
            kzg_commitments,
            kzg_proofs,
            ..MainnetDataColumnSidecar::default()
        }
    }

    #[test]
    fn verify_data_column_sidecar_accepts_valid() {
        let sidecar = make_sidecar(3, 2);
        assert!(verify_data_column_sidecar::<E, 4096, 4>(&sidecar, 6).is_ok());
    }

    #[test]
    fn verify_data_column_sidecar_rejects_index_out_of_range() {
        // NUMBER_OF_COLUMNS = 128 → index 128 is out of range.
        let sidecar = make_sidecar(128, 2);
        assert!(matches!(
            verify_data_column_sidecar::<E, 4096, 4>(&sidecar, 6),
            Err(DataColumnVerifyError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn verify_data_column_sidecar_rejects_zero_commitments() {
        let sidecar = make_sidecar(0, 0);
        assert!(matches!(
            verify_data_column_sidecar::<E, 4096, 4>(&sidecar, 6),
            Err(DataColumnVerifyError::NoCommitments)
        ));
    }

    #[test]
    fn verify_data_column_sidecar_rejects_over_blob_limit() {
        let sidecar = make_sidecar(0, 7);
        assert!(matches!(
            verify_data_column_sidecar::<E, 4096, 4>(&sidecar, 6),
            Err(DataColumnVerifyError::TooManyCommitments { got: 7, max: 6 })
        ));
    }

    #[test]
    fn verify_data_column_sidecar_rejects_length_mismatch() {
        // Tamper: more commitments than column cells.
        let mut sidecar = make_sidecar(0, 2);
        sidecar.kzg_commitments =
            SszList::<KZGCommitment, 4096>::from_items((0..3).map(|_| KZGCommitment::default()))
                .unwrap();
        assert!(matches!(
            verify_data_column_sidecar::<E, 4096, 4>(&sidecar, 6),
            Err(DataColumnVerifyError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn verify_data_column_sidecar_kzg_proofs_rejects_length_mismatch() {
        // Tamper: drop a proof so the cell/proof lengths differ → CellLengthMismatch.
        let mut sidecar = make_sidecar(0, 2);
        sidecar.kzg_proofs =
            SszList::<KZGProof, 4096>::from_items((0..1).map(|_| KZGProof::default())).unwrap();
        let kzg = KzgVerifier::mainnet();
        let res = verify_data_column_sidecar_kzg_proofs::<4096, 4>(&sidecar, &kzg);
        assert!(matches!(
            res,
            Err(DataColumnVerifyError::Kzg(
                KzgError::CellLengthMismatch { .. }
            ))
        ));
    }

    /// Build a column inclusion proof from a synthetic 16-leaf body field tree
    /// (field 11 = the `kzg_commitments` list root) and verify it round-trips;
    /// then tamper a branch element and confirm rejection.
    #[test]
    fn verify_data_column_sidecar_inclusion_proof_round_trip_and_tamper() {
        let mut sidecar = make_sidecar(0, 2);

        // Body field tree: 16 leaves; field 11 = hash_tree_root(kzg_commitments).
        let mut leaves: Vec<Hash256> = (0..16u64)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&i.to_le_bytes());
                Hash256::from(b)
            })
            .collect();
        let list_root = sidecar.kzg_commitments.tree_hash_root();
        leaves[11] = list_root;

        let body_proof = build_single_proof_from_leaves(&leaves, BLOB_KZG_COMMITMENTS_GINDEX);
        assert_eq!(body_proof.branch.len(), 4);

        // Body root: merkleize the 16-leaf field tree (root of gindex 1).
        let body_root = merkleize_padded(&leaves, 16);

        // Branch elements are `Hash256` (= `FixedBytes<32>`), copied directly.
        let branch_vec: Vec<FixedBytes<32>> = body_proof.branch.clone();
        sidecar.kzg_commitments_inclusion_proof =
            SszVector::<FixedBytes<32>, 4>::from_items(branch_vec.iter().copied()).unwrap();
        sidecar.signed_block_header.message.body_root = body_root;

        // Valid proof verifies.
        assert!(verify_data_column_sidecar_inclusion_proof::<4096, 4>(&sidecar).is_ok());

        // Tamper a branch element → rejection.
        let mut tampered = sidecar.clone();
        let mut bad = branch_vec.clone();
        bad[0] = FixedBytes::<32>::from([0xAAu8; 32]);
        tampered.kzg_commitments_inclusion_proof =
            SszVector::<FixedBytes<32>, 4>::from_items(bad.iter().copied()).unwrap();
        assert!(matches!(
            verify_data_column_sidecar_inclusion_proof::<4096, 4>(&tampered),
            Err(DataColumnVerifyError::InclusionProofInvalid)
        ));
    }

    #[test]
    fn compute_columns_for_custody_group_matches_spec() {
        // NUMBER_OF_COLUMNS == NUMBER_OF_CUSTODY_GROUPS == 128 → 1 column/group,
        // exactly the group index itself.
        assert_eq!(compute_columns_for_custody_group::<E>(0), vec![0]);
        assert_eq!(compute_columns_for_custody_group::<E>(7), vec![7]);
        assert_eq!(compute_columns_for_custody_group::<E>(127), vec![127]);
    }

    #[test]
    fn get_custody_groups_full_custody_is_all_groups() {
        let node_id = [0u8; 32];
        let groups = get_custody_groups::<E>(node_id, E::NUMBER_OF_CUSTODY_GROUPS);
        assert_eq!(groups.len(), 128);
        assert_eq!(groups, (0..128u64).collect::<Vec<_>>());
    }

    #[test]
    fn get_custody_groups_subset_is_sorted_distinct_and_sized() {
        let mut node_id = [0u8; 32];
        node_id[31] = 0x42;
        let groups = get_custody_groups::<E>(node_id, 4);
        assert_eq!(groups.len(), 4);
        // Sorted, distinct, all in range.
        for w in groups.windows(2) {
            assert!(
                w[0] < w[1],
                "groups must be strictly increasing (sorted+distinct)"
            );
        }
        for g in &groups {
            assert!(*g < E::NUMBER_OF_CUSTODY_GROUPS);
        }
    }
}
