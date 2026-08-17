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
use pharos_ssz::{SszList, SszVector, TreeHash, build_single_proof_from_leaves};
use pharos_types::BeaconSpec;
use pharos_types::deneb::blob::{KZGCommitment, KZGProof};
use pharos_types::fulu::data_column_sidecar::{Cell, ColumnIndex, CustodyIndex, DataColumnSidecar};
use pharos_types::phase0::operations::SignedBeaconBlockHeader;
use pharos_utils::hash::hash;
use pharos_utils::{FixedBytes, Hash256};

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
/// hashes `uint_to_bytes(current_id)` — the SSZ little-endian 32-byte encoding
/// of the uint256 (`ENDIANNESS = "little"`), so the BE input is reversed before
/// hashing — and takes the first 8 bytes (little-endian) mod
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

    // `current_id` is the `NodeID` uint256 held as a 32-byte BIG-endian array
    // (the discv5 canonical form). The spec hashes `uint_to_bytes(current_id)`,
    // which is the SSZ (`ENDIANNESS = "little"`) encoding of the uint256, so we
    // reverse the BE bytes to LE before hashing. Incrementing stays on the BE
    // representation (a numerically-correct uint256 += 1).
    let mut current_id = node_id;
    let mut custody_groups: Vec<CustodyIndex> = Vec::with_capacity(custody_group_count as usize);

    while (custody_groups.len() as u64) < custody_group_count {
        let mut le_id = current_id;
        le_id.reverse();
        let digest = hash(&le_id);
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

// ── Sidecar production (validator.md) ─────────────────────────────────────────

/// Size of the body-field tree (electra/fulu bodies pad to 16 leaves).
const BODY_FIELD_TREE_SIZE: usize = 16;

/// `build_kzg_commitments_inclusion_proof` — the depth-4 Merkle branch proving
/// the `blob_kzg_commitments` LIST root is body field 11.
///
/// Per `specs/fulu/validator.md` `get_data_column_sidecars_from_block`:
/// `kzg_commitments_inclusion_proof = compute_merkle_proof(body,
/// get_generalized_index(BeaconBlockBody, "blob_kzg_commitments"))`. The
/// generalized index is `16 + 11 = 27` (field 11 in the 16-leaf body field
/// tree), so the proof is the 4-element body-field-tree branch
/// (`KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = 4`). Unlike the deneb blob-sidecar
/// proof (depth 17, a single commitment leaf), this proves the WHOLE list root
/// as one body-field leaf, exactly matching
/// [`verify_data_column_sidecar_inclusion_proof`].
///
/// `all_body_field_hashes` is the 13 body-field `tree_hash_root` values in field
/// order (`randao_reveal=0`, ..., `blob_kzg_commitments=11`,
/// `execution_requests=12`).
pub fn build_kzg_commitments_inclusion_proof(
    all_body_field_hashes: &[Hash256; 13],
) -> [Hash256; 4] {
    let body_leaves: Vec<Hash256> = {
        let mut leaves = all_body_field_hashes.to_vec();
        leaves.resize(BODY_FIELD_TREE_SIZE, Hash256::default());
        leaves
    };
    let body_proof = build_single_proof_from_leaves(&body_leaves, BLOB_KZG_COMMITMENTS_GINDEX);
    debug_assert_eq!(body_proof.branch.len(), 4);
    let mut branch = [Hash256::default(); 4];
    branch.copy_from_slice(&body_proof.branch);
    branch
}

// ── FuluBodyFieldHashes ───────────────────────────────────────────────────────

/// Return the 13 body field `tree_hash_root()` values, in field order, for a
/// concrete Electra/Fulu `BeaconBlockBody`.
///
/// Mirrors `block_production.rs`'s `FuluBlockAssembler::body_field_hashes` /
/// `ElectraBlockAssembler::body_field_hashes` (same field order); factored out
/// here so the import-side reconstruction path (`fulu_body_field_hashes` in
/// `pharos-node`) and block production share one implementation instead of
/// duplicating the 13-field list.
///
/// Implemented for the concrete `electra::BeaconBlockBody<..>` type (reused
/// as-is by Fulu; see `pharos_types::fulu::body`) because the generic
/// `BeaconBlockBodyView` trait does not expose the 13 individual fields.
pub trait FuluBodyFieldHashes {
    /// The 13 body field `tree_hash_root()` values, field order 0..12
    /// (including `execution_requests` at index 12).
    fn body_field_hashes(&self) -> [Hash256; 13];
}

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS_ELECTRA: u64,
    const MAX_ATTESTATIONS_ELECTRA: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
> FuluBodyFieldHashes
    for pharos_types::electra::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_ATTESTATIONS_ELECTRA,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    fn body_field_hashes(&self) -> [Hash256; 13] {
        [
            self.randao_reveal.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.graffiti.tree_hash_root(),
            self.proposer_slashings.tree_hash_root(),
            self.attester_slashings.tree_hash_root(),
            self.attestations.tree_hash_root(),
            self.deposits.tree_hash_root(),
            self.voluntary_exits.tree_hash_root(),
            self.sync_aggregate.tree_hash_root(),
            self.execution_payload.tree_hash_root(),
            self.bls_to_execution_changes.tree_hash_root(),
            self.blob_kzg_commitments.tree_hash_root(),
            self.execution_requests.tree_hash_root(),
        ]
    }
}

/// `get_data_column_sidecars` per `specs/fulu/validator.md`.
///
/// Builds `NUMBER_OF_COLUMNS` (`= E::NUMBER_OF_COLUMNS`, 128) `DataColumnSidecar`s
/// from `(signed_block_header, kzg_commitments, inclusion_proof,
/// cells_and_kzg_proofs)`. Each `cells_and_kzg_proofs[i]` is the
/// `(cells, proofs)` tuple for blob `i`, where `cells.len() == proofs.len() ==
/// CELLS_PER_EXT_BLOB`. Per column index `c`, the sidecar's `column` is the
/// `c`-th cell of every blob and `kzg_proofs` is the `c`-th proof of every blob.
///
/// `assert len(cells_and_kzg_proofs) == len(kzg_commitments)` (one cells/proofs
/// tuple per commitment); a mismatch returns `Err(LengthMismatch)`.
#[allow(clippy::type_complexity)]
pub fn get_data_column_sidecars<
    E: BeaconSpec,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
>(
    signed_block_header: &SignedBeaconBlockHeader,
    kzg_commitments: &[KZGCommitment],
    inclusion_proof: &[Hash256],
    cells_and_kzg_proofs: &[(Vec<Cell>, Vec<KZGProof>)],
) -> Result<
    Vec<DataColumnSidecar<MAX_BLOB_COMMITMENTS_PER_BLOCK, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>>,
    DataColumnVerifyError,
> {
    // assert len(cells_and_kzg_proofs) == len(kzg_commitments).
    if cells_and_kzg_proofs.len() != kzg_commitments.len() {
        return Err(DataColumnVerifyError::LengthMismatch {
            column: cells_and_kzg_proofs.len(),
            commitments: kzg_commitments.len(),
            proofs: cells_and_kzg_proofs.len(),
        });
    }

    let commitments_list = SszList::<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>::from_items(
        kzg_commitments.iter().copied(),
    )
    .map_err(|_| DataColumnVerifyError::TooManyCommitments {
        got: kzg_commitments.len(),
        max: MAX_BLOB_COMMITMENTS_PER_BLOCK,
    })?;

    let inclusion_proof_vec =
        SszVector::<FixedBytes<32>, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>::from_items(
            inclusion_proof.iter().copied(),
        )
        .map_err(|_| DataColumnVerifyError::InclusionProofInvalid)?;

    let number_of_columns = E::NUMBER_OF_COLUMNS;
    let mut sidecars = Vec::with_capacity(number_of_columns as usize);
    for column_index in 0..number_of_columns {
        let ci = column_index as usize;
        let mut column_cells: Vec<Cell> = Vec::with_capacity(cells_and_kzg_proofs.len());
        let mut column_proofs: Vec<KZGProof> = Vec::with_capacity(cells_and_kzg_proofs.len());
        for (cells, proofs) in cells_and_kzg_proofs {
            // `cells`/`proofs` are length-CELLS_PER_EXT_BLOB; the column index
            // selects the cell/proof for this column. A short tuple (malformed
            // input) skips that blob's contribution rather than panicking.
            if let (Some(cell), Some(proof)) = (cells.get(ci), proofs.get(ci)) {
                column_cells.push(cell.clone());
                column_proofs.push(*proof);
            }
        }

        let column = SszList::<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>::from_items(column_cells)
            .map_err(|_| DataColumnVerifyError::TooManyCommitments {
                got: cells_and_kzg_proofs.len(),
                max: MAX_BLOB_COMMITMENTS_PER_BLOCK,
            })?;
        let kzg_proofs =
            SszList::<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>::from_items(column_proofs)
                .map_err(|_| DataColumnVerifyError::TooManyCommitments {
                    got: cells_and_kzg_proofs.len(),
                    max: MAX_BLOB_COMMITMENTS_PER_BLOCK,
                })?;

        sidecars.push(DataColumnSidecar {
            index: column_index,
            column,
            kzg_commitments: commitments_list.clone(),
            kzg_proofs,
            signed_block_header: signed_block_header.clone(),
            kzg_commitments_inclusion_proof: inclusion_proof_vec.clone(),
        });
    }

    Ok(sidecars)
}

/// `get_data_column_sidecars_from_block` per `specs/fulu/validator.md`.
///
/// Convenience wrapper over [`get_data_column_sidecars`] that takes the block's
/// `(signed_block_header, kzg_commitments, body_field_hashes)` and the
/// `cells_and_kzg_proofs`. The caller (block production) supplies the sealed
/// block's header + the 13 body-field hashes; this builds the depth-4
/// `kzg_commitments_inclusion_proof` via
/// [`build_kzg_commitments_inclusion_proof`] and delegates.
#[allow(clippy::type_complexity)]
pub fn get_data_column_sidecars_from_block<
    E: BeaconSpec,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64,
>(
    signed_block_header: &SignedBeaconBlockHeader,
    kzg_commitments: &[KZGCommitment],
    body_field_hashes: &[Hash256; 13],
    cells_and_kzg_proofs: &[(Vec<Cell>, Vec<KZGProof>)],
) -> Result<
    Vec<DataColumnSidecar<MAX_BLOB_COMMITMENTS_PER_BLOCK, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>>,
    DataColumnVerifyError,
> {
    let inclusion_proof = build_kzg_commitments_inclusion_proof(body_field_hashes);
    get_data_column_sidecars::<
        E,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    >(
        signed_block_header,
        kzg_commitments,
        &inclusion_proof,
        cells_and_kzg_proofs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_ssz::merkleize_padded;
    use pharos_types::MainnetBeaconSpec;
    use pharos_types::fulu::data_column_sidecar::MainnetDataColumnSidecar;

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

    /// `get_data_column_sidecars_from_block` yields `NUMBER_OF_COLUMNS` (128)
    /// sidecars, each carrying a verifying inclusion proof. Builds a synthetic
    /// 16-leaf body field tree (field 11 = the `blob_kzg_commitments` list root),
    /// derives the depth-4 inclusion proof, assembles 128 sidecars from 2 blobs'
    /// worth of cells/proofs, and confirms each sidecar's inclusion proof passes
    /// `verify_data_column_sidecar_inclusion_proof` (reusing Phase 4.1 verify).
    #[test]
    fn get_data_column_sidecars_yields_128_with_verifying_inclusion_proofs() {
        // Two blobs → two commitments → two cells/proofs tuples.
        let n_blobs = 2usize;
        let cells_per_ext_blob = E::CELLS_PER_EXT_BLOB as usize;
        let commitments: Vec<KZGCommitment> =
            (0..n_blobs).map(|_| KZGCommitment::default()).collect();
        let cells_and_kzg_proofs: Vec<(Vec<Cell>, Vec<KZGProof>)> = (0..n_blobs)
            .map(|_| {
                let cells: Vec<Cell> = (0..cells_per_ext_blob).map(|_| Cell::default()).collect();
                let proofs: Vec<KZGProof> = (0..cells_per_ext_blob)
                    .map(|_| KZGProof::default())
                    .collect();
                (cells, proofs)
            })
            .collect();

        // Build the 13 body-field hashes; field 11 = hash_tree_root(commitments list).
        let commitments_list =
            SszList::<KZGCommitment, 4096>::from_items(commitments.iter().copied()).unwrap();
        let mut body_field_hashes = [Hash256::default(); 13];
        for (i, h) in body_field_hashes.iter_mut().enumerate() {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(i as u64).to_le_bytes());
            *h = Hash256::from(b);
        }
        body_field_hashes[11] = commitments_list.tree_hash_root();

        // Compute the body_root so the sidecar inclusion proof verifies: the
        // 16-leaf body field tree root.
        let mut leaves: Vec<Hash256> = body_field_hashes.to_vec();
        leaves.resize(16, Hash256::default());
        let body_root = merkleize_padded(&leaves, 16);

        let mut header = SignedBeaconBlockHeader::default();
        header.message.body_root = body_root;

        let sidecars = get_data_column_sidecars_from_block::<E, 4096, 4>(
            &header,
            &commitments,
            &body_field_hashes,
            &cells_and_kzg_proofs,
        )
        .unwrap();

        // 128 sidecars, one per column.
        assert_eq!(sidecars.len(), E::NUMBER_OF_COLUMNS as usize);
        for (c, sidecar) in sidecars.iter().enumerate() {
            assert_eq!(sidecar.index, c as u64);
            // Each column carries one cell + one proof per blob, plus all commitments.
            assert_eq!(sidecar.column.as_slice().len(), n_blobs);
            assert_eq!(sidecar.kzg_proofs.as_slice().len(), n_blobs);
            assert_eq!(sidecar.kzg_commitments.as_slice().len(), n_blobs);
            // The inclusion proof verifies (reuse Phase 4.1 verifier).
            assert!(
                verify_data_column_sidecar_inclusion_proof::<4096, 4>(sidecar).is_ok(),
                "column {c} inclusion proof must verify"
            );
        }
    }
}
