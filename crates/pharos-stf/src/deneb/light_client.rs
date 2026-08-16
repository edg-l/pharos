//! Deneb light-client helpers.
//!
//! Per `specs/deneb/light-client/sync-protocol.md` and `full-node.md`.
//!
//! ## EXECUTION_PAYLOAD_GINDEX
//!
//! `EXECUTION_PAYLOAD_GINDEX = 25` — identical to capella.
//! The deneb `BeaconBlockBody` has 12 fields (adds `blob_kzg_commitments`),
//! padded to 16 in the SSZ Merkle tree.
//! Field 9 is still `execution_payload`; gindex = 16 + 9 = 25.
//! Branch depth = `floorlog2(25) = 4`.

use pharos_ssz::{SszVector, TreeHash, build_single_proof_from_leaves};
use pharos_types::{
    deneb::{
        BeaconBlock as DenebBeaconBlock,
        execution_payload::ExecutionPayloadHeader as DenebExecutionPayloadHeader,
        light_client::{EXECUTION_BRANCH_DEPTH, EXECUTION_PAYLOAD_GINDEX, LightClientHeader},
    },
    phase0::operations::BeaconBlockHeader,
};
use pharos_utils::Bytes32;

use crate::phase0::accessors::compute_epoch_at_slot;
use crate::phase0::operations::deposit::is_valid_merkle_branch;

// ── floorlog2 / get_subtree_index ─────────────────────────────────────────────

fn floorlog2(n: u64) -> u64 {
    debug_assert!(n >= 1, "floorlog2 undefined for 0");
    63 - n.leading_zeros() as u64
}

fn get_subtree_index(gindex: u64) -> u64 {
    let depth = floorlog2(gindex);
    gindex % (1u64 << depth)
}

// ── get_lc_execution_root ─────────────────────────────────────────────────────

/// `get_lc_execution_root(header)` for Deneb.
///
/// Returns `hash_tree_root(header.execution)` when the header's epoch is ≥
/// `capella_fork_epoch` (same condition as Capella, since Deneb is post-Capella).
pub fn get_lc_execution_root<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64>(
    header: &LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    capella_fork_epoch: u64,
    slots_per_epoch: u64,
) -> pharos_utils::Hash256
where
    DenebExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>: TreeHash,
{
    let epoch = compute_epoch_at_slot(header.beacon.slot, slots_per_epoch);
    if epoch.0 >= capella_fork_epoch {
        header.execution.tree_hash_root()
    } else {
        pharos_utils::Hash256::default()
    }
}

// ── is_valid_light_client_header ──────────────────────────────────────────────

/// `is_valid_light_client_header(header)` for Deneb.
///
/// Deneb uses the same branch structure as Capella (gindex 25, depth 4).
/// The only difference is the execution payload header type.
pub fn is_valid_light_client_header<
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    header: &LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    capella_fork_epoch: u64,
    slots_per_epoch: u64,
) -> bool
where
    DenebExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>: TreeHash,
    Bytes32: Default + Clone + PartialEq,
{
    let epoch = compute_epoch_at_slot(header.beacon.slot, slots_per_epoch);

    if epoch.0 < capella_fork_epoch {
        // Pre-capella: execution fields must be default/zero.
        let default_execution =
            DenebExecutionPayloadHeader::<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>::default();
        let default_branch = SszVector::<Bytes32, EXECUTION_BRANCH_DEPTH>::default();
        return header.execution == default_execution && header.execution_branch == default_branch;
    }

    // Deneb+: verify merkle branch (same gindex/depth as Capella).
    let leaf = get_lc_execution_root(header, capella_fork_epoch, slots_per_epoch);
    let branch: Vec<Bytes32> = header.execution_branch.as_slice().to_vec();
    let depth = floorlog2(EXECUTION_PAYLOAD_GINDEX);
    let index = get_subtree_index(EXECUTION_PAYLOAD_GINDEX);

    is_valid_merkle_branch(&leaf, &branch, depth, index, &header.beacon.body_root)
}

// ── deneb_block_to_light_client_header ───────────────────────────────────────

/// Build a Deneb `LightClientHeader` from a Deneb unsigned block.
///
/// Per `specs/deneb/light-client/full-node.md`:
/// Uses STF-verified `block.state_root` (not a re-computed `state.tree_hash_root()`).
/// The `body_root` is computed from `block.body.tree_hash_root()`.
#[allow(clippy::too_many_arguments)]
pub fn deneb_block_to_light_client_header<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
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
>(
    block: &DenebBeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
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
    >,
) -> LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    pharos_types::deneb::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
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
    >: TreeHash,
    pharos_types::deneb::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >: TreeHash,
    pharos_types::bellatrix::Transaction<MAX_BYTES_PER_TRANSACTION>: Default + Clone,
    pharos_types::capella::Withdrawal: Default + Clone,
    Bytes32: Default + Clone,
{
    use pharos_ssz::TreeHash as _;

    let payload = &block.body.execution_payload;

    // Build the deneb execution payload header from the payload fields.
    let execution_header = DenebExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions_root: payload.transactions.tree_hash_root(),
        withdrawals_root: payload.withdrawals.tree_hash_root(),
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    };

    // Build the execution_branch: Merkle proof of field 9 (execution_payload, gindex 25)
    // within the Deneb BeaconBlockBody (12 fields padded to 16 leaves).
    let execution_branch = compute_deneb_body_execution_branch(block);

    LightClientHeader {
        beacon: BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body_root: block.body.tree_hash_root(),
        },
        execution: execution_header,
        execution_branch,
    }
}

// ── compute_deneb_body_execution_branch ──────────────────────────────────────

/// Compute the Merkle proof of `execution_payload` (gindex 25) within
/// the Deneb `BeaconBlockBody`.
///
/// The Deneb body has 12 fields (indices 0–11), padded to 16 in the SSZ tree.
/// Field 9 is `execution_payload`; gindex = 16 + 9 = 25 (same as Capella).
#[allow(clippy::too_many_arguments)]
fn compute_deneb_body_execution_branch<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
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
>(
    block: &DenebBeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
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
    >,
) -> SszVector<Bytes32, EXECUTION_BRANCH_DEPTH>
where
    pharos_types::deneb::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >: TreeHash,
    pharos_types::bellatrix::Transaction<MAX_BYTES_PER_TRANSACTION>: Default + Clone,
    pharos_types::capella::Withdrawal: Default + Clone,
    Bytes32: Default + Clone,
{
    use pharos_ssz::TreeHash as _;

    let body = &block.body;

    // Deneb BeaconBlockBody has 12 fields (indices 0–11).
    // SSZ tree pads to 16 leaves. Leaf at position k has gindex 16+k.
    // execution_payload is field 9, gindex = 16+9 = 25.
    let field_hashes: [pharos_utils::Hash256; 12] = [
        body.randao_reveal.tree_hash_root(),            // 0
        body.eth1_data.tree_hash_root(),                // 1
        body.graffiti.tree_hash_root(),                 // 2
        body.proposer_slashings.tree_hash_root(),       // 3
        body.attester_slashings.tree_hash_root(),       // 4
        body.attestations.tree_hash_root(),             // 5
        body.deposits.tree_hash_root(),                 // 6
        body.voluntary_exits.tree_hash_root(),          // 7
        body.sync_aggregate.tree_hash_root(),           // 8
        body.execution_payload.tree_hash_root(),        // 9 ← gindex 25
        body.bls_to_execution_changes.tree_hash_root(), // 10
        body.blob_kzg_commitments.tree_hash_root(),     // 11 [New in Deneb]
    ];

    let proof = build_single_proof_from_leaves(&field_hashes, EXECUTION_PAYLOAD_GINDEX);

    debug_assert_eq!(
        proof.branch.len(),
        EXECUTION_BRANCH_DEPTH as usize,
        "execution_branch depth mismatch: expected {EXECUTION_BRANCH_DEPTH}, got {}",
        proof.branch.len()
    );

    let branch_vec: Vec<Bytes32> = proof.branch.into_iter().collect();
    SszVector::from_vec(branch_vec).unwrap_or_default()
}
