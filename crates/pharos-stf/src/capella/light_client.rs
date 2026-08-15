//! Capella light-client helpers.
//!
//! Per `specs/capella/light-client/sync-protocol.md` and `full-node.md`.
//!
//! ## EXECUTION_PAYLOAD_GINDEX
//!
//! `EXECUTION_PAYLOAD_GINDEX = get_generalized_index(BeaconBlockBody, 'execution_payload') = 25`.
//! `floorlog2(25) = 4`, so `ExecutionBranch = Vector[Bytes32, 4]`.
//! `get_subtree_index(25) = 25 % 16 = 9`.
//!
//! The capella `BeaconBlockBody` has 11 fields padded to 16 (next power of two ≥ 11):
//!   0: randao_reveal, 1: eth1_data, 2: graffiti, 3: proposer_slashings,
//!   4: attester_slashings, 5: attestations, 6: deposits, 7: voluntary_exits,
//!   8: sync_aggregate, 9: execution_payload ← gindex = 16+9 = 25,
//!  10: bls_to_execution_changes.

use pharos_ssz::{SszVector, TreeHash, build_single_proof_from_leaves};
use pharos_types::{
    capella::{
        BeaconBlock as CapellaBeaconBlock,
        execution_payload::ExecutionPayloadHeader,
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

/// `get_lc_execution_root(header)` per `specs/capella/light-client/sync-protocol.md`.
///
/// Returns `hash_tree_root(header.execution)` when
/// `compute_epoch_at_slot(header.beacon.slot) >= capella_fork_epoch`, else `Root::default()`.
pub fn get_lc_execution_root<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64>(
    header: &LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    capella_fork_epoch: u64,
    slots_per_epoch: u64,
) -> pharos_utils::Hash256
where
    ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>: TreeHash,
{
    let epoch = compute_epoch_at_slot(header.beacon.slot, slots_per_epoch);
    if epoch.0 >= capella_fork_epoch {
        header.execution.tree_hash_root()
    } else {
        pharos_utils::Hash256::default()
    }
}

// ── is_valid_light_client_header ──────────────────────────────────────────────

/// `is_valid_light_client_header(header)` per `specs/capella/light-client/sync-protocol.md`.
///
/// - Pre-capella: `execution` and `execution_branch` must be default/zero.
/// - Capella+: verify the execution Merkle branch against `beacon.body_root`.
pub fn is_valid_light_client_header<
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    header: &LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    capella_fork_epoch: u64,
    slots_per_epoch: u64,
) -> bool
where
    ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>: TreeHash,
    Bytes32: Default + Clone + PartialEq,
{
    let epoch = compute_epoch_at_slot(header.beacon.slot, slots_per_epoch);

    if epoch.0 < capella_fork_epoch {
        // Pre-capella: execution fields must be default/zero.
        let default_execution =
            ExecutionPayloadHeader::<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>::default();
        let default_branch = SszVector::<Bytes32, EXECUTION_BRANCH_DEPTH>::default();
        return header.execution == default_execution && header.execution_branch == default_branch;
    }

    // Capella+: verify merkle branch.
    let leaf = get_lc_execution_root(header, capella_fork_epoch, slots_per_epoch);
    let branch: Vec<Bytes32> = header.execution_branch.as_slice().to_vec();
    let depth = floorlog2(EXECUTION_PAYLOAD_GINDEX);
    let index = get_subtree_index(EXECUTION_PAYLOAD_GINDEX);

    is_valid_merkle_branch(&leaf, &branch, depth, index, &header.beacon.body_root)
}

// ── capella_block_to_light_client_header ──────────────────────────────────────

/// Build a Capella `LightClientHeader` from a Capella unsigned block.
///
/// Per `specs/capella/light-client/full-node.md`:
/// `block_to_light_client_header` constructs the header from the block's fields
/// using STF-verified `block.state_root` (not a re-computed `state.tree_hash_root()`).
/// The `body_root` is computed from `block.body.tree_hash_root()` which correctly
/// includes the `execution_payload` and `bls_to_execution_changes` fields.
///
/// `execution` is derived from `block.body.execution_payload` fields.
/// `execution_branch` is the Merkle proof of `execution_payload` (gindex 25)
/// within `BeaconBlockBody`.
#[allow(clippy::too_many_arguments)]
pub fn capella_block_to_light_client_header<
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
>(
    block: &CapellaBeaconBlock<
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
    >,
) -> LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    pharos_types::capella::BeaconBlockBody<
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
    >: TreeHash,
    pharos_types::capella::ExecutionPayload<
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

    // Build the execution payload header from the payload fields.
    // `transactions_root` and `withdrawals_root` are hash_tree_root of the lists.
    let execution_header = ExecutionPayloadHeader {
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
    };

    // Build the execution_branch: Merkle proof of field 9 (execution_payload, gindex 25)
    // within the BeaconBlockBody (11 fields padded to 16 leaves).
    let execution_branch = compute_body_execution_branch(block);

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

// ── compute_body_execution_branch ─────────────────────────────────────────────

/// Compute the Merkle proof of `execution_payload` (gindex 25) within
/// the Capella `BeaconBlockBody`.
///
/// The Capella body has 11 fields, padded to 16 in the SSZ Merkle tree.
/// Field 9 is `execution_payload`; its generalized index is 16 + 9 = 25.
/// The branch depth is `floorlog2(25) = 4`.
#[allow(clippy::too_many_arguments)]
fn compute_body_execution_branch<
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
>(
    block: &CapellaBeaconBlock<
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
    >,
) -> SszVector<Bytes32, EXECUTION_BRANCH_DEPTH>
where
    pharos_types::capella::ExecutionPayload<
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

    // Capella BeaconBlockBody has 11 fields (indices 0-10).
    // SSZ tree pads to 16 leaves. Leaf at position k has gindex 16+k.
    // execution_payload is field 9, gindex = 16+9 = 25.
    let field_hashes: [pharos_utils::Hash256; 11] = [
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floorlog2_execution_payload_gindex() {
        // EXECUTION_PAYLOAD_GINDEX = 25; floorlog2(25) = 4
        assert_eq!(floorlog2(EXECUTION_PAYLOAD_GINDEX), EXECUTION_BRANCH_DEPTH);
    }

    #[test]
    fn get_subtree_index_execution_payload() {
        // get_subtree_index(25) = 25 % 2^4 = 25 % 16 = 9
        assert_eq!(get_subtree_index(EXECUTION_PAYLOAD_GINDEX), 9);
    }
}
