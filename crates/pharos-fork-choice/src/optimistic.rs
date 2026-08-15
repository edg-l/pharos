//! Optimistic sync helpers.
//!
//! Per `consensus-specs/sync/optimistic.md`.

use pharos_types::{EthSpec, PayloadStatus, phase0::primitives::Root};

use crate::pow_block::block_is_execution_enabled;
use crate::store::Store;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum age (in slots behind current slot) at which a block can be
/// optimistically imported without confirming its parent is an execution block.
///
/// Per `consensus-specs/sync/optimistic.md` "Constants" table, value `128`.
/// The spec notes this MUST be user-configurable (fork-choice-poisoning
/// protection); the constant here is the default / compile-time value used
/// when no override is provided.
pub const SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY: u64 = 128;

// ── is_optimistic_candidate_block ─────────────────────────────────────────────

/// Return `true` if `block_root` is eligible for optimistic import.
///
/// Mirrors `is_optimistic_candidate_block` from
/// `consensus-specs/sync/optimistic.md` lines 112-122:
///
/// ```python
/// def is_optimistic_candidate_block(opt_store, current_slot, block):
///     if is_execution_block(opt_store.blocks[block.parent_root]):
///         return True
///     if block.slot + SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY <= current_slot:
///         return True
///     return False
/// ```
///
/// The spec takes `block` as a parameter and looks up `block.parent_root`
/// inside the store; here we take the already-extracted fields to avoid
/// re-deriving them from the enum.
///
/// # Arguments
/// - `store` — the fork-choice store (read-only)
/// - `current_slot` — wall-clock slot (`get_current_slot(&store)`)
/// - `parent_root` — `block.parent_root`
/// - `block_slot` — `block.slot`
///
/// # Parent-absent case
/// When the parent block is not yet in `store.blocks` (e.g. an out-of-order
/// delivery) we cannot confirm it carries an execution payload, so Branch 1
/// is skipped and we fall through to the age test (Branch 2).  The block may
/// still be a candidate if it is old enough (`block_slot +
/// SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY <= current_slot`).
pub fn is_optimistic_candidate_block<E: EthSpec>(
    store: &Store<E>,
    current_slot: u64,
    parent_root: Root,
    block_slot: u64,
) -> bool {
    // Branch 1 — parent is an execution block.
    // `consensus-specs/sync/optimistic.md:115`
    if let Some(parent_block) = store.blocks.get(&parent_root) {
        if block_is_execution_enabled::<E>(parent_block) {
            return true;
        }
    }

    // Branch 2 — block is old enough (SAFE_SLOTS behind wall clock).
    // `consensus-specs/sync/optimistic.md:118`
    block_slot + SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY <= current_slot
}

// ── is_optimistic ─────────────────────────────────────────────────────────────

/// Return `true` iff `root` refers to an optimistically imported block.
///
/// Derivation: `is_execution_block(block_at_root)` AND
/// `payload_statuses.get(root) != Some(Valid)`.
///
/// This is the single-source-of-truth derivation described in the M8
/// architecture: Phase 1 pre-seeds every execution-carrying block with
/// `payload_statuses[root] = NotValidated`, so a missing entry means either
/// (a) the root is unknown (return `false`) or (b) the block is pre-merge
/// (return `false` via `block_is_execution_enabled`).
///
/// Per `consensus-specs/sync/optimistic.md` "Helpers" `is_optimistic` +
/// `is_execution_block` definitions and the M8 architecture note that
/// `is_optimistic = is_execution_block && status != Valid`.
///
/// Finalized blocks are never optimistic: the EL must have marked them
/// `Valid` before the fork choice can finalize them. The derivation returns
/// `false` for them naturally because `Valid` ≠ `NotValidated`.
pub fn is_optimistic<E: EthSpec>(store: &Store<E>, root: Root) -> bool {
    let block = match store.blocks.get(&root) {
        Some(b) => b,
        None => return false,
    };
    block_is_execution_enabled::<E>(block)
        && !matches!(
            store.payload_statuses.get(&root),
            Some(PayloadStatus::Valid)
        )
}
