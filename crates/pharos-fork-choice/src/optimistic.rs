//! Optimistic sync helpers.
//!
//! Per `consensus-specs/sync/optimistic.md`.

use std::collections::VecDeque;

use pharos_types::{EthSpec, PayloadStatus, phase0::primitives::Root, views::BeaconBlockView};
use pharos_utils::Hash256;

use crate::pow_block::{block_is_execution_enabled, execution_block_hash_at_root};
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

// ── resolve_invalid_block ─────────────────────────────────────────────────────

/// Resolve the `invalidBlock` CL root from the EL `latestValidHash`.
///
/// Implements the 3-case table from
/// `consensus-specs/sync/optimistic.md:224-233`
/// "How to apply `latestValidHash` when payload status is `INVALID`":
///
/// | `latestValidHash`    | `invalidBlock`                                              |
/// |----------------------|-------------------------------------------------------------|
/// | `null`               | `block_in_question` itself                                  |
/// | `0x00..00` (zeroes)  | first execution-enabled block toward genesis from `block_in_question` |
/// | execution block hash | child of the ancestor whose `block_hash == latestValidHash` |
///
/// When `latestValidHash` is nonzero but no ancestor matches it, the spec
/// says the engine SHOULD behave as if it were `null` (`block_in_question`).
///
/// Per `consensus-specs/sync/optimistic.md:219-233`.
pub fn resolve_invalid_block<E: EthSpec>(
    store: &Store<E>,
    block_in_question: Root,
    latest_valid_hash: Option<Hash256>,
) -> Root
where
    E::BeaconBlock: BeaconBlockView,
{
    match latest_valid_hash {
        // Case (a): null → invalidate the submitted block only.
        // `consensus-specs/sync/optimistic.md:229` (null row).
        None => block_in_question,

        Some(lvh) if lvh == Hash256::default() => {
            // Case (b): 0x00..00 → the FIRST (deepest toward genesis)
            // execution-enabled block in the chain containing block_in_question.
            // `consensus-specs/sync/optimistic.md:227` (zeroes row).
            //
            // Walk from block_in_question toward genesis collecting the deepest
            // ancestor that has execution enabled.
            let mut cur = block_in_question;
            let mut first_exec = None;
            while let Some(block) = store.blocks.get(&cur) {
                if block_is_execution_enabled::<E>(block) {
                    first_exec = Some(cur);
                }
                let parent = block.parent_root();
                if parent == Root::default() || parent == cur {
                    break;
                }
                cur = parent;
            }
            first_exec.unwrap_or(block_in_question)
        }

        Some(lvh) => {
            // Case (c): nonzero hash → find ancestor with
            // `execution_payload.block_hash == lvh`; the invalid block is its
            // child on the path to block_in_question.
            // `consensus-specs/sync/optimistic.md:225-226` (hash row).
            //
            // Walk from block_in_question toward genesis; track (child, current)
            // so when we find the match we can return child.
            let mut cur = block_in_question;
            let mut prev_child: Option<Root> = None;
            loop {
                let cur_hash = execution_block_hash_at_root(store, cur);
                if cur_hash == lvh {
                    // `prev_child` is the child of `cur` on the path from
                    // block_in_question toward genesis.  If None, then
                    // block_in_question itself matches lvh (it is already
                    // considered valid by the EL), and block_in_question is
                    // the invalid block — same result as the null case.
                    // Either way, unwrap_or gives the right answer directly.
                    return prev_child.unwrap_or(block_in_question);
                }
                let block = match store.blocks.get(&cur) {
                    Some(b) => b,
                    None => break,
                };
                let parent = block.parent_root();
                if parent == Root::default() || parent == cur {
                    break;
                }
                prev_child = Some(cur);
                cur = parent;
            }
            // `consensus-specs/sync/optimistic.md:231-233`: cannot find a block
            // with block_hash == latestValidHash → behave as if null.
            block_in_question
        }
    }
}

// ── promote_valid_ancestors ───────────────────────────────────────────────────

/// Promote `root` and all `NOT_VALIDATED` ancestors to `PayloadStatus::Valid`.
///
/// When a block transitions `NOT_VALIDATED` → `VALID`, all ancestors MUST also
/// transition from `NOT_VALIDATED` → `VALID` per
/// `consensus-specs/sync/optimistic.md:193-196`:
///
/// > When a block transitions from `NOT_VALIDATED` -> `VALID`, all *ancestors* of
/// > the block MUST also transition from `NOT_VALIDATED` -> `VALID`. Such a block
/// > and any previously `NOT_VALIDATED` ancestors are no longer considered
/// > "optimistically imported".
///
/// Walk from `root` toward genesis via `parent_root`, setting every block that is
/// currently `NotValidated` (and `root` itself) to `Valid`.  The walk stops at the
/// first ancestor that is already `Valid` (its own ancestors are already promoted)
/// or at the anchor / `Root::default()` parent sentinel.
///
/// If an `Invalid` ancestor is encountered the walk stops immediately without
/// overwriting the `Invalid` status — this indicates a store inconsistency (a
/// VALID chain should never contain an Invalid ancestor) and a warning is logged.
///
/// Per `consensus-specs/sync/optimistic.md:193-196`.
pub fn promote_valid_ancestors<E: EthSpec>(store: &mut Store<E>, root: Root) {
    let mut cur = root;
    loop {
        match store.payload_statuses.get(&cur) {
            // Already Valid: stop — its ancestors are already promoted.
            Some(PayloadStatus::Valid) => break,
            // Inconsistency: should never occur on a VALID chain; log + stop.
            Some(PayloadStatus::Invalid) => {
                tracing::warn!(
                    %cur,
                    "promote_valid_ancestors: encountered Invalid ancestor; \
                     stopping promotion (store inconsistency)"
                );
                break;
            }
            // NotValidated (or absent entry): promote.
            _ => {
                store.mark_payload_status(cur, PayloadStatus::Valid);
            }
        }

        // Walk to parent.
        let parent = match store.blocks.get(&cur) {
            Some(b) => b.parent_root(),
            // Block not in store (e.g. pre-anchor parent): stop.
            None => break,
        };
        if parent == Root::default() || parent == cur {
            // Reached anchor sentinel; stop.
            break;
        }
        cur = parent;
    }
}

// ── apply_invalid_payload ─────────────────────────────────────────────────────

/// Mark `block_in_question` and all its descendants as `PayloadStatus::Invalid`.
///
/// Resolves the `invalidBlock` root via `resolve_invalid_block` (3-case
/// `latestValidHash` table), then BFS-walks `store.blocks` forward from that
/// root, marking every descendant block `Invalid`.
///
/// Per `consensus-specs/sync/optimistic.md:219-222` (Fork Choice section,
/// "INVALIDATED + all descendants"):
///
/// > 1. Consensus engine MUST identify `invalidBlock` …
/// > 2. `invalidBlock` and all of its descendants MUST be transitioned from
/// >    `NOT_VALIDATED` to `INVALIDATED`.
///
/// The filter_block_tree in `get_head` already excludes `Some(Invalid)` roots
/// so weights for invalidated blocks are never applied.
///
/// Per `consensus-specs/sync/optimistic.md:263-267`.
pub fn apply_invalid_payload<E: EthSpec>(
    store: &mut Store<E>,
    block_in_question: Root,
    latest_valid_hash: Option<Hash256>,
) where
    E::BeaconBlock: BeaconBlockView,
{
    let invalid_root = resolve_invalid_block(store, block_in_question, latest_valid_hash);

    // Build a parent→children adjacency map from store.blocks so we can BFS
    // forward (toward leaves) from invalid_root.
    //
    // We collect all roots first to avoid holding a reference into `store.blocks`
    // while mutating `store.payload_statuses`.
    let mut children_of: std::collections::HashMap<Root, Vec<Root>> =
        std::collections::HashMap::new();
    for (root, block) in &store.blocks {
        children_of
            .entry(block.parent_root())
            .or_default()
            .push(*root);
    }

    // BFS from invalid_root, marking each visited block Invalid.
    let mut queue: VecDeque<Root> = VecDeque::new();
    queue.push_back(invalid_root);
    while let Some(root) = queue.pop_front() {
        store.mark_payload_status(root, PayloadStatus::Invalid);
        if let Some(children) = children_of.get(&root) {
            for child in children {
                queue.push_back(*child);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::MinimalEthSpec;
    use pharos_utils::Hash256;

    use crate::store::get_forkchoice_store;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal store seeded with a genesis state/block (no real STF).
    fn make_store() -> crate::store::Store<MinimalEthSpec> {
        use pharos_ssz::TreeHash;
        use pharos_types::phase0::{BeaconBlock, BeaconState};

        let genesis_state: <MinimalEthSpec as pharos_types::EthSpec>::BeaconState =
            pharos_types::BeaconState::Phase0(BeaconState::default());
        // genesis_block must have state_root == tree_hash_root(genesis_state).
        let mut raw = BeaconBlock::default();
        raw.state_root = genesis_state.tree_hash_root();
        let genesis_block: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(raw);
        get_forkchoice_store::<MinimalEthSpec>(genesis_state, genesis_block)
    }

    // ── resolve_invalid_block tests ───────────────────────────────────────────

    /// Case (a): null LVH → returns block_in_question unchanged.
    #[test]
    fn resolve_null_lvh_returns_block_in_question() {
        let store = make_store();
        // Use an arbitrary root not in the store (no ancestors to walk).
        let root = Hash256::from_array([0xab; 32]);
        let result = resolve_invalid_block::<MinimalEthSpec>(&store, root, None);
        assert_eq!(result, root);
    }

    /// Case (a): None LVH on a root that IS in the store still returns that root.
    #[test]
    fn resolve_null_lvh_in_store_returns_block_in_question() {
        use pharos_ssz::TreeHash;
        use pharos_types::phase0::BeaconBlock;
        let mut store = make_store();
        let block: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(BeaconBlock::default());
        let root = block.tree_hash_root();
        store.blocks.insert(root, block);
        let result = resolve_invalid_block::<MinimalEthSpec>(&store, root, None);
        assert_eq!(result, root);
    }

    /// Case (b): zero LVH → returns `block_in_question` when no execution-enabled
    /// ancestor exists (all blocks are Phase0, so `block_is_execution_enabled` is
    /// always false → `first_exec` stays None → fallback to block_in_question).
    #[test]
    fn resolve_zero_lvh_no_execution_block_returns_block_in_question() {
        let store = make_store();
        let root = Hash256::from_array([0x01; 32]);
        let result =
            resolve_invalid_block::<MinimalEthSpec>(&store, root, Some(Hash256::default()));
        assert_eq!(result, root);
    }

    /// Case (c): nonzero LVH that no ancestor matches → fallback to
    /// block_in_question (spec "behave as null").
    #[test]
    fn resolve_unknown_lvh_falls_back_to_block_in_question() {
        let store = make_store();
        let root = Hash256::from_array([0x02; 32]);
        let unknown_hash = Hash256::from_array([0xff; 32]);
        let result = resolve_invalid_block::<MinimalEthSpec>(&store, root, Some(unknown_hash));
        assert_eq!(result, root);
    }

    /// Case (b): zero LVH on a chain of TWO execution-enabled (Bellatrix) blocks.
    ///
    /// The walk must return the EARLIEST (deepest toward genesis) execution block,
    /// i.e. `block_a`, NOT the tip `block_b`.  Guards against regressions that
    /// reverse the walk direction or short-circuit too early.
    #[test]
    fn resolve_zero_lvh_returns_earliest_execution_block() {
        use pharos_ssz::TreeHash;
        use pharos_types::bellatrix::MinimalBeaconBlock;
        use pharos_types::phase0::Slot;

        let mut store = make_store();
        let genesis_root = store.finalized_checkpoint.root;

        // block_a: slot 1, execution-enabled (non-zero block_hash), child of genesis.
        let mut raw_a = MinimalBeaconBlock::default();
        raw_a.slot = Slot(1);
        raw_a.parent_root = genesis_root;
        raw_a.body.execution_payload.block_hash = pharos_utils::Hash256::from_array([0x01; 32]);
        let block_a: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Bellatrix(raw_a);
        let root_a = block_a.tree_hash_root();
        store.blocks.insert(root_a, block_a);

        // block_b: slot 2, execution-enabled (different non-zero block_hash), child of block_a.
        let mut raw_b = MinimalBeaconBlock::default();
        raw_b.slot = Slot(2);
        raw_b.parent_root = root_a;
        raw_b.body.execution_payload.block_hash = pharos_utils::Hash256::from_array([0x02; 32]);
        let block_b: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Bellatrix(raw_b);
        let root_b = block_b.tree_hash_root();
        store.blocks.insert(root_b, block_b);

        // Zero LVH on block_b (the tip): must return block_a, the earliest
        // execution-enabled ancestor, NOT block_b.
        let result =
            resolve_invalid_block::<MinimalEthSpec>(&store, root_b, Some(Hash256::default()));
        assert_eq!(
            result, root_a,
            "zero LVH should return the earliest (genesis-ward) execution block"
        );
    }

    // ── apply_invalid_payload tests ───────────────────────────────────────────

    /// Null LVH: only the block_in_question is marked Invalid; no descendants.
    #[test]
    fn apply_invalid_payload_null_lvh_marks_only_root() {
        let mut store = make_store();
        use pharos_ssz::TreeHash;
        use pharos_types::phase0::BeaconBlock;

        let block: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(BeaconBlock::default());
        let root = block.tree_hash_root();
        store.blocks.insert(root, block);

        apply_invalid_payload::<MinimalEthSpec>(&mut store, root, None);

        assert_eq!(
            store.payload_statuses.get(&root),
            Some(&PayloadStatus::Invalid)
        );
    }

    /// Transitive descendant walk: a chain of 3 blocks with null LVH on the
    /// middle block marks middle + leaf as Invalid, not the root.
    #[test]
    fn apply_invalid_payload_marks_descendants_transitively() {
        use pharos_ssz::TreeHash;
        use pharos_types::phase0::{BeaconBlock, Slot};

        let mut store = make_store();

        // Build: genesis → block_a (slot 1) → block_b (slot 2)
        // genesis root is the anchor root stored in the finalized checkpoint.
        let genesis_root = store.finalized_checkpoint.root;

        let mut raw_a = BeaconBlock::default();
        raw_a.slot = Slot(1);
        raw_a.parent_root = genesis_root;
        let block_a: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(raw_a);
        let root_a = block_a.tree_hash_root();
        store.blocks.insert(root_a, block_a);

        let mut raw_b = BeaconBlock::default();
        raw_b.slot = Slot(2);
        raw_b.parent_root = root_a;
        let block_b: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(raw_b);
        let root_b = block_b.tree_hash_root();
        store.blocks.insert(root_b, block_b);

        // Invalidate block_a with null LVH: block_a + block_b must be marked.
        apply_invalid_payload::<MinimalEthSpec>(&mut store, root_a, None);

        assert_eq!(
            store.payload_statuses.get(&root_a),
            Some(&PayloadStatus::Invalid)
        );
        assert_eq!(
            store.payload_statuses.get(&root_b),
            Some(&PayloadStatus::Invalid)
        );
        // genesis (ancestor) must NOT be marked Invalid.
        assert_ne!(
            store.payload_statuses.get(&genesis_root),
            Some(&PayloadStatus::Invalid)
        );
    }

    // ── promote_valid_ancestors tests ─────────────────────────────────────────

    /// Chain: anchor(Valid) → A(NotValidated) → B(NotValidated).
    /// `promote_valid_ancestors(B)` MUST mark both A and B Valid and stop at anchor.
    ///
    /// Per `consensus-specs/sync/optimistic.md:193-196`.
    #[test]
    fn promote_valid_ancestors_marks_chain_and_stops_at_valid() {
        use pharos_ssz::TreeHash;
        use pharos_types::{
            PayloadStatus,
            phase0::{BeaconBlock, Slot},
        };

        let mut store = make_store();
        let anchor_root = store.finalized_checkpoint.root;

        // Seed anchor as Valid (mirrors the checkpoint-sync anchor invariant).
        store.mark_payload_status(anchor_root, PayloadStatus::Valid);

        // block A: slot 1, child of anchor.
        let mut raw_a = BeaconBlock::default();
        raw_a.slot = Slot(1);
        raw_a.parent_root = anchor_root;
        let block_a: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(raw_a);
        let root_a = block_a.tree_hash_root();
        store.blocks.insert(root_a, block_a);
        store.mark_payload_status(root_a, PayloadStatus::NotValidated);

        // block B: slot 2, child of A.
        let mut raw_b = BeaconBlock::default();
        raw_b.slot = Slot(2);
        raw_b.parent_root = root_a;
        let block_b: <MinimalEthSpec as pharos_types::EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(raw_b);
        let root_b = block_b.tree_hash_root();
        store.blocks.insert(root_b, block_b);
        store.mark_payload_status(root_b, PayloadStatus::NotValidated);

        // Promote from B.
        promote_valid_ancestors::<MinimalEthSpec>(&mut store, root_b);

        // B and A must be Valid.
        assert_eq!(
            store.payload_statuses.get(&root_b),
            Some(&PayloadStatus::Valid),
            "block B must be promoted to Valid"
        );
        assert_eq!(
            store.payload_statuses.get(&root_a),
            Some(&PayloadStatus::Valid),
            "block A must be promoted to Valid"
        );
        // Anchor must still be Valid (not re-visited to become something else).
        assert_eq!(
            store.payload_statuses.get(&anchor_root),
            Some(&PayloadStatus::Valid),
            "anchor must remain Valid (walk stops at first already-Valid)"
        );
    }
}
