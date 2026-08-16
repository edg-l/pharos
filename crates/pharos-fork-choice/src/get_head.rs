//! LMD-GHOST head-selection and proposer-head helpers.
//!
//! Per `specs/phase0/fork-choice.md:253-667`.

use std::collections::HashMap;

use pharos_types::{
    BeaconStateView, EthSpec, PayloadStatus,
    phase0::{Epoch, Root, Slot, ValidatorIndex},
    views::BeaconBlockView,
};
use pharos_utils::metrics::METRIC_FORK_CHOICE_GET_HEAD_SECONDS;

use crate::store::Store;

// ── Fork-choice constants ─────────────────────────────────────────────────────

/// `PROPOSER_SCORE_BOOST` per `specs/phase0/fork-choice.md:122`.
const PROPOSER_SCORE_BOOST: u64 = 40;
/// `REORG_HEAD_WEIGHT_THRESHOLD` per `specs/phase0/fork-choice.md:124`.
const REORG_HEAD_WEIGHT_THRESHOLD: u64 = 20;
/// `REORG_PARENT_WEIGHT_THRESHOLD` per `specs/phase0/fork-choice.md:125`.
const REORG_PARENT_WEIGHT_THRESHOLD: u64 = 160;
/// `REORG_MAX_EPOCHS_SINCE_FINALIZATION` per `specs/phase0/fork-choice.md:126`.
const REORG_MAX_EPOCHS_SINCE_FINALIZATION: u64 = 2;
/// `PROPOSER_REORG_CUTOFF_BPS` per `specs/phase0/fork-choice.md:136`.
const PROPOSER_REORG_CUTOFF_BPS: u64 = 1_667;

// ── Slot/time conversion helpers ─────────────────────────────────────────────

/// Slot number derivable from `time` and `genesis_time`.
///
/// Shared by `get_slots_since_genesis` and `on_tick`. Saturating-subtracts so
/// invalid stores (`time < genesis_time`) yield slot 0 rather than panicking.
pub(crate) fn slot_from_time<E: EthSpec>(time: u64, genesis_time: u64) -> u64 {
    time.saturating_sub(genesis_time) * 1000 / E::SLOT_DURATION_MS
}

/// Wall-clock time at the start of `slot`, inverse of `slot_from_time`.
///
/// Shared by `on_tick` and `get_forkchoice_store`.
pub(crate) fn slot_start_time<E: EthSpec>(slot: u64, genesis_time: u64) -> u64 {
    genesis_time + slot * E::SLOT_DURATION_MS / 1000
}

/// Milliseconds elapsed within the current slot of `store`.
///
/// Shared by `is_proposing_on_time` and `record_block_timeliness`.
pub(crate) fn time_into_current_slot_ms<E: EthSpec>(store: &Store<E>) -> u64 {
    let seconds_since_genesis = store.time.saturating_sub(store.genesis_time);
    seconds_to_milliseconds(seconds_since_genesis) % E::SLOT_DURATION_MS
}

// ── Slot/epoch helpers ────────────────────────────────────────────────────────

/// `get_slots_since_genesis` per `specs/phase0/fork-choice.md:224-226`.
pub fn get_slots_since_genesis<E: EthSpec>(store: &Store<E>) -> u64 {
    slot_from_time::<E>(store.time, store.genesis_time)
}

/// `get_current_slot` per `specs/phase0/fork-choice.md:229-231`.
pub fn get_current_slot<E: EthSpec>(store: &Store<E>) -> Slot {
    Slot(get_slots_since_genesis(store))
}

/// `get_current_store_epoch` per `specs/phase0/fork-choice.md:234-236`.
pub fn get_current_store_epoch<E: EthSpec>(store: &Store<E>) -> Epoch {
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    compute_epoch_at_slot(get_current_slot(store), E::SLOTS_PER_EPOCH)
}

/// `compute_slots_since_epoch_start` per `specs/phase0/fork-choice.md:239-241`.
pub fn compute_slots_since_epoch_start<E: EthSpec>(slot: Slot) -> u64 {
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let start = compute_start_slot_at_epoch(epoch, E::SLOTS_PER_EPOCH);
    slot.0 - start.0
}

// ── Ancestor / checkpoint helpers ─────────────────────────────────────────────

/// `get_ancestor` per `specs/phase0/fork-choice.md:253-258`.
///
/// Walk the chain from `root` backwards until a block at `slot` or earlier is
/// found, then return its root.
pub fn get_ancestor<E: EthSpec>(store: &Store<E>, root: Root, slot: Slot) -> Root
where
    E::BeaconBlock: BeaconBlockView,
{
    // Iterative walk (not recursion): this runs once per attesting validator in
    // `get_attestation_score`, and a deep unfinalized chain would otherwise risk
    // a stack overflow.
    let mut cur = root;
    loop {
        let Some(block) = store.blocks.get(&cur) else {
            return cur;
        };
        if block.slot() > slot {
            cur = block.parent_root();
        } else {
            return cur;
        }
    }
}

/// `get_checkpoint_block` per `specs/phase0/fork-choice.md:270-276`.
pub fn get_checkpoint_block<E: EthSpec>(store: &Store<E>, root: Root, epoch: Epoch) -> Root
where
    E::BeaconBlock: BeaconBlockView,
{
    use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
    let epoch_first_slot = compute_start_slot_at_epoch(epoch, E::SLOTS_PER_EPOCH);
    get_ancestor(store, root, epoch_first_slot)
}

// ── Attestation score / proposer score ───────────────────────────────────────

/// The active-validator index set for the justified-checkpoint state.
///
/// This set is invariant within a single `get_head` / `get_proposer_head` call:
/// every weight helper resolves the SAME `state =
/// store.checkpoint_states[store.justified_checkpoint]`, so both the epoch
/// (`get_current_epoch(state)`) and the resulting active set depend only on that
/// one state and never vary by `root`. Computing it once and reusing it across
/// roots avoids rebuilding an O(validators) `Vec` per weighed root.
fn active_indices_for_justified<E: EthSpec>(store: &Store<E>) -> Vec<ValidatorIndex>
where
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_active_validator_indices;
    use pharos_stf::phase0::accessors::get_current_epoch;

    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let current_epoch = get_current_epoch::<E>(state);
    get_active_validator_indices::<E>(state, current_epoch)
}

/// `get_attestation_score` per `specs/phase0/fork-choice.md:280-299`.
///
/// `active_indices` MUST be the active-validator index set of `state` for
/// `get_current_epoch(state)` (see `active_indices_for_justified`); callers pass
/// it in so it is built once per `get_head` / `get_proposer_head` call rather
/// than rebuilt per root.
fn get_attestation_score<E: EthSpec>(
    store: &Store<E>,
    root: Root,
    state: &E::BeaconState,
    active_indices: &[ValidatorIndex],
) -> u64
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let block_slot = store.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0));

    // Use the borrowing `validator(idx)` accessor, NOT `validators().get(idx)`:
    // the latter clones the entire validator registry on every call, which made
    // this an O(n^2) hot path (run once per active validator, per get_head).
    active_indices
        .iter()
        .filter(|i| !state.validator(i.0 as usize).is_none_or(|v| v.slashed))
        .filter(|i| {
            store.latest_messages.contains_key(i)
                && !store.equivocating_indices.contains(i)
                && store
                    .latest_messages
                    .get(i)
                    .map(|msg| get_ancestor(store, msg.root, block_slot) == root)
                    .unwrap_or(false)
        })
        .map(|i| {
            state
                .validator(i.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0)
        })
        .sum()
}

/// `compute_proposer_score` per `specs/phase0/fork-choice.md:303-307`.
pub fn compute_proposer_score<E: EthSpec>(state: &E::BeaconState) -> u64
where
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_total_active_balance;
    let committee_weight = get_total_active_balance::<E>(state).0 / E::SLOTS_PER_EPOCH;
    (committee_weight * PROPOSER_SCORE_BOOST) / 100
}

/// `get_proposer_score` per `specs/phase0/fork-choice.md:310-313`.
pub fn get_proposer_score<E: EthSpec>(store: &Store<E>) -> u64
where
    E::BeaconState: BeaconStateView,
{
    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return 0,
    };
    compute_proposer_score::<E>(state)
}

/// `get_weight` per `specs/phase0/fork-choice.md:316-333`.
///
/// Returns the LMD-GHOST vote weight for `root`, including proposer boost.
pub fn get_weight<E: EthSpec>(store: &Store<E>, root: Root) -> u64
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let active_indices = active_indices_for_justified(store);
    get_weight_with(store, root, &active_indices)
}

/// `get_weight` with the active-validator index set hoisted by the caller.
///
/// Identical result to `get_weight`; `active_indices` MUST be
/// `active_indices_for_justified(store)`. Splitting it out lets a single
/// `get_proposer_head` call build the active set once and reuse it across the
/// (head, parent) roots it weighs.
fn get_weight_with<E: EthSpec>(
    store: &Store<E>,
    root: Root,
    active_indices: &[ValidatorIndex],
) -> u64
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return 0,
    };
    let attestation_score = get_attestation_score(store, root, state, active_indices);

    if store.proposer_boost_root == Root::default() {
        return attestation_score;
    }

    let block_slot = store.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0));

    let proposer_score = if get_ancestor(store, store.proposer_boost_root, block_slot) == root {
        get_proposer_score::<E>(store)
    } else {
        0
    };

    attestation_score + proposer_score
}

// ── Voting source ─────────────────────────────────────────────────────────────

/// `get_voting_source` per `specs/phase0/fork-choice.md:336-353`.
fn get_voting_source<E: EthSpec>(
    store: &Store<E>,
    block_root: Root,
) -> pharos_types::phase0::Checkpoint
where
    E::BeaconBlock: BeaconBlockView,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    use pharos_types::phase0::Checkpoint;

    let block = match store.blocks.get(&block_root) {
        Some(b) => b,
        None => return Checkpoint::default(),
    };
    let current_epoch = get_current_store_epoch::<E>(store);
    let block_epoch = compute_epoch_at_slot(block.slot(), E::SLOTS_PER_EPOCH);

    if current_epoch > block_epoch {
        // Block from a prior epoch: use unrealized justification (pulled-up).
        store
            .unrealized_justifications
            .get(&block_root)
            .cloned()
            .unwrap_or_default()
    } else {
        // Block from current epoch: use on-chain justified checkpoint.
        store
            .block_states
            .get(&block_root)
            .map(|s| s.current_justified_checkpoint().clone())
            .unwrap_or_default()
    }
}

// ── filter_block_tree / get_head ──────────────────────────────────────────────

/// Build a `parent_root -> [child_root]` adjacency index over a block map in a
/// single pass. `filter_block_tree` and `get_head` both need to enumerate a
/// block's children; without this they each rescan the whole map per node,
/// which is O(n^2) over the block set on every `get_head` call.
fn children_index<E: EthSpec>(blocks: &HashMap<Root, E::BeaconBlock>) -> HashMap<Root, Vec<Root>>
where
    E::BeaconBlock: BeaconBlockView,
{
    let mut idx: HashMap<Root, Vec<Root>> = HashMap::new();
    for (root, b) in blocks.iter() {
        idx.entry(b.parent_root()).or_default().push(*root);
    }
    idx
}

/// `filter_block_tree` per `specs/phase0/fork-choice.md:356-405`.
///
/// Returns `true` if `block_root` is a viable head.  Inserts viable blocks
/// into `blocks`.
///
/// External calls MUST set `block_root` to `store.justified_checkpoint.root`.
pub fn filter_block_tree<E: EthSpec>(
    store: &Store<E>,
    block_root: Root,
    blocks: &mut HashMap<Root, E::BeaconBlock>,
    children_idx: &HashMap<Root, Vec<Root>>,
) -> bool
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::helpers::GENESIS_EPOCH;

    let block = match store.blocks.get(&block_root) {
        Some(b) => b,
        None => return false,
    };

    // Bellatrix per `specs/bellatrix/fork-choice.md:74-79`: skip any block
    // whose execution payload has been marked `Invalid` by the EL. The
    // descendants are also unreachable from this root, but recursion via
    // each parent already filters them out, so we only need the local check.
    //
    // GUARD — MUST NOT filter `NotValidated` (only `Some(Invalid)`):
    // Optimistically imported blocks remain in the viable tree while their
    // payload status is `NotValidated`. A re-org between two `NotValidated`
    // tips MUST resolve via normal LMD-GHOST weight, not by pruning either
    // tip from the tree. Per `consensus-specs/sync/optimistic.md` "Re-Orgs":
    // "The consensus engine MUST support any chain reorganisation which does
    // not affect the justified checkpoint."  `D-reorg-notvalidated-by-weight`.
    if matches!(
        store.payload_statuses.get(&block_root),
        Some(PayloadStatus::Invalid)
    ) {
        return false;
    }

    let children = children_idx
        .get(&block_root)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    if !children.is_empty() {
        // Recurse into EVERY child: the `blocks.insert` side effect must run for
        // all viable descendants, so this must not short-circuit (unlike `any`).
        let mut any_viable = false;
        for child in children {
            if filter_block_tree(store, *child, blocks, children_idx) {
                any_viable = true;
            }
        }
        if any_viable {
            blocks.insert(block_root, block.clone());
            return true;
        }
        return false;
    }

    // Leaf node: check justified/finalized viability.
    let current_epoch = get_current_store_epoch::<E>(store);
    let voting_source = get_voting_source::<E>(store, block_root);

    // Per `specs/phase0/fork-choice.md:382-386`.
    let correct_justified = store.justified_checkpoint.epoch.0 == GENESIS_EPOCH
        || voting_source.epoch == store.justified_checkpoint.epoch
        || voting_source.epoch.0 + 2 >= current_epoch.0;

    let finalized_checkpoint_block =
        get_checkpoint_block::<E>(store, block_root, store.finalized_checkpoint.epoch);

    // Per `specs/phase0/fork-choice.md:393-397`.
    let correct_finalized = store.finalized_checkpoint.epoch.0 == GENESIS_EPOCH
        || store.finalized_checkpoint.root == finalized_checkpoint_block;

    if correct_justified && correct_finalized {
        blocks.insert(block_root, block.clone());
        return true;
    }

    false
}

/// Root the fork-choice search anchors at.
///
/// The spec uses `store.justified_checkpoint.root` unconditionally. After a
/// weak-subjectivity / checkpoint-sync start that root can name a block we never
/// fetched: `on_block` -> `update_checkpoints` adopts the imported block state's
/// *real* justified checkpoint (a pre-anchor block), overwriting the synthetic
/// anchor checkpoint `apply_anchor` seeded. The justified block (and its state)
/// only land once backfill walks back to them. Until then, fall back to the
/// finalized root, which after checkpoint sync is the trusted anchor and is
/// always present in `blocks`. In genesis operation the justified root is always
/// present, so this is a no-op there.
pub(crate) fn effective_base<E: EthSpec>(store: &Store<E>) -> Root
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    if store.blocks.contains_key(&store.justified_checkpoint.root) {
        store.justified_checkpoint.root
    } else {
        store.finalized_checkpoint.root
    }
}

/// `get_filtered_block_tree` per `specs/phase0/fork-choice.md:408-419`.
fn get_filtered_block_tree<E: EthSpec>(store: &Store<E>) -> HashMap<Root, E::BeaconBlock>
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let base = effective_base(store);
    let children_idx = children_index::<E>(&store.blocks);
    let mut blocks = HashMap::new();
    filter_block_tree(store, base, &mut blocks, &children_idx);
    blocks
}

/// `get_head` per `specs/phase0/fork-choice.md:422-437`.
///
/// Executes LMD-GHOST on the filtered block tree.  Tie-break: higher root wins
/// (spec: `max_by_key(|(root, _)| (weight, root))`).
///
/// Per R7: "Fork-choice tie-break uses `(weight, root)` lexicographic max".
///
/// Contract: the returned root is normally present in `store.blocks`, but this
/// is NOT guaranteed in pathological states (e.g. a weak-subjectivity store
/// whose justified/finalized roots are both pre-anchor and unfetched). Callers
/// MUST handle absence defensively (return an error / fall back) rather than
/// `expect`/`unwrap` the lookup — a missing head must never panic the node.
pub fn get_head<E: EthSpec>(store: &Store<E>) -> Root
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let _t0 = std::time::Instant::now();

    let blocks = get_filtered_block_tree(store);
    let children_idx = children_index::<E>(&blocks);
    // Hoist the active-validator index set once: it is invariant across every
    // weighed root within this call (see `active_indices_for_justified`), so
    // `get_weight` need not rebuild it per child.
    let active_indices = active_indices_for_justified(store);
    // Memoize weights for the duration of this call: weights are constant within
    // a single store snapshot, but `max_by_key` would otherwise recompute
    // `get_weight` (itself O(validators)) once per child per descent level.
    let mut weights: HashMap<Root, u64> = HashMap::new();
    let mut head = effective_base(store);
    let result = loop {
        let Some(children) = children_idx.get(&head) else {
            break head; // No children → head is a leaf.
        };

        // Max by (weight, root) — higher root breaks ties per spec.
        head = children
            .iter()
            .copied()
            .max_by_key(|root| {
                let w = *weights
                    .entry(*root)
                    .or_insert_with(|| get_weight_with::<E>(store, *root, &active_indices));
                (w, *root)
            })
            .expect("children index never stores empty child lists");
    };

    metrics::histogram!(METRIC_FORK_CHOICE_GET_HEAD_SECONDS).record(_t0.elapsed().as_secs_f64());
    result
}

// ── calculate_committee_fraction ─────────────────────────────────────────────

/// `calculate_committee_fraction` per `specs/phase0/fork-choice.md:261-265`.
fn calculate_committee_fraction<E: EthSpec>(state: &E::BeaconState, committee_percent: u64) -> u64
where
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_total_active_balance;
    let committee_weight = get_total_active_balance::<E>(state).0 / E::SLOTS_PER_EPOCH;
    (committee_weight * committee_percent) / 100
}

// ── Proposer head and reorg helpers ──────────────────────────────────────────

/// `seconds_to_milliseconds` per `specs/phase0/fork-choice.md:490-497`.
pub(crate) fn seconds_to_milliseconds(seconds: u64) -> u64 {
    seconds.saturating_mul(1000)
}

/// `get_slot_component_duration_ms` per `specs/phase0/fork-choice.md:501-507`.
pub(crate) fn get_slot_component_duration_ms<E: EthSpec>(basis_points: u64) -> u64 {
    basis_points * E::SLOT_DURATION_MS / E::BASIS_POINTS
}

/// `get_proposer_reorg_cutoff_ms` per `specs/phase0/fork-choice.md:519-521`.
fn get_proposer_reorg_cutoff_ms<E: EthSpec>() -> u64 {
    get_slot_component_duration_ms::<E>(PROPOSER_REORG_CUTOFF_BPS)
}

/// `is_head_late` per `specs/phase0/fork-choice.md:535-537`.
pub fn is_head_late<E: EthSpec>(store: &Store<E>, head_root: Root) -> bool {
    !store
        .block_timeliness
        .get(&head_root)
        .copied()
        .unwrap_or(false)
}

/// `is_shuffling_stable` per `specs/phase0/fork-choice.md:541-543`.
pub fn is_shuffling_stable<E: EthSpec>(slot: Slot) -> bool {
    slot.0 % E::SLOTS_PER_EPOCH != 0
}

/// `is_ffg_competitive` per `specs/phase0/fork-choice.md:547-551`.
pub fn is_ffg_competitive<E: EthSpec>(
    store: &Store<E>,
    head_root: Root,
    parent_root: Root,
) -> bool {
    store
        .unrealized_justifications
        .get(&head_root)
        .zip(store.unrealized_justifications.get(&parent_root))
        .map(|(h, p)| h == p)
        .unwrap_or(false)
}

/// `is_finalization_ok` per `specs/phase0/fork-choice.md:555-558`.
pub fn is_finalization_ok<E: EthSpec>(store: &Store<E>, slot: Slot) -> bool {
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    let current_epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let epochs_since_finalization = current_epoch
        .0
        .saturating_sub(store.finalized_checkpoint.epoch.0);
    epochs_since_finalization <= REORG_MAX_EPOCHS_SINCE_FINALIZATION
}

/// `is_proposing_on_time` per `specs/phase0/fork-choice.md:561-565`.
pub fn is_proposing_on_time<E: EthSpec>(store: &Store<E>) -> bool {
    time_into_current_slot_ms::<E>(store) <= get_proposer_reorg_cutoff_ms::<E>()
}

/// `is_head_weak` per `specs/phase0/fork-choice.md:577-582`.
pub fn is_head_weak<E: EthSpec>(store: &Store<E>, head_root: Root) -> bool
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let active_indices = active_indices_for_justified(store);
    let mut weights = HashMap::new();
    is_head_weak_with(store, head_root, &active_indices, &mut weights)
}

/// `is_head_weak` with the active-validator set hoisted and a per-call weight
/// memo threaded by the caller. Identical result to `is_head_weak`.
fn is_head_weak_with<E: EthSpec>(
    store: &Store<E>,
    head_root: Root,
    active_indices: &[ValidatorIndex],
    weights: &mut HashMap<Root, u64>,
) -> bool
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return false,
    };
    let reorg_threshold = calculate_committee_fraction::<E>(state, REORG_HEAD_WEIGHT_THRESHOLD);
    let head_weight = *weights
        .entry(head_root)
        .or_insert_with(|| get_weight_with::<E>(store, head_root, active_indices));
    head_weight < reorg_threshold
}

/// `is_parent_strong` per `specs/phase0/fork-choice.md:586-592`.
pub fn is_parent_strong<E: EthSpec>(store: &Store<E>, root: Root) -> bool
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let active_indices = active_indices_for_justified(store);
    let mut weights = HashMap::new();
    is_parent_strong_with(store, root, &active_indices, &mut weights)
}

/// `is_parent_strong` with the active-validator set hoisted and a per-call
/// weight memo threaded by the caller. Identical result to `is_parent_strong`.
fn is_parent_strong_with<E: EthSpec>(
    store: &Store<E>,
    root: Root,
    active_indices: &[ValidatorIndex],
    weights: &mut HashMap<Root, u64>,
) -> bool
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return false,
    };
    let parent_threshold = calculate_committee_fraction::<E>(state, REORG_PARENT_WEIGHT_THRESHOLD);
    let parent_root = match store.blocks.get(&root) {
        Some(b) => b.parent_root(),
        None => return false,
    };
    let parent_weight = *weights
        .entry(parent_root)
        .or_insert_with(|| get_weight_with::<E>(store, parent_root, active_indices));
    parent_weight > parent_threshold
}

/// `is_proposer_equivocation` per `specs/phase0/fork-choice.md:596-611`.
pub fn is_proposer_equivocation<E: EthSpec>(store: &Store<E>, root: Root) -> bool
where
    E::BeaconBlock: BeaconBlockView,
{
    let block = match store.blocks.get(&root) {
        Some(b) => b,
        None => return false,
    };
    let proposer_index = block.proposer_index();
    let slot = block.slot();

    let matching_count = store
        .blocks
        .values()
        .filter(|b| b.proposer_index() == proposer_index && b.slot() == slot)
        .count();

    matching_count > 1
}

/// `get_proposer_head` per `specs/phase0/fork-choice.md:614-667`.
///
/// Returns `parent_root` when all re-org conditions hold, otherwise `head_root`.
/// Each predicate is a `pub fn` so Phase 9 conformance can exercise them
/// individually.
pub fn get_proposer_head<E: EthSpec>(store: &Store<E>, head_root: Root, slot: Slot) -> Root
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let head_block = match store.blocks.get(&head_root) {
        Some(b) => b,
        None => return head_root,
    };
    let parent_root = head_block.parent_root();
    let parent_block = match store.blocks.get(&parent_root) {
        Some(b) => b,
        None => return head_root,
    };

    let head_late = is_head_late::<E>(store, head_root);
    let shuffling_stable = is_shuffling_stable::<E>(slot);
    let ffg_competitive = is_ffg_competitive::<E>(store, head_root, parent_root);
    let finalization_ok = is_finalization_ok::<E>(store, slot);
    let proposing_on_time = is_proposing_on_time::<E>(store);

    // Single-slot reorg check.
    let parent_slot_ok = parent_block.slot().0 + 1 == head_block.slot().0;
    let current_time_ok = head_block.slot().0 + 1 == slot.0;
    let single_slot_reorg = parent_slot_ok && current_time_ok;

    // The proposer boost must have worn off (spec uses `assert`; we return
    // `head_root` conservatively when the boost is still active).
    if store.proposer_boost_root == head_root {
        return head_root;
    }

    // Hoist the active-validator index set once (invariant across both weighed
    // roots — see `active_indices_for_justified`) and share a per-call weight
    // memo across the two weight-consuming predicates. `is_head_weak` weighs
    // `head_root`; `is_parent_strong` weighs `parent_root`; without sharing,
    // each rebuilds the O(validators) active set and recomputes its weight.
    let active_indices = active_indices_for_justified(store);
    let mut weights: HashMap<Root, u64> = HashMap::new();
    let head_weak = is_head_weak_with::<E>(store, head_root, &active_indices, &mut weights);
    let parent_strong = is_parent_strong_with::<E>(store, head_root, &active_indices, &mut weights);
    let proposer_equivocation = is_proposer_equivocation::<E>(store, head_root);

    // Standard proposer re-org.
    if head_late
        && shuffling_stable
        && ffg_competitive
        && finalization_ok
        && proposing_on_time
        && single_slot_reorg
        && head_weak
        && parent_strong
    {
        return parent_root;
    }

    // Aggressive re-org on equivocation.
    if head_weak && current_time_ok && proposer_equivocation {
        return parent_root;
    }

    head_root
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::time::{SystemTime, UNIX_EPOCH};

    use pharos_types::{
        EthSpec, MinimalEthSpec,
        phase0::{Checkpoint, Root},
    };
    use pharos_utils::{Hash256, Uint256};

    use crate::store::Store;

    /// Build a bare `Store<MinimalEthSpec>` with all maps empty and the given
    /// `genesis_time`/`time`.  Only the fields consulted by `get_current_slot`
    /// matter; everything else is zeroed/defaulted.
    fn minimal_store(genesis_time: u64, time: u64) -> Store<MinimalEthSpec> {
        let cp = Checkpoint::default();
        Store {
            time,
            genesis_time,
            justified_checkpoint: cp.clone(),
            finalized_checkpoint: cp.clone(),
            unrealized_justified_checkpoint: cp.clone(),
            unrealized_finalized_checkpoint: cp,
            proposer_boost_root: Root::default(),
            equivocating_indices: HashSet::new(),
            blocks: HashMap::new(),
            block_states: HashMap::new(),
            block_timeliness: HashMap::new(),
            checkpoint_states: HashMap::new(),
            latest_messages: HashMap::new(),
            unrealized_justifications: HashMap::new(),
            payload_statuses: HashMap::new(),
            terminal_total_difficulty: Uint256::ZERO,
            terminal_block_hash: Hash256::default(),
            terminal_block_hash_activation_epoch: u64::MAX,
            altair_fork_epoch: u64::MAX,
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_epoch: u64::MAX,
            runtime_cfg: pharos_types::config::RuntimeConfig::default(),
        }
    }

    /// Pins the contract: `get_current_slot` derives the slot from the Store's
    /// `genesis_time`, not from the wall clock.
    ///
    /// Two assertions:
    /// 1. `genesis_time == wall_now` with `time == wall_now` → `Slot(0)`.
    /// 2. `genesis_time == wall_now - N * seconds_per_slot` with `time == wall_now`
    ///    → `Slot(N)`.
    #[test]
    fn current_slot_tracks_store_genesis_not_wallclock() {
        use super::get_current_slot;
        use pharos_types::phase0::Slot;

        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs();

        let seconds_per_slot = MinimalEthSpec::SLOT_DURATION_MS / 1000;

        // 1. genesis == now → slot 0.
        let store = minimal_store(wall_now, wall_now);
        assert_eq!(get_current_slot(&store), Slot(0));

        // 2. genesis N slots ago → Slot(N).
        const N: u64 = 100;
        let genesis_time = wall_now - N * seconds_per_slot;
        let store = minimal_store(genesis_time, wall_now);
        assert_eq!(get_current_slot(&store), Slot(N));
    }

    /// Regression: weak-subjectivity / checkpoint-sync head fallback.
    ///
    /// After a non-zero-anchor checkpoint sync, the first imported block's
    /// `update_checkpoints` adopts the block state's REAL justified root — a
    /// pre-anchor block never fetched, so absent from `store.blocks`. Before the
    /// fix, `get_head` seeded from that absent root and the import head lookup
    /// `.expect()`-panicked ("head must be in store"). `effective_base` must fall
    /// back to the finalized (anchor) root when the justified root is absent, and
    /// must be a no-op (return the justified root) once it IS present.
    #[test]
    fn effective_base_falls_back_to_finalized_when_justified_absent() {
        use pharos_types::phase0::BeaconBlock as Phase0BeaconBlock;

        let anchor_root = Hash256::from_array([0x11; 32]);
        let absent_justified_root = Hash256::from_array([0x22; 32]);

        let block: <MinimalEthSpec as EthSpec>::BeaconBlock =
            pharos_types::BeaconBlock::Phase0(Phase0BeaconBlock::default());

        let mut store = minimal_store(0, 0);
        // Anchor (finalized) block is present; the real justified root is not.
        store.blocks.insert(anchor_root, block.clone());
        store.finalized_checkpoint = Checkpoint {
            epoch: pharos_utils::Epoch(0),
            root: anchor_root,
        };
        store.justified_checkpoint = Checkpoint {
            epoch: pharos_utils::Epoch(13),
            root: absent_justified_root,
        };

        // Fallback: justified root absent → finalized/anchor root.
        assert_eq!(super::effective_base(&store), anchor_root);

        // No-op: once the justified block lands, it is used unchanged.
        store.blocks.insert(absent_justified_root, block);
        assert_eq!(super::effective_base(&store), absent_justified_root);
    }
}
