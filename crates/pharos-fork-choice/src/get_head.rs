//! LMD-GHOST head-selection and proposer-head helpers.
//!
//! Per `specs/phase0/fork-choice.md:253-667`.

use std::collections::HashMap;

use pharos_types::{
    BeaconStateView, EthSpec, PayloadStatus,
    phase0::{Epoch, Root, Slot},
    views::BeaconBlockView,
};

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
    let block = match store.blocks.get(&root) {
        Some(b) => b,
        None => return root,
    };
    if block.slot() > slot {
        get_ancestor(store, block.parent_root(), slot)
    } else {
        root
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

/// `get_attestation_score` per `specs/phase0/fork-choice.md:280-299`.
fn get_attestation_score<E: EthSpec>(store: &Store<E>, root: Root, state: &E::BeaconState) -> u64
where
    E::BeaconState: BeaconStateView,
    E::BeaconBlock: BeaconBlockView,
{
    use pharos_stf::phase0::accessors::get_active_validator_indices;
    use pharos_stf::phase0::accessors::get_current_epoch;

    let block_slot = store.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0));

    let current_epoch = get_current_epoch::<E>(state);
    let unslashed_active: Vec<_> = get_active_validator_indices::<E>(state, current_epoch)
        .into_iter()
        .filter(|i| {
            !state
                .validators()
                .get(i.0 as usize)
                .is_none_or(|v| v.slashed)
        })
        .collect();

    unslashed_active
        .into_iter()
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
                .validators()
                .get(i.0 as usize)
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
    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return 0,
    };
    let attestation_score = get_attestation_score(store, root, state);

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
    if matches!(
        store.payload_statuses.get(&block_root),
        Some(PayloadStatus::Invalid)
    ) {
        return false;
    }

    let children: Vec<Root> = store
        .blocks
        .iter()
        .filter_map(|(root, b)| {
            if b.parent_root() == block_root {
                Some(*root)
            } else {
                None
            }
        })
        .collect();

    if !children.is_empty() {
        let results: Vec<bool> = children
            .iter()
            .map(|child| filter_block_tree(store, *child, blocks))
            .collect();
        if results.into_iter().any(|r| r) {
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
fn effective_base<E: EthSpec>(store: &Store<E>) -> Root
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
    let mut blocks = HashMap::new();
    filter_block_tree(store, base, &mut blocks);
    blocks
}

/// `get_head` per `specs/phase0/fork-choice.md:422-437`.
///
/// Executes LMD-GHOST on the filtered block tree.  Tie-break: higher root wins
/// (spec: `max_by_key(|(root, _)| (weight, root))`).
///
/// Per R7: "Fork-choice tie-break uses `(weight, root)` lexicographic max".
pub fn get_head<E: EthSpec>(store: &Store<E>) -> Root
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let blocks = get_filtered_block_tree(store);
    let mut head = effective_base(store);
    loop {
        let children: Vec<Root> = blocks
            .iter()
            .filter_map(|(root, b)| {
                if b.parent_root() == head {
                    Some(*root)
                } else {
                    None
                }
            })
            .collect();

        if children.is_empty() {
            return head;
        }

        // Max by (weight, root) — higher root breaks ties per spec.
        head = children
            .into_iter()
            .max_by_key(|root| (get_weight::<E>(store, *root), *root))
            .unwrap();
    }
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
    let state = match store.checkpoint_states.get(&store.justified_checkpoint) {
        Some(s) => s,
        None => return false,
    };
    let reorg_threshold = calculate_committee_fraction::<E>(state, REORG_HEAD_WEIGHT_THRESHOLD);
    let head_weight = get_weight::<E>(store, head_root);
    head_weight < reorg_threshold
}

/// `is_parent_strong` per `specs/phase0/fork-choice.md:586-592`.
pub fn is_parent_strong<E: EthSpec>(store: &Store<E>, root: Root) -> bool
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
    let parent_weight = get_weight::<E>(store, parent_root);
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

    let head_weak = is_head_weak::<E>(store, head_root);
    let parent_strong = is_parent_strong::<E>(store, head_root);
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
}
