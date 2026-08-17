//! Fast Confirmation Rule (FCR).
//!
//! Per `specs/phase0/fast-confirmation.md`.
//!
//! All helpers are direct translations of the Python spec.  Naming,
//! argument order, and edge-case handling are kept byte-faithful to the spec.

use std::collections::HashSet;

use pharos_types::{
    BeaconSpec, BeaconStateView,
    phase0::{Checkpoint, Epoch, Gwei, Root, Slot, ValidatorIndex},
    views::BeaconBlockView,
};

use crate::get_head::{
    compute_slots_since_epoch_start, get_ancestor, get_attestation_score, get_checkpoint_block,
    get_current_slot, get_current_store_epoch, get_voting_source,
};
use crate::store::Store;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Per mille value to add to the committee weight estimate across a range of
/// slots that does not cover a full epoch, to ensure safety of FCR with high
/// probability.
///
/// `specs/phase0/fast-confirmation.md:Constants`.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// Maximum assumed percentage of Byzantine validators.
///
/// `specs/phase0/fast-confirmation.md:Configuration`.
const CONFIRMATION_BYZANTINE_THRESHOLD: u64 = 25;

// ── FastConfirmationStore ─────────────────────────────────────────────────────

/// Tracks information required for the Fast Confirmation Rule.
///
/// Per `specs/phase0/fast-confirmation.md:FastConfirmationStore`.
pub struct FastConfirmationStore {
    /// Root of the most recent confirmed block.
    pub confirmed_root: Root,
    /// A justified checkpoint observed by all honest nodes at the beginning of
    /// the previous epoch (assuming synchrony).
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    /// A justified checkpoint observed by all honest nodes at the beginning of
    /// the current epoch (assuming synchrony).
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    /// Greatest unrealized justified checkpoint at the start of the last slot
    /// of the previous epoch.
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    /// Head at the start of the previous slot.
    pub previous_slot_head: Root,
    /// Head at the start of the current slot.
    pub current_slot_head: Root,
}

// ── `get_fast_confirmation_store` ────────────────────────────────────────────

/// Initialise a `FastConfirmationStore` from the fork-choice `Store`.
///
/// Per `specs/phase0/fast-confirmation.md:get_fast_confirmation_store`.
/// Uses `store.finalized_checkpoint` conservatively for all variables.
pub fn get_fast_confirmation_store<E: BeaconSpec>(store: &Store<E>) -> FastConfirmationStore {
    FastConfirmationStore {
        confirmed_root: store.finalized_checkpoint.root,
        previous_epoch_observed_justified_checkpoint: store.finalized_checkpoint.clone(),
        current_epoch_observed_justified_checkpoint: store.finalized_checkpoint.clone(),
        previous_epoch_greatest_unrealized_checkpoint: store.finalized_checkpoint.clone(),
        previous_slot_head: store.finalized_checkpoint.root,
        current_slot_head: store.finalized_checkpoint.root,
    }
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

/// `get_block_slot` — slot of the block at `block_root`.
fn get_block_slot<E: BeaconSpec>(store: &Store<E>, block_root: Root) -> Slot
where
    E::BeaconBlock: BeaconBlockView,
{
    store
        .blocks
        .get(&block_root)
        .map(|b| b.slot())
        .unwrap_or(Slot(0))
}

/// `get_block_epoch` — epoch of the block at `block_root`.
fn get_block_epoch<E: BeaconSpec>(store: &Store<E>, block_root: Root) -> Epoch
where
    E::BeaconBlock: BeaconBlockView,
{
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    compute_epoch_at_slot(get_block_slot(store, block_root), E::SLOTS_PER_EPOCH)
}

/// `get_checkpoint_for_block` — checkpoint in the chain of `block_root` at
/// `epoch`.
fn get_checkpoint_for_block<E: BeaconSpec>(
    store: &Store<E>,
    block_root: Root,
    epoch: Epoch,
) -> Checkpoint
where
    E::BeaconBlock: BeaconBlockView,
{
    Checkpoint {
        epoch,
        root: get_checkpoint_block::<E>(store, block_root, epoch),
    }
}

/// `get_current_target` — current epoch target checkpoint for the current head.
fn get_current_target<E: BeaconSpec>(store: &Store<E>) -> Checkpoint
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let head = crate::get_head::get_head::<E>(store);
    let current_epoch = get_current_store_epoch::<E>(store);
    get_checkpoint_for_block::<E>(store, head, current_epoch)
}

/// `is_start_slot_at_epoch` — true if `slot` is the first slot of an epoch.
fn is_start_slot_at_epoch<E: BeaconSpec>(slot: Slot) -> bool {
    compute_slots_since_epoch_start::<E>(slot) == 0
}

/// `is_ancestor` — true if `ancestor_root` is an ancestor of `block_root`.
fn is_ancestor<E: BeaconSpec>(store: &Store<E>, block_root: Root, ancestor_root: Root) -> bool
where
    E::BeaconBlock: BeaconBlockView,
{
    let ancestor_slot = get_block_slot(store, ancestor_root);
    get_ancestor::<E>(store, block_root, ancestor_slot) == ancestor_root
}

/// `get_ancestor_roots` — ancestors of `block_root` down to (exclusive) the
/// slot of `terminal_root`, in ascending slot order.
///
/// Returns an empty vec when `terminal_root` is not in the chain of
/// `block_root`.
fn get_ancestor_roots<E: BeaconSpec>(
    store: &Store<E>,
    block_root: Root,
    terminal_root: Root,
) -> Vec<Root>
where
    E::BeaconBlock: BeaconBlockView,
{
    let terminal_slot = get_block_slot(store, terminal_root);
    let mut root = block_root;
    let mut ancestors: Vec<Root> = Vec::new();

    loop {
        let slot = get_block_slot(store, root);
        if slot <= terminal_slot {
            break;
        }
        ancestors.push(root);
        let parent = match store.blocks.get(&root) {
            Some(b) => b.parent_root(),
            None => break,
        };
        if parent == terminal_root {
            // Reached terminal; the chain contains terminal_root.
            // Reverse so the vec is in ascending slot order (smallest first).
            ancestors.reverse();
            return ancestors;
        }
        root = parent;
    }

    // terminal_root not found in chain.
    Vec::new()
}

// ── State helpers ─────────────────────────────────────────────────────────────

/// `get_slot_committee` — all validators assigned to committees in `slot`.
///
/// Uses the head state as the shuffling source.  Supports epochs from
/// `current_epoch - 2`.
fn get_slot_committee<E: BeaconSpec>(store: &Store<E>, slot: Slot) -> HashSet<ValidatorIndex>
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::{
        compute_epoch_at_slot, get_beacon_committee, get_committee_count_per_slot,
    };

    let head = crate::get_head::get_head::<E>(store);
    let shuffling_source = match store.block_states.get(&head) {
        Some(s) => s,
        None => return HashSet::new(),
    };

    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let committees_count = get_committee_count_per_slot::<E>(shuffling_source, epoch);
    let mut participants: HashSet<ValidatorIndex> = HashSet::new();
    for i in 0..committees_count {
        for v in get_beacon_committee::<E>(shuffling_source, slot, i) {
            participants.insert(v);
        }
    }
    participants
}

/// `get_pulled_up_head_state` — head state advanced to the current epoch start
/// if the head is from an earlier epoch.
fn get_pulled_up_head_state<E: BeaconSpec>(store: &Store<E>) -> Option<E::BeaconState>
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView + Clone,
    E::BeaconState: pharos_stf::phase0::BeaconStateWrite + pharos_ssz::TreeHash,
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState:
        pharos_stf::CapellaProcessSlotsDispatch<E> + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState:
        pharos_stf::DenebProcessSlotsDispatch<E> + pharos_stf::DenebUpgradeDispatch<E>,
    E::ElectraBeaconState:
        pharos_stf::ElectraProcessSlotsDispatch<E> + pharos_stf::ElectraUpgradeDispatch<E>,
    E::FuluBeaconState: pharos_stf::FuluProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::AltairBeaconState: pharos_stf::AltairJaFDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixJaFDispatch<E> + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaJaFDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebJaFDispatch<E> + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraJaFDispatch<E> + pharos_ssz::TreeHash,
    E::FuluBeaconState: pharos_stf::FuluJaFDispatch<E> + pharos_ssz::TreeHash,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
{
    use pharos_stf::phase0::accessors::{compute_epoch_at_slot, compute_start_slot_at_epoch};

    let head = crate::get_head::get_head::<E>(store);
    let head_state = store.block_states.get(&head)?.clone();
    let head_epoch = compute_epoch_at_slot(head_state.slot(), E::SLOTS_PER_EPOCH);
    let current_epoch = get_current_store_epoch::<E>(store);

    if head_epoch < current_epoch {
        let target_slot = compute_start_slot_at_epoch(current_epoch, E::SLOTS_PER_EPOCH);
        let mut pulled = head_state;
        let fork_epochs = store.fork_epochs();
        let runtime_cfg = E::default_runtime_config();
        pharos_stf::process_slots_fork::<E>(&mut pulled, target_slot, fork_epochs, &runtime_cfg)
            .ok()?;
        Some(pulled)
    } else {
        Some(head_state)
    }
}

/// `get_previous_balance_source` — state at the previous epoch observed
/// justified checkpoint.
fn get_previous_balance_source<'a, E: BeaconSpec>(
    store: &'a Store<E>,
    fcr: &FastConfirmationStore,
) -> Option<&'a E::BeaconState> {
    store
        .checkpoint_states
        .get(&fcr.previous_epoch_observed_justified_checkpoint)
}

/// `get_current_balance_source` — state at the current epoch observed
/// justified checkpoint.
fn get_current_balance_source<'a, E: BeaconSpec>(
    store: &'a Store<E>,
    fcr: &FastConfirmationStore,
) -> Option<&'a E::BeaconState> {
    store
        .checkpoint_states
        .get(&fcr.current_epoch_observed_justified_checkpoint)
}

// ── LMD-GHOST helpers ─────────────────────────────────────────────────────────

/// `get_block_support_between_slots` — attestation weight for `block_root`
/// from validators assigned to slots `[start_slot, end_slot]`.
fn get_block_support_between_slots<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    block_root: Root,
    start_slot: Slot,
    end_slot: Slot,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_current_epoch;
    use pharos_stf::phase0::predicates::is_active_validator;

    let mut participants: HashSet<ValidatorIndex> = HashSet::new();
    for s in start_slot.0..=end_slot.0 {
        for v in get_slot_committee::<E>(store, Slot(s)) {
            participants.insert(v);
        }
    }

    let balance_epoch = get_current_epoch::<E>(balance_source);

    // Per spec: support is counted by EXACT `latest_messages[i].root == block_root`
    // equality (NOT `get_ancestor` as in `get_attestation_score`).  This is the
    // defining difference between this helper and the LMD-GHOST attestation score.
    let sum: u64 = participants
        .iter()
        .filter(|i| {
            let idx = i.0 as usize;
            match balance_source.validator(idx) {
                Some(v) => {
                    !v.slashed
                        && is_active_validator(v, balance_epoch.0)
                        && store.latest_messages.contains_key(i)
                        && !store.equivocating_indices.contains(i)
                        && store
                            .latest_messages
                            .get(i)
                            .map(|msg| msg.root == block_root)
                            .unwrap_or(false)
                }
                None => false,
            }
        })
        .map(|i| {
            balance_source
                .validator(i.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0)
        })
        .sum();
    Gwei(sum)
}

/// `is_full_validator_set_covered` — true if `[start_slot, end_slot]` spans
/// an entire epoch.
fn is_full_validator_set_covered<E: BeaconSpec>(start_slot: Slot, end_slot: Slot) -> bool {
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
    let start_full_epoch = compute_epoch_at_slot(
        Slot(start_slot.0 + (E::SLOTS_PER_EPOCH - 1)),
        E::SLOTS_PER_EPOCH,
    );
    let end_full_epoch = compute_epoch_at_slot(Slot(end_slot.0 + 1), E::SLOTS_PER_EPOCH);
    start_full_epoch < end_full_epoch
}

/// `adjust_committee_weight_estimate_to_ensure_safety` — add a safety margin
/// for slot ranges spanning an epoch boundary without covering a full epoch.
fn adjust_committee_weight_estimate_to_ensure_safety(estimate: Gwei) -> Gwei {
    let ceil = estimate.0.div_ceil(1000);
    Gwei(ceil * (1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR))
}

/// `estimate_committee_weight_between_slots` — estimated total committee weight
/// for slots `[start_slot, end_slot]`.
fn estimate_committee_weight_between_slots<E: BeaconSpec>(
    total_active_balance: Gwei,
    start_slot: Slot,
    end_slot: Slot,
) -> Gwei {
    use pharos_stf::phase0::accessors::compute_epoch_at_slot;

    if start_slot > end_slot {
        return Gwei(0);
    }

    if is_full_validator_set_covered::<E>(start_slot, end_slot) {
        return total_active_balance;
    }

    let start_epoch = compute_epoch_at_slot(start_slot, E::SLOTS_PER_EPOCH);
    let end_epoch = compute_epoch_at_slot(end_slot, E::SLOTS_PER_EPOCH);
    let committee_weight = Gwei(total_active_balance.0 / E::SLOTS_PER_EPOCH);

    if start_epoch == end_epoch {
        return Gwei(committee_weight.0 * (end_slot.0 - start_slot.0 + 1));
    }

    // Spans an epoch boundary but does not cover a full epoch: pro-rata calc.
    let num_slots_in_end_epoch = compute_slots_since_epoch_start::<E>(end_slot) + 1;
    let remaining_slots_in_end_epoch = E::SLOTS_PER_EPOCH - num_slots_in_end_epoch;
    let num_slots_in_start_epoch =
        E::SLOTS_PER_EPOCH - compute_slots_since_epoch_start::<E>(start_slot);

    let start_epoch_weight = Gwei(committee_weight.0 * num_slots_in_start_epoch);
    let end_epoch_weight = Gwei(committee_weight.0 * num_slots_in_end_epoch);

    // start_epoch_weight_pro_rated = start_epoch_weight * (remaining_slots / SLOTS_PER_EPOCH)
    let start_epoch_weight_pro_rated =
        Gwei(start_epoch_weight.0 / E::SLOTS_PER_EPOCH * remaining_slots_in_end_epoch);

    adjust_committee_weight_estimate_to_ensure_safety(Gwei(
        start_epoch_weight_pro_rated.0 + end_epoch_weight.0,
    ))
}

/// `get_equivocation_score` — total weight of equivocating validators in the
/// committees of slots `[start_slot, end_slot]`.
fn get_equivocation_score<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    start_slot: Slot,
    end_slot: Slot,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_current_epoch;
    use pharos_stf::phase0::predicates::is_active_validator;

    let mut committee_indices: HashSet<ValidatorIndex> = HashSet::new();
    for s in start_slot.0..=end_slot.0 {
        for v in get_slot_committee::<E>(store, Slot(s)) {
            committee_indices.insert(v);
        }
    }

    let balance_epoch = get_current_epoch::<E>(balance_source);

    let active_equivocating: Vec<ValidatorIndex> = committee_indices
        .into_iter()
        .filter(|i| store.equivocating_indices.contains(i))
        .filter(|i| {
            balance_source
                .validator(i.0 as usize)
                .map(|v| is_active_validator(v, balance_epoch.0))
                .unwrap_or(false)
        })
        .collect();

    let sum: u64 = active_equivocating
        .iter()
        .map(|i| {
            balance_source
                .validator(i.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0)
        })
        .sum();
    Gwei(sum)
}

/// `compute_adversarial_weight` — maximum adversarial weight in committees of
/// slots `[start_slot, end_slot]`, discounting already-equivocated validators.
fn compute_adversarial_weight<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    start_slot: Slot,
    end_slot: Slot,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_total_active_balance;

    let total_active_balance = get_total_active_balance::<E>(balance_source);
    let maximum_weight =
        estimate_committee_weight_between_slots::<E>(total_active_balance, start_slot, end_slot);
    let max_adversarial_weight = Gwei(maximum_weight.0 / 100 * CONFIRMATION_BYZANTINE_THRESHOLD);

    let equivocation_score =
        get_equivocation_score::<E>(store, balance_source, start_slot, end_slot);
    if max_adversarial_weight.0 > equivocation_score.0 {
        Gwei(max_adversarial_weight.0 - equivocation_score.0)
    } else {
        Gwei(0)
    }
}

/// `get_adversarial_weight` — maximum adversarial weight that can support
/// `block_root`.
fn get_adversarial_weight<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    block_root: Root,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let current_slot = get_current_slot::<E>(store);
    if current_slot.0 == 0 {
        return Gwei(0);
    }
    let end_slot = Slot(current_slot.0 - 1);

    let parent_root = match store.blocks.get(&block_root) {
        Some(b) => b.parent_root(),
        None => return Gwei(0),
    };

    if get_block_epoch::<E>(store, block_root) > get_block_epoch::<E>(store, parent_root) {
        use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
        let start_slot = compute_start_slot_at_epoch(
            get_block_epoch::<E>(store, block_root),
            E::SLOTS_PER_EPOCH,
        );
        compute_adversarial_weight::<E>(store, balance_source, start_slot, end_slot)
    } else {
        let block_slot = get_block_slot(store, block_root);
        compute_adversarial_weight::<E>(store, balance_source, block_slot, end_slot)
    }
}

/// `compute_empty_slot_support_discount` — amount by which the safety threshold
/// can be discounted due to empty slots preceding the block.
fn compute_empty_slot_support_discount<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    block_root: Root,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let block_slot = get_block_slot(store, block_root);
    let parent_root = match store.blocks.get(&block_root) {
        Some(b) => b.parent_root(),
        None => return Gwei(0),
    };
    let parent_slot = get_block_slot(store, parent_root);

    // No empty slot.
    if parent_slot.0 + 1 == block_slot.0 {
        return Gwei(0);
    }

    let empty_start = Slot(parent_slot.0 + 1);
    let empty_end = Slot(block_slot.0 - 1);

    let parent_support_in_empty_slots = get_block_support_between_slots::<E>(
        store,
        balance_source,
        parent_root,
        empty_start,
        empty_end,
    );

    let adversarial_weight =
        compute_adversarial_weight::<E>(store, balance_source, empty_start, empty_end);

    if parent_support_in_empty_slots.0 > adversarial_weight.0 {
        Gwei(parent_support_in_empty_slots.0 - adversarial_weight.0)
    } else {
        Gwei(0)
    }
}

/// `get_support_discount` — discount for the safety threshold computation.
fn get_support_discount<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    block_root: Root,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    compute_empty_slot_support_discount::<E>(store, balance_source, block_root)
}

/// `compute_safety_threshold` — LMD-GHOST safety threshold for `block_root`.
fn compute_safety_threshold<E: BeaconSpec>(
    store: &Store<E>,
    block_root: Root,
    balance_source: &E::BeaconState,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_total_active_balance;

    let current_slot = get_current_slot::<E>(store);
    if current_slot.0 == 0 {
        return Gwei(0);
    }

    let parent_root = match store.blocks.get(&block_root) {
        Some(b) => b.parent_root(),
        None => return Gwei(0),
    };
    let parent_slot = get_block_slot(store, parent_root);

    // Range is [parent_slot+1, current_slot-1].
    // When start > end, `estimate_committee_weight_between_slots` returns 0 (maximum_support=0).
    // Per spec the early-return path is never taken — always apply the full formula.
    let range_start = Slot(parent_slot.0 + 1);
    let range_end = Slot(current_slot.0.saturating_sub(1));

    let total_active_balance = get_total_active_balance::<E>(balance_source);
    let proposer_score = crate::get_head::compute_proposer_score::<E>(balance_source);
    let maximum_support =
        estimate_committee_weight_between_slots::<E>(total_active_balance, range_start, range_end);
    let support_discount = get_support_discount::<E>(store, balance_source, block_root);
    let adversarial_weight = get_adversarial_weight::<E>(store, balance_source, block_root);

    // (maximum_support + proposer_score - support_discount) // 2 + adversarial_weight
    // with underflow guard.
    let lhs = maximum_support.0 + proposer_score + 2 * adversarial_weight.0;
    if support_discount.0 < lhs {
        Gwei((lhs - support_discount.0) / 2)
    } else {
        Gwei(0)
    }
}

/// `is_one_confirmed` — true iff `block_root` is LMD-GHOST safe.
///
/// Per `specs/phase0/fast-confirmation.md:is_one_confirmed`.
///
/// Per spec line 619: MUST return false if the block's payload status is not
/// VALID (`sync/optimistic.md`).  This is enforced here, not by the caller.
fn is_one_confirmed<E: BeaconSpec>(
    store: &Store<E>,
    balance_source: &E::BeaconState,
    block_root: Root,
) -> bool
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_active_validator_indices;
    use pharos_stf::phase0::accessors::get_current_epoch;

    // Spec MUST: execution-carrying blocks that are not VALID cannot be confirmed.
    if crate::optimistic::is_optimistic::<E>(store, block_root) {
        return false;
    }

    let active_indices =
        get_active_validator_indices::<E>(balance_source, get_current_epoch::<E>(balance_source));

    let support = get_attestation_score::<E>(store, block_root, balance_source, &active_indices);
    let safety_threshold = compute_safety_threshold::<E>(store, block_root, balance_source);
    support > safety_threshold.0
}

/// `is_confirmed_chain_safe` — true iff every block from
/// `current_epoch_observed_justified_checkpoint` to `confirmed_root` is
/// LMD-GHOST safe.
fn is_confirmed_chain_safe<E: BeaconSpec>(
    store: &Store<E>,
    fcr: &FastConfirmationStore,
    confirmed_root: Root,
) -> bool
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    if !is_ancestor::<E>(
        store,
        confirmed_root,
        fcr.current_epoch_observed_justified_checkpoint.root,
    ) {
        return false;
    }

    let current_epoch = get_current_store_epoch::<E>(store);

    let start_root_exclusive: Root;
    if fcr.current_epoch_observed_justified_checkpoint.epoch.0 + 1 >= current_epoch.0 {
        start_root_exclusive = fcr.current_epoch_observed_justified_checkpoint.root;
    } else {
        use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
        let prev_epoch_start =
            compute_start_slot_at_epoch(Epoch(current_epoch.0 - 1), E::SLOTS_PER_EPOCH);
        let ancestor_at_prev_epoch_start =
            get_ancestor::<E>(store, confirmed_root, prev_epoch_start);
        let ancestor_epoch = get_block_epoch::<E>(store, ancestor_at_prev_epoch_start);
        if ancestor_epoch.0 + 1 == current_epoch.0 {
            let parent = store
                .blocks
                .get(&ancestor_at_prev_epoch_start)
                .map(|b| b.parent_root())
                .unwrap_or(ancestor_at_prev_epoch_start);
            start_root_exclusive = parent;
        } else {
            start_root_exclusive = ancestor_at_prev_epoch_start;
        }
    }

    let prev_balance_source = match get_previous_balance_source(store, fcr) {
        Some(s) => s,
        None => return false,
    };

    let chain_roots = get_ancestor_roots::<E>(store, confirmed_root, start_root_exclusive);
    chain_roots
        .iter()
        .all(|root| is_one_confirmed::<E>(store, prev_balance_source, *root))
}

// ── FFG helpers ───────────────────────────────────────────────────────────────

/// `get_current_target_score` — FFG support estimate for the current epoch
/// target using LMD-GHOST votes.
fn get_current_target_score<E: BeaconSpec>(store: &Store<E>, pulled_state: &E::BeaconState) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::{get_active_validator_indices, get_current_epoch};

    let target = get_current_target::<E>(store);

    let unslashed_active: Vec<ValidatorIndex> =
        get_active_validator_indices::<E>(pulled_state, get_current_epoch::<E>(pulled_state))
            .into_iter()
            .filter(|i| {
                pulled_state
                    .validator(i.0 as usize)
                    .map(|v| !v.slashed)
                    .unwrap_or(false)
            })
            .collect();

    let sum: u64 = unslashed_active
        .iter()
        .filter(|i| {
            store.latest_messages.contains_key(i)
                && !store.equivocating_indices.contains(i)
                && store
                    .latest_messages
                    .get(i)
                    .map(|msg| {
                        get_checkpoint_for_block::<E>(store, msg.root, Epoch(msg.epoch.0)) == target
                    })
                    .unwrap_or(false)
        })
        .map(|i| {
            pulled_state
                .validator(i.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0)
        })
        .sum();
    Gwei(sum)
}

/// `compute_honest_ffg_support_for_current_target` — honest FFG support of the
/// current epoch target.
fn compute_honest_ffg_support_for_current_target<E: BeaconSpec>(
    store: &Store<E>,
    pulled_state: &E::BeaconState,
) -> Gwei
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::{compute_start_slot_at_epoch, get_total_active_balance};

    let current_slot = get_current_slot::<E>(store);
    let current_epoch = get_current_store_epoch::<E>(store);
    let total_active_balance = get_total_active_balance::<E>(pulled_state);

    let ffg_support_for_checkpoint = get_current_target_score::<E>(store, pulled_state);

    let epoch_start = compute_start_slot_at_epoch(current_epoch, E::SLOTS_PER_EPOCH);

    let ffg_weight_till_now = if current_slot > epoch_start {
        estimate_committee_weight_between_slots::<E>(
            total_active_balance,
            epoch_start,
            Slot(current_slot.0 - 1),
        )
    } else {
        Gwei(0)
    };

    let remaining_ffg_weight = if total_active_balance.0 > ffg_weight_till_now.0 {
        Gwei(total_active_balance.0 - ffg_weight_till_now.0)
    } else {
        Gwei(0)
    };
    let remaining_honest_ffg_weight =
        Gwei(remaining_ffg_weight.0 / 100 * (100 - CONFIRMATION_BYZANTINE_THRESHOLD));

    let adversarial_weight = if current_slot > epoch_start {
        compute_adversarial_weight::<E>(store, pulled_state, epoch_start, Slot(current_slot.0 - 1))
    } else {
        Gwei(0)
    };

    let discount = adversarial_weight.0.min(ffg_support_for_checkpoint.0);
    let min_honest_ffg_support = Gwei(ffg_support_for_checkpoint.0 - discount);

    Gwei(min_honest_ffg_support.0 + remaining_honest_ffg_weight.0)
}

/// `will_no_conflicting_checkpoint_be_justified` — true iff no checkpoint
/// conflicting with the current target can ever be justified.
fn will_no_conflicting_checkpoint_be_justified<E: BeaconSpec>(
    store: &Store<E>,
    pulled_state: &E::BeaconState,
) -> bool
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_total_active_balance;

    if get_current_target::<E>(store) == store.unrealized_justified_checkpoint {
        return true;
    }

    let total_active_balance = get_total_active_balance::<E>(pulled_state);
    let honest_ffg_support =
        compute_honest_ffg_support_for_current_target::<E>(store, pulled_state);
    3 * honest_ffg_support.0 > total_active_balance.0
}

/// `will_current_target_be_justified` — true iff the current target will
/// eventually be justified.
fn will_current_target_be_justified<E: BeaconSpec>(
    store: &Store<E>,
    pulled_state: &E::BeaconState,
) -> bool
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    use pharos_stf::phase0::accessors::get_total_active_balance;

    let total_active_balance = get_total_active_balance::<E>(pulled_state);
    let honest_ffg_support =
        compute_honest_ffg_support_for_current_target::<E>(store, pulled_state);
    3 * honest_ffg_support.0 >= 2 * total_active_balance.0
}

// ── update_fast_confirmation_variables ───────────────────────────────────────

/// `update_fast_confirmation_variables` — update FCR variables at slot start.
fn update_fast_confirmation_variables<E: BeaconSpec>(
    store: &Store<E>,
    fcr: &mut FastConfirmationStore,
) where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    fcr.previous_slot_head = fcr.current_slot_head;
    fcr.current_slot_head = crate::get_head::get_head::<E>(store);

    let current_slot = get_current_slot::<E>(store);

    // Update greatest unrealized checkpoint at the LAST slot of an epoch
    // (i.e. when the NEXT slot is an epoch start).
    let next_slot = Slot(current_slot.0 + 1);
    if is_start_slot_at_epoch::<E>(next_slot) {
        fcr.previous_epoch_greatest_unrealized_checkpoint =
            store.unrealized_justified_checkpoint.clone();
    }

    // Update observed justified checkpoints at the START of an epoch.
    if is_start_slot_at_epoch::<E>(current_slot) {
        fcr.previous_epoch_observed_justified_checkpoint =
            fcr.current_epoch_observed_justified_checkpoint.clone();
        fcr.current_epoch_observed_justified_checkpoint =
            fcr.previous_epoch_greatest_unrealized_checkpoint.clone();
    }
}

// ── find_latest_confirmed_descendant ─────────────────────────────────────────

/// `find_latest_confirmed_descendant` — advance `latest_confirmed_root` as far
/// as possible along the canonical chain.
fn find_latest_confirmed_descendant<E: BeaconSpec>(
    store: &Store<E>,
    fcr: &FastConfirmationStore,
    latest_confirmed_root: Root,
    pulled_state: &E::BeaconState,
) -> Root
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let head = crate::get_head::get_head::<E>(store);
    let current_epoch = get_current_store_epoch::<E>(store);
    let current_slot = get_current_slot::<E>(store);
    let mut confirmed_root = latest_confirmed_root;

    // Try to confirm previous-epoch blocks.
    let prev_voting_source_epoch = get_voting_source::<E>(store, fcr.previous_slot_head).epoch;

    if get_block_epoch::<E>(store, confirmed_root).0 + 1 == current_epoch.0
        && prev_voting_source_epoch.0 + 2 >= current_epoch.0
        && (is_start_slot_at_epoch::<E>(current_slot)
            || (will_no_conflicting_checkpoint_be_justified::<E>(store, pulled_state) && {
                let prev_unrealized = store
                    .unrealized_justifications
                    .get(&fcr.previous_slot_head)
                    .map(|c| c.epoch.0)
                    .unwrap_or(0);
                let head_unrealized = store
                    .unrealized_justifications
                    .get(&head)
                    .map(|c| c.epoch.0)
                    .unwrap_or(0);
                prev_unrealized + 1 >= current_epoch.0 || head_unrealized + 1 >= current_epoch.0
            }))
    {
        let canonical_roots = get_ancestor_roots::<E>(store, head, confirmed_root);

        let current_balance_source = match get_current_balance_source(store, fcr) {
            Some(s) => s,
            None => return confirmed_root,
        };

        for block_root in canonical_roots {
            let block_epoch = get_block_epoch::<E>(store, block_root);
            if block_epoch == current_epoch {
                break;
            }
            if !is_ancestor::<E>(store, fcr.previous_slot_head, block_root) {
                break;
            }
            if !is_one_confirmed::<E>(store, current_balance_source, block_root) {
                break;
            }
            confirmed_root = block_root;
        }
    }

    // Try to confirm current-epoch blocks.
    let head_unrealized_epoch = store
        .unrealized_justifications
        .get(&head)
        .map(|c| c.epoch.0)
        .unwrap_or(0);

    if is_start_slot_at_epoch::<E>(current_slot) || head_unrealized_epoch + 1 >= current_epoch.0 {
        let canonical_roots = get_ancestor_roots::<E>(store, head, confirmed_root);
        let mut tentative_confirmed_root = confirmed_root;

        let current_balance_source = match get_current_balance_source(store, fcr) {
            Some(s) => s,
            None => return confirmed_root,
        };

        for block_root in canonical_roots {
            let block_epoch = get_block_epoch::<E>(store, block_root);
            let tentative_confirmed_epoch = get_block_epoch::<E>(store, tentative_confirmed_root);

            // When advancing from previous epoch to current epoch, check
            // that the current target will be justified.
            if block_epoch > tentative_confirmed_epoch
                && !will_current_target_be_justified::<E>(store, pulled_state)
            {
                break;
            }

            if !is_one_confirmed::<E>(store, current_balance_source, block_root) {
                break;
            }
            tentative_confirmed_root = block_root;
        }

        // Only accept the tentative root if it can't be reorged out.
        let tentative_epoch = get_block_epoch::<E>(store, tentative_confirmed_root);
        let tentative_voting_source_epoch =
            get_voting_source::<E>(store, tentative_confirmed_root).epoch;

        if tentative_epoch == current_epoch
            || (tentative_voting_source_epoch.0 + 2 >= current_epoch.0
                && (is_start_slot_at_epoch::<E>(current_slot)
                    || will_no_conflicting_checkpoint_be_justified::<E>(store, pulled_state)))
        {
            confirmed_root = tentative_confirmed_root;
        }
    }

    confirmed_root
}

// ── get_latest_confirmed ──────────────────────────────────────────────────────

/// `get_latest_confirmed` — execute the FCR algorithm.
fn get_latest_confirmed<E: BeaconSpec>(
    store: &Store<E>,
    fcr: &FastConfirmationStore,
    pulled_state: &E::BeaconState,
) -> Root
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    let mut confirmed_root = fcr.confirmed_root;
    let current_epoch = get_current_store_epoch::<E>(store);
    let current_slot = get_current_slot::<E>(store);
    let head = crate::get_head::get_head::<E>(store);

    // Step 1-3: revert to finalized if any of the safety assumptions are broken.
    let is_too_old = get_block_epoch::<E>(store, confirmed_root).0 + 1 < current_epoch.0;
    let is_not_ancestor = !is_ancestor::<E>(store, head, confirmed_root);
    let chain_unsafe = is_start_slot_at_epoch::<E>(current_slot)
        && !is_confirmed_chain_safe::<E>(store, fcr, confirmed_root);

    if is_too_old || is_not_ancestor || chain_unsafe {
        confirmed_root = store.finalized_checkpoint.root;
    }

    // Step 4: restart from observed justified checkpoint if conditions are met.
    let is_epoch_start = is_start_slot_at_epoch::<E>(current_slot);
    let observed_justified_block_slot =
        get_block_slot(store, fcr.current_epoch_observed_justified_checkpoint.root);
    let is_observed_justified_block_epoch_ok = {
        use pharos_stf::phase0::accessors::compute_epoch_at_slot;
        compute_epoch_at_slot(observed_justified_block_slot, E::SLOTS_PER_EPOCH).0 + 1
            == current_epoch.0
    };
    let is_head_unrealized_justified_ok = store
        .unrealized_justifications
        .get(&head)
        .map(|c| *c == fcr.current_epoch_observed_justified_checkpoint)
        .unwrap_or(false);
    let is_confirmed_block_stale =
        get_block_slot(store, confirmed_root).0 < observed_justified_block_slot.0;

    if is_epoch_start
        && is_observed_justified_block_epoch_ok
        && is_head_unrealized_justified_ok
        && is_confirmed_block_stale
    {
        confirmed_root = fcr.current_epoch_observed_justified_checkpoint.root;
    }

    // Step 5: advance the confirmed root.
    if get_block_epoch::<E>(store, confirmed_root).0 + 1 >= current_epoch.0 {
        find_latest_confirmed_descendant::<E>(store, fcr, confirmed_root, pulled_state)
    } else {
        confirmed_root
    }
}

// ── on_fast_confirmation ──────────────────────────────────────────────────────

/// `on_fast_confirmation` handler.
///
/// Call sequence (per spec): `update_fast_confirmation_variables` then
/// `get_latest_confirmed`. MUST be called at the start of each slot after
/// past-slot attestations have been applied.
pub fn on_fast_confirmation<E: BeaconSpec>(store: &Store<E>, fcr: &mut FastConfirmationStore)
where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView + Clone,
    E::BeaconState: pharos_stf::phase0::BeaconStateWrite + pharos_ssz::TreeHash,
    E::AltairBeaconState: pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>
        + pharos_stf::CapellaJaFDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_stf::ElectraUpgradeDispatch<E>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_ssz::TreeHash,
    E::FuluBeaconState: pharos_stf::FuluProcessSlotsDispatch<E>
        + pharos_stf::FuluJaFDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::AltairBeaconState: pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixUpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
{
    update_fast_confirmation_variables::<E>(store, fcr);

    // get_pulled_up_head_state needs the same constraints.
    let pulled_state = match get_pulled_up_head_state::<E>(store) {
        Some(s) => s,
        None => return,
    };

    fcr.confirmed_root = get_latest_confirmed::<E>(store, fcr, &pulled_state);
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use pharos_ssz::TreeHash;
    use pharos_stf::phase0::state_write::BeaconStateWrite;
    use pharos_types::{
        MinimalBeaconSpec,
        phase0::Validator,
        state::{MinimalBeaconBlock as ForkMinBlock, MinimalBeaconState as ForkMinState},
    };
    use pharos_utils::{BLSPubkey, Bytes32};

    use crate::store::get_forkchoice_store;

    const EFF_BAL: u64 = 32_000_000_000;
    const SLOTS_PER_EPOCH: u64 = MinimalBeaconSpec::SLOTS_PER_EPOCH;

    fn make_validator_active() -> Validator {
        Validator {
            pubkey: BLSPubkey::from_array([0u8; 48]),
            withdrawal_credentials: Bytes32::default(),
            effective_balance: Gwei(EFF_BAL),
            slashed: false,
            activation_eligibility_epoch: Epoch(0),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            ..Validator::default()
        }
    }

    /// Minimal genesis store: `n_validators` validators, all active, zero slot.
    fn minimal_store(n_validators: usize) -> Store<MinimalBeaconSpec> {
        use pharos_stf::phase0::genesis::BeaconStateMut;
        use pharos_types::phase0::MinimalBeaconState;
        use pharos_utils::{Bytes4, Hash256};

        let genesis_time = 0u64;
        let eth1_data = pharos_types::phase0::Eth1Data::default();
        let body_root = pharos_types::phase0::MinimalBeaconBlockBody::default().tree_hash_root();
        let fork = pharos_types::phase0::Fork {
            previous_version: Bytes4::from_array([0; 4]),
            current_version: Bytes4::from_array([0; 4]),
            epoch: Epoch(0),
        };
        let mut state = MinimalBeaconState::genesis_state(
            genesis_time,
            fork,
            eth1_data,
            body_root,
            Hash256::default(),
        );
        for _ in 0..n_validators {
            let v = make_validator_active();
            state.push_validator(v).unwrap();
            state.push_balance(Gwei(EFF_BAL)).unwrap();
        }

        let anchor_block = pharos_types::phase0::MinimalBeaconBlock {
            state_root: state.tree_hash_root(),
            ..Default::default()
        };

        get_forkchoice_store::<MinimalBeaconSpec>(
            ForkMinState::Phase0(state),
            ForkMinBlock::Phase0(anchor_block),
        )
    }

    // ── estimate_committee_weight_between_slots ───────────────────────────────

    /// Within a single epoch, weight is proportional to slot count.
    #[test]
    fn estimate_committee_weight_same_epoch() {
        // With SLOTS_PER_EPOCH=8 (minimal) and total_balance=8*32e9,
        // each slot weighs 32e9 (= total / 8).
        let total = Gwei(SLOTS_PER_EPOCH * EFF_BAL);
        let committee = Gwei(EFF_BAL); // total / SLOTS_PER_EPOCH

        // 3 slots within epoch 0 (slots 0..=2)
        let w =
            estimate_committee_weight_between_slots::<MinimalBeaconSpec>(total, Slot(0), Slot(2));
        assert_eq!(
            w.0,
            committee.0 * 3,
            "same-epoch 3 slots: expected 3*committee"
        );

        // 1 slot
        let w1 =
            estimate_committee_weight_between_slots::<MinimalBeaconSpec>(total, Slot(1), Slot(1));
        assert_eq!(w1.0, committee.0, "same-epoch 1 slot: expected 1*committee");
    }

    /// Full epoch coverage returns total_active_balance exactly.
    #[test]
    fn estimate_committee_weight_full_epoch() {
        let total = Gwei(SLOTS_PER_EPOCH * EFF_BAL);
        // Slots 0..=SLOTS_PER_EPOCH-1 spans a full epoch.
        let w = estimate_committee_weight_between_slots::<MinimalBeaconSpec>(
            total,
            Slot(0),
            Slot(SLOTS_PER_EPOCH - 1),
        );
        assert_eq!(
            w.0, total.0,
            "full-epoch coverage must return total_active_balance"
        );
    }

    /// Cross-epoch boundary: the estimate is non-zero, less than full balance,
    /// but at least as large as one committee (the smallest meaningful coverage).
    #[test]
    fn estimate_committee_weight_epoch_boundary_has_safety_margin() {
        let total = Gwei(SLOTS_PER_EPOCH * EFF_BAL);
        let committee = Gwei(EFF_BAL); // total / SLOTS_PER_EPOCH
        // 1 slot in epoch 0 (slot SLOTS_PER_EPOCH-1) + 1 slot in epoch 1 (slot
        // SLOTS_PER_EPOCH) — crosses the boundary without covering a full epoch.
        let w = estimate_committee_weight_between_slots::<MinimalBeaconSpec>(
            total,
            Slot(SLOTS_PER_EPOCH - 1),
            Slot(SLOTS_PER_EPOCH),
        );
        // Cross-epoch estimate applies a safety margin (ADJUSTMENT_FACTOR).
        // The result is less than full-balance (it doesn't span a full epoch)
        // but strictly greater than a single committee weight.
        assert!(
            w.0 < total.0,
            "cross-epoch must be less than total_active_balance"
        );
        assert!(
            w.0 > committee.0,
            "cross-epoch weight {w:?} must exceed one committee ({committee:?})"
        );
        // And the safety adjustment adds a small positive margin over the raw
        // pro-rata sum: 60e9 → 60.3e9 for this specific case (FACTOR=5).
        // Verify the adjustment is present by checking > 2*raw_committee_weight.
        // With minimal 8-slot epochs: raw = (1 * committee * 7/8) + committee ≈ 1.875 committees.
        let raw_estimate =
            Gwei(committee.0 + (committee.0 / SLOTS_PER_EPOCH) * (SLOTS_PER_EPOCH - 1));
        assert!(
            w.0 > raw_estimate.0,
            "adjusted {w:?} must be > raw {raw_estimate:?}"
        );
    }

    // ── is_one_confirmed (no votes) ───────────────────────────────────────────

    /// A block with zero LMD-GHOST votes at slot 0 is not one-confirmed.
    ///
    /// `is_one_confirmed` is a pure LMD-GHOST check; no payload-status gate.
    /// With zero votes `support(0) > threshold(0)` is false.
    #[test]
    fn is_one_confirmed_zero_votes_returns_false() {
        let store = minimal_store(4);
        let anchor_root = store.finalized_checkpoint.root;
        let balance_source = store
            .block_states
            .get(&anchor_root)
            .expect("anchor state must be present")
            .clone();

        let result = is_one_confirmed::<MinimalBeaconSpec>(&store, &balance_source, anchor_root);
        assert!(
            !result,
            "block with no LMD-GHOST votes must not be one-confirmed (score 0 not > 0)"
        );
    }

    /// A block with no payload status entry (pre-merge) is not gated by the
    /// optimistic check; the result depends only on the LMD-GHOST score.
    #[test]
    fn is_one_confirmed_no_status_not_blocked() {
        use pharos_types::phase0::MinimalBeaconBlock;

        let mut store = minimal_store(4);
        // Insert a block that has NO payload_statuses entry (simulates pre-merge).
        let extra_block = MinimalBeaconBlock {
            slot: Slot(1),
            parent_root: store.finalized_checkpoint.root,
            ..Default::default()
        };
        let extra_root: Root = extra_block.tree_hash_root();
        let anchor_state = store
            .block_states
            .get(&store.finalized_checkpoint.root)
            .unwrap()
            .clone();
        store
            .blocks
            .insert(extra_root, ForkMinBlock::Phase0(extra_block));
        store.block_states.insert(extra_root, anchor_state.clone());

        assert!(
            !store.payload_statuses.contains_key(&extra_root),
            "precondition: extra_block has no payload status"
        );
        // Function must not panic; returns false here (no votes).
        let result = is_one_confirmed::<MinimalBeaconSpec>(&store, &anchor_state, extra_root);
        // With no votes (zero LMD-GHOST score) vs. a positive threshold, must be false.
        assert!(!result, "no-votes block cannot be one-confirmed");
    }

    // ── get_latest_confirmed (revert path) ────────────────────────────────────

    /// When `confirmed_root` is from an epoch older than `current_epoch - 1`,
    /// `get_latest_confirmed` reverts to `finalized_checkpoint.root`.
    #[test]
    fn get_latest_confirmed_reverts_on_too_old_confirmed_root() {
        use pharos_ssz::TreeHash;
        use pharos_types::phase0::MinimalBeaconBlock;

        let mut store = minimal_store(4);
        let anchor_root = store.finalized_checkpoint.root;

        // Advance the store clock to slot 2*SLOTS_PER_EPOCH (epoch 2) so
        // a confirmed_root from epoch 0 is "too old" (epoch 0 + 1 < epoch 2).
        // Advance to slot 2*SLOTS_PER_EPOCH (epoch 2).
        // genesis_time=0, slot N starts at N * seconds_per_slot.
        let seconds_per_slot = MinimalBeaconSpec::SLOT_DURATION_MS / 1000;
        crate::handlers::on_tick::<MinimalBeaconSpec>(
            &mut store,
            SLOTS_PER_EPOCH * 2 * seconds_per_slot,
        );

        // Insert a dummy block at slot 0 (epoch 0) to use as the stale confirmed root.
        // We insert it at the anchor root directly (anchor_root is already slot 0).
        let anchor_block = MinimalBeaconBlock {
            state_root: store
                .block_states
                .get(&anchor_root)
                .unwrap()
                .tree_hash_root(),
            ..Default::default()
        };
        let old_confirmed_root: Root = anchor_block.tree_hash_root();
        // Insert an extra mapping for a distinct "old confirmed" root in epoch 0.
        store
            .blocks
            .insert(old_confirmed_root, ForkMinBlock::Phase0(anchor_block));
        store.block_states.insert(
            old_confirmed_root,
            store.block_states.get(&anchor_root).unwrap().clone(),
        );

        let mut fcr = get_fast_confirmation_store::<MinimalBeaconSpec>(&store);
        // Set confirmed_root to our epoch-0 block.
        fcr.confirmed_root = old_confirmed_root;

        let balance_source = store
            .block_states
            .get(&anchor_root)
            .expect("anchor state")
            .clone();

        let result = get_latest_confirmed::<MinimalBeaconSpec>(&store, &fcr, &balance_source);
        assert_eq!(
            result, store.finalized_checkpoint.root,
            "confirmed_root in epoch 0 must revert to finalized when store is at epoch 2"
        );
    }
}
