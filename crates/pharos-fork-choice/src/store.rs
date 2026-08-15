//! Fork-choice `Store` and `get_forkchoice_store`.
//!
//! Per `specs/phase0/fork-choice.md:149-219`.

use std::collections::{HashMap, HashSet};

use pharos_ssz::TreeHash;
use pharos_types::{
    BeaconStateView, EthSpec,
    phase0::{Checkpoint, Epoch, Root, ValidatorIndex},
    views::BeaconBlockView,
};

use crate::get_head::get_current_slot;

// ── LatestMessage ─────────────────────────────────────────────────────────────

/// Per `specs/phase0/fork-choice.md:141-147`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestMessage {
    /// The target epoch of the attestation that produced this message.
    pub epoch: Epoch,
    /// The beacon block root voted for.
    pub root: Root,
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Fork-choice store.
///
/// Tracks all data needed by the LMD-GHOST + FFG Casper fork-choice algorithm.
///
/// Per `specs/phase0/fork-choice.md:168-185`.
pub struct Store<E: EthSpec> {
    /// Current time in seconds since Unix epoch.
    ///
    /// Per `specs/phase0/fork-choice.md:171`.
    pub time: u64,

    /// Genesis time in seconds since Unix epoch.
    ///
    /// Per `specs/phase0/fork-choice.md:172`.
    pub genesis_time: u64,

    /// The justified checkpoint used as the root for LMD-GHOST.
    ///
    /// Per `specs/phase0/fork-choice.md:173`.
    pub justified_checkpoint: Checkpoint,

    /// The highest known finalized checkpoint.
    ///
    /// Per `specs/phase0/fork-choice.md:174`.
    pub finalized_checkpoint: Checkpoint,

    /// Highest unrealized justified checkpoint (not yet on-chain FFG-processed).
    ///
    /// Per `specs/phase0/fork-choice.md:175`.
    pub unrealized_justified_checkpoint: Checkpoint,

    /// Highest unrealized finalized checkpoint.
    ///
    /// Per `specs/phase0/fork-choice.md:176`.
    pub unrealized_finalized_checkpoint: Checkpoint,

    /// Block root that has received the proposer score boost, or `Root::default()`.
    ///
    /// Per `specs/phase0/fork-choice.md:177`.
    pub proposer_boost_root: Root,

    /// Set of validator indices that have equivocated (double-voted).
    ///
    /// Per `specs/phase0/fork-choice.md:178`.
    pub equivocating_indices: HashSet<ValidatorIndex>,

    /// All known beacon blocks, keyed by their `hash_tree_root`.
    ///
    /// Per `specs/phase0/fork-choice.md:179`.
    pub blocks: HashMap<Root, E::BeaconBlock>,

    /// Post-state for each block in `blocks`.
    ///
    /// Per `specs/phase0/fork-choice.md:180`.
    pub block_states: HashMap<Root, E::BeaconState>,

    /// Whether each block arrived within the attestation deadline (timely).
    ///
    /// Per `specs/phase0/fork-choice.md:181`.
    pub block_timeliness: HashMap<Root, bool>,

    /// Beacon state at the start of each checkpoint epoch.
    ///
    /// Per `specs/phase0/fork-choice.md:182`.
    pub checkpoint_states: HashMap<Checkpoint, E::BeaconState>,

    /// Latest attestation message per validator index.
    ///
    /// Per `specs/phase0/fork-choice.md:183`.
    pub latest_messages: HashMap<ValidatorIndex, LatestMessage>,

    /// Unrealized justified checkpoint per block root.
    ///
    /// Per `specs/phase0/fork-choice.md:184`.
    pub unrealized_justifications: HashMap<Root, Checkpoint>,
}

// ── get_forkchoice_store ──────────────────────────────────────────────────────

/// Build the initial fork-choice store from a trusted anchor state and block.
///
/// Per `specs/phase0/fork-choice.md:187-219`.
///
/// Panics if `anchor_block.state_root != hash_tree_root(anchor_state)`,
/// matching the spec's first assertion.
pub fn get_forkchoice_store<E: EthSpec>(
    anchor_state: E::BeaconState,
    anchor_block: E::BeaconBlock,
) -> Store<E>
where
    E::BeaconBlock: TreeHash + BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView + TreeHash + Clone,
{
    use pharos_stf::phase0::accessors::get_current_epoch;

    assert_eq!(
        anchor_block.state_root(),
        anchor_state.tree_hash_root(),
        "anchor_block.state_root must equal hash_tree_root(anchor_state)"
    );

    let anchor_root: Root = anchor_block.tree_hash_root();
    let anchor_epoch = get_current_epoch::<E>(&anchor_state);

    let justified_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    let finalized_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };

    // time = anchor_state.genesis_time + SLOT_DURATION_MS * anchor_state.slot // 1000
    // Per `specs/phase0/fork-choice.md:207`.
    let time = anchor_state.genesis_time() + E::SLOT_DURATION_MS * anchor_state.slot().0 / 1000;

    let genesis_time = anchor_state.genesis_time();

    let mut blocks = HashMap::new();
    blocks.insert(anchor_root, anchor_block.clone());

    let mut block_states = HashMap::new();
    block_states.insert(anchor_root, anchor_state.clone());

    let mut checkpoint_states = HashMap::new();
    checkpoint_states.insert(justified_checkpoint.clone(), anchor_state.clone());

    let mut unrealized_justifications = HashMap::new();
    unrealized_justifications.insert(anchor_root, justified_checkpoint.clone());

    // Advance the current slot from genesis to anchor_state.slot.
    let store = Store {
        time,
        genesis_time,
        justified_checkpoint: justified_checkpoint.clone(),
        finalized_checkpoint: finalized_checkpoint.clone(),
        unrealized_justified_checkpoint: justified_checkpoint,
        unrealized_finalized_checkpoint: finalized_checkpoint,
        proposer_boost_root: Root::default(),
        equivocating_indices: HashSet::new(),
        blocks,
        block_states,
        block_timeliness: HashMap::new(),
        checkpoint_states,
        latest_messages: HashMap::new(),
        unrealized_justifications,
    };

    // Update the current slot based on the anchor state time.
    // The store's current slot must match after construction.
    let _ = get_current_slot(&store); // validate (panics only on underflow; anchor is trusted)

    store
}
