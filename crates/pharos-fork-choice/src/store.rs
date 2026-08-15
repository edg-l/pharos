//! Fork-choice `Store` and `get_forkchoice_store`.
//!
//! Per `specs/phase0/fork-choice.md:149-219`.

use std::collections::{HashMap, HashSet};

use pharos_ssz::TreeHash;
use pharos_types::{
    BeaconStateView, EthSpec, PayloadStatus,
    config::RuntimeConfig,
    phase0::{Checkpoint, Epoch, Root, ValidatorIndex},
    views::BeaconBlockView,
};
use pharos_utils::{Hash256, Uint256};

use crate::get_head::{get_current_slot, slot_start_time};

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

    /// EL-validated payload status per block root (Bellatrix+).
    ///
    /// Phase0/Altair blocks never populate this map; Bellatrix blocks land
    /// here as `NotValidated` and are updated to `Valid`/`Invalid` by the
    /// engine driver loop (M4a Phase 4). `filter_block_tree` skips any
    /// `Invalid` entry per `specs/bellatrix/fork-choice.md:74-79`.
    pub payload_statuses: HashMap<Root, PayloadStatus>,

    // ── Bellatrix terminal-block constants ────────────────────────────────────
    /// `TERMINAL_TOTAL_DIFFICULTY` per `specs/bellatrix/fork-choice.md`.
    ///
    /// Set from `RuntimeConfig::terminal_total_difficulty` at construction time.
    /// Used by `on_block`'s merge-transition guard (`validate_merge_block`)
    /// without threading `RuntimeConfig` through the fork-choice boundary.
    pub terminal_total_difficulty: Uint256,

    /// `TERMINAL_BLOCK_HASH` per `specs/bellatrix/fork-choice.md`.
    ///
    /// Zero means "use TTD-based mode". Non-zero means "override mode":
    /// the merge-transition block's `parent_hash` must equal this hash and
    /// the current epoch must be ≥ `terminal_block_hash_activation_epoch`.
    pub terminal_block_hash: Hash256,

    /// `TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH` per `specs/bellatrix/fork-choice.md`.
    ///
    /// Only consulted when `terminal_block_hash != zero`.
    pub terminal_block_hash_activation_epoch: u64,

    // ── Fork schedule epochs ──────────────────────────────────────────────────
    /// `ALTAIR_FORK_EPOCH` — epoch at which phase0 upgrades to Altair.
    ///
    /// Defaults to `u64::MAX` (never) in `get_forkchoice_store`. The node sets
    /// the real value via `Store::set_fork_epochs` after construction.
    pub altair_fork_epoch: u64,

    /// `BELLATRIX_FORK_EPOCH` — epoch at which Altair upgrades to Bellatrix.
    ///
    /// Same default/override policy as `altair_fork_epoch`.
    pub bellatrix_fork_epoch: u64,

    /// `CAPELLA_FORK_EPOCH` — epoch at which Bellatrix upgrades to Capella.
    ///
    /// Same default/override policy as `altair_fork_epoch`.
    pub capella_fork_epoch: u64,

    // ── Runtime configuration ─────────────────────────────────────────────────
    /// Full runtime configuration snapshot.
    ///
    /// Stored in the `Store` so that fork-choice handlers can call
    /// `process_slots_fork` (which needs fork versions for the upgrade
    /// dispatch) without threading `RuntimeConfig` through every function.
    /// Defaults to `RuntimeConfig::default()` (mainnet) in `get_forkchoice_store`;
    /// the node assigns the real network config after construction.
    pub runtime_cfg: RuntimeConfig,
}

impl<E: EthSpec> Store<E> {
    /// Record the EL's payload-validation verdict for `root`.
    pub fn mark_payload_status(&mut self, root: Root, status: PayloadStatus) {
        self.payload_statuses.insert(root, status);
    }

    /// Insert `status` for `root` ONLY if no entry exists yet.
    ///
    /// Used at import time to pre-seed `NotValidated` without clobbering a
    /// `Valid` / `Invalid` verdict the async engine driver may have already
    /// written for a block that raced through the newPayload path before the
    /// persist worker ran.
    ///
    /// Invariant (per `D-preseed-notvalidated-on-import`, M8 Phase 1): every
    /// execution-carrying block has a `payload_statuses` entry from import time.
    /// The async engine driver later overwrites with `Valid` or `Invalid`.
    pub fn mark_payload_status_if_absent(&mut self, root: Root, status: PayloadStatus) {
        self.payload_statuses.entry(root).or_insert(status);
    }

    /// Override the Bellatrix terminal-block constants in this store.
    ///
    /// Called at node startup after `get_forkchoice_store` (or
    /// `rehydrate_fork_choice_store`) constructs the store, so that
    /// `on_block`'s merge-transition guard uses the correct network values.
    pub fn set_terminal_config(
        &mut self,
        terminal_total_difficulty: Uint256,
        terminal_block_hash: Hash256,
        terminal_block_hash_activation_epoch: u64,
    ) {
        self.terminal_total_difficulty = terminal_total_difficulty;
        self.terminal_block_hash = terminal_block_hash;
        self.terminal_block_hash_activation_epoch = terminal_block_hash_activation_epoch;
    }

    /// Override the fork epoch schedule in this store.
    ///
    /// Called at node startup to wire real per-network fork epochs into the
    /// store so that `process_slots_fork` triggers live upgrades. Mirrors the
    /// `set_terminal_config` precedent.
    pub fn set_fork_epochs(
        &mut self,
        altair_fork_epoch: u64,
        bellatrix_fork_epoch: u64,
        capella_fork_epoch: u64,
    ) {
        self.altair_fork_epoch = altair_fork_epoch;
        self.bellatrix_fork_epoch = bellatrix_fork_epoch;
        self.capella_fork_epoch = capella_fork_epoch;
    }

    /// Return a `ForkEpochs` snapshot of the current fork epoch schedule.
    ///
    /// Used to thread fork epochs into `process_slots_fork` from fork-choice
    /// handlers without borrowing the full store.
    pub fn fork_epochs(&self) -> pharos_stf::ForkEpochs {
        pharos_stf::ForkEpochs {
            altair: self.altair_fork_epoch,
            bellatrix: self.bellatrix_fork_epoch,
            capella: self.capella_fork_epoch,
        }
    }
}

// ── get_forkchoice_store ──────────────────────────────────────────────────────

/// Build the initial fork-choice store from a trusted anchor state and block.
///
/// Per `specs/phase0/fork-choice.md:187-219`.
///
/// Panics if `anchor_block.state_root != hash_tree_root(anchor_state)`,
/// matching the spec's first assertion.
///
/// Terminal-block constants (`terminal_total_difficulty`, `terminal_block_hash`,
/// `terminal_block_hash_activation_epoch`) default to zero / default-hash.
/// Production callers override these via `Store::set_terminal_config` and
/// `Store::set_fork_epochs` after construction (see `main.rs`).
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
    let time = slot_start_time::<E>(anchor_state.slot().0, anchor_state.genesis_time());

    let genesis_time = anchor_state.genesis_time();

    let mut blocks = HashMap::new();
    blocks.insert(anchor_root, anchor_block.clone());

    let mut block_states = HashMap::new();
    block_states.insert(anchor_root, anchor_state.clone());

    let mut checkpoint_states = HashMap::new();
    checkpoint_states.insert(justified_checkpoint.clone(), anchor_state.clone());

    let mut unrealized_justifications = HashMap::new();
    unrealized_justifications.insert(anchor_root, justified_checkpoint.clone());

    // Per `specs/sync/optimistic.md` "Checkpoint Sync (Weak Subjectivity Sync)":
    // a CL MAY assume the anchor's ExecutionPayload is VALID.  Seed it here so
    // `is_optimistic(store, anchor_root)` returns false for a post-merge anchor
    // and `latest_verified_ancestor` never walks past the trusted anchor root.
    // For pre-merge (phase0/altair) anchors this is harmless: `is_optimistic`
    // short-circuits via `block_is_execution_enabled` = false regardless.
    let mut payload_statuses = HashMap::new();
    payload_statuses.insert(anchor_root, PayloadStatus::Valid);

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
        payload_statuses,
        // Terminal-block constants default to zero (no merge configured).
        // Production callers set these via `Store::set_terminal_config`.
        terminal_total_difficulty: Uint256::ZERO,
        terminal_block_hash: Hash256::default(),
        terminal_block_hash_activation_epoch: u64::MAX,
        // Fork epoch schedule defaults to u64::MAX (never upgrade).
        // Conformance fork_choice tests use this default — fork epochs stay
        // at u64::MAX so no upgrade ever fires, preserving byte-identical
        // behaviour. Production callers wire real epochs via
        // `Store::set_fork_epochs`.
        altair_fork_epoch: u64::MAX,
        bellatrix_fork_epoch: u64::MAX,
        capella_fork_epoch: u64::MAX,
        // RuntimeConfig defaults to mainnet; the node assigns the real config
        // after construction.
        runtime_cfg: RuntimeConfig::default(),
    };

    // Update the current slot based on the anchor state time.
    // The store's current slot must match after construction.
    let _ = get_current_slot(&store); // validate (panics only on underflow; anchor is trusted)

    store
}
