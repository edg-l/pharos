//! Fork-choice snapshot for warm-restart rehydration.
//!
//! # Warm-restart rehydration contract (`D-rocksdb` snapshot-rehydration)
//!
//! The `forkchoice` column family stores a single `ForkChoiceSnapshot` row.
//! It contains ONLY checkpoint cursors and head pointers — NOT the in-memory
//! `blocks`, `block_states`, or `checkpoint_states` HashMaps. Those live in
//! the `blocks` and `states` CFs already.
//!
//! On node restart, the caller reads this snapshot and rebuilds the in-memory
//! `pharos_fork_choice::Store<E>` by walking persisted blocks from
//! `finalized_checkpoint.root` forward to `head_root`, loading each block and
//! its post-state from `blocks` / `states` CFs. The walk is implemented in
//! `pharos-node::startup::rehydrate_fork_choice_store`.
//!
//! After rehydration, the binary must call `on_tick` with the current
//! wall-clock time to advance the store's time cursor from
//! `last_known_time` to the present.

use pharos_ssz::{Decode, Encode};
use pharos_types::phase0::misc::Checkpoint;
use pharos_types::phase0::primitives::{Root, Slot};

/// Cursor snapshot of the fork-choice store, persisted to the `forkchoice` CF.
///
/// Non-generic: contains only checkpoints, roots, and scalar values. The
/// block and state HashMaps are NOT included; they are stored in the `blocks`
/// and `states` CFs and rebuilt from them on warm restart.
///
/// Spec cite: `D-rocksdb` snapshot-rehydration paragraph.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct ForkChoiceSnapshot {
    /// The justified checkpoint cursor from the fork-choice store.
    pub justified_checkpoint: Checkpoint,

    /// The finalized checkpoint cursor from the fork-choice store.
    pub finalized_checkpoint: Checkpoint,

    /// The highest unrealized justified checkpoint.
    pub unrealized_justified_checkpoint: Checkpoint,

    /// The highest unrealized finalized checkpoint.
    pub unrealized_finalized_checkpoint: Checkpoint,

    /// Block root that has received the proposer score boost, or
    /// `Root::default()` if no boost is active.
    ///
    /// `Root::default()` (all zeros) is the sentinel for "no boost" as used
    /// by `pharos_fork_choice::Store::proposer_boost_root`.
    pub proposer_boost_root: Root,

    /// The fork-choice store's time cursor at the last snapshot write, in
    /// seconds since Unix epoch.
    ///
    /// This is "last known time", not a wall-clock cursor. After
    /// `rehydrate_fork_choice_store` returns, the caller must call
    /// `on_tick(store, SystemTime::now()...)` to advance to wall-clock time.
    pub last_known_time: u64,

    /// Genesis time in seconds since Unix epoch.
    ///
    /// Matches `anchor_state.genesis_time`; stored here so rehydration does
    /// not need to re-decode the genesis state.
    pub genesis_time: u64,

    /// The LMD-GHOST head block root at the time of the last snapshot.
    pub head_root: Root,

    /// The slot of `head_root`.
    pub head_slot: Slot,
}
