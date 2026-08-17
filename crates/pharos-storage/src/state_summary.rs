//! `StateSummary` — per-block summary row stored in the `state-summary` CF.
//!
//! Written on every block import. The replay walk
//! uses the `parent_root` field to walk the persisted chain backward and
//! `state_root` to look up the nearest stored epoch-boundary state.
//!
//! Per schema v3 (`D-schema-v3-migration`):
//! key = `Root` (32 B block-root),
//! value = SSZ `StateSummary { slot: u64 LE, state_root: Root 32B, parent_root: Root 32B }`.

use pharos_ssz::{Decode, Encode};
use pharos_types::phase0::primitives::{Root, Slot};

/// Compact per-block record used by the Phase-2 replay walk.
///
/// Stored in the `state-summary` CF keyed by the block's block-root.
/// The `state_root` field is the STF-verified post-state root (from
/// `block.state_root()`) — cheaper than re-merkleizing the state.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct StateSummary {
    /// Slot of the block this summary belongs to.
    pub slot: Slot,

    /// Post-state root of this block (STF-verified, from `block.state_root()`).
    ///
    /// Used to look up the stored epoch-boundary state in the `states` CF.
    pub state_root: Root,

    /// Parent block root; enables a backward walk from any block to the
    /// nearest stored state for replay-on-read.
    pub parent_root: Root,
}
