//! RocksDB column-family name constants.
//!
//! Layout follows `D-rocksdb`. One column family per storage domain; the
//! `default` CF is required by RocksDB but left empty.

/// Required RocksDB default column family; left empty.
pub const CF_DEFAULT: &str = "default";

/// Stores SSZ-encoded signed beacon blocks, keyed by block root (32 bytes).
///
/// Per `D-rocksdb`: `blocks` | key = `Root` (32 B) | value = SSZ `SignedBeaconBlock`.
pub const CF_BLOCKS: &str = "blocks";

/// Reverse index from block root to slot number.
///
/// Per `D-rocksdb`: key = `Root` (32 B) | value = `u64` LE (slot).
/// Used for range scans without decoding the full block.
pub const CF_BLOCK_ROOT_TO_SLOT: &str = "block_root_to_slot";

/// Forward index from slot number to block root.
///
/// Per `D-rocksdb`: key = `u64` BE (slot) | value = `Root` (32 B).
/// Keys are big-endian so lexicographic order equals numeric order,
/// enabling `Iterator::seek`-based range scans.
pub const CF_SLOT_TO_BLOCK_ROOT: &str = "slot_to_block_root";

/// Stores SSZ-encoded beacon states, keyed by state root (32 bytes).
///
/// Per `D-rocksdb`: `states` | key = `Root` (32 B) | value = SSZ `BeaconState`.
pub const CF_STATES: &str = "states";

/// Stores the single fork-choice snapshot row.
///
/// Per `D-rocksdb`: key = `b"forkchoice"` (static) | value = SSZ `ForkChoiceSnapshot`.
/// Rewritten atomically on each `on_block` transition.
pub const CF_FORKCHOICE: &str = "forkchoice";

/// Stores metadata key/value pairs (schema version, genesis validators root, etc.).
///
/// Per `D-rocksdb`: key = string bytes | value = raw bytes.
pub const CF_METADATA: &str = "metadata";

/// Returns all seven column-family names in declaration order.
///
/// Used when opening the database with `DB::open_cf_descriptors` so every CF
/// is registered. The ordering does not affect correctness; RocksDB looks up
/// CFs by name.
pub fn all_cfs() -> [&'static str; 7] {
    [
        CF_DEFAULT,
        CF_BLOCKS,
        CF_BLOCK_ROOT_TO_SLOT,
        CF_SLOT_TO_BLOCK_ROOT,
        CF_STATES,
        CF_FORKCHOICE,
        CF_METADATA,
    ]
}
