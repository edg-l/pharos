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

/// Stores SSZ-encoded `LightClientBootstrap` objects, keyed by block root (32 bytes).
///
/// Per `D-light-client-server-only` (Task 6.9): one bootstrap entry per finalized
/// epoch-boundary block. Key = `Root` (32 B), value = SSZ `LightClientBootstrap`.
pub const CF_LC_BOOTSTRAP: &str = "light-client-bootstrap";

/// Stores SSZ-encoded `LightClientUpdate` objects, keyed by sync-committee period (u64 LE, 8 bytes).
///
/// Per `D-light-client-server-only` (Task 6.9): one best update per sync-committee period.
/// Key = `u64` LE (period), value = SSZ `LightClientUpdate`.
pub const CF_LC_UPDATE: &str = "light-client-update";

/// Single-row CF storing the latest SSZ-encoded `LightClientFinalityUpdate`.
///
/// Per `D-light-client-server-only` (Task 6.9): overwrites on every finality advance.
/// Key = `b"latest"` (static), value = SSZ `LightClientFinalityUpdate`.
pub const CF_LC_FINALITY_UPDATE: &str = "latest-finality-update";

/// Single-row CF storing the latest SSZ-encoded `LightClientOptimisticUpdate`.
///
/// Per `D-light-client-server-only` (Task 6.9): overwrites on every optimistic head update.
/// Key = `b"latest"` (static), value = SSZ `LightClientOptimisticUpdate`.
pub const CF_LC_OPTIMISTIC_UPDATE: &str = "latest-optimistic-update";

/// Per-block EL payload validation status (Bellatrix+).
///
/// Per `D-payload-status-store` (M4a Phase 4): key = `Root` (32 B),
/// value = `u8` discriminant (0 = `Valid`, 1 = `Invalid`, 2 = `NotValidated`).
/// Written by `write_block_transition` when `payload_status` is `Some`.
/// Read at startup by `rehydrate_fork_choice_store` to seed the in-memory
/// `pharos_fork_choice::Store::payload_statuses` map.
pub const CF_PAYLOAD_STATUS: &str = "payload-status";

/// Stores SSZ-encoded Capella `LightClientBootstrap` objects, keyed by block root.
///
/// Capella bootstrap headers include `execution` and `execution_branch` fields.
pub const CF_LC_BOOTSTRAP_CAPELLA: &str = "capella-light-client-bootstrap";

/// Stores SSZ-encoded Capella `LightClientUpdate` objects, keyed by sync-committee period.
///
/// Capella update headers include `execution` and `execution_branch` fields.
pub const CF_LC_UPDATE_CAPELLA: &str = "capella-light-client-update";

/// Single-row CF storing the latest SSZ-encoded Capella `LightClientFinalityUpdate`.
pub const CF_LC_FINALITY_UPDATE_CAPELLA: &str = "capella-latest-finality-update";

/// Single-row CF storing the latest SSZ-encoded Capella `LightClientOptimisticUpdate`.
pub const CF_LC_OPTIMISTIC_UPDATE_CAPELLA: &str = "capella-latest-optimistic-update";

/// Stable key for the single-row light-client update CFs.
///
/// Used by `CF_LC_FINALITY_UPDATE`, `CF_LC_OPTIMISTIC_UPDATE`, and their Capella variants.
pub const LC_LATEST_KEY: &[u8] = b"latest";

// ── Schema v3 column families (D-schema-v3-migration) ─────────────────────────
//
// All four CFs below are declared here so `all_cfs()` (and thus `open()`) always
// passes the complete v3 set to RocksDB. `state-summary` is written from Phase 1
// (every block import). The three cold CFs are written only from Phase 3 (freezer
// migration), but RocksDB requires every CF to be present at `open()` time even
// if writes happen later.

/// Per-block state summary for the replay walk.
///
/// Per schema v3 (`D-schema-v3-migration`, Task 1.5):
/// key = `Root` (32 B block-root),
/// value = SSZ `StateSummary { slot: u64 LE, state_root: Root 32B, parent_root: Root 32B }`.
/// Written every import; read by Phase-2 `StateRegenService` to walk the persisted
/// block chain for replay-on-read.
pub const CF_STATE_SUMMARY: &str = "state-summary";

/// Cold (post-finalization) block store.
///
/// Per schema v3 (`D-schema-v3-migration`, Task 1.5):
/// key = `Root` (32 B block-root), value = SSZ `SignedBeaconBlock`.
/// Written by Phase-3 freezer migration; read by Phase-2 regen + Phase-4 restart.
pub const CF_COLD_BLOCKS: &str = "cold-blocks";

/// Cold (post-finalization) state snapshots at restore-point slots.
///
/// Per schema v3 (`D-schema-v3-migration`, Task 1.5):
/// key = `u64` BE (restore-point slot), value = SSZ `BeaconState`.
/// Written by Phase-3 freezer; read by Phase-2 regen + Phase-4 restart.
pub const CF_COLD_STATES: &str = "cold-states";

/// Restore-point index: maps a restore-point slot to its state-root.
///
/// Per schema v3 (`D-schema-v3-migration`, Task 1.5):
/// key = `u64` BE (restore-point slot), value = `Root` (32 B state-root).
/// Written by Phase-3 freezer; read by Phase-2 regen for nearest-restore-point lookup.
pub const CF_RESTORE_POINTS: &str = "restore-points";

/// Returns all twenty column-family names in declaration order.
///
/// Used when opening the database with `DB::open_cf_descriptors` so every CF
/// is registered. The ordering does not affect correctness; RocksDB looks up
/// CFs by name.
///
/// Per `D-schema-v3-migration`: the full v3 CF set (16 original + 4 new) is
/// declared here so a fresh v3 DB opens with all CFs at first boot.
pub fn all_cfs() -> [&'static str; 20] {
    [
        CF_DEFAULT,
        CF_BLOCKS,
        CF_BLOCK_ROOT_TO_SLOT,
        CF_SLOT_TO_BLOCK_ROOT,
        CF_STATES,
        CF_FORKCHOICE,
        CF_METADATA,
        CF_LC_BOOTSTRAP,
        CF_LC_UPDATE,
        CF_LC_FINALITY_UPDATE,
        CF_LC_OPTIMISTIC_UPDATE,
        CF_PAYLOAD_STATUS,
        CF_LC_BOOTSTRAP_CAPELLA,
        CF_LC_UPDATE_CAPELLA,
        CF_LC_FINALITY_UPDATE_CAPELLA,
        CF_LC_OPTIMISTIC_UPDATE_CAPELLA,
        CF_STATE_SUMMARY,
        CF_COLD_BLOCKS,
        CF_COLD_STATES,
        CF_RESTORE_POINTS,
    ]
}
