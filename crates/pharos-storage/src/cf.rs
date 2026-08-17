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
/// Per `D-light-client-server-only`: one bootstrap entry per finalized
/// epoch-boundary block. Key = `Root` (32 B), value = SSZ `LightClientBootstrap`.
pub const CF_LC_BOOTSTRAP: &str = "light-client-bootstrap";

/// Stores SSZ-encoded `LightClientUpdate` objects, keyed by sync-committee period (u64 LE, 8 bytes).
///
/// Per `D-light-client-server-only`: one best update per sync-committee period.
/// Key = `u64` LE (period), value = SSZ `LightClientUpdate`.
pub const CF_LC_UPDATE: &str = "light-client-update";

/// Single-row CF storing the latest SSZ-encoded `LightClientFinalityUpdate`.
///
/// Per `D-light-client-server-only`: overwrites on every finality advance.
/// Key = `b"latest"` (static), value = SSZ `LightClientFinalityUpdate`.
pub const CF_LC_FINALITY_UPDATE: &str = "latest-finality-update";

/// Single-row CF storing the latest SSZ-encoded `LightClientOptimisticUpdate`.
///
/// Per `D-light-client-server-only`: overwrites on every optimistic head update.
/// Key = `b"latest"` (static), value = SSZ `LightClientOptimisticUpdate`.
pub const CF_LC_OPTIMISTIC_UPDATE: &str = "latest-optimistic-update";

/// Per-block EL payload validation status (Bellatrix+).
///
/// Per `D-payload-status-store`: key = `Root` (32 B),
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
// passes the complete v3 set to RocksDB. `state-summary` is written on every
// block import. The three cold CFs are written only by the freezer migration,
// but RocksDB requires every CF to be present at `open()` time even
// if writes happen later.

/// Per-block state summary for the replay walk.
///
/// Per schema v3 (`D-schema-v3-migration`):
/// key = `Root` (32 B block-root),
/// value = SSZ `StateSummary { slot: u64 LE, state_root: Root 32B, parent_root: Root 32B }`.
/// Written every import; read by Phase-2 `StateRegenService` to walk the persisted
/// block chain for replay-on-read.
pub const CF_STATE_SUMMARY: &str = "state-summary";

/// Cold (post-finalization) block store.
///
/// Per schema v3 (`D-schema-v3-migration`):
/// key = `Root` (32 B block-root), value = SSZ `SignedBeaconBlock`.
/// Written by Phase-3 freezer migration; read by Phase-2 regen + Phase-4 restart.
pub const CF_COLD_BLOCKS: &str = "cold-blocks";

/// Cold (post-finalization) state snapshots at restore-point slots.
///
/// Per schema v3 (`D-schema-v3-migration`):
/// key = `u64` BE (restore-point slot), value = SSZ `BeaconState`.
/// Written by Phase-3 freezer; read by Phase-2 regen + Phase-4 restart.
pub const CF_COLD_STATES: &str = "cold-states";

/// Restore-point index: maps a restore-point slot to its state-root.
///
/// Per schema v3 (`D-schema-v3-migration`):
/// key = `u64` BE (restore-point slot), value = `Root` (32 B state-root).
/// Written by Phase-3 freezer; read by Phase-2 regen for nearest-restore-point lookup.
pub const CF_RESTORE_POINTS: &str = "restore-points";

// ── Schema v4 column families (D-schema-v4-migration) ─────────────────────────
//
// One new CF:
//   `blob-sidecars` — per-block blob sidecar storage keyed by
//   `block_root (32 B) || index_be (8 B)`.
// Opening a v3 DB returns `SchemaMismatch` → operator must resync.

/// Per-block blob sidecar store.
///
/// Per schema v4 (`D-blob-store-cf-keyed-by-root-index`):
/// key = `block_root` (32 B) `||` `index` (8 B big-endian u64),
/// value = SSZ `BlobSidecar`.
///
/// The 32-byte `block_root` prefix enables a RocksDB prefix iterator that
/// returns all sidecars for a given block in index order (big-endian keys
/// sort numerically, so index 0 < 1 < 2 … within the same block root prefix).
///
/// Per `D-blob-store-cf-keyed-by-root-index`.
pub const CF_BLOB_SIDECARS: &str = "blob-sidecars";

// ── Schema v5 column families (Deneb LC) ──────────────────────────────────────
//
// Four new CFs added for Deneb light-client types, which have a different SSZ
// layout than Capella LC (deneb `ExecutionPayloadHeader` adds `blob_gas_used` and
// `excess_blob_gas`).

/// Stores SSZ-encoded Deneb `LightClientBootstrap` objects, keyed by block root.
pub const CF_LC_BOOTSTRAP_DENEB: &str = "deneb-light-client-bootstrap";

/// Stores SSZ-encoded Deneb `LightClientUpdate` objects, keyed by sync-committee period.
pub const CF_LC_UPDATE_DENEB: &str = "deneb-light-client-update";

/// Single-row CF storing the latest SSZ-encoded Deneb `LightClientFinalityUpdate`.
pub const CF_LC_FINALITY_UPDATE_DENEB: &str = "deneb-latest-finality-update";

/// Single-row CF storing the latest SSZ-encoded Deneb `LightClientOptimisticUpdate`.
pub const CF_LC_OPTIMISTIC_UPDATE_DENEB: &str = "deneb-latest-optimistic-update";

// ── Schema v6 column families (Electra LC) ────────────────────────────────────
//
// Four new CFs added for Electra light-client types. Electra LC branches are
// deeper than Deneb (EIP-7251 enlarged BeaconState → deeper merkle paths), so
// electra and deneb LC objects are NOT interchangeable.

/// Stores SSZ-encoded Electra `LightClientBootstrap` objects, keyed by block root.
pub const CF_LC_BOOTSTRAP_ELECTRA: &str = "electra-light-client-bootstrap";

/// Stores SSZ-encoded Electra `LightClientUpdate` objects, keyed by sync-committee period.
pub const CF_LC_UPDATE_ELECTRA: &str = "electra-light-client-update";

/// Single-row CF storing the latest SSZ-encoded Electra `LightClientFinalityUpdate`.
pub const CF_LC_FINALITY_UPDATE_ELECTRA: &str = "electra-latest-finality-update";

/// Single-row CF storing the latest SSZ-encoded Electra `LightClientOptimisticUpdate`.
pub const CF_LC_OPTIMISTIC_UPDATE_ELECTRA: &str = "electra-latest-optimistic-update";

// ── Schema v8 column families (slasher Phase B) ─────────────────
//
// One new CF added for the opt-in (`--slasher`) chain-history replay slasher:
//   `slasher-proposers` — per-`(slot, proposer)` block-header index used by the
//   proposer double-block detector. Opening a v7 DB triggers the v7→v8 forward
//   migration (the CF is auto-created by `create_missing_column_families`).
//
// Per `D-slasher-proposer-index-cf`.

/// Proposer-header index for the Phase B slasher.
///
/// Per schema v8 (`D-slasher-proposer-index-cf`):
/// key = `slot` (8 B big-endian) `||` `proposer_index` (8 B big-endian) `||`
/// `header_root` (32 B), value = SSZ `SignedBeaconBlockHeader`.
///
/// The 16-byte `slot || proposer_index` prefix enables a RocksDB prefix
/// iterator that returns every distinct block header a proposer signed at a
/// given slot. Two entries under the same prefix with different `header_root`
/// suffixes are a slashable proposer double-block.
pub const CF_SLASHER_PROPOSERS: &str = "slasher-proposers";

// ── Schema v9 column families (PeerDAS) ────────────────────
//
// One new CF added for EIP-7594 PeerDAS data-column sidecar storage:
//   `data-column-sidecars` — per-block data-column sidecar storage keyed by
//   `block_root (32 B) || index_be (8 B)`, mirroring `blob-sidecars`.
// Opening a v8 DB triggers the v8→v9 forward migration (the CF is auto-created
// by `create_missing_column_families`).

/// Per-block data-column sidecar store (EIP-7594 PeerDAS).
///
/// Per schema v9:
/// key = `block_root` (32 B) `||` `index` (8 B big-endian u64),
/// value = SSZ `DataColumnSidecar`.
///
/// The 32-byte `block_root` prefix enables a RocksDB prefix iterator that
/// returns all column sidecars for a given block in column-index order
/// (big-endian keys sort numerically). Mirrors `CF_BLOB_SIDECARS`.
pub const CF_DATA_COLUMN_SIDECARS: &str = "data-column-sidecars";

/// Returns all thirty-one column-family names in declaration order.
///
/// Used when opening the database with `DB::open_cf_descriptors` so every CF
/// is registered. The ordering does not affect correctness; RocksDB looks up
/// CFs by name.
///
/// Per `D-schema-v6-migration`: the full v6 CF set (25 v5 CFs + 4 new Electra LC) is
/// declared here so a fresh v6 DB opens with all CFs at first boot.
///
/// Per `D-slasher-proposer-index-cf` (v8): the `slasher-proposers` CF is appended,
/// so a fresh v8 DB opens with all thirty CFs at first boot.
///
/// In v9 the `data-column-sidecars` CF is appended, so a fresh
/// v9 DB opens with all thirty-one CFs at first boot.
pub fn all_cfs() -> [&'static str; 31] {
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
        CF_BLOB_SIDECARS,
        CF_LC_BOOTSTRAP_DENEB,
        CF_LC_UPDATE_DENEB,
        CF_LC_FINALITY_UPDATE_DENEB,
        CF_LC_OPTIMISTIC_UPDATE_DENEB,
        CF_LC_BOOTSTRAP_ELECTRA,
        CF_LC_UPDATE_ELECTRA,
        CF_LC_FINALITY_UPDATE_ELECTRA,
        CF_LC_OPTIMISTIC_UPDATE_ELECTRA,
        CF_SLASHER_PROPOSERS,
        CF_DATA_COLUMN_SIDECARS,
    ]
}
