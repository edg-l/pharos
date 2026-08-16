//! Integration tests for blob sidecar storage (M10-DA Phase 4, Task 4.6).
//!
//! Tests:
//! - `put_get_blob_sidecar`: put/get roundtrip for a single sidecar.
//! - `get_blob_sidecars_by_root_returns_all_in_index_order`: prefix-scan returns
//!   all sidecars for a block root in ascending index order.
//! - `prune_blob_sidecars_below_slot_removes_old_deletes_nothing_recent`: pruning
//!   removes sidecars below the horizon slot and keeps newer ones.
//! - `blob_sidecars_in_block_transition_are_atomic`: sidecars written via
//!   `write_block_transition` are readable immediately.
//! - `schema_v3_db_returns_schema_mismatch`: opening a v3 DB (without the new
//!   `blob-sidecars` CF sentinel) returns `SchemaMismatch { found: 3, expected: 6 }`.

use pharos_storage::{BlockTransition, RocksStore, RocksStoreConfig, StorageError, Store};
use pharos_types::MainnetEthSpec;
use pharos_types::deneb::BlobSidecar;
use pharos_types::phase0::primitives::{Root, Slot};

// ── Type aliases ──────────────────────────────────────────────────────────────

type S = RocksStore;
type E = MainnetEthSpec;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn open(path: &std::path::Path) -> S {
    S::open::<E>(RocksStoreConfig {
        path: path.to_owned(),
        create_if_missing: true,
    })
    .expect("open db")
}

/// Build a `BlobSidecar` with the given `signed_block_header.message.slot`
/// and blob `index`. All other fields are default (zeroed).
fn make_sidecar(slot: u64, index: u64) -> BlobSidecar {
    let mut sidecar = BlobSidecar {
        index,
        ..BlobSidecar::default()
    };
    sidecar.signed_block_header.message.slot = Slot(slot);
    sidecar
}

/// Derive a deterministic 32-byte `Root` from a `u64` seed.
fn root_from(seed: u64) -> Root {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8] = 0xDA; // DA = data-availability marker
    Root::from(bytes)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Basic put/get roundtrip for a single `BlobSidecar`.
#[test]
fn put_get_blob_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    let root = root_from(1);
    let index = 0u64;
    let sidecar = make_sidecar(100, index);

    // Initially absent.
    let got = <S as Store<E>>::get_blob_sidecar(&store, &root, index).expect("get absent");
    assert!(got.is_none(), "expected None before put");

    // Write.
    <S as Store<E>>::put_blob_sidecar(&store, root, index, &sidecar).expect("put sidecar");

    // Read back.
    let got = <S as Store<E>>::get_blob_sidecar(&store, &root, index)
        .expect("get after put")
        .expect("expected Some after put");
    assert_eq!(got, sidecar, "sidecar roundtrip mismatch");
}

/// A prefix scan on `block_root` returns all sidecars in ascending index order.
#[test]
fn get_blob_sidecars_by_root_returns_all_in_index_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    let root = root_from(2);
    // Insert sidecars out of order (2, 0, 1) to prove ordering is by index, not insertion order.
    let indices = [2u64, 0u64, 1u64];
    for &idx in &indices {
        let sidecar = make_sidecar(200, idx);
        <S as Store<E>>::put_blob_sidecar(&store, root, idx, &sidecar).expect("put sidecar");
    }

    // A different root should return nothing.
    let other_root = root_from(99);
    let empty = <S as Store<E>>::get_blob_sidecars_by_root(&store, &other_root).expect("get other");
    assert!(empty.is_empty(), "expected empty for unrelated root");

    // Scan our root.
    let sidecars = <S as Store<E>>::get_blob_sidecars_by_root(&store, &root).expect("get by root");
    assert_eq!(sidecars.len(), 3, "expected 3 sidecars");
    assert_eq!(sidecars[0].index, 0, "index 0 must come first");
    assert_eq!(sidecars[1].index, 1, "index 1 must be second");
    assert_eq!(sidecars[2].index, 2, "index 2 must be last");
}

/// Pruning removes sidecars below `prune_slot` and keeps sidecars at or above.
#[test]
fn prune_blob_sidecars_below_slot_removes_old_keeps_recent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    // Sidecar at slot 10 (old) — should be pruned when prune_slot = 50.
    let old_root = root_from(10);
    let old_sidecar = make_sidecar(10, 0);
    <S as Store<E>>::put_blob_sidecar(&store, old_root, 0, &old_sidecar).expect("put old");

    // Sidecar at slot 50 (at boundary) — should NOT be pruned (< not <=).
    let boundary_root = root_from(50);
    let boundary_sidecar = make_sidecar(50, 0);
    <S as Store<E>>::put_blob_sidecar(&store, boundary_root, 0, &boundary_sidecar)
        .expect("put boundary");

    // Sidecar at slot 100 (recent) — should NOT be pruned.
    let recent_root = root_from(100);
    let recent_sidecar = make_sidecar(100, 0);
    <S as Store<E>>::put_blob_sidecar(&store, recent_root, 0, &recent_sidecar).expect("put recent");

    // Prune everything below slot 50.
    <S as Store<E>>::prune_blob_sidecars_below_slot(&store, Slot(50)).expect("prune");

    // Old sidecar (slot 10 < 50) must be gone.
    let gone =
        <S as Store<E>>::get_blob_sidecar(&store, &old_root, 0).expect("get old after prune");
    assert!(gone.is_none(), "slot-10 sidecar should have been pruned");

    // Boundary sidecar (slot 50 is NOT < 50) must still be present.
    let still_there =
        <S as Store<E>>::get_blob_sidecar(&store, &boundary_root, 0).expect("get boundary");
    assert!(
        still_there.is_some(),
        "slot-50 sidecar must NOT have been pruned (prune is strictly <)"
    );

    // Recent sidecar (slot 100) must still be present.
    let recent_still =
        <S as Store<E>>::get_blob_sidecar(&store, &recent_root, 0).expect("get recent");
    assert!(
        recent_still.is_some(),
        "slot-100 sidecar must not have been pruned"
    );
}

/// Blob sidecars written via `write_block_transition` (the atomic write path)
/// are readable immediately from the same store instance.
#[test]
fn blob_sidecars_in_block_transition_are_atomic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    let root = root_from(42);
    let sidecar0 = make_sidecar(300, 0);
    let sidecar1 = make_sidecar(300, 1);

    let mut bt = BlockTransition::<E>::new();
    bt.blob_sidecars = vec![
        (root, 0u64, sidecar0.clone()),
        (root, 1u64, sidecar1.clone()),
    ];

    <S as Store<E>>::write_block_transition(&store, bt).expect("write_block_transition");

    // Both sidecars must be readable.
    let got0 = <S as Store<E>>::get_blob_sidecar(&store, &root, 0)
        .expect("get 0")
        .expect("expected Some for index 0");
    let got1 = <S as Store<E>>::get_blob_sidecar(&store, &root, 1)
        .expect("get 1")
        .expect("expected Some for index 1");

    assert_eq!(got0, sidecar0, "sidecar index 0 roundtrip mismatch");
    assert_eq!(got1, sidecar1, "sidecar index 1 roundtrip mismatch");

    // Prefix scan must also return both, in order.
    let all = <S as Store<E>>::get_blob_sidecars_by_root(&store, &root).expect("scan");
    assert_eq!(all.len(), 2, "prefix scan must return 2 sidecars");
    assert_eq!(all[0].index, 0);
    assert_eq!(all[1].index, 1);
}

/// Opening a database that was written with schema v3 (before the `blob-sidecars`
/// CF was added) must return `SchemaMismatch { found: 3, expected: 6 }`.
///
/// Per `D-schema-v4-migration`: no in-place migration — the operator must resync.
#[test]
fn schema_v3_db_returns_schema_mismatch() {
    use rocksdb::{ColumnFamilyDescriptor, DB, Options};

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("chain_db_v3");

    // Simulate a v3 database: open with the 20 v3 CFs and write v3 sentinel.
    let v3_cfs = [
        "default",
        "blocks",
        "block_root_to_slot",
        "slot_to_block_root",
        "states",
        "forkchoice",
        "metadata",
        "light-client-bootstrap",
        "light-client-update",
        "latest-finality-update",
        "latest-optimistic-update",
        "payload-status",
        "capella-light-client-bootstrap",
        "capella-light-client-update",
        "capella-latest-finality-update",
        "capella-latest-optimistic-update",
        "state-summary",
        "cold-blocks",
        "cold-states",
        "restore-points",
        // Note: "blob-sidecars" is NOT present — this is the v3 set.
    ];
    {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let descriptors: Vec<ColumnFamilyDescriptor> = v3_cfs
            .iter()
            .map(|&n| ColumnFamilyDescriptor::new(n, Options::default()))
            .collect();
        let db = DB::open_cf_descriptors(&opts, &db_path, descriptors).expect("open v3 db");
        let meta_cf = db.cf_handle("metadata").expect("metadata cf");
        db.put_cf(meta_cf, b"schema_version", 3u32.to_le_bytes())
            .expect("write v3 sentinel");
    }

    // Now open with the current `RocksStore::open` which expects v6.
    let result = RocksStore::open::<E>(RocksStoreConfig {
        path: db_path,
        create_if_missing: false,
    });

    assert!(
        matches!(
            result,
            Err(StorageError::SchemaMismatch {
                found: 3,
                expected: 6
            })
        ),
        "expected SchemaMismatch{{found:3,expected:6}}, got {result:?}"
    );
}
