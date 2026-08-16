//! Integration tests for data-column sidecar storage (M13-Fulu Phase 4, schema v9).
//!
//! Tests:
//! - `put_get_data_column_sidecar`: put/get roundtrip for a single sidecar.
//! - `get_all_data_column_sidecars_by_root_returns_all_in_index_order`: prefix-scan
//!   returns all sidecars for a block root in ascending column-index order.
//! - `prune_data_column_sidecars_below_slot_removes_old_keeps_recent`: pruning
//!   removes sidecars below the horizon slot and keeps newer ones.
//!
//! The v8→v9 migration test (open a v8 DB, migrate, new CF exists + usable) lives
//! in `pharos_storage::db` unit tests as `migration_walk_v8_to_v9`.

use pharos_storage::{RocksStore, RocksStoreConfig, Store};
use pharos_types::MainnetBeaconSpec;
use pharos_types::fulu::MainnetDataColumnSidecar;
use pharos_types::phase0::primitives::{Root, Slot};

// ── Type aliases ──────────────────────────────────────────────────────────────

type S = RocksStore;
type E = MainnetBeaconSpec;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn open(path: &std::path::Path) -> S {
    S::open::<E>(RocksStoreConfig {
        path: path.to_owned(),
        create_if_missing: true,
    })
    .expect("open db")
}

/// Build a `DataColumnSidecar` with the given `signed_block_header.message.slot`
/// and column `index`. All other fields are default (zeroed).
fn make_sidecar(slot: u64, index: u64) -> MainnetDataColumnSidecar {
    let mut sidecar = MainnetDataColumnSidecar {
        index,
        ..MainnetDataColumnSidecar::default()
    };
    sidecar.signed_block_header.message.slot = Slot(slot);
    sidecar
}

/// Derive a deterministic 32-byte `Root` from a `u64` seed.
fn root_from(seed: u64) -> Root {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8] = 0xDC; // DC = data-column marker
    Root::from(bytes)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Basic put/get roundtrip for a single `DataColumnSidecar`.
#[test]
fn put_get_data_column_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    let root = root_from(1);
    let index = 7u64;
    let sidecar = make_sidecar(100, index);

    // Initially absent.
    let got = <S as Store<E>>::get_data_column_sidecar(&store, &root, index).expect("get absent");
    assert!(got.is_none(), "expected None before put");

    // Write (index is taken from the sidecar).
    <S as Store<E>>::put_data_column_sidecar(&store, root, &sidecar).expect("put sidecar");

    // Read back.
    let got = <S as Store<E>>::get_data_column_sidecar(&store, &root, index)
        .expect("get after put")
        .expect("expected Some after put");
    assert_eq!(got, sidecar, "sidecar roundtrip mismatch");
}

/// A prefix scan on `block_root` returns all sidecars in ascending column index order.
#[test]
fn get_all_data_column_sidecars_by_root_returns_all_in_index_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    let root = root_from(2);
    // Insert sidecars out of order (12, 0, 5) to prove ordering is by index.
    let indices = [12u64, 0u64, 5u64];
    for &idx in &indices {
        let sidecar = make_sidecar(200, idx);
        <S as Store<E>>::put_data_column_sidecar(&store, root, &sidecar).expect("put sidecar");
    }

    // A different root should return nothing.
    let other_root = root_from(99);
    let empty = <S as Store<E>>::get_all_data_column_sidecars_by_root(&store, &other_root)
        .expect("get other");
    assert!(empty.is_empty(), "expected empty for unrelated root");

    // Scan our root.
    let sidecars =
        <S as Store<E>>::get_all_data_column_sidecars_by_root(&store, &root).expect("get by root");
    assert_eq!(sidecars.len(), 3, "expected 3 sidecars");
    assert_eq!(sidecars[0].index, 0, "index 0 must come first");
    assert_eq!(sidecars[1].index, 5, "index 5 must be second");
    assert_eq!(sidecars[2].index, 12, "index 12 must be last");
}

/// Pruning removes sidecars below `prune_slot` and keeps sidecars at or above.
#[test]
fn prune_data_column_sidecars_below_slot_removes_old_keeps_recent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    // Sidecar at slot 10 (old) — should be pruned when prune_slot = 50.
    let old_root = root_from(10);
    <S as Store<E>>::put_data_column_sidecar(&store, old_root, &make_sidecar(10, 0))
        .expect("put old");

    // Sidecar at slot 50 (at boundary) — should NOT be pruned (< not <=).
    let boundary_root = root_from(50);
    <S as Store<E>>::put_data_column_sidecar(&store, boundary_root, &make_sidecar(50, 0))
        .expect("put boundary");

    // Sidecar at slot 100 (recent) — should NOT be pruned.
    let recent_root = root_from(100);
    <S as Store<E>>::put_data_column_sidecar(&store, recent_root, &make_sidecar(100, 0))
        .expect("put recent");

    // Prune everything below slot 50.
    <S as Store<E>>::prune_data_column_sidecars_below_slot(&store, Slot(50)).expect("prune");

    // Old sidecar (slot 10 < 50) must be gone.
    let gone = <S as Store<E>>::get_data_column_sidecar(&store, &old_root, 0)
        .expect("get old after prune");
    assert!(gone.is_none(), "slot-10 sidecar should have been pruned");

    // Boundary sidecar (slot 50 is NOT < 50) must still be present.
    let still_there =
        <S as Store<E>>::get_data_column_sidecar(&store, &boundary_root, 0).expect("get boundary");
    assert!(
        still_there.is_some(),
        "slot-50 sidecar must NOT have been pruned (prune is strictly <)"
    );

    // Recent sidecar (slot 100) must still be present.
    let recent_still =
        <S as Store<E>>::get_data_column_sidecar(&store, &recent_root, 0).expect("get recent");
    assert!(
        recent_still.is_some(),
        "slot-100 sidecar must not have been pruned"
    );
}
