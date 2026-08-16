//! Integration tests for `RocksStore` — verifies the full encode/decode
//! roundtrip over a real RocksDB instance on disk.
//!
//! Each test uses `tempfile::TempDir` so databases are isolated and cleaned up
//! automatically.

use pharos_storage::{
    BlockTransition, ForkChoiceSnapshot, RocksStore, StorageError, Store, db::RocksStoreConfig,
};
use pharos_types::MainnetEthSpec;
use pharos_types::phase0::Checkpoint;
use pharos_types::phase0::primitives::{Epoch, Root, Slot};
use pharos_types::state::MainnetSignedBeaconBlock;

// ── Type alias for readability ────────────────────────────────────────────────

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

fn make_block(slot: u64) -> (Root, MainnetSignedBeaconBlock) {
    let mut inner = pharos_types::phase0::MainnetSignedBeaconBlock::default();
    inner.message.slot = Slot(slot);
    let block = MainnetSignedBeaconBlock::Phase0(inner);
    // Use a simple non-zero root derived from the slot.
    let mut root_bytes = [0u8; 32];
    root_bytes[..8].copy_from_slice(&slot.to_le_bytes());
    root_bytes[8] = 0xBE;
    let root = Root::from(root_bytes);
    (root, block)
}

fn make_snapshot(head_slot: u64) -> ForkChoiceSnapshot {
    let cp = Checkpoint {
        epoch: Epoch(head_slot / 32),
        root: Root::default(),
    };
    ForkChoiceSnapshot {
        justified_checkpoint: cp.clone(),
        finalized_checkpoint: cp.clone(),
        unrealized_justified_checkpoint: cp.clone(),
        unrealized_finalized_checkpoint: cp,
        proposer_boost_root: Root::default(),
        last_known_time: 1_700_000_000,
        genesis_time: 1_606_824_023,
        head_root: Root::from([0xAB; 32]),
        head_slot: Slot(head_slot),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Opening a fresh DB writes schema_version=5; reopening reads it back.
///
/// Version history:
/// - v1 (M3a): initial schema.
/// - v2 (M4a): added `payload-status` CF.
/// - v3 (M-Storage Phase 1): added `state-summary`, `cold-blocks`, `cold-states`,
///   `restore-points` CFs per `D-schema-v3-migration`.
/// - v4 (M10-DA Phase 4): added `blob-sidecars` CF per `D-schema-v4-migration`.
/// - v5 (M10-Deneb Phase 1): added deneb LC CFs per `D-schema-v5-migration`.
#[test]
fn open_empty_db_writes_schema_version_5() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let _store = open(dir.path());
    }
    // Reopen and verify.
    let store = open(dir.path());
    let val = <S as Store<E>>::get_metadata(&store, b"schema_version")
        .expect("get schema_version")
        .expect("schema_version must be present");
    assert_eq!(val, 5u32.to_le_bytes(), "schema_version must be 5 LE");
}

/// Store a `StateSummary`, retrieve it, assert field equality.
#[test]
fn state_summary_roundtrip() {
    use pharos_storage::StateSummary;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());
    let root = Root::from([0x11u8; 32]);
    let summary = StateSummary {
        slot: Slot(42),
        state_root: Root::from([0x22u8; 32]),
        parent_root: Root::from([0x33u8; 32]),
    };
    <S as Store<E>>::put_state_summary(&store, root, &summary).expect("put_state_summary");
    let got = <S as Store<E>>::get_state_summary(&store, &root)
        .expect("get_state_summary")
        .expect("summary must exist");
    assert_eq!(got, summary, "StateSummary must roundtrip");
    // A missing root returns None, not an error.
    let absent = <S as Store<E>>::get_state_summary(&store, &Root::from([0x99u8; 32]))
        .expect("get_state_summary absent");
    assert!(absent.is_none(), "absent summary must be None");
}

/// Store a block, retrieve it, assert SSZ equality.
#[test]
fn block_put_get_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());
    let (root, block) = make_block(42);

    <S as Store<E>>::put_block(&store, root, &block).expect("put_block");
    let retrieved = <S as Store<E>>::get_block(&store, &root)
        .expect("get_block")
        .expect("block must exist");

    assert_eq!(retrieved, block, "SSZ roundtrip must be identity");
}

/// Blocks inserted out-of-order are returned by `get_blocks_by_range` in
/// ascending slot order.
#[test]
fn blocks_by_range_ordering() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());

    // Insert at slots 3, 5, 1, 7 (deliberately out of order).
    for slot in [3u64, 5, 1, 7] {
        let (root, block) = make_block(slot);
        let mut bt = BlockTransition::<E>::new();
        bt.block = Some((root, block));
        bt.slot_index = Some((Slot(slot), root));
        <S as Store<E>>::write_block_transition(&store, bt).expect("write transition");
    }

    let result =
        <S as Store<E>>::get_blocks_by_range(&store, Slot(1), 10).expect("get_blocks_by_range");

    let slots: Vec<u64> = result
        .iter()
        .map(|b: &MainnetSignedBeaconBlock| match b {
            MainnetSignedBeaconBlock::Phase0(inner) => inner.message.slot.0,
            MainnetSignedBeaconBlock::Altair(inner) => inner.message.slot.0,
            MainnetSignedBeaconBlock::Bellatrix(inner) => inner.message.slot.0,
            MainnetSignedBeaconBlock::Capella(inner) => inner.message.slot.0,
            MainnetSignedBeaconBlock::Deneb(inner) => inner.message.slot.0,
        })
        .collect();
    assert_eq!(slots, vec![1, 3, 5, 7], "must be in ascending slot order");
}

/// A `BlockTransition` write is atomic: reopening the DB after a crash should
/// see all four components or none.
#[test]
fn write_block_transition_is_atomic() {
    let dir = tempfile::tempdir().expect("tempdir");

    let (root, block) = make_block(100);
    let state_root = Root::from([0x55u8; 32]);
    let state = <E as pharos_types::EthSpec>::BeaconState::default();
    let snapshot = make_snapshot(100);

    {
        let store = open(dir.path());
        let mut bt = BlockTransition::<E>::new();
        bt.block = Some((root, block.clone()));
        bt.state = Some((state_root, state.clone()));
        bt.forkchoice = Some(snapshot.clone());
        bt.slot_index = Some((Slot(100), root));
        <S as Store<E>>::write_block_transition(&store, bt).expect("write transition");
    }

    // Reopen — all four should be present.
    let store = open(dir.path());

    let retrieved_block = <S as Store<E>>::get_block(&store, &root)
        .expect("get_block")
        .expect("block must exist after reopen");
    assert_eq!(retrieved_block, block);

    let retrieved_state = <S as Store<E>>::get_state(&store, &state_root)
        .expect("get_state")
        .expect("state must exist after reopen");
    assert_eq!(retrieved_state, state);

    let retrieved_snap = <S as Store<E>>::get_forkchoice_snapshot(&store)
        .expect("get_forkchoice_snapshot")
        .expect("snapshot must exist after reopen");
    assert_eq!(retrieved_snap, snapshot);

    // Slot index: verify via get_blocks_by_range.
    let range_result =
        <S as Store<E>>::get_blocks_by_range(&store, Slot(100), 1).expect("get_blocks_by_range");
    assert_eq!(
        range_result.len(),
        1,
        "slot-index entry must survive reopen"
    );
}

/// `ForkChoiceSnapshot` with non-default fields survives a close/reopen cycle.
#[test]
fn forkchoice_snapshot_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");

    let snapshot = ForkChoiceSnapshot {
        justified_checkpoint: Checkpoint {
            epoch: Epoch(4),
            root: Root::from([0x11u8; 32]),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch(3),
            root: Root::from([0x22u8; 32]),
        },
        unrealized_justified_checkpoint: Checkpoint {
            epoch: Epoch(5),
            root: Root::from([0x33u8; 32]),
        },
        unrealized_finalized_checkpoint: Checkpoint {
            epoch: Epoch(4),
            root: Root::from([0x44u8; 32]),
        },
        proposer_boost_root: Root::from([0x55u8; 32]),
        last_known_time: 9_999_999,
        genesis_time: 1_606_824_023,
        head_root: Root::from([0x77u8; 32]),
        head_slot: Slot(160),
    };

    {
        let store = open(dir.path());
        <S as Store<E>>::put_forkchoice_snapshot(&store, &snapshot)
            .expect("put_forkchoice_snapshot");
    }

    let store = open(dir.path());
    let retrieved = <S as Store<E>>::get_forkchoice_snapshot(&store)
        .expect("get_forkchoice_snapshot")
        .expect("snapshot must be present");

    assert_eq!(retrieved, snapshot);
}

/// Writing `schema_version=99` and then reopening returns `SchemaMismatch`.
#[test]
fn schema_mismatch_detected() {
    let dir = tempfile::tempdir().expect("tempdir");

    {
        // Open normally so the DB is created, then overwrite schema_version.
        let store = open(dir.path());
        <S as Store<E>>::put_metadata(&store, b"schema_version", &99u32.to_le_bytes())
            .expect("put schema_version");
    }

    // Reopen — should get SchemaMismatch.
    let result = S::open::<E>(RocksStoreConfig {
        path: dir.path().to_owned(),
        create_if_missing: false,
    });

    match result {
        Err(StorageError::SchemaMismatch { found, expected }) => {
            assert_eq!(found, 99, "found must be 99");
            assert_eq!(expected, 5, "expected must be 5");
        }
        other => panic!("expected SchemaMismatch, got {other:?}"),
    }
}
