//! Integration test: block persists across `HostImpl` teardown and restart.
//!
//! Verifies the end-to-end story: write a block to `RocksStore`, drop the
//! host (closing the DB), reopen at the same path, and confirm the block
//! and a fresh `MetaData.seq_number = 0` survive the round-trip.
//!
//! Spec cite: `D-rocksdb` (warm-restart correctness, M3a Edge Cases).

use std::sync::Arc;

use pharos_network::host::{BlockProvider, ForkContext};
use pharos_ssz::TreeHash;
use pharos_storage::{RocksStore, RocksStoreConfig, Store as StoreTrait};
use pharos_types::MinimalBeaconSpec;
use pharos_types::phase0::{
    MinimalBeaconBlock, MinimalSignedBeaconBlock as Phase0MinimalBlock, Slot,
};
use pharos_types::state::MinimalSignedBeaconBlock;

use crate::common::node::build_host;

/// Block written to storage in the first `RocksStore` open is retrievable
/// from a second `HostImpl` (via `build_host`) opened at the same path.
///
/// Additionally asserts `MetaData.seq_number == 0` on the second instance
/// (metadata is in-memory; persisted metadata is M11).
///
/// Per `D-rocksdb` warm-restart correctness requirement.
#[test]
fn block_survives_host_restart() {
    let datadir = tempfile::TempDir::new().unwrap();
    let db_path = datadir.path().join("chain_db");

    // ── First open: insert a block ────────────────────────────────────────────

    let known_inner = Phase0MinimalBlock {
        message: MinimalBeaconBlock {
            slot: Slot(42),
            ..MinimalBeaconBlock::default()
        },
        ..Phase0MinimalBlock::default()
    };
    let known_root = known_inner.message.tree_hash_root();
    let known_block = MinimalSignedBeaconBlock::Phase0(known_inner);

    {
        let store = Arc::new(
            RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
                path: db_path.clone(),
                create_if_missing: true,
            })
            .expect("open RocksStore"),
        );
        <RocksStore as StoreTrait<MinimalBeaconSpec>>::put_block(&store, known_root, &known_block)
            .expect("put_block must succeed");
        // `store` is dropped here, closing the DB.
    }

    // ── Second open: verify the block is still present ────────────────────────

    let host2 = build_host(datadir.path());

    let retrieved = host2.block_by_root(known_root);
    assert_eq!(
        retrieved,
        Some(known_block),
        "block must survive RocksStore close+reopen"
    );

    // MetaData.seq_number starts at 0 on every cold-open (in-memory; M11 will
    // persist it to the `metadata` CF if desired).
    assert_eq!(
        host2.local_metadata().seq_number,
        0,
        "seq_number must be 0 on fresh HostImpl regardless of prior session"
    );
}
