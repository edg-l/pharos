//! Integration test for `HostImpl::record_attnets_change` and
//! `MetaData.seq_number` increment semantics.
//!
//! Spec reference: `p2p-interface.md:391-393` — a node MUST increment
//! `seq_number` whenever its `MetaData` changes (attnets field), and MUST NOT
//! increment it when the value is unchanged (idempotent on same value).
//!
//! These tests exercise the real `HostImpl<MainnetEthSpec>` backed by a real
//! `RocksStore` in a `tempfile::TempDir`, providing integration-level coverage
//! of the full metadata-mutation path as added in M3a Phase 2 Task 2.6 and
//! wired in Phase 5 Task 5.1.

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_network::host::ForkContext;
use pharos_node::host_impl::HostImpl;
use pharos_ssz::{Bitvector, TreeHash};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::phase0::primitives::{ATTESTATION_SUBNET_COUNT, Root, Version};
use pharos_types::state::BeaconBlock as ForkBeaconBlock;
use pharos_types::{EthSpec, MainnetEthSpec};

fn make_host(dir: &tempfile::TempDir) -> HostImpl<MainnetEthSpec> {
    let store = Arc::new(
        RocksStore::open::<MainnetEthSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open RocksStore"),
    );

    let genesis_state = <MainnetEthSpec as EthSpec>::BeaconState::default();
    let state_root = genesis_state.tree_hash_root();
    let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
        state_root,
        ..pharos_types::phase0::MainnetBeaconBlock::default()
    });
    let fc_store =
        pharos_fork_choice::get_forkchoice_store::<MainnetEthSpec>(genesis_state, anchor_block);
    let fork_choice = Arc::new(RwLock::new(fc_store));

    let gvr = Root::default();
    let fv = Version::from_array([0x00, 0x00, 0x00, 0x00]);
    HostImpl::new(
        store,
        fork_choice,
        gvr,
        fv,
        Arc::new(pharos_types::RuntimeConfig::default()),
    )
}

/// Transition 1: zero → bit-5 set.
/// Transition 2: same bitvector again (no change).
/// Transition 3: bit-5 + bit-10 set.
///
/// Expected seq_number: 0 → 1 → 1 → 2.
///
/// Spec: `p2p-interface.md:391-393`.
#[test]
fn metadata_seq_three_transitions() {
    let dir = tempfile::TempDir::new().unwrap();
    let host = make_host(&dir);

    // Initial state: seq_number = 0, all-zero attnets.
    assert_eq!(
        host.local_metadata().seq_number,
        0,
        "initial seq_number must be 0"
    );

    // Transition 1: set bit 5.
    let mut attnets_1: Bitvector<ATTESTATION_SUBNET_COUNT> = Bitvector::default();
    attnets_1.set(5, true);
    host.record_attnets_change(attnets_1.clone());
    assert_eq!(
        host.local_metadata().seq_number,
        1,
        "seq_number must be 1 after first distinct change"
    );

    // Transition 2: same bitvector — no bump.
    host.record_attnets_change(attnets_1);
    assert_eq!(
        host.local_metadata().seq_number,
        1,
        "seq_number must stay 1 on identical change (idempotent)"
    );

    // Transition 3: set bit 5 + bit 10.
    let mut attnets_2: Bitvector<ATTESTATION_SUBNET_COUNT> = Bitvector::default();
    attnets_2.set(5, true);
    attnets_2.set(10, true);
    host.record_attnets_change(attnets_2);
    assert_eq!(
        host.local_metadata().seq_number,
        2,
        "seq_number must be 2 after second distinct change"
    );
}
