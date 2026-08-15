//! Gossip-validation benchmark for `LightClientFinalityUpdate`.

use std::sync::Arc;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;

use pharos_network::host::GossipValidator;
use pharos_ssz::TreeHash;
use pharos_storage::{RocksStore, RocksStoreConfig, Store as StoreTrait};
use pharos_types::EthSpec;
use pharos_types::MainnetEthSpec as E;
use pharos_types::RuntimeConfig;
use pharos_types::altair::light_client::{LightClientFinalityUpdate, LightClientHeader};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Root, Slot, Version};
use pharos_types::state::BeaconBlock as ForkBeaconBlock;

use pharos_node::host_impl::HostImpl;

// ── make_bench_host ───────────────────────────────────────────────────────────
//
// Duplicated from `crates/pharos-node/src/host_impl.rs:647-671` (the
// `make_host` test helper in the `#[cfg(test)]` block).  Not promoted to
// `pub mod test_helpers` because that would pollute the library surface for
// a single bench consumer.
fn make_bench_host(dir: &tempfile::TempDir) -> HostImpl<E> {
    let store = Arc::new(
        RocksStore::open::<E>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store"),
    );
    let genesis_state = <E as EthSpec>::BeaconState::default();
    let state_root = genesis_state.tree_hash_root();
    // Satisfy get_forkchoice_store's assertion: anchor_block.state_root == hash_tree_root(anchor_state).
    let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
        state_root,
        ..pharos_types::phase0::MainnetBeaconBlock::default()
    });
    let fc_store = pharos_fork_choice::get_forkchoice_store::<E>(genesis_state, anchor_block);
    let fork_choice = Arc::new(RwLock::new(fc_store));
    let gvr = Root::default();
    let fv = Version::from_array([0x00, 0x00, 0x00, 0x00]);
    let runtime_cfg = Arc::new(RuntimeConfig::default());
    HostImpl::new(store, fork_choice, gvr, fv, runtime_cfg)
}

/// Build a `LightClientFinalityUpdate` with the given slot number.
///
/// Slot numbers above 0 satisfy the clock-window check because
/// `genesis_time = 0` and `now_ms >> slot_start_ms`.
fn make_finality_update(slot: u64) -> <E as EthSpec>::AltairLightClientFinalityUpdate {
    LightClientFinalityUpdate {
        finalized_header: LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: Slot(slot),
                ..BeaconBlockHeader::default()
            },
        },
        attested_header: LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: Slot(slot),
                ..BeaconBlockHeader::default()
            },
        },
        signature_slot: Slot(slot),
        ..Default::default()
    }
}

// ── Criterion benchmark ───────────────────────────────────────────────────────

fn criterion_benchmark(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    let host = make_bench_host(&dir);

    // Write the initial snapshot so step 1 (snapshot lookup) succeeds.
    // The snapshot is overwritten in the per-iter setup phase (outside the
    // measured closure) to match the incoming msg, ensuring step 4
    // (tree_hash equality) also passes.
    let initial = make_finality_update(1);
    <RocksStore as StoreTrait<E>>::put_light_client_finality_update(&*host.store_arc(), &initial)
        .expect("put_light_client_finality_update failed in bench setup");

    // Slot counter — incremented per iteration so every call exercises the
    // full validation path (all five steps) rather than hitting the early
    // non-monotonic-slot return.
    let mut slot_counter: u64 = 1;

    // `iter_batched` keeps the RocksDB write in the (unmeasured) setup
    // phase. Measuring put + validate together would let the storage
    // write dominate and mask the validator cost we actually care about.
    c.bench_function("gossip_validation/lc_finality_update", |b| {
        b.iter_batched(
            || {
                slot_counter += 1;
                let msg = make_finality_update(slot_counter);
                <RocksStore as StoreTrait<E>>::put_light_client_finality_update(
                    &*host.store_arc(),
                    &msg,
                )
                .expect("put_light_client_finality_update failed in bench setup");
                msg
            },
            |msg| host.validate_light_client_finality_update(&msg),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
