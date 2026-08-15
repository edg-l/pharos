mod bench_helpers;

use criterion::{Criterion, criterion_group, criterion_main};

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::EthSpec;
use pharos_types::MainnetEthSpec as E;

// ── Fixture loading ───────────────────────────────────────────────────────────

/// Load an Altair `BeaconState` for benchmarking.
fn load_altair_state() -> <E as EthSpec>::BeaconState {
    let inner: <E as EthSpec>::AltairBeaconState =
        bench_helpers::load_pre_state("altair", "empty_block_transition");
    E::altair_into_state(inner)
}

/// Load a Bellatrix `BeaconState` for benchmarking.
fn load_bellatrix_state() -> <E as EthSpec>::BeaconState {
    let inner: <E as EthSpec>::BellatrixBeaconState =
        bench_helpers::load_pre_state("bellatrix", "empty_block_transition");
    E::bellatrix_into_state(inner)
}

// ── Criterion benchmark ───────────────────────────────────────────────────────

fn criterion_benchmark(c: &mut Criterion) {
    // ── altair_mainnet ────────────────────────────────────────────────────────
    // After the M4-perf cached_root work, the second iteration and beyond hit
    // the cached path (O(1) return of the previously computed root). The first
    // iteration populates the cache; criterion's warmup rounds ensure the
    // measured samples are on the hot path.
    let altair_state = load_altair_state();

    c.bench_function("tree_hash_beacon_state/altair_mainnet", |b| {
        b.iter(|| altair_state.tree_hash_root())
    });

    // ── bellatrix_mainnet ─────────────────────────────────────────────────────
    // Same cached-root warmup applies here.
    let bellatrix_state = load_bellatrix_state();

    c.bench_function("tree_hash_beacon_state/bellatrix_mainnet", |b| {
        b.iter(|| bellatrix_state.tree_hash_root())
    });

    // ── bellatrix_cold ────────────────────────────────────────────────────────
    // Mutates one validator's `effective_balance` per iteration to defeat the
    // cached root, exercising the full rehash path (unhappy path). The mutation
    // is via `SszSequence::with_set` which returns a new state with the
    // modified validator and a dirty cache.
    let bellatrix_inner_base: <E as EthSpec>::BellatrixBeaconState =
        bench_helpers::load_pre_state("bellatrix", "empty_block_transition");

    c.bench_function("tree_hash_beacon_state/bellatrix_cold", |b| {
        let mut counter: u64 = 0;
        b.iter(|| {
            // Clone inner state, mutate validator 0's effective_balance to
            // defeat the tree_hash cache, then re-wrap and hash.
            let mut inner = bellatrix_inner_base.clone();
            if let Some(v) = inner.validators.get(0).cloned() {
                let mut modified = v;
                modified.effective_balance.0 = modified.effective_balance.0.wrapping_add(counter);
                counter = counter.wrapping_add(1);
                inner.validators = inner
                    .validators
                    .with_set(0, modified)
                    .expect("with_set index 0 out of range");
            }
            let state = E::bellatrix_into_state(inner);
            state.tree_hash_root()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
