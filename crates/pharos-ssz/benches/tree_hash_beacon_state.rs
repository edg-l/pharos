mod bench_helpers;

use criterion::{Criterion, criterion_group, criterion_main};

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::BeaconSpec;
use pharos_types::MainnetBeaconSpec as E;

// ── Fixture loading ───────────────────────────────────────────────────────────

/// Load an Altair `BeaconState` for benchmarking.
fn load_altair_state() -> <E as BeaconSpec>::BeaconState {
    let inner: <E as BeaconSpec>::AltairBeaconState =
        bench_helpers::load_pre_state("altair", "empty_block_transition");
    E::altair_into_state(inner)
}

/// Load a Bellatrix `BeaconState` for benchmarking.
fn load_bellatrix_state() -> <E as BeaconSpec>::BeaconState {
    let inner: <E as BeaconSpec>::BellatrixBeaconState =
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
    // Measures the per-block "small mutation + rehash" path on a `Backend::Tree`
    // state. The base state is flipped to the tree backend once at setup so
    // the per-iter `with_set` on `validators` does an O(log n) path-copy
    // rather than the full `Vec` clone the naive backend would force.
    //
    // Per-iteration: `Clone` the inner state (the `CachedRoot` wrapper resets
    // on Clone per `D-validator-cache-clone-resets`, so the next
    // `cached_tree_hash_root()` call computes from scratch — that is the
    // "cold cache" the bench name promises), mutate validator 0 via
    // `with_set`, then call `cached_tree_hash_root()` to walk the tree and
    // populate the freshly-empty cache.
    let bellatrix_inner_base: <E as BeaconSpec>::BellatrixBeaconState =
        bench_helpers::load_pre_state("bellatrix", "empty_block_transition");
    let bellatrix_inner_tree = bellatrix_inner_base
        .into_tree_backend()
        .expect("flip bellatrix state validators+vectors to Tree backend");

    c.bench_function("tree_hash_beacon_state/bellatrix_cold", |b| {
        let mut counter: u64 = 0;
        b.iter(|| {
            let mut inner = bellatrix_inner_tree.clone();
            if let Some(v) = inner.validators.get(0).cloned() {
                let mut modified = v;
                modified.effective_balance.0 = modified.effective_balance.0.wrapping_add(counter);
                counter = counter.wrapping_add(1);
                inner.validators = inner
                    .validators
                    .with_set(0, modified)
                    .expect("with_set index 0 out of range");
            }
            inner.cached_tree_hash_root()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
