use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};

use pharos_ssz::Decode;
use pharos_ssz::tree_hash::TreeHash;
use pharos_stf::{NullExecutionEngine, state_transition};
use pharos_types::BeaconSpec;
use pharos_types::MainnetBeaconSpec as E;
use pharos_types::config::RuntimeConfig;

// ── Fixture loader ────────────────────────────────────────────────────────────

/// Decompress a raw (non-framed) snappy file, then SSZ-decode as `S`.
///
/// Panics with "bench fixture missing: <path>" when the file is absent.
fn load_ssz_snappy<S: Decode>(path: &Path) -> S {
    let compressed =
        std::fs::read(path).unwrap_or_else(|_| panic!("bench fixture missing: {}", path.display()));
    let mut dec = snap::raw::Decoder::new();
    let raw = dec
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("snappy decompress {}: {e}", path.display()));
    S::from_ssz_bytes(&raw).unwrap_or_else(|e| panic!("ssz decode {}: {e:?}", path.display()))
}

/// Load `(pre_state, signed_block)` from a single `sanity/blocks` test case.
///
/// `fork` is one of "phase0".."fulu".
/// `case` is the case directory name, e.g. "empty_block_transition".
fn load_fixture<State: Decode, Block: Decode>(fork: &str, case: &str) -> (State, Block) {
    let base = dirs_spec_tests();
    let case_dir = base.join(format!("mainnet/{fork}/sanity/blocks/pyspec_tests/{case}"));
    let pre: State = load_ssz_snappy(&case_dir.join("pre.ssz_snappy"));
    let block: Block = load_ssz_snappy(&case_dir.join("blocks_0.ssz_snappy"));
    (pre, block)
}

/// Path to the spec-test fixture root.
///
/// Resolves `$PHAROS_SPEC_TESTS` first, then falls back to
/// `$HOME/.cache/pharos-spec-tests` (the default from `fetch-spec-tests.sh`).
fn dirs_spec_tests() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PHAROS_SPEC_TESTS") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
    std::path::PathBuf::from(home)
        .join(".cache")
        .join("pharos-spec-tests")
}

// ── Criterion benchmark ───────────────────────────────────────────────────────

/// Load the `empty_block_transition` fixture for `$fork`, wrap it into the
/// enum-of-forks `BeaconState`/`SignedBeaconBlock`, and register a
/// `process_block/<fork>` bench that times a full `state_transition`.
///
/// The pre-state is put into the SAME shape the live node runs: decode yields a
/// `Backend::Flat` state, so live converts it once via `into_tree_backend()` at
/// every entry point (checkpoint-sync / genesis / storage load), then runs
/// Tree-backed forever after — `clone`-mutate preserves the per-node `OnceLock`
/// caches by structural sharing, so re-hashing only touches changed paths. The
/// bench replicates that exactly: convert + warm the caches before timing, so
/// the numbers reflect production, not the decode-only Naive path.
macro_rules! bench_fork {
    ($c:expr, $engine:expr, $cfg:expr, $fork:literal,
     $State:ident, $Block:ident, $into_state:ident, $into_block:ident) => {{
        let (pre_inner, block_inner) = load_fixture::<
            <E as BeaconSpec>::$State,
            <E as BeaconSpec>::$Block,
        >($fork, "empty_block_transition");
        let block = E::$into_block(block_inner);

        // Match live: decode (Naive) -> into_tree_backend -> warm caches.
        let pre = E::$into_state(pre_inner)
            .into_tree_backend()
            .unwrap_or_else(|e| panic!("{} into_tree_backend failed: {e:?}", $fork));
        let _ = pre.tree_hash_root(); // warm per-node OnceLock caches

        $c.bench_function(concat!("process_block/", $fork), |b| {
            b.iter(|| {
                state_transition::<E, NullExecutionEngine>(
                    pre.clone(),
                    &block,
                    $engine,
                    false,
                    $cfg,
                )
                .map(|(s, _)| s)
                .unwrap_or_else(|e| panic!("{} state_transition failed in bench: {e:?}", $fork))
            })
        });
    }};
}

fn criterion_benchmark(c: &mut Criterion) {
    let engine = NullExecutionEngine;
    let cfg = RuntimeConfig::default();

    bench_fork!(
        c,
        &engine,
        &cfg,
        "phase0",
        Phase0BeaconState,
        Phase0SignedBeaconBlock,
        phase0_into_state,
        phase0_into_signed_block
    );
    bench_fork!(
        c,
        &engine,
        &cfg,
        "altair",
        AltairBeaconState,
        AltairSignedBeaconBlock,
        altair_into_state,
        altair_into_signed_block
    );
    bench_fork!(
        c,
        &engine,
        &cfg,
        "bellatrix",
        BellatrixBeaconState,
        BellatrixSignedBeaconBlock,
        bellatrix_into_state,
        bellatrix_into_signed_block
    );
    bench_fork!(
        c,
        &engine,
        &cfg,
        "capella",
        CapellaBeaconState,
        CapellaSignedBeaconBlock,
        capella_into_state,
        capella_into_signed_block
    );
    bench_fork!(
        c,
        &engine,
        &cfg,
        "deneb",
        DenebBeaconState,
        DenebSignedBeaconBlock,
        deneb_into_state,
        deneb_into_signed_block
    );
    bench_fork!(
        c,
        &engine,
        &cfg,
        "electra",
        ElectraBeaconState,
        ElectraSignedBeaconBlock,
        electra_into_state,
        electra_into_signed_block
    );
    bench_fork!(
        c,
        &engine,
        &cfg,
        "fulu",
        FuluBeaconState,
        FuluSignedBeaconBlock,
        fulu_into_state,
        fulu_into_signed_block
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
