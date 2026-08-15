use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};

use pharos_ssz::Decode;
use pharos_stf::{NullExecutionEngine, state_transition};
use pharos_types::EthSpec;
use pharos_types::MainnetEthSpec as E;
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
/// `fork` is "phase0", "altair", or "bellatrix".
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

fn criterion_benchmark(c: &mut Criterion) {
    let engine = NullExecutionEngine;
    let cfg = RuntimeConfig::default();

    // ── phase0 ────────────────────────────────────────────────────────────────
    let (phase0_pre, phase0_block) = {
        let (pre_inner, block_inner) = load_fixture::<
            <E as EthSpec>::Phase0BeaconState,
            <E as EthSpec>::Phase0SignedBeaconBlock,
        >("phase0", "empty_block_transition");
        (
            E::phase0_into_state(pre_inner),
            E::phase0_into_signed_block(block_inner),
        )
    };

    c.bench_function("process_block/phase0", |b| {
        b.iter(|| {
            state_transition::<E, NullExecutionEngine>(
                phase0_pre.clone(),
                &phase0_block,
                &engine,
                false,
                &cfg,
            )
            .expect("phase0 state_transition failed in bench")
        })
    });

    // ── altair ────────────────────────────────────────────────────────────────
    let (altair_pre, altair_block) = {
        let (pre_inner, block_inner) = load_fixture::<
            <E as EthSpec>::AltairBeaconState,
            <E as EthSpec>::AltairSignedBeaconBlock,
        >("altair", "empty_block_transition");
        (
            E::altair_into_state(pre_inner),
            E::altair_into_signed_block(block_inner),
        )
    };

    c.bench_function("process_block/altair", |b| {
        b.iter(|| {
            state_transition::<E, NullExecutionEngine>(
                altair_pre.clone(),
                &altair_block,
                &engine,
                false,
                &cfg,
            )
            .expect("altair state_transition failed in bench")
        })
    });

    // ── bellatrix ─────────────────────────────────────────────────────────────
    let (bellatrix_pre, bellatrix_block) = {
        let (pre_inner, block_inner) = load_fixture::<
            <E as EthSpec>::BellatrixBeaconState,
            <E as EthSpec>::BellatrixSignedBeaconBlock,
        >("bellatrix", "empty_block_transition");
        (
            E::bellatrix_into_state(pre_inner),
            E::bellatrix_into_signed_block(block_inner),
        )
    };

    c.bench_function("process_block/bellatrix", |b| {
        b.iter(|| {
            state_transition::<E, NullExecutionEngine>(
                bellatrix_pre.clone(),
                &bellatrix_block,
                &engine,
                false,
                &cfg,
            )
            .expect("bellatrix state_transition failed in bench")
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
