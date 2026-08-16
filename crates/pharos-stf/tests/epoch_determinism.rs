//! Determinism test for `process_rewards_and_penalties`.
//!
//! Loads one large `phase0/epoch_processing/rewards_and_penalties` fixture,
//! runs `process_rewards_and_penalties` 8 times on independent state clones,
//! and asserts that all post-states produce identical SSZ bytes.
//!
//! This catches order-dependent bugs that could surface with rayon parallelism
//! (e.g., HashMap iteration order affecting accumulation).
//!
//! Skips cleanly when `$PHAROS_SPEC_TESTS` is unset and the default cache path
//! is absent, matching the conformance crate's skip pattern.

use std::path::PathBuf;

use pharos_ssz::{Decode, Encode};
use pharos_stf::phase0::epoch::process_rewards_and_penalties;
use pharos_types::{BeaconSpec, MainnetBeaconSpec};

// ── Fixture resolution ────────────────────────────────────────────────────────

fn fixtures_root() -> Option<PathBuf> {
    let path = if let Ok(val) = std::env::var("PHAROS_SPEC_TESTS") {
        PathBuf::from(val)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".cache/pharos-spec-tests")
    };

    if path.is_dir() && std::fs::read_dir(&path).ok()?.next().is_some() {
        Some(path)
    } else {
        None
    }
}

fn load_ssz_snappy<S: Decode>(path: &std::path::Path) -> S {
    let compressed = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut decoder = snap::raw::Decoder::new();
    let raw = decoder
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("snappy decompress {}: {e}", path.display()));
    S::from_ssz_bytes(&raw).unwrap_or_else(|e| panic!("ssz decode {}: {e:?}", path.display()))
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[test]
fn rewards_and_penalties_deterministic() {
    let root = match fixtures_root() {
        Some(r) => r,
        None => {
            eprintln!(
                "epoch_determinism: no fixtures found; skipping \
                 (run scripts/fetch-spec-tests.sh to download)"
            );
            return;
        }
    };

    // Use the mainnet "almost_full_attestations" case — large validator set,
    // exercises all delta paths.
    let case_dir = root
        .join("mainnet")
        .join("phase0")
        .join("epoch_processing")
        .join("rewards_and_penalties")
        .join("pyspec_tests")
        .join("almost_full_attestations");

    assert!(case_dir.is_dir(), "fixture missing: {}", case_dir.display());

    let pre_path = case_dir.join("pre.ssz_snappy");

    // Load 8 independent copies of the pre-state.
    // Fixture files are raw phase0 SSZ (no discriminant prefix); decode as
    // the concrete phase0 type then wrap into the fork-enum BeaconState.
    let mut states: Vec<<MainnetBeaconSpec as pharos_types::BeaconSpec>::BeaconState> = (0..8)
        .map(|_| {
            let inner =
                load_ssz_snappy::<<MainnetBeaconSpec as BeaconSpec>::Phase0BeaconState>(&pre_path);
            MainnetBeaconSpec::phase0_into_state(inner)
        })
        .collect();

    // Run process_rewards_and_penalties on each copy.
    for state in states.iter_mut() {
        process_rewards_and_penalties::<MainnetBeaconSpec>(state)
            .expect("process_rewards_and_penalties failed");
    }

    // All post-states must be byte-identical.
    let reference = states[0].as_ssz_bytes();
    for (i, state) in states.iter().enumerate().skip(1) {
        let bytes = state.as_ssz_bytes();
        assert_eq!(
            reference, bytes,
            "run {i} produced a different post-state (rayon determinism failure)"
        );
    }
}
