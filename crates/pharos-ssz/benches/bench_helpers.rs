//! Shared fixture-loading helpers for pharos-ssz benches.

use std::path::Path;

use pharos_ssz::Decode;

// ── Path resolution ───────────────────────────────────────────────────────────

/// Path to the spec-test fixture root.
///
/// Resolves `$PHAROS_SPEC_TESTS` first, then falls back to
/// `$HOME/.cache/pharos-spec-tests` (the default from `fetch-spec-tests.sh`).
pub fn spec_tests_root() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PHAROS_SPEC_TESTS") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
    std::path::PathBuf::from(home)
        .join(".cache")
        .join("pharos-spec-tests")
}

// ── SSZ / snappy loader ───────────────────────────────────────────────────────

/// Decompress raw (non-framed) snappy then SSZ-decode as `S`.
///
/// Panics with "bench fixture missing: <path>" when the file is absent.
pub fn load_ssz_snappy<S: Decode>(path: &Path) -> S {
    let compressed =
        std::fs::read(path).unwrap_or_else(|_| panic!("bench fixture missing: {}", path.display()));
    let mut dec = snap::raw::Decoder::new();
    let raw = dec
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("snappy decompress {}: {e}", path.display()));
    S::from_ssz_bytes(&raw).unwrap_or_else(|e| panic!("ssz decode {}: {e:?}", path.display()))
}

/// Load `pre.ssz_snappy` from a sanity/blocks test case and wrap in fork enum.
///
/// `fork` is "altair" or "bellatrix". Returns the fork-enum `BeaconState`.
pub fn load_pre_state<S: Decode>(fork: &str, case: &str) -> S {
    let case_dir = spec_tests_root()
        .join("mainnet")
        .join(fork)
        .join("sanity/blocks/pyspec_tests")
        .join(case);
    load_ssz_snappy(&case_dir.join("pre.ssz_snappy"))
}
