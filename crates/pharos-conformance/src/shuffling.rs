//! Shuffling conformance dispatcher.
//!
//! Covers `<preset>/phase0/shuffling/core/shuffle/<case>/mapping.yaml`.
//!
//! Exception S4: no `pyspec_tests/` level, no `meta.yaml`.
//! Uses `WalkOpts { meta_required: false, inner_dir: None }`.
//!
//! Tests both `mainnet` and `minimal` presets.

use std::path::{Path, PathBuf};

use pharos_stf::phase0::shuffling::compute_shuffled_permutation;
use pharos_utils::Hash256;
use rayon::prelude::*;

use crate::fixture_walker::{WalkOpts, walk_category};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Result of running all shuffling tests for one preset.
pub struct ShufflingResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

/// Run shuffling tests for a given preset and `SHUFFLE_ROUND_COUNT`.
///
/// Called with mainnet round count (90) and minimal round count (10).
pub fn run_shuffling_preset(root: &Path, preset: &str, round_count: u64) -> ShufflingResult {
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();

    // S4 exception: no pyspec_tests level, no meta.yaml.
    let opts = WalkOpts {
        meta_required: false,
        inner_dir: None,
    };

    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "shuffling",
        Some("core/shuffle"),
        opts,
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("phase0/shuffling/{}/{}", preset, dir_name(&case_dir));
            run_shuffling_case(&case_dir, &case_name, round_count)
        })
        .collect();

    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => pass += 1,
            CaseResult::Fail(msg) => {
                fail += 1;
                failures.push(msg);
            }
            CaseResult::Skip => skip += 1,
        }
    }

    ShufflingResult {
        pass,
        fail,
        skip,
        failures,
    }
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per shuffling test case in the same walk-order as
/// `run_shuffling_preset`. Called by the Phase 7 flat work-pool.
///
/// `preset` must be `"mainnet"` (round_count=90) or `"minimal"` (round_count=10).
pub fn enumerate_shuffling(root: &Path, preset: &'static str, row_ordinal: u32) -> Vec<CaseTask> {
    let round_count: u64 = match preset {
        "mainnet" => 90,
        "minimal" => 10,
        _ => 10,
    };

    let opts = WalkOpts {
        meta_required: false,
        inner_dir: None,
    };

    let cases: Vec<(PathBuf, _)> = walk_category(
        root,
        preset,
        "phase0",
        "shuffling",
        Some("core/shuffle"),
        opts,
    )
    .collect();

    cases
        .into_iter()
        .enumerate()
        .map(|(i, (case_dir, _meta))| {
            let case_ordinal = i as u32;
            let case_name = format!("phase0/shuffling/{}/{}", preset, dir_name(&case_dir));
            let run: CaseFn =
                Box::new(
                    move || match run_shuffling_case(&case_dir, &case_name, round_count) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                );
            CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            }
        })
        .collect()
}

// ── Case runner ───────────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
    #[allow(dead_code)]
    Skip,
}

fn run_shuffling_case(case_dir: &std::path::Path, case_name: &str, round_count: u64) -> CaseResult {
    let mapping_path = case_dir.join("mapping.yaml");
    if !mapping_path.exists() {
        return CaseResult::Fail(format!("{case_name}: missing mapping.yaml"));
    }
    let text = match std::fs::read_to_string(&mapping_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read mapping.yaml: {e}")),
    };
    let val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse mapping.yaml: {e}")),
    };

    // Decode seed: '0x...' hex string.
    let seed_str = match val.get("seed").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing 'seed'")),
    };
    let seed = match parse_hash256(seed_str) {
        Ok(h) => h,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let count = match val.get("count").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing 'count'")),
    };

    let mapping: Vec<u64> = match val.get("mapping").and_then(|v| v.as_sequence()) {
        Some(seq) => seq.iter().filter_map(|x| x.as_u64()).collect(),
        None => {
            if count == 0 {
                vec![]
            } else {
                return CaseResult::Fail(format!("{case_name}: missing or invalid 'mapping'"));
            }
        }
    };

    if count == 0 {
        return CaseResult::Pass;
    }

    if mapping.len() as u64 != count {
        return CaseResult::Fail(format!(
            "{case_name}: mapping length {} != count {}",
            mapping.len(),
            count
        ));
    }

    let got = compute_shuffled_permutation(count, &seed, round_count);

    for i in 0..count as usize {
        if got[i] != mapping[i] {
            return CaseResult::Fail(format!(
                "{case_name}: index {i}: got {}, expected {}",
                got[i], mapping[i]
            ));
        }
    }

    CaseResult::Pass
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_hash256(s: &str) -> Result<Hash256, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode seed: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("seed is {} bytes, expected 32", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from_array(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::fixtures_root;
    use crate::task::CaseOutcome;

    fn run_enumerate(preset: &'static str, row_ordinal: u32) -> (u64, u64, u64) {
        let Some(root) = fixtures_root() else {
            return (0, 0, 0);
        };
        let tasks = enumerate_shuffling(&root, preset, row_ordinal);
        let mut pass = 0u64;
        let mut fail = 0u64;
        let mut skip = 0u64;
        for task in tasks {
            match (task.run)() {
                CaseOutcome::Pass => pass += 1,
                CaseOutcome::Fail(_) => fail += 1,
                CaseOutcome::Skip => skip += 1,
            }
        }
        (pass, fail, skip)
    }

    #[test]
    fn enumerate_shuffling_parity_mainnet() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_shuffling_preset(&root, "mainnet", 90);
        let (ep, ef, es) = run_enumerate("mainnet", 4);
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_shuffling mainnet counts differ from run_shuffling_preset"
        );
    }

    #[test]
    fn enumerate_shuffling_parity_minimal() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_shuffling_preset(&root, "minimal", 10);
        let (ep, ef, es) = run_enumerate("minimal", 5);
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_shuffling minimal counts differ from run_shuffling_preset"
        );
    }
}
