//! Shuffling conformance dispatcher.
//!
//! Covers `<preset>/phase0/shuffling/core/shuffle/<case>/mapping.yaml`.
//!
//! Exception S4: no `pyspec_tests/` level, no `meta.yaml`.
//! Uses `WalkOpts { meta_required: false, inner_dir: None }`.
//!
//! Tests both `mainnet` and `minimal` presets.

use std::path::{Path, PathBuf};

use crate::fixture_walker::{WalkOpts, walk_category};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};
use pharos_stf::phase0::shuffling::compute_shuffled_permutation;
use pharos_utils::Hash256;

/// Produce one `CaseTask` per shuffling test case in the same walk-order as
/// `run_shuffling_preset`. Called by the flat work-pool.
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
