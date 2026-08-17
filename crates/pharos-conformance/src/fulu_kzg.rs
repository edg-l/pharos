//! KZG conformance runner for `general/fulu/kzg/` fixtures (EIP-7594 PeerDAS).
//!
//! Covers all five sub-categories:
//! - `compute_cells`
//! - `compute_cells_and_kzg_proofs`
//! - `compute_verify_cell_kzg_proof_batch_challenge`
//! - `recover_cells_and_kzg_proofs`
//! - `verify_cell_kzg_proof_batch`
//!
//! All fixtures live under `<root>/general/fulu/kzg/<sub>/<suite>/<case>/data.yaml`.
//! Each case has an `input` map and an `output`; `null` output means the
//! operation must fail (invalid input).
//!
//! The runner skips cleanly when fixtures are absent (returns all-zero counts).

use std::path::Path;
use std::sync::Arc;

use pharos_kzg::KzgVerifier;

use crate::fs_util::{dir_name, read_dir_sorted};
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Result of running all Fulu KZG conformance tests.
pub struct FuluKzgResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per Fulu KZG test case in the same walk-order as
/// `run_fulu_kzg`.  Called by the flat work-pool.
///
/// KZG tests live under `<root>/general/fulu/kzg/` and are preset-independent
/// (`("fulu", "kzg", "-")` in `rows.rs`).
pub fn enumerate_fulu_kzg(root: &Path, row_ordinal: u32) -> Vec<CaseTask> {
    let base = root.join("general/fulu/kzg");
    if !base.is_dir() {
        return Vec::new();
    }

    // Share one verifier across all cases via Arc.
    let verifier = Arc::new(KzgVerifier::mainnet());

    let sub_cats: &[&str] = &[
        "compute_cells",
        "compute_cells_and_kzg_proofs",
        "compute_verify_cell_kzg_proof_batch_challenge",
        "recover_cells_and_kzg_proofs",
        "verify_cell_kzg_proof_batch",
    ];

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    for &sub_cat in sub_cats {
        let sub_dir = base.join(sub_cat);
        if !sub_dir.is_dir() {
            continue;
        }

        let suites = match read_dir_sorted(&sub_dir) {
            Ok(s) => s,
            Err(_) => continue,
        };

        for suite_dir in suites {
            if !suite_dir.is_dir() {
                continue;
            }
            let cases = match read_dir_sorted(&suite_dir) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let suite_name = dir_name(&suite_dir);

            for case_dir in cases {
                if !case_dir.is_dir() {
                    continue;
                }
                let case_ordinal = ordinal;
                ordinal += 1;

                let case_name = format!(
                    "general/fulu/kzg/{}/{}/{}",
                    sub_cat,
                    suite_name,
                    dir_name(&case_dir)
                );
                let data_path = case_dir.join("data.yaml");
                let verifier_clone = Arc::clone(&verifier);
                let sub_cat_owned: &'static str = sub_cat;

                let run: CaseFn = Box::new(move || {
                    if !data_path.exists() {
                        return CaseOutcome::Skip;
                    }
                    let text = match std::fs::read_to_string(&data_path) {
                        Ok(t) => t,
                        Err(e) => {
                            return CaseOutcome::Fail(format!("{case_name}: read error: {e}"));
                        }
                    };
                    let val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
                        Ok(v) => v,
                        Err(e) => {
                            return CaseOutcome::Fail(format!(
                                "{case_name}: yaml parse error: {e}"
                            ));
                        }
                    };
                    let result = match sub_cat_owned {
                        "compute_cells" => run_compute_cells(&verifier_clone, &case_name, &val),
                        "compute_cells_and_kzg_proofs" => {
                            run_compute_cells_and_kzg_proofs(&verifier_clone, &case_name, &val)
                        }
                        "compute_verify_cell_kzg_proof_batch_challenge" => {
                            run_compute_verify_cell_kzg_proof_batch_challenge(&case_name, &val)
                        }
                        "recover_cells_and_kzg_proofs" => {
                            run_recover_cells_and_kzg_proofs(&verifier_clone, &case_name, &val)
                        }
                        "verify_cell_kzg_proof_batch" => {
                            run_verify_cell_kzg_proof_batch(&verifier_clone, &case_name, &val)
                        }
                        unknown => {
                            return CaseOutcome::Fail(format!(
                                "{case_name}: unknown fulu/kzg subcat '{unknown}'"
                            ));
                        }
                    };
                    match result {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                });

                tasks.push(CaseTask {
                    row_ordinal,
                    case_ordinal,
                    run,
                });
            }
        }
    }

    tasks
}

/// Run all Fulu KZG conformance tests under `<root>/general/fulu/kzg/`.
///
/// Returns an all-zero result when the directory is absent (clean skip).
pub fn run_fulu_kzg(root: &Path) -> FuluKzgResult {
    let base = root.join("general/fulu/kzg");
    if !base.is_dir() {
        return FuluKzgResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: vec![],
        };
    }

    // Instantiate the mainnet verifier once; it is shared across all cases.
    let verifier = KzgVerifier::mainnet();

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();

    for sub_cat in &[
        "compute_cells",
        "compute_cells_and_kzg_proofs",
        "compute_verify_cell_kzg_proof_batch_challenge",
        "recover_cells_and_kzg_proofs",
        "verify_cell_kzg_proof_batch",
    ] {
        let sub_dir = base.join(sub_cat);
        if !sub_dir.is_dir() {
            continue;
        }

        // Fixtures layout: <sub>/<suite>/<case>/data.yaml
        let suites = match read_dir_sorted(&sub_dir) {
            Ok(s) => s,
            Err(_) => continue,
        };

        for suite_dir in suites {
            if !suite_dir.is_dir() {
                continue;
            }
            let cases = match read_dir_sorted(&suite_dir) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for case_dir in cases {
                if !case_dir.is_dir() {
                    continue;
                }
                let case_name = format!(
                    "general/fulu/kzg/{}/{}/{}",
                    sub_cat,
                    dir_name(&suite_dir),
                    dir_name(&case_dir)
                );
                let data_path = case_dir.join("data.yaml");
                if !data_path.exists() {
                    skip += 1;
                    continue;
                }

                let text = match std::fs::read_to_string(&data_path) {
                    Ok(t) => t,
                    Err(e) => {
                        fail += 1;
                        failures.push(format!("{case_name}: read error: {e}"));
                        continue;
                    }
                };

                let val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        fail += 1;
                        failures.push(format!("{case_name}: yaml parse error: {e}"));
                        continue;
                    }
                };

                let result = match *sub_cat {
                    "compute_cells" => run_compute_cells(&verifier, &case_name, &val),
                    "compute_cells_and_kzg_proofs" => {
                        run_compute_cells_and_kzg_proofs(&verifier, &case_name, &val)
                    }
                    "compute_verify_cell_kzg_proof_batch_challenge" => {
                        run_compute_verify_cell_kzg_proof_batch_challenge(&case_name, &val)
                    }
                    "recover_cells_and_kzg_proofs" => {
                        run_recover_cells_and_kzg_proofs(&verifier, &case_name, &val)
                    }
                    "verify_cell_kzg_proof_batch" => {
                        run_verify_cell_kzg_proof_batch(&verifier, &case_name, &val)
                    }
                    unknown => {
                        fail += 1;
                        failures.push(format!("{case_name}: unknown fulu/kzg subcat '{unknown}'"));
                        continue;
                    }
                };

                match result {
                    CaseResult::Pass => pass += 1,
                    CaseResult::Fail(msg) => {
                        fail += 1;
                        failures.push(msg);
                    }
                }
            }
        }
    }

    FuluKzgResult {
        pass,
        fail,
        skip,
        failures,
    }
}

// ── Per-case result ───────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
}

// ── compute_cells ─────────────────────────────────────────────────────────────

fn run_compute_cells(
    verifier: &KzgVerifier,
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = val.get("output");
    let expect_failure =
        matches!(expected_output, Some(v) if v.is_null()) || expected_output.is_none();

    let blob_hex = match input.get("blob").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.blob")),
    };

    let blob_bytes = match parse_hex_to_fixed::<131072>(blob_hex) {
        Ok(b) => b,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: blob hex parse failed: {e}"));
        }
    };

    match verifier.compute_cells(&blob_bytes) {
        Ok(cells) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected failure but compute_cells succeeded"
                ));
            }
            let expected_cells = match expected_output.and_then(|v| v.as_sequence()) {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output is not a sequence"));
                }
            };
            if expected_cells.len() != 128 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected 128 output cells, got {}",
                    expected_cells.len()
                ));
            }
            for (i, exp_hex_val) in expected_cells.iter().enumerate() {
                let exp_hex = match exp_hex_val.as_str() {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[{i}] is not a string"
                        ));
                    }
                };
                let exp_cell = match parse_hex_to_fixed::<2048>(exp_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[{i}] hex parse failed: {e}"
                        ));
                    }
                };
                if cells.cell(i) != &exp_cell {
                    return CaseResult::Fail(format!("{case_name}: cell[{i}] mismatch"));
                }
            }
            CaseResult::Pass
        }
        Err(_) => {
            if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: unexpected KZG error on valid input"))
            }
        }
    }
}

// ── compute_cells_and_kzg_proofs ──────────────────────────────────────────────

fn run_compute_cells_and_kzg_proofs(
    verifier: &KzgVerifier,
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = val.get("output");
    let expect_failure =
        matches!(expected_output, Some(v) if v.is_null()) || expected_output.is_none();

    let blob_hex = match input.get("blob").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.blob")),
    };

    let blob_bytes = match parse_hex_to_fixed::<131072>(blob_hex) {
        Ok(b) => b,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: blob hex parse failed: {e}"));
        }
    };

    match verifier.compute_cells_and_kzg_proofs(&blob_bytes) {
        Ok((cells, proofs)) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected failure but compute_cells_and_kzg_proofs succeeded"
                ));
            }
            // output is [cells_list, proofs_list]
            let outer = match expected_output.and_then(|v| v.as_sequence()) {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output is not a sequence"));
                }
            };
            if outer.len() != 2 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected output length 2, got {}",
                    outer.len()
                ));
            }
            let expected_cells = match outer[0].as_sequence() {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output[0] is not a sequence"));
                }
            };
            let expected_proofs = match outer[1].as_sequence() {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output[1] is not a sequence"));
                }
            };
            if expected_cells.len() != 128 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected 128 output cells, got {}",
                    expected_cells.len()
                ));
            }
            if expected_proofs.len() != 128 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected 128 output proofs, got {}",
                    expected_proofs.len()
                ));
            }
            // Compare cells
            for (i, exp_hex_val) in expected_cells.iter().enumerate() {
                let exp_hex = match exp_hex_val.as_str() {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[0][{i}] is not a string"
                        ));
                    }
                };
                let exp_cell = match parse_hex_to_fixed::<2048>(exp_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[0][{i}] hex parse failed: {e}"
                        ));
                    }
                };
                if cells.cell(i) != &exp_cell {
                    return CaseResult::Fail(format!("{case_name}: cell[{i}] mismatch"));
                }
            }
            // Compare proofs
            for (i, exp_hex_val) in expected_proofs.iter().enumerate() {
                let exp_hex = match exp_hex_val.as_str() {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[1][{i}] is not a string"
                        ));
                    }
                };
                let exp_proof = match parse_hex_to_fixed::<48>(exp_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[1][{i}] hex parse failed: {e}"
                        ));
                    }
                };
                if proofs[i] != exp_proof {
                    return CaseResult::Fail(format!("{case_name}: proof[{i}] mismatch"));
                }
            }
            CaseResult::Pass
        }
        Err(_) => {
            if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: unexpected KZG error on valid input"))
            }
        }
    }
}

// ── recover_cells_and_kzg_proofs ──────────────────────────────────────────────

fn run_recover_cells_and_kzg_proofs(
    verifier: &KzgVerifier,
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = val.get("output");
    let expect_failure =
        matches!(expected_output, Some(v) if v.is_null()) || expected_output.is_none();

    let cell_indices_val = match input.get("cell_indices").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.cell_indices")),
    };
    let cells_val = match input.get("cells").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.cells")),
    };

    let cell_indices: Result<Vec<u64>, _> = cell_indices_val
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("{case_name}: cell_index is not u64"))
        })
        .collect();
    let cell_indices = match cell_indices {
        Ok(v) => v,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(e);
        }
    };

    let cells_owned: Result<Vec<[u8; 2048]>, _> = cells_val
        .iter()
        .map(|v| parse_hex_to_fixed::<2048>(v.as_str().unwrap_or("")))
        .collect();
    let cells_owned = match cells_owned {
        Ok(v) => v,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: cell hex parse failed: {e}"));
        }
    };
    let cell_refs: Vec<&[u8; 2048]> = cells_owned.iter().collect();

    match verifier.recover_cells_and_kzg_proofs(&cell_indices, &cell_refs) {
        Ok((recovered_cells, recovered_proofs)) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected failure but recover_cells_and_kzg_proofs succeeded"
                ));
            }
            // output is [cells_list, proofs_list]
            let outer = match expected_output.and_then(|v| v.as_sequence()) {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output is not a sequence"));
                }
            };
            if outer.len() != 2 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected output length 2, got {}",
                    outer.len()
                ));
            }
            let expected_cells = match outer[0].as_sequence() {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output[0] is not a sequence"));
                }
            };
            let expected_proofs = match outer[1].as_sequence() {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!("{case_name}: output[1] is not a sequence"));
                }
            };
            if expected_cells.len() != 128 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected 128 recovered cells, got {}",
                    expected_cells.len()
                ));
            }
            if expected_proofs.len() != 128 {
                return CaseResult::Fail(format!(
                    "{case_name}: expected 128 recovered proofs, got {}",
                    expected_proofs.len()
                ));
            }
            for (i, exp_hex_val) in expected_cells.iter().enumerate() {
                let exp_hex = match exp_hex_val.as_str() {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[0][{i}] is not a string"
                        ));
                    }
                };
                let exp_cell = match parse_hex_to_fixed::<2048>(exp_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[0][{i}] hex parse failed: {e}"
                        ));
                    }
                };
                if recovered_cells.cell(i) != &exp_cell {
                    return CaseResult::Fail(format!("{case_name}: recovered_cell[{i}] mismatch"));
                }
            }
            for (i, exp_hex_val) in expected_proofs.iter().enumerate() {
                let exp_hex = match exp_hex_val.as_str() {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[1][{i}] is not a string"
                        ));
                    }
                };
                let exp_proof = match parse_hex_to_fixed::<48>(exp_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: output[1][{i}] hex parse failed: {e}"
                        ));
                    }
                };
                if recovered_proofs[i] != exp_proof {
                    return CaseResult::Fail(format!("{case_name}: recovered_proof[{i}] mismatch"));
                }
            }
            CaseResult::Pass
        }
        Err(_) => {
            if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: unexpected KZG error on valid input"))
            }
        }
    }
}

// ── verify_cell_kzg_proof_batch ───────────────────────────────────────────────

fn run_verify_cell_kzg_proof_batch(
    verifier: &KzgVerifier,
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = val.get("output");
    // null output => operation must fail (invalid inputs).
    let expect_failure =
        matches!(expected_output, Some(v) if v.is_null()) || expected_output.is_none();

    // Fixture uses `commitments`, `cell_indices`, `cells`, `proofs`.
    // (Confirmed from actual fixture inspection: NOT `row_commitments`/`column_indices`.)
    let commitments_val = match input.get("commitments").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitments")),
    };
    let cell_indices_val = match input.get("cell_indices").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.cell_indices")),
    };
    let cells_val = match input.get("cells").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.cells")),
    };
    let proofs_val = match input.get("proofs").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.proofs")),
    };

    let commitments_owned: Result<Vec<[u8; 48]>, _> = commitments_val
        .iter()
        .map(|v| parse_hex_to_fixed::<48>(v.as_str().unwrap_or("")))
        .collect();
    let cell_indices: Result<Vec<u64>, _> = cell_indices_val
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("{case_name}: cell_index is not u64"))
        })
        .collect();
    let cells_owned: Result<Vec<[u8; 2048]>, _> = cells_val
        .iter()
        .map(|v| parse_hex_to_fixed::<2048>(v.as_str().unwrap_or("")))
        .collect();
    let proofs_owned: Result<Vec<[u8; 48]>, _> = proofs_val
        .iter()
        .map(|v| parse_hex_to_fixed::<48>(v.as_str().unwrap_or("")))
        .collect();

    let (commitments_owned, cell_indices, cells_owned, proofs_owned) =
        match (commitments_owned, cell_indices, cells_owned, proofs_owned) {
            (Ok(c), Ok(ci), Ok(cs), Ok(p)) => (c, ci, cs, p),
            _ => {
                return if expect_failure {
                    CaseResult::Pass
                } else {
                    CaseResult::Fail(format!("{case_name}: hex parse failed on valid input"))
                };
            }
        };

    let commitment_refs: Vec<&[u8; 48]> = commitments_owned.iter().collect();
    let cell_refs: Vec<&[u8; 2048]> = cells_owned.iter().collect();
    let proof_refs: Vec<&[u8; 48]> = proofs_owned.iter().collect();

    match verifier.verify_cell_kzg_proof_batch(
        &commitment_refs,
        &cell_indices,
        &cell_refs,
        &proof_refs,
    ) {
        Ok(valid) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected KZG error but got Ok({valid})"
                ));
            }
            let expected: bool = match expected_output.and_then(|v| v.as_bool()) {
                Some(b) => b,
                None => return CaseResult::Fail(format!("{case_name}: 'output' is not bool")),
            };
            if valid == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: verify_cell result mismatch: got {valid}, want {expected}"
                ))
            }
        }
        Err(_) => {
            if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: unexpected KZG error on valid input"))
            }
        }
    }
}

// ── compute_verify_cell_kzg_proof_batch_challenge ─────────────────────────────

/// Fixture format:
/// ```yaml
/// input:
///   commitments: [hex48, ...]
///   commitment_indices: [u64, ...]
///   cell_indices: [u64, ...]
///   cosets_evals: [[hex32, ...], ...]  # each inner list has 64 field elements
///   proofs: [hex48, ...]
/// output: hex32  # 32-byte BLS field element
/// ```
///
/// Implemented in-house per `specs/fulu/polynomial-commitments-sampling.md`.
fn run_compute_verify_cell_kzg_proof_batch_challenge(
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = val.get("output");
    let expect_failure =
        matches!(expected_output, Some(v) if v.is_null()) || expected_output.is_none();

    // Parse commitments
    let commitments_val = match input.get("commitments").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitments")),
    };
    let commitments_owned: Result<Vec<[u8; 48]>, _> = commitments_val
        .iter()
        .map(|v| parse_hex_to_fixed::<48>(v.as_str().unwrap_or("")))
        .collect();
    let commitments_owned = match commitments_owned {
        Ok(v) => v,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: commitments hex parse failed: {e}"));
        }
    };

    // Parse commitment_indices
    let commitment_indices_val = match input
        .get("commitment_indices")
        .and_then(|v| v.as_sequence())
    {
        Some(s) => s,
        None => {
            return CaseResult::Fail(format!("{case_name}: missing input.commitment_indices"));
        }
    };
    let commitment_indices: Result<Vec<u64>, _> = commitment_indices_val
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("{case_name}: commitment_index is not u64"))
        })
        .collect();
    let commitment_indices = match commitment_indices {
        Ok(v) => v,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(e);
        }
    };

    // Parse cell_indices
    let cell_indices_val = match input.get("cell_indices").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.cell_indices")),
    };
    let cell_indices: Result<Vec<u64>, _> = cell_indices_val
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("{case_name}: cell_index is not u64"))
        })
        .collect();
    let cell_indices = match cell_indices {
        Ok(v) => v,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(e);
        }
    };

    // Parse cosets_evals: list of lists of 32-byte field elements.
    // Each inner list has FIELD_ELEMENTS_PER_CELL = 64 field elements.
    // We reconstruct each "cell" as a 2048-byte array (64 × 32 bytes).
    let cosets_evals_val = match input.get("cosets_evals").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.cosets_evals")),
    };
    let mut cells_owned: Vec<[u8; 2048]> = Vec::with_capacity(cosets_evals_val.len());
    for (i, coset_val) in cosets_evals_val.iter().enumerate() {
        let evals = match coset_val.as_sequence() {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!(
                    "{case_name}: cosets_evals[{i}] is not a sequence"
                ));
            }
        };
        if evals.len() != 64 {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!(
                "{case_name}: cosets_evals[{i}] has {} elements, expected 64",
                evals.len()
            ));
        }
        let mut cell = [0u8; 2048];
        for (j, eval_val) in evals.iter().enumerate() {
            let eval_hex = match eval_val.as_str() {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: cosets_evals[{i}][{j}] is not a string"
                    ));
                }
            };
            let eval_bytes = match parse_hex_to_fixed::<32>(eval_hex) {
                Ok(b) => b,
                Err(e) => {
                    if expect_failure {
                        return CaseResult::Pass;
                    }
                    return CaseResult::Fail(format!(
                        "{case_name}: cosets_evals[{i}][{j}] hex parse failed: {e}"
                    ));
                }
            };
            cell[j * 32..(j + 1) * 32].copy_from_slice(&eval_bytes);
        }
        cells_owned.push(cell);
    }

    // Parse proofs
    let proofs_val = match input.get("proofs").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.proofs")),
    };
    let proofs_owned: Result<Vec<[u8; 48]>, _> = proofs_val
        .iter()
        .map(|v| parse_hex_to_fixed::<48>(v.as_str().unwrap_or("")))
        .collect();
    let proofs_owned = match proofs_owned {
        Ok(v) => v,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: proofs hex parse failed: {e}"));
        }
    };

    let commitment_refs: Vec<&[u8; 48]> = commitments_owned.iter().collect();
    let cell_refs: Vec<&[u8; 2048]> = cells_owned.iter().collect();
    let proof_refs: Vec<&[u8; 48]> = proofs_owned.iter().collect();

    let challenge = KzgVerifier::compute_verify_cell_kzg_proof_batch_challenge(
        &commitment_refs,
        &commitment_indices,
        &cell_indices,
        &cell_refs,
        &proof_refs,
    );

    if expect_failure {
        return CaseResult::Fail(format!(
            "{case_name}: expected failure but challenge computation succeeded"
        ));
    }

    let expected_hex = match expected_output.and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing output string")),
    };
    let expected_bytes = match parse_hex_to_fixed::<32>(expected_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: bad expected hex: {e}")),
    };

    if challenge == expected_bytes {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!(
            "{case_name}: challenge mismatch: got 0x{}, want {expected_hex}",
            hex::encode(challenge)
        ))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a `0x`-prefixed hex string into a fixed-size byte array.
fn parse_hex_to_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != N {
        return Err(format!("expected {N} bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::fixtures_root;
    use crate::task::CaseOutcome;

    #[test]
    fn enumerate_fulu_kzg_parity() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_fulu_kzg(&root);
        let tasks = enumerate_fulu_kzg(&root, 133);
        let mut ep = 0u64;
        let mut ef = 0u64;
        let mut es = 0u64;
        for task in tasks {
            match (task.run)() {
                CaseOutcome::Pass => ep += 1,
                CaseOutcome::Fail(_) => ef += 1,
                CaseOutcome::Skip => es += 1,
            }
        }
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_fulu_kzg counts differ from run_fulu_kzg"
        );
    }
}
