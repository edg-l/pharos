//! KZG conformance runner for `general/deneb/kzg/` fixtures.
//!
//! Covers all seven sub-categories:
//! - `blob_to_kzg_commitment`
//! - `compute_blob_kzg_proof`
//! - `compute_challenge`
//! - `compute_kzg_proof`
//! - `verify_blob_kzg_proof`
//! - `verify_blob_kzg_proof_batch`
//! - `verify_kzg_proof`
//!
//! All fixtures live under `<root>/general/deneb/kzg/<sub>/<suite>/<case>/data.yaml`.
//! Each case has an `input` map and an `output`; `null` output means the
//! operation must fail (invalid input).
//!
//! The runner skips cleanly when fixtures are absent (returns all-zero counts).

use std::path::Path;
use std::sync::Arc;

use pharos_kzg::KzgVerifier;

use crate::fs_util::{dir_name, read_dir_sorted};
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Result of running all KZG conformance tests.
pub struct KzgResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per KZG test case in the same walk-order as `run_kzg`.
/// Called by the Phase 7 flat work-pool.
///
/// KZG tests live under `<root>/general/deneb/kzg/` and are preset-independent
/// (row 84 in `rows.rs`: `("deneb", "kzg", "-")`).
pub fn enumerate_kzg(root: &Path, row_ordinal: u32) -> Vec<CaseTask> {
    let base = root.join("general/deneb/kzg");
    if !base.is_dir() {
        return Vec::new();
    }

    // Share one verifier across all cases via Arc.
    let verifier = Arc::new(KzgVerifier::mainnet());

    let sub_cats: &[&str] = &[
        "blob_to_kzg_commitment",
        "compute_blob_kzg_proof",
        "compute_challenge",
        "compute_kzg_proof",
        "verify_blob_kzg_proof",
        "verify_blob_kzg_proof_batch",
        "verify_kzg_proof",
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
                    "general/deneb/kzg/{}/{}/{}",
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
                        "blob_to_kzg_commitment" => {
                            run_blob_to_kzg_commitment(&verifier_clone, &case_name, &val)
                        }
                        "compute_blob_kzg_proof" => {
                            run_compute_blob_kzg_proof(&verifier_clone, &case_name, &val)
                        }
                        "compute_challenge" => run_compute_challenge(&case_name, &val),
                        "compute_kzg_proof" => {
                            run_compute_kzg_proof(&verifier_clone, &case_name, &val)
                        }
                        "verify_blob_kzg_proof" => {
                            run_verify_blob_kzg_proof(&verifier_clone, &case_name, &val)
                        }
                        "verify_blob_kzg_proof_batch" => {
                            run_verify_blob_kzg_proof_batch(&verifier_clone, &case_name, &val)
                        }
                        "verify_kzg_proof" => {
                            run_verify_kzg_proof(&verifier_clone, &case_name, &val)
                        }
                        unknown => {
                            return CaseOutcome::Fail(format!(
                                "{case_name}: unknown deneb/kzg subcat '{unknown}'"
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

/// Run all KZG conformance tests under `<root>/general/deneb/kzg/`.
///
/// Returns an all-zero result when the directory is absent (clean skip).
pub fn run_kzg(root: &Path) -> KzgResult {
    let base = root.join("general/deneb/kzg");
    if !base.is_dir() {
        return KzgResult {
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
        "blob_to_kzg_commitment",
        "compute_blob_kzg_proof",
        "compute_challenge",
        "compute_kzg_proof",
        "verify_blob_kzg_proof",
        "verify_blob_kzg_proof_batch",
        "verify_kzg_proof",
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
                    "general/deneb/kzg/{}/{}/{}",
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
                    "blob_to_kzg_commitment" => {
                        run_blob_to_kzg_commitment(&verifier, &case_name, &val)
                    }
                    "compute_blob_kzg_proof" => {
                        run_compute_blob_kzg_proof(&verifier, &case_name, &val)
                    }
                    "compute_challenge" => run_compute_challenge(&case_name, &val),
                    "compute_kzg_proof" => run_compute_kzg_proof(&verifier, &case_name, &val),
                    "verify_blob_kzg_proof" => {
                        run_verify_blob_kzg_proof(&verifier, &case_name, &val)
                    }
                    "verify_blob_kzg_proof_batch" => {
                        run_verify_blob_kzg_proof_batch(&verifier, &case_name, &val)
                    }
                    "verify_kzg_proof" => run_verify_kzg_proof(&verifier, &case_name, &val),
                    unknown => {
                        fail += 1;
                        failures.push(format!("{case_name}: unknown deneb/kzg subcat '{unknown}'"));
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

    KzgResult {
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

// ── blob_to_kzg_commitment ────────────────────────────────────────────────────

fn run_blob_to_kzg_commitment(
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

    match verifier.blob_to_kzg_commitment(&blob_bytes) {
        Ok(commitment) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected failure but got commitment 0x{}",
                    hex::encode(commitment)
                ));
            }
            let expected_hex = match expected_output.and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return CaseResult::Fail(format!("{case_name}: missing output string")),
            };
            let expected_bytes = match parse_hex_to_fixed::<48>(expected_hex) {
                Ok(b) => b,
                Err(e) => return CaseResult::Fail(format!("{case_name}: bad expected hex: {e}")),
            };
            if commitment == expected_bytes {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: commitment mismatch: got 0x{}, want {expected_hex}",
                    hex::encode(commitment)
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

// ── verify_blob_kzg_proof ─────────────────────────────────────────────────────

fn run_verify_blob_kzg_proof(
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

    let blob_hex = match input.get("blob").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.blob")),
    };
    let commitment_hex = match input.get("commitment").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitment")),
    };
    let proof_hex = match input.get("proof").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.proof")),
    };

    let blob_bytes = match parse_hex_to_fixed::<131072>(blob_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: blob hex parse failed on valid input"))
            };
        }
    };
    let commitment_bytes = match parse_hex_to_fixed::<48>(commitment_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: commitment hex parse failed on valid input"
                ))
            };
        }
    };
    let proof_bytes = match parse_hex_to_fixed::<48>(proof_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: proof hex parse failed on valid input"
                ))
            };
        }
    };

    match verifier.verify_blob_kzg_proof(&blob_bytes, &commitment_bytes, &proof_bytes) {
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
                    "{case_name}: verify result mismatch: got {valid}, want {expected}"
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

// ── verify_blob_kzg_proof_batch ───────────────────────────────────────────────

fn run_verify_blob_kzg_proof_batch(
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

    let blobs_val = match input.get("blobs").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.blobs")),
    };
    let commitments_val = match input.get("commitments").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitments")),
    };
    let proofs_val = match input.get("proofs").and_then(|v| v.as_sequence()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.proofs")),
    };

    let blobs: Result<Vec<[u8; 131072]>, _> = blobs_val
        .iter()
        .map(|v| parse_hex_to_fixed::<131072>(v.as_str().unwrap_or("")))
        .collect();
    let commitments: Result<Vec<[u8; 48]>, _> = commitments_val
        .iter()
        .map(|v| parse_hex_to_fixed::<48>(v.as_str().unwrap_or("")))
        .collect();
    let proofs: Result<Vec<[u8; 48]>, _> = proofs_val
        .iter()
        .map(|v| parse_hex_to_fixed::<48>(v.as_str().unwrap_or("")))
        .collect();

    let (blobs, commitments, proofs) = match (blobs, commitments, proofs) {
        (Ok(b), Ok(c), Ok(p)) => (b, c, p),
        _ => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: hex parse failed on valid input"))
            };
        }
    };

    match verifier.verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs) {
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
                    "{case_name}: batch verify mismatch: got {valid}, want {expected}"
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

// ── compute_kzg_proof ─────────────────────────────────────────────────────────

/// Fixture format: `input: {blob, z}` → `output: [proof_hex, y_hex]` or null.
fn run_compute_kzg_proof(
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
    let z_hex = match input.get("z").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.z")),
    };

    let blob_bytes = match parse_hex_to_fixed::<131072>(blob_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: blob hex parse failed on valid input"))
            };
        }
    };
    let z_bytes = match parse_hex_to_fixed::<32>(z_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: z hex parse failed on valid input"))
            };
        }
    };

    match verifier.compute_kzg_proof(&blob_bytes, &z_bytes) {
        Ok((proof, y)) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected failure but compute_kzg_proof succeeded"
                ));
            }
            // output is [proof_hex, y_hex]
            let outer = match expected_output.and_then(|v| v.as_sequence()) {
                Some(s) if s.len() == 2 => s,
                _ => {
                    return CaseResult::Fail(format!(
                        "{case_name}: output must be a 2-element sequence [proof, y]"
                    ));
                }
            };
            let expected_proof = match outer[0].as_str().map(parse_hex_to_fixed::<48>) {
                Some(Ok(b)) => b,
                _ => {
                    return CaseResult::Fail(format!("{case_name}: output[0] (proof) bad hex"));
                }
            };
            let expected_y = match outer[1].as_str().map(parse_hex_to_fixed::<32>) {
                Some(Ok(b)) => b,
                _ => {
                    return CaseResult::Fail(format!("{case_name}: output[1] (y) bad hex"));
                }
            };
            if proof != expected_proof {
                return CaseResult::Fail(format!(
                    "{case_name}: proof mismatch: got 0x{}, want 0x{}",
                    hex::encode(proof),
                    hex::encode(expected_proof)
                ));
            }
            if y != expected_y {
                return CaseResult::Fail(format!(
                    "{case_name}: y mismatch: got 0x{}, want 0x{}",
                    hex::encode(y),
                    hex::encode(expected_y)
                ));
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

// ── compute_blob_kzg_proof ────────────────────────────────────────────────────

/// Fixture format: `input: {blob, commitment}` → `output: proof_hex` or null.
fn run_compute_blob_kzg_proof(
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
    let commitment_hex = match input.get("commitment").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitment")),
    };

    let blob_bytes = match parse_hex_to_fixed::<131072>(blob_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: blob hex parse failed on valid input"))
            };
        }
    };
    let commitment_bytes = match parse_hex_to_fixed::<48>(commitment_hex) {
        Ok(b) => b,
        Err(_) => {
            return if expect_failure {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: commitment hex parse failed on valid input"
                ))
            };
        }
    };

    match verifier.compute_blob_kzg_proof(&blob_bytes, &commitment_bytes) {
        Ok(proof) => {
            if expect_failure {
                return CaseResult::Fail(format!(
                    "{case_name}: expected failure but compute_blob_kzg_proof succeeded"
                ));
            }
            let expected_hex = match expected_output.and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return CaseResult::Fail(format!("{case_name}: missing output string")),
            };
            let expected_bytes = match parse_hex_to_fixed::<48>(expected_hex) {
                Ok(b) => b,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: bad expected hex: {e}"));
                }
            };
            if proof == expected_bytes {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: proof mismatch: got 0x{}, want {expected_hex}",
                    hex::encode(proof)
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

// ── compute_challenge ─────────────────────────────────────────────────────────

/// Fixture format: `input: {blob, commitment}` → `output: challenge_hex` (32 bytes).
///
/// The deneb `compute_challenge` is Fiat-Shamir; the fixture never has a null output
/// (there are no "invalid input" cases — the hash always succeeds).  However, if the
/// blob or commitment fails to parse we propagate that as a failure.
fn run_compute_challenge(case_name: &str, val: &serde_yaml_ng::Value) -> CaseResult {
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
    let commitment_hex = match input.get("commitment").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitment")),
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
    let commitment_bytes = match parse_hex_to_fixed::<48>(commitment_hex) {
        Ok(b) => b,
        Err(e) => {
            if expect_failure {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: commitment hex parse failed: {e}"));
        }
    };

    let challenge = KzgVerifier::compute_challenge(&blob_bytes, &commitment_bytes);

    if expect_failure {
        return CaseResult::Fail(format!(
            "{case_name}: expected failure but compute_challenge succeeded"
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

// ── verify_kzg_proof ──────────────────────────────────────────────────────────

/// Fixture format: `input: {commitment, z, y, proof}` → `output: bool` or null.
fn run_verify_kzg_proof(
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

    let commitment_hex = match input.get("commitment").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.commitment")),
    };
    let z_hex = match input.get("z").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.z")),
    };
    let y_hex = match input.get("y").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.y")),
    };
    let proof_hex = match input.get("proof").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing input.proof")),
    };

    let commitment_bytes = parse_hex_to_fixed::<48>(commitment_hex);
    let z_bytes = parse_hex_to_fixed::<32>(z_hex);
    let y_bytes = parse_hex_to_fixed::<32>(y_hex);
    let proof_bytes = parse_hex_to_fixed::<48>(proof_hex);

    let (commitment_bytes, z_bytes, y_bytes, proof_bytes) =
        match (commitment_bytes, z_bytes, y_bytes, proof_bytes) {
            (Ok(c), Ok(z), Ok(y), Ok(p)) => (c, z, y, p),
            _ => {
                return if expect_failure {
                    CaseResult::Pass
                } else {
                    CaseResult::Fail(format!("{case_name}: hex parse failed on valid input"))
                };
            }
        };

    match verifier.verify_kzg_proof(&commitment_bytes, &z_bytes, &y_bytes, &proof_bytes) {
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
                    "{case_name}: verify result mismatch: got {valid}, want {expected}"
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
    fn enumerate_kzg_parity() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_kzg(&root);
        let tasks = enumerate_kzg(&root, 84);
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
            "enumerate_kzg counts differ from run_kzg"
        );
    }
}
