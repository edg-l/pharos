//! BLS conformance dispatcher for `tests/general/altair/bls/`.
//!
//! # Coverage
//!
//! Only two sub-categories exist in consensus-spec-tests v1.6.1:
//!   - `eth_aggregate_pubkeys`
//!   - `eth_fast_aggregate_verify`
//!
//! The following six sub-categories have **no upstream fixtures** in v1.6.1
//! (risk R-bls from the M1 plan):
//!   - `sign`
//!   - `verify`
//!   - `aggregate`
//!   - `fast_aggregate_verify`
//!   - `aggregate_verify`
//!   - `batch_verify`
//!
//! These will be added when upstream fixtures appear. Until then they are not
//! enumerated in `all_categories()` and carry no conformance row.

use std::path::{Path, PathBuf};

use pharos_utils::{BLSPubkey, BLSSignature};

/// Compressed G2 point at infinity (96 bytes, first byte 0xC0, rest zeros).
/// Used by `eth_fast_aggregate_verify` per `specs/altair/bls.md:64`.
const G2_POINT_AT_INFINITY: &[u8] = &{
    let mut b = [0u8; 96];
    b[0] = 0xC0;
    b
};

use crate::fs_util::{dir_name, read_dir_sorted};
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Result of running all BLS tests.
pub struct BlsResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per BLS test case in the same walk-order as `run_bls`.
/// Called by the Phase 7 flat work-pool.
///
/// BLS tests are preset-independent (row 3: `("general", "bls", "-")`).
pub fn enumerate_bls(root: &Path, row_ordinal: u32) -> Vec<CaseTask> {
    let base = root.join("tests/general/altair/bls");
    if !base.is_dir() {
        return Vec::new();
    }

    let sub_cats: &[&'static str] = &["eth_aggregate_pubkeys", "eth_fast_aggregate_verify"];

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    for &sub_cat in sub_cats {
        let sub_dir = base.join(sub_cat);
        if !sub_dir.is_dir() {
            continue;
        }
        let inner = sub_dir.join("bls");
        let cases_dir: PathBuf = if inner.is_dir() { inner } else { sub_dir };

        let cases = match read_dir_sorted(&cases_dir) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for case_dir in cases {
            if !case_dir.is_dir() {
                continue;
            }
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!("general/bls/{}/{}", sub_cat, dir_name(&case_dir));
            let data_path = case_dir.join("data.yaml");

            let run: CaseFn = Box::new(move || {
                if !data_path.exists() {
                    return CaseOutcome::Skip;
                }
                let text = match std::fs::read_to_string(&data_path) {
                    Ok(t) => t,
                    Err(e) => return CaseOutcome::Fail(format!("{case_name}: read error: {e}")),
                };
                let val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        return CaseOutcome::Fail(format!("{case_name}: yaml parse error: {e}"));
                    }
                };
                let result = match sub_cat {
                    "eth_aggregate_pubkeys" => run_eth_aggregate_pubkeys(&case_name, &val),
                    "eth_fast_aggregate_verify" => run_eth_fast_aggregate_verify(&case_name, &val),
                    _ => return CaseOutcome::Skip,
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

    tasks
}

/// Run all BLS conformance tests under `root/tests/general/altair/bls/`.
pub fn run_bls(root: &Path) -> BlsResult {
    let base = root.join("tests/general/altair/bls");
    if !base.is_dir() {
        return BlsResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: vec![],
        };
    }

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();

    // Walk: eth_aggregate_pubkeys and eth_fast_aggregate_verify sub-categories.
    for sub_cat in &["eth_aggregate_pubkeys", "eth_fast_aggregate_verify"] {
        let sub_dir = base.join(sub_cat);
        if !sub_dir.is_dir() {
            continue;
        }
        // Each sub-category has a single inner dir named "bls" then case dirs.
        let inner = sub_dir.join("bls");
        let cases_dir = if inner.is_dir() {
            inner
        } else {
            sub_dir.clone()
        };

        let cases = match read_dir_sorted(&cases_dir) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for case_dir in cases {
            if !case_dir.is_dir() {
                continue;
            }
            let case_name = format!("general/bls/{}/{}", sub_cat, dir_name(&case_dir));
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
                "eth_aggregate_pubkeys" => run_eth_aggregate_pubkeys(&case_name, &val),
                "eth_fast_aggregate_verify" => run_eth_fast_aggregate_verify(&case_name, &val),
                _ => {
                    skip += 1;
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

    BlsResult {
        pass,
        fail,
        skip,
        failures,
    }
}

enum CaseResult {
    Pass,
    Fail(String),
}

// ── eth_aggregate_pubkeys ─────────────────────────────────────────────────────

fn run_eth_aggregate_pubkeys(case_name: &str, val: &serde_yaml_ng::Value) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = val.get("output");

    // input is a YAML sequence of 0x-prefixed pubkey hex strings
    let pubkeys = match input.as_sequence() {
        Some(seq) => seq,
        None => return CaseResult::Fail(format!("{case_name}: input is not a sequence")),
    };

    let parsed: Result<Vec<BLSPubkey>, _> = pubkeys
        .iter()
        .map(|v| {
            let s = v.as_str().unwrap_or("");
            parse_pubkey_hex(s)
        })
        .collect();

    match parsed {
        Ok(pks) => {
            // Aggregate the pubkeys
            let result = aggregate_pubkeys(&pks);
            match (result, expected_output) {
                (Ok(agg), Some(out)) if out.is_null() => {
                    // Expected failure but we produced a pubkey
                    CaseResult::Fail(format!(
                        "{case_name}: expected null output but got aggregated pubkey 0x{}",
                        hex::encode(agg.as_slice())
                    ))
                }
                (Ok(agg), Some(out)) => {
                    let expected_hex = out.as_str().unwrap_or("");
                    match parse_pubkey_hex(expected_hex) {
                        Ok(expected_pk) => {
                            if agg.as_slice() == expected_pk.as_slice() {
                                CaseResult::Pass
                            } else {
                                CaseResult::Fail(format!(
                                    "{case_name}: pubkey mismatch: got 0x{}, want {expected_hex}",
                                    hex::encode(agg.as_slice())
                                ))
                            }
                        }
                        Err(e) => {
                            CaseResult::Fail(format!("{case_name}: bad expected pubkey: {e}"))
                        }
                    }
                }
                (Ok(_), None) => CaseResult::Fail(format!("{case_name}: missing 'output' field")),
                (Err(_), Some(out)) if out.is_null() => CaseResult::Pass,
                (Err(e), _) => {
                    CaseResult::Fail(format!("{case_name}: unexpected aggregate error: {e}"))
                }
            }
        }
        Err(e) => {
            // Some input pubkey was invalid
            match expected_output {
                Some(out) if out.is_null() => CaseResult::Pass,
                _ => CaseResult::Fail(format!("{case_name}: parse error on valid input: {e}")),
            }
        }
    }
}

// ── eth_fast_aggregate_verify ─────────────────────────────────────────────────

fn run_eth_fast_aggregate_verify(case_name: &str, val: &serde_yaml_ng::Value) -> CaseResult {
    let input = match val.get("input") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'input'")),
    };
    let expected_output = match val.get("output") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing 'output'")),
    };
    let expected: bool = match expected_output.as_bool() {
        Some(b) => b,
        None => return CaseResult::Fail(format!("{case_name}: 'output' is not bool")),
    };

    let pubkeys_val = match input.get("pubkeys") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing input.pubkeys")),
    };
    let message_val = match input.get("message") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing input.message")),
    };
    let signature_val = match input.get("signature") {
        Some(v) => v,
        None => return CaseResult::Fail(format!("{case_name}: missing input.signature")),
    };

    let pubkeys: Result<Vec<BLSPubkey>, _> = pubkeys_val
        .as_sequence()
        .unwrap_or(&vec![])
        .iter()
        .map(|v| parse_pubkey_hex(v.as_str().unwrap_or("")))
        .collect();

    let pubkeys = match pubkeys {
        Ok(pks) => pks,
        Err(_) => {
            // Invalid pubkey encoding; spec says result is false.
            if !expected {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!("{case_name}: invalid pubkey but expected true"));
        }
    };

    let message_hex = message_val.as_str().unwrap_or("");
    let message = match parse_hex_bytes(message_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: bad message hex: {e}")),
    };

    let signature = match parse_signature_hex(signature_val.as_str().unwrap_or("")) {
        Ok(s) => s,
        Err(_) => {
            if !expected {
                return CaseResult::Pass;
            }
            return CaseResult::Fail(format!(
                "{case_name}: invalid signature encoding but expected true"
            ));
        }
    };

    // Per `specs/altair/bls.md:58-66`: empty pubkeys + G2_POINT_AT_INFINITY => true.
    let got = if pubkeys.is_empty() {
        signature.as_slice() == G2_POINT_AT_INFINITY
    } else {
        pharos_utils::bls::fast_aggregate_verify(&pubkeys, &message, &signature).unwrap_or_default()
    };

    if got == expected {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: got {got}, want {expected}"))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_pubkey_hex(s: &str) -> Result<BLSPubkey, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 48 {
        return Err(format!("pubkey is {} bytes, expected 48", bytes.len()));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(BLSPubkey::from_array(arr))
}

fn parse_signature_hex(s: &str) -> Result<BLSSignature, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 96 {
        return Err(format!("signature is {} bytes, expected 96", bytes.len()));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(&bytes);
    Ok(BLSSignature::from_array(arr))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| e.to_string())
}

fn aggregate_pubkeys(pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, String> {
    pharos_utils::bls::aggregate_pubkeys(pubkeys).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::fixtures_root;
    use crate::task::CaseOutcome;

    #[test]
    fn enumerate_bls_parity() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_bls(&root);
        let tasks = enumerate_bls(&root, 3);
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
            "enumerate_bls counts differ from run_bls"
        );
    }
}
