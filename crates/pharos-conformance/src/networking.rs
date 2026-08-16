//! Networking conformance runner for `<preset>/fulu/networking/` fixtures.
//!
//! Fulu's `networking` category (EIP-7594 PeerDAS) ships two flavours of
//! fixture:
//!
//! - **Pure DAS-core custody helpers** — `get_custody_groups` and
//!   `compute_columns_for_custody_group`. These are deterministic functions
//!   of `(node_id, custody_group_count)` / `(custody_group)` with a `result`
//!   list in `meta.yaml`; pharos implements both in
//!   `pharos_stf::fulu::data_columns`, so we run them for real.
//! - **Gossip-validator condition fixtures** — `gossip_attester_slashing`,
//!   `gossip_bls_to_execution_change`, `gossip_proposer_slashing`,
//!   `gossip_sync_committee_*`. These require a wired gossip-validator harness
//!   with a live store; the offline conformance writer does not exercise them
//!   (the validators themselves ship in `pharos-node` and are unit-tested).
//!   We enumerate their cases as **skips** so the gap is visible in the report
//!   rather than hidden behind a placeholder row.
//!
//! Fixtures layout: `<root>/<preset>/fulu/networking/<handler>/<suite>/<case>/meta.yaml`.
//! The runner skips cleanly when fixtures are absent (returns no tasks).

use std::path::Path;

use pharos_stf::fulu::data_columns::{compute_columns_for_custody_group, get_custody_groups};
use pharos_types::{MainnetBeaconSpec, MinimalBeaconSpec};

use crate::fs_util::{dir_name, read_dir_sorted};
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Handlers we run for real (deterministic DAS-core custody helpers). Every
/// other handler — the gossip validators (`gossip_attester_slashing`,
/// `gossip_bls_to_execution_change`, `gossip_proposer_slashing`,
/// `gossip_sync_committee_*`) and any future upstream handler — is enumerated
/// as a skip (those need a live store + wired gossip harness, not the offline
/// writer).
const RUNNABLE_HANDLERS: &[&str] = &["compute_columns_for_custody_group", "get_custody_groups"];

// ── Flat-pool enumerate ─────────────────────────────────────────────────────────

/// Produce one `CaseTask` per `<preset>/fulu/networking/` case. The two custody
/// helpers run for real; every other handler's cases are skips. Called by the
/// flat work-pool via `enumerate_row`.
pub fn enumerate_networking(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let base = root.join(preset).join(fork).join("networking");
    if !base.is_dir() {
        return Vec::new();
    }

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    // Walk handlers in sorted order so enumeration is deterministic.
    let handlers = match read_dir_sorted(&base) {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    for handler_dir in handlers {
        if !handler_dir.is_dir() {
            continue;
        }
        let handler = dir_name(&handler_dir);
        let runnable = RUNNABLE_HANDLERS.contains(&handler.as_str());

        let suites = match read_dir_sorted(&handler_dir) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for suite_dir in suites {
            if !suite_dir.is_dir() {
                continue;
            }
            let suite_name = dir_name(&suite_dir);
            let cases = match read_dir_sorted(&suite_dir) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for case_dir in cases {
                if !case_dir.is_dir() {
                    continue;
                }
                let case_ordinal = ordinal;
                ordinal += 1;

                let case_name = format!(
                    "{preset}/{fork}/networking/{}/{}/{}",
                    handler,
                    suite_name,
                    dir_name(&case_dir)
                );
                let meta_path = case_dir.join("meta.yaml");
                let handler_owned = handler.clone();

                let run: CaseFn = if runnable {
                    Box::new(move || {
                        if !meta_path.exists() {
                            return CaseOutcome::Skip;
                        }
                        let text = match std::fs::read_to_string(&meta_path) {
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
                        let result = match handler_owned.as_str() {
                            "get_custody_groups" => {
                                run_get_custody_groups(preset, &case_name, &text, &val)
                            }
                            "compute_columns_for_custody_group" => {
                                run_compute_columns_for_custody_group(preset, &case_name, &val)
                            }
                            _ => return CaseOutcome::Skip,
                        };
                        match result {
                            Ok(()) => CaseOutcome::Pass,
                            Err(msg) => CaseOutcome::Fail(msg),
                        }
                    })
                } else {
                    // Gossip-validator (and any unknown) handler: skip offline.
                    Box::new(move || CaseOutcome::Skip)
                };

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

// ── get_custody_groups ──────────────────────────────────────────────────────────

fn run_get_custody_groups(
    preset: &'static str,
    case_name: &str,
    raw: &str,
    val: &serde_yaml_ng::Value,
) -> Result<(), String> {
    let node_id = parse_node_id(raw, case_name)?;
    let custody_group_count = val
        .get("custody_group_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{case_name}: missing/invalid custody_group_count"))?;
    let expected = parse_u64_seq(val.get("result"), case_name)?;

    let got = match preset {
        "mainnet" => get_custody_groups::<MainnetBeaconSpec>(node_id, custody_group_count),
        "minimal" => get_custody_groups::<MinimalBeaconSpec>(node_id, custody_group_count),
        other => unreachable!("unexpected preset {other}"),
    };
    if got == expected {
        Ok(())
    } else {
        Err(format!(
            "{case_name}: get_custody_groups mismatch: got {got:?}, want {expected:?}"
        ))
    }
}

// ── compute_columns_for_custody_group ─────────────────────────────────────────────

fn run_compute_columns_for_custody_group(
    preset: &'static str,
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> Result<(), String> {
    let custody_group = val
        .get("custody_group")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{case_name}: missing/invalid custody_group"))?;
    let expected = parse_u64_seq(val.get("result"), case_name)?;

    let got = match preset {
        "mainnet" => compute_columns_for_custody_group::<MainnetBeaconSpec>(custody_group),
        "minimal" => compute_columns_for_custody_group::<MinimalBeaconSpec>(custody_group),
        other => unreachable!("unexpected preset {other}"),
    };
    if got == expected {
        Ok(())
    } else {
        Err(format!(
            "{case_name}: compute_columns_for_custody_group mismatch: got {got:?}, want {expected:?}"
        ))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────────

/// Parse the `node_id` scalar (a base-10 uint256) into a 32-byte big-endian
/// array. `node_id` can be `2**256 - 1`, which overflows `f64`/`u64`, so we
/// read the decimal digits straight from the raw YAML text rather than through
/// `serde_yaml_ng::Value` (which lossily parses it as a float).
fn parse_node_id(raw: &str, case_name: &str) -> Result<[u8; 32], String> {
    let digits = extract_scalar_digits(raw, "node_id")
        .ok_or_else(|| format!("{case_name}: missing/unreadable node_id"))?;
    decimal_to_be_bytes::<32>(&digits).ok_or_else(|| format!("{case_name}: bad node_id '{digits}'"))
}

/// Extract the decimal digits of a top-level scalar `key:` from raw YAML text.
/// Handles both inline (`key: 123`) and continuation (`key:\n  123`) forms; the
/// value is a single integer with no internal whitespace. Returns `None` if the
/// key is absent or no digits follow.
fn extract_scalar_digits(raw: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    let start = raw.find(&needle)? + needle.len();
    let rest = &raw[start..];
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

/// Parse a base-10 string into an `N`-byte big-endian array. Returns `None` on
/// a non-digit char or overflow past `N` bytes.
fn decimal_to_be_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut buf = [0u8; N];
    for ch in s.chars() {
        let digit = ch.to_digit(10)? as u16;
        // buf = buf * 10 + digit, big-endian, with overflow detection.
        let mut carry = digit;
        for byte in buf.iter_mut().rev() {
            let acc = (*byte as u16) * 10 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return None; // overflowed N bytes
        }
    }
    Some(buf)
}

/// Parse a YAML sequence of unsigned integers into a `Vec<u64>`.
fn parse_u64_seq(seq: Option<&serde_yaml_ng::Value>, case_name: &str) -> Result<Vec<u64>, String> {
    let seq = seq
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| format!("{case_name}: missing/invalid 'result' sequence"))?;
    seq.iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("{case_name}: result entry is not u64"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_to_be_bytes_small() {
        // 1048576 = 0x100000 → low 3 bytes 0x10 0x00 0x00.
        let b = decimal_to_be_bytes::<32>("1048576").unwrap();
        assert_eq!(b[31], 0x00);
        assert_eq!(b[30], 0x00);
        assert_eq!(b[29], 0x10);
        assert!(b[..29].iter().all(|&x| x == 0));
    }

    #[test]
    fn decimal_to_be_bytes_max_uint256() {
        // 2**256 - 1 → all 0xff.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let b = decimal_to_be_bytes::<32>(max).unwrap();
        assert!(b.iter().all(|&x| x == 0xff));
    }

    #[test]
    fn extract_scalar_digits_inline_and_continuation() {
        let inline = "node_id: 1048576\ncustody_group_count: 1\nresult: [65]\n";
        assert_eq!(
            extract_scalar_digits(inline, "node_id").as_deref(),
            Some("1048576")
        );
        let cont = "node_id: \n  115792089237316195423570985008687907853269984665640564039457584007913129639935\ncustody_group_count: 128\n";
        assert_eq!(
            extract_scalar_digits(cont, "node_id").as_deref(),
            Some("115792089237316195423570985008687907853269984665640564039457584007913129639935")
        );
        assert_eq!(extract_scalar_digits(inline, "missing"), None);
    }

    #[test]
    fn decimal_to_be_bytes_overflow_is_none() {
        // 2**256 overflows 32 bytes.
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(decimal_to_be_bytes::<32>(over).is_none());
    }
}
