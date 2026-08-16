//! Runner for the `ssz_generic` test category.
//!
//! Fixture path: `<root>/general/phase0/ssz_generic/<handler>/<suite>/<case>/`
//!
//! Handlers:
//! - `boolean`      → `bool`
//! - `uints`        → `u8/u16/u32/u64/u128/Uint256`
//! - `basic_vector` → `SszVector<elem, N>`
//! - `bitvector`    → `Bitvector<N>`
//! - `bitlist`      → `Bitlist<N>`
//! - `containers`   → named test structs
//! - others         → skip with message

use std::path::Path;

use pharos_ssz::{Bitlist, Bitvector, Decode, Encode, SszVector, TreeHash};
use pharos_utils::Uint256;

use crate::error::ConformanceError;
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::snappy::decompress_raw;
use crate::ssz_generic_types::{
    BitsStruct, ComplexTestStruct, FixedTestStruct, SingleFieldTestStruct, SmallTestStruct,
    VarTestStruct,
};
use crate::task::{CaseFn, CaseOutcome as TaskCaseOutcome, CaseTask};
use crate::yaml_util::read_root_from_file;

/// Result of running all ssz_generic tests.
pub struct GenericResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per ssz_generic test case in the same walk-order as
/// `run_ssz_generic`. Called by the Phase 7 flat work-pool.
///
/// The walk is handler → suite → case (sorted). Unsupported handlers are
/// skipped (no tasks emitted), matching the `continue` in `run_ssz_generic`.
///
/// Outcome mapping:
/// - `Ok(CaseOutcome::Pass)` → `TaskCaseOutcome::Pass`
/// - `Ok(CaseOutcome::Skip)` → `TaskCaseOutcome::Skip`
/// - `Err(e)`                → `TaskCaseOutcome::Fail("`{case_label}`: {e}")`
#[allow(dead_code)]
pub fn enumerate_ssz_generic(root: &Path, row_ordinal: u32) -> Vec<CaseTask> {
    let base = root.join("general/phase0/ssz_generic");
    if !base.is_dir() {
        return Vec::new();
    }

    let handlers = match read_dir_sorted(&base) {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    for handler_path in handlers {
        let handler: String = dir_name(&handler_path);
        // Skip unsupported handlers — same set as in run_ssz_generic.
        match handler.as_str() {
            "basic_progressive_list"
            | "progressive_bitlist"
            | "progressive_containers"
            | "compatible_unions" => {
                continue;
            }
            _ => {}
        }

        let suites = read_dir_sorted(&handler_path).unwrap_or_default();
        for suite_path in suites {
            let suite: String = dir_name(&suite_path);
            let is_valid = suite == "valid";

            let cases = read_dir_sorted(&suite_path).unwrap_or_default();
            for case_path in cases {
                let case_name = dir_name(&case_path);
                let case_label = format!("ssz_generic/{handler}/{suite}/{case_name}");
                let case_ordinal = ordinal;
                ordinal += 1;

                let handler_owned = handler.clone();
                let is_valid_owned = is_valid;
                let run: CaseFn = Box::new(move || {
                    let result = run_case(
                        &handler_owned,
                        &case_name,
                        &case_path,
                        &case_label,
                        is_valid_owned,
                    );
                    match result {
                        Ok(CaseOutcome::Pass) => TaskCaseOutcome::Pass,
                        Ok(CaseOutcome::Skip) => TaskCaseOutcome::Skip,
                        Err(e) => TaskCaseOutcome::Fail(format!("`{case_label}`: {e}")),
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

/// Run all ssz_generic tests under `root/general/phase0/ssz_generic/`.
pub fn run_ssz_generic(root: &Path) -> GenericResult {
    let base = root.join("general/phase0/ssz_generic");
    if !base.is_dir() {
        eprintln!("ssz_generic dir not found: {}", base.display());
        return GenericResult {
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

    let handlers = match read_dir_sorted(&base) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Cannot read ssz_generic dir: {e}");
            return GenericResult {
                pass: 0,
                fail: 0,
                skip: 0,
                failures: vec![],
            };
        }
    };

    for handler_path in handlers {
        let handler = dir_name(&handler_path);
        // Skip unsupported progressive/union handlers
        match handler.as_str() {
            "basic_progressive_list"
            | "progressive_bitlist"
            | "progressive_containers"
            | "compatible_unions" => {
                eprintln!("skipping unsupported handler: {handler}");
                continue;
            }
            _ => {}
        }

        let suites = read_dir_sorted(&handler_path).unwrap_or_default();
        for suite_path in suites {
            let suite = dir_name(&suite_path);
            // valid or invalid
            let is_valid = suite == "valid";
            let is_invalid = suite == "invalid";
            if !is_valid && !is_invalid {
                // Some handlers nest handler/suite/case differently
                // Treat this as a suite directory containing cases
            }

            let cases = read_dir_sorted(&suite_path).unwrap_or_default();
            for case_path in cases {
                let case_name = dir_name(&case_path);
                let case_label = format!("ssz_generic/{handler}/{suite}/{case_name}");
                // Type parsers (e.g. `parse_uint_size`) need the case name —
                // not the suite name — to extract the type spec. The case
                // dir is e.g. `uint_64_last_byte_empty` or `bitvec_8_random`.
                let result = run_case(&handler, &case_name, &case_path, &case_label, is_valid);
                match result {
                    Ok(CaseOutcome::Pass) => pass += 1,
                    Ok(CaseOutcome::Skip) => skip += 1,
                    Err(e) => {
                        fail += 1;
                        failures.push(format!("`{case_label}`: {e}"));
                    }
                }
            }
        }
    }

    GenericResult {
        pass,
        fail,
        skip,
        failures,
    }
}

enum CaseOutcome {
    Pass,
    Skip,
}

fn run_case(
    handler: &str,
    case_name: &str,
    case_path: &Path,
    case_label: &str,
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    let ssz_snappy = case_path.join("serialized.ssz_snappy");
    if !ssz_snappy.exists() {
        return Ok(CaseOutcome::Skip);
    }

    let compressed = std::fs::read(&ssz_snappy)?;
    let ssz_bytes = decompress_raw(&compressed)?;

    match handler {
        "boolean" => run_typed::<bool>(case_path, case_label, &ssz_bytes, is_valid),
        "uints" => run_uint(case_name, case_path, case_label, &ssz_bytes, is_valid),
        "basic_vector" => run_basic_vector(case_name, case_path, case_label, &ssz_bytes, is_valid),
        "bitvector" => run_bitvector(case_name, case_path, case_label, &ssz_bytes, is_valid),
        "bitlist" => run_bitlist(case_name, case_path, case_label, &ssz_bytes, is_valid),
        "containers" => run_container(case_name, case_path, case_label, &ssz_bytes, is_valid),
        _ => {
            eprintln!("skipping unknown handler: {handler}");
            Ok(CaseOutcome::Skip)
        }
    }
}

/// Core assertion: decode → re-encode → compare bytes → check tree root.
fn assert_valid<T>(
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
) -> Result<CaseOutcome, ConformanceError>
where
    T: Encode + Decode + TreeHash,
{
    let value = T::from_ssz_bytes(ssz_bytes)?;
    let re_encoded = value.as_ssz_bytes();
    if re_encoded != ssz_bytes {
        return Err(ConformanceError::EncodeRoundTrip {
            case: case_label.into(),
            got_hex: hex::encode(&re_encoded),
            want_hex: hex::encode(ssz_bytes),
        });
    }
    // meta.yaml contains the root for ssz_generic (not roots.yaml). Per spec
    // README, every valid case must have meta.yaml; a missing one is corrupt
    // fixture data, not an excuse to skip the tree_hash_root check.
    let meta_path = case_path.join("meta.yaml");
    if !meta_path.exists() {
        return Err(ConformanceError::Yaml(format!(
            "meta.yaml missing for valid case `{case_label}`"
        )));
    }
    let expected_root = read_root_from_file(&meta_path)?;
    let got_root = value.tree_hash_root();
    if got_root != expected_root {
        return Err(ConformanceError::HashTreeRoot {
            case: case_label.into(),
            got: format!("0x{}", hex::encode(got_root.as_ref())),
            want: format!("0x{}", hex::encode(expected_root.as_ref())),
        });
    }
    Ok(CaseOutcome::Pass)
}

/// Core assertion for invalid cases: decode must return Err.
fn assert_invalid<T: Decode>(ssz_bytes: &[u8]) -> Result<CaseOutcome, ConformanceError> {
    match T::from_ssz_bytes(ssz_bytes) {
        Err(_) => Ok(CaseOutcome::Pass),
        Ok(_) => Err(ConformanceError::Ssz(pharos_ssz::SszError::Custom(
            "expected decode error for invalid case, but got Ok".into(),
        ))),
    }
}

fn run_typed<T>(
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError>
where
    T: Encode + Decode + TreeHash,
{
    if is_valid {
        assert_valid::<T>(case_path, case_label, ssz_bytes)
    } else {
        assert_invalid::<T>(ssz_bytes)
    }
}

// ── uint dispatch ─────────────────────────────────────────────────────────────

fn run_uint(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // suite name may be like "uint_8_...", "uint_64_max", etc.
    // Extract bit-width from the first two underscore-separated parts
    let size = parse_uint_size(suite);
    match size {
        Some(8) => run_typed::<u8>(case_path, case_label, ssz_bytes, is_valid),
        Some(16) => run_typed::<u16>(case_path, case_label, ssz_bytes, is_valid),
        Some(32) => run_typed::<u32>(case_path, case_label, ssz_bytes, is_valid),
        Some(64) => run_typed::<u64>(case_path, case_label, ssz_bytes, is_valid),
        Some(128) => run_typed::<u128>(case_path, case_label, ssz_bytes, is_valid),
        Some(256) => run_typed::<Uint256>(case_path, case_label, ssz_bytes, is_valid),
        _ => {
            eprintln!("skipping uints case with unknown size in suite: {suite}");
            Ok(CaseOutcome::Skip)
        }
    }
}

fn parse_uint_size(suite: &str) -> Option<u32> {
    // suite looks like "uint_8", "uint_8_last", "uint_256_zero", etc.
    let parts: Vec<&str> = suite.splitn(3, '_').collect();
    if parts.len() >= 2 && parts[0] == "uint" {
        parts[1].parse().ok()
    } else {
        None
    }
}

// ── basic_vector dispatch ─────────────────────────────────────────────────────

fn run_basic_vector(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // suite: "vec_{elem}_{N}[_extra...]"
    // e.g. "vec_bool_1", "vec_uint8_16", "vec_uint256_1"
    let (elem, n) = match parse_vec_params(suite) {
        Some(v) => v,
        None => {
            eprintln!("skipping basic_vector with unparseable suite: {suite}");
            return Ok(CaseOutcome::Skip);
        }
    };

    // Dispatch over (elem, N) combinations present in the fixture matrix.
    // We enumerate all N values that appear for each element type.
    // The fixture matrix uses N: 1, 2, 3, 4, 5, 8, 16, 31, 32, 33, 64, 128, 256, 512, 1024
    macro_rules! dispatch_vec {
        ($T:ty, $n:expr) => {
            match $n {
                0 => run_typed::<SszVector<$T, 0>>(case_path, case_label, ssz_bytes, is_valid),
                1 => run_typed::<SszVector<$T, 1>>(case_path, case_label, ssz_bytes, is_valid),
                2 => run_typed::<SszVector<$T, 2>>(case_path, case_label, ssz_bytes, is_valid),
                3 => run_typed::<SszVector<$T, 3>>(case_path, case_label, ssz_bytes, is_valid),
                4 => run_typed::<SszVector<$T, 4>>(case_path, case_label, ssz_bytes, is_valid),
                5 => run_typed::<SszVector<$T, 5>>(case_path, case_label, ssz_bytes, is_valid),
                8 => run_typed::<SszVector<$T, 8>>(case_path, case_label, ssz_bytes, is_valid),
                16 => run_typed::<SszVector<$T, 16>>(case_path, case_label, ssz_bytes, is_valid),
                31 => run_typed::<SszVector<$T, 31>>(case_path, case_label, ssz_bytes, is_valid),
                32 => run_typed::<SszVector<$T, 32>>(case_path, case_label, ssz_bytes, is_valid),
                33 => run_typed::<SszVector<$T, 33>>(case_path, case_label, ssz_bytes, is_valid),
                64 => run_typed::<SszVector<$T, 64>>(case_path, case_label, ssz_bytes, is_valid),
                128 => run_typed::<SszVector<$T, 128>>(case_path, case_label, ssz_bytes, is_valid),
                256 => run_typed::<SszVector<$T, 256>>(case_path, case_label, ssz_bytes, is_valid),
                512 => run_typed::<SszVector<$T, 512>>(case_path, case_label, ssz_bytes, is_valid),
                513 => run_typed::<SszVector<$T, 513>>(case_path, case_label, ssz_bytes, is_valid),
                1024 => {
                    run_typed::<SszVector<$T, 1024>>(case_path, case_label, ssz_bytes, is_valid)
                }
                _ => {
                    eprintln!("skipping vec_{elem}_{n}: length {n} not in dispatch table");
                    Ok(CaseOutcome::Skip)
                }
            }
        };
    }

    match elem.as_str() {
        "bool" => dispatch_vec!(bool, n),
        "uint8" => dispatch_vec!(u8, n),
        "uint16" => dispatch_vec!(u16, n),
        "uint32" => dispatch_vec!(u32, n),
        "uint64" => dispatch_vec!(u64, n),
        "uint128" => dispatch_vec!(u128, n),
        "uint256" => dispatch_vec!(Uint256, n),
        _ => {
            eprintln!("skipping basic_vector with unknown element type: {elem}");
            Ok(CaseOutcome::Skip)
        }
    }
}

fn parse_vec_params(suite: &str) -> Option<(String, u64)> {
    // "vec_{elem}_{N}[_extra]"
    let rest = suite.strip_prefix("vec_")?;
    // Elem types: bool, uint8, uint16, uint32, uint64, uint128, uint256
    let elem_types = [
        "uint256", "uint128", "uint64", "uint32", "uint16", "uint8", "bool",
    ];
    for elem in &elem_types {
        if let Some(after_elem) = rest.strip_prefix(elem) {
            // after_elem starts with "_N" or "_N_extra"
            let after = after_elem.strip_prefix('_')?;
            let n_str = after.split('_').next()?;
            let n: u64 = n_str.parse().ok()?;
            return Some((elem.to_string(), n));
        }
    }
    None
}

// ── bitvector dispatch ────────────────────────────────────────────────────────

fn run_bitvector(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // suite: "bitvec_{N}[_extra]"
    let n = match parse_bitvec_n(suite) {
        Some(n) => n,
        None => {
            eprintln!("skipping bitvector with unparseable suite: {suite}");
            return Ok(CaseOutcome::Skip);
        }
    };

    macro_rules! dispatch_bv {
        ($n:expr) => {
            match $n {
                0 => run_typed::<Bitvector<0>>(case_path, case_label, ssz_bytes, is_valid),
                1 => run_typed::<Bitvector<1>>(case_path, case_label, ssz_bytes, is_valid),
                2 => run_typed::<Bitvector<2>>(case_path, case_label, ssz_bytes, is_valid),
                3 => run_typed::<Bitvector<3>>(case_path, case_label, ssz_bytes, is_valid),
                4 => run_typed::<Bitvector<4>>(case_path, case_label, ssz_bytes, is_valid),
                5 => run_typed::<Bitvector<5>>(case_path, case_label, ssz_bytes, is_valid),
                6 => run_typed::<Bitvector<6>>(case_path, case_label, ssz_bytes, is_valid),
                7 => run_typed::<Bitvector<7>>(case_path, case_label, ssz_bytes, is_valid),
                8 => run_typed::<Bitvector<8>>(case_path, case_label, ssz_bytes, is_valid),
                9 => run_typed::<Bitvector<9>>(case_path, case_label, ssz_bytes, is_valid),
                15 => run_typed::<Bitvector<15>>(case_path, case_label, ssz_bytes, is_valid),
                16 => run_typed::<Bitvector<16>>(case_path, case_label, ssz_bytes, is_valid),
                17 => run_typed::<Bitvector<17>>(case_path, case_label, ssz_bytes, is_valid),
                31 => run_typed::<Bitvector<31>>(case_path, case_label, ssz_bytes, is_valid),
                32 => run_typed::<Bitvector<32>>(case_path, case_label, ssz_bytes, is_valid),
                33 => run_typed::<Bitvector<33>>(case_path, case_label, ssz_bytes, is_valid),
                64 => run_typed::<Bitvector<64>>(case_path, case_label, ssz_bytes, is_valid),
                128 => run_typed::<Bitvector<128>>(case_path, case_label, ssz_bytes, is_valid),
                256 => run_typed::<Bitvector<256>>(case_path, case_label, ssz_bytes, is_valid),
                511 => run_typed::<Bitvector<511>>(case_path, case_label, ssz_bytes, is_valid),
                512 => run_typed::<Bitvector<512>>(case_path, case_label, ssz_bytes, is_valid),
                513 => run_typed::<Bitvector<513>>(case_path, case_label, ssz_bytes, is_valid),
                _ => {
                    eprintln!("skipping bitvec_{n}: length not in dispatch table");
                    Ok(CaseOutcome::Skip)
                }
            }
        };
    }

    dispatch_bv!(n)
}

fn parse_bitvec_n(suite: &str) -> Option<u64> {
    // "bitvec_{N}" or "bitvec_{N}_{extra}"
    let rest = suite.strip_prefix("bitvec_")?;
    let n_str = rest.split('_').next()?;
    n_str.parse().ok()
}

// ── bitlist dispatch ──────────────────────────────────────────────────────────

fn run_bitlist(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // suite: "bitlist_{N}[_extra]"
    let n = match parse_bitlist_n(suite) {
        Some(n) => n,
        None => {
            eprintln!("skipping bitlist with unparseable suite: {suite}");
            return Ok(CaseOutcome::Skip);
        }
    };

    macro_rules! dispatch_bl {
        ($n:expr) => {
            match $n {
                0 => run_typed::<Bitlist<0>>(case_path, case_label, ssz_bytes, is_valid),
                1 => run_typed::<Bitlist<1>>(case_path, case_label, ssz_bytes, is_valid),
                2 => run_typed::<Bitlist<2>>(case_path, case_label, ssz_bytes, is_valid),
                3 => run_typed::<Bitlist<3>>(case_path, case_label, ssz_bytes, is_valid),
                4 => run_typed::<Bitlist<4>>(case_path, case_label, ssz_bytes, is_valid),
                5 => run_typed::<Bitlist<5>>(case_path, case_label, ssz_bytes, is_valid),
                6 => run_typed::<Bitlist<6>>(case_path, case_label, ssz_bytes, is_valid),
                7 => run_typed::<Bitlist<7>>(case_path, case_label, ssz_bytes, is_valid),
                8 => run_typed::<Bitlist<8>>(case_path, case_label, ssz_bytes, is_valid),
                9 => run_typed::<Bitlist<9>>(case_path, case_label, ssz_bytes, is_valid),
                15 => run_typed::<Bitlist<15>>(case_path, case_label, ssz_bytes, is_valid),
                16 => run_typed::<Bitlist<16>>(case_path, case_label, ssz_bytes, is_valid),
                17 => run_typed::<Bitlist<17>>(case_path, case_label, ssz_bytes, is_valid),
                31 => run_typed::<Bitlist<31>>(case_path, case_label, ssz_bytes, is_valid),
                32 => run_typed::<Bitlist<32>>(case_path, case_label, ssz_bytes, is_valid),
                33 => run_typed::<Bitlist<33>>(case_path, case_label, ssz_bytes, is_valid),
                64 => run_typed::<Bitlist<64>>(case_path, case_label, ssz_bytes, is_valid),
                128 => run_typed::<Bitlist<128>>(case_path, case_label, ssz_bytes, is_valid),
                256 => run_typed::<Bitlist<256>>(case_path, case_label, ssz_bytes, is_valid),
                511 => run_typed::<Bitlist<511>>(case_path, case_label, ssz_bytes, is_valid),
                512 => run_typed::<Bitlist<512>>(case_path, case_label, ssz_bytes, is_valid),
                513 => run_typed::<Bitlist<513>>(case_path, case_label, ssz_bytes, is_valid),
                _ => {
                    eprintln!("skipping bitlist_{n}: limit not in dispatch table");
                    Ok(CaseOutcome::Skip)
                }
            }
        };
    }

    dispatch_bl!(n)
}

fn parse_bitlist_n(suite: &str) -> Option<u64> {
    // "bitlist_{N}" or "bitlist_{N}_{extra}"
    let rest = suite.strip_prefix("bitlist_")?;
    let n_str = rest.split('_').next()?;
    n_str.parse().ok()
}

// ── containers dispatch ───────────────────────────────────────────────────────

fn run_container(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // suite is the struct name (e.g. "SingleFieldTestStruct") possibly with extras
    // Strip any trailing "_{extra}" by matching known prefixes
    let name = suite.split('_').next().unwrap_or(suite);

    match name {
        "SingleFieldTestStruct" => {
            run_typed::<SingleFieldTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        "SmallTestStruct" => {
            run_typed::<SmallTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        "FixedTestStruct" => {
            run_typed::<FixedTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        "VarTestStruct" => run_typed::<VarTestStruct>(case_path, case_label, ssz_bytes, is_valid),
        "ComplexTestStruct" => {
            run_typed::<ComplexTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        "BitsStruct" => run_typed::<BitsStruct>(case_path, case_label, ssz_bytes, is_valid),
        _ => {
            eprintln!("skipping containers case with unknown struct: {suite}");
            Ok(CaseOutcome::Skip)
        }
    }
}

// Helpers `read_dir_sorted` and `dir_name` are shared with `ssz_static` via
// the `fs_util` module.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::fixtures_root;
    use crate::task::CaseOutcome as TaskCaseOutcome;

    fn drain_tasks(tasks: Vec<CaseTask>) -> (u64, u64, u64) {
        let mut pass = 0u64;
        let mut fail = 0u64;
        let mut skip = 0u64;
        for task in tasks {
            match (task.run)() {
                TaskCaseOutcome::Pass => pass += 1,
                TaskCaseOutcome::Fail(_) => fail += 1,
                TaskCaseOutcome::Skip => skip += 1,
            }
        }
        (pass, fail, skip)
    }

    #[test]
    fn enumerate_ssz_generic_parity() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_ssz_generic(&root);
        let (ep, ef, es) = drain_tasks(enumerate_ssz_generic(&root, 0));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_ssz_generic counts differ from run_ssz_generic"
        );
    }
}
