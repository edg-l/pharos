//! Runner for the `ssz_generic` test category.
//!
//! Fixture path: `<root>/general/phase0/ssz_generic/<handler>/<suite>/<case>/`
//!
//! Handlers:
//! - `boolean`                → `bool`
//! - `uints`                  → `u8/u16/u32/u64/u128/Uint256`
//! - `basic_vector`           → `SszVector<elem, N>`
//! - `bitvector`              → `Bitvector<N>`
//! - `bitlist`                → `Bitlist<N>`
//! - `containers`             → named test structs (including progressive-field structs)
//! - `basic_progressive_list` → `ProgressiveList<T>` (EIP-7916)
//! - `progressive_bitlist`    → `ProgressiveBitlist` (EIP-7916)
//! - `progressive_containers` → progressive-container test structs (EIP-7495)
//! - `compatible_unions`      → `CompatibleUnion*` test types (EIP-7495)
//! - other unknown handlers   → Fail (`ConformanceError::UnsupportedHandler`)

use std::path::Path;

use pharos_ssz::{
    Bitlist, Bitvector, Decode, Encode, ProgressiveBitlist, ProgressiveList, SszVector, TreeHash,
};
use pharos_utils::Uint256;

use crate::error::ConformanceError;
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::snappy::decompress_raw;
use crate::ssz_generic_types::{
    BitsStruct, CompatibleUnionA, CompatibleUnionABCA, CompatibleUnionBC, ComplexTestStruct,
    FixedTestStruct, ProgressiveBitsStruct, ProgressiveComplexTestStruct,
    ProgressiveSingleFieldContainerTestStruct, ProgressiveSingleListContainerTestStruct,
    ProgressiveTestStruct, ProgressiveVarTestStruct, SingleFieldTestStruct, SmallTestStruct,
    VarTestStruct,
};
use crate::task::{CaseFn, CaseOutcome as TaskCaseOutcome, CaseTask};
use crate::yaml_util::read_root_from_file;

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per ssz_generic test case.
///
/// The walk is handler → suite → case (sorted). All handlers are wired to
/// real implementations; an unknown handler produces `Err` (Fail), never a
/// silent drop.
///
/// Outcome mapping:
/// - `Ok(CaseOutcome::Pass)` → `TaskCaseOutcome::Pass`
/// - `Ok(CaseOutcome::Skip)` → `TaskCaseOutcome::Skip`
/// - `Err(e)`                → `TaskCaseOutcome::Fail("`{case_label}`: {e}")`
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
        "basic_progressive_list" => {
            run_progressive_list(case_name, case_path, case_label, &ssz_bytes, is_valid)
        }
        "progressive_bitlist" => {
            run_progressive_bitlist(case_path, case_label, &ssz_bytes, is_valid)
        }
        "progressive_containers" => {
            run_progressive_container(case_name, case_path, case_label, &ssz_bytes, is_valid)
        }
        "compatible_unions" => {
            run_compatible_union(case_name, case_path, case_label, &ssz_bytes, is_valid)
        }
        _ => Err(ConformanceError::UnsupportedHandler(handler.to_string())),
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
        _ => Err(ConformanceError::UnknownUintSize {
            suite: suite.to_string(),
        }),
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
            return Err(ConformanceError::MalformedFixture(format!(
                "basic_vector suite name unparseable: {suite}"
            )));
        }
    };

    // Dispatch over (elem, N) combinations present in the fixture matrix.
    // Fixture Ns: 0, 1, 2, 3, 4, 5, 8, 16, 31, 512, 513
    // Extra arms (32, 33, 64, 128, 256, 1024) are retained for forward-compatibility.
    macro_rules! dispatch_vec {
        ($T:ty, $elem_str:expr, $n:expr) => {
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
                _ => Err(ConformanceError::UnknownVecLength {
                    elem: $elem_str.to_string(),
                    n: $n,
                }),
            }
        };
    }

    match elem.as_str() {
        "bool" => dispatch_vec!(bool, "bool", n),
        "uint8" => dispatch_vec!(u8, "uint8", n),
        "uint16" => dispatch_vec!(u16, "uint16", n),
        "uint32" => dispatch_vec!(u32, "uint32", n),
        "uint64" => dispatch_vec!(u64, "uint64", n),
        "uint128" => dispatch_vec!(u128, "uint128", n),
        "uint256" => dispatch_vec!(Uint256, "uint256", n),
        _ => Err(ConformanceError::UnknownVecElemType { elem }),
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
            return Err(ConformanceError::MalformedFixture(format!(
                "bitvector suite name unparseable: {suite}"
            )));
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
                257 => run_typed::<Bitvector<257>>(case_path, case_label, ssz_bytes, is_valid),
                511 => run_typed::<Bitvector<511>>(case_path, case_label, ssz_bytes, is_valid),
                512 => run_typed::<Bitvector<512>>(case_path, case_label, ssz_bytes, is_valid),
                513 => run_typed::<Bitvector<513>>(case_path, case_label, ssz_bytes, is_valid),
                1280 => run_typed::<Bitvector<1280>>(case_path, case_label, ssz_bytes, is_valid),
                1281 => run_typed::<Bitvector<1281>>(case_path, case_label, ssz_bytes, is_valid),
                _ => Err(ConformanceError::UnknownBitvectorLength { n: $n }),
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
            return Err(ConformanceError::MalformedFixture(format!(
                "bitlist suite name unparseable: {suite}"
            )));
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
                257 => run_typed::<Bitlist<257>>(case_path, case_label, ssz_bytes, is_valid),
                511 => run_typed::<Bitlist<511>>(case_path, case_label, ssz_bytes, is_valid),
                512 => run_typed::<Bitlist<512>>(case_path, case_label, ssz_bytes, is_valid),
                513 => run_typed::<Bitlist<513>>(case_path, case_label, ssz_bytes, is_valid),
                1280 => run_typed::<Bitlist<1280>>(case_path, case_label, ssz_bytes, is_valid),
                1281 => run_typed::<Bitlist<1281>>(case_path, case_label, ssz_bytes, is_valid),
                _ => Err(ConformanceError::UnknownBitlistLimit { n: $n }),
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
    // suite is the struct name (e.g. "SingleFieldTestStruct") possibly with extras.
    // The split is on the first `_` separator.
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
        // EIP-7916 progressive-field structs (container serialization, progressive field types).
        "ProgressiveTestStruct" => {
            run_typed::<ProgressiveTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        "ProgressiveBitsStruct" => {
            run_typed::<ProgressiveBitsStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        _ => Err(ConformanceError::UnknownContainerStruct {
            name: name.to_string(),
        }),
    }
}

// ── basic_progressive_list dispatch ──────────────────────────────────────────

/// Dispatch `basic_progressive_list` fixtures.
///
/// Fixture naming: `proglist_{type}_{fill}_{len}` where `type` is one of
/// `bool`, `uint8`, `uint16`, `uint32`, `uint64`, `uint128`, `uint256`.
fn run_progressive_list(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // Name pattern: proglist_{type}_{fill}_{len} (valid) or proglist_{type}_{len}_{suffix} (invalid)
    // We only need to dispatch on the type.
    let elem_type = parse_proglist_type(suite);

    match elem_type.as_deref() {
        Some("bool") => {
            run_typed::<ProgressiveList<bool>>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("uint8") => {
            run_typed::<ProgressiveList<u8>>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("uint16") => {
            run_typed::<ProgressiveList<u16>>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("uint32") => {
            run_typed::<ProgressiveList<u32>>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("uint64") => {
            run_typed::<ProgressiveList<u64>>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("uint128") => {
            run_typed::<ProgressiveList<u128>>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("uint256") => {
            run_typed::<ProgressiveList<Uint256>>(case_path, case_label, ssz_bytes, is_valid)
        }
        _ => Err(ConformanceError::MalformedFixture(format!(
            "basic_progressive_list suite name unparseable: {suite}"
        ))),
    }
}

/// Parse the element type from a `basic_progressive_list` fixture name.
///
/// Name format: `proglist_{type}_{fill}_{len}` or `proglist_{type}_{len}_{invalid_reason}`.
fn parse_proglist_type(suite: &str) -> Option<String> {
    // Strip "proglist_" prefix, then the next segment is the type.
    let rest = suite.strip_prefix("proglist_")?;
    // Longest-match to distinguish "uint128" from "uint16" etc.
    let types = [
        "uint256", "uint128", "uint64", "uint32", "uint16", "uint8", "bool",
    ];
    for t in &types {
        if rest.starts_with(t) {
            return Some(t.to_string());
        }
    }
    None
}

// ── progressive_bitlist dispatch ──────────────────────────────────────────────

/// Dispatch `progressive_bitlist` fixtures.
///
/// All cases use `ProgressiveBitlist` regardless of the case name.
fn run_progressive_bitlist(
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    run_typed::<ProgressiveBitlist>(case_path, case_label, ssz_bytes, is_valid)
}

// ── progressive_containers dispatch ──────────────────────────────────────────

/// Dispatch `progressive_containers` fixtures.
///
/// Fixture naming: `{StructName}_{fill}[_{variant}]`.
/// We match on the struct name prefix (up to the first `_`).
fn run_progressive_container(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    // Struct name prefix: split on first `_` of the part AFTER the first uppercase segment.
    // The fixture names are like "ProgressiveSingleFieldContainerTestStruct_max_0".
    // We need to find the struct name portion.
    let name = parse_progressive_container_name(suite);

    match name.as_deref() {
        Some("ProgressiveSingleFieldContainerTestStruct") => {
            run_typed::<ProgressiveSingleFieldContainerTestStruct>(
                case_path, case_label, ssz_bytes, is_valid,
            )
        }
        Some("ProgressiveSingleListContainerTestStruct") => {
            run_typed::<ProgressiveSingleListContainerTestStruct>(
                case_path, case_label, ssz_bytes, is_valid,
            )
        }
        Some("ProgressiveVarTestStruct") => {
            run_typed::<ProgressiveVarTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("ProgressiveComplexTestStruct") => {
            run_typed::<ProgressiveComplexTestStruct>(case_path, case_label, ssz_bytes, is_valid)
        }
        _ => Err(ConformanceError::UnknownContainerStruct {
            name: suite.to_string(),
        }),
    }
}

/// Extract the struct name from a progressive-containers fixture case name.
///
/// Case names look like `ProgressiveSingleFieldContainerTestStruct_max_0` or
/// `ProgressiveComplexTestStruct_lengthy_chaos_1`.
fn parse_progressive_container_name(suite: &str) -> Option<String> {
    // Known struct names in the progressive_containers handler.
    let known = [
        "ProgressiveComplexTestStruct",
        "ProgressiveSingleFieldContainerTestStruct",
        "ProgressiveSingleListContainerTestStruct",
        "ProgressiveVarTestStruct",
    ];
    for name in &known {
        if let Some(rest) = suite.strip_prefix(name) {
            // Verify it's followed by '_' or is the full name.
            if rest.is_empty() || rest.starts_with('_') {
                return Some(name.to_string());
            }
        }
    }
    None
}

// ── compatible_unions dispatch ────────────────────────────────────────────────

/// Dispatch `compatible_unions` fixtures.
///
/// Fixture naming: `{UnionName}_{fill}[_{extra}]`. We match on the union-type
/// name prefix. The three union types are:
/// - `CompatibleUnionA` = `CompatibleUnion({1: PSF})`
/// - `CompatibleUnionBC` = `CompatibleUnion({2: PSL, 3: PVar})`
/// - `CompatibleUnionABCA` = `CompatibleUnion({1: PSF, 2: PSL, 3: PVar, 4: PSF})`
fn run_compatible_union(
    suite: &str,
    case_path: &Path,
    case_label: &str,
    ssz_bytes: &[u8],
    is_valid: bool,
) -> Result<CaseOutcome, ConformanceError> {
    let name = parse_union_name(suite);

    match name.as_deref() {
        Some("CompatibleUnionA") => {
            run_typed::<CompatibleUnionA>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("CompatibleUnionBC") => {
            run_typed::<CompatibleUnionBC>(case_path, case_label, ssz_bytes, is_valid)
        }
        Some("CompatibleUnionABCA") => {
            run_typed::<CompatibleUnionABCA>(case_path, case_label, ssz_bytes, is_valid)
        }
        _ => Err(ConformanceError::UnknownContainerStruct {
            name: suite.to_string(),
        }),
    }
}

/// Extract the union type name from a `compatible_unions` fixture case name.
fn parse_union_name(suite: &str) -> Option<String> {
    // Known names — match longest-first to avoid "CompatibleUnionA" matching
    // "CompatibleUnionABCA" cases.
    let known = [
        "CompatibleUnionABCA",
        "CompatibleUnionBC",
        "CompatibleUnionA",
    ];
    for name in &known {
        if let Some(rest) = suite.strip_prefix(name) {
            if rest.is_empty() || rest.starts_with('_') {
                return Some(name.to_string());
            }
        }
    }
    None
}

// Helpers `read_dir_sorted` and `dir_name` are shared with `ssz_static` via
// the `fs_util` module.
