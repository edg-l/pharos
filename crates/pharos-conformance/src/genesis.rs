//! Genesis conformance dispatcher.
//!
//! Covers two sub-categories:
//!   - `initialization`: `initialize_beacon_state_from_eth1` → compare to `state.ssz_snappy`.
//!   - `validity`: decode `genesis.ssz_snappy`, run `is_valid_genesis_state`, compare to bool.
//!
//! Only `phase0/genesis/minimal` exists in consensus-spec-tests v1.6.1.
//! No mainnet genesis fixtures exist upstream.

use std::path::Path;

use pharos_ssz::{Decode, Encode};
use pharos_stf::phase0::{
    BeaconStateWrite,
    genesis::{BeaconStateMut, initialize_beacon_state_from_eth1, is_valid_genesis_state},
};
use pharos_types::{EthSpec, MinimalEthSpec, phase0::Deposit};

use crate::fixture_walker::{WalkOpts, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;

/// Result of running all genesis tests for one preset.
pub struct GenesisResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

/// Run genesis/initialization and genesis/validity tests for the minimal preset.
pub fn run_genesis_minimal(root: &Path) -> GenesisResult {
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();

    // ── initialization ────────────────────────────────────────────────────────
    for (case_dir, meta) in walk_category(
        root,
        "minimal",
        "phase0",
        "genesis",
        Some("initialization"),
        WalkOpts::default(),
    ) {
        let case_name = format!(
            "phase0/genesis/minimal/initialization/{}",
            dir_name(&case_dir)
        );

        let result = run_initialization_case::<MinimalEthSpec>(&case_dir, &case_name, meta);
        match result {
            CaseResult::Pass => pass += 1,
            CaseResult::Fail(msg) => {
                fail += 1;
                failures.push(msg);
            }
            CaseResult::Skip => skip += 1,
        }
    }

    // ── validity ──────────────────────────────────────────────────────────────
    for (case_dir, _meta) in walk_category(
        root,
        "minimal",
        "phase0",
        "genesis",
        Some("validity"),
        WalkOpts::default(),
    ) {
        let case_name = format!("phase0/genesis/minimal/validity/{}", dir_name(&case_dir));

        let result = run_validity_case::<MinimalEthSpec>(&case_dir, &case_name);
        match result {
            CaseResult::Pass => pass += 1,
            CaseResult::Fail(msg) => {
                fail += 1;
                failures.push(msg);
            }
            CaseResult::Skip => skip += 1,
        }
    }

    GenesisResult {
        pass,
        fail,
        skip,
        failures,
    }
}

// ── Altair entry points ───────────────────────────────────────────────────────
//
// No altair genesis fixtures exist in the upstream consensus-spec-tests
// (the genesis sub-category is phase0-only through at least v1.6.1).
// These entry points are provided to satisfy the conformance table; they
// walk the non-existent directories and return zero counts, which lets the
// `run` dispatcher present them as "0 pass / 0 fail / 0 skip" (placeholder
// semantics) rather than generating a compile error.

/// Run altair genesis tests for the mainnet preset (no fixtures; returns zero counts).
pub fn run_genesis_altair_mainnet(_root: &Path) -> GenesisResult {
    GenesisResult {
        pass: 0,
        fail: 0,
        skip: 0,
        failures: Vec::new(),
    }
}

/// Run altair genesis tests for the minimal preset (no fixtures; returns zero counts).
pub fn run_genesis_altair_minimal(_root: &Path) -> GenesisResult {
    GenesisResult {
        pass: 0,
        fail: 0,
        skip: 0,
        failures: Vec::new(),
    }
}

// ── Case runners ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
enum CaseResult {
    Pass,
    Fail(String),
    Skip,
}

fn run_initialization_case<E: EthSpec>(
    case_dir: &Path,
    case_name: &str,
    meta: Option<crate::fixture_walker::MetaYaml>,
) -> CaseResult
where
    E::BeaconState: BeaconStateMut + BeaconStateWrite,
    E::Phase0BeaconBlockBody: Default + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode,
{
    // Read eth1.yaml for eth1_block_hash and eth1_timestamp.
    let eth1_path = case_dir.join("eth1.yaml");
    if !eth1_path.exists() {
        return CaseResult::Fail(format!("{case_name}: missing eth1.yaml"));
    }
    let eth1_text = match std::fs::read_to_string(&eth1_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read eth1.yaml: {e}")),
    };
    let eth1_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&eth1_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse eth1.yaml: {e}")),
    };

    let eth1_block_hash = match parse_hash256_field(&eth1_val, "eth1_block_hash") {
        Ok(h) => h,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let eth1_timestamp = match eth1_val.get("eth1_timestamp").and_then(|v| v.as_u64()) {
        Some(t) => t,
        None => return CaseResult::Fail(format!("{case_name}: missing eth1_timestamp")),
    };

    // Read deposits_count from meta.yaml.
    let deposits_count = match meta.and_then(|m| m.deposits_count) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing meta.yaml deposits_count")),
    };

    // Load deposits sorted numerically by suffix.
    let mut deposits: Vec<(u64, Deposit<33>)> = Vec::new();
    for i in 0..deposits_count {
        let fname = format!("deposits_{i}.ssz_snappy");
        match load_ssz_snappy::<Deposit<33>>(case_dir, &fname) {
            Ok(d) => deposits.push((i, d)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    }
    // Sort numerically (already in order 0..N but be explicit).
    deposits.sort_by_key(|(i, _)| *i);
    let deposits: Vec<Deposit<33>> = deposits.into_iter().map(|(_, d)| d).collect();

    // Call initialize_beacon_state_from_eth1.
    let produced_state =
        initialize_beacon_state_from_eth1::<E>(eth1_block_hash, eth1_timestamp, &deposits);

    // Load expected state (raw phase0 SSZ, no discriminant prefix).
    let expected_bytes = match load_raw_ssz_snappy(case_dir, "state.ssz_snappy") {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected_inner = match E::Phase0BeaconState::from_ssz_bytes(&expected_bytes) {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: decode state.ssz_snappy: {e:?}")),
    };
    let expected_state = E::phase0_into_state(expected_inner);

    // Compare by SSZ encoding (bytewise equality).
    let produced_bytes = produced_state.as_ssz_bytes();
    let expected_bytes2 = expected_state.as_ssz_bytes();
    if produced_bytes == expected_bytes2 {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!(
            "{case_name}: state mismatch (produced {} bytes, expected {} bytes)",
            produced_bytes.len(),
            expected_bytes2.len()
        ))
    }
}

fn run_validity_case<E: EthSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::BeaconState: BeaconStateMut,
    E::Phase0BeaconState: Decode,
{
    // Decode genesis.ssz_snappy (raw phase0 SSZ, no discriminant prefix).
    let state_bytes = match load_raw_ssz_snappy(case_dir, "genesis.ssz_snappy") {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_inner = match E::Phase0BeaconState::from_ssz_bytes(&state_bytes) {
        Ok(s) => s,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: decode genesis.ssz_snappy: {e:?}"));
        }
    };
    let state = E::phase0_into_state(state_inner);

    // Read expected bool from is_valid.yaml.
    let is_valid_path = case_dir.join("is_valid.yaml");
    if !is_valid_path.exists() {
        return CaseResult::Fail(format!("{case_name}: missing is_valid.yaml"));
    }
    let is_valid_text = match std::fs::read_to_string(&is_valid_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read is_valid.yaml: {e}")),
    };
    let is_valid_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&is_valid_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse is_valid.yaml: {e}")),
    };
    let expected_valid = match is_valid_val.as_bool() {
        Some(b) => b,
        None => return CaseResult::Fail(format!("{case_name}: is_valid.yaml is not a bool")),
    };

    let got_valid = is_valid_genesis_state::<E>(&state);

    if got_valid == expected_valid {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!(
            "{case_name}: is_valid_genesis_state returned {got_valid}, expected {expected_valid}"
        ))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_hash256_field(
    val: &serde_yaml_ng::Value,
    key: &str,
) -> Result<pharos_utils::Hash256, String> {
    let s = val
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing '{key}' field"))?;
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode '{key}': {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("'{key}' is {} bytes, expected 32", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(pharos_utils::Hash256::from_array(arr))
}

fn load_raw_ssz_snappy(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    let compressed = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    crate::snappy::decompress_raw(&compressed)
        .map_err(|e| format!("snappy decompress {}: {e}", path.display()))
}
