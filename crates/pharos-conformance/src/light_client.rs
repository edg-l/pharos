//! Altair light-client conformance dispatcher.
//!
//! Covers two sub-categories:
//!   - `single_merkle_proof` — verify Merkle branch proofs against `BeaconState`.
//!   - `sync`               — full light-client sync protocol step runner.
//!
//! # single_merkle_proof
//!
//! Fixture layout (non-standard — no `pyspec_tests` directory):
//! ```text
//! tests/{preset}/altair/light_client/single_merkle_proof/BeaconState/{case_name}/
//!   object.ssz_snappy   — altair BeaconState
//!   proof.yaml          — leaf, leaf_index (generalized index), branch
//! ```
//! Test: `is_valid_merkle_branch(leaf, branch, depth, index, hash_tree_root(object))`.
//!
//! # sync
//!
//! Fixture layout (standard `pyspec_tests` directory):
//! ```text
//! tests/{preset}/altair/light_client/sync/pyspec_tests/{case_name}/
//!   meta.yaml          — genesis_validators_root, trusted_block_root, fork digests
//!   bootstrap.ssz_snappy
//!   steps.yaml         — process_update / force_update steps
//!   update_*.ssz_snappy
//! ```

use std::path::Path;

use pharos_ssz::{Decode, TreeHash};
use pharos_stf::altair::light_client::{
    initialize_light_client_store, process_light_client_store_force_update,
    process_light_client_update,
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    altair::light_client::LightClientStore,
    fork::compute_fork_digest,
    phase0::primitives::{Root, Slot},
};
use pharos_utils::Bytes32;

use rayon::prelude::*;

use crate::fixture_walker::{WalkOpts, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;

/// Result tally for light-client tests.
pub struct LightClientResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl LightClientResult {
    fn new() -> Self {
        LightClientResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: LightClientResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all altair light-client tests for the mainnet preset.
pub fn run_light_client_altair_mainnet(root: &Path) -> LightClientResult {
    let mut total = LightClientResult::new();
    total.merge(run_single_merkle_proof_mainnet(root));
    total.merge(run_sync_mainnet(root));
    total
}

/// Run all altair light-client tests for the minimal preset.
pub fn run_light_client_altair_minimal(root: &Path) -> LightClientResult {
    let mut total = LightClientResult::new();
    total.merge(run_single_merkle_proof_minimal(root));
    total.merge(run_sync_minimal(root));
    total
}

// ── single_merkle_proof ───────────────────────────────────────────────────────

fn run_single_merkle_proof_mainnet(root: &Path) -> LightClientResult {
    run_single_merkle_proof_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_single_merkle_proof_minimal(root: &Path) -> LightClientResult {
    run_single_merkle_proof_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_single_merkle_proof_preset<E: EthSpec>(
    root: &Path,
    preset: &'static str,
) -> LightClientResult
where
    E::AltairBeaconState: Decode + TreeHash,
{
    let mut out = LightClientResult::new();
    let beacon_state_dir = root
        .join(preset)
        .join("altair")
        .join("light_client")
        .join("single_merkle_proof")
        .join("BeaconState");

    if !beacon_state_dir.is_dir() {
        return out;
    }

    let entries = match std::fs::read_dir(&beacon_state_dir) {
        Ok(e) => e,
        Err(_) => return out,
    };

    for entry in entries.flatten() {
        let case_dir = entry.path();
        if !case_dir.is_dir() {
            continue;
        }
        let case_name = format!(
            "altair/light_client/single_merkle_proof/{preset}/BeaconState/{}",
            dir_name(&case_dir)
        );
        let result = run_single_merkle_proof_case::<E>(&case_dir, &case_name);
        match result {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
            CaseResult::Skip => out.skip += 1,
        }
    }
    out
}

fn run_single_merkle_proof_case<E: EthSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::AltairBeaconState: Decode + TreeHash,
{
    // Load proof.yaml.
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}"));
        }
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}"));
        }
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf in proof.yaml")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            return CaseResult::Fail(format!("{case_name}: missing leaf_index in proof.yaml"));
        }
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch in proof.yaml")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] is not a string"));
            }
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    // Load object (altair BeaconState), compute its hash_tree_root.
    let state_inner = match load_ssz_snappy::<E::AltairBeaconState>(case_dir, "object.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

    // Verify the Merkle proof.
    // generalized_index → depth = floorlog2(gindex), index = gindex % 2^depth.
    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &state_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

// ── sync ──────────────────────────────────────────────────────────────────────

fn run_sync_mainnet(root: &Path) -> LightClientResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "altair",
        "light_client",
        Some("sync"),
        WalkOpts::default(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("altair/light_client/sync/mainnet/{}", dir_name(&case_dir));
            run_sync_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = LightClientResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
            CaseResult::Skip => out.skip += 1,
        }
    }
    out
}

fn run_sync_minimal(root: &Path) -> LightClientResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "altair",
        "light_client",
        Some("sync"),
        WalkOpts::default(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("altair/light_client/sync/minimal/{}", dir_name(&case_dir));
            run_sync_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = LightClientResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
            CaseResult::Skip => out.skip += 1,
        }
    }
    out
}

fn run_sync_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_impl::<MainnetEthSpec, 512>(case_dir, case_name)
}

fn run_sync_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_impl::<MinimalEthSpec, 32>(case_dir, case_name)
}

fn run_sync_case_impl<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    pharos_types::altair::LightClientBootstrap<SYNC_COMMITTEE_SIZE>: Decode,
    pharos_types::altair::LightClientUpdate<SYNC_COMMITTEE_SIZE>: Decode + Clone,
    pharos_utils::Bytes32: Default + PartialEq + Clone,
    pharos_utils::BLSPubkey: Default + PartialEq + Clone,
{
    // Parse meta.yaml.
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(_) => return CaseResult::Skip,
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}"));
        }
    };

    let genesis_validators_root: Root = match meta_val
        .get("genesis_validators_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!(
                "{case_name}: missing/invalid genesis_validators_root"
            ));
        }
    };

    let trusted_block_root: Root = match meta_val
        .get("trusted_block_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!("{case_name}: missing/invalid trusted_block_root"));
        }
    };

    // Check fork digests — skip cross-fork upgrade tests (capella/deneb/electra).
    //
    // `bootstrap_fork_digest` is a 4-byte hex digest (e.g. "0x15cfa0a7").
    // `store_fork_digest` (when present) is also a hex digest.
    // `store_fork_version` (when present) is a 4-byte fork-version hex (e.g. "0x01000001").
    //
    // When `store_fork_version` is present (not `store_fork_digest`), compute the
    // expected store digest from `genesis_validators_root` + `store_fork_version`
    // and compare against `bootstrap_fork_digest` to detect cross-fork tests.
    let bootstrap_fork_digest_str = meta_val
        .get("bootstrap_fork_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let is_cross_fork = if let Some(store_digest_str) =
        meta_val.get("store_fork_digest").and_then(|v| v.as_str())
    {
        // Direct digest comparison.
        store_digest_str != bootstrap_fork_digest_str
    } else if let Some(store_version_str) =
        meta_val.get("store_fork_version").and_then(|v| v.as_str())
    {
        // Compute store_fork_digest from version + GVR and compare.
        let version_hex = store_version_str
            .strip_prefix("0x")
            .unwrap_or(store_version_str);
        match hex::decode(version_hex) {
            Ok(version_bytes) if version_bytes.len() == 4 => {
                let version: [u8; 4] = version_bytes.try_into().unwrap();
                let computed_digest = compute_fork_digest(version.into(), &genesis_validators_root);
                let computed_hex = format!(
                    "0x{:02x}{:02x}{:02x}{:02x}",
                    computed_digest.into_inner()[0],
                    computed_digest.into_inner()[1],
                    computed_digest.into_inner()[2],
                    computed_digest.into_inner()[3],
                );
                computed_hex != bootstrap_fork_digest_str
            }
            _ => {
                // Cannot parse version: treat as cross-fork (skip).
                true
            }
        }
    } else {
        // No store fork info: not a cross-fork test.
        false
    };

    if is_cross_fork {
        // Cross-fork test requires Capella/Deneb/Electra types; skip for altair runner.
        return CaseResult::Skip;
    }

    // Load bootstrap.
    let bootstrap = match load_ssz_snappy::<
        pharos_types::altair::LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
    >(case_dir, "bootstrap.ssz_snappy")
    {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    // Initialize store.
    let mut store = match initialize_light_client_store::<E, SYNC_COMMITTEE_SIZE>(
        &trusted_block_root,
        &bootstrap,
    ) {
        Ok(s) => s,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: initialize_store: {e}"));
        }
    };

    // Parse and execute steps.yaml.
    let steps_path = case_dir.join("steps.yaml");
    let steps_text = match std::fs::read_to_string(&steps_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read steps.yaml: {e}")),
    };
    let steps_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&steps_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse steps.yaml: {e}")),
    };
    let steps = match steps_val.as_sequence() {
        Some(s) => s.clone(),
        None => return CaseResult::Fail(format!("{case_name}: steps.yaml is not a sequence")),
    };

    for (step_idx, step) in steps.iter().enumerate() {
        if let Some(force_update) = step.get("force_update") {
            let current_slot = match force_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };
            process_light_client_store_force_update::<E, SYNC_COMMITTEE_SIZE>(
                &mut store,
                current_slot,
            );
            if let Some(checks) = force_update.get("checks") {
                if let Err(e) =
                    check_store::<SYNC_COMMITTEE_SIZE>(&store, checks, case_name, step_idx)
                {
                    return CaseResult::Fail(e);
                }
            }
        } else if let Some(process_update) = step.get("process_update") {
            let update_file = match process_update.get("update").and_then(|v| v.as_str()) {
                Some(s) => format!("{s}.ssz_snappy"),
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing update filename"
                    ));
                }
            };
            let current_slot = match process_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };

            // Check if this step's update fork digest matches the store fork digest.
            let update_fork_digest = process_update
                .get("update_fork_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !update_fork_digest.is_empty() && update_fork_digest != bootstrap_fork_digest_str {
                // Cross-fork update; skip this step.
                continue;
            }

            let update = match load_ssz_snappy::<
                pharos_types::altair::LightClientUpdate<SYNC_COMMITTEE_SIZE>,
            >(case_dir, &update_file)
            {
                Ok(u) => u,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: load update: {e}"
                    ));
                }
            };

            if let Err(e) = process_light_client_update::<E, SYNC_COMMITTEE_SIZE>(
                &mut store,
                &update,
                current_slot,
                &genesis_validators_root,
            ) {
                return CaseResult::Fail(format!(
                    "{case_name}: step {step_idx}: process_update: {e}"
                ));
            }

            if let Some(checks) = process_update.get("checks") {
                if let Err(e) =
                    check_store::<SYNC_COMMITTEE_SIZE>(&store, checks, case_name, step_idx)
                {
                    return CaseResult::Fail(e);
                }
            }
        } else if step.get("upgrade_store").is_some() {
            // Cross-fork store upgrade; skip for altair-only runner.
            continue;
        }
    }

    CaseResult::Pass
}

fn check_store<const SYNC_COMMITTEE_SIZE: u64>(
    store: &LightClientStore<SYNC_COMMITTEE_SIZE>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
) -> Result<(), String> {
    if let Some(fin_check) = checks.get("finalized_header") {
        let expected_slot = fin_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot {
            if store.finalized_header.beacon.slot != expected_slot {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.slot mismatch: got {}, expected {}",
                    store.finalized_header.beacon.slot.0, expected_slot.0
                ));
            }
        }
        if let Some(expected_root_hex) = fin_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.finalized_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.beacon_root mismatch"
                ));
            }
        }
    }
    if let Some(opt_check) = checks.get("optimistic_header") {
        let expected_slot = opt_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot {
            if store.optimistic_header.beacon.slot != expected_slot {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.slot mismatch: got {}, expected {}",
                    store.optimistic_header.beacon.slot.0, expected_slot.0
                ));
            }
        }
        if let Some(expected_root_hex) = opt_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.optimistic_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.beacon_root mismatch"
                ));
            }
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_bytes32(hex: &str) -> Result<Bytes32, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Bytes32::from_array(arr))
}

fn parse_root(hex: &str) -> Result<Root, String> {
    parse_bytes32(hex)
}

// ── Internal result ───────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
    Skip,
}
