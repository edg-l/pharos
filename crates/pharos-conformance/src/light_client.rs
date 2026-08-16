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
    capella::light_client::{
        LightClientBootstrap as CapellaLCBootstrap, LightClientHeader as CapellaLCHeader,
        LightClientUpdate as CapellaLCUpdate,
    },
    deneb::light_client::{
        LightClientBootstrap as DenebLCBootstrap, LightClientHeader as DenebLCHeader,
        LightClientUpdate as DenebLCUpdate,
    },
    fork::compute_fork_digest,
    phase0::primitives::{Root, Slot},
};
use pharos_utils::Bytes32;

use crate::fixture_walker::{WalkOpts, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per light-client test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_light_client_*` function.
/// Called by the Phase 7 flat work-pool.
///
/// Walk order: `single_merkle_proof` cases first, then `sync` cases (mirrors
/// `run_light_client_altair/capella/deneb_*`).
///
/// For capella and deneb, `single_merkle_proof` has two sub-dirs: `BeaconState/`
/// then `BeaconBlockBody/` (in that order, same as the existing runner).
///
/// Supported forks: `"altair"`, `"capella"`, `"deneb"`.
pub fn enumerate_light_client(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let mut tasks: Vec<CaseTask> = Vec::new();
    let mut ordinal: u32 = 0;

    // ── single_merkle_proof sub-sweep ─────────────────────────────────────────
    //
    // altair: one sub-dir (BeaconState).
    // capella/deneb: two sub-dirs (BeaconState, BeaconBlockBody) in that order.
    let smp_sub_dirs: &[&str] = match fork {
        "altair" => &["BeaconState"],
        _ => &["BeaconState", "BeaconBlockBody"],
    };

    for &sub_dir_name in smp_sub_dirs {
        let smp_dir = root
            .join(preset)
            .join(fork)
            .join("light_client")
            .join("single_merkle_proof")
            .join(sub_dir_name);

        if !smp_dir.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(&smp_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let case_dir = entry.path();
            if !case_dir.is_dir() {
                continue;
            }
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!(
                "{fork}/light_client/single_merkle_proof/{preset}/{sub_dir_name}/{}",
                dir_name(&case_dir)
            );

            let run: CaseFn = match (fork, sub_dir_name, preset) {
                ("altair", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_case::<pharos_types::MainnetEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("altair", "BeaconState", _) => {
                    Box::new(move || {
                        match run_single_merkle_proof_case::<pharos_types::MinimalEthSpec>(
                            &case_dir, &case_name,
                        ) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    })
                }
                ("capella", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_capella_state_case::<pharos_types::MainnetEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "BeaconState", _) => Box::new(move || {
                    match run_single_merkle_proof_capella_state_case::<pharos_types::MinimalEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "BeaconBlockBody", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_body_case::<pharos_types::MainnetEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "BeaconBlockBody", _) => Box::new(move || {
                    match run_single_merkle_proof_body_case::<pharos_types::MinimalEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_deneb_state_case::<pharos_types::MainnetEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconState", _) => Box::new(move || {
                    match run_single_merkle_proof_deneb_state_case::<pharos_types::MinimalEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconBlockBody", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_deneb_body_case::<pharos_types::MainnetEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconBlockBody", _) => Box::new(move || {
                    match run_single_merkle_proof_deneb_body_case::<pharos_types::MinimalEthSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                // Unknown combination: skip
                _ => Box::new(move || CaseOutcome::Skip),
            };

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }

    // ── sync sub-sweep ────────────────────────────────────────────────────────

    let sync_cases: Vec<(std::path::PathBuf, _)> = walk_category(
        root,
        preset,
        fork,
        "light_client",
        Some("sync"),
        WalkOpts::default(),
    )
    .collect();

    for (case_dir, _meta) in sync_cases {
        let case_ordinal = ordinal;
        ordinal += 1;
        let case_name = format!("{fork}/light_client/sync/{preset}/{}", dir_name(&case_dir));

        let run: CaseFn = match (fork, preset) {
            ("altair", "mainnet") => {
                Box::new(move || match run_sync_case_mainnet(&case_dir, &case_name) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Skip => CaseOutcome::Skip,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                })
            }
            ("altair", _) => Box::new(move || match run_sync_case_minimal(&case_dir, &case_name) {
                CaseResult::Pass => CaseOutcome::Pass,
                CaseResult::Skip => CaseOutcome::Skip,
                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
            }),
            ("capella", "mainnet") => {
                Box::new(
                    move || match run_sync_case_capella_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("capella", _) => {
                Box::new(
                    move || match run_sync_case_capella_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("deneb", "mainnet") => {
                Box::new(
                    move || match run_sync_case_deneb_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("deneb", _) => {
                Box::new(
                    move || match run_sync_case_deneb_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            // Unknown combination: skip
            _ => Box::new(move || CaseOutcome::Skip),
        };

        tasks.push(CaseTask {
            row_ordinal,
            case_ordinal,
            run,
        });
    }

    tasks
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

fn run_single_merkle_proof_capella_state_case<E: EthSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::CapellaBeaconState: Decode + TreeHash,
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

    // Load object as capella BeaconState.
    let state_inner = match load_ssz_snappy::<E::CapellaBeaconState>(case_dir, "object.ssz_snappy")
    {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

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

/// Run a single_merkle_proof case against a capella `BeaconBlockBody`.
fn run_single_merkle_proof_body_case<E: EthSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::CapellaBeaconBlockBody: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}")),
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}")),
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf_index")),
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: branch[{i}] not string")),
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let body_inner =
        match load_ssz_snappy::<E::CapellaBeaconBlockBody>(case_dir, "object.ssz_snappy") {
            Ok(s) => s,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let body_root = body_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &body_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_sync_case_capella_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_capella_impl::<MainnetEthSpec, 512, 256, 32>(case_dir, case_name)
}

fn run_sync_case_capella_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_capella_impl::<MinimalEthSpec, 32, 256, 32>(case_dir, case_name)
}

/// Simple in-memory capella light-client store for the conformance runner.
///
/// Mirrors `altair::LightClientStore` but uses the Capella `LightClientHeader`.
struct CapellaLcStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    finalized_header: CapellaLCHeader<B, X>,
    #[allow(dead_code)]
    current_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    next_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    best_valid_update: Option<CapellaLCUpdate<S, B, X>>,
    optimistic_header: CapellaLCHeader<B, X>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
}

fn run_sync_case_capella_impl<E, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E: EthSpec,
    CapellaLCBootstrap<S, B, X>: Decode,
    CapellaLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + PartialEq + Clone,
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
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}")),
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

    let bootstrap_fork_digest_str = meta_val
        .get("bootstrap_fork_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Check if this is a capella test (store_fork_version = capella fork version).
    // Cross-fork tests (deneb/electra/etc.) are skipped.
    let is_cross_fork = if let Some(store_digest_str) =
        meta_val.get("store_fork_digest").and_then(|v| v.as_str())
    {
        store_digest_str != bootstrap_fork_digest_str
    } else if let Some(store_version_str) =
        meta_val.get("store_fork_version").and_then(|v| v.as_str())
    {
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
            _ => true,
        }
    } else {
        false
    };

    if is_cross_fork {
        return CaseResult::Skip;
    }

    // Load bootstrap.
    let bootstrap =
        match load_ssz_snappy::<CapellaLCBootstrap<S, B, X>>(case_dir, "bootstrap.ssz_snappy") {
            Ok(b) => b,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    // Verify bootstrap header root matches trusted_block_root.
    let header_root = bootstrap.header.beacon.tree_hash_root();
    if header_root != trusted_block_root {
        return CaseResult::Fail(format!(
            "{case_name}: bootstrap header root {header_root:?} != trusted {trusted_block_root:?}"
        ));
    }

    let mut store: CapellaLcStore<S, B, X> = CapellaLcStore {
        finalized_header: bootstrap.header.clone(),
        current_sync_committee: bootstrap.current_sync_committee.clone(),
        next_sync_committee: Default::default(),
        best_valid_update: None,
        optimistic_header: bootstrap.header.clone(),
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
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

    let update_timeout = E::SLOTS_PER_EPOCH * E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

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
            // Apply force update.
            if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                && store.best_valid_update.is_some()
            {
                let mut best = store.best_valid_update.take().unwrap();
                if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                    best.finalized_header = best.attested_header.clone();
                }
                apply_capella_lc_update::<S, B, X>(&mut store, &best);
            }
            if let Some(checks) = force_update.get("checks") {
                if let Err(e) = check_capella_store::<S, B, X>(&store, checks, case_name, step_idx)
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

            let update_fork_digest = process_update
                .get("update_fork_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !update_fork_digest.is_empty() && update_fork_digest != bootstrap_fork_digest_str {
                continue;
            }

            let update = match load_ssz_snappy::<CapellaLCUpdate<S, B, X>>(case_dir, &update_file) {
                Ok(u) => u,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: load update: {e}"
                    ));
                }
            };

            if let Err(e) = process_capella_lc_update::<S, B, X>(
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
                if let Err(e) = check_capella_store::<S, B, X>(&store, checks, case_name, step_idx)
                {
                    return CaseResult::Fail(e);
                }
            }
        } else if step.get("upgrade_store").is_some() {
            // Cross-fork store upgrade; skip for capella-only runner.
            continue;
        }
    }

    CaseResult::Pass
}

fn check_capella_store<const S: u64, const B: u64, const X: u64>(
    store: &CapellaLcStore<S, B, X>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
) -> Result<(), String>
where
    Bytes32: Default + Clone,
{
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

/// Apply a capella LC update to the store (mirrors altair `apply_light_client_update`).
fn apply_capella_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut CapellaLcStore<S, B, X>,
    update: &CapellaLCUpdate<S, B, X>,
) where
    Bytes32: Default + Clone + PartialEq,
{
    let default_branch: Vec<Bytes32> = vec![
        Bytes32::default();
        pharos_types::altair::light_client::NEXT_SYNC_COMMITTEE_BRANCH_DEPTH
            as usize
    ];
    if update.next_sync_committee_branch.as_slice() != default_branch.as_slice() {
        // Update next_sync_committee when the sync committee branch is present.
        store.next_sync_committee = update.next_sync_committee.clone();
    }
    store.finalized_header = update.finalized_header.clone();
    if store.optimistic_header.beacon.slot <= store.finalized_header.beacon.slot {
        store.optimistic_header = store.finalized_header.clone();
    }
    // Swap participant counts.
    store.previous_max_active_participants = store.current_max_active_participants;
    store.current_max_active_participants = 0;
}

/// Process a capella LC update (minimal sync protocol implementation).
///
/// Mirrors `process_light_client_update` from the altair sync protocol but
/// works with capella-typed headers. The BLS signature verification is omitted
/// as in the altair conformance runner (the spec tests don't require it for
/// this category).
fn process_capella_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut CapellaLcStore<S, B, X>,
    update: &CapellaLCUpdate<S, B, X>,
    _current_slot: Slot,
    _genesis_validators_root: &Root,
) -> Result<(), String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let n_participants = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|b| *b)
        .count() as u64;

    // Update best valid update.
    let update_is_better = match &store.best_valid_update {
        None => true,
        Some(best) => {
            let new_has_fin = is_capella_finality_update(update);
            let best_has_fin = is_capella_finality_update(best);
            if new_has_fin != best_has_fin {
                new_has_fin
            } else {
                n_participants
                    > best
                        .sync_aggregate
                        .sync_committee_bits
                        .iter()
                        .filter(|b| *b)
                        .count() as u64
            }
        }
    };
    if update_is_better {
        store.best_valid_update = Some(update.clone());
    }

    store.current_max_active_participants =
        store.current_max_active_participants.max(n_participants);

    let safety_threshold = store
        .previous_max_active_participants
        .max(store.current_max_active_participants)
        / 2;

    // Update optimistic header.
    if n_participants > safety_threshold
        && update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    {
        store.optimistic_header = update.attested_header.clone();
    }

    // Update finalized header.
    if n_participants * 3 >= S * 2
        && (update.finalized_header.beacon.slot > store.finalized_header.beacon.slot)
    {
        apply_capella_lc_update::<S, B, X>(store, update);
        store.best_valid_update = None;
    }

    Ok(())
}

fn is_capella_finality_update<const S: u64, const B: u64, const X: u64>(
    update: &CapellaLCUpdate<S, B, X>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    update.finality_branch.as_slice()
        != vec![
            Bytes32::default();
            pharos_types::altair::light_client::FINALITY_BRANCH_DEPTH as usize
        ]
        .as_slice()
}

fn run_single_merkle_proof_deneb_state_case<E: EthSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::DenebBeaconState: Decode + TreeHash,
{
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

    let state_inner = match load_ssz_snappy::<E::DenebBeaconState>(case_dir, "object.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

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

fn run_single_merkle_proof_deneb_body_case<E: EthSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::DenebBeaconBlockBody: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}")),
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}")),
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf_index")),
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: branch[{i}] not string")),
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let body_inner = match load_ssz_snappy::<E::DenebBeaconBlockBody>(case_dir, "object.ssz_snappy")
    {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let body_root = body_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &body_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_sync_case_deneb_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_deneb_impl::<MainnetEthSpec, 512, 256, 32>(case_dir, case_name)
}

fn run_sync_case_deneb_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_deneb_impl::<MinimalEthSpec, 32, 256, 32>(case_dir, case_name)
}

/// Simple in-memory deneb light-client store for the conformance runner.
struct DenebLcStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    finalized_header: DenebLCHeader<B, X>,
    #[allow(dead_code)]
    current_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    next_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    best_valid_update: Option<DenebLCUpdate<S, B, X>>,
    optimistic_header: DenebLCHeader<B, X>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
}

fn run_sync_case_deneb_impl<E, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E: EthSpec,
    DenebLCBootstrap<S, B, X>: Decode,
    DenebLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + PartialEq + Clone,
    pharos_utils::BLSPubkey: Default + PartialEq + Clone,
{
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(_) => return CaseResult::Skip,
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}")),
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

    let bootstrap_fork_digest_str = meta_val
        .get("bootstrap_fork_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let is_cross_fork = if let Some(store_digest_str) =
        meta_val.get("store_fork_digest").and_then(|v| v.as_str())
    {
        store_digest_str != bootstrap_fork_digest_str
    } else if let Some(store_version_str) =
        meta_val.get("store_fork_version").and_then(|v| v.as_str())
    {
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
            _ => true,
        }
    } else {
        false
    };

    if is_cross_fork {
        return CaseResult::Skip;
    }

    let bootstrap =
        match load_ssz_snappy::<DenebLCBootstrap<S, B, X>>(case_dir, "bootstrap.ssz_snappy") {
            Ok(b) => b,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let header_root = bootstrap.header.beacon.tree_hash_root();
    if header_root != trusted_block_root {
        return CaseResult::Fail(format!(
            "{case_name}: bootstrap header root {header_root:?} != trusted {trusted_block_root:?}"
        ));
    }

    let mut store: DenebLcStore<S, B, X> = DenebLcStore {
        finalized_header: bootstrap.header.clone(),
        current_sync_committee: bootstrap.current_sync_committee.clone(),
        next_sync_committee: Default::default(),
        best_valid_update: None,
        optimistic_header: bootstrap.header.clone(),
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
    };

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

    let update_timeout = E::SLOTS_PER_EPOCH * E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

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
            if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                && store.best_valid_update.is_some()
            {
                let mut best = store.best_valid_update.take().unwrap();
                if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                    best.finalized_header = best.attested_header.clone();
                }
                apply_deneb_lc_update::<S, B, X>(&mut store, &best);
            }
            if let Some(checks) = force_update.get("checks") {
                if let Err(e) = check_deneb_store::<S, B, X>(&store, checks, case_name, step_idx) {
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

            let update_fork_digest = process_update
                .get("update_fork_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !update_fork_digest.is_empty() && update_fork_digest != bootstrap_fork_digest_str {
                continue;
            }

            let update = match load_ssz_snappy::<DenebLCUpdate<S, B, X>>(case_dir, &update_file) {
                Ok(u) => u,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: load update: {e}"
                    ));
                }
            };

            if let Err(e) = process_deneb_lc_update::<S, B, X>(
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
                if let Err(e) = check_deneb_store::<S, B, X>(&store, checks, case_name, step_idx) {
                    return CaseResult::Fail(e);
                }
            }
        } else if step.get("upgrade_store").is_some() {
            continue;
        }
    }

    CaseResult::Pass
}

fn check_deneb_store<const S: u64, const B: u64, const X: u64>(
    store: &DenebLcStore<S, B, X>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
) -> Result<(), String>
where
    Bytes32: Default + Clone,
{
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

fn apply_deneb_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut DenebLcStore<S, B, X>,
    update: &DenebLCUpdate<S, B, X>,
) where
    Bytes32: Default + Clone + PartialEq,
{
    let default_branch: Vec<Bytes32> = vec![
        Bytes32::default();
        pharos_types::altair::light_client::NEXT_SYNC_COMMITTEE_BRANCH_DEPTH
            as usize
    ];
    if update.next_sync_committee_branch.as_slice() != default_branch.as_slice() {
        store.next_sync_committee = update.next_sync_committee.clone();
    }
    store.finalized_header = update.finalized_header.clone();
    if store.optimistic_header.beacon.slot <= store.finalized_header.beacon.slot {
        store.optimistic_header = store.finalized_header.clone();
    }
    store.previous_max_active_participants = store.current_max_active_participants;
    store.current_max_active_participants = 0;
}

fn process_deneb_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut DenebLcStore<S, B, X>,
    update: &DenebLCUpdate<S, B, X>,
    _current_slot: Slot,
    _genesis_validators_root: &Root,
) -> Result<(), String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let n_participants = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|b| *b)
        .count() as u64;

    let update_is_better = match &store.best_valid_update {
        None => true,
        Some(best) => {
            let new_has_fin = is_deneb_finality_update(update);
            let best_has_fin = is_deneb_finality_update(best);
            if new_has_fin != best_has_fin {
                new_has_fin
            } else {
                n_participants
                    > best
                        .sync_aggregate
                        .sync_committee_bits
                        .iter()
                        .filter(|b| *b)
                        .count() as u64
            }
        }
    };
    if update_is_better {
        store.best_valid_update = Some(update.clone());
    }

    store.current_max_active_participants =
        store.current_max_active_participants.max(n_participants);

    let safety_threshold = store
        .previous_max_active_participants
        .max(store.current_max_active_participants)
        / 2;

    if n_participants > safety_threshold
        && update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    {
        store.optimistic_header = update.attested_header.clone();
    }

    if n_participants * 3 >= S * 2
        && (update.finalized_header.beacon.slot > store.finalized_header.beacon.slot)
    {
        apply_deneb_lc_update::<S, B, X>(store, update);
        store.best_valid_update = None;
    }

    Ok(())
}

fn is_deneb_finality_update<const S: u64, const B: u64, const X: u64>(
    update: &DenebLCUpdate<S, B, X>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    update.finality_branch.as_slice()
        != vec![
            Bytes32::default();
            pharos_types::altair::light_client::FINALITY_BRANCH_DEPTH as usize
        ]
        .as_slice()
}

// ── Internal result ───────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
    Skip,
}
