//! Sanity conformance dispatcher.
//!
//! Covers two sub-categories of `phase0/sanity` for both presets:
//!   - `blocks`  — apply a sequence of signed blocks via `state_transition`.
//!   - `slots`   — advance the state forward by N slots via `process_slots`.
//!
//! # blocks sub-category
//!
//! Each case has `pre.ssz_snappy`, `blocks_<i>.ssz_snappy` for `i in
//! 0..blocks_count`, and an optional `post.ssz_snappy`:
//! - post present  → all blocks must apply successfully; final state must equal post.
//! - post absent   → at least one block must fail `state_transition` (negative test).
//!
//! `bls_setting`:
//! - `2` → `validate_result = false` (BLS ignored, signatures are placeholders).
//! - otherwise    → `validate_result = true`.
//!
//! # slots sub-category
//!
//! Each case has `pre.ssz_snappy`, `post.ssz_snappy`, and `slots.yaml` (a bare
//! integer, optionally followed by YAML `...` end-document marker). The fixture
//! contains no `meta.yaml`, so `WalkOpts::meta_required` is `false`.

use std::path::{Path, PathBuf};

use pharos_ssz::Encode;
use pharos_stf::altair::state_transition::process_slots_altair;
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::process_slots;
use pharos_types::config::RuntimeConfig;
use pharos_types::{
    BeaconSpec, BeaconStateView, MainnetBeaconSpec, MinimalBeaconSpec,
    phase0::{Attestation, Slot},
    views::BeaconBlockBodyView,
};

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_bellatrix_signed_block,
    load_bellatrix_state, load_capella_signed_block, load_capella_state, load_deneb_signed_block,
    load_deneb_state, load_electra_signed_block, load_electra_state, load_fulu_signed_block,
    load_fulu_state, load_phase0_signed_block, load_pre_post_altair_state,
    load_pre_post_bellatrix_state, load_pre_post_capella_state, load_pre_post_deneb_state,
    load_pre_post_electra_state, load_pre_post_fulu_state, load_pre_post_phase0_state,
    run_blocks_case, walk_category,
};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per sanity test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_sanity_*` function.
/// Called by the Phase 7 flat work-pool.
///
/// Sub-sweep order: blocks cases fully, then slots cases (matches dispatcher order).
///
/// Supported forks: `"phase0"`, `"altair"`, `"bellatrix"`, `"capella"`, `"deneb"`.
pub fn enumerate_sanity(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let mut tasks: Vec<CaseTask> = Vec::new();
    let mut ordinal: u32 = 0;

    // ── blocks sub-sweep ──────────────────────────────────────────────────────
    {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            fork,
            "sanity",
            Some("blocks"),
            WalkOpts::default(),
        )
        .collect();

        for (case_dir, meta) in cases {
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!("{fork}/sanity/blocks/{preset}/{}", dir_name(&case_dir));
            let blocks_count = meta.as_ref().and_then(|m| m.blocks_count);
            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);

            let run: CaseFn = match (fork, preset) {
                ("phase0", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &RuntimeConfig::default(),
                        load_pre_post_phase0_state::<MainnetBeaconSpec>,
                        load_phase0_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("phase0", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &RuntimeConfig::default(),
                        load_pre_post_phase0_state::<MinimalBeaconSpec>,
                        load_phase0_signed_block::<MinimalBeaconSpec>,
                    )
                }),
                ("altair", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &RuntimeConfig::default(),
                        load_pre_post_altair_state::<MainnetBeaconSpec>,
                        load_altair_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("altair", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &RuntimeConfig::default(),
                        load_pre_post_altair_state::<MinimalBeaconSpec>,
                        load_altair_signed_block::<MinimalBeaconSpec>,
                    )
                }),
                ("bellatrix", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MainnetBeaconSpec::default_runtime_config(),
                        load_pre_post_bellatrix_state::<MainnetBeaconSpec>,
                        load_bellatrix_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("bellatrix", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MinimalBeaconSpec::default_runtime_config(),
                        load_pre_post_bellatrix_state::<MinimalBeaconSpec>,
                        load_bellatrix_signed_block::<MinimalBeaconSpec>,
                    )
                }),
                ("capella", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MainnetBeaconSpec::default_runtime_config(),
                        load_pre_post_capella_state::<MainnetBeaconSpec>,
                        load_capella_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("capella", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MinimalBeaconSpec::default_runtime_config(),
                        load_pre_post_capella_state::<MinimalBeaconSpec>,
                        load_capella_signed_block::<MinimalBeaconSpec>,
                    )
                }),
                ("deneb", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MainnetBeaconSpec::default_runtime_config(),
                        load_pre_post_deneb_state::<MainnetBeaconSpec>,
                        load_deneb_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("deneb", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MinimalBeaconSpec::default_runtime_config(),
                        load_pre_post_deneb_state::<MinimalBeaconSpec>,
                        load_deneb_signed_block::<MinimalBeaconSpec>,
                    )
                }),
                ("electra", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MainnetBeaconSpec::default_runtime_config(),
                        load_pre_post_electra_state::<MainnetBeaconSpec>,
                        load_electra_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("fulu", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MainnetBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MainnetBeaconSpec::default_runtime_config(),
                        load_pre_post_fulu_state::<MainnetBeaconSpec>,
                        load_fulu_signed_block::<MainnetBeaconSpec>,
                    )
                }),
                ("fulu", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MinimalBeaconSpec::default_runtime_config(),
                        load_pre_post_fulu_state::<MinimalBeaconSpec>,
                        load_fulu_signed_block::<MinimalBeaconSpec>,
                    )
                }),
                _ => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    run_blocks_case::<MinimalBeaconSpec, _, _>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                        &MinimalBeaconSpec::default_runtime_config(),
                        load_pre_post_electra_state::<MinimalBeaconSpec>,
                        load_electra_signed_block::<MinimalBeaconSpec>,
                    )
                }),
            };
            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }

    // ── slots sub-sweep ───────────────────────────────────────────────────────
    {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            fork,
            "sanity",
            Some("slots"),
            WalkOpts {
                meta_required: false,
                inner_dir: Some("pyspec_tests"),
            },
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!("{fork}/sanity/slots/{preset}/{}", dir_name(&case_dir));

            let run: CaseFn =
                match (fork, preset) {
                    ("phase0", "mainnet") => Box::new(move || {
                        match run_slots_case::<MainnetBeaconSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("phase0", _) => Box::new(move || {
                        match run_slots_case::<MinimalBeaconSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("altair", "mainnet") => {
                        Box::new(move || {
                            match run_altair_slots_case_mainnet(&case_dir, &case_name) {
                                CaseResult::Pass => CaseOutcome::Pass,
                                CaseResult::Skip => CaseOutcome::Skip,
                                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                            }
                        })
                    }
                    ("altair", _) => Box::new(move || {
                        match run_altair_slots_case_minimal(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("bellatrix", "mainnet") => Box::new(move || {
                        match run_bellatrix_slots_case_mainnet(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("bellatrix", _) => Box::new(move || {
                        match run_bellatrix_slots_case_minimal(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("capella", "mainnet") => {
                        Box::new(move || {
                            match run_capella_slots_case_mainnet(&case_dir, &case_name) {
                                CaseResult::Pass => CaseOutcome::Pass,
                                CaseResult::Skip => CaseOutcome::Skip,
                                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                            }
                        })
                    }
                    ("capella", _) => Box::new(move || {
                        match run_capella_slots_case_minimal(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("deneb", "mainnet") => Box::new(move || {
                        match run_deneb_slots_case_mainnet(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("deneb", _) => Box::new(move || {
                        match run_deneb_slots_case_minimal(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("electra", "mainnet") => {
                        Box::new(move || {
                            match run_electra_slots_case_mainnet(&case_dir, &case_name) {
                                CaseResult::Pass => CaseOutcome::Pass,
                                CaseResult::Skip => CaseOutcome::Skip,
                                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                            }
                        })
                    }
                    ("fulu", "mainnet") => {
                        Box::new(
                            move || match run_fulu_slots_case_mainnet(&case_dir, &case_name) {
                                CaseResult::Pass => CaseOutcome::Pass,
                                CaseResult::Skip => CaseOutcome::Skip,
                                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                            },
                        )
                    }
                    ("fulu", _) => {
                        Box::new(
                            move || match run_fulu_slots_case_minimal(&case_dir, &case_name) {
                                CaseResult::Pass => CaseOutcome::Pass,
                                CaseResult::Skip => CaseOutcome::Skip,
                                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                            },
                        )
                    }
                    _ => Box::new(move || {
                        match run_electra_slots_case_minimal(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                };
            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }

    tasks
}

fn run_slots_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: BeaconSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconState: pharos_ssz::Decode,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    // slots.yaml is a bare integer (optionally followed by YAML end-document `...`).
    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match post {
        Some(p) => p,
        None => return CaseResult::Fail(format!("{case_name}: missing post.ssz_snappy")),
    };

    let target_slot = Slot(pre.slot().0 + slots_count);
    if let Err(e) = process_slots::<E>(&mut pre, target_slot) {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }

    if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

// ── YAML helper ───────────────────────────────────────────────────────────────

/// Parse a bare integer from a YAML file.
///
/// `slots.yaml` in the sanity/slots fixtures is a single integer value,
/// optionally followed by a YAML end-document marker (`...`). Example:
/// ```text
/// 1
/// ...
/// ```
fn read_u64_yaml(path: &Path) -> Result<u64, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let val: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
        .map_err(|e| format!("yaml parse {}: {e}", path.display()))?;
    val.as_u64()
        .ok_or_else(|| format!("{}: expected integer, got {:?}", path.display(), val))
}

fn run_altair_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_types::MainnetBeaconSpec as E;
    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_altair_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_altair_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_altair_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not altair state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) =
        process_slots_altair::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
            &mut pre_inner,
            target_slot,
        )
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::altair_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_altair_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_types::MinimalBeaconSpec as E;
    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_altair_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_altair_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_altair_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not altair state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_altair::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut pre_inner,
        target_slot,
    ) {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::altair_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_bellatrix_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::bellatrix::state_transition::process_slots_bellatrix;
    use pharos_types::MainnetBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_bellatrix_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_bellatrix_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_bellatrix_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not bellatrix state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_bellatrix::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        256,
        32,
        E,
    >(&mut pre_inner, target_slot)
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::bellatrix_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_bellatrix_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::bellatrix::state_transition::process_slots_bellatrix;
    use pharos_types::MinimalBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_bellatrix_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_bellatrix_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_bellatrix_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not bellatrix state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) =
        process_slots_bellatrix::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, 256, 32, E>(
            &mut pre_inner,
            target_slot,
        )
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::bellatrix_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

// ── Internal result type ──────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
    #[allow(dead_code)]
    Skip,
}

fn run_capella_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::state_transition::process_slots_capella;
    use pharos_types::MainnetBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_capella_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_capella_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_capella_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not capella state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_capella::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        256,
        32,
        E,
    >(&mut pre_inner, target_slot)
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::capella_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}
fn run_capella_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::state_transition::process_slots_capella;
    use pharos_types::MinimalBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_capella_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_capella_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_capella_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not capella state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) =
        process_slots_capella::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, 256, 32, E>(
            &mut pre_inner,
            target_slot,
        )
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::capella_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_deneb_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::deneb::state_transition::process_slots_deneb;
    use pharos_types::MainnetBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_deneb_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_deneb_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_deneb_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not deneb state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_deneb::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        256,
        32,
        E,
    >(&mut pre_inner, target_slot)
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::deneb_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_deneb_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::deneb::state_transition::process_slots_deneb;
    use pharos_types::MinimalBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_deneb_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_deneb_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_deneb_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not deneb state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) =
        process_slots_deneb::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, 256, 32, E>(
            &mut pre_inner,
            target_slot,
        )
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::deneb_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_electra_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::electra::state_transition::process_slots_electra_with_cfg;
    use pharos_types::MainnetBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_electra_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_electra_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_electra_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not electra state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_electra_with_cfg::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        256,
        32,
        134_217_728,
        134_217_728,
        262_144,
        E,
    >(&mut pre_inner, target_slot, &E::default_runtime_config())
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::electra_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_electra_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::electra::state_transition::process_slots_electra_with_cfg;
    use pharos_types::MinimalBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_electra_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_electra_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_electra_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not electra state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_electra_with_cfg::<
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        32,
        256,
        32,
        134_217_728,
        64,
        64,
        E,
    >(&mut pre_inner, target_slot, &E::default_runtime_config())
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::electra_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_fulu_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::fulu::state_transition::process_slots_fulu_with_cfg;
    use pharos_types::MainnetBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_fulu_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_fulu_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_fulu_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not fulu state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_fulu_with_cfg::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        256,
        32,
        134_217_728,
        134_217_728,
        262_144,
        64,
        E,
    >(&mut pre_inner, target_slot, &E::default_runtime_config())
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::fulu_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}

fn run_fulu_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::fulu::state_transition::process_slots_fulu_with_cfg;
    use pharos_types::MinimalBeaconSpec as E;

    let slots_path = case_dir.join("slots.yaml");
    let slots_count: u64 = match read_u64_yaml(&slots_path) {
        Ok(n) => n,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let pre_state = match load_fulu_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_fulu_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre_inner = match E::into_fulu_state(pre_state) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not fulu state")),
    };
    let target_slot = Slot(pre_inner.slot.0 + slots_count);
    if let Err(e) = process_slots_fulu_with_cfg::<
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        32,
        256,
        32,
        134_217_728,
        64,
        64,
        16,
        E,
    >(&mut pre_inner, target_slot, &E::default_runtime_config())
    {
        return CaseResult::Fail(format!("{case_name}: process_slots failed: {e}"));
    }
    let final_state = E::fulu_into_state(pre_inner);
    if final_state.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after slots advance"))
    }
}
