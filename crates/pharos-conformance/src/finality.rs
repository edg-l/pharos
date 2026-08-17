//! Finality conformance dispatcher.
//!
//! Walks `phase0/finality/finality/pyspec_tests/<case>/` for both presets.
//! Each case has the same block-sequence shape as `sanity/blocks`:
//! - `pre.ssz_snappy`, `blocks_<i>.ssz_snappy` for `i in 0..blocks_count`,
//!   and an optional `post.ssz_snappy`.
//! - `meta.yaml` carries `blocks_count` and an optional `bls_setting`.
//!
//! `post.ssz_snappy` present  → all blocks apply successfully; final state equals post.
//! `post.ssz_snappy` absent   → at least one block fails (negative test).
//!
//! All forks share the generic `fixture_walker::run_blocks_case`; per-fork arms
//! differ only by the pre/post loader, the block loader, and the `RuntimeConfig`
//! passed (phase0/altair use `RuntimeConfig::default()`; bellatrix+ use
//! `E::default_runtime_config()`).

use std::path::{Path, PathBuf};

use pharos_types::config::RuntimeConfig;
use pharos_types::{BeaconSpec, MainnetBeaconSpec, MinimalBeaconSpec};

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_bellatrix_signed_block, load_capella_signed_block,
    load_deneb_signed_block, load_electra_signed_block, load_fulu_signed_block,
    load_phase0_signed_block, load_pre_post_altair_state, load_pre_post_bellatrix_state,
    load_pre_post_capella_state, load_pre_post_deneb_state, load_pre_post_electra_state,
    load_pre_post_fulu_state, load_pre_post_phase0_state, run_blocks_case, walk_category,
};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per finality test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_finality_*` function.
/// Called by the flat work-pool.
///
/// Supported forks: `"phase0"`, `"altair"`, `"bellatrix"`, `"capella"`, `"deneb"`.
pub fn enumerate_finality(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let cases: Vec<(PathBuf, _)> = walk_category(
        root,
        preset,
        fork,
        "finality",
        Some("finality"),
        WalkOpts::default(),
    )
    .collect();

    cases
        .into_iter()
        .enumerate()
        .map(|(i, (case_dir, meta))| {
            let case_ordinal = i as u32;
            let case_name = format!("{fork}/finality/finality/{preset}/{}", dir_name(&case_dir));
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

            CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            }
        })
        .collect()
}
