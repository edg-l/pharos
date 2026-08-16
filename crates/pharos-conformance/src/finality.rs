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

use std::path::{Path, PathBuf};

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::{
    AltairProcessSlotsDispatch, AltairUpgradeDispatch, BellatrixProcessSlotsDispatch,
    BellatrixUpgradeDispatch, CapellaProcessSlotsDispatch, CapellaUpgradeDispatch,
    DenebProcessSlotsDispatch, Phase0UpgradeDispatch, state_transition,
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use rayon::prelude::*;

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_bellatrix_signed_block, load_capella_signed_block,
    load_deneb_signed_block, load_phase0_signed_block, load_pre_post_altair_state,
    load_pre_post_bellatrix_state, load_pre_post_capella_state, load_pre_post_deneb_state,
    load_pre_post_phase0_state, walk_category,
};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Result tally for a single finality preset run.
pub struct FinalityResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl FinalityResult {
    fn new() -> Self {
        FinalityResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per finality test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_finality_*` function.
/// Called by the Phase 7 flat work-pool.
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
                    match run_blocks_case::<MainnetEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("phase0", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_blocks_case::<MinimalEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("altair", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_altair_blocks_case::<MainnetEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("altair", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_altair_blocks_case::<MinimalEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("bellatrix", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_bellatrix_blocks_case::<MainnetEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("bellatrix", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_bellatrix_blocks_case::<MinimalEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_capella_finality_blocks_case::<MainnetEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", _) => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_capella_finality_blocks_case::<MinimalEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "mainnet") => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_deneb_finality_blocks_case::<MainnetEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                _ => Box::new(move || {
                    let Some(n) = blocks_count else {
                        return CaseOutcome::Skip;
                    };
                    match run_deneb_finality_blocks_case::<MinimalEthSpec>(
                        &case_dir,
                        &case_name,
                        n,
                        validate_result,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
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

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all finality tests for the mainnet preset.
pub fn run_finality_mainnet(root: &Path) -> FinalityResult {
    run_finality_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all finality tests for the minimal preset.
pub fn run_finality_minimal(root: &Path) -> FinalityResult {
    run_finality_preset::<MinimalEthSpec>(root, "minimal")
}

/// Run all finality tests for a single preset.
pub fn run_finality_preset<E>(root: &Path, preset: &'static str) -> FinalityResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState:
        pharos_stf::AltairDispatch<E> + AltairProcessSlotsDispatch<E> + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "finality",
        Some("finality"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("phase0/finality/finality/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = FinalityResult::new();
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

// ── Block-sequence case runner ────────────────────────────────────────────────

fn run_blocks_case<E>(
    case_dir: &Path,
    case_name: &str,
    blocks_count: u64,
    validate_result: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState:
        pharos_stf::AltairDispatch<E> + AltairProcessSlotsDispatch<E> + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let (pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut current: Option<E::BeaconState> = Some(pre);
    let mut block_error: Option<String> = None;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block = match load_phase0_signed_block::<E>(case_dir, &block_file) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let state = current.take().unwrap();
        match state_transition::<E, pharos_stf::NullExecutionEngine>(
            state,
            &block,
            &pharos_stf::NullExecutionEngine,
            validate_result,
            &pharos_types::config::RuntimeConfig::default(),
        ) {
            Ok((new_state, _)) => current = Some(new_state),
            Err(e) => {
                block_error = Some(format!("{e}"));
                break;
            }
        }
    }

    match (block_error, post) {
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        (None, None) => CaseResult::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        (Some(_), None) => CaseResult::Pass,
        (Some(e), Some(_)) => {
            CaseResult::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
}

// ── Altair entry points ───────────────────────────────────────────────────────

/// Run all altair finality tests for the mainnet preset.
pub fn run_finality_altair_mainnet(root: &Path) -> FinalityResult {
    run_finality_altair_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all altair finality tests for the minimal preset.
pub fn run_finality_altair_minimal(root: &Path) -> FinalityResult {
    run_finality_altair_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_finality_altair_preset<E>(root: &Path, preset: &'static str) -> FinalityResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::AltairSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "altair",
        "finality",
        Some("finality"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("altair/finality/finality/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_altair_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = FinalityResult::new();
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

fn run_altair_blocks_case<E>(
    case_dir: &Path,
    case_name: &str,
    blocks_count: u64,
    validate_result: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::AltairSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let (pre, post) = match load_pre_post_altair_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut current: Option<E::BeaconState> = Some(pre);
    let mut block_error: Option<String> = None;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block = match load_altair_signed_block::<E>(case_dir, &block_file) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let state = current.take().unwrap();
        match state_transition::<E, pharos_stf::NullExecutionEngine>(
            state,
            &block,
            &pharos_stf::NullExecutionEngine,
            validate_result,
            &pharos_types::config::RuntimeConfig::default(),
        ) {
            Ok((new_state, _)) => current = Some(new_state),
            Err(e) => {
                block_error = Some(format!("{e}"));
                break;
            }
        }
    }

    match (block_error, post) {
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        (None, None) => CaseResult::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        (Some(_), None) => CaseResult::Pass,
        (Some(e), Some(_)) => {
            CaseResult::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
}

// ── Bellatrix entry points ────────────────────────────────────────────────────

/// Run all bellatrix finality tests for the mainnet preset.
pub fn run_finality_bellatrix_mainnet(root: &Path) -> FinalityResult {
    run_finality_bellatrix_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all bellatrix finality tests for the minimal preset.
pub fn run_finality_bellatrix_minimal(root: &Path) -> FinalityResult {
    run_finality_bellatrix_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_finality_bellatrix_preset<E>(root: &Path, preset: &'static str) -> FinalityResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::BellatrixSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "bellatrix",
        "finality",
        Some("finality"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/finality/finality/{preset}/{}",
                dir_name(&case_dir)
            );

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_bellatrix_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = FinalityResult::new();
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

fn run_bellatrix_blocks_case<E>(
    case_dir: &Path,
    case_name: &str,
    blocks_count: u64,
    validate_result: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::BellatrixSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let (pre, post) = match load_pre_post_bellatrix_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut current: Option<E::BeaconState> = Some(pre);
    let mut block_error: Option<String> = None;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block = match load_bellatrix_signed_block::<E>(case_dir, &block_file) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let state = current.take().unwrap();
        match state_transition::<E, pharos_stf::NullExecutionEngine>(
            state,
            &block,
            &pharos_stf::NullExecutionEngine,
            validate_result,
            &E::default_runtime_config(),
        ) {
            Ok((new_state, _)) => current = Some(new_state),
            Err(e) => {
                block_error = Some(format!("{e}"));
                break;
            }
        }
    }

    match (block_error, post) {
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        (None, None) => CaseResult::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        (Some(_), None) => CaseResult::Pass,
        (Some(e), Some(_)) => {
            CaseResult::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
}

// ── Internal result type ──────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
    Skip,
}

// ── Capella entry points ──────────────────────────────────────────────────────

/// Run all capella finality tests for the mainnet preset.
pub fn run_finality_capella_mainnet(root: &Path) -> FinalityResult {
    run_finality_capella_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all capella finality tests for the minimal preset.
pub fn run_finality_capella_minimal(root: &Path) -> FinalityResult {
    run_finality_capella_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_finality_capella_preset<E>(root: &Path, preset: &'static str) -> FinalityResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "capella",
        "finality",
        Some("finality"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("capella/finality/finality/{preset}/{}", dir_name(&case_dir));
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };
            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_capella_finality_blocks_case::<E>(
                &case_dir,
                &case_name,
                blocks_count,
                validate_result,
            )
        })
        .collect();

    let mut out = FinalityResult::new();
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

fn run_capella_finality_blocks_case<E>(
    case_dir: &Path,
    case_name: &str,
    blocks_count: u64,
    validate_result: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let (pre, post) = match load_pre_post_capella_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut current: Option<E::BeaconState> = Some(pre);
    let mut block_error: Option<String> = None;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block = match load_capella_signed_block::<E>(case_dir, &block_file) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let state = current.take().unwrap();
        match state_transition::<E, pharos_stf::NullExecutionEngine>(
            state,
            &block,
            &pharos_stf::NullExecutionEngine,
            validate_result,
            &E::default_runtime_config(),
        ) {
            Ok((new_state, _)) => current = Some(new_state),
            Err(e) => {
                block_error = Some(format!("{e}"));
                break;
            }
        }
    }

    match (block_error, post) {
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        (None, None) => CaseResult::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        (Some(_), None) => CaseResult::Pass,
        (Some(e), Some(_)) => {
            CaseResult::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
}

// ── Deneb finality entry points ───────────────────────────────────────────────

/// Run all deneb finality tests for the mainnet preset.
pub fn run_finality_deneb_mainnet(root: &Path) -> FinalityResult {
    run_finality_deneb_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all deneb finality tests for the minimal preset.
pub fn run_finality_deneb_minimal(root: &Path) -> FinalityResult {
    run_finality_deneb_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_finality_deneb_preset<E>(root: &Path, preset: &'static str) -> FinalityResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::DenebSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "deneb",
        "finality",
        Some("finality"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("deneb/finality/finality/{preset}/{}", dir_name(&case_dir));
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };
            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_deneb_finality_blocks_case::<E>(
                &case_dir,
                &case_name,
                blocks_count,
                validate_result,
            )
        })
        .collect();

    let mut out = FinalityResult::new();
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

fn run_deneb_finality_blocks_case<E>(
    case_dir: &Path,
    case_name: &str,
    blocks_count: u64,
    validate_result: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::DenebSignedBeaconBlock: Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
{
    let (pre, post) = match load_pre_post_deneb_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut current: Option<E::BeaconState> = Some(pre);
    let mut block_error: Option<String> = None;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block = match load_deneb_signed_block::<E>(case_dir, &block_file) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let state = current.take().unwrap();
        match state_transition::<E, pharos_stf::NullExecutionEngine>(
            state,
            &block,
            &pharos_stf::NullExecutionEngine,
            validate_result,
            &E::default_runtime_config(),
        ) {
            Ok((new_state, _)) => current = Some(new_state),
            Err(e) => {
                block_error = Some(format!("{e}"));
                break;
            }
        }
    }

    match (block_error, post) {
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        (None, None) => CaseResult::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        (Some(_), None) => CaseResult::Pass,
        (Some(e), Some(_)) => {
            CaseResult::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::fixtures_root;
    use crate::task::CaseOutcome;

    fn drain_tasks(tasks: Vec<CaseTask>) -> (u64, u64, u64) {
        let mut pass = 0u64;
        let mut fail = 0u64;
        let mut skip = 0u64;
        for task in tasks {
            match (task.run)() {
                CaseOutcome::Pass => pass += 1,
                CaseOutcome::Fail(_) => fail += 1,
                CaseOutcome::Skip => skip += 1,
            }
        }
        (pass, fail, skip)
    }

    #[test]
    fn enumerate_finality_parity_phase0_mainnet() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_finality_mainnet(&root);
        let (ep, ef, es) = drain_tasks(enumerate_finality(&root, "phase0", "mainnet", 13));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_finality phase0/mainnet counts differ from run_finality_mainnet"
        );
    }

    #[test]
    fn enumerate_finality_parity_phase0_minimal() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_finality_minimal(&root);
        let (ep, ef, es) = drain_tasks(enumerate_finality(&root, "phase0", "minimal", 14));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_finality phase0/minimal counts differ from run_finality_minimal"
        );
    }
}
