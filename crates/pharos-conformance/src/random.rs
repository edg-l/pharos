//! Random conformance dispatcher.
//!
//! Walks `phase0/random/random/pyspec_tests/<case>/` for both presets.
//! Each case has the same block-sequence shape as `sanity/blocks` and `finality`:
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

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_bellatrix_signed_block, load_capella_signed_block,
    load_deneb_signed_block, load_phase0_signed_block, load_pre_post_altair_state,
    load_pre_post_bellatrix_state, load_pre_post_capella_state, load_pre_post_deneb_state,
    load_pre_post_phase0_state, walk_category,
};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per random test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_random_*` function.
/// Called by the Phase 7 flat work-pool.
///
/// Supported forks: `"phase0"`, `"altair"`, `"bellatrix"`, `"capella"`, `"deneb"`.
pub fn enumerate_random(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let cases: Vec<(PathBuf, _)> = walk_category(
        root,
        preset,
        fork,
        "random",
        Some("random"),
        WalkOpts::default(),
    )
    .collect();

    cases
        .into_iter()
        .enumerate()
        .map(|(i, (case_dir, meta))| {
            let case_ordinal = i as u32;
            let case_name = format!("{fork}/random/random/{preset}/{}", dir_name(&case_dir));
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
                    match run_capella_random_blocks_case::<MainnetEthSpec>(
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
                    match run_capella_random_blocks_case::<MinimalEthSpec>(
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
                    match run_deneb_random_blocks_case::<MainnetEthSpec>(
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
                    match run_deneb_random_blocks_case::<MinimalEthSpec>(
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
    E::Phase0BeaconState: pharos_ssz::Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
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
        + pharos_ssz::Decode,
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
    E::AltairSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: pharos_ssz::Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
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
        + pharos_ssz::Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + pharos_ssz::Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: pharos_ssz::Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
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
    #[allow(dead_code)]
    Skip,
}

fn run_capella_random_blocks_case<E>(
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

fn run_deneb_random_blocks_case<E>(
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
