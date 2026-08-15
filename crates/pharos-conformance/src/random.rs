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

use std::path::Path;

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::state_transition;
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use rayon::prelude::*;

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_bellatrix_signed_block, load_phase0_signed_block,
    load_pre_post_altair_state, load_pre_post_bellatrix_state, load_pre_post_phase0_state,
    walk_category,
};
use crate::fs_util::dir_name;

/// Result tally for a single random preset run.
pub struct RandomResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl RandomResult {
    fn new() -> Self {
        RandomResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all random tests for the mainnet preset.
pub fn run_random_mainnet(root: &Path) -> RandomResult {
    run_random_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all random tests for the minimal preset.
pub fn run_random_minimal(root: &Path) -> RandomResult {
    run_random_preset::<MinimalEthSpec>(root, "minimal")
}

/// Run all random tests for a single preset.
pub fn run_random_preset<E>(root: &Path, preset: &'static str) -> RandomResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine> + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode,
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
        "random",
        Some("random"),
        WalkOpts::default(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("phase0/random/random/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);

            run_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();
    let mut out = RandomResult::new();
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
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine> + pharos_ssz::TreeHash,
    E::Phase0BeaconState: pharos_ssz::Decode,
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
            Ok(new_state) => current = Some(new_state),
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

/// Run all altair random tests for the mainnet preset.
pub fn run_random_altair_mainnet(root: &Path) -> RandomResult {
    run_random_altair_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all altair random tests for the minimal preset.
pub fn run_random_altair_minimal(root: &Path) -> RandomResult {
    run_random_altair_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_random_altair_preset<E>(root: &Path, preset: &'static str) -> RandomResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E> + pharos_ssz::Decode,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine> + pharos_ssz::TreeHash,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: pharos_ssz::Decode,
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
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "altair",
        "random",
        Some("random"),
        WalkOpts::default(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("altair/random/random/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);

            run_altair_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();
    let mut out = RandomResult::new();
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
    E::AltairBeaconState: pharos_stf::AltairDispatch<E> + pharos_ssz::Decode,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine> + pharos_ssz::TreeHash,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: pharos_ssz::Decode,
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
            Ok(new_state) => current = Some(new_state),
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

/// Run all bellatrix random tests for the mainnet preset.
pub fn run_random_bellatrix_mainnet(root: &Path) -> RandomResult {
    run_random_bellatrix_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all bellatrix random tests for the minimal preset.
pub fn run_random_bellatrix_minimal(root: &Path) -> RandomResult {
    run_random_bellatrix_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_random_bellatrix_preset<E>(root: &Path, preset: &'static str) -> RandomResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E> + pharos_ssz::Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_ssz::TreeHash
        + pharos_ssz::Decode,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: Decode,
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
        "random",
        Some("random"),
        WalkOpts::default(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("bellatrix/random/random/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);

            run_bellatrix_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();
    let mut out = RandomResult::new();
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
    E::AltairBeaconState: pharos_stf::AltairDispatch<E> + pharos_ssz::Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_ssz::TreeHash
        + pharos_ssz::Decode,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: pharos_ssz::Decode,
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
            Ok(new_state) => current = Some(new_state),
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
