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

use std::path::Path;

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::state_transition;
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use crate::fixture_walker::{
    WalkOpts, load_phase0_signed_block, load_pre_post_phase0_state, walk_category,
};
use crate::fs_util::dir_name;

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
    let mut out = FinalityResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "finality",
        Some("finality"),
        WalkOpts::default(),
    ) {
        let case_name = format!("phase0/finality/finality/{preset}/{}", dir_name(&case_dir));

        let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
            Some(n) => n,
            None => {
                out.skip += 1;
                continue;
            }
        };

        let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);

        let result = run_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result);
        match result {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
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
        match state_transition::<E>(state, &block, validate_result) {
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
}
