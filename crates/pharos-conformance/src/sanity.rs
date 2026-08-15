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

use std::path::Path;

use pharos_ssz::{Encode, TreeHash};
use pharos_stf::altair::state_transition::process_slots_altair;
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::{
    AltairProcessSlotsDispatch, AltairUpgradeDispatch, BellatrixProcessSlotsDispatch,
    BellatrixUpgradeDispatch, CapellaProcessSlotsDispatch, Phase0UpgradeDispatch, process_slots,
    state_transition,
};
use pharos_types::{
    BeaconStateView, EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit, Slot},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use rayon::prelude::*;

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_bellatrix_signed_block,
    load_bellatrix_state, load_capella_signed_block, load_capella_state, load_phase0_signed_block,
    load_pre_post_altair_state, load_pre_post_bellatrix_state, load_pre_post_capella_state,
    load_pre_post_phase0_state, walk_category,
};
use crate::fs_util::dir_name;

/// Result tally for a single sanity preset run.
pub struct SanityResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl SanityResult {
    fn new() -> Self {
        SanityResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: SanityResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all sanity sub-categories for the mainnet preset.
pub fn run_sanity_mainnet(root: &Path) -> SanityResult {
    run_sanity_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all sanity sub-categories for the minimal preset.
pub fn run_sanity_minimal(root: &Path) -> SanityResult {
    run_sanity_preset::<MinimalEthSpec>(root, "minimal")
}

/// Run all sanity sub-categories for a single preset.
pub fn run_sanity_preset<E>(root: &Path, preset: &'static str) -> SanityResult
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
        + CapellaProcessSlotsDispatch<E>,
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
    let mut total = SanityResult::new();
    total.merge(run_blocks_preset::<E>(root, preset));
    total.merge(run_slots_preset::<E>(root, preset));
    total
}

// ── blocks sub-sweep ──────────────────────────────────────────────────────────

fn run_blocks_preset<E>(root: &Path, preset: &'static str) -> SanityResult
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
        + CapellaProcessSlotsDispatch<E>,
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
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "sanity",
        Some("blocks"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("phase0/sanity/blocks/{preset}/{}", dir_name(&case_dir));

            // blocks_count is required for the blocks sub-category.
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            // bls_setting == 2 → skip BLS verification; anything else → verify.
            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = SanityResult::new();
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
        + CapellaProcessSlotsDispatch<E>,
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
        // All blocks applied, post present — compare states.
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        // All blocks applied but no post expected — should have failed.
        (None, None) => CaseResult::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        // A block failed and we expected it (no post) — negative test passed.
        (Some(_), None) => CaseResult::Pass,
        // A block failed unexpectedly (post was present).
        (Some(e), Some(_)) => {
            CaseResult::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
}

// ── slots sub-sweep ───────────────────────────────────────────────────────────

fn run_slots_preset<E>(root: &Path, preset: &'static str) -> SanityResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconState: pharos_ssz::Decode,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("phase0/sanity/slots/{preset}/{}", dir_name(&case_dir));
            run_slots_case::<E>(&case_dir, &case_name)
        })
        .collect();

    let mut out = SanityResult::new();
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

fn run_slots_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec,
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

// ── Altair entry points ───────────────────────────────────────────────────────

/// Run all altair sanity sub-categories for the mainnet preset.
pub fn run_sanity_altair_mainnet(root: &Path) -> SanityResult {
    let mut total = SanityResult::new();
    total.merge(run_altair_blocks_preset::<MainnetEthSpec>(root, "mainnet"));
    total.merge(run_altair_slots_preset_mainnet(root));
    total
}

/// Run all altair sanity sub-categories for the minimal preset.
pub fn run_sanity_altair_minimal(root: &Path) -> SanityResult {
    let mut total = SanityResult::new();
    total.merge(run_altair_blocks_preset::<MinimalEthSpec>(root, "minimal"));
    total.merge(run_altair_slots_preset_minimal(root));
    total
}

// ── altair/sanity/blocks ──────────────────────────────────────────────────────

fn run_altair_blocks_preset<E>(root: &Path, preset: &'static str) -> SanityResult
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
        + CapellaProcessSlotsDispatch<E>,
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
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "altair",
        "sanity",
        Some("blocks"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("altair/sanity/blocks/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_altair_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = SanityResult::new();
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
        + pharos_ssz::Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>,
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

// ── altair/sanity/slots ───────────────────────────────────────────────────────

fn run_altair_slots_preset_mainnet(root: &Path) -> SanityResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "altair",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("altair/sanity/slots/mainnet/{}", dir_name(&case_dir));
            run_altair_slots_case_mainnet(&case_dir, &case_name)
        })
        .collect();

    let mut out = SanityResult::new();
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

fn run_altair_slots_preset_minimal(root: &Path) -> SanityResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "altair",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("altair/sanity/slots/minimal/{}", dir_name(&case_dir));
            run_altair_slots_case_minimal(&case_dir, &case_name)
        })
        .collect();

    let mut out = SanityResult::new();
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

fn run_altair_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_types::MainnetEthSpec as E;
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
    use pharos_types::MinimalEthSpec as E;
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

// ── Bellatrix entry points ────────────────────────────────────────────────────

/// Run all bellatrix sanity sub-categories for the mainnet preset.
pub fn run_sanity_bellatrix_mainnet(root: &Path) -> SanityResult {
    let mut total = SanityResult::new();
    total.merge(run_bellatrix_blocks_preset::<MainnetEthSpec>(
        root, "mainnet",
    ));
    total.merge(run_bellatrix_slots_preset_mainnet(root));
    total
}

/// Run all bellatrix sanity sub-categories for the minimal preset.
pub fn run_sanity_bellatrix_minimal(root: &Path) -> SanityResult {
    let mut total = SanityResult::new();
    total.merge(run_bellatrix_blocks_preset::<MinimalEthSpec>(
        root, "minimal",
    ));
    total.merge(run_bellatrix_slots_preset_minimal(root));
    total
}

// ── bellatrix/sanity/blocks ───────────────────────────────────────────────────

fn run_bellatrix_blocks_preset<E>(root: &Path, preset: &'static str) -> SanityResult
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
        + CapellaProcessSlotsDispatch<E>,
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
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "bellatrix",
        "sanity",
        Some("blocks"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("bellatrix/sanity/blocks/{preset}/{}", dir_name(&case_dir));

            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_bellatrix_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = SanityResult::new();
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
        + pharos_ssz::Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + pharos_ssz::Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>,
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

// ── bellatrix/sanity/slots ────────────────────────────────────────────────────

fn run_bellatrix_slots_preset_mainnet(root: &Path) -> SanityResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "bellatrix",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("bellatrix/sanity/slots/mainnet/{}", dir_name(&case_dir));
            run_bellatrix_slots_case_mainnet(&case_dir, &case_name)
        })
        .collect();

    let mut out = SanityResult::new();
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

fn run_bellatrix_slots_preset_minimal(root: &Path) -> SanityResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "bellatrix",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("bellatrix/sanity/slots/minimal/{}", dir_name(&case_dir));
            run_bellatrix_slots_case_minimal(&case_dir, &case_name)
        })
        .collect();

    let mut out = SanityResult::new();
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

fn run_bellatrix_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::bellatrix::state_transition::process_slots_bellatrix;
    use pharos_types::MainnetEthSpec as E;

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
    use pharos_types::MinimalEthSpec as E;

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
    Skip,
}

// ── Capella entry points ──────────────────────────────────────────────────────

/// Run all capella sanity sub-categories for the mainnet preset.
pub fn run_sanity_capella_mainnet(root: &Path) -> SanityResult {
    let mut total = SanityResult::new();
    total.merge(run_capella_blocks_preset::<MainnetEthSpec>(root, "mainnet"));
    total.merge(run_capella_slots_preset_mainnet(root));
    total
}

/// Run all capella sanity sub-categories for the minimal preset.
pub fn run_sanity_capella_minimal(root: &Path) -> SanityResult {
    let mut total = SanityResult::new();
    total.merge(run_capella_blocks_preset::<MinimalEthSpec>(root, "minimal"));
    total.merge(run_capella_slots_preset_minimal(root));
    total
}

// ── capella/sanity/blocks ─────────────────────────────────────────────────────

fn run_capella_blocks_preset<E>(root: &Path, preset: &'static str) -> SanityResult
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
        + pharos_ssz::Decode,
    E::CapellaSignedBeaconBlock: pharos_ssz::Decode,
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
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "capella",
        "sanity",
        Some("blocks"),
        WalkOpts::default(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("capella/sanity/blocks/{preset}/{}", dir_name(&case_dir));
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };
            let validate_result = meta.as_ref().and_then(|m| m.bls_setting) != Some(2);
            run_capella_blocks_case::<E>(&case_dir, &case_name, blocks_count, validate_result)
        })
        .collect();

    let mut out = SanityResult::new();
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

fn run_capella_blocks_case<E>(
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
        + pharos_ssz::Decode,
    E::CapellaSignedBeaconBlock: pharos_ssz::Decode,
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

// ── capella/sanity/slots ──────────────────────────────────────────────────────

fn run_capella_slots_preset_mainnet(root: &Path) -> SanityResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("capella/sanity/slots/mainnet/{}", dir_name(&case_dir));
            run_capella_slots_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = SanityResult::new();
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

fn run_capella_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::state_transition::process_slots_capella;
    use pharos_types::MainnetEthSpec as E;

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

fn run_capella_slots_preset_minimal(root: &Path) -> SanityResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "sanity",
        Some("slots"),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("capella/sanity/slots/minimal/{}", dir_name(&case_dir));
            run_capella_slots_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = SanityResult::new();
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

fn run_capella_slots_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::state_transition::process_slots_capella;
    use pharos_types::MinimalEthSpec as E;

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
