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

use pharos_ssz::{Encode, TreeHash};
use pharos_stf::altair::state_transition::process_slots_altair;
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::{
    AltairProcessSlotsDispatch, AltairUpgradeDispatch, BellatrixProcessSlotsDispatch,
    BellatrixUpgradeDispatch, CapellaProcessSlotsDispatch, CapellaUpgradeDispatch,
    DenebProcessSlotsDispatch, Phase0UpgradeDispatch, process_slots, state_transition,
};
use pharos_types::{
    BeaconStateView, EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit, Slot},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_bellatrix_signed_block,
    load_bellatrix_state, load_capella_signed_block, load_capella_state, load_deneb_signed_block,
    load_deneb_state, load_phase0_signed_block, load_pre_post_altair_state,
    load_pre_post_bellatrix_state, load_pre_post_capella_state, load_pre_post_deneb_state,
    load_pre_post_phase0_state, walk_category,
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
                    match run_capella_blocks_case::<MainnetEthSpec>(
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
                    match run_capella_blocks_case::<MinimalEthSpec>(
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
                    match run_deneb_blocks_case::<MainnetEthSpec>(
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
                    match run_deneb_blocks_case::<MinimalEthSpec>(
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
                        match run_slots_case::<MainnetEthSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    }),
                    ("phase0", _) => Box::new(move || {
                        match run_slots_case::<MinimalEthSpec>(&case_dir, &case_name) {
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
                    _ => Box::new(move || {
                        match run_deneb_slots_case_minimal(&case_dir, &case_name) {
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
    #[allow(dead_code)]
    Skip,
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
        + CapellaUpgradeDispatch<E>
        + pharos_ssz::Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
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

fn run_deneb_blocks_case<E>(
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
        + CapellaUpgradeDispatch<E>
        + pharos_ssz::Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash
        + pharos_ssz::Decode,
    E::DenebSignedBeaconBlock: pharos_ssz::Decode,
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

fn run_deneb_slots_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::deneb::state_transition::process_slots_deneb;
    use pharos_types::MainnetEthSpec as E;

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
    use pharos_types::MinimalEthSpec as E;

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
