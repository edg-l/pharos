//! Operations conformance dispatcher.
//!
//! Covers six sub-categories of `phase0/operations` for both presets:
//!   - `attestation`
//!   - `attester_slashing`
//!   - `block_header`
//!   - `deposit`
//!   - `proposer_slashing`
//!   - `voluntary_exit`
//!
//! For each case:
//! - `pre.ssz_snappy` is the input state.
//! - An operation-specific file holds the operation to apply.
//! - `post.ssz_snappy` present → expect `Ok(())` and state matches post.
//! - `post.ssz_snappy` absent → expect `Err(_)`.
//! - `meta.yaml` with `bls_setting: 1` → `verify_signatures = false`.
//!   Absence of `meta.yaml` → `verify_signatures = true` (spec default).

use std::path::Path;

use pharos_ssz::{Decode, Encode};
use pharos_stf::phase0::{
    BeaconStateWrite,
    operations::{
        process_attestation, process_attester_slashing, process_block_header, process_deposit,
        process_proposer_slashing, process_voluntary_exit,
    },
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit, ProposerSlashing, SignedVoluntaryExit},
    views::{BeaconBlockBodyView, BeaconBlockView},
};

use rayon::prelude::*;

use crate::fixture_walker::{WalkOpts, load_pre_post_phase0_state, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;

/// Result of running all operation tests for a single operation sub-category
/// and preset.
pub struct OpsResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl OpsResult {
    fn new() -> Self {
        OpsResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: OpsResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Walk options for operation fixtures: `pyspec_tests/` inner dir, no required meta.yaml
/// (many block_header and proposer_slashing cases have no meta.yaml).
fn ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Resolve `verify_signatures` from an optional `meta.yaml`.
///
/// Per consensus-spec-tests format README:
/// - `bls_setting: 0` or absent — BLS outcome doesn't affect test; run with verification on.
/// - `bls_setting: 1` — "BLS required": test validity depends on BLS being ON. Verify signatures.
/// - `bls_setting: 2` — "BLS ignored": test validity depends on BLS being OFF. Skip BLS.
fn bls_verify(meta: &Option<crate::fixture_walker::MetaYaml>) -> bool {
    match meta {
        Some(m) => m.bls_setting.unwrap_or(0) != 2,
        None => true,
    }
}

#[allow(dead_code)]
enum CaseResult {
    Pass,
    Fail(String),
    Skip,
}

fn tally(result: CaseResult, out: &mut OpsResult) {
    match result {
        CaseResult::Pass => out.pass += 1,
        CaseResult::Fail(msg) => {
            out.fail += 1;
            out.failures.push(msg);
        }
        CaseResult::Skip => out.skip += 1,
    }
}

// ── Generic applicator ────────────────────────────────────────────────────────

/// Apply one operation case: load pre/post states, load the operation file,
/// run the process function, then compare (Ok+Some → htr equality, Ok+None →
/// fail, Err+None → pass, Err+Some → fail). NO rayon inside.
///
/// Resolution C1: the process callback returns the CONCRETE `StateTransitionError`
/// — no generic error type parameter.
fn apply_op<S, Op, F>(
    case_dir: &std::path::Path,
    case_name: &str,
    op_file: &str,
    load_states: impl FnOnce(&std::path::Path) -> Result<(S, Option<S>), String>,
    process: F,
    verify_sigs: bool,
) -> crate::task::CaseOutcome
where
    S: Encode,
    Op: Decode,
    F: FnOnce(&mut S, &Op, bool) -> Result<(), pharos_stf::StateTransitionError>,
{
    let (mut pre, post) = match load_states(case_dir) {
        Ok(v) => v,
        Err(e) => return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}")),
    };
    let op = match load_ssz_snappy::<Op>(case_dir, op_file) {
        Ok(v) => v,
        Err(e) => return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}")),
    };

    let result = process(&mut pre, &op, verify_sigs);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                crate::task::CaseOutcome::Pass
            } else {
                crate::task::CaseOutcome::Fail(format!(
                    "{case_name}: state mismatch after {op_file_stem}",
                    op_file_stem = op_file.trim_end_matches(".ssz_snappy"),
                ))
            }
        }
        (Ok(()), None) => {
            crate::task::CaseOutcome::Fail(format!("{case_name}: expected Err but got Ok"))
        }
        (Err(_), None) => crate::task::CaseOutcome::Pass,
        (Err(e), Some(_)) => {
            crate::task::CaseOutcome::Fail(format!("{case_name}: expected Ok but got Err: {e}"))
        }
    }
}

// ── Generic walker ────────────────────────────────────────────────────────────

/// Walk one operation sub-category and produce a `Vec<CaseTask>`, assigning
/// sequential `case_ordinal`s from the threaded counter.
///
/// Resolution C3: `apply` is `Fn` + `Clone` + `Send` + `Sync` + `'static` so it
/// can be cloned into each case's `Box<dyn FnOnce>` without capturing a `FnOnce`.
#[allow(clippy::too_many_arguments)]
fn enumerate_op<F>(
    root: &std::path::Path,
    fork: &str,
    preset: &str,
    sub: &str,
    row_ordinal: u32,
    case_ordinal: &mut u32,
    walk_opts: WalkOpts,
    apply: F,
) -> Vec<crate::task::CaseTask>
where
    F: Fn(
            std::path::PathBuf,
            String,
            Option<crate::fixture_walker::MetaYaml>,
        ) -> crate::task::CaseOutcome
        + Clone
        + Send
        + Sync
        + 'static,
{
    walk_category(root, preset, fork, "operations", Some(sub), walk_opts)
        .map(|(case_dir, meta)| {
            let co = *case_ordinal;
            *case_ordinal += 1;
            let case_name = format!("{fork}/operations/{preset}/{sub}/{}", dir_name(&case_dir));
            let apply_clone = apply.clone();
            crate::task::CaseTask {
                row_ordinal,
                case_ordinal: co,
                run: Box::new(move || apply_clone(case_dir, case_name, meta)),
            }
        })
        .collect()
}

// ── phase0 descriptor table ───────────────────────────────────────────────────

/// Descriptor table for phase0 operations.
///
/// Sub order (verified from `run_operations_mainnet` body, L68):
///   block_header, proposer_slashing, attester_slashing, deposit, attestation, voluntary_exit
///
/// Each entry is `(sub_name, apply_closure)`. The `apply_closure` is `Fn` +
/// `Clone` + `Send` + `Sync` + `'static` (Resolution C3). EthSpec bounds are
/// stated once on this builder — `apply_op` itself carries no EthSpec bound
/// (D-apply-op-no-ethspec-bound).
#[allow(clippy::type_complexity)]
fn phase0_op_table<E>() -> Vec<(
    &'static str,
    Box<
        dyn Fn(
                std::path::PathBuf,
                String,
                Option<crate::fixture_walker::MetaYaml>,
            ) -> crate::task::CaseOutcome
            + Send
            + Sync,
    >,
)>
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlock: BeaconBlockView + Decode,
    <E::Phase0BeaconBlock as BeaconBlockView>::Body: pharos_ssz::TreeHash,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
    E::Phase0BeaconState: Decode,
{
    vec![
        // block_header: op file is block.ssz_snappy; meta is ignored (no verify_sigs param).
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                // load_pre_post_phase0_state is called as a function pointer — no FnOnce capture.
                let (mut pre, post) = match load_pre_post_phase0_state::<E>(&case_dir) {
                    Ok(v) => v,
                    Err(e) => return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}")),
                };
                let block =
                    match load_ssz_snappy::<E::Phase0BeaconBlock>(&case_dir, "block.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let result = process_block_header::<E>(&mut pre, &block);
                match (result, post) {
                    (Ok(()), Some(expected)) => {
                        if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                            crate::task::CaseOutcome::Pass
                        } else {
                            crate::task::CaseOutcome::Fail(format!(
                                "{case_name}: state mismatch after block_header"
                            ))
                        }
                    }
                    (Ok(()), None) => crate::task::CaseOutcome::Fail(format!(
                        "{case_name}: expected Err but got Ok"
                    )),
                    (Err(_), None) => crate::task::CaseOutcome::Pass,
                    (Err(e), Some(_)) => crate::task::CaseOutcome::Fail(format!(
                        "{case_name}: expected Ok but got Err: {e}"
                    )),
                }
            }),
        ),
        // proposer_slashing
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                apply_op::<E::BeaconState, ProposerSlashing, _>(
                    &case_dir,
                    &case_name,
                    "proposer_slashing.ssz_snappy",
                    load_pre_post_phase0_state::<E>,
                    |state, op, verify| process_proposer_slashing::<E>(state, op, verify),
                    bls_verify(&meta),
                )
            }),
        ),
        // attester_slashing
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                apply_op::<E::BeaconState, AttesterSlashing<2048>, _>(
                    &case_dir,
                    &case_name,
                    "attester_slashing.ssz_snappy",
                    load_pre_post_phase0_state::<E>,
                    |state, op, verify| process_attester_slashing::<E>(state, op, verify),
                    bls_verify(&meta),
                )
            }),
        ),
        // deposit
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                apply_op::<E::BeaconState, Deposit<33>, _>(
                    &case_dir,
                    &case_name,
                    "deposit.ssz_snappy",
                    load_pre_post_phase0_state::<E>,
                    |state, op, verify| process_deposit::<E>(state, op, verify),
                    bls_verify(&meta),
                )
            }),
        ),
        // attestation
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                apply_op::<E::BeaconState, Attestation<2048>, _>(
                    &case_dir,
                    &case_name,
                    "attestation.ssz_snappy",
                    load_pre_post_phase0_state::<E>,
                    |state, op, verify| process_attestation::<E>(state, op, verify),
                    bls_verify(&meta),
                )
            }),
        ),
        // voluntary_exit
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                apply_op::<E::BeaconState, SignedVoluntaryExit, _>(
                    &case_dir,
                    &case_name,
                    "voluntary_exit.ssz_snappy",
                    load_pre_post_phase0_state::<E>,
                    |state, op, verify| process_voluntary_exit::<E>(state, op, verify),
                    bls_verify(&meta),
                )
            }),
        ),
    ]
}

/// Enumerate all phase0 operation cases for one preset, returning `CaseTask`s
/// with sequential `case_ordinal` in (sub-table-order, walk-order).
fn enumerate_operations_phase0<E>(
    root: &std::path::Path,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask>
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlock: BeaconBlockView + Decode,
    <E::Phase0BeaconBlock as BeaconBlockView>::Body: pharos_ssz::TreeHash,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
    E::Phase0BeaconState: Decode,
{
    let table = phase0_op_table::<E>();
    let mut case_ordinal: u32 = 0;
    let mut tasks = Vec::new();
    for (sub, apply) in table {
        // apply is Box<dyn Fn+Send+Sync> — wrap in Arc for Clone.
        let apply = std::sync::Arc::new(apply);
        let sub_tasks = enumerate_op(
            root,
            "phase0",
            preset,
            sub,
            row_ordinal,
            &mut case_ordinal,
            ops_walk_opts(),
            move |dir, name, meta| apply(dir, name, meta),
        );
        tasks.extend(sub_tasks);
    }
    tasks
}

/// Run all six operation sub-categories for the mainnet preset.
pub fn run_operations_mainnet(root: &Path) -> OpsResult {
    let tasks = enumerate_operations_phase0::<MainnetEthSpec>(root, "mainnet", 0);
    drain_tasks_to_ops_result(tasks)
}

/// Run all six operation sub-categories for the minimal preset.
pub fn run_operations_minimal(root: &Path) -> OpsResult {
    let tasks = enumerate_operations_phase0::<MinimalEthSpec>(root, "minimal", 0);
    drain_tasks_to_ops_result(tasks)
}

/// Drain a `Vec<CaseTask>` via ONE `into_par_iter`, sort by `case_ordinal`, and
/// repack into `OpsResult` in `case_ordinal` order. This is the single relocated
/// rayon drain per preset entry-point (migration invariant: one per fork-preset
/// until the flat-pool flip in Phase 7).
fn drain_tasks_to_ops_result(tasks: Vec<crate::task::CaseTask>) -> OpsResult {
    let mut outcomes: Vec<(u32, crate::task::CaseOutcome)> = tasks
        .into_par_iter()
        .map(|t| (t.case_ordinal, (t.run)()))
        .collect();
    outcomes.sort_by_key(|(co, _)| *co);

    let mut out = OpsResult::new();
    for (_, outcome) in outcomes {
        match outcome {
            crate::task::CaseOutcome::Pass => out.pass += 1,
            crate::task::CaseOutcome::Skip => out.skip += 1,
            crate::task::CaseOutcome::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

// ── Altair operations ─────────────────────────────────────────────────────────

/// Walk options for altair operation fixtures.
fn altair_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Descriptor table for altair operations — mainnet preset.
///
/// Sub order (verified from `run_operations_altair_mainnet` body):
///   block_header, proposer_slashing, attester_slashing, deposit, attestation,
///   voluntary_exit, sync_aggregate
///
/// block_header and sync_aggregate are bespoke (concrete preset types,
/// projection through `E::altair_into_state`). The 5 shared subs follow the
/// same pattern inline. All closures return `CaseOutcome` directly.
/// EthSpec bounds are stated once on this builder; `apply_op` carries no
/// EthSpec bound (D-apply-op-no-ethspec-bound).
#[allow(clippy::type_complexity)]
fn altair_op_table_mainnet() -> Vec<(
    &'static str,
    Box<
        dyn Fn(
                std::path::PathBuf,
                String,
                Option<crate::fixture_walker::MetaYaml>,
            ) -> crate::task::CaseOutcome
            + Send
            + Sync,
    >,
)> {
    use pharos_types::MainnetEthSpec as E;
    vec![
        // block_header: bespoke — loads raw altair::MainnetBeaconState, projects via altair_into_state.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_types::altair::MainnetBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v)),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let block =
                    match load_ssz_snappy::<MainnetBeaconBlock>(&case_dir, "block.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let mut pre = pre_inner;
                let result = process_block_header_altair::<
                    16,
                    2,
                    128,
                    16,
                    16,
                    2048,
                    33,
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &block);
                let current = E::altair_into_state(pre);
                match (result, post_inner) {
                    (Ok(()), Some(expected)) => {
                        if current.as_ssz_bytes() == expected.as_ssz_bytes() {
                            crate::task::CaseOutcome::Pass
                        } else {
                            crate::task::CaseOutcome::Fail(format!(
                                "{case_name}: state mismatch after block_header"
                            ))
                        }
                    }
                    (Ok(()), None) => crate::task::CaseOutcome::Fail(format!(
                        "{case_name}: expected Err but got Ok"
                    )),
                    (Err(_), None) => crate::task::CaseOutcome::Pass,
                    (Err(e), Some(_)) => crate::task::CaseOutcome::Fail(format!(
                        "{case_name}: expected Ok but got Err: {e}"
                    )),
                }
            }),
        ),
        // proposer_slashing
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_proposer_slashing;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<ProposerSlashing>(
                    &case_dir,
                    "proposer_slashing.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_proposer_slashing::<
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attester_slashing;
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<AttesterSlashing<2048>>(
                    &case_dir,
                    "attester_slashing.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_attester_slashing::<
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<Deposit<33>>(&case_dir, "deposit.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_deposit::<
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attestation;
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op =
                    match load_ssz_snappy::<Attestation<2048>>(&case_dir, "attestation.ssz_snappy")
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let mut pre = pre_inner;
                let result = process_attestation::<
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_voluntary_exit;
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<SignedVoluntaryExit>(
                    &case_dir,
                    "voluntary_exit.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_voluntary_exit::<
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — uses MainnetSyncAggregate concrete type.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_types::altair::MainnetSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<MainnetSyncAggregate>(
                    &case_dir,
                    "sync_aggregate.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_sync_aggregate::<
                    8192,
                    16_777_216,
                    2048,
                    1_099_511_627_776,
                    65536,
                    8192,
                    4,
                    512,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
    ]
}

/// Descriptor table for altair operations — minimal preset.
///
/// Same sub order as mainnet: block_header, proposer_slashing, attester_slashing,
/// deposit, attestation, voluntary_exit, sync_aggregate.
#[allow(clippy::type_complexity)]
fn altair_op_table_minimal() -> Vec<(
    &'static str,
    Box<
        dyn Fn(
                std::path::PathBuf,
                String,
                Option<crate::fixture_walker::MetaYaml>,
            ) -> crate::task::CaseOutcome
            + Send
            + Sync,
    >,
)> {
    use pharos_types::MinimalEthSpec as E;
    vec![
        // block_header: bespoke.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_types::altair::MinimalBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v)),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let block =
                    match load_ssz_snappy::<MinimalBeaconBlock>(&case_dir, "block.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let mut pre = pre_inner;
                let result = process_block_header_altair::<
                    16,
                    2,
                    128,
                    16,
                    16,
                    2048,
                    33,
                    64,
                    16_777_216,
                    32,
                    1_099_511_627_776,
                    64,
                    64,
                    4,
                    32,
                    E,
                >(&mut pre, &block);
                let current = E::altair_into_state(pre);
                match (result, post_inner) {
                    (Ok(()), Some(expected)) => {
                        if current.as_ssz_bytes() == expected.as_ssz_bytes() {
                            crate::task::CaseOutcome::Pass
                        } else {
                            crate::task::CaseOutcome::Fail(format!(
                                "{case_name}: state mismatch after block_header"
                            ))
                        }
                    }
                    (Ok(()), None) => crate::task::CaseOutcome::Fail(format!(
                        "{case_name}: expected Err but got Ok"
                    )),
                    (Err(_), None) => crate::task::CaseOutcome::Pass,
                    (Err(e), Some(_)) => crate::task::CaseOutcome::Fail(format!(
                        "{case_name}: expected Ok but got Err: {e}"
                    )),
                }
            }),
        ),
        // proposer_slashing
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_proposer_slashing;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<ProposerSlashing>(
                    &case_dir,
                    "proposer_slashing.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_proposer_slashing::<
                    64,
                    16_777_216,
                    32,
                    1_099_511_627_776,
                    64,
                    64,
                    4,
                    32,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attester_slashing;
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<AttesterSlashing<2048>>(
                    &case_dir,
                    "attester_slashing.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_attester_slashing::<
                    64,
                    16_777_216,
                    32,
                    1_099_511_627_776,
                    64,
                    64,
                    4,
                    32,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<Deposit<33>>(&case_dir, "deposit.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result =
                    process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut pre,
                        &op,
                        bls_verify(&meta),
                    );
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attestation;
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op =
                    match load_ssz_snappy::<Attestation<2048>>(&case_dir, "attestation.ssz_snappy")
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let mut pre = pre_inner;
                let result =
                    process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut pre,
                        &op,
                        bls_verify(&meta),
                    );
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_voluntary_exit;
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<SignedVoluntaryExit>(
                    &case_dir,
                    "voluntary_exit.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_voluntary_exit::<
                    64,
                    16_777_216,
                    32,
                    1_099_511_627_776,
                    64,
                    64,
                    4,
                    32,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — uses MinimalSyncAggregate concrete type.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_types::altair::MinimalSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::altair_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<MinimalSyncAggregate>(
                    &case_dir,
                    "sync_aggregate.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_sync_aggregate::<
                    64,
                    16_777_216,
                    32,
                    1_099_511_627_776,
                    64,
                    64,
                    4,
                    32,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::altair_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
    ]
}

/// Shared outcome helper for altair ops: compares bytes-level post-state
/// (both sides already wrapped via `E::altair_into_state`).
fn altair_op_outcome(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> crate::task::CaseOutcome {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                crate::task::CaseOutcome::Pass
            } else {
                crate::task::CaseOutcome::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => {
            crate::task::CaseOutcome::Fail(format!("{case_name}: expected Err but got Ok"))
        }
        (Err(_), None) => crate::task::CaseOutcome::Pass,
        (Err(e), Some(_)) => {
            crate::task::CaseOutcome::Fail(format!("{case_name}: expected Ok but got Err: {e}"))
        }
    }
}

/// Enumerate all altair operation cases for one preset, returning `CaseTask`s
/// with sequential `case_ordinal` in (sub-table-order, walk-order).
fn enumerate_operations_altair(
    root: &std::path::Path,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask> {
    let table = if preset == "mainnet" {
        altair_op_table_mainnet()
    } else {
        altair_op_table_minimal()
    };
    let mut case_ordinal: u32 = 0;
    let mut tasks = Vec::new();
    for (sub, apply) in table {
        let apply = std::sync::Arc::new(apply);
        let sub_tasks = enumerate_op(
            root,
            "altair",
            preset,
            sub,
            row_ordinal,
            &mut case_ordinal,
            altair_ops_walk_opts(),
            move |dir, name, meta| apply(dir, name, meta),
        );
        tasks.extend(sub_tasks);
    }
    tasks
}

/// Run all altair operation sub-categories for the mainnet preset.
pub fn run_operations_altair_mainnet(root: &Path) -> OpsResult {
    let tasks = enumerate_operations_altair(root, "mainnet", 0);
    drain_tasks_to_ops_result(tasks)
}

/// Run all altair operation sub-categories for the minimal preset.
pub fn run_operations_altair_minimal(root: &Path) -> OpsResult {
    let tasks = enumerate_operations_altair(root, "minimal", 0);
    drain_tasks_to_ops_result(tasks)
}

// ── Bellatrix operations ──────────────────────────────────────────────────────

/// Run all bellatrix operation sub-categories for the mainnet preset.
pub fn run_operations_bellatrix_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_bellatrix_block_header_mainnet(root));
    total.merge(run_bellatrix_proposer_slashing_mainnet(root));
    total.merge(run_bellatrix_attester_slashing_mainnet(root));
    total.merge(run_bellatrix_deposit_mainnet(root));
    total.merge(run_bellatrix_attestation_mainnet(root));
    total.merge(run_bellatrix_voluntary_exit_mainnet(root));
    total.merge(run_bellatrix_sync_aggregate_mainnet(root));
    total.merge(run_bellatrix_execution_payload_mainnet(root));
    total
}

/// Run all bellatrix operation sub-categories for the minimal preset.
pub fn run_operations_bellatrix_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_bellatrix_block_header_minimal(root));
    total.merge(run_bellatrix_proposer_slashing_minimal(root));
    total.merge(run_bellatrix_attester_slashing_minimal(root));
    total.merge(run_bellatrix_deposit_minimal(root));
    total.merge(run_bellatrix_attestation_minimal(root));
    total.merge(run_bellatrix_voluntary_exit_minimal(root));
    total.merge(run_bellatrix_sync_aggregate_minimal(root));
    total.merge(run_bellatrix_execution_payload_minimal(root));
    total
}

// ── Bellatrix helpers ─────────────────────────────────────────────────────────

fn bellatrix_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

fn run_bellatrix_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    run_case: impl Fn(&Path, &str, bool) -> CaseResult + Sync + Send,
) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "bellatrix",
        "operations",
        Some(sub),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/operations/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_case(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

// ── bellatrix/block_header ────────────────────────────────────────────────────

fn run_bellatrix_block_header_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(root, "mainnet", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::bellatrix::helpers::{
            bellatrix_state_to_altair, update_bellatrix_from_altair,
        };
        use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::bellatrix_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MainnetBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = bellatrix_state_to_altair(&pre);
        let altair_block = pharos_stf::bellatrix::bellatrix_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            8192,
            16_777_216,
            2048,
            1_099_511_627_776,
            65536,
            8192,
            4,
            512,
            E,
        >(&mut altair_state, &altair_block);
        // Patch body_root to the Bellatrix block body hash (includes execution_payload),
        // matching what `process_block` does per spec line 214 in bellatrix/block.rs.
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_bellatrix_from_altair(&mut pre, altair_state);
        cmp_bellatrix_result(
            result,
            E::bellatrix_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

fn run_bellatrix_block_header_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(root, "minimal", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::bellatrix::helpers::{
            bellatrix_state_to_altair, update_bellatrix_from_altair,
        };
        use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::bellatrix_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MinimalBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = bellatrix_state_to_altair(&pre);
        let altair_block = pharos_stf::bellatrix::bellatrix_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            64,
            16_777_216,
            32,
            1_099_511_627_776,
            64,
            64,
            4,
            32,
            E,
        >(&mut altair_state, &altair_block);
        // Patch body_root to the Bellatrix block body hash (includes execution_payload).
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_bellatrix_from_altair(&mut pre, altair_state);
        cmp_bellatrix_result(
            result,
            E::bellatrix_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

// ── bellatrix/proposer_slashing ───────────────────────────────────────────────

fn run_bellatrix_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_proposer_slashing_bellatrix;
            use pharos_types::{MainnetEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_bellatrix::<
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
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

fn run_bellatrix_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_proposer_slashing_bellatrix;
            use pharos_types::{MinimalEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_bellatrix::<
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
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

// ── bellatrix/attester_slashing ───────────────────────────────────────────────

fn run_bellatrix_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_attester_slashing_bellatrix;
            use pharos_types::{MainnetEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_bellatrix::<
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
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

fn run_bellatrix_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_attester_slashing_bellatrix;
            use pharos_types::{MinimalEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_bellatrix::<
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
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

// ── bellatrix/deposit ─────────────────────────────────────────────────────────

fn run_bellatrix_deposit_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_deposit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &deposit, verify_signatures);
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

fn run_bellatrix_deposit_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut altair_state,
                &deposit,
                verify_signatures,
            );
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

// ── bellatrix/attestation ─────────────────────────────────────────────────────

fn run_bellatrix_attestation_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_attestation::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &attestation, verify_signatures);
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

fn run_bellatrix_attestation_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result =
                process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &attestation,
                    verify_signatures,
                );
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

// ── bellatrix/voluntary_exit ──────────────────────────────────────────────────

fn run_bellatrix_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_voluntary_exit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &exit, verify_signatures);
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

fn run_bellatrix_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result =
                process_voluntary_exit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &exit,
                    verify_signatures,
                );
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

// ── bellatrix/sync_aggregate ──────────────────────────────────────────────────

fn run_bellatrix_sync_aggregate_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "bellatrix",
        "operations",
        Some("sync_aggregate"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/operations/mainnet/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_bellatrix_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_sync_aggregate_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
    use pharos_types::{MainnetEthSpec as E, altair::MainnetSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MainnetSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = bellatrix_state_to_altair(&pre);
    let result = process_sync_aggregate::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut altair_state, &sync_aggregate, verify_signatures);
    update_bellatrix_from_altair(&mut pre, altair_state);
    cmp_bellatrix_result(
        result,
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

fn run_bellatrix_sync_aggregate_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "bellatrix",
        "operations",
        Some("sync_aggregate"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/operations/minimal/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_bellatrix_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_sync_aggregate_case_minimal(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
    use pharos_types::{MinimalEthSpec as E, altair::MinimalSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MinimalSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = bellatrix_state_to_altair(&pre);
    let result = process_sync_aggregate::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut altair_state,
        &sync_aggregate,
        verify_signatures,
    );
    update_bellatrix_from_altair(&mut pre, altair_state);
    cmp_bellatrix_result(
        result,
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

// ── bellatrix/execution_payload ───────────────────────────────────────────────

fn run_bellatrix_execution_payload_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "bellatrix",
        "operations",
        Some("execution_payload"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "bellatrix/operations/mainnet/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_bellatrix_execution_payload_case_mainnet(&case_dir, &case_name)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_execution_payload_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::bellatrix::operations::process_execution_payload;
    use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MainnetBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        256,
        32,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_bellatrix_result(
        result.map(|_| ()),
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

fn run_bellatrix_execution_payload_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "bellatrix",
        "operations",
        Some("execution_payload"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "bellatrix/operations/minimal/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_bellatrix_execution_payload_case_minimal(&case_dir, &case_name)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_execution_payload_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::bellatrix::operations::process_execution_payload;
    use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MinimalBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        256,
        32,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_bellatrix_result(
        result.map(|_| ()),
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

// ── Bellatrix shared helpers ──────────────────────────────────────────────────

/// Read `execution.yaml` from `case_dir`, returning `execution_valid` field.
///
/// Defaults to `true` when the file is absent or the field cannot be parsed,
/// matching the behaviour expected for spec-test cases without EL interaction.
fn read_execution_valid(case_dir: &Path) -> bool {
    let path = case_dir.join("execution.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return true;
    };
    // Format: `{execution_valid: true}` or `{execution_valid: false}`.
    !text.contains("execution_valid: false")
}

fn cmp_bellatrix_result(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> CaseResult {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── Capella operations ────────────────────────────────────────────────────────

/// Run all capella operation sub-categories for the mainnet preset.
pub fn run_operations_capella_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_capella_block_header_mainnet(root));
    total.merge(run_capella_proposer_slashing_mainnet(root));
    total.merge(run_capella_attester_slashing_mainnet(root));
    total.merge(run_capella_deposit_mainnet(root));
    total.merge(run_capella_attestation_mainnet(root));
    total.merge(run_capella_voluntary_exit_mainnet(root));
    total.merge(run_capella_sync_aggregate_mainnet(root));
    total.merge(run_capella_execution_payload_mainnet(root));
    total.merge(run_capella_withdrawals_mainnet(root));
    total.merge(run_capella_bls_to_execution_change_mainnet(root));
    total
}

/// Run all capella operation sub-categories for the minimal preset.
pub fn run_operations_capella_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_capella_block_header_minimal(root));
    total.merge(run_capella_proposer_slashing_minimal(root));
    total.merge(run_capella_attester_slashing_minimal(root));
    total.merge(run_capella_deposit_minimal(root));
    total.merge(run_capella_attestation_minimal(root));
    total.merge(run_capella_voluntary_exit_minimal(root));
    total.merge(run_capella_sync_aggregate_minimal(root));
    total.merge(run_capella_execution_payload_minimal(root));
    total.merge(run_capella_withdrawals_minimal(root));
    total.merge(run_capella_bls_to_execution_change_minimal(root));
    total
}

fn capella_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

fn run_capella_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    run_case: impl Fn(&Path, &str, bool) -> CaseResult + Sync + Send,
) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "capella",
        "operations",
        Some(sub),
        capella_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("capella/operations/{preset}/{sub}/{}", dir_name(&case_dir));
            let verify_signatures = bls_verify(&meta);
            run_case(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn cmp_capella_result(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> CaseResult {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── capella/block_header ──────────────────────────────────────────────────────

fn run_capella_block_header_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(root, "mainnet", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        use pharos_types::{MainnetEthSpec as E, capella::MainnetBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::capella_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MainnetBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = capella_state_to_altair(&pre);
        let altair_block = pharos_stf::capella::capella_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            8192,
            16_777_216,
            2048,
            1_099_511_627_776,
            65536,
            8192,
            4,
            512,
            E,
        >(&mut altair_state, &altair_block);
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_capella_from_altair(&mut pre, altair_state);
        cmp_capella_result(
            result,
            E::capella_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

fn run_capella_block_header_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(root, "minimal", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        use pharos_types::{MinimalEthSpec as E, capella::MinimalBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::capella_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MinimalBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = capella_state_to_altair(&pre);
        let altair_block = pharos_stf::capella::capella_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            64,
            16_777_216,
            32,
            1_099_511_627_776,
            64,
            64,
            4,
            32,
            E,
        >(&mut altair_state, &altair_block);
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_capella_from_altair(&mut pre, altair_state);
        cmp_capella_result(
            result,
            E::capella_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

// ── capella/proposer_slashing ─────────────────────────────────────────────────

fn run_capella_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_proposer_slashing_capella;
            use pharos_types::{MainnetEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_capella::<
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
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

fn run_capella_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_proposer_slashing_capella;
            use pharos_types::{MinimalEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_capella::<
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
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

// ── capella/attester_slashing ─────────────────────────────────────────────────

fn run_capella_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_attester_slashing_capella;
            use pharos_types::{MainnetEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_capella::<
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
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

fn run_capella_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_attester_slashing_capella;
            use pharos_types::{MinimalEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_capella::<
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
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

// ── capella/deposit ───────────────────────────────────────────────────────────

fn run_capella_deposit_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_deposit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &deposit, verify_signatures);
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

fn run_capella_deposit_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut altair_state,
                &deposit,
                verify_signatures,
            );
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

// ── capella/attestation ───────────────────────────────────────────────────────

fn run_capella_attestation_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_attestation::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &attestation, verify_signatures);
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

fn run_capella_attestation_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result =
                process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &attestation,
                    verify_signatures,
                );
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

// ── capella/voluntary_exit ────────────────────────────────────────────────────

fn run_capella_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_voluntary_exit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &exit, verify_signatures);
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

fn run_capella_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result =
                process_voluntary_exit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &exit,
                    verify_signatures,
                );
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

// ── capella/sync_aggregate ────────────────────────────────────────────────────

fn run_capella_sync_aggregate_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "operations",
        Some("sync_aggregate"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "capella/operations/mainnet/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_capella_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_sync_aggregate_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_types::{MainnetEthSpec as E, altair::MainnetSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MainnetSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = capella_state_to_altair(&pre);
    let result = process_sync_aggregate::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut altair_state, &sync_aggregate, verify_signatures);
    update_capella_from_altair(&mut pre, altair_state);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

fn run_capella_sync_aggregate_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "operations",
        Some("sync_aggregate"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "capella/operations/minimal/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_capella_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_sync_aggregate_case_minimal(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_types::{MinimalEthSpec as E, altair::MinimalSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MinimalSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = capella_state_to_altair(&pre);
    let result = process_sync_aggregate::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut altair_state,
        &sync_aggregate,
        verify_signatures,
    );
    update_capella_from_altair(&mut pre, altair_state);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

// ── capella/execution_payload ─────────────────────────────────────────────────

fn run_capella_execution_payload_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "operations",
        Some("execution_payload"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/mainnet/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_capella_execution_payload_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_execution_payload_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::capella::operations::process_execution_payload;
    use pharos_types::{MainnetEthSpec as E, capella::MainnetBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MainnetBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        256,
        32,
        16, // MAX_WITHDRAWALS_PER_PAYLOAD mainnet
        16, // MAX_BLS_TO_EXECUTION_CHANGES mainnet
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_capella_result(
        result.map(|_| ()),
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

fn run_capella_execution_payload_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "operations",
        Some("execution_payload"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/minimal/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_capella_execution_payload_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_execution_payload_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::capella::operations::process_execution_payload;
    use pharos_types::{MinimalEthSpec as E, capella::MinimalBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MinimalBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        256,
        32,
        4,  // MAX_WITHDRAWALS_PER_PAYLOAD minimal
        16, // MAX_BLS_TO_EXECUTION_CHANGES minimal
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_capella_result(
        result.map(|_| ()),
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

// ── capella/withdrawals ───────────────────────────────────────────────────────

fn run_capella_withdrawals_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "operations",
        Some("withdrawals"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/mainnet/withdrawals/{}",
                dir_name(&case_dir)
            );
            run_capella_withdrawals_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_withdrawals_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::operations::process_withdrawals;
    use pharos_types::{MainnetEthSpec as E, capella::MainnetExecutionPayload};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let payload = match load_ssz_snappy::<MainnetExecutionPayload>(
        case_dir,
        "execution_payload.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre = pre_inner;
    let result = process_withdrawals::<
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
        1_073_741_824,
        1_048_576,
        16, // MAX_WITHDRAWALS_PER_PAYLOAD mainnet
        E,
    >(&mut pre, &payload);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "withdrawals",
    )
}

fn run_capella_withdrawals_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "operations",
        Some("withdrawals"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/minimal/withdrawals/{}",
                dir_name(&case_dir)
            );
            run_capella_withdrawals_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_withdrawals_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::operations::process_withdrawals;
    use pharos_types::{MinimalEthSpec as E, capella::MinimalExecutionPayload};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let payload = match load_ssz_snappy::<MinimalExecutionPayload>(
        case_dir,
        "execution_payload.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre = pre_inner;
    let result = process_withdrawals::<
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
        1_073_741_824,
        1_048_576,
        4, // MAX_WITHDRAWALS_PER_PAYLOAD minimal
        E,
    >(&mut pre, &payload);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "withdrawals",
    )
}

// ── capella/bls_to_execution_change ──────────────────────────────────────────

fn run_capella_bls_to_execution_change_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "bls_to_execution_change",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_bls_to_execution_change;
            use pharos_types::{MainnetEthSpec as E, capella::SignedBLSToExecutionChange};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let signed_change = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                case_dir,
                "address_change.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_bls_to_execution_change::<
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
            >(&mut pre, &signed_change, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "bls_to_execution_change",
            )
        },
    )
}

fn run_capella_bls_to_execution_change_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "bls_to_execution_change",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_bls_to_execution_change;
            use pharos_types::{MinimalEthSpec as E, capella::SignedBLSToExecutionChange};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let signed_change = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                case_dir,
                "address_change.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_bls_to_execution_change::<
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
                E,
            >(&mut pre, &signed_change, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "bls_to_execution_change",
            )
        },
    )
}

// ── Deneb operations entry points ─────────────────────────────────────────────

/// Run all deneb operation sub-categories for the mainnet preset.
pub fn run_operations_deneb_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_deneb_block_header_mainnet(root));
    total.merge(run_deneb_proposer_slashing_mainnet(root));
    total.merge(run_deneb_attester_slashing_mainnet(root));
    total.merge(run_deneb_deposit_mainnet(root));
    total.merge(run_deneb_attestation_mainnet(root));
    total.merge(run_deneb_voluntary_exit_mainnet(root));
    total.merge(run_deneb_sync_aggregate_mainnet(root));
    total.merge(run_deneb_execution_payload_mainnet(root));
    total.merge(run_deneb_withdrawals_mainnet(root));
    total.merge(run_deneb_bls_to_execution_change_mainnet(root));
    total
}

/// Run all deneb operation sub-categories for the minimal preset.
pub fn run_operations_deneb_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_deneb_block_header_minimal(root));
    total.merge(run_deneb_proposer_slashing_minimal(root));
    total.merge(run_deneb_attester_slashing_minimal(root));
    total.merge(run_deneb_deposit_minimal(root));
    total.merge(run_deneb_attestation_minimal(root));
    total.merge(run_deneb_voluntary_exit_minimal(root));
    total.merge(run_deneb_sync_aggregate_minimal(root));
    total.merge(run_deneb_execution_payload_minimal(root));
    total.merge(run_deneb_withdrawals_minimal(root));
    total.merge(run_deneb_bls_to_execution_change_minimal(root));
    total
}

fn deneb_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

fn run_deneb_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    run_case: impl Fn(&Path, &str, bool) -> CaseResult + Sync + Send,
) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "deneb",
        "operations",
        Some(sub),
        deneb_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("deneb/operations/{preset}/{sub}/{}", dir_name(&case_dir));
            let verify_signatures = bls_verify(&meta);
            run_case(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn cmp_deneb_result(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> CaseResult {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── deneb/block_header ────────────────────────────────────────────────────────

fn run_deneb_block_header_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(root, "mainnet", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        use pharos_stf::deneb::block::deneb_block_to_capella_block;
        use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
        use pharos_types::{MainnetEthSpec as E, deneb::MainnetBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::deneb_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MainnetBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut capella = deneb_state_to_capella(&pre);
        let mut altair_state = capella_state_to_altair(&capella);
        let capella_block = deneb_block_to_capella_block::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            512,
            1_073_741_824,
            1_048_576,
            256,
            32,
            16,
            16,
            4096,
        >(&block);
        let altair_block = pharos_stf::capella::capella_block_to_altair_block(&capella_block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            8192,
            16_777_216,
            2048,
            1_099_511_627_776,
            65536,
            8192,
            4,
            512,
            E,
        >(&mut altair_state, &altair_block);
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_capella_from_altair(&mut capella, altair_state);
        update_deneb_from_capella(&mut pre, capella);
        cmp_deneb_result(
            result,
            E::deneb_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

fn run_deneb_block_header_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(root, "minimal", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        use pharos_stf::deneb::block::deneb_block_to_capella_block;
        use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
        use pharos_types::{MinimalEthSpec as E, deneb::MinimalBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::deneb_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MinimalBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut capella = deneb_state_to_capella(&pre);
        let mut altair_state = capella_state_to_altair(&capella);
        let capella_block = deneb_block_to_capella_block::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            32,
            1_073_741_824,
            1_048_576,
            256,
            32,
            4,
            16,
            4096,
        >(&block); // SYNC_COMMITTEE_SIZE=32 for minimal
        let altair_block = pharos_stf::capella::capella_block_to_altair_block(&capella_block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            64,
            16_777_216,
            32,
            1_099_511_627_776,
            64,
            64,
            4,
            32,
            E,
        >(&mut altair_state, &altair_block);
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_capella_from_altair(&mut capella, altair_state);
        update_deneb_from_capella(&mut pre, capella);
        cmp_deneb_result(
            result,
            E::deneb_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

// ── deneb/proposer_slashing ───────────────────────────────────────────────────

fn run_deneb_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "mainnet",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_proposer_slashing_capella;
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MainnetEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let result = process_proposer_slashing_capella::<
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
            >(&mut capella, &slashing, verify_signatures);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

fn run_deneb_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "minimal",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_proposer_slashing_capella;
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MinimalEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let result = process_proposer_slashing_capella::<
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
                E,
            >(&mut capella, &slashing, verify_signatures);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

// ── deneb/attester_slashing ───────────────────────────────────────────────────

fn run_deneb_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "mainnet",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_attester_slashing_capella;
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MainnetEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let result = process_attester_slashing_capella::<
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
            >(&mut capella, &slashing, verify_signatures);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

fn run_deneb_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "minimal",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_attester_slashing_capella;
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MinimalEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let result = process_attester_slashing_capella::<
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
                E,
            >(&mut capella, &slashing, verify_signatures);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

// ── deneb/deposit ─────────────────────────────────────────────────────────────

fn run_deneb_deposit_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "mainnet",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MainnetEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let mut altair_state = capella_state_to_altair(&capella);
            let result = process_deposit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &deposit, verify_signatures);
            update_capella_from_altair(&mut capella, altair_state);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

fn run_deneb_deposit_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "minimal",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MinimalEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let mut altair_state = capella_state_to_altair(&capella);
            let result = process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut altair_state,
                &deposit,
                verify_signatures,
            );
            update_capella_from_altair(&mut capella, altair_state);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

// ── deneb/attestation ─────────────────────────────────────────────────────────

fn run_deneb_attestation_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "mainnet",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::deneb::operations::process_attestation;
            use pharos_types::{MainnetEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_attestation::<
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
            >(&mut pre, &attestation, verify_signatures);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

fn run_deneb_attestation_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "minimal",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::deneb::operations::process_attestation;
            use pharos_types::{MinimalEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_attestation::<
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
                E,
            >(&mut pre, &attestation, verify_signatures);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

// ── deneb/voluntary_exit ──────────────────────────────────────────────────────

fn run_deneb_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "mainnet",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::deneb::operations::process_voluntary_exit;
            use pharos_types::{MainnetEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_voluntary_exit::<
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
            >(
                &mut pre,
                &exit,
                verify_signatures,
                &E::default_runtime_config(),
            );
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

fn run_deneb_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "minimal",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::deneb::operations::process_voluntary_exit;
            use pharos_types::{MinimalEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_voluntary_exit::<
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
                E,
            >(
                &mut pre,
                &exit,
                verify_signatures,
                &E::default_runtime_config(),
            );
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

// ── deneb/sync_aggregate ──────────────────────────────────────────────────────

fn run_deneb_sync_aggregate_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "deneb",
        "operations",
        Some("sync_aggregate"),
        deneb_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "deneb/operations/mainnet/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_deneb_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deneb_sync_aggregate_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::deneb::helpers::{deneb_state_to_altair, update_deneb_from_altair};
    use pharos_types::{MainnetEthSpec as E, altair::MainnetSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::deneb_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MainnetSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = deneb_state_to_altair(&pre);
    let result = process_sync_aggregate::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut altair_state, &sync_aggregate, verify_signatures);
    update_deneb_from_altair(&mut pre, altair_state);
    cmp_deneb_result(
        result,
        E::deneb_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

fn run_deneb_sync_aggregate_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "deneb",
        "operations",
        Some("sync_aggregate"),
        deneb_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "deneb/operations/minimal/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_deneb_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deneb_sync_aggregate_case_minimal(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::deneb::helpers::{deneb_state_to_altair, update_deneb_from_altair};
    use pharos_types::{MinimalEthSpec as E, altair::MinimalSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::deneb_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MinimalSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = deneb_state_to_altair(&pre);
    let result = process_sync_aggregate::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut altair_state,
        &sync_aggregate,
        verify_signatures,
    );
    update_deneb_from_altair(&mut pre, altair_state);
    cmp_deneb_result(
        result,
        E::deneb_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

// ── deneb/execution_payload ───────────────────────────────────────────────────

fn run_deneb_execution_payload_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "deneb",
        "operations",
        Some("execution_payload"),
        deneb_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "deneb/operations/mainnet/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_deneb_execution_payload_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deneb_execution_payload_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::deneb::operations::process_execution_payload;
    use pharos_types::{MainnetEthSpec as E, deneb::MainnetBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::deneb_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MainnetBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        256,
        32,
        16,   // MAX_WITHDRAWALS_PER_PAYLOAD mainnet
        16,   // MAX_BLS_TO_EXECUTION_CHANGES mainnet
        4096, // MAX_BLOB_COMMITMENTS_PER_BLOCK mainnet
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_deneb_result(
        result.map(|_| ()),
        E::deneb_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

fn run_deneb_execution_payload_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "deneb",
        "operations",
        Some("execution_payload"),
        deneb_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "deneb/operations/minimal/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_deneb_execution_payload_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deneb_execution_payload_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::deneb::operations::process_execution_payload;
    use pharos_types::{MinimalEthSpec as E, deneb::MinimalBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::deneb_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MinimalBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        256,
        32,
        4,    // MAX_WITHDRAWALS_PER_PAYLOAD minimal
        16,   // MAX_BLS_TO_EXECUTION_CHANGES minimal
        4096, // MAX_BLOB_COMMITMENTS_PER_BLOCK minimal
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_deneb_result(
        result.map(|_| ()),
        E::deneb_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

// ── deneb/withdrawals ─────────────────────────────────────────────────────────

fn run_deneb_withdrawals_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "deneb",
        "operations",
        Some("withdrawals"),
        deneb_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "deneb/operations/mainnet/withdrawals/{}",
                dir_name(&case_dir)
            );
            run_deneb_withdrawals_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deneb_withdrawals_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::operations::process_withdrawals;
    use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
    use pharos_types::{MainnetEthSpec as E, deneb::MainnetExecutionPayload};

    let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::deneb_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let payload = match load_ssz_snappy::<MainnetExecutionPayload>(
        case_dir,
        "execution_payload.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre = pre_inner;
    let mut capella = deneb_state_to_capella(&pre);
    let capella_payload = pharos_types::capella::MainnetExecutionPayload {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions: payload.transactions.clone(),
        withdrawals: payload.withdrawals.clone(),
    };
    let result = process_withdrawals::<
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
        1_073_741_824,
        1_048_576,
        16, // MAX_WITHDRAWALS_PER_PAYLOAD mainnet
        E,
    >(&mut capella, &capella_payload);
    update_deneb_from_capella(&mut pre, capella);
    cmp_deneb_result(
        result,
        E::deneb_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "withdrawals",
    )
}

fn run_deneb_withdrawals_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "deneb",
        "operations",
        Some("withdrawals"),
        deneb_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "deneb/operations/minimal/withdrawals/{}",
                dir_name(&case_dir)
            );
            run_deneb_withdrawals_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deneb_withdrawals_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::operations::process_withdrawals;
    use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
    use pharos_types::{MinimalEthSpec as E, deneb::MinimalExecutionPayload};

    let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::deneb_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let payload = match load_ssz_snappy::<MinimalExecutionPayload>(
        case_dir,
        "execution_payload.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre = pre_inner;
    let mut capella = deneb_state_to_capella(&pre);
    let capella_payload = pharos_types::capella::MinimalExecutionPayload {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions: payload.transactions.clone(),
        withdrawals: payload.withdrawals.clone(),
    };
    let result = process_withdrawals::<
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
        1_073_741_824,
        1_048_576,
        4, // MAX_WITHDRAWALS_PER_PAYLOAD minimal
        E,
    >(&mut capella, &capella_payload);
    update_deneb_from_capella(&mut pre, capella);
    cmp_deneb_result(
        result,
        E::deneb_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "withdrawals",
    )
}

// ── deneb/bls_to_execution_change ─────────────────────────────────────────────

fn run_deneb_bls_to_execution_change_mainnet(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "mainnet",
        "bls_to_execution_change",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_bls_to_execution_change;
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MainnetEthSpec as E, capella::SignedBLSToExecutionChange};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let signed_change = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                case_dir,
                "address_change.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let result = process_bls_to_execution_change::<
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
            >(&mut capella, &signed_change, verify_signatures);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "bls_to_execution_change",
            )
        },
    )
}

fn run_deneb_bls_to_execution_change_minimal(root: &Path) -> OpsResult {
    run_deneb_op_preset(
        root,
        "minimal",
        "bls_to_execution_change",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_bls_to_execution_change;
            use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
            use pharos_types::{MinimalEthSpec as E, capella::SignedBLSToExecutionChange};

            let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::deneb_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let signed_change = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                case_dir,
                "address_change.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut capella = deneb_state_to_capella(&pre);
            let result = process_bls_to_execution_change::<
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
                E,
            >(&mut capella, &signed_change, verify_signatures);
            update_deneb_from_capella(&mut pre, capella);
            cmp_deneb_result(
                result,
                E::deneb_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "bls_to_execution_change",
            )
        },
    )
}
