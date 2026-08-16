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

use crate::fixture_walker::{WalkOpts, load_pre_post_phase0_state, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;

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

// ── Bellatrix operations ──────────────────────────────────────────────────────

/// Walk options for bellatrix operation fixtures.
fn bellatrix_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Descriptor table for bellatrix operations — mainnet preset.
///
/// Sub order (verified from `run_operations_bellatrix_mainnet` body):
///   block_header, proposer_slashing, attester_slashing, deposit, attestation,
///   voluntary_exit, sync_aggregate, execution_payload
///
/// block_header, sync_aggregate, and execution_payload are bespoke (concrete
/// preset types, projection through `bellatrix_state_to_altair` /
/// `update_bellatrix_from_altair`). The 5 shared subs operate directly on the
/// bellatrix state. All closures return `CaseOutcome` directly.
/// EthSpec bounds (D-apply-op-no-ethspec-bound): none on this builder; each
/// closure names `MainnetEthSpec` directly.
#[allow(clippy::type_complexity)]
fn bellatrix_op_table_mainnet() -> Vec<(
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
        // block_header: bespoke — projects via bellatrix_state_to_altair, patches body_root.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::bellatrix::MainnetBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: operates directly on bellatrix state.
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::bellatrix::operations::process_proposer_slashing_bellatrix;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing: operates directly on bellatrix state.
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::bellatrix::operations::process_attester_slashing_bellatrix;
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit: projects through bellatrix_state_to_altair.
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation: projects through bellatrix_state_to_altair.
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attestation;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit: projects through bellatrix_state_to_altair.
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_voluntary_exit;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — projects via bellatrix_state_to_altair, uses MainnetSyncAggregate.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::altair::MainnetSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // execution_payload: bespoke — uses read_execution_valid + FixedExecutionEngine.
        (
            "execution_payload",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::FixedExecutionEngine;
                use pharos_stf::bellatrix::operations::process_execution_payload;
                use pharos_types::bellatrix::MainnetBeaconBlockBody;

                let execution_valid = read_execution_valid(&case_dir);
                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let body =
                    match load_ssz_snappy::<MainnetBeaconBlockBody>(&case_dir, "body.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let engine = FixedExecutionEngine(execution_valid);
                let mut pre = pre_inner;
                let result =
                    process_execution_payload::<
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
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result.map(|_| ()),
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "execution_payload",
                )
            }),
        ),
    ]
}

/// Descriptor table for bellatrix operations — minimal preset.
///
/// Same sub order as mainnet: block_header, proposer_slashing, attester_slashing,
/// deposit, attestation, voluntary_exit, sync_aggregate, execution_payload.
#[allow(clippy::type_complexity)]
fn bellatrix_op_table_minimal() -> Vec<(
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
        // block_header: bespoke — projects via bellatrix_state_to_altair, patches body_root.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::bellatrix::MinimalBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: operates directly on bellatrix state.
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::bellatrix::operations::process_proposer_slashing_bellatrix;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing: operates directly on bellatrix state.
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::bellatrix::operations::process_attester_slashing_bellatrix;
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit: projects through bellatrix_state_to_altair.
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = bellatrix_state_to_altair(&pre);
                let result =
                    process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut altair_state,
                        &op,
                        bls_verify(&meta),
                    );
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation: projects through bellatrix_state_to_altair.
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attestation;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = bellatrix_state_to_altair(&pre);
                let result =
                    process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut altair_state,
                        &op,
                        bls_verify(&meta),
                    );
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit: projects through bellatrix_state_to_altair.
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_voluntary_exit;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = bellatrix_state_to_altair(&pre);
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — projects via bellatrix_state_to_altair, uses MinimalSyncAggregate.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_stf::bellatrix::helpers::{
                    bellatrix_state_to_altair, update_bellatrix_from_altair,
                };
                use pharos_types::altair::MinimalSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = bellatrix_state_to_altair(&pre);
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_bellatrix_from_altair(&mut pre, altair_state);
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // execution_payload: bespoke — uses read_execution_valid + FixedExecutionEngine.
        (
            "execution_payload",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::FixedExecutionEngine;
                use pharos_stf::bellatrix::operations::process_execution_payload;
                use pharos_types::bellatrix::MinimalBeaconBlockBody;

                let execution_valid = read_execution_valid(&case_dir);
                let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::bellatrix_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let body =
                    match load_ssz_snappy::<MinimalBeaconBlockBody>(&case_dir, "body.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let engine = FixedExecutionEngine(execution_valid);
                let mut pre = pre_inner;
                let result =
                    process_execution_payload::<
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
                let current_bytes = E::bellatrix_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result.map(|_| ()),
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "execution_payload",
                )
            }),
        ),
    ]
}

/// Enumerate all bellatrix operation cases for one preset, returning `CaseTask`s
/// with sequential `case_ordinal` in (sub-table-order, walk-order).
fn enumerate_operations_bellatrix(
    root: &std::path::Path,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask> {
    let table = if preset == "mainnet" {
        bellatrix_op_table_mainnet()
    } else {
        bellatrix_op_table_minimal()
    };
    let mut case_ordinal: u32 = 0;
    let mut tasks = Vec::new();
    for (sub, apply) in table {
        let apply = std::sync::Arc::new(apply);
        let sub_tasks = enumerate_op(
            root,
            "bellatrix",
            preset,
            sub,
            row_ordinal,
            &mut case_ordinal,
            bellatrix_ops_walk_opts(),
            move |dir, name, meta| apply(dir, name, meta),
        );
        tasks.extend(sub_tasks);
    }
    tasks
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

// ── Capella operations ────────────────────────────────────────────────────────

/// Walk options for capella operation fixtures.
fn capella_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Descriptor table for capella operations — mainnet preset.
///
/// Sub order (verified from `run_operations_capella_mainnet` body):
///   block_header, proposer_slashing, attester_slashing, deposit, attestation,
///   voluntary_exit, sync_aggregate, execution_payload, withdrawals,
///   bls_to_execution_change
///
/// block_header, sync_aggregate, execution_payload, and withdrawals are bespoke
/// (projection through `capella_state_to_altair` / `update_capella_from_altair`,
/// or loading `execution_payload.ssz_snappy` / `body.ssz_snappy`).
/// proposer_slashing, attester_slashing, and bls_to_execution_change operate
/// directly on the capella state.
/// deposit, attestation, and voluntary_exit project via capella_state_to_altair.
#[allow(clippy::type_complexity)]
fn capella_op_table_mainnet() -> Vec<(
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
        // block_header: bespoke — projects via capella_state_to_altair, patches body_root.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::capella::MainnetBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: operates directly on capella state.
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_proposer_slashing_capella;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing: operates directly on capella state.
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_attester_slashing_capella;
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit: projects via capella_state_to_altair.
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation: projects via capella_state_to_altair.
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attestation;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit: projects via capella_state_to_altair.
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_voluntary_exit;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — projects via capella_state_to_altair, uses MainnetSyncAggregate.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::altair::MainnetSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // execution_payload: bespoke — uses read_execution_valid + FixedExecutionEngine.
        (
            "execution_payload",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::FixedExecutionEngine;
                use pharos_stf::capella::operations::process_execution_payload;
                use pharos_types::capella::MainnetBeaconBlockBody;

                let execution_valid = read_execution_valid(&case_dir);
                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let body =
                    match load_ssz_snappy::<MainnetBeaconBlockBody>(&case_dir, "body.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let engine = FixedExecutionEngine(execution_valid);
                let mut pre = pre_inner;
                let result =
                    process_execution_payload::<
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
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result.map(|_| ()),
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "execution_payload",
                )
            }),
        ),
        // withdrawals: bespoke — loads execution_payload.ssz_snappy, direct capella state.
        (
            "withdrawals",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::capella::operations::process_withdrawals;
                use pharos_types::capella::MainnetExecutionPayload;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let payload = match load_ssz_snappy::<MainnetExecutionPayload>(
                    &case_dir,
                    "execution_payload.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "withdrawals")
            }),
        ),
        // bls_to_execution_change: operates directly on capella state.
        (
            "bls_to_execution_change",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_bls_to_execution_change;
                use pharos_types::capella::SignedBLSToExecutionChange;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                    &case_dir,
                    "address_change.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "bls_to_execution_change",
                )
            }),
        ),
    ]
}

/// Descriptor table for capella operations — minimal preset.
///
/// Same sub order as mainnet: block_header, proposer_slashing, attester_slashing,
/// deposit, attestation, voluntary_exit, sync_aggregate, execution_payload,
/// withdrawals, bls_to_execution_change.
#[allow(clippy::type_complexity)]
fn capella_op_table_minimal() -> Vec<(
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
        // block_header: bespoke — projects via capella_state_to_altair, patches body_root.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::capella::MinimalBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: operates directly on capella state.
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_proposer_slashing_capella;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing: operates directly on capella state.
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_attester_slashing_capella;
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit: projects via capella_state_to_altair.
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = capella_state_to_altair(&pre);
                let result =
                    process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut altair_state,
                        &op,
                        bls_verify(&meta),
                    );
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation: projects via capella_state_to_altair.
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_attestation;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = capella_state_to_altair(&pre);
                let result =
                    process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut altair_state,
                        &op,
                        bls_verify(&meta),
                    );
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit: projects via capella_state_to_altair.
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_voluntary_exit;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = capella_state_to_altair(&pre);
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — projects via capella_state_to_altair, uses MinimalSyncAggregate.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_types::altair::MinimalSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = capella_state_to_altair(&pre);
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut pre, altair_state);
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // execution_payload: bespoke — uses read_execution_valid + FixedExecutionEngine.
        (
            "execution_payload",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::FixedExecutionEngine;
                use pharos_stf::capella::operations::process_execution_payload;
                use pharos_types::capella::MinimalBeaconBlockBody;

                let execution_valid = read_execution_valid(&case_dir);
                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let body =
                    match load_ssz_snappy::<MinimalBeaconBlockBody>(&case_dir, "body.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let engine = FixedExecutionEngine(execution_valid);
                let mut pre = pre_inner;
                let result =
                    process_execution_payload::<
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
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result.map(|_| ()),
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "execution_payload",
                )
            }),
        ),
        // withdrawals: bespoke — loads execution_payload.ssz_snappy, direct capella state.
        (
            "withdrawals",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::capella::operations::process_withdrawals;
                use pharos_types::capella::MinimalExecutionPayload;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let payload = match load_ssz_snappy::<MinimalExecutionPayload>(
                    &case_dir,
                    "execution_payload.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "withdrawals")
            }),
        ),
        // bls_to_execution_change: operates directly on capella state.
        (
            "bls_to_execution_change",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_bls_to_execution_change;
                use pharos_types::capella::SignedBLSToExecutionChange;

                let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::capella_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                    &case_dir,
                    "address_change.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::capella_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "bls_to_execution_change",
                )
            }),
        ),
    ]
}

/// Enumerate all capella operation cases for one preset, returning `CaseTask`s
/// with sequential `case_ordinal` in (sub-table-order, walk-order).
fn enumerate_operations_capella(
    root: &std::path::Path,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask> {
    let table = if preset == "mainnet" {
        capella_op_table_mainnet()
    } else {
        capella_op_table_minimal()
    };
    let mut case_ordinal: u32 = 0;
    let mut tasks = Vec::new();
    for (sub, apply) in table {
        let apply = std::sync::Arc::new(apply);
        let sub_tasks = enumerate_op(
            root,
            "capella",
            preset,
            sub,
            row_ordinal,
            &mut case_ordinal,
            capella_ops_walk_opts(),
            move |dir, name, meta| apply(dir, name, meta),
        );
        tasks.extend(sub_tasks);
    }
    tasks
}

// ── Deneb operations ──────────────────────────────────────────────────────────

fn deneb_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Descriptor table for deneb operations — mainnet preset.
///
/// Sub order (verified from `run_operations_deneb_mainnet` body):
///   block_header, proposer_slashing, attester_slashing, deposit, attestation,
///   voluntary_exit, sync_aggregate, execution_payload, withdrawals,
///   bls_to_execution_change
///
/// block_header: deneb→capella→altair (triple projection).
/// sync_aggregate: deneb→altair directly (deneb_state_to_altair).
/// execution_payload: direct on deneb state (deneb process_execution_payload, blob consts).
/// withdrawals: deneb→capella payload conversion, then process_withdrawals on capella state.
/// proposer_slashing, attester_slashing, bls_to_execution_change: deneb→capella.
/// deposit: deneb→capella→altair.
/// attestation, voluntary_exit: direct on deneb state (deneb-specific process fns).
#[allow(clippy::type_complexity)]
fn deneb_op_table_mainnet() -> Vec<(
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
        // block_header: bespoke — deneb→capella→altair projection, patches body_root.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_stf::deneb::block::deneb_block_to_capella_block;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::deneb::MainnetBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                let altair_block =
                    pharos_stf::capella::capella_block_to_altair_block(&capella_block);
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
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: deneb→capella projection.
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_proposer_slashing_capella;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut capella, &op, bls_verify(&meta));
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing: deneb→capella projection.
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_attester_slashing_capella;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut capella, &op, bls_verify(&meta));
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit: deneb→capella→altair projection.
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_capella_from_altair(&mut capella, altair_state);
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation: direct on deneb state (EIP-7045 process_attestation).
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::deneb::operations::process_attestation;
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                    256,
                    32,
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit: direct on deneb state (EIP-7044 fixed domain).
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::deneb::operations::process_voluntary_exit;
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                    256,
                    32,
                    E,
                >(
                    &mut pre,
                    &op,
                    bls_verify(&meta),
                    &E::default_runtime_config(),
                );
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — deneb→altair directly.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_stf::deneb::helpers::{deneb_state_to_altair, update_deneb_from_altair};
                use pharos_types::altair::MainnetSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_deneb_from_altair(&mut pre, altair_state);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // execution_payload: bespoke — direct on deneb state, EIP-4844 blob consts.
        (
            "execution_payload",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::FixedExecutionEngine;
                use pharos_stf::deneb::operations::process_execution_payload;
                use pharos_types::deneb::MainnetBeaconBlockBody;

                let execution_valid = read_execution_valid(&case_dir);
                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let body =
                    match load_ssz_snappy::<MainnetBeaconBlockBody>(&case_dir, "body.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let engine = FixedExecutionEngine(execution_valid);
                let mut pre = pre_inner;
                let result =
                    process_execution_payload::<
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
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result.map(|_| ()),
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "execution_payload",
                )
            }),
        ),
        // withdrawals: bespoke — loads deneb payload, converts to capella payload, projects state.
        (
            "withdrawals",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::capella::operations::process_withdrawals;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::deneb::MainnetExecutionPayload;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let payload = match load_ssz_snappy::<MainnetExecutionPayload>(
                    &case_dir,
                    "execution_payload.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "withdrawals")
            }),
        ),
        // bls_to_execution_change: deneb→capella projection.
        (
            "bls_to_execution_change",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_bls_to_execution_change;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::capella::SignedBLSToExecutionChange;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MainnetBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                    &case_dir,
                    "address_change.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                >(&mut capella, &op, bls_verify(&meta));
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "bls_to_execution_change",
                )
            }),
        ),
    ]
}

/// Descriptor table for deneb operations — minimal preset.
///
/// Same sub order as mainnet: block_header, proposer_slashing, attester_slashing,
/// deposit, attestation, voluntary_exit, sync_aggregate, execution_payload,
/// withdrawals, bls_to_execution_change.
#[allow(clippy::type_complexity)]
fn deneb_op_table_minimal() -> Vec<(
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
        // block_header: bespoke — deneb→capella→altair projection, patches body_root.
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_stf::altair::block::process_block_header_altair;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_stf::deneb::block::deneb_block_to_capella_block;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::deneb::MinimalBeaconBlock;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&block);
                let altair_block =
                    pharos_stf::capella::capella_block_to_altair_block(&capella_block);
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
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: deneb→capella projection.
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_proposer_slashing_capella;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut capella, &op, bls_verify(&meta));
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // attester_slashing: deneb→capella projection.
        (
            "attester_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_attester_slashing_capella;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::phase0::AttesterSlashing;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut capella, &op, bls_verify(&meta));
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit: deneb→capella→altair projection.
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::altair::operations::process_deposit;
                use pharos_stf::capella::helpers::{
                    capella_state_to_altair, update_capella_from_altair,
                };
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::phase0::Deposit;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                let mut capella = deneb_state_to_capella(&pre);
                let mut altair_state = capella_state_to_altair(&capella);
                let result =
                    process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                        &mut altair_state,
                        &op,
                        bls_verify(&meta),
                    );
                update_capella_from_altair(&mut capella, altair_state);
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // attestation: direct on deneb state (EIP-7045 process_attestation).
        (
            "attestation",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::deneb::operations::process_attestation;
                use pharos_types::phase0::Attestation;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // voluntary_exit: direct on deneb state (EIP-7044 fixed domain).
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::deneb::operations::process_voluntary_exit;
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                    256,
                    32,
                    E,
                >(
                    &mut pre,
                    &op,
                    bls_verify(&meta),
                    &E::default_runtime_config(),
                );
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: bespoke — deneb→altair directly.
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_stf::altair::operations::process_sync_aggregate;
                use pharos_stf::deneb::helpers::{deneb_state_to_altair, update_deneb_from_altair};
                use pharos_types::altair::MinimalSyncAggregate;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
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
                let mut altair_state = deneb_state_to_altair(&pre);
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
                >(&mut altair_state, &op, bls_verify(&meta));
                update_deneb_from_altair(&mut pre, altair_state);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // execution_payload: bespoke — direct on deneb state, EIP-4844 blob consts.
        (
            "execution_payload",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::FixedExecutionEngine;
                use pharos_stf::deneb::operations::process_execution_payload;
                use pharos_types::deneb::MinimalBeaconBlockBody;

                let execution_valid = read_execution_valid(&case_dir);
                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let body =
                    match load_ssz_snappy::<MinimalBeaconBlockBody>(&case_dir, "body.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let engine = FixedExecutionEngine(execution_valid);
                let mut pre = pre_inner;
                let result =
                    process_execution_payload::<
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
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result.map(|_| ()),
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "execution_payload",
                )
            }),
        ),
        // withdrawals: bespoke — loads deneb payload, converts to capella payload, projects state.
        (
            "withdrawals",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_stf::capella::operations::process_withdrawals;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::deneb::MinimalExecutionPayload;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let payload = match load_ssz_snappy::<MinimalExecutionPayload>(
                    &case_dir,
                    "execution_payload.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "withdrawals")
            }),
        ),
        // bls_to_execution_change: deneb→capella projection.
        (
            "bls_to_execution_change",
            Box::new(|case_dir, case_name, meta| {
                use pharos_stf::capella::operations::process_bls_to_execution_change;
                use pharos_stf::deneb::helpers::{
                    deneb_state_to_capella, update_deneb_from_capella,
                };
                use pharos_types::capella::SignedBLSToExecutionChange;

                let pre_inner = match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                    &case_dir,
                    "pre.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<pharos_types::deneb::MinimalBeaconState>(
                        &case_dir,
                        "post.ssz_snappy",
                    ) {
                        Ok(v) => Some(E::deneb_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                    &case_dir,
                    "address_change.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
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
                >(&mut capella, &op, bls_verify(&meta));
                update_deneb_from_capella(&mut pre, capella);
                let current_bytes = E::deneb_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "bls_to_execution_change",
                )
            }),
        ),
    ]
}

/// Enumerate all deneb operation cases for one preset, returning `CaseTask`s
/// with sequential `case_ordinal` in (sub-table-order, walk-order).
fn enumerate_operations_deneb(
    root: &std::path::Path,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask> {
    let table = if preset == "mainnet" {
        deneb_op_table_mainnet()
    } else {
        deneb_op_table_minimal()
    };
    let mut case_ordinal: u32 = 0;
    let mut tasks = Vec::new();
    for (sub, apply) in table {
        let apply = std::sync::Arc::new(apply);
        let sub_tasks = enumerate_op(
            root,
            "deneb",
            preset,
            sub,
            row_ordinal,
            &mut case_ordinal,
            deneb_ops_walk_opts(),
            move |dir, name, meta| apply(dir, name, meta),
        );
        tasks.extend(sub_tasks);
    }
    tasks
}

// ── Electra operations ────────────────────────────────────────────────────────

fn electra_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Descriptor table for electra operations — mainnet preset.
///
/// Phase 2b+2c+3a: `block_header`, `proposer_slashing`, `deposit`, `voluntary_exit`,
/// `sync_aggregate`, `attestation`, `attester_slashing`, `deposit_request` sub-ops
/// registered. Remaining sub-ops (execution_payload, withdrawals,
/// withdrawal_request, consolidation_request) land in later phases.
#[allow(clippy::type_complexity)]
fn electra_op_table_mainnet() -> Vec<(
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
    use pharos_stf::electra::operations::{
        process_attestation_electra, process_attester_slashing_electra,
        process_block_header_electra, process_consolidation_request, process_deposit_electra,
        process_deposit_request, process_proposer_slashing_electra, process_sync_aggregate_electra,
        process_voluntary_exit_electra, process_withdrawal_request,
    };
    use pharos_types::MainnetEthSpec as E;
    vec![
        // block_header: direct on electra state (electra proposer index).
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_types::electra::{MainnetBeaconBlock, MainnetBeaconState};

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let body_root = block.body.tree_hash_root();
                let result = process_block_header_electra::<
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
                >(
                    &mut pre,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    body_root,
                );
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: direct on electra state (slash_validator_electra).
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::MainnetBeaconState;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_proposer_slashing_electra::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // deposit: direct on electra state (PendingDeposit append).
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::MainnetBeaconState;
                use pharos_types::phase0::Deposit;

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_deposit_electra::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // voluntary_exit: direct on electra state (EIP-7251 + EIP-7044).
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::MainnetBeaconState;
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_voluntary_exit_electra::<
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
                >(
                    &mut pre,
                    &op,
                    bls_verify(&meta),
                    &E::default_runtime_config(),
                );
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: direct on electra state (electra proposer index).
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_types::altair::MainnetSyncAggregate;
                use pharos_types::electra::MainnetBeaconState;

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_sync_aggregate_electra::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // attestation: direct on electra state (EIP-7549).
        (
            "attestation",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_types::electra::{MainnetAttestation, MainnetBeaconState};

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<MainnetAttestation>(
                    &case_dir,
                    "attestation.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_attestation_electra::<
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
                    131_072, // MAX_AGGREGATION_BITS mainnet (2048 * 64)
                    64,      // MAX_COMMITTEES_PER_SLOT mainnet
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // attester_slashing: direct on electra state (EIP-7251 slash_validator).
        (
            "attester_slashing",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_types::electra::{MainnetAttesterSlashing, MainnetBeaconState};

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<MainnetAttesterSlashing>(
                    &case_dir,
                    "attester_slashing.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_attester_slashing_electra::<
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
                    131_072, // MAX_AGGREGATION_BITS mainnet (2048 * 64)
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit_request: EIP-6110 — enqueues a PendingDeposit with slot = state.slot.
        (
            "deposit_request",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::{MainnetBeaconState, requests::DepositRequest};

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<DepositRequest>(
                    &case_dir,
                    "deposit_request.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_deposit_request::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "deposit_request",
                )
            }),
        ),
        // withdrawal_request: EIP-7002 — full exit or partial withdrawal queue.
        (
            "withdrawal_request",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::{MainnetBeaconState, requests::WithdrawalRequest};

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<WithdrawalRequest>(
                    &case_dir,
                    "withdrawal_request.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_withdrawal_request::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "withdrawal_request",
                )
            }),
        ),
        // consolidation_request: EIP-7251 — switch-to-compounding or consolidation.
        (
            "consolidation_request",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::{MainnetBeaconState, requests::ConsolidationRequest};

                let pre_inner =
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MainnetBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<ConsolidationRequest>(
                    &case_dir,
                    "consolidation_request.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_consolidation_request::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "consolidation_request",
                )
            }),
        ),
    ]
}

/// Descriptor table for electra operations — minimal preset.
///
/// Phase 2b+2c+3a: same sub-op set as mainnet (block_header, proposer_slashing,
/// deposit, voluntary_exit, sync_aggregate, attestation, attester_slashing,
/// deposit_request).
#[allow(clippy::type_complexity)]
fn electra_op_table_minimal() -> Vec<(
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
    use pharos_stf::electra::operations::{
        process_attestation_electra, process_attester_slashing_electra,
        process_block_header_electra, process_consolidation_request, process_deposit_electra,
        process_deposit_request, process_proposer_slashing_electra, process_sync_aggregate_electra,
        process_voluntary_exit_electra, process_withdrawal_request,
    };
    use pharos_types::MinimalEthSpec as E;
    vec![
        // block_header: direct on electra state (electra proposer index).
        (
            "block_header",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, _meta| {
                use pharos_ssz::TreeHash as _;
                use pharos_types::electra::{MinimalBeaconBlock, MinimalBeaconState};

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let body_root = block.body.tree_hash_root();
                let result = process_block_header_electra::<
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
                >(
                    &mut pre,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    body_root,
                );
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "block_header",
                )
            }),
        ),
        // proposer_slashing: direct on electra state (slash_validator_electra).
        (
            "proposer_slashing",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::MinimalBeaconState;
                use pharos_types::phase0::ProposerSlashing;

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_proposer_slashing_electra::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "proposer_slashing",
                )
            }),
        ),
        // deposit: direct on electra state (PendingDeposit append).
        (
            "deposit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::MinimalBeaconState;
                use pharos_types::phase0::Deposit;

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_deposit_electra::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "deposit")
            }),
        ),
        // voluntary_exit: direct on electra state (EIP-7251 + EIP-7044).
        (
            "voluntary_exit",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::MinimalBeaconState;
                use pharos_types::phase0::SignedVoluntaryExit;

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_voluntary_exit_electra::<
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
                >(
                    &mut pre,
                    &op,
                    bls_verify(&meta),
                    &E::default_runtime_config(),
                );
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "voluntary_exit",
                )
            }),
        ),
        // sync_aggregate: direct on electra state (electra proposer index).
        (
            "sync_aggregate",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_types::altair::MinimalSyncAggregate;
                use pharos_types::electra::MinimalBeaconState;

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
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
                let result = process_sync_aggregate_electra::<
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
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "sync_aggregate",
                )
            }),
        ),
        // attestation: direct on electra state (EIP-7549).
        (
            "attestation",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_types::electra::{MinimalAttestation, MinimalBeaconState};

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<MinimalAttestation>(
                    &case_dir,
                    "attestation.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_attestation_electra::<
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
                    134_217_728, // PENDING_DEPOSITS_LIMIT minimal
                    64,          // PENDING_PARTIAL_WITHDRAWALS_LIMIT minimal
                    64,          // PENDING_CONSOLIDATIONS_LIMIT minimal
                    8192,        // MAX_AGGREGATION_BITS minimal (2048 * 4)
                    4,           // MAX_COMMITTEES_PER_SLOT minimal
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(result, current_bytes, post_bytes, &case_name, "attestation")
            }),
        ),
        // attester_slashing: direct on electra state (EIP-7251 slash_validator).
        (
            "attester_slashing",
            Box::new(|case_dir: std::path::PathBuf, case_name: String, meta| {
                use pharos_types::electra::{MinimalAttesterSlashing, MinimalBeaconState};

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<MinimalAttesterSlashing>(
                    &case_dir,
                    "attester_slashing.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_attester_slashing_electra::<
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
                    134_217_728, // PENDING_DEPOSITS_LIMIT minimal
                    64,          // PENDING_PARTIAL_WITHDRAWALS_LIMIT minimal
                    64,          // PENDING_CONSOLIDATIONS_LIMIT minimal
                    8192,        // MAX_AGGREGATION_BITS minimal (2048 * 4)
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "attester_slashing",
                )
            }),
        ),
        // deposit_request: EIP-6110 — enqueues a PendingDeposit with slot = state.slot.
        (
            "deposit_request",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::{MinimalBeaconState, requests::DepositRequest};

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<DepositRequest>(
                    &case_dir,
                    "deposit_request.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_deposit_request::<
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
                    134_217_728, // PENDING_DEPOSITS_LIMIT minimal
                    64,          // PENDING_PARTIAL_WITHDRAWALS_LIMIT minimal
                    64,          // PENDING_CONSOLIDATIONS_LIMIT minimal
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "deposit_request",
                )
            }),
        ),
        // withdrawal_request: EIP-7002 — full exit or partial withdrawal queue.
        (
            "withdrawal_request",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::{MinimalBeaconState, requests::WithdrawalRequest};

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<WithdrawalRequest>(
                    &case_dir,
                    "withdrawal_request.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_withdrawal_request::<
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
                    134_217_728, // PENDING_DEPOSITS_LIMIT minimal
                    64,          // PENDING_PARTIAL_WITHDRAWALS_LIMIT minimal
                    64,          // PENDING_CONSOLIDATIONS_LIMIT minimal
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "withdrawal_request",
                )
            }),
        ),
        // consolidation_request: EIP-7251 — switch-to-compounding or consolidation.
        (
            "consolidation_request",
            Box::new(|case_dir, case_name, meta| {
                use pharos_types::electra::{MinimalBeaconState, requests::ConsolidationRequest};

                let pre_inner =
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "pre.ssz_snappy") {
                        Ok(v) => v,
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    };
                let post_bytes = if case_dir.join("post.ssz_snappy").exists() {
                    match load_ssz_snappy::<MinimalBeaconState>(&case_dir, "post.ssz_snappy") {
                        Ok(v) => Some(E::electra_into_state(v).as_ssz_bytes()),
                        Err(e) => {
                            return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                        }
                    }
                } else {
                    None
                };
                let op = match load_ssz_snappy::<ConsolidationRequest>(
                    &case_dir,
                    "consolidation_request.ssz_snappy",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return crate::task::CaseOutcome::Fail(format!("{case_name}: {e}"));
                    }
                };
                let mut pre = pre_inner;
                let result = process_consolidation_request::<
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
                    134_217_728, // PENDING_DEPOSITS_LIMIT minimal
                    64,          // PENDING_PARTIAL_WITHDRAWALS_LIMIT minimal
                    64,          // PENDING_CONSOLIDATIONS_LIMIT minimal
                    E,
                >(&mut pre, &op, bls_verify(&meta));
                let current_bytes = E::electra_into_state(pre).as_ssz_bytes();
                altair_op_outcome(
                    result,
                    current_bytes,
                    post_bytes,
                    &case_name,
                    "consolidation_request",
                )
            }),
        ),
    ]
}

/// Enumerate all electra operation cases for one preset, returning `CaseTask`s
/// with sequential `case_ordinal` in (sub-table-order, walk-order).
fn enumerate_operations_electra(
    root: &std::path::Path,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask> {
    let table = if preset == "mainnet" {
        electra_op_table_mainnet()
    } else {
        electra_op_table_minimal()
    };
    let mut case_ordinal: u32 = 0;
    let mut tasks = Vec::new();
    for (sub, apply) in table {
        let apply = std::sync::Arc::new(apply);
        let sub_tasks = enumerate_op(
            root,
            "electra",
            preset,
            sub,
            row_ordinal,
            &mut case_ordinal,
            electra_ops_walk_opts(),
            move |dir, name, meta| apply(dir, name, meta),
        );
        tasks.extend(sub_tasks);
    }
    tasks
}

/// Public dispatch: enumerate all operation cases for a given `(fork, preset)` pair.
///
/// Called by the flat-pool driver in `lib.rs::run()`. Returns a `Vec<CaseTask>`
/// with `row_ordinal` set to `row_ordinal` and `case_ordinal`s assigned in
/// sub-table order × fixture-walk order.
pub fn enumerate_operations(
    root: &Path,
    fork: &str,
    preset: &str,
    row_ordinal: u32,
) -> Vec<crate::task::CaseTask> {
    match (fork, preset) {
        ("phase0", "mainnet") => {
            enumerate_operations_phase0::<MainnetEthSpec>(root, "mainnet", row_ordinal)
        }
        ("phase0", "minimal") => {
            enumerate_operations_phase0::<MinimalEthSpec>(root, "minimal", row_ordinal)
        }
        ("altair", "mainnet") => enumerate_operations_altair(root, "mainnet", row_ordinal),
        ("altair", "minimal") => enumerate_operations_altair(root, "minimal", row_ordinal),
        ("bellatrix", "mainnet") => enumerate_operations_bellatrix(root, "mainnet", row_ordinal),
        ("bellatrix", "minimal") => enumerate_operations_bellatrix(root, "minimal", row_ordinal),
        ("capella", "mainnet") => enumerate_operations_capella(root, "mainnet", row_ordinal),
        ("capella", "minimal") => enumerate_operations_capella(root, "minimal", row_ordinal),
        ("deneb", "mainnet") => enumerate_operations_deneb(root, "mainnet", row_ordinal),
        ("deneb", "minimal") => enumerate_operations_deneb(root, "minimal", row_ordinal),
        ("electra", "mainnet") => enumerate_operations_electra(root, "mainnet", row_ordinal),
        ("electra", "minimal") => enumerate_operations_electra(root, "minimal", row_ordinal),
        _ => Vec::new(),
    }
}
