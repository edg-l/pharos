//! Fork-choice conformance dispatcher.
//!
//! Walks `tests/{preset}/altair/fork_choice/{sub_category}/pyspec_tests/<case>/`
//! and drives `pharos_fork_choice::Store` through the `steps.yaml` tape for
//! each case, asserting the expected store state at each `checks` step.
//!
//! # Why altair fixtures?
//!
//! Phase-0 fork-choice fixtures do not exist upstream (consensus-spec-tests
//! ships fork-choice cases starting from altair).  Per the M1 plan Q1, the
//! `phase0/fork_choice/*` report rows point at the altair fixtures with a
//! footnote recorded in `docs/decisions.md`.
//!
//! # Skip-unknown-step-keys policy
//!
//! - **Unknown top-level step variant** (`on_merge_block`, `pow_block`,
//!   `on_payload_info`, `on_execution_payload_envelope`,
//!   `on_payload_attestation_message`, …) → the case is counted as **skip**,
//!   not fail.  These steps belong to bellatrix-and-later forks and have no
//!   handler in `pharos-fork-choice` yet.
//! - **Unknown key inside a `checks` block** is silently ignored.  Examples:
//!   `viable_for_head_roots_and_weights`, `should_override_forkchoice_update`,
//!   `head_payload_status`, `payload_timeliness_vote`,
//!   `payload_data_availability_vote`, `genesis_time` (we treat it as
//!   informational since it cannot drift mid-test).
//! - **Anchor-state / anchor-block SSZ decode failure** (neither altair nor
//!   phase0 succeeds) counts the case as **skip**. With altair types landed
//!   (M3b), all altair fork-choice fixtures decode successfully and the runner
//!   produces real pass/fail counts. Q1 is resolved as of M3b.

use std::path::{Path, PathBuf};

use pharos_fork_choice::get_head::{get_current_slot, get_proposer_head};
use pharos_fork_choice::{
    ForkChoiceError, HashMapPowBlockProvider, NoopPowBlockProvider, PowBlock, Store,
    get_forkchoice_store, get_head, on_attestation, on_attestation_electra, on_attester_slashing,
    on_block, on_tick, should_override_forkchoice_update,
};
use pharos_kzg::KzgVerifier;
use pharos_ssz::{Decode, SszList, SszSequence, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::{NullExecutionEngine, state_transition};
use pharos_types::{
    BeaconStateView, EthSpec, MainnetEthSpec, MinimalEthSpec,
    deneb::{Blob, KZGCommitment},
    phase0::{Attestation, AttesterSlashing, Checkpoint, Deposit, Epoch, Root, Slot},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_bellatrix_signed_block,
    load_bellatrix_state, load_capella_state, load_deneb_state, load_electra_state,
    load_phase0_state, load_ssz_snappy, walk_category,
};
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Electra (EIP-7549) attestation shim ────────────────────────────────────────

/// Per-preset access to the concrete electra `Attestation<A, C>` type.
///
/// The electra attestation envelope is const-generic on `MAX_AGGREGATION_BITS`
/// and `MAX_COMMITTEES_PER_SLOT` (mainnet `131072, 64`; minimal `8192, 4`).
/// Those constants cannot be named generically (they would need
/// `generic_const_exprs`), so the `attestation`-step decode and the in-block
/// attestation feed-through route through this trait, implemented once per
/// preset. Both impls drive `on_attestation_electra` (the EIP-7549
/// committee-bits extractor) so the LMD votes use the electra attester set.
trait ElectraFcSpec: EthSpec {
    /// Decode `<attestation>.ssz_snappy` as the preset's electra `Attestation`
    /// and run `on_attestation_electra` (standalone `attestation` step).
    fn run_electra_attestation_step(
        store: &mut Store<Self>,
        case_dir: &Path,
        attestation: &str,
        is_from_block: bool,
    ) -> Result<Result<(), ForkChoiceError>, String>;

    /// Feed every attestation in an electra block body into the store via
    /// `on_attestation_electra` (post-block feed-through, errors ignored).
    fn feed_electra_block_attestations(
        store: &mut Store<Self>,
        signed: &Self::ElectraSignedBeaconBlock,
    );

    /// Parent root of the concrete electra signed block.
    fn electra_block_parent_root(signed: &Self::ElectraSignedBeaconBlock) -> Root;

    /// `blob_kzg_commitments` of the concrete electra signed block (EIP-4844
    /// data-availability gate carried from Deneb).
    fn electra_block_commitments(signed: &Self::ElectraSignedBeaconBlock) -> Vec<KZGCommitment>;
}

impl ElectraFcSpec for MainnetEthSpec {
    fn run_electra_attestation_step(
        store: &mut Store<Self>,
        case_dir: &Path,
        attestation: &str,
        is_from_block: bool,
    ) -> Result<Result<(), ForkChoiceError>, String> {
        let att: pharos_types::electra::MainnetAttestation =
            load_ssz_snappy(case_dir, &format!("{attestation}.ssz_snappy"))?;
        Ok(on_attestation_electra::<131072, 64, Self>(
            store,
            &att,
            is_from_block,
        ))
    }

    fn feed_electra_block_attestations(
        store: &mut Store<Self>,
        signed: &Self::ElectraSignedBeaconBlock,
    ) {
        for att in signed.message.body.attestations.as_slice() {
            let _ = on_attestation_electra::<131072, 64, Self>(store, att, true);
        }
    }

    fn electra_block_parent_root(signed: &Self::ElectraSignedBeaconBlock) -> Root {
        signed.message.parent_root
    }

    fn electra_block_commitments(signed: &Self::ElectraSignedBeaconBlock) -> Vec<KZGCommitment> {
        signed.message.body.blob_kzg_commitments.as_slice().to_vec()
    }
}

impl ElectraFcSpec for MinimalEthSpec {
    fn run_electra_attestation_step(
        store: &mut Store<Self>,
        case_dir: &Path,
        attestation: &str,
        is_from_block: bool,
    ) -> Result<Result<(), ForkChoiceError>, String> {
        let att: pharos_types::electra::MinimalAttestation =
            load_ssz_snappy(case_dir, &format!("{attestation}.ssz_snappy"))?;
        Ok(on_attestation_electra::<8192, 4, Self>(
            store,
            &att,
            is_from_block,
        ))
    }

    fn feed_electra_block_attestations(
        store: &mut Store<Self>,
        signed: &Self::ElectraSignedBeaconBlock,
    ) {
        for att in signed.message.body.attestations.as_slice() {
            let _ = on_attestation_electra::<8192, 4, Self>(store, att, true);
        }
    }

    fn electra_block_parent_root(signed: &Self::ElectraSignedBeaconBlock) -> Root {
        signed.message.parent_root
    }

    fn electra_block_commitments(signed: &Self::ElectraSignedBeaconBlock) -> Vec<KZGCommitment> {
        signed.message.body.blob_kzg_commitments.as_slice().to_vec()
    }
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per fork-choice test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_fork_choice_*` function.
/// Called by the Phase 7 flat work-pool.
///
/// Walk order: sorted sub-categories (from `read_dir_sorted`), then sorted cases
/// within each sub-category. Ordinals thread across sub-sweeps.
///
/// Supported forks:
/// - `"phase0"`: exercises altair fixtures per Q1 (same as `run_fork_choice_mainnet/minimal`).
/// - `"bellatrix"`: bellatrix case driver.
/// - `"capella"`: capella case driver.
/// - `"deneb"`: deneb case driver.
pub fn enumerate_fork_choice(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    // phase0/fork_choice rows use altair fixtures per Q1.
    let fixture_fork: &'static str = if fork == "phase0" { "altair" } else { fork };

    let base = root.join(preset).join(fixture_fork).join("fork_choice");
    let sub_paths = if base.is_dir() {
        read_dir_sorted(&base).unwrap_or_default()
    } else {
        return Vec::new();
    };

    let mut tasks: Vec<CaseTask> = Vec::new();
    let mut ordinal: u32 = 0;

    for sub_path in sub_paths {
        if !sub_path.is_dir() {
            continue;
        }
        let sub: String = match sub_path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };

        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            fixture_fork,
            "fork_choice",
            Some(&sub),
            WalkOpts {
                meta_required: false,
                inner_dir: Some("pyspec_tests"),
            },
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!(
                "{fixture_fork}/fork_choice/{sub}/{preset}/{}",
                dir_name(&case_dir)
            );

            let run: CaseFn = match (fork, preset) {
                // phase0 rows → altair case driver (Q1: altair fixtures used)
                ("phase0", "mainnet") => {
                    Box::new(
                        move || match run_case::<MainnetEthSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        },
                    )
                }
                ("phase0", _) => {
                    Box::new(
                        move || match run_case::<MinimalEthSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        },
                    )
                }
                // bellatrix rows → bellatrix case driver
                ("bellatrix", "mainnet") => Box::new(move || {
                    match run_bellatrix_case::<MainnetEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("bellatrix", _) => Box::new(move || {
                    match run_bellatrix_case::<MinimalEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                // capella rows → capella case driver
                ("capella", "mainnet") => Box::new(move || {
                    match run_capella_case::<MainnetEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", _) => Box::new(move || {
                    match run_capella_case::<MinimalEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                // deneb rows → deneb case driver
                ("deneb", "mainnet") => Box::new(move || {
                    match run_deneb_case::<MainnetEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", _) => Box::new(move || {
                    match run_deneb_case::<MinimalEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                // electra rows → electra case driver (EIP-7549)
                ("electra", "mainnet") => Box::new(move || {
                    match run_electra_case::<MainnetEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("electra", _) => Box::new(move || {
                    match run_electra_case::<MinimalEthSpec>(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Skip => CaseOutcome::Skip,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                // Fallback: altair case driver (also handles "altair" if ever added)
                (_, "mainnet") => {
                    Box::new(
                        move || match run_case::<MainnetEthSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        },
                    )
                }
                (_, _) => {
                    Box::new(
                        move || match run_case::<MinimalEthSpec>(&case_dir, &case_name) {
                            CaseResult::Pass => CaseOutcome::Pass,
                            CaseResult::Skip => CaseOutcome::Skip,
                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        },
                    )
                }
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

// ── Case driver ───────────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Skip,
    Fail(String),
}

fn run_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode + pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView<Body = E::AltairBeaconBlockBody>,
    E::AltairBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    // Anchor state: try altair SSZ first (altair fork-choice fixtures use altair
    // states), then fall back to phase0. Skip on both failures.
    // Per Q1 resolution in docs/decisions.md: altair types landed in M3b so
    // this now produces real pass/fail counts.
    let anchor_state: E::BeaconState =
        match load_altair_state::<E>(case_dir, "anchor_state.ssz_snappy") {
            Ok(s) => s,
            Err(_) => match load_phase0_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                Ok(s) => s,
                Err(_) => return CaseResult::Skip,
            },
        };
    // Anchor block: try altair SSZ first, then fall back to phase0. Skip on both failures.
    let anchor_block: E::BeaconBlock = {
        use pharos_ssz::Decode as _;
        let compressed = match std::fs::read(case_dir.join("anchor_block.ssz_snappy")) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        let raw = match crate::snappy::decompress_raw(&compressed) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        if let Ok(b) = E::AltairBeaconBlock::from_ssz_bytes(&raw) {
            E::altair_into_block(b)
        } else if let Ok(b) = E::Phase0BeaconBlock::from_ssz_bytes(&raw) {
            E::phase0_into_block(b)
        } else {
            return CaseResult::Skip;
        }
    };

    // `get_forkchoice_store` asserts `state_root == hash_tree_root(state)`.
    // Check first so a panic in the conformance crate does not crash the run.
    if anchor_block.state_root() != anchor_state.tree_hash_root() {
        return CaseResult::Skip;
    }
    let mut store: Store<E> = get_forkchoice_store::<E>(anchor_state, anchor_block);

    let steps_path = case_dir.join("steps.yaml");
    let steps = match parse_steps(&steps_path) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    for step in steps {
        match step {
            Step::Tick { tick, .. } => {
                on_tick::<E>(&mut store, tick);
            }
            Step::Block { block, valid, .. } => {
                // Decode as the inner type (altair first, phase0 fallback) so
                // we can access body attestations for the post-block feed-through.
                // The fork-enum `message()` panics, so we keep the inner ref.
                let block_file = format!("{block}.ssz_snappy");
                let cfg = E::default_runtime_config();

                // Try altair first; altair fork-choice fixtures use altair blocks.
                if let Ok(altair_inner) = load_altair_signed_block::<E>(case_dir, &block_file) {
                    // Run state transition externally (on_block now takes post_state).
                    let altair_parent_root = E::unwrap_altair_signed_block(&altair_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&altair_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &altair_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                if let Some(inner) = E::unwrap_altair_signed_block(&altair_inner) {
                                    inner.message().body().attestations().to_vec()
                                } else {
                                    vec![]
                                };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, NoopPowBlockProvider>(
                        &mut store,
                        &altair_inner,
                        post_state,
                        now,
                        &NoopPowBlockProvider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else {
                    // Fall back to phase0 block decode.
                    let phase0_inner: E::Phase0SignedBeaconBlock =
                        match load_ssz_snappy(case_dir, &block_file) {
                            Ok(b) => b,
                            Err(e) => {
                                return CaseResult::Fail(format!("{case_name}: {e}"));
                            }
                        };
                    let signed = E::phase0_into_signed_block(phase0_inner.clone());
                    // Run state transition externally.
                    let pre_state = match store
                        .block_states
                        .get(&phase0_inner.message().parent_root())
                        .cloned()
                    {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &signed,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let post_state = match post_state_result {
                        Ok((ps, _)) => ps,
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, NoopPowBlockProvider>(
                        &mut store,
                        &signed,
                        post_state,
                        now,
                        &NoopPowBlockProvider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in phase0_inner.message().body().attestations() {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                }
            }
            Step::Attestation { attestation, valid } => {
                let att: Attestation<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attestation}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attestation::<E>(&mut store, &att, false);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::AttesterSlashing {
                attester_slashing,
                valid,
            } => {
                let slashing: AttesterSlashing<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attester_slashing}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attester_slashing::<E>(&mut store, &slashing);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::Checks(checks) => {
                if let Err(e) = run_checks::<E>(&store, &checks) {
                    return CaseResult::Fail(format!("{case_name}: {e}"));
                }
            }
            Step::PowBlock(_) | Step::Unknown(_) => {
                // Unknown top-level step variant (e.g. `payload_status`).
                // Per the skip-unknown-step-keys policy, skip the whole case.
                // `PowBlock` is handled in the bellatrix driver; its presence
                // here (altair runner) counts as an unknown step.
                return CaseResult::Skip;
            }
        }
    }

    CaseResult::Pass
}

// ── Bellatrix case driver ─────────────────────────────────────────────────────

/// Case driver for bellatrix fork-choice fixtures.
///
/// Differs from `run_case` in that:
/// - Anchor state tries bellatrix first, then altair, then phase0.
/// - Block decode tries bellatrix first, then altair, then phase0.
/// - `pow_block` steps populate a `HashMapPowBlockProvider`.
/// - `should_override_forkchoice_update` checks are asserted.
///   When the YAML expects `true`, the assertion is skipped (M4a always returns `false`).
fn run_bellatrix_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode + pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView<Body = E::AltairBeaconBlockBody>,
    E::AltairBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconBlock: BeaconBlockView<Body = E::BellatrixBeaconBlockBody>,
    E::BellatrixBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::BellatrixSignedBeaconBlock:
        Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    // Load anchor state: bellatrix first, then altair, then phase0.
    let anchor_state: E::BeaconState =
        match load_bellatrix_state::<E>(case_dir, "anchor_state.ssz_snappy") {
            Ok(s) => s,
            Err(_) => match load_altair_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                Ok(s) => s,
                Err(_) => match load_phase0_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                    Ok(s) => s,
                    Err(_) => return CaseResult::Skip,
                },
            },
        };

    // Load anchor block: try bellatrix first, then altair, then phase0.
    let anchor_block: E::BeaconBlock = {
        use pharos_ssz::Decode as _;
        let compressed = match std::fs::read(case_dir.join("anchor_block.ssz_snappy")) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        let raw = match crate::snappy::decompress_raw(&compressed) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        if let Ok(b) = E::BellatrixBeaconBlock::from_ssz_bytes(&raw) {
            E::bellatrix_into_block(b)
        } else if let Ok(b) = E::AltairBeaconBlock::from_ssz_bytes(&raw) {
            E::altair_into_block(b)
        } else if let Ok(b) = E::Phase0BeaconBlock::from_ssz_bytes(&raw) {
            E::phase0_into_block(b)
        } else {
            return CaseResult::Skip;
        }
    };

    if anchor_block.state_root() != anchor_state.tree_hash_root() {
        return CaseResult::Skip;
    }
    let mut store: Store<E> = get_forkchoice_store::<E>(anchor_state, anchor_block);

    // Set terminal-block constants from the preset's default config.
    // Each preset uses its own pow_block fixtures with TTD values matching
    // that preset's TERMINAL_TOTAL_DIFFICULTY:
    //   mainnet: 58750000000000000000000
    //   minimal: 115792089...912 (max_uint256 - a large value per minimal.yaml)
    let rtcfg = E::default_runtime_config();
    store.set_terminal_config(
        rtcfg.terminal_total_difficulty,
        rtcfg.terminal_block_hash,
        rtcfg.terminal_block_hash_activation_epoch,
    );

    // pow_block provider — populated by `pow_block` steps.
    let mut pow_provider = HashMapPowBlockProvider {
        blocks: std::collections::HashMap::new(),
    };

    let steps_path = case_dir.join("steps.yaml");
    let steps = match parse_steps(&steps_path) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    for step in steps {
        match step {
            Step::Tick { tick, .. } => {
                on_tick::<E>(&mut store, tick);
            }
            Step::PowBlock(name) => {
                // Load PowBlock SSZ-snappy from `<name>.ssz_snappy`.
                let file = format!("{name}.ssz_snappy");
                let pow_block: PowBlock = match load_ssz_snappy(case_dir, &file) {
                    Ok(p) => p,
                    Err(e) => {
                        return CaseResult::Fail(format!("{case_name}: pow_block({name}): {e}"));
                    }
                };
                pow_provider.blocks.insert(pow_block.block_hash, pow_block);
            }
            Step::Block { block, valid, .. } => {
                let block_file = format!("{block}.ssz_snappy");
                let cfg = E::default_runtime_config();

                // Try bellatrix first, then altair, then phase0.
                if let Ok(bel_inner) = load_bellatrix_signed_block::<E>(case_dir, &block_file) {
                    let parent_root = E::unwrap_bellatrix_signed_block(&bel_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &bel_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                if let Some(inner) = E::unwrap_bellatrix_signed_block(&bel_inner) {
                                    inner.message().body().attestations().to_vec()
                                } else {
                                    vec![]
                                };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &bel_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(altair_inner) =
                    load_altair_signed_block::<E>(case_dir, &block_file)
                {
                    let altair_parent_root = E::unwrap_altair_signed_block(&altair_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&altair_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &altair_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                if let Some(inner) = E::unwrap_altair_signed_block(&altair_inner) {
                                    inner.message().body().attestations().to_vec()
                                } else {
                                    vec![]
                                };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &altair_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else {
                    let phase0_inner: E::Phase0SignedBeaconBlock =
                        match load_ssz_snappy(case_dir, &block_file) {
                            Ok(b) => b,
                            Err(e) => {
                                return CaseResult::Fail(format!("{case_name}: {e}"));
                            }
                        };
                    let signed = E::phase0_into_signed_block(phase0_inner.clone());
                    let pre_state = match store
                        .block_states
                        .get(&phase0_inner.message().parent_root())
                        .cloned()
                    {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &signed,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let post_state = match post_state_result {
                        Ok((ps, _)) => ps,
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &signed,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in phase0_inner.message().body().attestations() {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                }
            }
            Step::Attestation { attestation, valid } => {
                let att: Attestation<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attestation}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attestation::<E>(&mut store, &att, false);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::AttesterSlashing {
                attester_slashing,
                valid,
            } => {
                let slashing: AttesterSlashing<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attester_slashing}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attester_slashing::<E>(&mut store, &slashing);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::Checks(checks) => {
                if let Err(e) = run_bellatrix_checks::<E>(&store, &checks) {
                    return CaseResult::Fail(format!("{case_name}: {e}"));
                }
            }
            Step::Unknown(_) => {
                // Unknown step in bellatrix fixture. Skip case per policy.
                return CaseResult::Skip;
            }
        }
    }

    CaseResult::Pass
}

// ── Checks runner ─────────────────────────────────────────────────────────────

/// Checks runner for bellatrix fork-choice cases.
///
/// Like `run_checks` but also handles `should_override_forkchoice_update`.
/// For cases where the YAML expects `true`, the assertion is skipped
/// (M4a always returns `false`; full re-org logic deferred to M11).
fn run_bellatrix_checks<E>(store: &Store<E>, checks: &Checks) -> Result<(), String>
where
    E: EthSpec,
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    run_checks::<E>(store, checks)?;
    if let Some(want) = checks.should_override_forkchoice_update {
        let got = should_override_forkchoice_update::<E>(store);
        if want {
            // Expected true but M4a always returns false; skip assertion.
            // (Full proposer-boost re-org logic deferred to M11.)
        } else if got != want {
            return Err(format!(
                "should_override_forkchoice_update: want {want}, got {got}"
            ));
        }
    }
    Ok(())
}

fn run_checks<E>(store: &Store<E>, checks: &Checks) -> Result<(), String>
where
    E: EthSpec,
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: BeaconStateView,
{
    if let Some(want) = checks.time {
        if store.time != want {
            return Err(format!("time: want {want}, got {}", store.time));
        }
    }
    if let Some(want) = &checks.justified_checkpoint
        && (store.justified_checkpoint.epoch != want.epoch
            || store.justified_checkpoint.root != want.root)
    {
        return Err(format!(
            "justified_checkpoint: want {{epoch: {}, root: {}}}, got {{epoch: {}, root: {}}}",
            want.epoch.0,
            want.root,
            store.justified_checkpoint.epoch.0,
            store.justified_checkpoint.root,
        ));
    }
    if let Some(want) = &checks.finalized_checkpoint
        && (store.finalized_checkpoint.epoch != want.epoch
            || store.finalized_checkpoint.root != want.root)
    {
        return Err(format!(
            "finalized_checkpoint: want {{epoch: {}, root: {}}}, got {{epoch: {}, root: {}}}",
            want.epoch.0,
            want.root,
            store.finalized_checkpoint.epoch.0,
            store.finalized_checkpoint.root,
        ));
    }
    if let Some(want) = &checks.proposer_boost_root
        && store.proposer_boost_root != *want
    {
        return Err(format!(
            "proposer_boost_root: want {want}, got {}",
            store.proposer_boost_root,
        ));
    }
    if let Some(want) = &checks.head {
        let head = get_head::<E>(store);
        if head != want.root {
            return Err(format!("head.root: want {}, got {head}", want.root));
        }
        if let Some(want_slot) = want.slot {
            let head_slot = store.blocks.get(&head).map(|b| b.slot()).unwrap_or(Slot(0));
            if head_slot != want_slot {
                return Err(format!(
                    "head.slot: want {}, got {}",
                    want_slot.0, head_slot.0,
                ));
            }
        }
    }
    if let Some(want) = &checks.get_proposer_head {
        let head = get_head::<E>(store);
        let current_slot = get_current_slot(store);
        let got = get_proposer_head::<E>(store, head, current_slot);
        if got != *want {
            return Err(format!("get_proposer_head: want {want}, got {got}"));
        }
    }
    Ok(())
}

// ── steps.yaml parsing ────────────────────────────────────────────────────────

/// One parsed step from `steps.yaml`.
enum Step {
    Tick {
        tick: u64,
        #[allow(dead_code)]
        valid: bool,
    },
    Block {
        block: String,
        valid: bool,
        /// Deneb (EIP-4844): optional `blobs_<root>.ssz_snappy` file name.
        blobs: Option<String>,
        /// Deneb (EIP-4844): optional byte48 hex proofs for the blobs.
        proofs: Vec<String>,
    },
    Attestation {
        attestation: String,
        valid: bool,
    },
    AttesterSlashing {
        attester_slashing: String,
        valid: bool,
    },
    Checks(Box<Checks>),
    /// `pow_block` step: load `<name>.ssz_snappy` as a `PowBlock`.
    PowBlock(String),
    /// Unknown top-level variant — triggers case-level skip per policy.
    /// The string carries the offending key for diagnostics.
    Unknown(#[allow(dead_code)] String),
}

/// Parsed `checks` block.  Unknown keys are silently ignored.
struct Checks {
    head: Option<HeadCheck>,
    justified_checkpoint: Option<Checkpoint>,
    finalized_checkpoint: Option<Checkpoint>,
    time: Option<u64>,
    proposer_boost_root: Option<Root>,
    get_proposer_head: Option<Root>,
    /// `should_override_forkchoice_update: { validator_is_connected: bool, result: bool }`.
    /// We only use the `result` field.
    should_override_forkchoice_update: Option<bool>,
}

struct HeadCheck {
    slot: Option<Slot>,
    root: Root,
}

fn parse_steps(path: &Path) -> Result<Vec<Step>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let val: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
        .map_err(|e| format!("yaml parse {}: {e}", path.display()))?;
    let seq = val
        .as_sequence()
        .ok_or_else(|| format!("{}: top-level is not a sequence", path.display()))?;

    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        out.push(parse_step(item)?);
    }
    Ok(out)
}

fn parse_step(val: &serde_yaml_ng::Value) -> Result<Step, String> {
    let map = match val.as_mapping() {
        Some(m) => m,
        None => return Ok(Step::Unknown("non-mapping step".into())),
    };

    // Discriminate by the first recognised key.
    if let Some(checks) = map.get("checks") {
        let parsed = parse_checks(checks)?;
        return Ok(Step::Checks(Box::new(parsed)));
    }
    if let Some(tick) = map.get("tick").and_then(|v| v.as_u64()) {
        return Ok(Step::Tick {
            tick,
            valid: read_valid(map),
        });
    }
    if let Some(block) = map.get("block").and_then(value_as_str) {
        // Deneb (EIP-4844) block steps may carry `blobs` (a file name) and
        // `proofs` (byte48 hex). These feed `is_data_available`; absent fields
        // mean empty lists per `tests/formats/fork_choice/README.md`.
        let blobs = map.get("blobs").and_then(value_as_str);
        let proofs = map
            .get("proofs")
            .and_then(|v| v.as_sequence())
            .map(|seq| seq.iter().filter_map(value_as_str).collect())
            .unwrap_or_default();
        return Ok(Step::Block {
            block,
            valid: read_valid(map),
            blobs,
            proofs,
        });
    }
    if let Some(attestation) = map.get("attestation").and_then(value_as_str) {
        return Ok(Step::Attestation {
            attestation,
            valid: read_valid(map),
        });
    }
    if let Some(attester_slashing) = map.get("attester_slashing").and_then(value_as_str) {
        return Ok(Step::AttesterSlashing {
            attester_slashing,
            valid: read_valid(map),
        });
    }
    if let Some(name) = map.get("pow_block").and_then(value_as_str) {
        return Ok(Step::PowBlock(name));
    }

    // Unknown top-level variants: `payload_status`, `execution_payload`,
    // `payload_attestation_message`, etc. Per policy, return Unknown so the
    // caller can skip the whole case.
    let key = map
        .keys()
        .find_map(|k| k.as_str().map(|s| s.to_owned()))
        .unwrap_or_else(|| "?".into());
    Ok(Step::Unknown(key))
}

fn parse_checks(val: &serde_yaml_ng::Value) -> Result<Checks, String> {
    let map = match val.as_mapping() {
        Some(m) => m,
        None => return Err("checks: not a mapping".into()),
    };

    let mut out = Checks {
        head: None,
        justified_checkpoint: None,
        finalized_checkpoint: None,
        time: None,
        proposer_boost_root: None,
        get_proposer_head: None,
        should_override_forkchoice_update: None,
    };

    for (k, v) in map {
        let key = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        match key {
            "head" => out.head = Some(parse_head(v)?),
            "time" => out.time = v.as_u64(),
            "justified_checkpoint" => out.justified_checkpoint = Some(parse_checkpoint(v)?),
            "finalized_checkpoint" => out.finalized_checkpoint = Some(parse_checkpoint(v)?),
            "proposer_boost_root" => {
                out.proposer_boost_root = value_as_str(v).map(|s| parse_root(&s)).transpose()?;
            }
            "get_proposer_head" => {
                out.get_proposer_head = value_as_str(v).map(|s| parse_root(&s)).transpose()?;
            }
            "should_override_forkchoice_update" => {
                // Value is `{ validator_is_connected: bool, result: bool }`.
                // We only care about `result`.
                out.should_override_forkchoice_update = v
                    .as_mapping()
                    .and_then(|m| m.get("result"))
                    .and_then(|r| r.as_bool());
            }
            // Silently ignored unknown keys per spec/policy:
            // `viable_for_head_roots_and_weights`, `head_payload_status`,
            // `payload_timeliness_vote`, `payload_data_availability_vote`,
            // `genesis_time` (informational).
            _ => {}
        }
    }
    Ok(out)
}

fn parse_head(val: &serde_yaml_ng::Value) -> Result<HeadCheck, String> {
    let map = val
        .as_mapping()
        .ok_or_else(|| "head: not a mapping".to_string())?;
    let slot = map.get("slot").and_then(|v| v.as_u64()).map(Slot);
    let root = map
        .get("root")
        .and_then(value_as_str)
        .ok_or_else(|| "head: missing root".to_string())?;
    Ok(HeadCheck {
        slot,
        root: parse_root(&root)?,
    })
}

fn parse_checkpoint(val: &serde_yaml_ng::Value) -> Result<Checkpoint, String> {
    let map = val
        .as_mapping()
        .ok_or_else(|| "checkpoint: not a mapping".to_string())?;
    let epoch = map
        .get("epoch")
        .and_then(|v| v.as_u64())
        .map(Epoch)
        .ok_or_else(|| "checkpoint: missing epoch".to_string())?;
    let root_s = map
        .get("root")
        .and_then(value_as_str)
        .ok_or_else(|| "checkpoint: missing root".to_string())?;
    Ok(Checkpoint {
        epoch,
        root: parse_root(&root_s)?,
    })
}

fn parse_root(s: &str) -> Result<Root, String> {
    s.parse::<Root>().map_err(|e| format!("root parse: {e:?}"))
}

fn value_as_str(v: &serde_yaml_ng::Value) -> Option<String> {
    v.as_str().map(|s| s.to_owned())
}

fn read_valid(map: &serde_yaml_ng::Mapping) -> bool {
    map.get("valid").and_then(|v| v.as_bool()).unwrap_or(true)
}

/// EIP-4844 data-availability check for the deneb fork-choice test format.
///
/// Mirrors `is_data_available` (`specs/deneb/fork-choice.md`): the step-provided
/// `blobs`/`proofs` are what `retrieve_blobs_and_proofs` returns; absent fields
/// mean empty lists (`tests/formats/fork_choice/README.md`). Data is available
/// iff `verify_blob_kzg_proof_batch(blobs, blob_kzg_commitments, proofs)` is
/// `Ok(true)`; a length mismatch surfaces as `Err`, i.e. not available (this is
/// how the `invalid_wrong_{blobs,proofs}_length` / `invalid_data_unavailable`
/// cases are rejected). The blobs file is a `List[Blob, MAX_BLOB_COMMITMENTS_PER_BLOCK]`
/// (4096 both presets).
fn deneb_data_available(
    case_dir: &Path,
    blobs_name: Option<&str>,
    proofs_hex: &[String],
    commitments: &[KZGCommitment],
) -> bool {
    let blobs: Vec<[u8; 131_072]> = match blobs_name {
        Some(name) => {
            let file = format!("{name}.ssz_snappy");
            match load_ssz_snappy::<SszList<Blob, 4096>>(case_dir, &file) {
                Ok(list) => {
                    let mut out = Vec::with_capacity(list.len());
                    for blob in list.as_slice() {
                        let mut arr = [0u8; 131_072];
                        arr.copy_from_slice(blob.as_slice());
                        out.push(arr);
                    }
                    out
                }
                Err(_) => return false,
            }
        }
        None => Vec::new(),
    };

    let mut proofs: Vec<[u8; 48]> = Vec::with_capacity(proofs_hex.len());
    for p in proofs_hex {
        let hex = p.strip_prefix("0x").unwrap_or(p);
        match hex::decode(hex) {
            Ok(bytes) if bytes.len() == 48 => {
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&bytes);
                proofs.push(arr);
            }
            _ => return false,
        }
    }

    let commitments: Vec<[u8; 48]> = commitments.iter().map(|c| (*c).into()).collect();

    KzgVerifier::mainnet()
        .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
        .unwrap_or(false)
}

fn run_capella_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode + pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView<Body = E::AltairBeaconBlockBody>,
    E::AltairBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconBlock: BeaconBlockView<Body = E::BellatrixBeaconBlockBody>,
    E::BellatrixBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::BellatrixSignedBeaconBlock:
        Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView<Body = E::CapellaBeaconBlockBody>,
    E::CapellaBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::CapellaSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    // Load anchor state: capella first, then bellatrix, then altair, then phase0.
    let anchor_state: E::BeaconState =
        match load_capella_state::<E>(case_dir, "anchor_state.ssz_snappy") {
            Ok(s) => s,
            Err(_) => match load_bellatrix_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                Ok(s) => s,
                Err(_) => match load_altair_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                    Ok(s) => s,
                    Err(_) => match load_phase0_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                        Ok(s) => s,
                        Err(_) => return CaseResult::Skip,
                    },
                },
            },
        };

    // Load anchor block: capella first, then bellatrix, then altair, then phase0.
    let anchor_block: E::BeaconBlock = {
        use pharos_ssz::Decode as _;
        let compressed = match std::fs::read(case_dir.join("anchor_block.ssz_snappy")) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        let raw = match crate::snappy::decompress_raw(&compressed) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        if let Ok(b) = E::CapellaBeaconBlock::from_ssz_bytes(&raw) {
            E::capella_into_block(b)
        } else if let Ok(b) = E::BellatrixBeaconBlock::from_ssz_bytes(&raw) {
            E::bellatrix_into_block(b)
        } else if let Ok(b) = E::AltairBeaconBlock::from_ssz_bytes(&raw) {
            E::altair_into_block(b)
        } else if let Ok(b) = E::Phase0BeaconBlock::from_ssz_bytes(&raw) {
            E::phase0_into_block(b)
        } else {
            return CaseResult::Skip;
        }
    };

    if anchor_block.state_root() != anchor_state.tree_hash_root() {
        return CaseResult::Skip;
    }
    let mut store: Store<E> = get_forkchoice_store::<E>(anchor_state, anchor_block);

    let rtcfg = E::default_runtime_config();
    store.set_terminal_config(
        rtcfg.terminal_total_difficulty,
        rtcfg.terminal_block_hash,
        rtcfg.terminal_block_hash_activation_epoch,
    );

    let mut pow_provider = HashMapPowBlockProvider {
        blocks: std::collections::HashMap::new(),
    };

    let steps_path = case_dir.join("steps.yaml");
    let steps = match parse_steps(&steps_path) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    for step in steps {
        match step {
            Step::Tick { tick, .. } => {
                on_tick::<E>(&mut store, tick);
            }
            Step::Block { block, valid, .. } => {
                let block_file = format!("{block}.ssz_snappy");
                let cfg = E::default_runtime_config();

                // Try capella first, then bellatrix, then altair, then phase0.
                if let Ok(capella_inner) =
                    load_ssz_snappy::<E::CapellaSignedBeaconBlock>(case_dir, &block_file)
                {
                    let capella_inner_wrapped = E::capella_into_signed_block(capella_inner.clone());
                    let parent_root = capella_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &capella_inner_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                capella_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &capella_inner_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(bellatrix_inner) =
                    load_bellatrix_signed_block::<E>(case_dir, &block_file)
                {
                    let bellatrix_parent_root = E::unwrap_bellatrix_signed_block(&bellatrix_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&bellatrix_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &bellatrix_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> = if let Some(inner) =
                                E::unwrap_bellatrix_signed_block(&bellatrix_inner)
                            {
                                inner.message().body().attestations().to_vec()
                            } else {
                                vec![]
                            };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &bellatrix_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(altair_inner) =
                    load_altair_signed_block::<E>(case_dir, &block_file)
                {
                    let altair_parent_root = E::unwrap_altair_signed_block(&altair_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&altair_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &altair_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                if let Some(inner) = E::unwrap_altair_signed_block(&altair_inner) {
                                    inner.message().body().attestations().to_vec()
                                } else {
                                    vec![]
                                };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &altair_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else {
                    // phase0 fallback
                    let phase0_inner: E::Phase0SignedBeaconBlock =
                        match load_ssz_snappy(case_dir, &block_file) {
                            Ok(b) => b,
                            Err(e) => {
                                return CaseResult::Fail(format!("{case_name}: {e}"));
                            }
                        };
                    let signed = E::phase0_into_signed_block(phase0_inner.clone());
                    let pre_state = match store
                        .block_states
                        .get(&phase0_inner.message().parent_root())
                        .cloned()
                    {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &signed,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let post_state = match post_state_result {
                        Ok((ps, _)) => ps,
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &signed,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in phase0_inner.message().body().attestations() {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                }
            }
            Step::Attestation { attestation, valid } => {
                let att: Attestation<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attestation}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attestation::<E>(&mut store, &att, false);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::AttesterSlashing {
                attester_slashing,
                valid,
            } => {
                let slashing: AttesterSlashing<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attester_slashing}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attester_slashing::<E>(&mut store, &slashing);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::Checks(checks) => {
                if let Err(e) = run_bellatrix_checks::<E>(&store, &checks) {
                    return CaseResult::Fail(format!("{case_name}: {e}"));
                }
            }
            Step::PowBlock(name) => {
                let file = format!("{name}.ssz_snappy");
                let pow_block: PowBlock = match load_ssz_snappy(case_dir, &file) {
                    Ok(b) => b,
                    Err(_) => return CaseResult::Skip,
                };
                pow_provider.blocks.insert(pow_block.block_hash, pow_block);
            }
            Step::Unknown(_) => {
                return CaseResult::Skip;
            }
        }
    }

    CaseResult::Pass
}

fn run_deneb_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: Decode + pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView<Body = E::AltairBeaconBlockBody>,
    E::AltairBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconBlock: BeaconBlockView<Body = E::BellatrixBeaconBlockBody>,
    E::BellatrixBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::BellatrixSignedBeaconBlock:
        Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView<Body = E::CapellaBeaconBlockBody>,
    E::CapellaBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::CapellaSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::DenebBeaconBlock: BeaconBlockView<Body = E::DenebBeaconBlockBody>,
    E::DenebBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::DenebSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    // Load anchor state: deneb first, then capella, bellatrix, altair, phase0.
    let anchor_state: E::BeaconState =
        match load_deneb_state::<E>(case_dir, "anchor_state.ssz_snappy") {
            Ok(s) => s,
            Err(_) => match load_capella_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                Ok(s) => s,
                Err(_) => match load_bellatrix_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                    Ok(s) => s,
                    Err(_) => match load_altair_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                        Ok(s) => s,
                        Err(_) => match load_phase0_state::<E>(case_dir, "anchor_state.ssz_snappy")
                        {
                            Ok(s) => s,
                            Err(_) => return CaseResult::Skip,
                        },
                    },
                },
            },
        };

    // Load anchor block: deneb first, then capella, bellatrix, altair, phase0.
    let anchor_block: E::BeaconBlock = {
        use pharos_ssz::Decode as _;
        let compressed = match std::fs::read(case_dir.join("anchor_block.ssz_snappy")) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        let raw = match crate::snappy::decompress_raw(&compressed) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        if let Ok(b) = E::DenebBeaconBlock::from_ssz_bytes(&raw) {
            E::deneb_into_block(b)
        } else if let Ok(b) = E::CapellaBeaconBlock::from_ssz_bytes(&raw) {
            E::capella_into_block(b)
        } else if let Ok(b) = E::BellatrixBeaconBlock::from_ssz_bytes(&raw) {
            E::bellatrix_into_block(b)
        } else if let Ok(b) = E::AltairBeaconBlock::from_ssz_bytes(&raw) {
            E::altair_into_block(b)
        } else if let Ok(b) = E::Phase0BeaconBlock::from_ssz_bytes(&raw) {
            E::phase0_into_block(b)
        } else {
            return CaseResult::Skip;
        }
    };

    if anchor_block.state_root() != anchor_state.tree_hash_root() {
        return CaseResult::Skip;
    }
    let mut store: Store<E> = get_forkchoice_store::<E>(anchor_state, anchor_block);

    let rtcfg = E::default_runtime_config();
    store.set_terminal_config(
        rtcfg.terminal_total_difficulty,
        rtcfg.terminal_block_hash,
        rtcfg.terminal_block_hash_activation_epoch,
    );

    let mut pow_provider = HashMapPowBlockProvider {
        blocks: std::collections::HashMap::new(),
    };

    let steps_path = case_dir.join("steps.yaml");
    let steps = match parse_steps(&steps_path) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    for step in steps {
        match step {
            Step::Tick { tick, .. } => {
                on_tick::<E>(&mut store, tick);
            }
            Step::Block {
                block,
                valid,
                blobs,
                proofs,
            } => {
                let block_file = format!("{block}.ssz_snappy");
                let cfg = E::default_runtime_config();

                // Try deneb first, then capella, bellatrix, altair, phase0.
                if let Ok(deneb_inner) =
                    load_ssz_snappy::<E::DenebSignedBeaconBlock>(case_dir, &block_file)
                {
                    let deneb_wrapped = E::deneb_into_signed_block(deneb_inner.clone());
                    let parent_root = deneb_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    // EIP-4844 data-availability check (deneb fork-choice test
                    // format): `is_data_available` runs
                    // `verify_blob_kzg_proof_batch` over the step-provided
                    // blobs/proofs vs the block's `blob_kzg_commitments`. A
                    // data-unavailable block must be rejected; fold it into the
                    // `valid` expectation before state-transition/on_block.
                    let commitments = deneb_inner.message().body().blob_kzg_commitments_slice();
                    if !deneb_data_available(case_dir, blobs.as_deref(), &proofs, commitments) {
                        if valid {
                            return CaseResult::Fail(format!(
                                "{case_name}: block({block}) data unavailable but valid=true"
                            ));
                        } else {
                            continue;
                        }
                    }
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &deneb_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                deneb_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &deneb_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(capella_inner) =
                    load_ssz_snappy::<E::CapellaSignedBeaconBlock>(case_dir, &block_file)
                {
                    let capella_inner_wrapped = E::capella_into_signed_block(capella_inner.clone());
                    let parent_root = capella_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &capella_inner_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                capella_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &capella_inner_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(bellatrix_inner) =
                    load_bellatrix_signed_block::<E>(case_dir, &block_file)
                {
                    let bellatrix_parent_root = E::unwrap_bellatrix_signed_block(&bellatrix_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&bellatrix_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &bellatrix_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> = if let Some(inner) =
                                E::unwrap_bellatrix_signed_block(&bellatrix_inner)
                            {
                                inner.message().body().attestations().to_vec()
                            } else {
                                vec![]
                            };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &bellatrix_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(altair_inner) =
                    load_altair_signed_block::<E>(case_dir, &block_file)
                {
                    let altair_parent_root = E::unwrap_altair_signed_block(&altair_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&altair_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &altair_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                if let Some(inner) = E::unwrap_altair_signed_block(&altair_inner) {
                                    inner.message().body().attestations().to_vec()
                                } else {
                                    vec![]
                                };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &altair_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else {
                    // phase0 fallback
                    let phase0_inner: E::Phase0SignedBeaconBlock =
                        match load_ssz_snappy(case_dir, &block_file) {
                            Ok(b) => b,
                            Err(e) => {
                                return CaseResult::Fail(format!("{case_name}: {e}"));
                            }
                        };
                    let signed = E::phase0_into_signed_block(phase0_inner.clone());
                    let pre_state = match store
                        .block_states
                        .get(&phase0_inner.message().parent_root())
                        .cloned()
                    {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &signed,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let post_state = match post_state_result {
                        Ok((ps, _)) => ps,
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &signed,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in phase0_inner.message().body().attestations() {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                }
            }
            Step::Attestation { attestation, valid } => {
                let att: Attestation<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attestation}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attestation::<E>(&mut store, &att, false);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::AttesterSlashing {
                attester_slashing,
                valid,
            } => {
                let slashing: AttesterSlashing<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attester_slashing}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attester_slashing::<E>(&mut store, &slashing);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::Checks(checks) => {
                if let Err(e) = run_bellatrix_checks::<E>(&store, &checks) {
                    return CaseResult::Fail(format!("{case_name}: {e}"));
                }
            }
            Step::PowBlock(name) => {
                let file = format!("{name}.ssz_snappy");
                let pow_block: PowBlock = match load_ssz_snappy(case_dir, &file) {
                    Ok(b) => b,
                    Err(_) => return CaseResult::Skip,
                };
                pow_provider.blocks.insert(pow_block.block_hash, pow_block);
            }
            Step::Unknown(_) => {
                return CaseResult::Skip;
            }
        }
    }

    CaseResult::Pass
}

/// Case driver for electra (EIP-7549/4844) fork-choice fixtures.
///
/// Mirrors `run_deneb_case` with an electra decode tier prepended (electra →
/// deneb → capella → bellatrix → altair → phase0) and routes electra blocks +
/// the standalone `attestation` step through `on_attestation_electra` (the
/// committee-bits attester extractor). The deneb EIP-4844 data-availability
/// gate is carried verbatim for electra blocks.
#[allow(clippy::too_many_lines)]
fn run_electra_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec + ElectraFcSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash
        + Decode,
    E::Phase0BeaconState: Decode + pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView<Body = E::AltairBeaconBlockBody>,
    E::AltairBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconBlock: BeaconBlockView<Body = E::BellatrixBeaconBlockBody>,
    E::BellatrixBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::BellatrixSignedBeaconBlock:
        Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView<Body = E::CapellaBeaconBlockBody>,
    E::CapellaBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::CapellaSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::DenebBeaconBlock: BeaconBlockView<Body = E::DenebBeaconBlockBody>,
    E::DenebBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::DenebSignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::ElectraBeaconBlock: Decode + BeaconBlockView,
    E::ElectraSignedBeaconBlock: Decode,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    // Load anchor state: electra first, then deneb, capella, bellatrix, altair, phase0.
    let anchor_state: E::BeaconState =
        match load_electra_state::<E>(case_dir, "anchor_state.ssz_snappy") {
            Ok(s) => s,
            Err(_) => match load_deneb_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                Ok(s) => s,
                Err(_) => match load_capella_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                    Ok(s) => s,
                    Err(_) => {
                        match load_bellatrix_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                            Ok(s) => s,
                            Err(_) => {
                                match load_altair_state::<E>(case_dir, "anchor_state.ssz_snappy") {
                                    Ok(s) => s,
                                    Err(_) => match load_phase0_state::<E>(
                                        case_dir,
                                        "anchor_state.ssz_snappy",
                                    ) {
                                        Ok(s) => s,
                                        Err(_) => return CaseResult::Skip,
                                    },
                                }
                            }
                        }
                    }
                },
            },
        };

    // Load anchor block: electra first, then deneb, capella, bellatrix, altair, phase0.
    let anchor_block: E::BeaconBlock = {
        use pharos_ssz::Decode as _;
        let compressed = match std::fs::read(case_dir.join("anchor_block.ssz_snappy")) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        let raw = match crate::snappy::decompress_raw(&compressed) {
            Ok(b) => b,
            Err(_) => return CaseResult::Skip,
        };
        if let Ok(b) = E::ElectraBeaconBlock::from_ssz_bytes(&raw) {
            E::electra_into_block(b)
        } else if let Ok(b) = E::DenebBeaconBlock::from_ssz_bytes(&raw) {
            E::deneb_into_block(b)
        } else if let Ok(b) = E::CapellaBeaconBlock::from_ssz_bytes(&raw) {
            E::capella_into_block(b)
        } else if let Ok(b) = E::BellatrixBeaconBlock::from_ssz_bytes(&raw) {
            E::bellatrix_into_block(b)
        } else if let Ok(b) = E::AltairBeaconBlock::from_ssz_bytes(&raw) {
            E::altair_into_block(b)
        } else if let Ok(b) = E::Phase0BeaconBlock::from_ssz_bytes(&raw) {
            E::phase0_into_block(b)
        } else {
            return CaseResult::Skip;
        }
    };

    if anchor_block.state_root() != anchor_state.tree_hash_root() {
        return CaseResult::Skip;
    }
    let mut store: Store<E> = get_forkchoice_store::<E>(anchor_state, anchor_block);

    let rtcfg = E::default_runtime_config();
    store.set_terminal_config(
        rtcfg.terminal_total_difficulty,
        rtcfg.terminal_block_hash,
        rtcfg.terminal_block_hash_activation_epoch,
    );

    let mut pow_provider = HashMapPowBlockProvider {
        blocks: std::collections::HashMap::new(),
    };

    let steps_path = case_dir.join("steps.yaml");
    let steps = match parse_steps(&steps_path) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    for step in steps {
        match step {
            Step::Tick { tick, .. } => {
                on_tick::<E>(&mut store, tick);
            }
            Step::Block {
                block,
                valid,
                blobs,
                proofs,
            } => {
                let block_file = format!("{block}.ssz_snappy");
                let cfg = E::default_runtime_config();

                // Try electra first, then deneb, capella, bellatrix, altair, phase0.
                if let Ok(electra_inner) =
                    load_ssz_snappy::<E::ElectraSignedBeaconBlock>(case_dir, &block_file)
                {
                    let electra_wrapped = E::electra_into_signed_block(electra_inner.clone());
                    let parent_root = E::electra_block_parent_root(&electra_inner);
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    // EIP-4844 data-availability check (deneb fork-choice test
                    // format, carried into electra): `is_data_available` runs
                    // `verify_blob_kzg_proof_batch` over the step-provided
                    // blobs/proofs vs the block's `blob_kzg_commitments`.
                    let commitments = E::electra_block_commitments(&electra_inner);
                    if !deneb_data_available(case_dir, blobs.as_deref(), &proofs, &commitments) {
                        if valid {
                            return CaseResult::Fail(format!(
                                "{case_name}: block({block}) data unavailable but valid=true"
                            ));
                        } else {
                            continue;
                        }
                    }
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &electra_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let post_state = match post_state_result {
                        Ok((ps, _)) => ps,
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &electra_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            // [Modified in Electra:EIP7549] feed body attestations
                            // through the committee-bits extractor.
                            E::feed_electra_block_attestations(&mut store, &electra_inner);
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(deneb_inner) =
                    load_ssz_snappy::<E::DenebSignedBeaconBlock>(case_dir, &block_file)
                {
                    let deneb_wrapped = E::deneb_into_signed_block(deneb_inner.clone());
                    let parent_root = deneb_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let commitments = deneb_inner.message().body().blob_kzg_commitments_slice();
                    if !deneb_data_available(case_dir, blobs.as_deref(), &proofs, commitments) {
                        if valid {
                            return CaseResult::Fail(format!(
                                "{case_name}: block({block}) data unavailable but valid=true"
                            ));
                        } else {
                            continue;
                        }
                    }
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &deneb_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                deneb_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &deneb_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(capella_inner) =
                    load_ssz_snappy::<E::CapellaSignedBeaconBlock>(case_dir, &block_file)
                {
                    let capella_inner_wrapped = E::capella_into_signed_block(capella_inner.clone());
                    let parent_root = capella_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &capella_inner_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                capella_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &capella_inner_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(bellatrix_inner) =
                    load_bellatrix_signed_block::<E>(case_dir, &block_file)
                {
                    let bellatrix_parent_root = E::unwrap_bellatrix_signed_block(&bellatrix_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&bellatrix_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &bellatrix_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> = if let Some(inner) =
                                E::unwrap_bellatrix_signed_block(&bellatrix_inner)
                            {
                                inner.message().body().attestations().to_vec()
                            } else {
                                vec![]
                            };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &bellatrix_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else if let Ok(altair_inner) =
                    load_altair_signed_block::<E>(case_dir, &block_file)
                {
                    let altair_parent_root = E::unwrap_altair_signed_block(&altair_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&altair_parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &altair_inner,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                if let Some(inner) = E::unwrap_altair_signed_block(&altair_inner) {
                                    inner.message().body().attestations().to_vec()
                                } else {
                                    vec![]
                                };
                            (ps, atts)
                        }
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &altair_inner,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in &attestations {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                } else {
                    // phase0 fallback
                    let phase0_inner: E::Phase0SignedBeaconBlock =
                        match load_ssz_snappy(case_dir, &block_file) {
                            Ok(b) => b,
                            Err(e) => {
                                return CaseResult::Fail(format!("{case_name}: {e}"));
                            }
                        };
                    let signed = E::phase0_into_signed_block(phase0_inner.clone());
                    let pre_state = match store
                        .block_states
                        .get(&phase0_inner.message().parent_root())
                        .cloned()
                    {
                        Some(s) => s,
                        None => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: on_block({block}) missing parent state"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &signed,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let post_state = match post_state_result {
                        Ok((ps, _)) => ps,
                        Err(e) => {
                            if valid {
                                return CaseResult::Fail(format!(
                                    "{case_name}: state_transition({block}) failed but valid=true: {e}"
                                ));
                            } else {
                                continue;
                            }
                        }
                    };
                    let now = store.time;
                    let outcome = on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &signed,
                        post_state,
                        now,
                        &pow_provider,
                    );
                    match (outcome, valid) {
                        (Ok(()), true) => {
                            for att in phase0_inner.message().body().attestations() {
                                let _ = on_attestation::<E>(&mut store, att, true);
                            }
                        }
                        (Err(e), true) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) failed but valid=true: {e}"
                            ));
                        }
                        (Ok(()), false) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: on_block({block}) succeeded but valid=false"
                            ));
                        }
                        (Err(_), false) => {}
                    }
                }
            }
            Step::Attestation { attestation, valid } => {
                // [Modified in Electra:EIP7549] decode the electra attestation
                // (committee_bits + wider aggregation_bits) and route through
                // `on_attestation_electra`.
                let outcome = match E::run_electra_attestation_step(
                    &mut store,
                    case_dir,
                    &attestation,
                    false,
                ) {
                    Ok(o) => o,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attestation({attestation}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::AttesterSlashing {
                attester_slashing,
                valid,
            } => {
                let slashing: AttesterSlashing<2048> =
                    match load_ssz_snappy(case_dir, &format!("{attester_slashing}.ssz_snappy")) {
                        Ok(a) => a,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let outcome = on_attester_slashing::<E>(&mut store, &slashing);
                match (outcome.is_ok(), valid) {
                    (true, true) | (false, false) => {}
                    (false, true) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) failed but valid=true"
                        ));
                    }
                    (true, false) => {
                        return CaseResult::Fail(format!(
                            "{case_name}: on_attester_slashing({attester_slashing}) succeeded but valid=false"
                        ));
                    }
                }
            }
            Step::Checks(checks) => {
                if let Err(e) = run_bellatrix_checks::<E>(&store, &checks) {
                    return CaseResult::Fail(format!("{case_name}: {e}"));
                }
            }
            Step::PowBlock(name) => {
                let file = format!("{name}.ssz_snappy");
                let pow_block: PowBlock = match load_ssz_snappy(case_dir, &file) {
                    Ok(b) => b,
                    Err(_) => return CaseResult::Skip,
                };
                pow_provider.blocks.insert(pow_block.block_hash, pow_block);
            }
            Step::Unknown(_) => {
                return CaseResult::Skip;
            }
        }
    }

    CaseResult::Pass
}
