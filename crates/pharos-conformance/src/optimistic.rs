//! Conformance runner for `sync/optimistic` spec-test cases.
//!
//! Fixture path: `{root}/{preset}/{fork}/sync/optimistic/pyspec_tests/{case}/`
//!
//! Forks covered: bellatrix, capella (both mainnet + minimal).
//! Higher forks (deneb, electra, fulu) are skipped — types not yet landed.
//!
//! # Step types
//!
//! - `{tick: <u64>}` — `on_tick` (same units as fork_choice: seconds).
//! - `{checks: {...}}` — assert store state (head, checkpoints, proposer_boost_root).
//! - `{block_hash: '0x..', payload_status: {status, latest_valid_hash, validation_error}}`
//!   — declare the EL verdict for the payload whose EL block_hash == block_hash.
//! - `{block: <stem>, valid: bool}` — import block.  `valid: false` means the
//!   EL has (or will) declare this block's payload INVALID.  The block is still
//!   imported unconditionally: the pyspec `add_block(is_optimistic=True,
//!   valid=False)` helper calls `run_on_block` (which succeeds) BEFORE
//!   recording the `valid:false` marker
//!   (`consensus-specs/tests/core/pyspec/eth2spec/test/helpers/fork_choice.py`,
//!   `add_block`, ~line 375-378).  The block does not become canonical because
//!   the separately-declared INVALID `payload_status` step causes
//!   `apply_invalid_payload` → `filter_block_tree` to exclude it from
//!   `get_head`, not because `on_block` rejects it.
//!
//! # Payload-status semantics
//!
//! The runner maintains two maps:
//! - `el_hash_to_verdict`: EL block_hash → (status string, latest_valid_hash)
//!   Populated by `payload_status` steps; consumed when the corresponding block
//!   is imported.
//! - `el_hash_to_cl_root`: EL block_hash → CL block root.
//!   Populated on every successful `on_block`; used by standalone `payload_status`
//!   steps that arrive after the block is already in the store.
//!
//! On a `block` step, after `on_block` succeeds, the pre-declared verdict
//! (if any) is applied:
//! - `VALID` → `promote_valid_ancestors(store, block_root)` (marks block+ancestors Valid)
//! - `SYNCING` / `ACCEPTED` → `mark_payload_status(block_root, NotValidated)`
//!   (already pre-seeded via `on_block`; explicit re-seed is a no-op but harmless)
//! - `INVALID` → `apply_invalid_payload(store, block_root, lvh)` (marks block +
//!   descendants Invalid; `get_head` excludes them, so head reverts)
//!
//! # Per `consensus-specs/sync/optimistic.md`.

use std::collections::HashMap;
use std::path::Path;

use pharos_fork_choice::{
    HashMapPowBlockProvider, PayloadStatus, Store, apply_invalid_payload, get_forkchoice_store,
    get_head, is_optimistic, on_attestation, on_block, on_tick, promote_valid_ancestors,
};
use pharos_ssz::{Decode, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::{NullExecutionEngine, state_transition};
use pharos_types::{
    BeaconStateView, EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Checkpoint, Deposit, Epoch, Root, Slot},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};
use pharos_utils::Hash256;
use rayon::prelude::*;

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_bellatrix_state,
    load_capella_state, load_phase0_state, load_ssz_snappy, walk_category,
};
use crate::fork_choice::ForkChoiceResult;
use crate::fs_util::dir_name;

// ── Public entry points ───────────────────────────────────────────────────────

pub fn run_optimistic_mainnet(root: &Path) -> ForkChoiceResult {
    let mut total = ForkChoiceResult::new();
    for fork in ["bellatrix", "capella"] {
        total.merge(run_optimistic_fork_preset::<MainnetEthSpec>(
            root, "mainnet", fork,
        ));
    }
    total
}

pub fn run_optimistic_minimal(root: &Path) -> ForkChoiceResult {
    let mut total = ForkChoiceResult::new();
    for fork in ["bellatrix", "capella"] {
        total.merge(run_optimistic_fork_preset::<MinimalEthSpec>(
            root, "minimal", fork,
        ));
    }
    total
}

// ── Per-fork driver ───────────────────────────────────────────────────────────

fn run_optimistic_fork_preset<E>(
    root: &Path,
    preset: &'static str,
    fork: &'static str,
) -> ForkChoiceResult
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
    E::BellatrixBeaconBlock: BeaconBlockView<Body = E::BellatrixBeaconBlockBody> + TreeHash,
    E::BellatrixBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::BellatrixSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView<Body = E::CapellaBeaconBlockBody> + TreeHash,
    E::CapellaBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::CapellaSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    let base = root.join(preset).join(fork).join("sync").join("optimistic");
    if !base.is_dir() {
        return ForkChoiceResult::new();
    }

    let cases: Vec<_> = walk_category(
        root,
        preset,
        fork,
        "sync/optimistic",
        None,
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("{fork}/sync/optimistic/{preset}/{}", dir_name(&case_dir));
            run_optimistic_case::<E>(&case_dir, &case_name)
        })
        .collect();

    let mut out = ForkChoiceResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Skip => out.skip += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

// ── Case outcome ──────────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Skip,
    Fail(String),
}

// ── Case driver ───────────────────────────────────────────────────────────────

fn run_optimistic_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
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
    E::BellatrixBeaconBlock: BeaconBlockView<Body = E::BellatrixBeaconBlockBody> + TreeHash,
    E::BellatrixBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::BellatrixSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView<Body = E::CapellaBeaconBlockBody> + TreeHash,
    E::CapellaBeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::CapellaSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
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

    // Seed anchor block's EL block_hash as Valid in the reverse map.
    // (The anchor is trusted; `get_forkchoice_store` already seeds it Valid
    // in `payload_statuses`; here we just pre-populate the reverse hash map.)
    let anchor_root = store.finalized_checkpoint.root;
    let anchor_el_hash = store
        .blocks
        .get(&anchor_root)
        .and_then(|b| E::get_execution_block_hash(b))
        .unwrap_or_default();

    // EL block_hash → declared (status_str, latest_valid_hash).
    // Populated by `payload_status` steps; consumed on the subsequent `block` step.
    let mut el_hash_to_verdict: HashMap<Hash256, (String, Option<Hash256>)> = HashMap::new();

    // EL block_hash → CL block root.
    // Populated when blocks are imported via `on_block`.
    let mut el_hash_to_cl_root: HashMap<Hash256, Root> = HashMap::new();

    // Seed anchor in reverse map.
    if anchor_el_hash != Hash256::default() {
        el_hash_to_cl_root.insert(anchor_el_hash, anchor_root);
    }

    // pow_block provider: the optimistic fixtures have no `pow_block` steps
    // (all fixture blocks are post-merge), but on_block requires a PowBlockProvider.
    let pow_provider = HashMapPowBlockProvider {
        blocks: HashMap::new(),
    };

    let steps_path = case_dir.join("steps.yaml");
    let steps = match parse_steps(&steps_path) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    for step in steps {
        match step {
            Step::Tick { tick } => {
                on_tick::<E>(&mut store, tick);
            }

            Step::PayloadStatus {
                block_hash,
                status,
                latest_valid_hash,
            } => {
                // Record the verdict for when the matching block imports.
                el_hash_to_verdict.insert(block_hash, (status.clone(), latest_valid_hash));

                // If the block is already in the store (e.g. a post-import update),
                // apply the verdict immediately.
                if let Some(&cl_root) = el_hash_to_cl_root.get(&block_hash) {
                    apply_payload_verdict(&mut store, cl_root, &status, latest_valid_hash);
                }
            }

            Step::Block { block, .. } => {
                // Import every block unconditionally regardless of `valid`.
                // Per pyspec add_block (~line 375-378): run_on_block is called
                // first, then valid:false is recorded.  Canonicality is
                // controlled by the INVALID payload_status step that follows,
                // not by on_block returning an error.
                let block_file = format!("{block}.ssz_snappy");
                let cfg = E::default_runtime_config();

                // Decode the block: try capella (raw inner type), then bellatrix
                // (already wrapped as E::SignedBeaconBlock), then altair, then skip.
                //
                // Using the raw inner type for capella gives typed access to
                // Attestation<2048> (concrete type, not an associated type without
                // a Clone bound).  Same pattern as `run_capella_case` in fork_choice.rs.
                if let Ok(cap_inner) =
                    load_ssz_snappy::<E::CapellaSignedBeaconBlock>(case_dir, &block_file)
                {
                    let cap_wrapped = E::capella_into_signed_block(cap_inner.clone());
                    let parent_root = cap_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            return CaseResult::Fail(format!(
                                "{case_name}: capella block {block}: parent state for {parent_root} not found in store"
                            ));
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &cap_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            // cap_inner is E::CapellaSignedBeaconBlock, body().attestations()
                            // returns &[Attestation<2048>] via the concrete capella type.
                            let atts: Vec<Attestation<2048>> =
                                cap_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: capella block {block}: state_transition failed: {e:?}"
                            ));
                        }
                    };
                    let now = store.time;
                    // Compute block_root from the inner block type (avoids calling
                    // .message() on the fork-enum E::SignedBeaconBlock which panics).
                    let block_root = cap_inner.message().tree_hash_root();
                    if on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &cap_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    )
                    .is_ok()
                    {
                        // Look up the block from the store to get E::BeaconBlock for
                        // E::get_execution_block_hash (which takes &E::BeaconBlock).
                        let el_hash = store
                            .blocks
                            .get(&block_root)
                            .and_then(|b| E::get_execution_block_hash(b))
                            .unwrap_or_default();
                        if el_hash != Hash256::default() {
                            el_hash_to_cl_root.insert(el_hash, block_root);
                            if let Some((status, lvh)) = el_hash_to_verdict.get(&el_hash).cloned() {
                                apply_payload_verdict(&mut store, block_root, &status, lvh);
                            }
                        }
                        for att in &attestations {
                            let _ = on_attestation::<E>(&mut store, att, true);
                        }
                    }
                } else if let Ok(bel_inner) =
                    load_ssz_snappy::<E::BellatrixSignedBeaconBlock>(case_dir, &block_file)
                {
                    // Load raw inner type (same pattern as capella above) to get
                    // typed access to block_root + attestations without calling
                    // .message() on the fork-enum (which panics).
                    let bel_wrapped = E::bellatrix_into_signed_block(bel_inner.clone());
                    let parent_root = bel_inner.message().parent_root();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            return CaseResult::Fail(format!(
                                "{case_name}: bellatrix block {block}: parent state for {parent_root} not found in store"
                            ));
                        }
                    };
                    let post_state_result = state_transition::<E, NullExecutionEngine>(
                        pre_state,
                        &bel_wrapped,
                        &NullExecutionEngine,
                        true,
                        &cfg,
                    );
                    let (post_state, attestations) = match post_state_result {
                        Ok((ps, _)) => {
                            let atts: Vec<Attestation<2048>> =
                                bel_inner.message().body().attestations().to_vec();
                            (ps, atts)
                        }
                        Err(e) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: bellatrix block {block}: state_transition failed: {e:?}"
                            ));
                        }
                    };
                    let now = store.time;
                    let block_root = bel_inner.message().tree_hash_root();
                    if on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &bel_wrapped,
                        post_state,
                        now,
                        &pow_provider,
                    )
                    .is_ok()
                    {
                        let el_hash = store
                            .blocks
                            .get(&block_root)
                            .and_then(|b| E::get_execution_block_hash(b))
                            .unwrap_or_default();
                        if el_hash != Hash256::default() {
                            el_hash_to_cl_root.insert(el_hash, block_root);
                            if let Some((status, lvh)) = el_hash_to_verdict.get(&el_hash).cloned() {
                                apply_payload_verdict(&mut store, block_root, &status, lvh);
                            }
                        }
                        for att in &attestations {
                            let _ = on_attestation::<E>(&mut store, att, true);
                        }
                    }
                } else if let Ok(altair_inner) =
                    load_altair_signed_block::<E>(case_dir, &block_file)
                {
                    let parent_root = E::unwrap_altair_signed_block(&altair_inner)
                        .map(|inner| inner.message().parent_root())
                        .unwrap_or_default();
                    let pre_state = match store.block_states.get(&parent_root).cloned() {
                        Some(s) => s,
                        None => {
                            return CaseResult::Fail(format!(
                                "{case_name}: altair block {block}: parent state for {parent_root} not found in store"
                            ));
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
                            return CaseResult::Fail(format!(
                                "{case_name}: altair block {block}: state_transition failed: {e:?}"
                            ));
                        }
                    };
                    let now = store.time;
                    if on_block::<E, HashMapPowBlockProvider>(
                        &mut store,
                        &altair_inner,
                        post_state,
                        now,
                        &pow_provider,
                    )
                    .is_ok()
                    {
                        for att in &attestations {
                            let _ = on_attestation::<E>(&mut store, att, true);
                        }
                    }
                } else {
                    // Unknown block type: skip this individual block.
                    continue;
                }
            }

            Step::Checks(checks) => {
                if let Err(e) = run_checks::<E>(&store, &checks) {
                    return CaseResult::Fail(format!("{case_name}: {e}"));
                }
            }
        }
    }

    CaseResult::Pass
}

// ── Payload verdict application ───────────────────────────────────────────────

/// Apply a declared payload verdict to `cl_root` in the store.
///
/// Per `consensus-specs/sync/optimistic.md`:
/// - VALID → promote root and all NotValidated ancestors to Valid.
/// - SYNCING / ACCEPTED → pre-seed NotValidated (idempotent; already set by
///   the pre-seed invariant in production; here it is explicit for clarity).
/// - INVALID → BFS-invalidate root + all descendants via `apply_invalid_payload`.
///
/// `latest_valid_hash` is only meaningful for INVALID (used by
/// `resolve_invalid_block` for the 3-case LVH table).
fn apply_payload_verdict<E: EthSpec>(
    store: &mut Store<E>,
    cl_root: Root,
    status: &str,
    latest_valid_hash: Option<Hash256>,
) where
    E::BeaconBlock: pharos_types::views::BeaconBlockView,
{
    match status {
        "VALID" => {
            // Mark root + all NotValidated ancestors Valid.
            // Per `consensus-specs/sync/optimistic.md:193-196`.
            promote_valid_ancestors(store, cl_root);
        }
        "SYNCING" | "ACCEPTED" => {
            // Pre-seed NotValidated (idempotent).
            // Only set if not already Valid (don't downgrade a Valid entry).
            if !matches!(
                store.payload_statuses.get(&cl_root),
                Some(PayloadStatus::Valid)
            ) {
                store.mark_payload_status(cl_root, PayloadStatus::NotValidated);
            }
        }
        "INVALID" => {
            // Invalidate root + descendants.
            // Per `consensus-specs/sync/optimistic.md:219-222`.
            apply_invalid_payload(store, cl_root, latest_valid_hash);
        }
        _ => {
            // Unknown status: treat conservatively as SYNCING.
            if !matches!(
                store.payload_statuses.get(&cl_root),
                Some(PayloadStatus::Valid)
            ) {
                store.mark_payload_status(cl_root, PayloadStatus::NotValidated);
            }
        }
    }
}

// ── Checks runner ─────────────────────────────────────────────────────────────

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
    // Per `consensus-specs/sync/optimistic.md` Beacon APIs (execution_optimistic):
    // `is_optimistic(store, get_head(store))` reflects whether the head block's
    // payload has been verified.  Future-fork fixtures may assert this field.
    if let Some(want) = checks.is_optimistic {
        let head = get_head::<E>(store);
        let got = is_optimistic::<E>(store, head);
        if got != want {
            return Err(format!(
                "is_optimistic: want {want}, got {got} (head={head})"
            ));
        }
    }
    Ok(())
}

// ── steps.yaml parsing ────────────────────────────────────────────────────────

enum Step {
    Tick {
        tick: u64,
    },
    Block {
        block: String,
        #[allow(dead_code)]
        valid: bool,
    },
    PayloadStatus {
        block_hash: Hash256,
        status: String,
        latest_valid_hash: Option<Hash256>,
    },
    Checks(Box<Checks>),
}

struct Checks {
    head: Option<HeadCheck>,
    justified_checkpoint: Option<Checkpoint>,
    finalized_checkpoint: Option<Checkpoint>,
    time: Option<u64>,
    proposer_boost_root: Option<Root>,
    /// Per `consensus-specs/sync/optimistic.md` Beacon APIs (execution_optimistic):
    /// `true` iff the head block's payload has not yet been verified by the EL.
    is_optimistic: Option<bool>,
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
        if let Some(step) = parse_step(item)? {
            out.push(step);
        }
    }
    Ok(out)
}

fn parse_step(val: &serde_yaml_ng::Value) -> Result<Option<Step>, String> {
    let map = match val.as_mapping() {
        Some(m) => m,
        None => return Ok(None),
    };

    if let Some(checks_val) = map.get("checks") {
        let parsed = parse_checks(checks_val)?;
        return Ok(Some(Step::Checks(Box::new(parsed))));
    }

    if let Some(tick) = map.get("tick").and_then(|v| v.as_u64()) {
        return Ok(Some(Step::Tick { tick }));
    }

    if let Some(block) = map.get("block").and_then(value_as_str) {
        return Ok(Some(Step::Block {
            block,
            valid: map.get("valid").and_then(|v| v.as_bool()).unwrap_or(true),
        }));
    }

    // `payload_status` step: top-level keys are `block_hash` + `payload_status`.
    // Per the fixture YAML format, the structure is:
    //   - block_hash: '0x...'
    //     payload_status:
    //       status: VALID|SYNCING|INVALID|ACCEPTED
    //       latest_valid_hash: '0x...' | null
    //       validation_error: null | '...'
    if let Some(bh_str) = map.get("block_hash").and_then(value_as_str) {
        let block_hash = parse_hash256(&bh_str)?;
        let ps_map = map
            .get("payload_status")
            .and_then(|v| v.as_mapping())
            .ok_or_else(|| "payload_status step missing payload_status mapping".to_string())?;
        let status = ps_map
            .get("status")
            .and_then(value_as_str)
            .ok_or_else(|| "payload_status: missing status".to_string())?;
        let latest_valid_hash = ps_map
            .get("latest_valid_hash")
            .and_then(value_as_str)
            .map(|s| parse_hash256(&s))
            .transpose()?;
        return Ok(Some(Step::PayloadStatus {
            block_hash,
            status,
            latest_valid_hash,
        }));
    }

    // Unknown step type (e.g. pow_block, on_payload_info): silently skip.
    Ok(None)
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
        is_optimistic: None,
    };

    for (k, v) in map {
        let key = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        match key {
            "head" => out.head = Some(parse_head(v)?),
            "time" => out.time = v.as_u64(),
            "justified_checkpoint" => {
                out.justified_checkpoint = Some(parse_checkpoint(v)?);
            }
            "finalized_checkpoint" => {
                out.finalized_checkpoint = Some(parse_checkpoint(v)?);
            }
            "proposer_boost_root" => {
                out.proposer_boost_root = value_as_str(v).map(|s| parse_root(&s)).transpose()?;
            }
            "is_optimistic" => {
                out.is_optimistic = v.as_bool();
            }
            // Unknown keys silently ignored.
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

fn parse_hash256(s: &str) -> Result<Hash256, String> {
    s.parse::<Hash256>()
        .map_err(|e| format!("hash256 parse '{s}': {e:?}"))
}

fn value_as_str(v: &serde_yaml_ng::Value) -> Option<String> {
    v.as_str().map(|s| s.to_owned())
}
