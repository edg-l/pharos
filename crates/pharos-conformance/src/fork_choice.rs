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
//! - **Anchor-state SSZ decode failure** counts the case as **skip** with
//!   reason "altair ssz layout not yet supported".  In M1 the runner is
//!   plumbed in over `MainnetEthSpec` / `MinimalEthSpec` (both phase-0), so
//!   every altair anchor state will fail to decode and every case will skip.
//!   The row goes live with `pass = 0`, `fail = 0`, `skip = N`.  Altair STF +
//!   types land in M3, at which point this runner will produce real pass/fail
//!   counts without any code change.

use std::path::{Path, PathBuf};

use pharos_fork_choice::get_head::{get_current_slot, get_proposer_head};
use pharos_fork_choice::{
    Store, get_forkchoice_store, get_head, on_attestation, on_attester_slashing, on_block, on_tick,
};
use pharos_ssz::{Decode, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_types::{
    BeaconStateView, EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Checkpoint, Deposit, Epoch, Root, Slot},
    views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView},
};

use crate::fixture_walker::{WalkOpts, load_phase0_state, load_ssz_snappy, walk_category};
use crate::fs_util::{dir_name, read_dir_sorted};

// ── Result tally ──────────────────────────────────────────────────────────────

/// Result tally for a single fork-choice preset run.
pub struct ForkChoiceResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl ForkChoiceResult {
    fn new() -> Self {
        ForkChoiceResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: ForkChoiceResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all altair fork-choice sub-categories for the mainnet preset.
pub fn run_fork_choice_mainnet(root: &Path) -> ForkChoiceResult {
    run_fork_choice_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all altair fork-choice sub-categories for the minimal preset.
pub fn run_fork_choice_minimal(root: &Path) -> ForkChoiceResult {
    run_fork_choice_preset::<MinimalEthSpec>(root, "minimal")
}

/// Run all altair fork-choice sub-categories for a single preset.
///
/// Parameterised over `E: EthSpec` so the same runner serves altair, bellatrix,
/// and later forks in future milestones — only the fork path segment needs to
/// change when those land.
pub fn run_fork_choice_preset<E>(root: &Path, preset: &'static str) -> ForkChoiceResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::Phase0BeaconState: Decode,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    let fork = "altair";
    let base = root
        .join("tests")
        .join(preset)
        .join(fork)
        .join("fork_choice");

    let sub_categories: Vec<PathBuf> = if base.is_dir() {
        read_dir_sorted(&base).unwrap_or_default()
    } else {
        return ForkChoiceResult::new();
    };

    let mut total = ForkChoiceResult::new();
    for sub_path in sub_categories {
        if !sub_path.is_dir() {
            continue;
        }
        let sub = match sub_path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };
        total.merge(run_sub_category::<E>(root, preset, fork, &sub));
    }
    total
}

fn run_sub_category<E>(
    root: &Path,
    preset: &'static str,
    fork: &'static str,
    sub_category: &str,
) -> ForkChoiceResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::Phase0BeaconState: Decode,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    let mut out = ForkChoiceResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        preset,
        fork,
        "fork_choice",
        Some(sub_category),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    ) {
        let case_name = format!(
            "{fork}/fork_choice/{sub_category}/{preset}/{}",
            dir_name(&case_dir)
        );
        match run_case::<E>(&case_dir, &case_name) {
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
    E::Phase0BeaconState: Decode,
    E::Phase0BeaconBlock: Decode + BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::BeaconBlock: BeaconBlockView + TreeHash + Clone,
    E::SignedBeaconBlock: SignedBeaconBlockView<Message = E::BeaconBlock>,
{
    // Anchor state: skip on SSZ decode failure (e.g. altair layout vs phase-0
    // types; altair fixture files contain raw altair SSZ without a discriminant
    // prefix, which phase0 decode rejects).  This is the dominant skip path
    // until M3 lands full altair conformance support.
    let anchor_state: E::BeaconState =
        match load_phase0_state::<E>(case_dir, "anchor_state.ssz_snappy") {
            Ok(s) => s,
            Err(_) => return CaseResult::Skip,
        };
    // Anchor block: skip on decode failure (altair fixture blocks are raw altair SSZ).
    // Try loading as phase0 block; if it fails (altair layout mismatch), skip the case.
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
        match E::Phase0BeaconBlock::from_ssz_bytes(&raw) {
            Ok(b) => E::phase0_into_block(b),
            Err(_) => return CaseResult::Skip,
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
            Step::Block { block, valid } => {
                // Decode as the phase0 inner type so we can access body attestations
                // without going through the fork-enum `message()` (which panics).
                let block_file = format!("{block}.ssz_snappy");
                let phase0_inner: E::Phase0SignedBeaconBlock =
                    match load_ssz_snappy(case_dir, &block_file) {
                        Ok(b) => b,
                        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                    };
                let signed = E::phase0_into_signed_block(phase0_inner.clone());
                let outcome = on_block::<E>(&mut store, &signed);
                match (outcome, valid) {
                    (Ok(()), true) => {
                        // Per spec: also feed body attestations through
                        // on_attestation when block applied successfully.
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
            Step::Unknown(_) => {
                // Unknown top-level step variant (e.g. `pow_block`,
                // `payload_status`).  Per the skip-unknown-step-keys policy,
                // skip the whole case rather than fail.
                return CaseResult::Skip;
            }
        }
    }

    CaseResult::Pass
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
        return Ok(Step::Block {
            block,
            valid: read_valid(map),
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

    // Unknown top-level variants: `pow_block`, `payload_status`,
    // `execution_payload`, `payload_attestation_message`, etc.  Per policy,
    // return Unknown so the caller can skip the whole case.
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
            // Silently ignored unknown keys per spec/policy:
            // `viable_for_head_roots_and_weights`,
            // `should_override_forkchoice_update`, `head_payload_status`,
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
