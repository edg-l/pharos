//! Epoch processing conformance dispatcher.
//!
//! Covers ten sub-categories of `phase0/epoch_processing` for both presets:
//!   - `justification_and_finalization`
//!   - `rewards_and_penalties`
//!   - `registry_updates`
//!   - `slashings`
//!   - `eth1_data_reset`
//!   - `effective_balance_updates`
//!   - `slashings_reset`
//!   - `randao_mixes_reset`
//!   - `historical_roots_update`
//!   - `participation_record_updates`
//!
//! For each case:
//! - `pre.ssz_snappy` is the input state.
//! - `post.ssz_snappy` present → expect `Ok(())` and state matches post.
//! - `post.ssz_snappy` absent → expect `Err(_)`.

use std::path::Path;

use pharos_ssz::Encode;
use pharos_stf::phase0::{
    BeaconStateWrite,
    epoch::{
        process_effective_balance_updates, process_eth1_data_reset,
        process_historical_roots_update, process_justification_and_finalization,
        process_participation_record_updates, process_randao_mixes_reset, process_registry_updates,
        process_rewards_and_penalties, process_slashings, process_slashings_reset,
    },
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec, phase0::Attestation, views::BeaconBlockBodyView,
};

use crate::fixture_walker::{WalkOpts, load_pre_post_phase0_state, walk_category};
use crate::fs_util::dir_name;

/// Result of running all epoch-processing tests for a single preset.
pub struct EpochResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl EpochResult {
    fn new() -> Self {
        EpochResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: EpochResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

/// Run all epoch-processing sub-categories for the mainnet preset.
pub fn run_epoch_processing_mainnet(root: &Path) -> EpochResult {
    run_epoch_processing_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all epoch-processing sub-categories for the minimal preset.
pub fn run_epoch_processing_minimal(root: &Path) -> EpochResult {
    run_epoch_processing_preset::<MinimalEthSpec>(root, "minimal")
}

fn run_epoch_processing_preset<E>(root: &Path, preset: &str) -> EpochResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let mut total = EpochResult::new();
    total.merge(run_sub::<E, _>(
        root,
        preset,
        "justification_and_finalization",
        |state| process_justification_and_finalization::<E>(state).map_err(|e| format!("{e}")),
    ));
    total.merge(run_sub::<E, _>(
        root,
        preset,
        "rewards_and_penalties",
        |state| process_rewards_and_penalties::<E>(state).map_err(|e| format!("{e}")),
    ));
    total.merge(run_sub::<E, _>(root, preset, "registry_updates", |state| {
        process_registry_updates::<E>(state).map_err(|e| format!("{e}"))
    }));
    total.merge(run_sub::<E, _>(root, preset, "slashings", |state| {
        process_slashings::<E>(state).map_err(|e| format!("{e}"))
    }));
    total.merge(run_sub::<E, _>(root, preset, "eth1_data_reset", |state| {
        process_eth1_data_reset::<E>(state).map_err(|e| format!("{e}"))
    }));
    total.merge(run_sub::<E, _>(
        root,
        preset,
        "effective_balance_updates",
        |state| process_effective_balance_updates::<E>(state).map_err(|e| format!("{e}")),
    ));
    total.merge(run_sub::<E, _>(root, preset, "slashings_reset", |state| {
        process_slashings_reset::<E>(state).map_err(|e| format!("{e}"))
    }));
    total.merge(run_sub::<E, _>(
        root,
        preset,
        "randao_mixes_reset",
        |state| process_randao_mixes_reset::<E>(state).map_err(|e| format!("{e}")),
    ));
    total.merge(run_sub::<E, _>(
        root,
        preset,
        "historical_roots_update",
        |state| process_historical_roots_update::<E>(state).map_err(|e| format!("{e}")),
    ));
    total.merge(run_sub::<E, _>(
        root,
        preset,
        "participation_record_updates",
        |state| process_participation_record_updates::<E>(state).map_err(|e| format!("{e}")),
    ));
    total
}

// ── sub-routine runner ────────────────────────────────────────────────────────

fn epoch_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

fn run_sub<E, F>(root: &Path, preset: &str, sub: &str, mut apply: F) -> EpochResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + pharos_ssz::Decode,
    F: FnMut(&mut E::BeaconState) -> Result<(), String>,
{
    let mut out = EpochResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        preset,
        "phase0",
        "epoch_processing",
        Some(sub),
        epoch_walk_opts(),
    ) {
        let case_name = format!(
            "phase0/epoch_processing/{preset}/{sub}/{}",
            dir_name(&case_dir)
        );
        let result = run_epoch_case::<E, _>(&case_dir, &case_name, &mut apply);
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

enum CaseResult {
    Pass,
    Fail(String),
}

fn run_epoch_case<E, F>(case_dir: &Path, case_name: &str, apply: &mut F) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + pharos_ssz::Decode,
    F: FnMut(&mut E::BeaconState) -> Result<(), String>,
{
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let result = apply(&mut pre);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after epoch sub-routine"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}
