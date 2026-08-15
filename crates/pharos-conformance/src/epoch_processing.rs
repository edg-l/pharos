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

use crate::fixture_walker::{
    WalkOpts, load_pre_post_altair_state, load_pre_post_bellatrix_state,
    load_pre_post_phase0_state, walk_category,
};
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

// ── Altair epoch-processing dispatchers ───────────────────────────────────────

/// Run all altair epoch-processing sub-categories for the mainnet preset.
pub fn run_epoch_processing_altair_mainnet(root: &Path) -> EpochResult {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_historical_roots_update as altair_hist_roots,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_registry_updates as altair_registry,
        process_rewards_and_penalties as altair_rewards, process_slashings as altair_slashings,
        process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_types::{MainnetEthSpec as E, altair::MainnetBeaconState};

    let mut total = EpochResult::new();
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "justification_and_finalization",
        |s| {
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "inactivity_updates",
        |s| {
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "rewards_and_penalties",
        |s| {
            altair_rewards::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "registry_updates",
        |s| {
            altair_registry::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "slashings",
        |s| {
            altair_slashings::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "eth1_data_reset",
        |s| {
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "effective_balance_updates",
        |s| {
            altair_eff_bal::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "slashings_reset",
        |s| {
            altair_slash_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "randao_mixes_reset",
        |s| {
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "historical_roots_update",
        |s| {
            altair_hist_roots::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "participation_flag_updates",
        |s| {
            altair_participation_flags::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(s)
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MainnetBeaconState, E, _>(root, "mainnet", "sync_committee_updates", |s| {
        altair_sync_committee::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s).map_err(|e| format!("{e}"))
    }));
    total
}

/// Run all altair epoch-processing sub-categories for the minimal preset.
pub fn run_epoch_processing_altair_minimal(root: &Path) -> EpochResult {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_historical_roots_update as altair_hist_roots,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_registry_updates as altair_registry,
        process_rewards_and_penalties as altair_rewards, process_slashings as altair_slashings,
        process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_types::{MinimalEthSpec as E, altair::MinimalBeaconState};

    let mut total = EpochResult::new();
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "justification_and_finalization",
        |s| {
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "inactivity_updates",
        |s| {
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "rewards_and_penalties",
        |s| {
            altair_rewards::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "registry_updates",
        |s| {
            altair_registry::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "slashings",
        |s| {
            altair_slashings::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "eth1_data_reset",
        |s| {
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "effective_balance_updates",
        |s| {
            altair_eff_bal::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "slashings_reset",
        |s| {
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "randao_mixes_reset",
        |s| {
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "historical_roots_update",
        |s| {
            altair_hist_roots::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "participation_flag_updates",
        |s| {
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_altair_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "sync_committee_updates",
        |s| {
            altair_sync_committee::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        },
    ));
    total
}

/// Walk an altair epoch sub-category and run each case with a concrete closure.
///
/// `S` is the concrete altair `BeaconState<...>` type for this preset.
/// `E` is the `EthSpec` impl.
/// `F` is the sub-routine closure: `FnMut(&mut S) -> Result<(), String>`.
fn run_altair_sub<S, E, F>(root: &Path, preset: &str, sub: &str, mut apply: F) -> EpochResult
where
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    E: EthSpec<AltairBeaconState = S>,
    F: FnMut(&mut S) -> Result<(), String>,
{
    let mut out = EpochResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        preset,
        "altair",
        "epoch_processing",
        Some(sub),
        epoch_walk_opts(),
    ) {
        let case_name = format!(
            "altair/epoch_processing/{preset}/{sub}/{}",
            dir_name(&case_dir)
        );
        let result = run_altair_epoch_case::<S, E, _>(&case_dir, &case_name, &mut apply);
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

fn run_altair_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &mut F) -> CaseResult
where
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    E: EthSpec<AltairBeaconState = S>,
    F: FnMut(&mut S) -> Result<(), String>,
{
    let (mut pre, post) = match load_pre_post_altair_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    // Unwrap from fork-enum to inner altair state.
    let mut pre_inner = match E::into_altair_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not altair state")),
    };

    let result = apply(&mut pre_inner);

    // Rewrap for comparison.
    pre = E::altair_into_state(pre_inner);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after altair epoch sub-routine"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── Bellatrix epoch-processing dispatchers ────────────────────────────────────

/// Run all bellatrix epoch-processing sub-categories for the mainnet preset.
pub fn run_epoch_processing_bellatrix_mainnet(root: &Path) -> EpochResult {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_historical_roots_update as altair_hist_roots,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_registry_updates as altair_registry,
        process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_stf::bellatrix::epoch::{
        process_rewards_and_penalties_bellatrix, process_slashings_bellatrix,
    };
    use pharos_stf::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
    use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconState};

    let mut total = EpochResult::new();

    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "justification_and_finalization",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "inactivity_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "rewards_and_penalties",
        |s| {
            process_rewards_and_penalties_bellatrix::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "registry_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_registry::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "slashings",
        |s| {
            process_slashings_bellatrix::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "eth1_data_reset",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "effective_balance_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eff_bal::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "slashings_reset",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_slash_reset::<
                8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E,
            >(&mut a)
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "randao_mixes_reset",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "historical_roots_update",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_hist_roots::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "participation_flag_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_participation_flags::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut a)
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MainnetBeaconState, E, _>(
        root,
        "mainnet",
        "sync_committee_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_sync_committee::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut a)
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total
}

/// Run all bellatrix epoch-processing sub-categories for the minimal preset.
pub fn run_epoch_processing_bellatrix_minimal(root: &Path) -> EpochResult {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_historical_roots_update as altair_hist_roots,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_registry_updates as altair_registry,
        process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_stf::bellatrix::epoch::{
        process_rewards_and_penalties_bellatrix, process_slashings_bellatrix,
    };
    use pharos_stf::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
    use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconState};

    let mut total = EpochResult::new();

    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "justification_and_finalization",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "inactivity_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "rewards_and_penalties",
        |s| {
            process_rewards_and_penalties_bellatrix::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "registry_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_registry::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "slashings",
        |s| {
            process_slashings_bellatrix::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "eth1_data_reset",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "effective_balance_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eff_bal::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "slashings_reset",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "randao_mixes_reset",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "historical_roots_update",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_hist_roots::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "participation_flag_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total.merge(run_bellatrix_sub::<MinimalBeaconState, E, _>(
        root,
        "minimal",
        "sync_committee_updates",
        |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_sync_committee::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        },
    ));
    total
}

/// Walk a bellatrix epoch sub-category and run each case with a concrete closure.
fn run_bellatrix_sub<S, E, F>(root: &Path, preset: &str, sub: &str, mut apply: F) -> EpochResult
where
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    E: EthSpec<BellatrixBeaconState = S>,
    F: FnMut(&mut S) -> Result<(), String>,
{
    let mut out = EpochResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        preset,
        "bellatrix",
        "epoch_processing",
        Some(sub),
        epoch_walk_opts(),
    ) {
        let case_name = format!(
            "bellatrix/epoch_processing/{preset}/{sub}/{}",
            dir_name(&case_dir)
        );
        let result = run_bellatrix_epoch_case::<S, E, _>(&case_dir, &case_name, &mut apply);
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

fn run_bellatrix_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &mut F) -> CaseResult
where
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    E: EthSpec<BellatrixBeaconState = S>,
    F: FnMut(&mut S) -> Result<(), String>,
{
    let (pre, post) = match load_pre_post_bellatrix_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut pre_inner = match E::into_bellatrix_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not bellatrix state")),
    };

    let result = apply(&mut pre_inner);

    let post_bytes = post.map(|p| p.as_ssz_bytes());
    let current_bytes = E::bellatrix_into_state(pre_inner).as_ssz_bytes();

    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after bellatrix epoch sub-routine"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}
