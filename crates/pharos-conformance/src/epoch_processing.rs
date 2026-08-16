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

use std::path::{Path, PathBuf};

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
    load_pre_post_capella_state, load_pre_post_deneb_state, load_pre_post_phase0_state,
    walk_category,
};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per epoch-processing test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_epoch_processing_*` function.
/// Called by the Phase 7 flat work-pool.
///
/// Sub-step order per fork (matches dispatcher merge order):
/// - phase0 (10): justification_and_finalization, rewards_and_penalties, registry_updates,
///   slashings, eth1_data_reset, effective_balance_updates, slashings_reset,
///   randao_mixes_reset, historical_roots_update, participation_record_updates
/// - altair (12): justification_and_finalization, inactivity_updates, rewards_and_penalties,
///   registry_updates, slashings, eth1_data_reset, effective_balance_updates, slashings_reset,
///   randao_mixes_reset, historical_roots_update, participation_flag_updates,
///   sync_committee_updates
/// - bellatrix (12): same as altair
/// - capella (12): justification_and_finalization, inactivity_updates, rewards_and_penalties,
///   registry_updates, slashings, eth1_data_reset, effective_balance_updates, slashings_reset,
///   randao_mixes_reset, historical_summaries_update, participation_flag_updates,
///   sync_committee_updates
/// - deneb (12): same as capella
/// - electra (11, Phase 4a): justification_and_finalization, inactivity_updates,
///   rewards_and_penalties, registry_updates (electra-native), slashings
///   (electra-native), eth1_data_reset, slashings_reset, randao_mixes_reset,
///   historical_summaries_update, participation_flag_updates, sync_committee_updates.
///   `pending_deposits`, `pending_consolidations`, `effective_balance_updates` are
///   NOT registered until Phases 4b/4c add their electra-native impls.
///
/// Supported forks: `"phase0"`, `"altair"`, `"bellatrix"`, `"capella"`, `"deneb"`,
/// `"electra"`.
pub fn enumerate_epoch_processing(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let mut tasks: Vec<CaseTask> = Vec::new();
    let mut ordinal: u32 = 0;

    match (fork, preset) {
        // ── phase0 ────────────────────────────────────────────────────────────
        ("phase0", "mainnet") => {
            enumerate_phase0_ep_subs::<MainnetEthSpec>(
                root,
                preset,
                row_ordinal,
                &mut ordinal,
                &mut tasks,
            );
        }
        ("phase0", _) => {
            enumerate_phase0_ep_subs::<MinimalEthSpec>(
                root,
                preset,
                row_ordinal,
                &mut ordinal,
                &mut tasks,
            );
        }
        // ── altair ────────────────────────────────────────────────────────────
        ("altair", "mainnet") => {
            enumerate_altair_ep_subs_mainnet(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        ("altair", _) => {
            enumerate_altair_ep_subs_minimal(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        // ── bellatrix ─────────────────────────────────────────────────────────
        ("bellatrix", "mainnet") => {
            enumerate_bellatrix_ep_subs_mainnet(
                root,
                preset,
                row_ordinal,
                &mut ordinal,
                &mut tasks,
            );
        }
        ("bellatrix", _) => {
            enumerate_bellatrix_ep_subs_minimal(
                root,
                preset,
                row_ordinal,
                &mut ordinal,
                &mut tasks,
            );
        }
        // ── capella ───────────────────────────────────────────────────────────
        ("capella", "mainnet") => {
            enumerate_capella_ep_subs_mainnet(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        ("capella", _) => {
            enumerate_capella_ep_subs_minimal(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        // ── deneb ─────────────────────────────────────────────────────────────
        ("deneb", "mainnet") => {
            enumerate_deneb_ep_subs_mainnet(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        ("deneb", _) => {
            enumerate_deneb_ep_subs_minimal(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        // ── electra ───────────────────────────────────────────────────────────
        ("electra", "mainnet") => {
            enumerate_electra_ep_subs_mainnet(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
        _ => {
            enumerate_electra_ep_subs_minimal(root, preset, row_ordinal, &mut ordinal, &mut tasks);
        }
    }

    tasks
}

// ── phase0 sub-step walker ────────────────────────────────────────────────────

fn enumerate_phase0_ep_subs<E>(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + pharos_ssz::Decode,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    #[allow(clippy::type_complexity)]
    let subs: &[(&'static str, fn(&mut E::BeaconState) -> Result<(), String>)] = &[
        ("justification_and_finalization", |s| {
            process_justification_and_finalization::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("rewards_and_penalties", |s| {
            process_rewards_and_penalties::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("registry_updates", |s| {
            process_registry_updates::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            process_slashings::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("eth1_data_reset", |s| {
            process_eth1_data_reset::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("effective_balance_updates", |s| {
            process_effective_balance_updates::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("slashings_reset", |s| {
            process_slashings_reset::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("randao_mixes_reset", |s| {
            process_randao_mixes_reset::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("historical_roots_update", |s| {
            process_historical_roots_update::<E>(s).map_err(|e| format!("{e}"))
        }),
        ("participation_record_updates", |s| {
            process_participation_record_updates::<E>(s).map_err(|e| format!("{e}"))
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "phase0",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "phase0/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn =
                Box::new(
                    move || match run_epoch_case::<E, _>(&case_dir, &case_name, &apply_fn) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                );

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

// ── altair sub-step walkers ───────────────────────────────────────────────────

fn enumerate_altair_ep_subs_mainnet(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
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
    use pharos_types::{MainnetEthSpec as E, altair::MainnetBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("inactivity_updates", |s| {
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        }),
        ("rewards_and_penalties", |s| {
            altair_rewards::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("registry_updates", |s| {
            altair_registry::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            altair_slashings::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("eth1_data_reset", |s| {
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        }),
        ("effective_balance_updates", |s| {
            altair_eff_bal::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("slashings_reset", |s| {
            altair_slash_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        }),
        ("randao_mixes_reset", |s| {
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("historical_roots_update", |s| {
            altair_hist_roots::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                s,
            )
            .map_err(|e| format!("{e}"))
        }),
        ("participation_flag_updates", |s| {
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
        }),
        ("sync_committee_updates", |s| {
            altair_sync_committee::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(s)
                .map_err(|e| format!("{e}"))
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "altair",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "altair/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_altair_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

fn enumerate_altair_ep_subs_minimal(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
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
    use pharos_types::{MinimalEthSpec as E, altair::MinimalBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("inactivity_updates", |s| {
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("rewards_and_penalties", |s| {
            altair_rewards::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("registry_updates", |s| {
            altair_registry::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            altair_slashings::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("eth1_data_reset", |s| {
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("effective_balance_updates", |s| {
            altair_eff_bal::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("slashings_reset", |s| {
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("randao_mixes_reset", |s| {
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("historical_roots_update", |s| {
            altair_hist_roots::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("participation_flag_updates", |s| {
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
        ("sync_committee_updates", |s| {
            altair_sync_committee::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(s)
                .map_err(|e| format!("{e}"))
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "altair",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "altair/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_altair_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

// ── bellatrix sub-step walkers ────────────────────────────────────────────────

fn enumerate_bellatrix_ep_subs_mainnet(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
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
    use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
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
        }),
        ("registry_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_registry::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("slashings", |s| {
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
        }),
        ("eth1_data_reset", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("effective_balance_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eff_bal::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_slash_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("historical_roots_update", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_hist_roots::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("participation_flag_updates", |s| {
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
        }),
        ("sync_committee_updates", |s| {
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
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "bellatrix",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "bellatrix/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_bellatrix_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

fn enumerate_bellatrix_ep_subs_minimal(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
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
    use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
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
        }),
        ("registry_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_registry::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("slashings", |s| {
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
        }),
        ("eth1_data_reset", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("effective_balance_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_eff_bal::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("historical_roots_update", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_hist_roots::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("participation_flag_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
        ("sync_committee_updates", |s| {
            let mut a = bellatrix_state_to_altair(s);
            altair_sync_committee::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_bellatrix_from_altair(s, a);
            Ok(())
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "bellatrix",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "bellatrix/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_bellatrix_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

// ── capella sub-step walkers ──────────────────────────────────────────────────

fn enumerate_capella_ep_subs_mainnet(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_registry_updates as altair_registry,
        process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_stf::capella::epoch::{
        process_historical_summaries_update, process_rewards_and_penalties_capella,
        process_slashings_capella,
    };
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_types::{MainnetEthSpec as E, capella::MainnetBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut a = capella_state_to_altair(s);
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
            process_rewards_and_penalties_capella::<
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
        }),
        ("registry_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_registry::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("slashings", |s| {
            process_slashings_capella::<
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
        }),
        ("eth1_data_reset", |s| {
            let mut a = capella_state_to_altair(s);
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("effective_balance_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_eff_bal::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut a = capella_state_to_altair(s);
            altair_slash_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut a = capella_state_to_altair(s);
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("historical_summaries_update", |s| {
            process_historical_summaries_update::<
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
        }),
        ("participation_flag_updates", |s| {
            let mut a = capella_state_to_altair(s);
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
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("sync_committee_updates", |s| {
            let mut a = capella_state_to_altair(s);
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
            update_capella_from_altair(s, a);
            Ok(())
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "capella",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "capella/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_capella_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

fn enumerate_capella_ep_subs_minimal(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_registry_updates as altair_registry,
        process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_stf::capella::epoch::{
        process_historical_summaries_update, process_rewards_and_penalties_capella,
        process_slashings_capella,
    };
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_types::{MinimalEthSpec as E, capella::MinimalBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut a = capella_state_to_altair(s);
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
            process_rewards_and_penalties_capella::<
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
        }),
        ("registry_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_registry::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("slashings", |s| {
            process_slashings_capella::<
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
        }),
        ("eth1_data_reset", |s| {
            let mut a = capella_state_to_altair(s);
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("effective_balance_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_eff_bal::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut a = capella_state_to_altair(s);
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut a = capella_state_to_altair(s);
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("historical_summaries_update", |s| {
            process_historical_summaries_update::<
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
        }),
        ("participation_flag_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
        ("sync_committee_updates", |s| {
            let mut a = capella_state_to_altair(s);
            altair_sync_committee::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(s, a);
            Ok(())
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "capella",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "capella/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_capella_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

// ── deneb sub-step walkers ────────────────────────────────────────────────────

fn enumerate_deneb_ep_subs_mainnet(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_stf::capella::epoch::process_historical_summaries_update;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_stf::deneb::epoch::registry_updates::process_registry_updates as process_registry_updates_deneb;
    use pharos_stf::deneb::epoch::{process_rewards_and_penalties_deneb, process_slashings_deneb};
    use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
    use pharos_types::{MainnetEthSpec as E, deneb::MainnetBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
            process_rewards_and_penalties_deneb::<
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
        }),
        ("registry_updates", |s| {
            process_registry_updates_deneb::<
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
            >(s, &E::default_runtime_config())
            .map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            process_slashings_deneb::<
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
        }),
        ("eth1_data_reset", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("effective_balance_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_eff_bal::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_slash_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("historical_summaries_update", |s| {
            let mut capella = deneb_state_to_capella(s);
            process_historical_summaries_update::<
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
            >(&mut capella)
            .map_err(|e| format!("{e}"))?;
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("participation_flag_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
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
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("sync_committee_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
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
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "deneb",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "deneb/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_deneb_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

fn enumerate_deneb_ep_subs_minimal(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
    use pharos_stf::altair::epoch::{
        process_effective_balance_updates as altair_eff_bal,
        process_eth1_data_reset as altair_eth1_reset,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_slashings_reset as altair_slash_reset,
        process_sync_committee_updates as altair_sync_committee,
    };
    use pharos_stf::capella::epoch::process_historical_summaries_update;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_stf::deneb::epoch::registry_updates::process_registry_updates as process_registry_updates_deneb;
    use pharos_stf::deneb::epoch::{process_rewards_and_penalties_deneb, process_slashings_deneb};
    use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
    use pharos_types::{MinimalEthSpec as E, deneb::MinimalBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
            process_rewards_and_penalties_deneb::<
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
        }),
        ("registry_updates", |s| {
            process_registry_updates_deneb::<
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
            >(s, &E::default_runtime_config())
            .map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            process_slashings_deneb::<
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
        }),
        ("eth1_data_reset", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("effective_balance_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_eff_bal::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("historical_summaries_update", |s| {
            let mut capella = deneb_state_to_capella(s);
            process_historical_summaries_update::<
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
            >(&mut capella)
            .map_err(|e| format!("{e}"))?;
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("participation_flag_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
        ("sync_committee_updates", |s| {
            let mut capella = deneb_state_to_capella(s);
            let mut a = capella_state_to_altair(&capella);
            altair_sync_committee::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(s, capella);
            Ok(())
        }),
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "deneb",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "deneb/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_deneb_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

// ── electra sub-step walkers (Phase 4a) ───────────────────────────────────────

fn enumerate_electra_ep_subs_mainnet(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
    use pharos_stf::altair::epoch::{
        process_eth1_data_reset as altair_eth1_reset,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_slashings_reset as altair_slash_reset,
    };
    use pharos_stf::capella::epoch::process_historical_summaries_update;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_stf::deneb::epoch::process_rewards_and_penalties_deneb;
    use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
    use pharos_stf::electra::epoch::registry_updates::process_registry_updates as process_registry_updates_electra;
    use pharos_stf::electra::epoch::slashings::process_slashings as process_slashings_electra;
    use pharos_stf::electra::helpers::{electra_state_to_deneb, update_electra_from_deneb};
    use pharos_types::{MainnetEthSpec as E, electra::MainnetBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_jf::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_inactivity::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
            let mut deneb = electra_state_to_deneb(s);
            process_rewards_and_penalties_deneb::<
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
            >(&mut deneb)
            .map_err(|e| format!("{e}"))?;
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("registry_updates", |s| {
            process_registry_updates_electra::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            process_slashings_electra::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        }),
        ("eth1_data_reset", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_eth1_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_slash_reset::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_randao::<8192, 16_777_216, 2048, 1_099_511_627_776, 65536, 8192, 4, 512, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("historical_summaries_update", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            process_historical_summaries_update::<
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
            >(&mut capella)
            .map_err(|e| format!("{e}"))?;
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("participation_flag_updates", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
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
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        // NOTE: `sync_committee_updates` is NOT registered for electra. The spec
        // call site is unmodified, but the underlying `get_next_sync_committee_indices`
        // is `[Modified in Electra:EIP7251]` (16-bit random byte +
        // `MAX_EFFECTIVE_BALANCE_ELECTRA`), so the altair delegation produces a wrong
        // next-sync-committee. It lands in Phase 4c (Task 4c.2). See
        // `docs/m12-electra-plan.md`.
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "electra",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "electra/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_electra_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

fn enumerate_electra_ep_subs_minimal(
    root: &Path,
    preset: &'static str,
    row_ordinal: u32,
    ordinal: &mut u32,
    tasks: &mut Vec<CaseTask>,
) {
    use pharos_stf::altair::epoch::{
        process_eth1_data_reset as altair_eth1_reset,
        process_inactivity_updates as altair_inactivity,
        process_justification_and_finalization as altair_jf,
        process_participation_flag_updates as altair_participation_flags,
        process_randao_mixes_reset as altair_randao, process_slashings_reset as altair_slash_reset,
    };
    use pharos_stf::capella::epoch::process_historical_summaries_update;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_stf::deneb::epoch::process_rewards_and_penalties_deneb;
    use pharos_stf::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
    use pharos_stf::electra::epoch::registry_updates::process_registry_updates as process_registry_updates_electra;
    use pharos_stf::electra::epoch::slashings::process_slashings as process_slashings_electra;
    use pharos_stf::electra::helpers::{electra_state_to_deneb, update_electra_from_deneb};
    use pharos_types::{MinimalEthSpec as E, electra::MinimalBeaconState as S};

    type ApplyFn = fn(&mut S) -> Result<(), String>;
    let subs: &[(&'static str, ApplyFn)] = &[
        ("justification_and_finalization", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_jf::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("inactivity_updates", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_inactivity::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("rewards_and_penalties", |s| {
            let mut deneb = electra_state_to_deneb(s);
            process_rewards_and_penalties_deneb::<
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
            >(&mut deneb)
            .map_err(|e| format!("{e}"))?;
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("registry_updates", |s| {
            process_registry_updates_electra::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        }),
        ("slashings", |s| {
            process_slashings_electra::<
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
            >(s)
            .map_err(|e| format!("{e}"))
        }),
        ("eth1_data_reset", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_eth1_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("slashings_reset", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_slash_reset::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("randao_mixes_reset", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_randao::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(&mut a)
                .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("historical_summaries_update", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            process_historical_summaries_update::<
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
            >(&mut capella)
            .map_err(|e| format!("{e}"))?;
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        ("participation_flag_updates", |s| {
            let mut deneb = electra_state_to_deneb(s);
            let mut capella = deneb_state_to_capella(&deneb);
            let mut a = capella_state_to_altair(&capella);
            altair_participation_flags::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut a,
            )
            .map_err(|e| format!("{e}"))?;
            update_capella_from_altair(&mut capella, a);
            update_deneb_from_capella(&mut deneb, capella);
            update_electra_from_deneb(s, deneb);
            Ok(())
        }),
        // NOTE: `sync_committee_updates` is NOT registered for electra (electra-delta
        // in `get_next_sync_committee_indices`); lands in Phase 4c. See the mainnet
        // walker for the full rationale.
    ];

    for (sub, apply_fn) in subs {
        let cases: Vec<(PathBuf, _)> = walk_category(
            root,
            preset,
            "electra",
            "epoch_processing",
            Some(sub),
            epoch_walk_opts(),
        )
        .collect();

        for (case_dir, _meta) in cases {
            let case_ordinal = *ordinal;
            *ordinal += 1;
            let case_name = format!(
                "electra/epoch_processing/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let apply_fn = *apply_fn;

            let run: CaseFn = Box::new(move || {
                match run_electra_epoch_case::<S, E, _>(&case_dir, &case_name, &apply_fn) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            });

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }
}

// ── sub-routine runner ────────────────────────────────────────────────────────

fn epoch_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}
enum CaseResult {
    Pass,
    Fail(String),
}

fn run_epoch_case<E, F>(case_dir: &Path, case_name: &str, apply: &F) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + pharos_ssz::Decode,
    F: Fn(&mut E::BeaconState) -> Result<(), String>,
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
fn run_altair_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &F) -> CaseResult
where
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    E: EthSpec<AltairBeaconState = S>,
    F: Fn(&mut S) -> Result<(), String>,
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

fn run_bellatrix_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &F) -> CaseResult
where
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    E: EthSpec<BellatrixBeaconState = S>,
    F: Fn(&mut S) -> Result<(), String>,
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
fn run_electra_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &F) -> CaseResult
where
    E: EthSpec<ElectraBeaconState = S>,
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    F: Fn(&mut S) -> Result<(), String>,
{
    let (pre, post) = match crate::fixture_walker::load_pre_post_electra_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut pre_inner = match E::into_electra_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not electra state")),
    };

    let result = apply(&mut pre_inner);

    let post_bytes = post.map(|p| p.as_ssz_bytes());
    let current_bytes = E::electra_into_state(pre_inner).as_ssz_bytes();

    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after electra epoch sub-routine"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}
fn run_capella_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &F) -> CaseResult
where
    E: EthSpec<CapellaBeaconState = S>,
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    F: Fn(&mut S) -> Result<(), String>,
{
    let (pre, post) = match load_pre_post_capella_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut pre_inner = match E::into_capella_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not capella state")),
    };

    let result = apply(&mut pre_inner);

    let post_bytes = post.map(|p| p.as_ssz_bytes());
    let current_bytes = E::capella_into_state(pre_inner).as_ssz_bytes();

    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after capella epoch sub-routine"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}
fn run_deneb_epoch_case<S, E, F>(case_dir: &Path, case_name: &str, apply: &F) -> CaseResult
where
    E: EthSpec<DenebBeaconState = S>,
    S: pharos_ssz::Decode + pharos_ssz::Encode,
    F: Fn(&mut S) -> Result<(), String>,
{
    let (pre, post) = match load_pre_post_deneb_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut pre_inner = match E::into_deneb_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not deneb state")),
    };

    let result = apply(&mut pre_inner);

    let post_bytes = post.map(|p| p.as_ssz_bytes());
    let current_bytes = E::deneb_into_state(pre_inner).as_ssz_bytes();

    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after deneb epoch sub-routine"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}
