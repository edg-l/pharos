//! Light-client conformance dispatcher (altair through electra).
//!
//! Covers two sub-categories:
//!   - `single_merkle_proof` — verify Merkle branch proofs against `BeaconState`.
//!   - `sync`               — full light-client sync protocol step runner.
//!
//! # single_merkle_proof
//!
//! Fixture layout (non-standard — no `pyspec_tests` directory):
//! ```text
//! tests/{preset}/altair/light_client/single_merkle_proof/BeaconState/{case_name}/
//!   object.ssz_snappy   — altair BeaconState
//!   proof.yaml          — leaf, leaf_index (generalized index), branch
//! ```
//! Test: `is_valid_merkle_branch(leaf, branch, depth, index, hash_tree_root(object))`.
//!
//! # sync
//!
//! Fixture layout (standard `pyspec_tests` directory):
//! ```text
//! tests/{preset}/altair/light_client/sync/pyspec_tests/{case_name}/
//!   meta.yaml          — genesis_validators_root, trusted_block_root, fork digests
//!   bootstrap.ssz_snappy
//!   steps.yaml         — process_update / force_update steps
//!   update_*.ssz_snappy
//! ```

use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Mutex;

use pharos_ssz::{Decode, Encode, SszVector, TreeHash};
use pharos_stf::altair::light_client::{
    initialize_light_client_store, process_light_client_store_force_update,
    process_light_client_update,
};
use pharos_stf::{
    AltairDispatch, AltairDispatchBounds, CapellaDispatch, CapellaDispatchBounds, DenebDispatch,
    DenebDispatchBounds, ElectraDispatch, ElectraDispatchBounds, FuluDispatch, FuluDispatchBounds,
    NullExecutionEngine,
};
use pharos_storage::{StorageError, Store as StoreT};
use pharos_types::{
    BeaconSpec, MainnetBeaconSpec, MinimalBeaconSpec,
    altair::light_client::{
        FINALITY_BRANCH_DEPTH, LightClientStore, LightClientUpdate as AltairLCUpdate,
        NEXT_SYNC_COMMITTEE_BRANCH_DEPTH,
    },
    capella::ExecutionPayloadHeader as CapellaExecutionPayloadHeader,
    capella::light_client::{
        LightClientBootstrap as CapellaLCBootstrap, LightClientHeader as CapellaLCHeader,
        LightClientUpdate as CapellaLCUpdate,
    },
    config::RuntimeConfig,
    deneb::execution_payload::ExecutionPayloadHeader as DenebExecutionPayloadHeader,
    deneb::light_client::{
        LightClientBootstrap as DenebLCBootstrap, LightClientHeader as DenebLCHeader,
        LightClientUpdate as DenebLCUpdate,
    },
    electra::light_client::{
        FINALITY_BRANCH_DEPTH_ELECTRA, LightClientBootstrap as ElectraLCBootstrap,
        LightClientHeader as ElectraLCHeader, LightClientUpdate as ElectraLCUpdate,
        NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA,
    },
    phase0::primitives::{Root, Slot},
    views::{BeaconBlockView, BeaconStateView, SignedBeaconBlockView},
};
use pharos_utils::Bytes32;

use crate::fixture_walker::{WalkOpts, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per light-client test case for a single `(fork, preset)` row,
/// in the same walk-order as the corresponding `run_light_client_*` function.
/// Called by the flat work-pool.
///
/// Walk order: `single_merkle_proof` cases first, then `sync` cases (mirrors
/// `run_light_client_altair/capella/deneb/electra_*`).
///
/// For capella, deneb, and electra, `single_merkle_proof` has two sub-dirs:
/// `BeaconState/` then `BeaconBlockBody/` (in that order, same as the existing runner).
///
/// Supported forks: `"altair"`, `"capella"`, `"deneb"`, `"electra"`.
pub fn enumerate_light_client(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let mut tasks: Vec<CaseTask> = Vec::new();
    let mut ordinal: u32 = 0;

    // ── single_merkle_proof sub-sweep ─────────────────────────────────────────
    //
    // altair: one sub-dir (BeaconState).
    // capella/deneb: two sub-dirs (BeaconState, BeaconBlockBody) in that order.
    let smp_sub_dirs: &[&str] = match fork {
        "altair" => &["BeaconState"],
        _ => &["BeaconState", "BeaconBlockBody"],
    };

    for &sub_dir_name in smp_sub_dirs {
        let smp_dir = root
            .join(preset)
            .join(fork)
            .join("light_client")
            .join("single_merkle_proof")
            .join(sub_dir_name);

        if !smp_dir.is_dir() {
            continue;
        }

        let entries = match std::fs::read_dir(&smp_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let case_dir = entry.path();
            if !case_dir.is_dir() {
                continue;
            }
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!(
                "{fork}/light_client/single_merkle_proof/{preset}/{sub_dir_name}/{}",
                dir_name(&case_dir)
            );

            let run: CaseFn = match (fork, sub_dir_name, preset) {
                ("altair", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("altair", "BeaconState", _) => {
                    Box::new(move || {
                        match run_single_merkle_proof_case::<pharos_types::MinimalBeaconSpec>(
                            &case_dir, &case_name,
                        ) {
                            CaseResult::Pass => CaseOutcome::Pass,

                            CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                        }
                    })
                }
                ("capella", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_capella_state_case::<
                        pharos_types::MainnetBeaconSpec,
                    >(&case_dir, &case_name)
                    {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "BeaconState", _) => Box::new(move || {
                    match run_single_merkle_proof_capella_state_case::<
                        pharos_types::MinimalBeaconSpec,
                    >(&case_dir, &case_name)
                    {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "BeaconBlockBody", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_body_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("capella", "BeaconBlockBody", _) => Box::new(move || {
                    match run_single_merkle_proof_body_case::<pharos_types::MinimalBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_deneb_state_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconState", _) => Box::new(move || {
                    match run_single_merkle_proof_deneb_state_case::<pharos_types::MinimalBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconBlockBody", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_deneb_body_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("deneb", "BeaconBlockBody", _) => Box::new(move || {
                    match run_single_merkle_proof_deneb_body_case::<pharos_types::MinimalBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("electra", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_electra_state_case::<
                        pharos_types::MainnetBeaconSpec,
                    >(&case_dir, &case_name)
                    {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("electra", "BeaconState", _) => Box::new(move || {
                    match run_single_merkle_proof_electra_state_case::<
                        pharos_types::MinimalBeaconSpec,
                    >(&case_dir, &case_name)
                    {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("electra", "BeaconBlockBody", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_electra_body_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("electra", "BeaconBlockBody", _) => Box::new(move || {
                    match run_single_merkle_proof_electra_body_case::<pharos_types::MinimalBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("fulu", "BeaconState", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_fulu_state_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("fulu", "BeaconState", _) => Box::new(move || {
                    match run_single_merkle_proof_fulu_state_case::<pharos_types::MinimalBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                // Fulu `BeaconBlockBody` IS the electra body (re-export), so the
                // electra body merkle-proof case decodes it unchanged.
                ("fulu", "BeaconBlockBody", "mainnet") => Box::new(move || {
                    match run_single_merkle_proof_electra_body_case::<pharos_types::MainnetBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                ("fulu", "BeaconBlockBody", _) => Box::new(move || {
                    match run_single_merkle_proof_electra_body_case::<pharos_types::MinimalBeaconSpec>(
                        &case_dir, &case_name,
                    ) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    }
                }),
                _ => Box::new(move || {
                    CaseOutcome::Fail(format!("{case_name}: unsupported fork/preset combination"))
                }),
            };

            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }

    // ── sync sub-sweep ────────────────────────────────────────────────────────

    let sync_cases: Vec<(std::path::PathBuf, _)> = walk_category(
        root,
        preset,
        fork,
        "light_client",
        Some("sync"),
        WalkOpts::default(),
    )
    .collect();

    for (case_dir, _meta) in sync_cases {
        // Filter out gloas and post-fulu cross-fork cases; they reference fork
        // version 0x07 (gloas), which is not implemented.
        let case_dirname = dir_name(&case_dir);
        if case_dirname.contains("gloas") {
            continue;
        }

        let case_ordinal = ordinal;
        ordinal += 1;
        let case_name = format!("{fork}/light_client/sync/{preset}/{case_dirname}");

        let run: CaseFn = match (fork, preset) {
            ("altair", "mainnet") => {
                Box::new(move || match run_sync_case_mainnet(&case_dir, &case_name) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                })
            }
            ("altair", _) => Box::new(move || match run_sync_case_minimal(&case_dir, &case_name) {
                CaseResult::Pass => CaseOutcome::Pass,
                CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
            }),
            ("capella", "mainnet") => {
                Box::new(
                    move || match run_sync_case_capella_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("capella", _) => {
                Box::new(
                    move || match run_sync_case_capella_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("deneb", "mainnet") => {
                Box::new(
                    move || match run_sync_case_deneb_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("deneb", _) => {
                Box::new(
                    move || match run_sync_case_deneb_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("electra", "mainnet") => {
                Box::new(
                    move || match run_sync_case_electra_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("electra", _) => {
                Box::new(
                    move || match run_sync_case_electra_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("fulu", "mainnet") => {
                Box::new(
                    move || match run_sync_case_fulu_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("fulu", _) => {
                Box::new(
                    move || match run_sync_case_fulu_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,

                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            _ => Box::new(move || {
                CaseOutcome::Fail(format!("{case_name}: unsupported fork/preset combination"))
            }),
        };

        tasks.push(CaseTask {
            row_ordinal,
            case_ordinal,
            run,
        });
    }

    // ── update_ranking sub-sweep ──────────────────────────────────────────────
    //
    // One case per fork (`update_ranking/pyspec_tests/update_ranking/`).
    // Verifies that the N updates are in descending `is_better_update` order:
    // for all consecutive i < j, updates[i] must rank better than updates[j].
    let update_ranking_cases: Vec<(std::path::PathBuf, _)> = walk_category(
        root,
        preset,
        fork,
        "light_client",
        Some("update_ranking"),
        WalkOpts::default(),
    )
    .collect();

    for (case_dir, _meta) in update_ranking_cases {
        let case_ordinal = ordinal;
        ordinal += 1;
        let case_name = format!(
            "{fork}/light_client/update_ranking/{preset}/{}",
            dir_name(&case_dir)
        );

        let run: CaseFn = match (fork, preset) {
            ("altair", "mainnet") => {
                Box::new(
                    move || match run_update_ranking_altair_mainnet(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("altair", _) => {
                Box::new(
                    move || match run_update_ranking_altair_minimal(&case_dir, &case_name) {
                        CaseResult::Pass => CaseOutcome::Pass,
                        CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                    },
                )
            }
            ("capella", "mainnet") => Box::new(move || {
                match run_update_ranking_capella::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("capella", _) => Box::new(move || {
                match run_update_ranking_capella::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("deneb", "mainnet") => Box::new(move || {
                match run_update_ranking_deneb::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("deneb", _) => Box::new(move || {
                match run_update_ranking_deneb::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            // Electra reuses the deneb header type; branch depths are deeper but
            // the ranking algorithm fields are identical.
            ("electra", "mainnet") => Box::new(move || {
                match run_update_ranking_electra::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("electra", _) => Box::new(move || {
                match run_update_ranking_electra::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            // Fulu uses the same update types as electra.
            ("fulu", "mainnet") => Box::new(move || {
                match run_update_ranking_electra::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("fulu", _) => Box::new(move || {
                match run_update_ranking_electra::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            _ => Box::new(move || {
                CaseOutcome::Fail(format!("{case_name}: unsupported fork/preset combination"))
            }),
        };

        tasks.push(CaseTask {
            row_ordinal,
            case_ordinal,
            run,
        });
    }

    // ── data_collection sub-sweep ─────────────────────────────────────────────
    //
    // Tests the full-node LC server's data collection: blocks are processed
    // through the STF and LC state (bootstrap, best_update, finality/optimistic
    // update) is verified after each `new_head` step.
    let data_collection_cases: Vec<(std::path::PathBuf, _)> = walk_category(
        root,
        preset,
        fork,
        "light_client",
        Some("data_collection"),
        WalkOpts::default(),
    )
    .collect();

    for (case_dir, _meta) in data_collection_cases {
        let case_ordinal = ordinal;
        ordinal += 1;
        let case_name = format!(
            "{fork}/light_client/data_collection/{preset}/{}",
            dir_name(&case_dir)
        );

        let run: CaseFn = match (fork, preset) {
            ("altair", "mainnet") => Box::new(move || {
                match run_data_collection_altair::<pharos_types::MainnetBeaconSpec>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("altair", _) => Box::new(move || {
                match run_data_collection_altair::<pharos_types::MinimalBeaconSpec>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("capella", "mainnet") => Box::new(move || {
                match run_data_collection_capella::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("capella", _) => Box::new(move || {
                match run_data_collection_capella::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("deneb", "mainnet") => Box::new(move || {
                match run_data_collection_deneb::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("deneb", _) => Box::new(move || {
                match run_data_collection_deneb::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("electra", "mainnet") => Box::new(move || {
                match run_data_collection_electra::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("electra", _) => Box::new(move || {
                match run_data_collection_electra::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("fulu", "mainnet") => Box::new(move || {
                match run_data_collection_fulu::<pharos_types::MainnetBeaconSpec, 512, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            ("fulu", _) => Box::new(move || {
                match run_data_collection_fulu::<pharos_types::MinimalBeaconSpec, 32, 256, 32>(
                    &case_dir, &case_name,
                ) {
                    CaseResult::Pass => CaseOutcome::Pass,
                    CaseResult::Fail(msg) => CaseOutcome::Fail(msg),
                }
            }),
            _ => Box::new(move || {
                CaseOutcome::Fail(format!("{case_name}: unsupported fork/preset combination"))
            }),
        };

        tasks.push(CaseTask {
            row_ordinal,
            case_ordinal,
            run,
        });
    }

    tasks
}

// ── update_ranking runners ────────────────────────────────────────────────────

/// Extracted fields from any fork's `LightClientUpdate` needed for `is_better_update`.
#[allow(dead_code)]
struct UpdateRankFields {
    /// Number of active participants in sync_aggregate.
    n_participants: u64,
    /// Whether `attested_header.beacon.slot` is in the same sync committee period
    /// as `signature_slot` (relevant sync committee criterion).
    relevant_sync_committee: bool,
    /// Whether this update has a non-zero `finality_branch`.
    is_finality_update: bool,
    /// Whether `finalized_header.beacon.slot` is in the same period as
    /// `attested_header.beacon.slot` (sync committee finality criterion).
    sync_committee_finality: bool,
    attested_slot: u64,
    signature_slot: u64,
}

fn is_better_update_with_size(
    new: &UpdateRankFields,
    old: &UpdateRankFields,
    sc_size: u64,
) -> bool {
    let new_super = new.n_participants * 3 >= sc_size * 2;
    let old_super = old.n_participants * 3 >= sc_size * 2;
    if new_super != old_super {
        return new_super;
    }
    if !new_super && new.n_participants != old.n_participants {
        return new.n_participants > old.n_participants;
    }
    if new.relevant_sync_committee != old.relevant_sync_committee {
        return new.relevant_sync_committee;
    }
    if new.is_finality_update != old.is_finality_update {
        return new.is_finality_update;
    }
    if new.is_finality_update && new.sync_committee_finality != old.sync_committee_finality {
        return new.sync_committee_finality;
    }
    if new.n_participants != old.n_participants {
        return new.n_participants > old.n_participants;
    }
    if new.attested_slot != old.attested_slot {
        return new.attested_slot < old.attested_slot;
    }
    new.signature_slot < old.signature_slot
}

fn count_bits<const N: u64>(bits: &pharos_ssz::Bitvector<N>) -> u64 {
    bits.num_set_bits() as u64
}

fn extract_altair_update_fields<E: BeaconSpec, const S: u64>(
    u: &AltairLCUpdate<S>,
) -> UpdateRankFields
where
    Bytes32: Default + Clone + PartialEq,
{
    let n = count_bits(&u.sync_aggregate.sync_committee_bits);
    let is_sc = u.next_sync_committee_branch.as_slice() != vec![Bytes32::default(); 5].as_slice();
    let attested_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<
        E,
    >(u.attested_header.beacon.slot);
    let sig_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.signature_slot,
    );
    let relevant = is_sc && attested_period == sig_period;
    let is_fin = u.finality_branch.as_slice() != vec![Bytes32::default(); 6].as_slice();
    let fin_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.finalized_header.beacon.slot,
    );
    let sc_fin = is_fin && (fin_period == attested_period);
    UpdateRankFields {
        n_participants: n,
        relevant_sync_committee: relevant,
        is_finality_update: is_fin,
        sync_committee_finality: sc_fin,
        attested_slot: u.attested_header.beacon.slot.0,
        signature_slot: u.signature_slot.0,
    }
}

fn extract_capella_update_fields<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    u: &CapellaLCUpdate<S, B, X>,
) -> UpdateRankFields
where
    Bytes32: Default + Clone + PartialEq,
{
    let n = count_bits(&u.sync_aggregate.sync_committee_bits);
    let is_sc = u.next_sync_committee_branch.as_slice()
        != vec![Bytes32::default(); NEXT_SYNC_COMMITTEE_BRANCH_DEPTH as usize].as_slice();
    let attested_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<
        E,
    >(u.attested_header.beacon.slot);
    let sig_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.signature_slot,
    );
    let relevant = is_sc && attested_period == sig_period;
    let is_fin = u.finality_branch.as_slice()
        != vec![Bytes32::default(); FINALITY_BRANCH_DEPTH as usize].as_slice();
    let fin_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.finalized_header.beacon.slot,
    );
    let sc_fin = is_fin && (fin_period == attested_period);
    UpdateRankFields {
        n_participants: n,
        relevant_sync_committee: relevant,
        is_finality_update: is_fin,
        sync_committee_finality: sc_fin,
        attested_slot: u.attested_header.beacon.slot.0,
        signature_slot: u.signature_slot.0,
    }
}

fn extract_deneb_update_fields<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    u: &DenebLCUpdate<S, B, X>,
) -> UpdateRankFields
where
    Bytes32: Default + Clone + PartialEq,
{
    let n = count_bits(&u.sync_aggregate.sync_committee_bits);
    let is_sc = u.next_sync_committee_branch.as_slice()
        != vec![Bytes32::default(); NEXT_SYNC_COMMITTEE_BRANCH_DEPTH as usize].as_slice();
    let attested_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<
        E,
    >(u.attested_header.beacon.slot);
    let sig_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.signature_slot,
    );
    let relevant = is_sc && attested_period == sig_period;
    let is_fin = u.finality_branch.as_slice()
        != vec![Bytes32::default(); FINALITY_BRANCH_DEPTH as usize].as_slice();
    let fin_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.finalized_header.beacon.slot,
    );
    let sc_fin = is_fin && (fin_period == attested_period);
    UpdateRankFields {
        n_participants: n,
        relevant_sync_committee: relevant,
        is_finality_update: is_fin,
        sync_committee_finality: sc_fin,
        attested_slot: u.attested_header.beacon.slot.0,
        signature_slot: u.signature_slot.0,
    }
}

fn extract_electra_update_fields<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    u: &ElectraLCUpdate<S, B, X>,
) -> UpdateRankFields
where
    Bytes32: Default + Clone + PartialEq,
{
    let n = count_bits(&u.sync_aggregate.sync_committee_bits);
    let is_sc = u.next_sync_committee_branch.as_slice()
        != vec![Bytes32::default(); NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA as usize].as_slice();
    let attested_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<
        E,
    >(u.attested_header.beacon.slot);
    let sig_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.signature_slot,
    );
    let relevant = is_sc && attested_period == sig_period;
    let is_fin = u.finality_branch.as_slice()
        != vec![Bytes32::default(); FINALITY_BRANCH_DEPTH_ELECTRA as usize].as_slice();
    let fin_period = pharos_stf::altair::light_client::compute_sync_committee_period_at_slot::<E>(
        u.finalized_header.beacon.slot,
    );
    let sc_fin = is_fin && (fin_period == attested_period);
    UpdateRankFields {
        n_participants: n,
        relevant_sync_committee: relevant,
        is_finality_update: is_fin,
        sync_committee_finality: sc_fin,
        attested_slot: u.attested_header.beacon.slot.0,
        signature_slot: u.signature_slot.0,
    }
}

fn run_update_ranking_core<U>(
    case_dir: &Path,
    case_name: &str,
    sc_size: u64,
    load_update: impl Fn(&Path, &str) -> Result<U, String>,
    extract: impl Fn(&U) -> UpdateRankFields,
) -> CaseResult {
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read meta.yaml: {e}")),
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}")),
    };
    let updates_count = match meta_val.get("updates_count").and_then(|v| v.as_u64()) {
        Some(n) => n as usize,
        None => return CaseResult::Fail(format!("{case_name}: missing updates_count")),
    };
    if updates_count < 2 {
        return CaseResult::Pass;
    }

    let mut updates: Vec<U> = Vec::with_capacity(updates_count);
    for i in 0..updates_count {
        let filename = format!("updates_{i}.ssz_snappy");
        match load_update(case_dir, &filename) {
            Ok(u) => updates.push(u),
            Err(e) => return CaseResult::Fail(format!("{case_name}: load updates_{i}: {e}")),
        }
    }

    // Verify descending precedence: updates[i] must be better than updates[i+1].
    for i in 0..updates_count - 1 {
        let new_fields = extract(&updates[i]);
        let old_fields = extract(&updates[i + 1]);
        if !is_better_update_with_size(&new_fields, &old_fields, sc_size) {
            return CaseResult::Fail(format!(
                "{case_name}: is_better_update(updates[{i}], updates[{}]) returned false",
                i + 1
            ));
        }
    }
    CaseResult::Pass
}

fn run_update_ranking_altair_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_update_ranking_altair_impl::<MainnetBeaconSpec, 512>(case_dir, case_name)
}

fn run_update_ranking_altair_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_update_ranking_altair_impl::<MinimalBeaconSpec, 32>(case_dir, case_name)
}

fn run_update_ranking_altair_impl<E: BeaconSpec, const S: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    AltairLCUpdate<S>: Decode + Clone,
    Bytes32: Default + Clone + PartialEq,
{
    run_update_ranking_core(
        case_dir,
        case_name,
        S,
        |dir, filename| {
            load_ssz_snappy::<AltairLCUpdate<S>>(dir, filename).map_err(|e| e.to_string())
        },
        |u| extract_altair_update_fields::<E, S>(u),
    )
}

fn run_update_ranking_capella<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    CapellaLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + Clone + PartialEq,
{
    run_update_ranking_core(
        case_dir,
        case_name,
        S,
        |dir, filename| {
            load_ssz_snappy::<CapellaLCUpdate<S, B, X>>(dir, filename).map_err(|e| e.to_string())
        },
        |u| extract_capella_update_fields::<E, S, B, X>(u),
    )
}

fn run_update_ranking_deneb<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    DenebLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + Clone + PartialEq,
{
    run_update_ranking_core(
        case_dir,
        case_name,
        S,
        |dir, filename| {
            load_ssz_snappy::<DenebLCUpdate<S, B, X>>(dir, filename).map_err(|e| e.to_string())
        },
        |u| extract_deneb_update_fields::<E, S, B, X>(u),
    )
}

fn run_update_ranking_electra<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    ElectraLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + Clone + PartialEq,
{
    run_update_ranking_core(
        case_dir,
        case_name,
        S,
        |dir, filename| {
            load_ssz_snappy::<ElectraLCUpdate<S, B, X>>(dir, filename).map_err(|e| e.to_string())
        },
        |u| extract_electra_update_fields::<E, S, B, X>(u),
    )
}

// ── data_collection runners ───────────────────────────────────────────────────
//
// The data_collection fixtures test the full-node LC server's data collection.
// Each case requires processing `SignedBeaconBlock`s through the STF and verifying
// the LC state after each `new_head` signal. This requires types from all four
// forks' block/state pipelines and is fork-specific.
//
// The checks verify: bootstraps, best_updates per period, latest finality/optimistic
// updates. Each check compares SSZ-encoded expected data against what the
// runner would produce.

fn run_data_collection_altair<E: BeaconSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::AltairBeaconState:
        Decode + AltairDispatch<E> + AltairDispatchBounds<E> + BeaconStateView + Clone,
    E::AltairSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView + Clone,
    E::AltairLightClientBootstrap: Decode + Encode + Clone,
    E::AltairLightClientUpdate: Decode + Encode + Clone,
    E::AltairLightClientFinalityUpdate: Decode + Encode + Clone,
    E::AltairLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_impl_altair::<E>(case_dir, case_name)
}

fn run_data_collection_capella<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::CapellaBeaconState: Decode
        + CapellaDispatch<E, NullExecutionEngine>
        + CapellaDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::CapellaSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView + Clone,
    E::CapellaLightClientBootstrap: Decode + Encode + Clone,
    E::CapellaLightClientUpdate: Decode + Encode + Clone,
    E::CapellaLightClientFinalityUpdate: Decode + Encode + Clone,
    E::CapellaLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_impl_capella::<E, S, B, X>(case_dir, case_name)
}

fn run_data_collection_deneb<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::DenebBeaconState: Decode
        + DenebDispatch<E, NullExecutionEngine>
        + DenebDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::DenebSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::DenebBeaconBlock: BeaconBlockView + Clone,
    E::DenebLightClientBootstrap: Decode + Encode + Clone,
    E::DenebLightClientUpdate: Decode + Encode + Clone,
    E::DenebLightClientFinalityUpdate: Decode + Encode + Clone,
    E::DenebLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_impl_deneb::<E, S, B, X>(case_dir, case_name)
}

fn run_data_collection_electra<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::ElectraBeaconState: Decode
        + ElectraDispatch<E, NullExecutionEngine>
        + ElectraDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::ElectraSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::ElectraBeaconBlock>,
    E::ElectraBeaconBlock: BeaconBlockView + Clone,
    E::ElectraLightClientBootstrap: Decode + Encode + Clone,
    E::ElectraLightClientUpdate: Decode + Encode + Clone,
    E::ElectraLightClientFinalityUpdate: Decode + Encode + Clone,
    E::ElectraLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_impl_electra::<E, S, B, X>(case_dir, case_name)
}

fn run_data_collection_fulu<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::FuluBeaconState: Decode
        + FuluDispatch<E, NullExecutionEngine>
        + FuluDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::FuluSignedBeaconBlock: Decode + Clone + SignedBeaconBlockView<Message = E::FuluBeaconBlock>,
    E::FuluBeaconBlock: BeaconBlockView + Clone,
    E::ElectraLightClientBootstrap: Decode + Encode + Clone,
    E::ElectraLightClientUpdate: Decode + Encode + Clone,
    E::ElectraLightClientFinalityUpdate: Decode + Encode + Clone,
    E::ElectraLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_impl_fulu::<E, S, B, X>(case_dir, case_name)
}

// ── data_collection: in-memory LC store + per-fork impl ──────────────────────

/// Minimal in-memory `Store<E>` that backs the data_collection conformance
/// runner. Only the light-client LC snapshot methods (put/get bootstrap,
/// update, finality_update, optimistic_update for each fork) are
/// implemented. All other methods are unreachable since `call_update_lc_snapshots`
/// never calls them.
struct LcMemStore<E: BeaconSpec> {
    altair_bootstraps: Mutex<HashMap<Root, E::AltairLightClientBootstrap>>,
    altair_updates: Mutex<HashMap<u64, E::AltairLightClientUpdate>>,
    altair_fin: Mutex<Option<E::AltairLightClientFinalityUpdate>>,
    altair_opt: Mutex<Option<E::AltairLightClientOptimisticUpdate>>,
    capella_bootstraps: Mutex<HashMap<Root, E::CapellaLightClientBootstrap>>,
    capella_updates: Mutex<HashMap<u64, E::CapellaLightClientUpdate>>,
    capella_fin: Mutex<Option<E::CapellaLightClientFinalityUpdate>>,
    capella_opt: Mutex<Option<E::CapellaLightClientOptimisticUpdate>>,
    deneb_bootstraps: Mutex<HashMap<Root, E::DenebLightClientBootstrap>>,
    deneb_updates: Mutex<HashMap<u64, E::DenebLightClientUpdate>>,
    deneb_fin: Mutex<Option<E::DenebLightClientFinalityUpdate>>,
    deneb_opt: Mutex<Option<E::DenebLightClientOptimisticUpdate>>,
    electra_bootstraps: Mutex<HashMap<Root, E::ElectraLightClientBootstrap>>,
    electra_updates: Mutex<HashMap<u64, E::ElectraLightClientUpdate>>,
    electra_fin: Mutex<Option<E::ElectraLightClientFinalityUpdate>>,
    electra_opt: Mutex<Option<E::ElectraLightClientOptimisticUpdate>>,
    _phantom: PhantomData<E>,
}

impl<E: BeaconSpec> LcMemStore<E> {
    fn new() -> Self {
        Self {
            altair_bootstraps: Mutex::new(HashMap::new()),
            altair_updates: Mutex::new(HashMap::new()),
            altair_fin: Mutex::new(None),
            altair_opt: Mutex::new(None),
            capella_bootstraps: Mutex::new(HashMap::new()),
            capella_updates: Mutex::new(HashMap::new()),
            capella_fin: Mutex::new(None),
            capella_opt: Mutex::new(None),
            deneb_bootstraps: Mutex::new(HashMap::new()),
            deneb_updates: Mutex::new(HashMap::new()),
            deneb_fin: Mutex::new(None),
            deneb_opt: Mutex::new(None),
            electra_bootstraps: Mutex::new(HashMap::new()),
            electra_updates: Mutex::new(HashMap::new()),
            electra_fin: Mutex::new(None),
            electra_opt: Mutex::new(None),
            _phantom: PhantomData,
        }
    }
}

impl<E: BeaconSpec> StoreT<E> for LcMemStore<E> {
    fn put_block(&self, _root: Root, _block: &E::SignedBeaconBlock) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_block")
    }
    fn get_block(&self, _root: &Root) -> Result<Option<E::SignedBeaconBlock>, StorageError> {
        unreachable!("LcMemStore: get_block")
    }
    fn get_blocks_by_range(
        &self,
        _s: Slot,
        _c: u64,
    ) -> Result<Vec<E::SignedBeaconBlock>, StorageError> {
        unreachable!("LcMemStore: get_blocks_by_range")
    }
    fn put_state(&self, _root: Root, _state: &E::BeaconState) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_state")
    }
    fn get_state(&self, _root: &Root) -> Result<Option<E::BeaconState>, StorageError> {
        unreachable!("LcMemStore: get_state")
    }
    fn put_forkchoice_snapshot(
        &self,
        _snap: &pharos_storage::ForkChoiceSnapshot,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_forkchoice_snapshot")
    }
    fn get_forkchoice_snapshot(
        &self,
    ) -> Result<Option<pharos_storage::ForkChoiceSnapshot>, StorageError> {
        unreachable!("LcMemStore: get_forkchoice_snapshot")
    }
    fn put_metadata(&self, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_metadata")
    }
    fn get_metadata(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        unreachable!("LcMemStore: get_metadata")
    }
    fn write_block_transition(
        &self,
        _batch: pharos_storage::BlockTransition<E>,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: write_block_transition")
    }
    fn payload_status(
        &self,
        _root: Root,
    ) -> Result<Option<pharos_types::PayloadStatus>, StorageError> {
        unreachable!("LcMemStore: payload_status")
    }
    fn payload_statuses_iter(
        &self,
    ) -> Result<Vec<(Root, pharos_types::PayloadStatus)>, StorageError> {
        unreachable!("LcMemStore: payload_statuses_iter")
    }
    fn put_cold_block(
        &self,
        _root: Root,
        _block: &E::SignedBeaconBlock,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_cold_block")
    }
    fn get_cold_block(&self, _root: &Root) -> Result<Option<E::SignedBeaconBlock>, StorageError> {
        unreachable!("LcMemStore: get_cold_block")
    }
    fn put_cold_state(
        &self,
        _restore_slot: Slot,
        _state: &E::BeaconState,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_cold_state")
    }
    fn get_cold_state(&self, _restore_slot: Slot) -> Result<Option<E::BeaconState>, StorageError> {
        unreachable!("LcMemStore: get_cold_state")
    }
    fn put_restore_point(&self, _slot: Slot, _state_root: Root) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_restore_point")
    }
    fn nearest_restore_point(
        &self,
        _target_slot: Slot,
    ) -> Result<Option<(Slot, Root)>, StorageError> {
        unreachable!("LcMemStore: nearest_restore_point")
    }
    fn migrate_to_cold(
        &self,
        _batch: pharos_storage::ColdMigrationBatch<E>,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: migrate_to_cold")
    }
    fn put_state_summary(
        &self,
        _block_root: Root,
        _summary: &pharos_storage::StateSummary,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_state_summary")
    }
    fn get_state_summary(
        &self,
        _block_root: &Root,
    ) -> Result<Option<pharos_storage::StateSummary>, StorageError> {
        unreachable!("LcMemStore: get_state_summary")
    }
    // ── Altair LC ─────────────────────────────────────────────────────────────
    fn put_light_client_bootstrap(
        &self,
        block_root: Root,
        bootstrap: &E::AltairLightClientBootstrap,
    ) -> Result<(), StorageError> {
        self.altair_bootstraps
            .lock()
            .unwrap()
            .insert(block_root, bootstrap.clone());
        Ok(())
    }
    fn get_light_client_bootstrap(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::AltairLightClientBootstrap>, StorageError> {
        Ok(self
            .altair_bootstraps
            .lock()
            .unwrap()
            .get(block_root)
            .cloned())
    }
    fn put_light_client_update(
        &self,
        period: u64,
        update: &E::AltairLightClientUpdate,
    ) -> Result<(), StorageError> {
        self.altair_updates
            .lock()
            .unwrap()
            .insert(period, update.clone());
        Ok(())
    }
    fn get_light_client_update(
        &self,
        period: u64,
    ) -> Result<Option<E::AltairLightClientUpdate>, StorageError> {
        Ok(self.altair_updates.lock().unwrap().get(&period).cloned())
    }
    fn get_light_client_updates_by_range(
        &self,
        _start_period: u64,
        _count: u64,
    ) -> Result<Vec<E::AltairLightClientUpdate>, StorageError> {
        unreachable!("LcMemStore: get_light_client_updates_by_range")
    }
    fn put_light_client_finality_update(
        &self,
        update: &E::AltairLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        *self.altair_fin.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_finality_update(
        &self,
    ) -> Result<Option<E::AltairLightClientFinalityUpdate>, StorageError> {
        Ok(self.altair_fin.lock().unwrap().clone())
    }
    fn put_light_client_optimistic_update(
        &self,
        update: &E::AltairLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        *self.altair_opt.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_optimistic_update(
        &self,
    ) -> Result<Option<E::AltairLightClientOptimisticUpdate>, StorageError> {
        Ok(self.altair_opt.lock().unwrap().clone())
    }
    // ── Capella LC ────────────────────────────────────────────────────────────
    fn put_light_client_bootstrap_capella(
        &self,
        block_root: Root,
        bootstrap: &E::CapellaLightClientBootstrap,
    ) -> Result<(), StorageError> {
        self.capella_bootstraps
            .lock()
            .unwrap()
            .insert(block_root, bootstrap.clone());
        Ok(())
    }
    fn get_light_client_bootstrap_capella(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::CapellaLightClientBootstrap>, StorageError> {
        Ok(self
            .capella_bootstraps
            .lock()
            .unwrap()
            .get(block_root)
            .cloned())
    }
    fn put_light_client_update_capella(
        &self,
        period: u64,
        update: &E::CapellaLightClientUpdate,
    ) -> Result<(), StorageError> {
        self.capella_updates
            .lock()
            .unwrap()
            .insert(period, update.clone());
        Ok(())
    }
    fn get_light_client_update_capella(
        &self,
        period: u64,
    ) -> Result<Option<E::CapellaLightClientUpdate>, StorageError> {
        Ok(self.capella_updates.lock().unwrap().get(&period).cloned())
    }
    fn put_light_client_finality_update_capella(
        &self,
        update: &E::CapellaLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        *self.capella_fin.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_finality_update_capella(
        &self,
    ) -> Result<Option<E::CapellaLightClientFinalityUpdate>, StorageError> {
        Ok(self.capella_fin.lock().unwrap().clone())
    }
    fn put_light_client_optimistic_update_capella(
        &self,
        update: &E::CapellaLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        *self.capella_opt.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_optimistic_update_capella(
        &self,
    ) -> Result<Option<E::CapellaLightClientOptimisticUpdate>, StorageError> {
        Ok(self.capella_opt.lock().unwrap().clone())
    }
    // ── Deneb LC ──────────────────────────────────────────────────────────────
    fn put_light_client_bootstrap_deneb(
        &self,
        block_root: Root,
        bootstrap: &E::DenebLightClientBootstrap,
    ) -> Result<(), StorageError> {
        self.deneb_bootstraps
            .lock()
            .unwrap()
            .insert(block_root, bootstrap.clone());
        Ok(())
    }
    fn get_light_client_bootstrap_deneb(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::DenebLightClientBootstrap>, StorageError> {
        Ok(self
            .deneb_bootstraps
            .lock()
            .unwrap()
            .get(block_root)
            .cloned())
    }
    fn put_light_client_update_deneb(
        &self,
        period: u64,
        update: &E::DenebLightClientUpdate,
    ) -> Result<(), StorageError> {
        self.deneb_updates
            .lock()
            .unwrap()
            .insert(period, update.clone());
        Ok(())
    }
    fn get_light_client_update_deneb(
        &self,
        period: u64,
    ) -> Result<Option<E::DenebLightClientUpdate>, StorageError> {
        Ok(self.deneb_updates.lock().unwrap().get(&period).cloned())
    }
    fn put_light_client_finality_update_deneb(
        &self,
        update: &E::DenebLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        *self.deneb_fin.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_finality_update_deneb(
        &self,
    ) -> Result<Option<E::DenebLightClientFinalityUpdate>, StorageError> {
        Ok(self.deneb_fin.lock().unwrap().clone())
    }
    fn put_light_client_optimistic_update_deneb(
        &self,
        update: &E::DenebLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        *self.deneb_opt.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_optimistic_update_deneb(
        &self,
    ) -> Result<Option<E::DenebLightClientOptimisticUpdate>, StorageError> {
        Ok(self.deneb_opt.lock().unwrap().clone())
    }
    // ── Electra LC ────────────────────────────────────────────────────────────
    fn put_light_client_bootstrap_electra(
        &self,
        block_root: Root,
        bootstrap: &E::ElectraLightClientBootstrap,
    ) -> Result<(), StorageError> {
        self.electra_bootstraps
            .lock()
            .unwrap()
            .insert(block_root, bootstrap.clone());
        Ok(())
    }
    fn get_light_client_bootstrap_electra(
        &self,
        block_root: &Root,
    ) -> Result<Option<E::ElectraLightClientBootstrap>, StorageError> {
        Ok(self
            .electra_bootstraps
            .lock()
            .unwrap()
            .get(block_root)
            .cloned())
    }
    fn put_light_client_update_electra(
        &self,
        period: u64,
        update: &E::ElectraLightClientUpdate,
    ) -> Result<(), StorageError> {
        self.electra_updates
            .lock()
            .unwrap()
            .insert(period, update.clone());
        Ok(())
    }
    fn get_light_client_update_electra(
        &self,
        period: u64,
    ) -> Result<Option<E::ElectraLightClientUpdate>, StorageError> {
        Ok(self.electra_updates.lock().unwrap().get(&period).cloned())
    }
    fn put_light_client_finality_update_electra(
        &self,
        update: &E::ElectraLightClientFinalityUpdate,
    ) -> Result<(), StorageError> {
        *self.electra_fin.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_finality_update_electra(
        &self,
    ) -> Result<Option<E::ElectraLightClientFinalityUpdate>, StorageError> {
        Ok(self.electra_fin.lock().unwrap().clone())
    }
    fn put_light_client_optimistic_update_electra(
        &self,
        update: &E::ElectraLightClientOptimisticUpdate,
    ) -> Result<(), StorageError> {
        *self.electra_opt.lock().unwrap() = Some(update.clone());
        Ok(())
    }
    fn get_light_client_optimistic_update_electra(
        &self,
    ) -> Result<Option<E::ElectraLightClientOptimisticUpdate>, StorageError> {
        Ok(self.electra_opt.lock().unwrap().clone())
    }
    // ── Blob/DataColumn/Slasher stubs (never called) ─────────────────────────
    fn put_blob_sidecar(
        &self,
        _block_root: Root,
        _index: u64,
        _sidecar: &pharos_types::deneb::BlobSidecar,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_blob_sidecar")
    }
    fn get_blob_sidecar(
        &self,
        _block_root: &Root,
        _index: u64,
    ) -> Result<Option<pharos_types::deneb::BlobSidecar>, StorageError> {
        unreachable!("LcMemStore: get_blob_sidecar")
    }
    fn get_blob_sidecars_by_root(
        &self,
        _block_root: &Root,
    ) -> Result<Vec<pharos_types::deneb::BlobSidecar>, StorageError> {
        unreachable!("LcMemStore: get_blob_sidecars_by_root")
    }
    fn prune_blob_sidecars_below_slot(&self, _prune_slot: Slot) -> Result<(), StorageError> {
        unreachable!("LcMemStore: prune_blob_sidecars_below_slot")
    }
    fn put_data_column_sidecar(
        &self,
        _block_root: Root,
        _sidecar: &pharos_types::fulu::MainnetDataColumnSidecar,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_data_column_sidecar")
    }
    fn get_data_column_sidecar(
        &self,
        _block_root: &Root,
        _index: u64,
    ) -> Result<Option<pharos_types::fulu::MainnetDataColumnSidecar>, StorageError> {
        unreachable!("LcMemStore: get_data_column_sidecar")
    }
    fn get_all_data_column_sidecars_by_root(
        &self,
        _block_root: &Root,
    ) -> Result<Vec<pharos_types::fulu::MainnetDataColumnSidecar>, StorageError> {
        unreachable!("LcMemStore: get_all_data_column_sidecars_by_root")
    }
    fn prune_data_column_sidecars_below_slot(&self, _prune_slot: Slot) -> Result<(), StorageError> {
        unreachable!("LcMemStore: prune_data_column_sidecars_below_slot")
    }
    fn put_slasher_proposer_header(
        &self,
        _slot: Slot,
        _validator_index: u64,
        _header_root: Root,
        _header: &pharos_types::phase0::operations::SignedBeaconBlockHeader,
    ) -> Result<(), StorageError> {
        unreachable!("LcMemStore: put_slasher_proposer_header")
    }
    fn slasher_proposer_headers_at(
        &self,
        _slot: Slot,
        _validator_index: u64,
    ) -> Result<Vec<pharos_types::phase0::operations::SignedBeaconBlockHeader>, StorageError> {
        unreachable!("LcMemStore: slasher_proposer_headers_at")
    }
}

/// Helper: load a snappy-compressed SSZ file, decode as `T`, return SSZ bytes.
fn load_lc_ssz_bytes<T: Decode>(case_dir: &Path, filename: &str) -> Result<Vec<u8>, String> {
    let path = case_dir.join(filename);
    let compressed = std::fs::read(&path).map_err(|e| format!("read {filename}: {e}"))?;
    let mut decoder = snap::raw::Decoder::new();
    let raw = decoder
        .decompress_vec(&compressed)
        .map_err(|e| format!("snappy {filename}: {e}"))?;
    // Validate it decodes to the expected type.
    T::from_ssz_bytes(&raw).map_err(|e| format!("ssz decode {filename}: {e}"))?;
    Ok(raw)
}

/// Load initial state helper: decompress snappy + SSZ decode.
fn load_ssz_snappy_bytes(dir: &Path, filename: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(filename);
    let compressed = std::fs::read(&path).map_err(|e| format!("read {filename}: {e}"))?;
    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(&compressed)
        .map_err(|e| format!("snappy {filename}: {e}"))
}

/// Run a data_collection case for the altair fork.
fn run_data_collection_impl_altair<E: BeaconSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::AltairBeaconState:
        Decode + AltairDispatch<E> + AltairDispatchBounds<E> + BeaconStateView + Clone,
    E::AltairSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::AltairBeaconBlock: BeaconBlockView + Clone,
    E::AltairLightClientBootstrap: Decode + Encode + Clone,
    E::AltairLightClientUpdate: Decode + Encode + Clone,
    E::AltairLightClientFinalityUpdate: Decode + Encode + Clone,
    E::AltairLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_core::<
        E,
        E::AltairBeaconState,
        E::AltairSignedBeaconBlock,
        E::AltairBeaconBlock,
    >(
        case_dir,
        case_name,
        |dir| {
            let raw = load_ssz_snappy_bytes(dir, "initial_state.ssz_snappy")?;
            E::AltairBeaconState::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz initial_state: {e}"))
        },
        |dir, filename| {
            let raw = load_ssz_snappy_bytes(dir, filename)?;
            E::AltairSignedBeaconBlock::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz {filename}: {e}"))
        },
        |sb| sb.message().tree_hash_root(),
        |sb| sb.message(),
        |pre, sb| {
            pre.apply_signed_block(sb, false)
                .map(|post| (post, Root::default()))
                .map_err(|e| format!("{e:?}"))
        },
        |post, sb, att_st, att_blk, fin_blk, store| {
            post.call_update_lc_snapshots::<LcMemStore<E>>(
                sb.message(),
                att_st,
                att_blk,
                fin_blk,
                store,
            );
        },
        |post| {
            let fc = post.finalized_checkpoint();
            (fc.epoch.0, fc.root)
        },
        |dir, root, filename, store| {
            if filename.is_empty() {
                return if store.get_light_client_bootstrap(&root).unwrap().is_some() {
                    Err(format!("unexpected altair bootstrap for {root:?}"))
                } else {
                    Ok(())
                };
            }
            let exp = load_lc_ssz_bytes::<E::AltairLightClientBootstrap>(dir, filename)?;
            let got = store
                .get_light_client_bootstrap(&root)
                .unwrap()
                .ok_or_else(|| format!("no altair bootstrap for {root:?}"))?;
            if got.as_ssz_bytes() != exp {
                return Err(format!("altair bootstrap mismatch for {root:?}"));
            }
            Ok(())
        },
        |dir, period, fname_opt, store| {
            match fname_opt {
                None => {
                    if store.get_light_client_update(period).unwrap().is_some() {
                        return Err(format!("unexpected altair update period {period}"));
                    }
                }
                Some(fname) => {
                    let exp = load_lc_ssz_bytes::<E::AltairLightClientUpdate>(dir, fname)?;
                    let got = store
                        .get_light_client_update(period)
                        .unwrap()
                        .ok_or_else(|| format!("no altair update period {period}"))?;
                    if got.as_ssz_bytes() != exp {
                        return Err(format!("altair update mismatch period {period}"));
                    }
                }
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::AltairLightClientFinalityUpdate>(dir, fname)?;
            let got = store
                .get_light_client_finality_update()
                .unwrap()
                .ok_or_else(|| "no altair finality_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("altair finality_update mismatch".to_string());
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::AltairLightClientOptimisticUpdate>(dir, fname)?;
            let got = store
                .get_light_client_optimistic_update()
                .unwrap()
                .ok_or_else(|| "no altair optimistic_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("altair optimistic_update mismatch".to_string());
            }
            Ok(())
        },
    )
}

/// Run a data_collection case for the capella fork.
fn run_data_collection_impl_capella<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::CapellaBeaconState: Decode
        + CapellaDispatch<E, NullExecutionEngine>
        + CapellaDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::CapellaSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::CapellaBeaconBlock: BeaconBlockView + Clone,
    E::CapellaLightClientBootstrap: Decode + Encode + Clone,
    E::CapellaLightClientUpdate: Decode + Encode + Clone,
    E::CapellaLightClientFinalityUpdate: Decode + Encode + Clone,
    E::CapellaLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_core::<
        E,
        E::CapellaBeaconState,
        E::CapellaSignedBeaconBlock,
        E::CapellaBeaconBlock,
    >(
        case_dir,
        case_name,
        |dir| {
            let raw = load_ssz_snappy_bytes(dir, "initial_state.ssz_snappy")?;
            E::CapellaBeaconState::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz initial_state: {e}"))
        },
        |dir, filename| {
            let raw = load_ssz_snappy_bytes(dir, filename)?;
            E::CapellaSignedBeaconBlock::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz {filename}: {e}"))
        },
        |sb| sb.message().tree_hash_root(),
        |sb| sb.message(),
        |pre, sb| {
            pre.apply_signed_block(sb, &NullExecutionEngine, false, &RuntimeConfig::default())
                .map(|(post, _)| (post, Root::default()))
                .map_err(|e| format!("{e:?}"))
        },
        |post, sb, att_st, att_blk, fin_blk, store| {
            post.call_update_lc_snapshots_capella::<LcMemStore<E>>(
                sb.message(),
                att_st,
                att_blk,
                fin_blk,
                store,
            );
        },
        |post| {
            let fc = post.finalized_checkpoint();
            (fc.epoch.0, fc.root)
        },
        |dir, root, filename, store| {
            if filename.is_empty() {
                return if store
                    .get_light_client_bootstrap_capella(&root)
                    .unwrap()
                    .is_some()
                {
                    Err(format!("unexpected capella bootstrap for {root:?}"))
                } else {
                    Ok(())
                };
            }
            let exp = load_lc_ssz_bytes::<E::CapellaLightClientBootstrap>(dir, filename)?;
            let got = store
                .get_light_client_bootstrap_capella(&root)
                .unwrap()
                .ok_or_else(|| format!("no capella bootstrap for {root:?}"))?;
            if got.as_ssz_bytes() != exp {
                return Err(format!("capella bootstrap mismatch for {root:?}"));
            }
            Ok(())
        },
        |dir, period, fname_opt, store| {
            match fname_opt {
                None => {
                    if store
                        .get_light_client_update_capella(period)
                        .unwrap()
                        .is_some()
                    {
                        return Err(format!("unexpected capella update period {period}"));
                    }
                }
                Some(fname) => {
                    let exp = load_lc_ssz_bytes::<E::CapellaLightClientUpdate>(dir, fname)?;
                    let got = store
                        .get_light_client_update_capella(period)
                        .unwrap()
                        .ok_or_else(|| format!("no capella update period {period}"))?;
                    if got.as_ssz_bytes() != exp {
                        return Err(format!("capella update mismatch period {period}"));
                    }
                }
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::CapellaLightClientFinalityUpdate>(dir, fname)?;
            let got = store
                .get_light_client_finality_update_capella()
                .unwrap()
                .ok_or_else(|| "no capella finality_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("capella finality_update mismatch".to_string());
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::CapellaLightClientOptimisticUpdate>(dir, fname)?;
            let got = store
                .get_light_client_optimistic_update_capella()
                .unwrap()
                .ok_or_else(|| "no capella optimistic_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("capella optimistic_update mismatch".to_string());
            }
            Ok(())
        },
    )
}

/// Run a data_collection case for the deneb fork.
fn run_data_collection_impl_deneb<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::DenebBeaconState: Decode
        + DenebDispatch<E, NullExecutionEngine>
        + DenebDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::DenebSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::DenebBeaconBlock: BeaconBlockView + Clone,
    E::DenebLightClientBootstrap: Decode + Encode + Clone,
    E::DenebLightClientUpdate: Decode + Encode + Clone,
    E::DenebLightClientFinalityUpdate: Decode + Encode + Clone,
    E::DenebLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_core::<E, E::DenebBeaconState, E::DenebSignedBeaconBlock, E::DenebBeaconBlock>(
        case_dir,
        case_name,
        |dir| {
            let raw = load_ssz_snappy_bytes(dir, "initial_state.ssz_snappy")?;
            E::DenebBeaconState::from_ssz_bytes(&raw).map_err(|e| format!("ssz initial_state: {e}"))
        },
        |dir, filename| {
            let raw = load_ssz_snappy_bytes(dir, filename)?;
            E::DenebSignedBeaconBlock::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz {filename}: {e}"))
        },
        |sb| sb.message().tree_hash_root(),
        |sb| sb.message(),
        |pre, sb| {
            pre.apply_signed_block(sb, &NullExecutionEngine, false, &RuntimeConfig::default())
                .map(|(post, _)| (post, Root::default()))
                .map_err(|e| format!("{e:?}"))
        },
        |post, sb, att_st, att_blk, fin_blk, store| {
            post.call_update_lc_snapshots_deneb::<LcMemStore<E>>(
                sb.message(),
                att_st,
                att_blk,
                fin_blk,
                store,
            );
        },
        |post| {
            let fc = post.finalized_checkpoint();
            (fc.epoch.0, fc.root)
        },
        |dir, root, filename, store| {
            if filename.is_empty() {
                return if store
                    .get_light_client_bootstrap_deneb(&root)
                    .unwrap()
                    .is_some()
                {
                    Err(format!("unexpected deneb bootstrap for {root:?}"))
                } else {
                    Ok(())
                };
            }
            let exp = load_lc_ssz_bytes::<E::DenebLightClientBootstrap>(dir, filename)?;
            let got = store
                .get_light_client_bootstrap_deneb(&root)
                .unwrap()
                .ok_or_else(|| format!("no deneb bootstrap for {root:?}"))?;
            if got.as_ssz_bytes() != exp {
                return Err(format!("deneb bootstrap mismatch for {root:?}"));
            }
            Ok(())
        },
        |dir, period, fname_opt, store| {
            match fname_opt {
                None => {
                    if store
                        .get_light_client_update_deneb(period)
                        .unwrap()
                        .is_some()
                    {
                        return Err(format!("unexpected deneb update period {period}"));
                    }
                }
                Some(fname) => {
                    let exp = load_lc_ssz_bytes::<E::DenebLightClientUpdate>(dir, fname)?;
                    let got = store
                        .get_light_client_update_deneb(period)
                        .unwrap()
                        .ok_or_else(|| format!("no deneb update period {period}"))?;
                    if got.as_ssz_bytes() != exp {
                        return Err(format!("deneb update mismatch period {period}"));
                    }
                }
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::DenebLightClientFinalityUpdate>(dir, fname)?;
            let got = store
                .get_light_client_finality_update_deneb()
                .unwrap()
                .ok_or_else(|| "no deneb finality_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("deneb finality_update mismatch".to_string());
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::DenebLightClientOptimisticUpdate>(dir, fname)?;
            let got = store
                .get_light_client_optimistic_update_deneb()
                .unwrap()
                .ok_or_else(|| "no deneb optimistic_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("deneb optimistic_update mismatch".to_string());
            }
            Ok(())
        },
    )
}

/// Run a data_collection case for the electra fork.
fn run_data_collection_impl_electra<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::ElectraBeaconState: Decode
        + ElectraDispatch<E, NullExecutionEngine>
        + ElectraDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::ElectraSignedBeaconBlock:
        Decode + Clone + SignedBeaconBlockView<Message = E::ElectraBeaconBlock>,
    E::ElectraBeaconBlock: BeaconBlockView + Clone,
    E::ElectraLightClientBootstrap: Decode + Encode + Clone,
    E::ElectraLightClientUpdate: Decode + Encode + Clone,
    E::ElectraLightClientFinalityUpdate: Decode + Encode + Clone,
    E::ElectraLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_core::<
        E,
        E::ElectraBeaconState,
        E::ElectraSignedBeaconBlock,
        E::ElectraBeaconBlock,
    >(
        case_dir,
        case_name,
        |dir| {
            let raw = load_ssz_snappy_bytes(dir, "initial_state.ssz_snappy")?;
            E::ElectraBeaconState::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz initial_state: {e}"))
        },
        |dir, filename| {
            let raw = load_ssz_snappy_bytes(dir, filename)?;
            E::ElectraSignedBeaconBlock::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz {filename}: {e}"))
        },
        |sb| sb.message().tree_hash_root(),
        |sb| sb.message(),
        |pre, sb| {
            pre.apply_signed_block(sb, &NullExecutionEngine, false, &RuntimeConfig::default())
                .map(|(post, _)| (post, Root::default()))
                .map_err(|e| format!("{e:?}"))
        },
        |post, sb, att_st, att_blk, fin_blk, store| {
            post.call_update_lc_snapshots_electra::<LcMemStore<E>>(
                sb.message(),
                att_st,
                att_blk,
                fin_blk,
                store,
            );
        },
        |post| {
            let fc = post.finalized_checkpoint();
            (fc.epoch.0, fc.root)
        },
        |dir, root, filename, store| {
            if filename.is_empty() {
                return if store
                    .get_light_client_bootstrap_electra(&root)
                    .unwrap()
                    .is_some()
                {
                    Err(format!("unexpected electra bootstrap for {root:?}"))
                } else {
                    Ok(())
                };
            }
            let exp = load_lc_ssz_bytes::<E::ElectraLightClientBootstrap>(dir, filename)?;
            let got = store
                .get_light_client_bootstrap_electra(&root)
                .unwrap()
                .ok_or_else(|| format!("no electra bootstrap for {root:?}"))?;
            if got.as_ssz_bytes() != exp {
                return Err(format!("electra bootstrap mismatch for {root:?}"));
            }
            Ok(())
        },
        |dir, period, fname_opt, store| {
            match fname_opt {
                None => {
                    if store
                        .get_light_client_update_electra(period)
                        .unwrap()
                        .is_some()
                    {
                        return Err(format!("unexpected electra update period {period}"));
                    }
                }
                Some(fname) => {
                    let exp = load_lc_ssz_bytes::<E::ElectraLightClientUpdate>(dir, fname)?;
                    let got = store
                        .get_light_client_update_electra(period)
                        .unwrap()
                        .ok_or_else(|| format!("no electra update period {period}"))?;
                    if got.as_ssz_bytes() != exp {
                        return Err(format!("electra update mismatch period {period}"));
                    }
                }
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::ElectraLightClientFinalityUpdate>(dir, fname)?;
            let got = store
                .get_light_client_finality_update_electra()
                .unwrap()
                .ok_or_else(|| "no electra finality_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("electra finality_update mismatch".to_string());
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::ElectraLightClientOptimisticUpdate>(dir, fname)?;
            let got = store
                .get_light_client_optimistic_update_electra()
                .unwrap()
                .ok_or_else(|| "no electra optimistic_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("electra optimistic_update mismatch".to_string());
            }
            Ok(())
        },
    )
}

/// Run a data_collection case for the fulu fork (same LC types as electra).
fn run_data_collection_impl_fulu<E: BeaconSpec, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::FuluBeaconState: Decode
        + FuluDispatch<E, NullExecutionEngine>
        + FuluDispatchBounds<E>
        + BeaconStateView
        + Clone,
    E::FuluSignedBeaconBlock: Decode + Clone + SignedBeaconBlockView<Message = E::FuluBeaconBlock>,
    E::FuluBeaconBlock: BeaconBlockView + Clone,
    E::ElectraLightClientBootstrap: Decode + Encode + Clone,
    E::ElectraLightClientUpdate: Decode + Encode + Clone,
    E::ElectraLightClientFinalityUpdate: Decode + Encode + Clone,
    E::ElectraLightClientOptimisticUpdate: Decode + Encode + Clone,
    Bytes32: Default + Clone,
    pharos_utils::BLSPubkey: Default + Clone,
{
    run_data_collection_core::<E, E::FuluBeaconState, E::FuluSignedBeaconBlock, E::FuluBeaconBlock>(
        case_dir,
        case_name,
        |dir| {
            let raw = load_ssz_snappy_bytes(dir, "initial_state.ssz_snappy")?;
            E::FuluBeaconState::from_ssz_bytes(&raw).map_err(|e| format!("ssz initial_state: {e}"))
        },
        |dir, filename| {
            let raw = load_ssz_snappy_bytes(dir, filename)?;
            E::FuluSignedBeaconBlock::from_ssz_bytes(&raw)
                .map_err(|e| format!("ssz {filename}: {e}"))
        },
        |sb| sb.message().tree_hash_root(),
        |sb| sb.message(),
        |pre, sb| {
            pre.apply_signed_block(sb, &NullExecutionEngine, false, &RuntimeConfig::default())
                .map(|(post, _)| (post, Root::default()))
                .map_err(|e| format!("{e:?}"))
        },
        |post, sb, att_st, att_blk, fin_blk, store| {
            post.call_update_lc_snapshots_fulu::<LcMemStore<E>>(
                sb.message(),
                att_st,
                att_blk,
                fin_blk,
                store,
            );
        },
        |post| {
            let fc = post.finalized_checkpoint();
            (fc.epoch.0, fc.root)
        },
        |dir, root, filename, store| {
            if filename.is_empty() {
                return if store
                    .get_light_client_bootstrap_electra(&root)
                    .unwrap()
                    .is_some()
                {
                    Err(format!("unexpected fulu bootstrap for {root:?}"))
                } else {
                    Ok(())
                };
            }
            let exp = load_lc_ssz_bytes::<E::ElectraLightClientBootstrap>(dir, filename)?;
            let got = store
                .get_light_client_bootstrap_electra(&root)
                .unwrap()
                .ok_or_else(|| format!("no fulu bootstrap for {root:?}"))?;
            if got.as_ssz_bytes() != exp {
                return Err(format!("fulu bootstrap mismatch for {root:?}"));
            }
            Ok(())
        },
        |dir, period, fname_opt, store| {
            match fname_opt {
                None => {
                    if store
                        .get_light_client_update_electra(period)
                        .unwrap()
                        .is_some()
                    {
                        return Err(format!("unexpected fulu update period {period}"));
                    }
                }
                Some(fname) => {
                    let exp = load_lc_ssz_bytes::<E::ElectraLightClientUpdate>(dir, fname)?;
                    let got = store
                        .get_light_client_update_electra(period)
                        .unwrap()
                        .ok_or_else(|| format!("no fulu update period {period}"))?;
                    if got.as_ssz_bytes() != exp {
                        return Err(format!("fulu update mismatch period {period}"));
                    }
                }
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::ElectraLightClientFinalityUpdate>(dir, fname)?;
            let got = store
                .get_light_client_finality_update_electra()
                .unwrap()
                .ok_or_else(|| "no fulu finality_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("fulu finality_update mismatch".to_string());
            }
            Ok(())
        },
        |dir, fname, store| {
            let exp = load_lc_ssz_bytes::<E::ElectraLightClientOptimisticUpdate>(dir, fname)?;
            let got = store
                .get_light_client_optimistic_update_electra()
                .unwrap()
                .ok_or_else(|| "no fulu optimistic_update".to_string())?;
            if got.as_ssz_bytes() != exp {
                return Err("fulu optimistic_update mismatch".to_string());
            }
            Ok(())
        },
    )
}

/// Core data_collection loop, parameterized over the fork's state and block types.
///
/// All block/state types are fully generic (`St`, `Sb`, `Bl`) so the function
/// never touches `E::SignedBeaconBlock` or `E::BeaconBlock` directly.  Each
/// per-fork caller passes its own concrete associated types.
///
/// Callbacks (all `Fn`; closures may borrow from the call site):
/// - `load_block(dir, filename) -> Result<Sb, String>`
/// - `block_root(sb) -> Root`
/// - `get_block_msg(sb) -> &Bl`
/// - `apply(pre_state, sb) -> Result<(St /*post*/, Root /*parent_root*/), String>`
/// - `update_lc(post, sb, att_state, att_blk, fin_blk, store)`
/// - `get_finalized(post) -> (u64 /*epoch*/, Root)`
/// - `check_bootstrap(dir, root, filename, store) -> Result<(), String>`
/// - `check_update(dir, period, filename, store) -> Result<(), String>`  (None means no update expected)
/// - `check_finality(dir, filename, store) -> Result<(), String>`
/// - `check_optimistic(dir, filename, store) -> Result<(), String>`
#[allow(clippy::too_many_arguments)]
fn run_data_collection_core<E, St, Sb, Bl>(
    case_dir: &Path,
    case_name: &str,
    load_initial: impl Fn(&Path) -> Result<St, String>,
    load_block: impl Fn(&Path, &str) -> Result<Sb, String>,
    block_root: impl Fn(&Sb) -> Root,
    get_block_msg: impl Fn(&Sb) -> &Bl,
    apply: impl Fn(St, &Sb) -> Result<(St, Root), String>,
    update_lc: impl Fn(&St, &Sb, Option<&St>, Option<&Bl>, Option<&Bl>, &LcMemStore<E>),
    get_finalized: impl Fn(&St) -> (u64, Root),
    check_bootstrap: impl Fn(&Path, Root, &str, &LcMemStore<E>) -> Result<(), String>,
    check_update: impl Fn(&Path, u64, Option<&str>, &LcMemStore<E>) -> Result<(), String>,
    check_finality: impl Fn(&Path, &str, &LcMemStore<E>) -> Result<(), String>,
    check_optimistic: impl Fn(&Path, &str, &LcMemStore<E>) -> Result<(), String>,
) -> CaseResult
where
    E: BeaconSpec,
    St: Clone,
    Bl: Clone + BeaconBlockView,
{
    let initial_state = match load_initial(case_dir) {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: load initial_state: {e}")),
    };

    let steps_text = match std::fs::read_to_string(case_dir.join("steps.yaml")) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read steps.yaml: {e}")),
    };
    let steps_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&steps_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse steps.yaml: {e}")),
    };
    let steps = match steps_val.as_sequence() {
        Some(s) => s.clone(),
        None => return CaseResult::Fail(format!("{case_name}: steps.yaml is not a sequence")),
    };

    // Keyed by block_root (the root of the *unsigned* block).
    let mut signed_by_root: HashMap<Root, Sb> = HashMap::new();
    let mut state_by_root: HashMap<Root, St> = HashMap::new();
    let mut current_state: St = initial_state;
    let lc_store = LcMemStore::<E>::new();

    for (step_idx, step) in steps.iter().enumerate() {
        if let Some(new_block_v) = step.get("new_block") {
            let data_stem = match new_block_v.get("data").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: new_block missing data"
                    ));
                }
            };
            let filename = format!("{data_stem}.ssz_snappy");
            let signed_block = match load_block(case_dir, &filename) {
                Ok(b) => b,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: load block {filename}: {e}"
                    ));
                }
            };
            let root = block_root(&signed_block);
            let parent_root = get_block_msg(&signed_block).parent_root();
            // Attested state = state of the parent block (the block being attested to).
            let attested_state = state_by_root.get(&parent_root).cloned();
            // Attested block = the parent signed block's message.
            let attested_block = signed_by_root
                .get(&parent_root)
                .map(|sb| get_block_msg(sb).clone());
            // Apply the block to advance the chain.
            let (new_state, _) = match apply(current_state, &signed_block) {
                Ok(v) => v,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: apply block: {e}"
                    ));
                }
            };
            // Finalized block = block at finalized_checkpoint.root in the new state.
            let (_, fin_root) = get_finalized(&new_state);
            let finalized_block = if fin_root == Root::default() {
                None
            } else {
                signed_by_root
                    .get(&fin_root)
                    .map(|sb| get_block_msg(sb).clone())
            };
            update_lc(
                &new_state,
                &signed_block,
                attested_state.as_ref(),
                attested_block.as_ref(),
                finalized_block.as_ref(),
                &lc_store,
            );
            state_by_root.insert(root, new_state.clone());
            signed_by_root.insert(root, signed_block);
            current_state = new_state;
        } else if let Some(new_head_v) = step.get("new_head") {
            let checks = match new_head_v.get("checks") {
                Some(c) => c,
                None => continue,
            };

            // Check bootstraps.
            if let Some(bootstraps) = checks.get("bootstraps").and_then(|v| v.as_sequence()) {
                for (bi, entry) in bootstraps.iter().enumerate() {
                    let block_root_str = match entry.get("block_root").and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => {
                            return CaseResult::Fail(format!(
                                "{case_name}: step {step_idx}: bootstraps[{bi}] missing block_root"
                            ));
                        }
                    };
                    let br = match parse_root(block_root_str) {
                        Ok(r) => r,
                        Err(e) => {
                            return CaseResult::Fail(format!(
                                "{case_name}: step {step_idx}: bootstraps[{bi}] block_root: {e}"
                            ));
                        }
                    };
                    let bootstrap_v = match entry.get("bootstrap") {
                        Some(v) => v,
                        None => {
                            // No bootstrap entry — check that none is stored.
                            if let Err(e) = check_bootstrap(case_dir, br, "", &lc_store) {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: bootstrap check[{bi}]: {e}"
                                ));
                            }
                            continue;
                        }
                    };
                    let data_stem = match bootstrap_v.get("data").and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => {
                            return CaseResult::Fail(format!(
                                "{case_name}: step {step_idx}: bootstraps[{bi}] missing data"
                            ));
                        }
                    };
                    let filename = format!("{data_stem}.ssz_snappy");
                    if let Err(e) = check_bootstrap(case_dir, br, &filename, &lc_store) {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: bootstrap check[{bi}]: {e}"
                        ));
                    }
                }
            }

            // Check best_updates.
            if let Some(best_updates) = checks.get("best_updates").and_then(|v| v.as_sequence()) {
                for (ui, entry) in best_updates.iter().enumerate() {
                    let period = match entry.get("period").and_then(|v| v.as_u64()) {
                        Some(p) => p,
                        None => {
                            return CaseResult::Fail(format!(
                                "{case_name}: step {step_idx}: best_updates[{ui}] missing period"
                            ));
                        }
                    };
                    // update field is optional; absent means we expect no update for this period.
                    let update_filename = entry
                        .get("update")
                        .and_then(|v| v.get("data"))
                        .and_then(|v| v.as_str())
                        .map(|s| format!("{s}.ssz_snappy"));
                    if let Err(e) =
                        check_update(case_dir, period, update_filename.as_deref(), &lc_store)
                    {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: best_update check[{ui}] period {period}: {e}"
                        ));
                    }
                }
            }

            // Check latest_finality_update.
            if let Some(fin_v) = checks.get("latest_finality_update") {
                let data_stem = match fin_v.get("data").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: latest_finality_update missing data"
                        ));
                    }
                };
                let filename = format!("{data_stem}.ssz_snappy");
                if let Err(e) = check_finality(case_dir, &filename, &lc_store) {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: finality_update check: {e}"
                    ));
                }
            }

            // Check latest_optimistic_update.
            if let Some(opt_v) = checks.get("latest_optimistic_update") {
                let data_stem = match opt_v.get("data").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: latest_optimistic_update missing data"
                        ));
                    }
                };
                let filename = format!("{data_stem}.ssz_snappy");
                if let Err(e) = check_optimistic(case_dir, &filename, &lc_store) {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: optimistic_update check: {e}"
                    ));
                }
            }
        }
    }
    CaseResult::Pass
}

fn run_single_merkle_proof_case<E: BeaconSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::AltairBeaconState: Decode + TreeHash,
{
    // Load proof.yaml.
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}"));
        }
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}"));
        }
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf in proof.yaml")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            return CaseResult::Fail(format!("{case_name}: missing leaf_index in proof.yaml"));
        }
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch in proof.yaml")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] is not a string"));
            }
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    // Load object (altair BeaconState), compute its hash_tree_root.
    let state_inner = match load_ssz_snappy::<E::AltairBeaconState>(case_dir, "object.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

    // Verify the Merkle proof.
    // generalized_index → depth = floorlog2(gindex), index = gindex % 2^depth.
    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &state_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_sync_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_impl::<MainnetBeaconSpec, 512>(case_dir, case_name)
}

fn run_sync_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_impl::<MinimalBeaconSpec, 32>(case_dir, case_name)
}

fn run_sync_case_impl<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    pharos_types::altair::LightClientBootstrap<SYNC_COMMITTEE_SIZE>: Decode,
    pharos_types::altair::LightClientUpdate<SYNC_COMMITTEE_SIZE>: Decode + Clone,
    pharos_utils::Bytes32: Default + PartialEq + Clone,
    pharos_utils::BLSPubkey: Default + PartialEq + Clone,
{
    // Parse meta.yaml.
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read meta.yaml: {e}")),
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}"));
        }
    };

    let genesis_validators_root: Root = match meta_val
        .get("genesis_validators_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!(
                "{case_name}: missing/invalid genesis_validators_root"
            ));
        }
    };

    let trusted_block_root: Root = match meta_val
        .get("trusted_block_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!("{case_name}: missing/invalid trusted_block_root"));
        }
    };

    let bootstrap_fork_digest_str = meta_val
        .get("bootstrap_fork_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Load bootstrap.
    let bootstrap = match load_ssz_snappy::<
        pharos_types::altair::LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
    >(case_dir, "bootstrap.ssz_snappy")
    {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    // Initialize store.
    let mut store = match initialize_light_client_store::<E, SYNC_COMMITTEE_SIZE>(
        &trusted_block_root,
        &bootstrap,
    ) {
        Ok(s) => s,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: initialize_store: {e}"));
        }
    };

    // Parse and execute steps.yaml.
    let steps_path = case_dir.join("steps.yaml");
    let steps_text = match std::fs::read_to_string(&steps_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read steps.yaml: {e}")),
    };
    let steps_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&steps_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse steps.yaml: {e}")),
    };
    let steps = match steps_val.as_sequence() {
        Some(s) => s.clone(),
        None => return CaseResult::Fail(format!("{case_name}: steps.yaml is not a sequence")),
    };

    for (step_idx, step) in steps.iter().enumerate() {
        if let Some(force_update) = step.get("force_update") {
            let current_slot = match force_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };
            process_light_client_store_force_update::<E, SYNC_COMMITTEE_SIZE>(
                &mut store,
                current_slot,
            );
            if let Some(checks) = force_update.get("checks")
                && let Err(e) =
                    check_store::<SYNC_COMMITTEE_SIZE>(&store, checks, case_name, step_idx)
            {
                return CaseResult::Fail(e);
            }
        } else if let Some(process_update) = step.get("process_update") {
            let update_file = match process_update.get("update").and_then(|v| v.as_str()) {
                Some(s) => format!("{s}.ssz_snappy"),
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing update filename"
                    ));
                }
            };
            let current_slot = match process_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };

            // Check if this step's update fork digest matches the store fork digest.
            let update_fork_digest = process_update
                .get("update_fork_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !update_fork_digest.is_empty() && update_fork_digest != bootstrap_fork_digest_str {
                // Cross-fork update; skip this step.
                continue;
            }

            let update = match load_ssz_snappy::<
                pharos_types::altair::LightClientUpdate<SYNC_COMMITTEE_SIZE>,
            >(case_dir, &update_file)
            {
                Ok(u) => u,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: load update: {e}"
                    ));
                }
            };

            if let Err(e) = process_light_client_update::<E, SYNC_COMMITTEE_SIZE>(
                &mut store,
                &update,
                current_slot,
                &genesis_validators_root,
            ) {
                return CaseResult::Fail(format!(
                    "{case_name}: step {step_idx}: process_update: {e}"
                ));
            }

            if let Some(checks) = process_update.get("checks")
                && let Err(e) =
                    check_store::<SYNC_COMMITTEE_SIZE>(&store, checks, case_name, step_idx)
            {
                return CaseResult::Fail(e);
            }
        } else if step.get("upgrade_store").is_some() {
            // Cross-fork store upgrade; skip for altair-only runner.
            continue;
        }
    }

    CaseResult::Pass
}

fn check_store<const SYNC_COMMITTEE_SIZE: u64>(
    store: &LightClientStore<SYNC_COMMITTEE_SIZE>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
) -> Result<(), String> {
    if let Some(fin_check) = checks.get("finalized_header") {
        let expected_slot = fin_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.finalized_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: finalized_header.slot mismatch: got {}, expected {}",
                store.finalized_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = fin_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.finalized_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.beacon_root mismatch"
                ));
            }
        }
    }
    if let Some(opt_check) = checks.get("optimistic_header") {
        let expected_slot = opt_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.optimistic_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: optimistic_header.slot mismatch: got {}, expected {}",
                store.optimistic_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = opt_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.optimistic_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.beacon_root mismatch"
                ));
            }
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a fork epoch from the test case's config.yaml. Returns `u64::MAX`
/// (never activated) when the key is absent or unparseable.
fn parse_config_fork_epoch(config_path: &Path, key: &str) -> u64 {
    let text = match std::fs::read_to_string(config_path) {
        Ok(t) => t,
        Err(_) => return u64::MAX,
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            // Require ':' as the separator so a key is not matched as a prefix of
            // a longer key (e.g. DENEB_FORK_EPOCH vs DENEB_FORK_EPOCH_SOMETHING).
            let rest = rest.trim_start();
            if !rest.starts_with(':') {
                continue;
            }
            let rest = rest.trim_start_matches(':').trim();
            if let Ok(v) = rest.parse::<u64>() {
                return v;
            }
        }
    }
    u64::MAX
}

/// Compute the capella-format `execution_root` from a deneb `ExecutionPayloadHeader`.
/// Used when the header's slot is in a capella epoch (< deneb_fork_epoch) but the
/// header is stored in the deneb-upgraded format (blob_gas_used/excess_blob_gas = 0).
fn capella_execution_root_from_deneb<const B: u64, const X: u64>(
    deneb_exec: &DenebExecutionPayloadHeader<B, X>,
) -> Root
where
    pharos_types::capella::ExecutionPayloadHeader<B, X>: TreeHash,
    CapellaExecutionPayloadHeader<B, X>: Clone,
{
    let capella_exec = CapellaExecutionPayloadHeader {
        parent_hash: deneb_exec.parent_hash,
        fee_recipient: deneb_exec.fee_recipient,
        state_root: deneb_exec.state_root,
        receipts_root: deneb_exec.receipts_root,
        logs_bloom: deneb_exec.logs_bloom.clone(),
        prev_randao: deneb_exec.prev_randao,
        block_number: deneb_exec.block_number,
        gas_limit: deneb_exec.gas_limit,
        gas_used: deneb_exec.gas_used,
        timestamp: deneb_exec.timestamp,
        extra_data: deneb_exec.extra_data.clone(),
        base_fee_per_gas: deneb_exec.base_fee_per_gas,
        block_hash: deneb_exec.block_hash,
        transactions_root: deneb_exec.transactions_root,
        withdrawals_root: deneb_exec.withdrawals_root,
    };
    capella_exec.tree_hash_root()
}

fn parse_bytes32(hex: &str) -> Result<Bytes32, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Bytes32::from_array(arr))
}

fn parse_root(hex: &str) -> Result<Root, String> {
    parse_bytes32(hex)
}

fn run_single_merkle_proof_capella_state_case<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::CapellaBeaconState: Decode + TreeHash,
{
    // Load proof.yaml.
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}"));
        }
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}"));
        }
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf in proof.yaml")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            return CaseResult::Fail(format!("{case_name}: missing leaf_index in proof.yaml"));
        }
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch in proof.yaml")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] is not a string"));
            }
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    // Load object as capella BeaconState.
    let state_inner = match load_ssz_snappy::<E::CapellaBeaconState>(case_dir, "object.ssz_snappy")
    {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &state_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

/// Run a single_merkle_proof case against a capella `BeaconBlockBody`.
fn run_single_merkle_proof_body_case<E: BeaconSpec>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E::CapellaBeaconBlockBody: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}")),
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}")),
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf_index")),
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: branch[{i}] not string")),
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let body_inner =
        match load_ssz_snappy::<E::CapellaBeaconBlockBody>(case_dir, "object.ssz_snappy") {
            Ok(s) => s,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let body_root = body_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &body_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

// ── Cross-fork upgrade helpers ────────────────────────────────────────────────

/// Upgrade a capella `LightClientHeader` to a deneb `LightClientHeader` by
/// adding `blob_gas_used = 0` and `excess_blob_gas = 0` to the execution header.
/// The `execution_branch` depth is unchanged (capella = deneb = 4).
fn upgrade_capella_header_to_deneb<const B: u64, const X: u64>(
    h: &CapellaLCHeader<B, X>,
) -> DenebLCHeader<B, X>
where
    Bytes32: Default + Clone,
    CapellaExecutionPayloadHeader<B, X>: Clone,
{
    let ce = &h.execution;
    DenebLCHeader {
        beacon: h.beacon.clone(),
        execution: DenebExecutionPayloadHeader {
            parent_hash: ce.parent_hash,
            fee_recipient: ce.fee_recipient,
            state_root: ce.state_root,
            receipts_root: ce.receipts_root,
            logs_bloom: ce.logs_bloom.clone(),
            prev_randao: ce.prev_randao,
            block_number: ce.block_number,
            gas_limit: ce.gas_limit,
            gas_used: ce.gas_used,
            timestamp: ce.timestamp,
            extra_data: ce.extra_data.clone(),
            base_fee_per_gas: ce.base_fee_per_gas,
            block_hash: ce.block_hash,
            transactions_root: ce.transactions_root,
            withdrawals_root: ce.withdrawals_root,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        },
        execution_branch: h.execution_branch.clone(),
    }
}

/// Upgrade a capella `LightClientUpdate` to a deneb `LightClientUpdate`.
///
/// Branch depths are unchanged (capella→deneb only changes the execution header).
fn upgrade_capella_update_to_deneb<const S: u64, const B: u64, const X: u64>(
    u: &CapellaLCUpdate<S, B, X>,
) -> DenebLCUpdate<S, B, X>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
    CapellaExecutionPayloadHeader<B, X>: Clone,
{
    DenebLCUpdate {
        attested_header: upgrade_capella_header_to_deneb(&u.attested_header),
        next_sync_committee: u.next_sync_committee.clone(),
        next_sync_committee_branch: u.next_sync_committee_branch.clone(),
        finalized_header: upgrade_capella_header_to_deneb(&u.finalized_header),
        finality_branch: u.finality_branch.clone(),
        sync_aggregate: u.sync_aggregate.clone(),
        signature_slot: u.signature_slot,
    }
}

/// Upgrade a deneb `LightClientUpdate` to an electra `LightClientUpdate`.
///
/// The execution header type is unchanged (electra re-exports deneb's header).
/// The sync-committee and finality branches are extended from depth 5→6 and 6→7
/// respectively by prepending one zero hash (`normalize_merkle_branch` in the spec).
fn upgrade_deneb_update_to_electra<const S: u64, const B: u64, const X: u64>(
    u: &DenebLCUpdate<S, B, X>,
) -> Result<ElectraLCUpdate<S, B, X>, String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let mut sc_branch = vec![Bytes32::default()];
    sc_branch.extend_from_slice(u.next_sync_committee_branch.as_slice());
    let next_sync_committee_branch =
        SszVector::<Bytes32, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA>::from_vec(sc_branch)
            .map_err(|e| format!("extend sc_branch: {e}"))?;

    let mut fin_branch = vec![Bytes32::default()];
    fin_branch.extend_from_slice(u.finality_branch.as_slice());
    let finality_branch = SszVector::<Bytes32, FINALITY_BRANCH_DEPTH_ELECTRA>::from_vec(fin_branch)
        .map_err(|e| format!("extend fin_branch: {e}"))?;

    Ok(ElectraLCUpdate {
        attested_header: u.attested_header.clone(),
        next_sync_committee: u.next_sync_committee.clone(),
        next_sync_committee_branch,
        finalized_header: u.finalized_header.clone(),
        finality_branch,
        sync_aggregate: u.sync_aggregate.clone(),
        signature_slot: u.signature_slot,
    })
}

/// Upgrade a capella LC store to a deneb LC store.
fn upgrade_capella_store_to_deneb<const S: u64, const B: u64, const X: u64>(
    s: CapellaLcStore<S, B, X>,
) -> DenebLcStore<S, B, X>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
    CapellaExecutionPayloadHeader<B, X>: Clone,
{
    let best_valid_update = s
        .best_valid_update
        .as_ref()
        .map(upgrade_capella_update_to_deneb);
    DenebLcStore {
        finalized_header: upgrade_capella_header_to_deneb(&s.finalized_header),
        current_sync_committee: s.current_sync_committee,
        next_sync_committee: s.next_sync_committee,
        best_valid_update,
        optimistic_header: upgrade_capella_header_to_deneb(&s.optimistic_header),
        previous_max_active_participants: s.previous_max_active_participants,
        current_max_active_participants: s.current_max_active_participants,
    }
}

/// Upgrade a deneb LC store to an electra LC store.
fn upgrade_deneb_store_to_electra<const S: u64, const B: u64, const X: u64>(
    s: DenebLcStore<S, B, X>,
) -> Result<ElectraLcStore<S, B, X>, String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let best_valid_update = match &s.best_valid_update {
        None => None,
        Some(u) => Some(upgrade_deneb_update_to_electra(u)?),
    };
    Ok(ElectraLcStore {
        finalized_header: s.finalized_header,
        current_sync_committee: s.current_sync_committee,
        next_sync_committee: s.next_sync_committee,
        best_valid_update,
        optimistic_header: s.optimistic_header,
        previous_max_active_participants: s.previous_max_active_participants,
        current_max_active_participants: s.current_max_active_participants,
    })
}

// ── Fork version string constants (minimal) ───────────────────────────────────
// Used to identify the initial store fork from meta.yaml `store_fork_version`.

const CAPELLA_FORK_VERSION_MINIMAL: &str = "0x03000001";
const DENEB_FORK_VERSION_MINIMAL: &str = "0x04000001";
const ELECTRA_FORK_VERSION_MINIMAL: &str = "0x05000001";
const CAPELLA_FORK_VERSION_MAINNET: &str = "0x03000000";
const DENEB_FORK_VERSION_MAINNET: &str = "0x04000000";
const ELECTRA_FORK_VERSION_MAINNET: &str = "0x05000000";

fn run_sync_case_capella_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_capella_impl::<MainnetBeaconSpec, 512, 256, 32>(case_dir, case_name)
}

fn run_sync_case_capella_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_capella_impl::<MinimalBeaconSpec, 32, 256, 32>(case_dir, case_name)
}

/// Simple in-memory capella light-client store for the conformance runner.
///
/// Mirrors `altair::LightClientStore` but uses the Capella `LightClientHeader`.
struct CapellaLcStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    finalized_header: CapellaLCHeader<B, X>,
    #[allow(dead_code)]
    current_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    next_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    best_valid_update: Option<CapellaLCUpdate<S, B, X>>,
    optimistic_header: CapellaLCHeader<B, X>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
}

/// Tracks the active LC store across `upgrade_store` steps in the capella runner.
/// The bootstrap is decoded as `CapellaLCBootstrap`; the initial store variant
/// is determined by `store_fork_version` in meta.yaml.
enum ActiveCapellaStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    Capella(CapellaLcStore<S, B, X>),
    Deneb(DenebLcStore<S, B, X>),
    Electra(ElectraLcStore<S, B, X>),
}

fn run_sync_case_capella_impl<E, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E: BeaconSpec,
    CapellaLCBootstrap<S, B, X>: Decode,
    CapellaLCUpdate<S, B, X>: Decode + Clone,
    DenebLCUpdate<S, B, X>: Decode + Clone,
    ElectraLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + PartialEq + Clone,
    pharos_utils::BLSPubkey: Default + PartialEq + Clone,
    CapellaExecutionPayloadHeader<B, X>: Clone,
    pharos_types::capella::ExecutionPayloadHeader<B, X>: TreeHash,
    pharos_types::deneb::ExecutionPayloadHeader<B, X>: TreeHash,
{
    // Parse meta.yaml.
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read meta.yaml: {e}")),
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}")),
    };

    let genesis_validators_root: Root = match meta_val
        .get("genesis_validators_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!(
                "{case_name}: missing/invalid genesis_validators_root"
            ));
        }
    };

    let trusted_block_root: Root = match meta_val
        .get("trusted_block_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!("{case_name}: missing/invalid trusted_block_root"));
        }
    };

    let bootstrap_fork_digest_str = meta_val
        .get("bootstrap_fork_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // `store_fork_version` determines the initial store type. When higher than
    // the bootstrap fork, the bootstrap header is upgraded on initialization.
    let store_fork_version = meta_val
        .get("store_fork_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Load bootstrap (always decoded as capella format).
    let bootstrap =
        match load_ssz_snappy::<CapellaLCBootstrap<S, B, X>>(case_dir, "bootstrap.ssz_snappy") {
            Ok(b) => b,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    // Verify bootstrap header root matches trusted_block_root.
    let header_root = bootstrap.header.beacon.tree_hash_root();
    if header_root != trusted_block_root {
        return CaseResult::Fail(format!(
            "{case_name}: bootstrap header root {header_root:?} != trusted {trusted_block_root:?}"
        ));
    }

    // Initialize the active store at the fork indicated by `store_fork_version`.
    let mut active_store: ActiveCapellaStore<S, B, X> = match store_fork_version {
        v if v == CAPELLA_FORK_VERSION_MINIMAL
            || v == CAPELLA_FORK_VERSION_MAINNET
            || v.is_empty() =>
        {
            ActiveCapellaStore::Capella(CapellaLcStore {
                finalized_header: bootstrap.header.clone(),
                current_sync_committee: bootstrap.current_sync_committee.clone(),
                next_sync_committee: Default::default(),
                best_valid_update: None,
                optimistic_header: bootstrap.header.clone(),
                previous_max_active_participants: 0,
                current_max_active_participants: 0,
            })
        }
        v if v == DENEB_FORK_VERSION_MINIMAL || v == DENEB_FORK_VERSION_MAINNET => {
            let deneb_header = upgrade_capella_header_to_deneb(&bootstrap.header);
            ActiveCapellaStore::Deneb(DenebLcStore {
                finalized_header: deneb_header.clone(),
                current_sync_committee: bootstrap.current_sync_committee.clone(),
                next_sync_committee: Default::default(),
                best_valid_update: None,
                optimistic_header: deneb_header,
                previous_max_active_participants: 0,
                current_max_active_participants: 0,
            })
        }
        v if v == ELECTRA_FORK_VERSION_MINIMAL || v == ELECTRA_FORK_VERSION_MAINNET => {
            // capella → deneb → electra (header is deneb = electra re-export)
            let deneb_header = upgrade_capella_header_to_deneb(&bootstrap.header);
            ActiveCapellaStore::Electra(ElectraLcStore {
                finalized_header: deneb_header.clone(),
                current_sync_committee: bootstrap.current_sync_committee.clone(),
                next_sync_committee: Default::default(),
                best_valid_update: None,
                optimistic_header: deneb_header,
                previous_max_active_participants: 0,
                current_max_active_participants: 0,
            })
        }
        other => {
            return CaseResult::Fail(format!("{case_name}: unknown store_fork_version '{other}'"));
        }
    };

    // Load fork epoch constants for epoch-conditional execution_root computation.
    let config_path = case_dir.join("config.yaml");
    let deneb_fork_epoch = parse_config_fork_epoch(&config_path, "DENEB_FORK_EPOCH");
    let slots_per_epoch = E::SLOTS_PER_EPOCH;

    // Parse and execute steps.yaml.
    let steps_path = case_dir.join("steps.yaml");
    let steps_text = match std::fs::read_to_string(&steps_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read steps.yaml: {e}")),
    };
    let steps_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&steps_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse steps.yaml: {e}")),
    };
    let steps = match steps_val.as_sequence() {
        Some(s) => s.clone(),
        None => return CaseResult::Fail(format!("{case_name}: steps.yaml is not a sequence")),
    };

    let update_timeout = E::SLOTS_PER_EPOCH * E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

    for (step_idx, step) in steps.iter().enumerate() {
        if let Some(force_update) = step.get("force_update") {
            let current_slot = match force_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };
            match &mut active_store {
                ActiveCapellaStore::Capella(store) => {
                    if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                        && store.best_valid_update.is_some()
                    {
                        let mut best = store.best_valid_update.take().unwrap();
                        if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                            best.finalized_header = best.attested_header.clone();
                        }
                        apply_capella_lc_update::<S, B, X>(store, &best);
                    }
                    if let Some(checks) = force_update.get("checks")
                        && let Err(e) =
                            check_capella_store::<S, B, X>(store, checks, case_name, step_idx)
                    {
                        return CaseResult::Fail(e);
                    }
                }
                ActiveCapellaStore::Deneb(store) => {
                    if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                        && store.best_valid_update.is_some()
                    {
                        let mut best = store.best_valid_update.take().unwrap();
                        if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                            best.finalized_header = best.attested_header.clone();
                        }
                        apply_deneb_lc_update::<S, B, X>(store, &best);
                    }
                    if let Some(checks) = force_update.get("checks")
                        && let Err(e) = check_deneb_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
                ActiveCapellaStore::Electra(store) => {
                    if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                        && store.best_valid_update.is_some()
                    {
                        let mut best = store.best_valid_update.take().unwrap();
                        if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                            best.finalized_header = best.attested_header.clone();
                        }
                        apply_electra_lc_update::<S, B, X>(store, &best);
                    }
                    if let Some(checks) = force_update.get("checks")
                        && let Err(e) = check_electra_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
            }
        } else if let Some(process_update) = step.get("process_update") {
            let update_file = match process_update.get("update").and_then(|v| v.as_str()) {
                Some(s) => format!("{s}.ssz_snappy"),
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing update filename"
                    ));
                }
            };
            let current_slot = match process_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };

            let update_fork_digest = process_update
                .get("update_fork_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Determine update SSZ format: capella digest → decode as capella update;
            // anything else (deneb, electra digest) → decode at the appropriate level.
            let is_capella_update =
                update_fork_digest.is_empty() || update_fork_digest == bootstrap_fork_digest_str;

            match &mut active_store {
                ActiveCapellaStore::Capella(store) => {
                    let update = if is_capella_update {
                        match load_ssz_snappy::<CapellaLCUpdate<S, B, X>>(case_dir, &update_file) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load update: {e}"
                                ));
                            }
                        }
                    } else {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: cross-fork update (digest {update_fork_digest}) arrived before upgrade_store"
                        ));
                    };
                    if let Err(e) = process_capella_lc_update::<S, B, X>(
                        store,
                        &update,
                        current_slot,
                        &genesis_validators_root,
                    ) {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: process_update: {e}"
                        ));
                    }
                    if let Some(checks) = process_update.get("checks")
                        && let Err(e) =
                            check_capella_store::<S, B, X>(store, checks, case_name, step_idx)
                    {
                        return CaseResult::Fail(e);
                    }
                }
                ActiveCapellaStore::Deneb(store) => {
                    let update: DenebLCUpdate<S, B, X> = if is_capella_update {
                        let capella_u = match load_ssz_snappy::<CapellaLCUpdate<S, B, X>>(
                            case_dir,
                            &update_file,
                        ) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load capella update: {e}"
                                ));
                            }
                        };
                        upgrade_capella_update_to_deneb(&capella_u)
                    } else {
                        match load_ssz_snappy::<DenebLCUpdate<S, B, X>>(case_dir, &update_file) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load deneb update: {e}"
                                ));
                            }
                        }
                    };
                    if let Err(e) = process_deneb_lc_update::<S, B, X>(
                        store,
                        &update,
                        current_slot,
                        &genesis_validators_root,
                    ) {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: process_update: {e}"
                        ));
                    }
                    if let Some(checks) = process_update.get("checks")
                        && let Err(e) = check_deneb_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
                ActiveCapellaStore::Electra(store) => {
                    let update: ElectraLCUpdate<S, B, X> = if is_capella_update {
                        let capella_u = match load_ssz_snappy::<CapellaLCUpdate<S, B, X>>(
                            case_dir,
                            &update_file,
                        ) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load capella update: {e}"
                                ));
                            }
                        };
                        let deneb_u = upgrade_capella_update_to_deneb(&capella_u);
                        match upgrade_deneb_update_to_electra(&deneb_u) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: upgrade to electra: {e}"
                                ));
                            }
                        }
                    } else {
                        // Check if deneb-format update (must be upgraded to electra).
                        // Electra-format updates would also be possible but capella sync cases
                        // only ever use bootstrap (capella) or deneb digest updates.
                        let deneb_u = match load_ssz_snappy::<DenebLCUpdate<S, B, X>>(
                            case_dir,
                            &update_file,
                        ) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load deneb update (for electra store): {e}"
                                ));
                            }
                        };
                        match upgrade_deneb_update_to_electra(&deneb_u) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: upgrade to electra: {e}"
                                ));
                            }
                        }
                    };
                    if let Err(e) = process_electra_lc_update::<S, B, X>(
                        store,
                        &update,
                        current_slot,
                        &genesis_validators_root,
                    ) {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: process_update: {e}"
                        ));
                    }
                    if let Some(checks) = process_update.get("checks")
                        && let Err(e) = check_electra_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
            }
        } else if let Some(upgrade) = step.get("upgrade_store") {
            // Perform the cross-fork store upgrade indicated by `store_fork_version`.
            let target_version = upgrade
                .get("store_fork_version")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let checks_val = upgrade.get("checks").cloned();

            let upgraded = match active_store {
                ActiveCapellaStore::Capella(store) => match target_version {
                    v if v == DENEB_FORK_VERSION_MINIMAL || v == DENEB_FORK_VERSION_MAINNET => {
                        ActiveCapellaStore::Deneb(upgrade_capella_store_to_deneb(store))
                    }
                    v if v == ELECTRA_FORK_VERSION_MINIMAL || v == ELECTRA_FORK_VERSION_MAINNET => {
                        let deneb = upgrade_capella_store_to_deneb(store);
                        match upgrade_deneb_store_to_electra(deneb) {
                            Ok(s) => ActiveCapellaStore::Electra(s),
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: upgrade_store: {e}"
                                ));
                            }
                        }
                    }
                    other => {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: upgrade_store to unknown version '{other}'"
                        ));
                    }
                },
                ActiveCapellaStore::Deneb(store) => match target_version {
                    v if v == ELECTRA_FORK_VERSION_MINIMAL || v == ELECTRA_FORK_VERSION_MAINNET => {
                        match upgrade_deneb_store_to_electra(store) {
                            Ok(s) => ActiveCapellaStore::Electra(s),
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: upgrade_store: {e}"
                                ));
                            }
                        }
                    }
                    other => {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: upgrade_store deneb→{other} not supported"
                        ));
                    }
                },
                ActiveCapellaStore::Electra(_) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: upgrade_store on already-electra store"
                    ));
                }
            };
            active_store = upgraded;

            if let Some(checks) = checks_val {
                let result = match &active_store {
                    ActiveCapellaStore::Capella(store) => {
                        check_capella_store::<S, B, X>(store, &checks, case_name, step_idx)
                    }
                    ActiveCapellaStore::Deneb(store) => check_deneb_store::<S, B, X>(
                        store,
                        &checks,
                        case_name,
                        step_idx,
                        deneb_fork_epoch,
                        slots_per_epoch,
                    ),
                    ActiveCapellaStore::Electra(store) => check_electra_store::<S, B, X>(
                        store,
                        &checks,
                        case_name,
                        step_idx,
                        deneb_fork_epoch,
                        slots_per_epoch,
                    ),
                };
                if let Err(e) = result {
                    return CaseResult::Fail(e);
                }
            }
        }
    }

    CaseResult::Pass
}

fn check_capella_store<const S: u64, const B: u64, const X: u64>(
    store: &CapellaLcStore<S, B, X>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
) -> Result<(), String>
where
    Bytes32: Default + Clone,
    pharos_types::capella::ExecutionPayloadHeader<B, X>: TreeHash,
{
    if let Some(fin_check) = checks.get("finalized_header") {
        let expected_slot = fin_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.finalized_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: finalized_header.slot mismatch: got {}, expected {}",
                store.finalized_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = fin_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.finalized_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.beacon_root mismatch"
                ));
            }
        }
        if let Some(expected_root_hex) = fin_check.get("execution_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: execution_root parse: {e}"))?;
            let actual_root = store.finalized_header.execution.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.execution_root mismatch"
                ));
            }
        }
    }
    if let Some(opt_check) = checks.get("optimistic_header") {
        let expected_slot = opt_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.optimistic_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: optimistic_header.slot mismatch: got {}, expected {}",
                store.optimistic_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = opt_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.optimistic_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.beacon_root mismatch"
                ));
            }
        }
        if let Some(expected_root_hex) = opt_check.get("execution_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: execution_root parse: {e}"))?;
            let actual_root = store.optimistic_header.execution.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.execution_root mismatch"
                ));
            }
        }
    }
    Ok(())
}

/// Apply a capella LC update to the store (mirrors altair `apply_light_client_update`).
fn apply_capella_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut CapellaLcStore<S, B, X>,
    update: &CapellaLCUpdate<S, B, X>,
) where
    Bytes32: Default + Clone + PartialEq,
{
    let default_branch: Vec<Bytes32> = vec![
        Bytes32::default();
        pharos_types::altair::light_client::NEXT_SYNC_COMMITTEE_BRANCH_DEPTH
            as usize
    ];
    if update.next_sync_committee_branch.as_slice() != default_branch.as_slice() {
        // Update next_sync_committee when the sync committee branch is present.
        store.next_sync_committee = update.next_sync_committee.clone();
    }
    store.finalized_header = update.finalized_header.clone();
    if store.optimistic_header.beacon.slot <= store.finalized_header.beacon.slot {
        store.optimistic_header = store.finalized_header.clone();
    }
    // Swap participant counts.
    store.previous_max_active_participants = store.current_max_active_participants;
    store.current_max_active_participants = 0;
}

/// Process a capella LC update (minimal sync protocol implementation).
///
/// Mirrors `process_light_client_update` from the altair sync protocol but
/// works with capella-typed headers. The BLS signature verification is omitted
/// as in the altair conformance runner (the spec tests don't require it for
/// this category).
fn process_capella_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut CapellaLcStore<S, B, X>,
    update: &CapellaLCUpdate<S, B, X>,
    _current_slot: Slot,
    _genesis_validators_root: &Root,
) -> Result<(), String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let n_participants = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|b| *b)
        .count() as u64;

    // Update best valid update.
    let update_is_better = match &store.best_valid_update {
        None => true,
        Some(best) => {
            let new_has_fin = is_capella_finality_update(update);
            let best_has_fin = is_capella_finality_update(best);
            if new_has_fin != best_has_fin {
                new_has_fin
            } else {
                n_participants
                    > best
                        .sync_aggregate
                        .sync_committee_bits
                        .iter()
                        .filter(|b| *b)
                        .count() as u64
            }
        }
    };
    if update_is_better {
        store.best_valid_update = Some(update.clone());
    }

    store.current_max_active_participants =
        store.current_max_active_participants.max(n_participants);

    let safety_threshold = store
        .previous_max_active_participants
        .max(store.current_max_active_participants)
        / 2;

    // Update optimistic header.
    if n_participants > safety_threshold
        && update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    {
        store.optimistic_header = update.attested_header.clone();
    }

    // Update finalized header.
    if n_participants * 3 >= S * 2
        && (update.finalized_header.beacon.slot > store.finalized_header.beacon.slot)
    {
        apply_capella_lc_update::<S, B, X>(store, update);
        store.best_valid_update = None;
    }

    Ok(())
}

fn is_capella_finality_update<const S: u64, const B: u64, const X: u64>(
    update: &CapellaLCUpdate<S, B, X>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    update.finality_branch.as_slice()
        != vec![
            Bytes32::default();
            pharos_types::altair::light_client::FINALITY_BRANCH_DEPTH as usize
        ]
        .as_slice()
}

fn run_single_merkle_proof_deneb_state_case<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::DenebBeaconState: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}"));
        }
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}"));
        }
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf in proof.yaml")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            return CaseResult::Fail(format!("{case_name}: missing leaf_index in proof.yaml"));
        }
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch in proof.yaml")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] is not a string"));
            }
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let state_inner = match load_ssz_snappy::<E::DenebBeaconState>(case_dir, "object.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &state_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_single_merkle_proof_deneb_body_case<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::DenebBeaconBlockBody: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}")),
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}")),
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf_index")),
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: branch[{i}] not string")),
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let body_inner = match load_ssz_snappy::<E::DenebBeaconBlockBody>(case_dir, "object.ssz_snappy")
    {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let body_root = body_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &body_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_sync_case_deneb_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_deneb_impl::<MainnetBeaconSpec, 512, 256, 32>(case_dir, case_name)
}

fn run_sync_case_deneb_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_deneb_impl::<MinimalBeaconSpec, 32, 256, 32>(case_dir, case_name)
}

/// Simple in-memory deneb light-client store for the conformance runner.
struct DenebLcStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    finalized_header: DenebLCHeader<B, X>,
    #[allow(dead_code)]
    current_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    next_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    best_valid_update: Option<DenebLCUpdate<S, B, X>>,
    optimistic_header: DenebLCHeader<B, X>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
}

/// Tracks the active LC store across `upgrade_store` steps in the deneb runner.
enum ActiveDenebStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    Deneb(DenebLcStore<S, B, X>),
    Electra(ElectraLcStore<S, B, X>),
}

fn run_sync_case_deneb_impl<E, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E: BeaconSpec,
    DenebLCBootstrap<S, B, X>: Decode,
    DenebLCUpdate<S, B, X>: Decode + Clone,
    ElectraLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + PartialEq + Clone,
    pharos_utils::BLSPubkey: Default + PartialEq + Clone,
    pharos_types::deneb::ExecutionPayloadHeader<B, X>: TreeHash,
{
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read meta.yaml: {e}")),
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}")),
    };

    let genesis_validators_root: Root = match meta_val
        .get("genesis_validators_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!(
                "{case_name}: missing/invalid genesis_validators_root"
            ));
        }
    };

    let trusted_block_root: Root = match meta_val
        .get("trusted_block_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!("{case_name}: missing/invalid trusted_block_root"));
        }
    };

    let bootstrap_fork_digest_str = meta_val
        .get("bootstrap_fork_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let store_fork_version = meta_val
        .get("store_fork_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let bootstrap =
        match load_ssz_snappy::<DenebLCBootstrap<S, B, X>>(case_dir, "bootstrap.ssz_snappy") {
            Ok(b) => b,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let header_root = bootstrap.header.beacon.tree_hash_root();
    if header_root != trusted_block_root {
        return CaseResult::Fail(format!(
            "{case_name}: bootstrap header root {header_root:?} != trusted {trusted_block_root:?}"
        ));
    }

    // Initialize the active store at the fork indicated by `store_fork_version`.
    let mut active_store: ActiveDenebStore<S, B, X> = match store_fork_version {
        v if v == DENEB_FORK_VERSION_MINIMAL || v == DENEB_FORK_VERSION_MAINNET || v.is_empty() => {
            ActiveDenebStore::Deneb(DenebLcStore {
                finalized_header: bootstrap.header.clone(),
                current_sync_committee: bootstrap.current_sync_committee.clone(),
                next_sync_committee: Default::default(),
                best_valid_update: None,
                optimistic_header: bootstrap.header.clone(),
                previous_max_active_participants: 0,
                current_max_active_participants: 0,
            })
        }
        v if v == ELECTRA_FORK_VERSION_MINIMAL || v == ELECTRA_FORK_VERSION_MAINNET => {
            // deneb → electra: header is the same type (electra re-exports deneb's header)
            ActiveDenebStore::Electra(ElectraLcStore {
                finalized_header: bootstrap.header.clone(),
                current_sync_committee: bootstrap.current_sync_committee.clone(),
                next_sync_committee: Default::default(),
                best_valid_update: None,
                optimistic_header: bootstrap.header.clone(),
                previous_max_active_participants: 0,
                current_max_active_participants: 0,
            })
        }
        other => {
            return CaseResult::Fail(format!("{case_name}: unknown store_fork_version '{other}'"));
        }
    };

    // Load fork epoch constants for epoch-conditional execution_root computation.
    let config_path = case_dir.join("config.yaml");
    let deneb_fork_epoch = parse_config_fork_epoch(&config_path, "DENEB_FORK_EPOCH");
    let slots_per_epoch = E::SLOTS_PER_EPOCH;

    let steps_path = case_dir.join("steps.yaml");
    let steps_text = match std::fs::read_to_string(&steps_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read steps.yaml: {e}")),
    };
    let steps_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&steps_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse steps.yaml: {e}")),
    };
    let steps = match steps_val.as_sequence() {
        Some(s) => s.clone(),
        None => return CaseResult::Fail(format!("{case_name}: steps.yaml is not a sequence")),
    };

    let update_timeout = E::SLOTS_PER_EPOCH * E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

    for (step_idx, step) in steps.iter().enumerate() {
        if let Some(force_update) = step.get("force_update") {
            let current_slot = match force_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };
            match &mut active_store {
                ActiveDenebStore::Deneb(store) => {
                    if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                        && store.best_valid_update.is_some()
                    {
                        let mut best = store.best_valid_update.take().unwrap();
                        if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                            best.finalized_header = best.attested_header.clone();
                        }
                        apply_deneb_lc_update::<S, B, X>(store, &best);
                    }
                    if let Some(checks) = force_update.get("checks")
                        && let Err(e) = check_deneb_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
                ActiveDenebStore::Electra(store) => {
                    if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                        && store.best_valid_update.is_some()
                    {
                        let mut best = store.best_valid_update.take().unwrap();
                        if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                            best.finalized_header = best.attested_header.clone();
                        }
                        apply_electra_lc_update::<S, B, X>(store, &best);
                    }
                    if let Some(checks) = force_update.get("checks")
                        && let Err(e) = check_electra_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
            }
        } else if let Some(process_update) = step.get("process_update") {
            let update_file = match process_update.get("update").and_then(|v| v.as_str()) {
                Some(s) => format!("{s}.ssz_snappy"),
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing update filename"
                    ));
                }
            };
            let current_slot = match process_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };

            let update_fork_digest = process_update
                .get("update_fork_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // deneb digest = bootstrap_fork_digest_str; electra digest = anything else
            let is_deneb_update =
                update_fork_digest.is_empty() || update_fork_digest == bootstrap_fork_digest_str;

            match &mut active_store {
                ActiveDenebStore::Deneb(store) => {
                    let update = if is_deneb_update {
                        match load_ssz_snappy::<DenebLCUpdate<S, B, X>>(case_dir, &update_file) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load update: {e}"
                                ));
                            }
                        }
                    } else {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: cross-fork update (digest {update_fork_digest}) arrived before upgrade_store"
                        ));
                    };
                    if let Err(e) = process_deneb_lc_update::<S, B, X>(
                        store,
                        &update,
                        current_slot,
                        &genesis_validators_root,
                    ) {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: process_update: {e}"
                        ));
                    }
                    if let Some(checks) = process_update.get("checks")
                        && let Err(e) = check_deneb_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
                ActiveDenebStore::Electra(store) => {
                    let update: ElectraLCUpdate<S, B, X> = if is_deneb_update {
                        let deneb_u =
                            match load_ssz_snappy::<DenebLCUpdate<S, B, X>>(case_dir, &update_file)
                            {
                                Ok(u) => u,
                                Err(e) => {
                                    return CaseResult::Fail(format!(
                                        "{case_name}: step {step_idx}: load deneb update: {e}"
                                    ));
                                }
                            };
                        match upgrade_deneb_update_to_electra(&deneb_u) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: upgrade to electra: {e}"
                                ));
                            }
                        }
                    } else {
                        match load_ssz_snappy::<ElectraLCUpdate<S, B, X>>(case_dir, &update_file) {
                            Ok(u) => u,
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: load electra update: {e}"
                                ));
                            }
                        }
                    };
                    if let Err(e) = process_electra_lc_update::<S, B, X>(
                        store,
                        &update,
                        current_slot,
                        &genesis_validators_root,
                    ) {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: process_update: {e}"
                        ));
                    }
                    if let Some(checks) = process_update.get("checks")
                        && let Err(e) = check_electra_store::<S, B, X>(
                            store,
                            checks,
                            case_name,
                            step_idx,
                            deneb_fork_epoch,
                            slots_per_epoch,
                        )
                    {
                        return CaseResult::Fail(e);
                    }
                }
            }
        } else if let Some(upgrade) = step.get("upgrade_store") {
            let target_version = upgrade
                .get("store_fork_version")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let checks_val = upgrade.get("checks").cloned();

            let upgraded = match active_store {
                ActiveDenebStore::Deneb(store) => match target_version {
                    v if v == ELECTRA_FORK_VERSION_MINIMAL || v == ELECTRA_FORK_VERSION_MAINNET => {
                        match upgrade_deneb_store_to_electra(store) {
                            Ok(s) => ActiveDenebStore::Electra(s),
                            Err(e) => {
                                return CaseResult::Fail(format!(
                                    "{case_name}: step {step_idx}: upgrade_store: {e}"
                                ));
                            }
                        }
                    }
                    other => {
                        return CaseResult::Fail(format!(
                            "{case_name}: step {step_idx}: upgrade_store deneb→{other} not supported"
                        ));
                    }
                },
                ActiveDenebStore::Electra(_) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: upgrade_store on already-electra store"
                    ));
                }
            };
            active_store = upgraded;

            if let Some(checks) = checks_val {
                let result = match &active_store {
                    ActiveDenebStore::Deneb(store) => check_deneb_store::<S, B, X>(
                        store,
                        &checks,
                        case_name,
                        step_idx,
                        deneb_fork_epoch,
                        slots_per_epoch,
                    ),
                    ActiveDenebStore::Electra(store) => check_electra_store::<S, B, X>(
                        store,
                        &checks,
                        case_name,
                        step_idx,
                        deneb_fork_epoch,
                        slots_per_epoch,
                    ),
                };
                if let Err(e) = result {
                    return CaseResult::Fail(e);
                }
            }
        }
    }

    CaseResult::Pass
}

fn check_deneb_store<const S: u64, const B: u64, const X: u64>(
    store: &DenebLcStore<S, B, X>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
    deneb_fork_epoch: u64,
    slots_per_epoch: u64,
) -> Result<(), String>
where
    Bytes32: Default + Clone,
    pharos_types::deneb::ExecutionPayloadHeader<B, X>: TreeHash,
    pharos_types::capella::ExecutionPayloadHeader<B, X>: TreeHash,
    CapellaExecutionPayloadHeader<B, X>: Clone,
{
    if let Some(fin_check) = checks.get("finalized_header") {
        let expected_slot = fin_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.finalized_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: finalized_header.slot mismatch: got {}, expected {}",
                store.finalized_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = fin_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.finalized_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.beacon_root mismatch"
                ));
            }
        }
        if let Some(expected_root_hex) = fin_check.get("execution_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: execution_root parse: {e}"))?;
            let fin_slot_epoch = store
                .finalized_header
                .beacon
                .slot
                .0
                .checked_div(slots_per_epoch)
                .unwrap_or(0);
            let actual_root = if fin_slot_epoch < deneb_fork_epoch {
                capella_execution_root_from_deneb(&store.finalized_header.execution)
            } else {
                store.finalized_header.execution.tree_hash_root()
            };
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.execution_root mismatch"
                ));
            }
        }
    }
    if let Some(opt_check) = checks.get("optimistic_header") {
        let expected_slot = opt_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.optimistic_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: optimistic_header.slot mismatch: got {}, expected {}",
                store.optimistic_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = opt_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.optimistic_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.beacon_root mismatch"
                ));
            }
        }
        if let Some(expected_root_hex) = opt_check.get("execution_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: execution_root parse: {e}"))?;
            let opt_slot_epoch = store
                .optimistic_header
                .beacon
                .slot
                .0
                .checked_div(slots_per_epoch)
                .unwrap_or(0);
            let actual_root = if opt_slot_epoch < deneb_fork_epoch {
                capella_execution_root_from_deneb(&store.optimistic_header.execution)
            } else {
                store.optimistic_header.execution.tree_hash_root()
            };
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.execution_root mismatch"
                ));
            }
        }
    }
    Ok(())
}

fn apply_deneb_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut DenebLcStore<S, B, X>,
    update: &DenebLCUpdate<S, B, X>,
) where
    Bytes32: Default + Clone + PartialEq,
{
    let default_branch: Vec<Bytes32> = vec![
        Bytes32::default();
        pharos_types::altair::light_client::NEXT_SYNC_COMMITTEE_BRANCH_DEPTH
            as usize
    ];
    if update.next_sync_committee_branch.as_slice() != default_branch.as_slice() {
        store.next_sync_committee = update.next_sync_committee.clone();
    }
    store.finalized_header = update.finalized_header.clone();
    if store.optimistic_header.beacon.slot <= store.finalized_header.beacon.slot {
        store.optimistic_header = store.finalized_header.clone();
    }
    store.previous_max_active_participants = store.current_max_active_participants;
    store.current_max_active_participants = 0;
}

fn process_deneb_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut DenebLcStore<S, B, X>,
    update: &DenebLCUpdate<S, B, X>,
    _current_slot: Slot,
    _genesis_validators_root: &Root,
) -> Result<(), String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let n_participants = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|b| *b)
        .count() as u64;

    let update_is_better = match &store.best_valid_update {
        None => true,
        Some(best) => {
            let new_has_fin = is_deneb_finality_update(update);
            let best_has_fin = is_deneb_finality_update(best);
            if new_has_fin != best_has_fin {
                new_has_fin
            } else {
                n_participants
                    > best
                        .sync_aggregate
                        .sync_committee_bits
                        .iter()
                        .filter(|b| *b)
                        .count() as u64
            }
        }
    };
    if update_is_better {
        store.best_valid_update = Some(update.clone());
    }

    store.current_max_active_participants =
        store.current_max_active_participants.max(n_participants);

    let safety_threshold = store
        .previous_max_active_participants
        .max(store.current_max_active_participants)
        / 2;

    if n_participants > safety_threshold
        && update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    {
        store.optimistic_header = update.attested_header.clone();
    }

    if n_participants * 3 >= S * 2
        && (update.finalized_header.beacon.slot > store.finalized_header.beacon.slot)
    {
        apply_deneb_lc_update::<S, B, X>(store, update);
        store.best_valid_update = None;
    }

    Ok(())
}

fn is_deneb_finality_update<const S: u64, const B: u64, const X: u64>(
    update: &DenebLCUpdate<S, B, X>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    update.finality_branch.as_slice()
        != vec![
            Bytes32::default();
            pharos_types::altair::light_client::FINALITY_BRANCH_DEPTH as usize
        ]
        .as_slice()
}

// ── Electra light-client runners ──────────────────────────────────────────────

fn run_single_merkle_proof_electra_state_case<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::ElectraBeaconState: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}"));
        }
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => {
            return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}"));
        }
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf in proof.yaml")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            return CaseResult::Fail(format!("{case_name}: missing leaf_index in proof.yaml"));
        }
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch in proof.yaml")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] is not a string"));
            }
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let state_inner = match load_ssz_snappy::<E::ElectraBeaconState>(case_dir, "object.ssz_snappy")
    {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &state_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

/// Fulu `BeaconState` merkle-proof case. Fulu reshapes `BeaconState` (adds the
/// EIP-7917 `proposer_lookahead` field), so the fulu state type is decoded here
/// rather than the electra one. The LC branch proofs (current/next sync committee,
/// finality root) are otherwise identical to electra.
fn run_single_merkle_proof_fulu_state_case<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::FuluBeaconState: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}")),
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}")),
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf in proof.yaml")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf_index in proof.yaml")),
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch in proof.yaml")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: branch[{i}] is not a string")),
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}")),
        }
    }

    let state_inner = match load_ssz_snappy::<E::FuluBeaconState>(case_dir, "object.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let state_root = state_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &state_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_single_merkle_proof_electra_body_case<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E::ElectraBeaconBlockBody: Decode + TreeHash,
{
    let proof_path = case_dir.join("proof.yaml");
    let proof_text = match std::fs::read_to_string(&proof_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read proof.yaml: {e}")),
    };
    let proof_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&proof_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse proof.yaml: {e}")),
    };

    let leaf_hex = match proof_val.get("leaf").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf")),
    };
    let leaf_index = match proof_val.get("leaf_index").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => return CaseResult::Fail(format!("{case_name}: missing leaf_index")),
    };
    let branch_val = match proof_val.get("branch").and_then(|v| v.as_sequence()) {
        Some(b) => b.clone(),
        None => return CaseResult::Fail(format!("{case_name}: missing branch")),
    };

    let leaf = match parse_bytes32(leaf_hex) {
        Ok(b) => b,
        Err(e) => return CaseResult::Fail(format!("{case_name}: leaf parse: {e}")),
    };

    let mut branch: Vec<Bytes32> = Vec::new();
    for (i, v) in branch_val.iter().enumerate() {
        let hex = match v.as_str() {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: branch[{i}] not string")),
        };
        match parse_bytes32(hex) {
            Ok(b) => branch.push(b),
            Err(e) => {
                return CaseResult::Fail(format!("{case_name}: branch[{i}] parse: {e}"));
            }
        }
    }

    let body_inner =
        match load_ssz_snappy::<E::ElectraBeaconBlockBody>(case_dir, "object.ssz_snappy") {
            Ok(s) => s,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let body_root = body_inner.tree_hash_root();

    if leaf_index == 0 {
        return CaseResult::Fail(format!("{case_name}: leaf_index 0 is invalid"));
    }
    let depth = 63 - leaf_index.leading_zeros() as u64;
    let index = leaf_index % (1u64 << depth);

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    if is_valid_merkle_branch(&leaf, &branch, depth, index, &body_root) {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: merkle branch verification failed"))
    }
}

fn run_sync_case_electra_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_electra_impl::<MainnetBeaconSpec, 512, 256, 32>(case_dir, case_name)
}

fn run_sync_case_electra_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_electra_impl::<MinimalBeaconSpec, 32, 256, 32>(case_dir, case_name)
}

// Fulu LC sync: the fulu LC bootstrap/update/header types ARE the electra LC
// types (re-exported in `pharos_types::fulu::light_client`), so the fulu sync
// case decodes and verifies through the same electra LC store machinery.
fn run_sync_case_fulu_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_electra_impl::<MainnetBeaconSpec, 512, 256, 32>(case_dir, case_name)
}

fn run_sync_case_fulu_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    run_sync_case_electra_impl::<MinimalBeaconSpec, 32, 256, 32>(case_dir, case_name)
}

/// Simple in-memory electra light-client store for the conformance runner.
struct ElectraLcStore<const S: u64, const B: u64, const X: u64>
where
    Bytes32: Default + Clone,
{
    finalized_header: ElectraLCHeader<B, X>,
    #[allow(dead_code)]
    current_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    next_sync_committee: pharos_types::altair::operations::SyncCommittee<S>,
    best_valid_update: Option<ElectraLCUpdate<S, B, X>>,
    optimistic_header: ElectraLCHeader<B, X>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
}

fn run_sync_case_electra_impl<E, const S: u64, const B: u64, const X: u64>(
    case_dir: &Path,
    case_name: &str,
) -> CaseResult
where
    E: BeaconSpec,
    ElectraLCBootstrap<S, B, X>: Decode,
    ElectraLCUpdate<S, B, X>: Decode + Clone,
    Bytes32: Default + PartialEq + Clone,
    pharos_utils::BLSPubkey: Default + PartialEq + Clone,
{
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read meta.yaml: {e}")),
    };
    let meta_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse meta.yaml: {e}")),
    };

    let genesis_validators_root: Root = match meta_val
        .get("genesis_validators_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!(
                "{case_name}: missing/invalid genesis_validators_root"
            ));
        }
    };

    let trusted_block_root: Root = match meta_val
        .get("trusted_block_root")
        .and_then(|v| v.as_str())
        .map(parse_root)
    {
        Some(Ok(r)) => r,
        _ => {
            return CaseResult::Fail(format!("{case_name}: missing/invalid trusted_block_root"));
        }
    };

    let bootstrap =
        match load_ssz_snappy::<ElectraLCBootstrap<S, B, X>>(case_dir, "bootstrap.ssz_snappy") {
            Ok(b) => b,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let header_root = bootstrap.header.beacon.tree_hash_root();
    if header_root != trusted_block_root {
        return CaseResult::Fail(format!(
            "{case_name}: bootstrap header root {header_root:?} != trusted {trusted_block_root:?}"
        ));
    }

    let mut store: ElectraLcStore<S, B, X> = ElectraLcStore {
        finalized_header: bootstrap.header.clone(),
        current_sync_committee: bootstrap.current_sync_committee.clone(),
        next_sync_committee: Default::default(),
        best_valid_update: None,
        optimistic_header: bootstrap.header.clone(),
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
    };

    // Load fork epoch constants for epoch-conditional execution_root computation.
    let config_path = case_dir.join("config.yaml");
    let deneb_fork_epoch = parse_config_fork_epoch(&config_path, "DENEB_FORK_EPOCH");
    let slots_per_epoch = E::SLOTS_PER_EPOCH;

    let steps_path = case_dir.join("steps.yaml");
    let steps_text = match std::fs::read_to_string(&steps_path) {
        Ok(t) => t,
        Err(e) => return CaseResult::Fail(format!("{case_name}: read steps.yaml: {e}")),
    };
    let steps_val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&steps_text) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: parse steps.yaml: {e}")),
    };
    let steps = match steps_val.as_sequence() {
        Some(s) => s.clone(),
        None => return CaseResult::Fail(format!("{case_name}: steps.yaml is not a sequence")),
    };

    let update_timeout = E::SLOTS_PER_EPOCH * E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

    for (step_idx, step) in steps.iter().enumerate() {
        if let Some(force_update) = step.get("force_update") {
            let current_slot = match force_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };
            if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
                && store.best_valid_update.is_some()
            {
                let mut best = store.best_valid_update.take().unwrap();
                if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
                    best.finalized_header = best.attested_header.clone();
                }
                apply_electra_lc_update::<S, B, X>(&mut store, &best);
            }
            if let Some(checks) = force_update.get("checks")
                && let Err(e) = check_electra_store::<S, B, X>(
                    &store,
                    checks,
                    case_name,
                    step_idx,
                    deneb_fork_epoch,
                    slots_per_epoch,
                )
            {
                return CaseResult::Fail(e);
            }
        } else if let Some(process_update) = step.get("process_update") {
            let update_file = match process_update.get("update").and_then(|v| v.as_str()) {
                Some(s) => format!("{s}.ssz_snappy"),
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing update filename"
                    ));
                }
            };
            let current_slot = match process_update
                .get("current_slot")
                .and_then(|v| v.as_u64())
                .map(Slot)
            {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: missing current_slot"
                    ));
                }
            };

            let update = match load_ssz_snappy::<ElectraLCUpdate<S, B, X>>(case_dir, &update_file) {
                Ok(u) => u,
                Err(e) => {
                    return CaseResult::Fail(format!(
                        "{case_name}: step {step_idx}: load update: {e}"
                    ));
                }
            };

            if let Err(e) = process_electra_lc_update::<S, B, X>(
                &mut store,
                &update,
                current_slot,
                &genesis_validators_root,
            ) {
                return CaseResult::Fail(format!(
                    "{case_name}: step {step_idx}: process_update: {e}"
                ));
            }

            if let Some(checks) = process_update.get("checks")
                && let Err(e) = check_electra_store::<S, B, X>(
                    &store,
                    checks,
                    case_name,
                    step_idx,
                    deneb_fork_epoch,
                    slots_per_epoch,
                )
            {
                return CaseResult::Fail(e);
            }
        } else if step.get("upgrade_store").is_some() {
            // Electra sync cases that would upgrade to fulu are gloas cases and are
            // filtered at enumeration time. If we reach here, it is an unexpected step.
            return CaseResult::Fail(format!(
                "{case_name}: step {step_idx}: unexpected upgrade_store in electra runner"
            ));
        }
    }

    CaseResult::Pass
}

fn check_electra_store<const S: u64, const B: u64, const X: u64>(
    store: &ElectraLcStore<S, B, X>,
    checks: &serde_yaml_ng::Value,
    case_name: &str,
    step_idx: usize,
    deneb_fork_epoch: u64,
    slots_per_epoch: u64,
) -> Result<(), String>
where
    Bytes32: Default + Clone,
    pharos_types::deneb::ExecutionPayloadHeader<B, X>: TreeHash,
    pharos_types::capella::ExecutionPayloadHeader<B, X>: TreeHash,
    CapellaExecutionPayloadHeader<B, X>: Clone,
{
    // Electra header re-exports deneb's header (same execution payload header type).
    // Use epoch-conditional execution_root per spec's get_lc_execution_root.
    if let Some(fin_check) = checks.get("finalized_header") {
        let expected_slot = fin_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.finalized_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: finalized_header.slot mismatch: got {}, expected {}",
                store.finalized_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = fin_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.finalized_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.beacon_root mismatch"
                ));
            }
        }
        if let Some(expected_root_hex) = fin_check.get("execution_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: execution_root parse: {e}"))?;
            let fin_slot_epoch = store
                .finalized_header
                .beacon
                .slot
                .0
                .checked_div(slots_per_epoch)
                .unwrap_or(0);
            let actual_root = if fin_slot_epoch < deneb_fork_epoch {
                capella_execution_root_from_deneb(&store.finalized_header.execution)
            } else {
                store.finalized_header.execution.tree_hash_root()
            };
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: finalized_header.execution_root mismatch"
                ));
            }
        }
    }
    if let Some(opt_check) = checks.get("optimistic_header") {
        let expected_slot = opt_check.get("slot").and_then(|v| v.as_u64()).map(Slot);
        if let Some(expected_slot) = expected_slot
            && store.optimistic_header.beacon.slot != expected_slot
        {
            return Err(format!(
                "{case_name}: step {step_idx}: optimistic_header.slot mismatch: got {}, expected {}",
                store.optimistic_header.beacon.slot.0, expected_slot.0
            ));
        }
        if let Some(expected_root_hex) = opt_check.get("beacon_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: beacon_root parse: {e}"))?;
            let actual_root = store.optimistic_header.beacon.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.beacon_root mismatch"
                ));
            }
        }
        if let Some(expected_root_hex) = opt_check.get("execution_root").and_then(|v| v.as_str()) {
            let expected_root = parse_root(expected_root_hex)
                .map_err(|e| format!("{case_name}: step {step_idx}: execution_root parse: {e}"))?;
            let opt_slot_epoch = store
                .optimistic_header
                .beacon
                .slot
                .0
                .checked_div(slots_per_epoch)
                .unwrap_or(0);
            let actual_root = if opt_slot_epoch < deneb_fork_epoch {
                capella_execution_root_from_deneb(&store.optimistic_header.execution)
            } else {
                store.optimistic_header.execution.tree_hash_root()
            };
            if actual_root != expected_root {
                return Err(format!(
                    "{case_name}: step {step_idx}: optimistic_header.execution_root mismatch"
                ));
            }
        }
    }
    Ok(())
}

fn apply_electra_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut ElectraLcStore<S, B, X>,
    update: &ElectraLCUpdate<S, B, X>,
) where
    Bytes32: Default + Clone + PartialEq,
{
    let default_branch: Vec<Bytes32> = vec![
        Bytes32::default();
        pharos_types::electra::light_client::NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA
            as usize
    ];
    if update.next_sync_committee_branch.as_slice() != default_branch.as_slice() {
        store.next_sync_committee = update.next_sync_committee.clone();
    }
    store.finalized_header = update.finalized_header.clone();
    if store.optimistic_header.beacon.slot <= store.finalized_header.beacon.slot {
        store.optimistic_header = store.finalized_header.clone();
    }
    store.previous_max_active_participants = store.current_max_active_participants;
    store.current_max_active_participants = 0;
}

fn process_electra_lc_update<const S: u64, const B: u64, const X: u64>(
    store: &mut ElectraLcStore<S, B, X>,
    update: &ElectraLCUpdate<S, B, X>,
    _current_slot: Slot,
    _genesis_validators_root: &Root,
) -> Result<(), String>
where
    Bytes32: Default + Clone + PartialEq,
    pharos_utils::BLSPubkey: Default + Clone + PartialEq,
{
    let n_participants = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .filter(|b| *b)
        .count() as u64;

    let update_is_better = match &store.best_valid_update {
        None => true,
        Some(best) => {
            let new_has_fin = is_electra_finality_update(update);
            let best_has_fin = is_electra_finality_update(best);
            if new_has_fin != best_has_fin {
                new_has_fin
            } else {
                n_participants
                    > best
                        .sync_aggregate
                        .sync_committee_bits
                        .iter()
                        .filter(|b| *b)
                        .count() as u64
            }
        }
    };
    if update_is_better {
        store.best_valid_update = Some(update.clone());
    }

    store.current_max_active_participants =
        store.current_max_active_participants.max(n_participants);

    let safety_threshold = store
        .previous_max_active_participants
        .max(store.current_max_active_participants)
        / 2;

    if n_participants > safety_threshold
        && update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    {
        store.optimistic_header = update.attested_header.clone();
    }

    if n_participants * 3 >= S * 2
        && (update.finalized_header.beacon.slot > store.finalized_header.beacon.slot)
    {
        apply_electra_lc_update::<S, B, X>(store, update);
        store.best_valid_update = None;
    }

    Ok(())
}

fn is_electra_finality_update<const S: u64, const B: u64, const X: u64>(
    update: &ElectraLCUpdate<S, B, X>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    update.finality_branch.as_slice()
        != vec![
            Bytes32::default();
            pharos_types::electra::light_client::FINALITY_BRANCH_DEPTH_ELECTRA as usize
        ]
        .as_slice()
}

// ── Internal result ───────────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
}
