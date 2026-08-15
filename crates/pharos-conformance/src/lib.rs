//! Spec-test conformance harness for Pharos.
//!
//! Walks consensus-spec-tests fixtures and tallies pass/fail per
//! (fork, category). Produces `docs/conformance.md` on every run.
//!
//! # Quick start
//!
//! 1. Download fixtures: `scripts/fetch-spec-tests.sh`
//! 2. Run: `cargo run -p pharos-conformance -- --write`

pub mod bls;
pub mod engine;
pub mod epoch_processing;
pub mod error;
pub mod filter;
pub mod finality;
pub mod fixture_walker;
pub mod fixtures;
pub mod fork_choice;
pub mod genesis;
pub mod light_client;
pub mod operations;
pub mod random;
pub mod report;
pub mod rewards;
pub mod sanity;
pub mod shuffling;
pub mod snappy;
pub mod ssz_generic_types;
pub mod transition;
pub mod yaml_util;

mod fs_util;
mod ssz_generic;
mod ssz_static;

pub use error::ConformanceError;
pub use filter::Filter;
pub use report::{Report, Row, print_report, write_markdown};

use std::path::Path;

/// Run all conformance tests matching `filter` against the fixtures directory.
///
/// If `bail` is true, the process exits with code 1 after the first category
/// that has one or more failures, before running subsequent categories.
///
/// If no fixtures are present, returns a `Report` with only placeholder rows.
pub fn run(filter: &Filter, bail: bool) -> Report {
    let date = current_date();

    let Some(root) = fixtures::fixtures_root() else {
        let mut report = Report {
            fixtures_path: "<not found>".into(),
            date,
            ..Report::default()
        };
        fill_placeholders(&mut report);
        return report;
    };

    let tag = read_tag(&root);
    let fixtures_path = root.display().to_string();
    let mut report = Report {
        fixtures_path,
        tag,
        date,
        ..Report::default()
    };

    // ── ssz_generic ───────────────────────────────────────────────────────────
    if filter.matches("phase0", "ssz_generic", "-") {
        let result = ssz_generic::run_ssz_generic(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "ssz_generic",
            "-",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "ssz_generic", "-"));
    }

    // ── ssz_static mainnet ────────────────────────────────────────────────────
    if filter.matches("phase0", "ssz_static", "mainnet") {
        let mainnet_dir = root.join("mainnet");
        if mainnet_dir.is_dir() {
            let result = ssz_static::run_ssz_static_preset(&mainnet_dir, "mainnet");
            let had_failures = result.fail > 0;
            report.rows.push(Row::live(
                "phase0",
                "ssz_static",
                "mainnet",
                result.pass,
                result.fail,
                result.skip,
            ));
            report.failures.extend(result.failures);
            if bail && had_failures {
                fill_future_placeholders(&mut report);
                return report;
            }
        } else {
            report
                .rows
                .push(Row::placeholder("phase0", "ssz_static", "mainnet"));
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "ssz_static", "mainnet"));
    }

    // ── ssz_static minimal ────────────────────────────────────────────────────
    if filter.matches("phase0", "ssz_static", "minimal") {
        let minimal_dir = root.join("minimal");
        if minimal_dir.is_dir() {
            let result = ssz_static::run_ssz_static_preset(&minimal_dir, "minimal");
            let had_failures = result.fail > 0;
            report.rows.push(Row::live(
                "phase0",
                "ssz_static",
                "minimal",
                result.pass,
                result.fail,
                result.skip,
            ));
            report.failures.extend(result.failures);
            if bail && had_failures {
                fill_future_placeholders(&mut report);
                return report;
            }
        } else {
            report
                .rows
                .push(Row::placeholder("phase0", "ssz_static", "minimal"));
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "ssz_static", "minimal"));
    }

    // ── general/bls ───────────────────────────────────────────────────────────
    if filter.matches("general", "bls", "-") {
        let result = bls::run_bls(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "general",
            "bls",
            "-",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report.rows.push(Row::placeholder("general", "bls", "-"));
    }

    // ── phase0/shuffling/mainnet ──────────────────────────────────────────────
    if filter.matches("phase0", "shuffling", "mainnet") {
        let result = shuffling::run_shuffling_preset(&root, "mainnet", 90);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "shuffling",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "shuffling", "mainnet"));
    }

    // ── phase0/shuffling/minimal ──────────────────────────────────────────────
    if filter.matches("phase0", "shuffling", "minimal") {
        let result = shuffling::run_shuffling_preset(&root, "minimal", 10);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "shuffling",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "shuffling", "minimal"));
    }

    // ── phase0/genesis/minimal ────────────────────────────────────────────────
    if filter.matches("phase0", "genesis", "minimal") {
        let result = genesis::run_genesis_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "genesis",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "genesis", "minimal"));
    }

    // ── phase0/operations/mainnet ─────────────────────────────────────────────
    if filter.matches("phase0", "operations", "mainnet") {
        let result = operations::run_operations_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "operations",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "operations", "mainnet"));
    }

    // ── phase0/operations/minimal ─────────────────────────────────────────────
    if filter.matches("phase0", "operations", "minimal") {
        let result = operations::run_operations_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "operations",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "operations", "minimal"));
    }

    // ── phase0/epoch_processing/mainnet ──────────────────────────────────────
    if filter.matches("phase0", "epoch_processing", "mainnet") {
        let result = epoch_processing::run_epoch_processing_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "epoch_processing",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "epoch_processing", "mainnet"));
    }

    // ── phase0/epoch_processing/minimal ──────────────────────────────────────
    if filter.matches("phase0", "epoch_processing", "minimal") {
        let result = epoch_processing::run_epoch_processing_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "epoch_processing",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "epoch_processing", "minimal"));
    }

    // ── phase0/sanity/mainnet ─────────────────────────────────────────────────
    if filter.matches("phase0", "sanity", "mainnet") {
        let result = sanity::run_sanity_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "sanity",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "sanity", "mainnet"));
    }

    // ── phase0/sanity/minimal ─────────────────────────────────────────────────
    if filter.matches("phase0", "sanity", "minimal") {
        let result = sanity::run_sanity_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "sanity",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "sanity", "minimal"));
    }

    // ── phase0/finality/mainnet ───────────────────────────────────────────────
    if filter.matches("phase0", "finality", "mainnet") {
        let result = finality::run_finality_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "finality",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "finality", "mainnet"));
    }

    // ── phase0/finality/minimal ───────────────────────────────────────────────
    if filter.matches("phase0", "finality", "minimal") {
        let result = finality::run_finality_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "finality",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "finality", "minimal"));
    }

    // ── phase0/random/mainnet ─────────────────────────────────────────────────
    if filter.matches("phase0", "random", "mainnet") {
        let result = random::run_random_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "random",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "random", "mainnet"));
    }

    // ── phase0/random/minimal ─────────────────────────────────────────────────
    if filter.matches("phase0", "random", "minimal") {
        let result = random::run_random_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "random",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "random", "minimal"));
    }

    // ── phase0/rewards/mainnet ────────────────────────────────────────────────
    if filter.matches("phase0", "rewards", "mainnet") {
        let result = rewards::run_rewards_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "rewards",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "rewards", "mainnet"));
    }

    // ── phase0/rewards/minimal ────────────────────────────────────────────────
    if filter.matches("phase0", "rewards", "minimal") {
        let result = rewards::run_rewards_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "phase0",
            "rewards",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "rewards", "minimal"));
    }

    // ── phase0/fork_choice/{mainnet,minimal} ──────────────────────────────────
    //
    // Per M1 plan Q1: phase-0 fork-choice fixtures do not exist upstream, so
    // these rows are driven against `tests/{preset}/altair/fork_choice/`.
    // The shared Q1 footnote is registered once and attached to both rows.
    let fc_footnote = report.add_footnote(
        "Phase-0 fork-choice fixtures do not exist upstream; runner exercises the M1 store against altair fork-choice fixtures. Resolved by M3b (commit `784d75b`): altair containers landed so anchor states now decode and the rows show real pass counts. The skip-unknown-step-keys policy is retained for bellatrix+ step types. Decision recorded in `docs/decisions.md` (Q1).",
    );

    if filter.matches("phase0", "fork_choice", "mainnet") {
        let result = fork_choice::run_fork_choice_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(
            Row::live(
                "phase0",
                "fork_choice",
                "mainnet",
                result.pass,
                result.fail,
                result.skip,
            )
            .with_footnote(fc_footnote),
        );
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "fork_choice", "mainnet").with_footnote(fc_footnote));
    }

    if filter.matches("phase0", "fork_choice", "minimal") {
        let result = fork_choice::run_fork_choice_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(
            Row::live(
                "phase0",
                "fork_choice",
                "minimal",
                result.pass,
                result.fail,
                result.skip,
            )
            .with_footnote(fc_footnote),
        );
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("phase0", "fork_choice", "minimal").with_footnote(fc_footnote));
    }

    // ── altair/transition ────────────────────────────────────────────────────
    if filter.matches("altair", "transition", "mainnet") {
        let result = transition::run_transition_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "transition",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "transition", "mainnet"));
    }

    if filter.matches("altair", "transition", "minimal") {
        let result = transition::run_transition_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "transition",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "transition", "minimal"));
    }

    // ── altair/ssz_static ────────────────────────────────────────────────────
    if filter.matches("altair", "ssz_static", "mainnet") {
        let mainnet_dir = root.join("mainnet");
        if mainnet_dir.is_dir() {
            let result = ssz_static::run_altair_ssz_static_preset(&mainnet_dir, "mainnet");
            let had_failures = result.fail > 0;
            report.rows.push(Row::live(
                "altair",
                "ssz_static",
                "mainnet",
                result.pass,
                result.fail,
                result.skip,
            ));
            report.failures.extend(result.failures);
            if bail && had_failures {
                fill_future_placeholders(&mut report);
                return report;
            }
        } else {
            report
                .rows
                .push(Row::placeholder("altair", "ssz_static", "mainnet"));
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "ssz_static", "mainnet"));
    }

    if filter.matches("altair", "ssz_static", "minimal") {
        let minimal_dir = root.join("minimal");
        if minimal_dir.is_dir() {
            let result = ssz_static::run_altair_ssz_static_preset(&minimal_dir, "minimal");
            let had_failures = result.fail > 0;
            report.rows.push(Row::live(
                "altair",
                "ssz_static",
                "minimal",
                result.pass,
                result.fail,
                result.skip,
            ));
            report.failures.extend(result.failures);
            if bail && had_failures {
                fill_future_placeholders(&mut report);
                return report;
            }
        } else {
            report
                .rows
                .push(Row::placeholder("altair", "ssz_static", "minimal"));
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "ssz_static", "minimal"));
    }

    // ── altair/operations ────────────────────────────────────────────────────
    if filter.matches("altair", "operations", "mainnet") {
        let result = operations::run_operations_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "operations",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "operations", "mainnet"));
    }

    if filter.matches("altair", "operations", "minimal") {
        let result = operations::run_operations_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "operations",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "operations", "minimal"));
    }

    // ── altair/epoch_processing ───────────────────────────────────────────────
    if filter.matches("altair", "epoch_processing", "mainnet") {
        let result = epoch_processing::run_epoch_processing_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "epoch_processing",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "epoch_processing", "mainnet"));
    }

    if filter.matches("altair", "epoch_processing", "minimal") {
        let result = epoch_processing::run_epoch_processing_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "epoch_processing",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "epoch_processing", "minimal"));
    }

    // ── altair/sanity ─────────────────────────────────────────────────────────
    if filter.matches("altair", "sanity", "mainnet") {
        let result = sanity::run_sanity_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "sanity",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "sanity", "mainnet"));
    }

    if filter.matches("altair", "sanity", "minimal") {
        let result = sanity::run_sanity_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "sanity",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "sanity", "minimal"));
    }

    // ── altair/finality ───────────────────────────────────────────────────────
    if filter.matches("altair", "finality", "mainnet") {
        let result = finality::run_finality_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "finality",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "finality", "mainnet"));
    }

    if filter.matches("altair", "finality", "minimal") {
        let result = finality::run_finality_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "finality",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "finality", "minimal"));
    }

    // ── altair/random ─────────────────────────────────────────────────────────
    if filter.matches("altair", "random", "mainnet") {
        let result = random::run_random_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "random",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "random", "mainnet"));
    }

    if filter.matches("altair", "random", "minimal") {
        let result = random::run_random_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "random",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "random", "minimal"));
    }

    // ── altair/rewards ────────────────────────────────────────────────────────
    if filter.matches("altair", "rewards", "mainnet") {
        let result = rewards::run_rewards_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "rewards",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "rewards", "mainnet"));
    }

    if filter.matches("altair", "rewards", "minimal") {
        let result = rewards::run_rewards_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "rewards",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "rewards", "minimal"));
    }

    // ── altair/light_client ───────────────────────────────────────────────────
    if filter.matches("altair", "light_client", "mainnet") {
        let result = light_client::run_light_client_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "light_client",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "light_client", "mainnet"));
    }

    if filter.matches("altair", "light_client", "minimal") {
        let result = light_client::run_light_client_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "light_client",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "light_client", "minimal"));
    }

    // ── altair/genesis ────────────────────────────────────────────────────────
    if filter.matches("altair", "genesis", "mainnet") {
        let result = genesis::run_genesis_altair_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "genesis",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "genesis", "mainnet"));
    }

    if filter.matches("altair", "genesis", "minimal") {
        let result = genesis::run_genesis_altair_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "altair",
            "genesis",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("altair", "genesis", "minimal"));
    }

    // ── bellatrix/transition ──────────────────────────────────────────────────
    if filter.matches("bellatrix", "transition", "mainnet") {
        let result = transition::run_transition_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "transition",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "transition", "mainnet"));
    }

    if filter.matches("bellatrix", "transition", "minimal") {
        let result = transition::run_transition_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "transition",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "transition", "minimal"));
    }

    // ── bellatrix/ssz_static ──────────────────────────────────────────────────
    if filter.matches("bellatrix", "ssz_static", "mainnet") {
        let result = ssz_static::run_ssz_static_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "ssz_static",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "ssz_static", "mainnet"));
    }

    if filter.matches("bellatrix", "ssz_static", "minimal") {
        let result = ssz_static::run_ssz_static_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "ssz_static",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "ssz_static", "minimal"));
    }

    // ── bellatrix/operations ──────────────────────────────────────────────────
    if filter.matches("bellatrix", "operations", "mainnet") {
        let result = operations::run_operations_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "operations",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "operations", "mainnet"));
    }

    if filter.matches("bellatrix", "operations", "minimal") {
        let result = operations::run_operations_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "operations",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "operations", "minimal"));
    }

    // ── bellatrix/epoch_processing ────────────────────────────────────────────
    if filter.matches("bellatrix", "epoch_processing", "mainnet") {
        let result = epoch_processing::run_epoch_processing_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "epoch_processing",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "epoch_processing", "mainnet"));
    }

    if filter.matches("bellatrix", "epoch_processing", "minimal") {
        let result = epoch_processing::run_epoch_processing_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "epoch_processing",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "epoch_processing", "minimal"));
    }

    // ── bellatrix/sanity ──────────────────────────────────────────────────────
    if filter.matches("bellatrix", "sanity", "mainnet") {
        let result = sanity::run_sanity_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "sanity",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "sanity", "mainnet"));
    }

    if filter.matches("bellatrix", "sanity", "minimal") {
        let result = sanity::run_sanity_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "sanity",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "sanity", "minimal"));
    }

    // ── bellatrix/finality ────────────────────────────────────────────────────
    if filter.matches("bellatrix", "finality", "mainnet") {
        let result = finality::run_finality_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "finality",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "finality", "mainnet"));
    }

    if filter.matches("bellatrix", "finality", "minimal") {
        let result = finality::run_finality_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "finality",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "finality", "minimal"));
    }

    // ── bellatrix/random ──────────────────────────────────────────────────────
    if filter.matches("bellatrix", "random", "mainnet") {
        let result = random::run_random_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "random",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "random", "mainnet"));
    }

    if filter.matches("bellatrix", "random", "minimal") {
        let result = random::run_random_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "random",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "random", "minimal"));
    }

    // ── bellatrix/rewards ─────────────────────────────────────────────────────
    if filter.matches("bellatrix", "rewards", "mainnet") {
        let result = rewards::run_rewards_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "rewards",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "rewards", "mainnet"));
    }

    if filter.matches("bellatrix", "rewards", "minimal") {
        let result = rewards::run_rewards_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "rewards",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "rewards", "minimal"));
    }

    // ── bellatrix/fork_choice ─────────────────────────────────────────────────
    if filter.matches("bellatrix", "fork_choice", "mainnet") {
        let result = fork_choice::run_fork_choice_bellatrix_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "fork_choice",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "fork_choice", "mainnet"));
    }

    if filter.matches("bellatrix", "fork_choice", "minimal") {
        let result = fork_choice::run_fork_choice_bellatrix_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "bellatrix",
            "fork_choice",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("bellatrix", "fork_choice", "minimal"));
    }

    // ── capella/transition ────────────────────────────────────────────────────
    if filter.matches("capella", "transition", "mainnet") {
        let result = transition::run_transition_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "transition",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "transition", "mainnet"));
    }

    if filter.matches("capella", "transition", "minimal") {
        let result = transition::run_transition_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "transition",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "transition", "minimal"));
    }

    // ── capella/ssz_static ────────────────────────────────────────────────────
    if filter.matches("capella", "ssz_static", "mainnet") {
        let result = ssz_static::run_ssz_static_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "ssz_static",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "ssz_static", "mainnet"));
    }

    if filter.matches("capella", "ssz_static", "minimal") {
        let result = ssz_static::run_ssz_static_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "ssz_static",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "ssz_static", "minimal"));
    }

    // ── capella/operations ────────────────────────────────────────────────────
    if filter.matches("capella", "operations", "mainnet") {
        let result = operations::run_operations_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "operations",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "operations", "mainnet"));
    }

    if filter.matches("capella", "operations", "minimal") {
        let result = operations::run_operations_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "operations",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "operations", "minimal"));
    }

    // ── capella/epoch_processing ──────────────────────────────────────────────
    if filter.matches("capella", "epoch_processing", "mainnet") {
        let result = epoch_processing::run_epoch_processing_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "epoch_processing",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "epoch_processing", "mainnet"));
    }

    if filter.matches("capella", "epoch_processing", "minimal") {
        let result = epoch_processing::run_epoch_processing_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "epoch_processing",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "epoch_processing", "minimal"));
    }

    // ── capella/sanity ────────────────────────────────────────────────────────
    if filter.matches("capella", "sanity", "mainnet") {
        let result = sanity::run_sanity_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "sanity",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "sanity", "mainnet"));
    }

    if filter.matches("capella", "sanity", "minimal") {
        let result = sanity::run_sanity_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "sanity",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "sanity", "minimal"));
    }

    // ── capella/finality ──────────────────────────────────────────────────────
    if filter.matches("capella", "finality", "mainnet") {
        let result = finality::run_finality_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "finality",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "finality", "mainnet"));
    }

    if filter.matches("capella", "finality", "minimal") {
        let result = finality::run_finality_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "finality",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "finality", "minimal"));
    }

    // ── capella/random ────────────────────────────────────────────────────────
    if filter.matches("capella", "random", "mainnet") {
        let result = random::run_random_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "random",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "random", "mainnet"));
    }

    if filter.matches("capella", "random", "minimal") {
        let result = random::run_random_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "random",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "random", "minimal"));
    }

    // ── capella/rewards ───────────────────────────────────────────────────────
    if filter.matches("capella", "rewards", "mainnet") {
        let result = rewards::run_rewards_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "rewards",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "rewards", "mainnet"));
    }

    if filter.matches("capella", "rewards", "minimal") {
        let result = rewards::run_rewards_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "rewards",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "rewards", "minimal"));
    }

    // ── capella/fork_choice ───────────────────────────────────────────────────
    if filter.matches("capella", "fork_choice", "mainnet") {
        let result = fork_choice::run_fork_choice_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "fork_choice",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "fork_choice", "mainnet"));
    }

    if filter.matches("capella", "fork_choice", "minimal") {
        let result = fork_choice::run_fork_choice_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "fork_choice",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "fork_choice", "minimal"));
    }

    // ── capella/light_client ──────────────────────────────────────────────────
    if filter.matches("capella", "light_client", "mainnet") {
        let result = light_client::run_light_client_capella_mainnet(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "light_client",
            "mainnet",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "light_client", "mainnet"));
    }

    if filter.matches("capella", "light_client", "minimal") {
        let result = light_client::run_light_client_capella_minimal(&root);
        let had_failures = result.fail > 0;
        report.rows.push(Row::live(
            "capella",
            "light_client",
            "minimal",
            result.pass,
            result.fail,
            result.skip,
        ));
        report.failures.extend(result.failures);
        if bail && had_failures {
            fill_future_placeholders(&mut report);
            return report;
        }
    } else {
        report
            .rows
            .push(Row::placeholder("capella", "light_client", "minimal"));
    }

    // ── engine/yaml ───────────────────────────────────────────────────────────
    if filter.matches("engine", "yaml", "-") {
        let specs_dir = dirs_engine_yaml();
        if specs_dir.is_dir() {
            let result = engine::run_engine_yaml_suite(&specs_dir);
            let had_failures = result.fail > 0;
            report.rows.push(Row::live(
                "engine",
                "yaml",
                "-",
                result.pass,
                result.fail,
                result.skip,
            ));
            report.failures.extend(result.failures);
            if bail && had_failures {
                fill_future_placeholders(&mut report);
                return report;
            }
        } else {
            report.rows.push(Row::placeholder("engine", "yaml", "-"));
        }
    } else {
        report.rows.push(Row::placeholder("engine", "yaml", "-"));
    }

    // ── placeholder rows for future categories ────────────────────────────────
    fill_future_placeholders(&mut report);

    report
}

/// Fill all placeholder rows (used when fixtures are absent).
fn fill_placeholders(report: &mut Report) {
    for (fork, cat, preset) in all_categories() {
        report.rows.push(Row::placeholder(fork, cat, preset));
    }
}

/// Fill placeholder rows only for categories not yet added.
fn fill_future_placeholders(report: &mut Report) {
    let implemented: std::collections::HashSet<(&str, &str, &str)> = [
        ("phase0", "ssz_generic", "-"),
        ("phase0", "ssz_static", "mainnet"),
        ("phase0", "ssz_static", "minimal"),
        ("general", "bls", "-"),
        ("phase0", "genesis", "minimal"),
        ("phase0", "shuffling", "mainnet"),
        ("phase0", "shuffling", "minimal"),
        ("phase0", "operations", "mainnet"),
        ("phase0", "operations", "minimal"),
        ("phase0", "epoch_processing", "mainnet"),
        ("phase0", "epoch_processing", "minimal"),
        ("phase0", "sanity", "mainnet"),
        ("phase0", "sanity", "minimal"),
        ("phase0", "finality", "mainnet"),
        ("phase0", "finality", "minimal"),
        ("phase0", "random", "mainnet"),
        ("phase0", "random", "minimal"),
        ("phase0", "rewards", "mainnet"),
        ("phase0", "rewards", "minimal"),
        ("phase0", "fork_choice", "mainnet"),
        ("phase0", "fork_choice", "minimal"),
        // Altair categories
        ("altair", "transition", "mainnet"),
        ("altair", "transition", "minimal"),
        ("altair", "ssz_static", "mainnet"),
        ("altair", "ssz_static", "minimal"),
        ("altair", "operations", "mainnet"),
        ("altair", "operations", "minimal"),
        ("altair", "epoch_processing", "mainnet"),
        ("altair", "epoch_processing", "minimal"),
        ("altair", "sanity", "mainnet"),
        ("altair", "sanity", "minimal"),
        ("altair", "finality", "mainnet"),
        ("altair", "finality", "minimal"),
        ("altair", "random", "mainnet"),
        ("altair", "random", "minimal"),
        ("altair", "rewards", "mainnet"),
        ("altair", "rewards", "minimal"),
        ("altair", "light_client", "mainnet"),
        ("altair", "light_client", "minimal"),
        ("altair", "genesis", "mainnet"),
        ("altair", "genesis", "minimal"),
        // Bellatrix categories
        ("bellatrix", "transition", "mainnet"),
        ("bellatrix", "transition", "minimal"),
        ("bellatrix", "ssz_static", "mainnet"),
        ("bellatrix", "ssz_static", "minimal"),
        ("bellatrix", "operations", "mainnet"),
        ("bellatrix", "operations", "minimal"),
        ("bellatrix", "epoch_processing", "mainnet"),
        ("bellatrix", "epoch_processing", "minimal"),
        ("bellatrix", "sanity", "mainnet"),
        ("bellatrix", "sanity", "minimal"),
        ("bellatrix", "finality", "mainnet"),
        ("bellatrix", "finality", "minimal"),
        ("bellatrix", "random", "mainnet"),
        ("bellatrix", "random", "minimal"),
        ("bellatrix", "rewards", "mainnet"),
        ("bellatrix", "rewards", "minimal"),
        ("bellatrix", "fork_choice", "mainnet"),
        ("bellatrix", "fork_choice", "minimal"),
        // Capella categories
        ("capella", "transition", "mainnet"),
        ("capella", "transition", "minimal"),
        ("capella", "ssz_static", "mainnet"),
        ("capella", "ssz_static", "minimal"),
        ("capella", "operations", "mainnet"),
        ("capella", "operations", "minimal"),
        ("capella", "epoch_processing", "mainnet"),
        ("capella", "epoch_processing", "minimal"),
        ("capella", "sanity", "mainnet"),
        ("capella", "sanity", "minimal"),
        ("capella", "finality", "mainnet"),
        ("capella", "finality", "minimal"),
        ("capella", "random", "mainnet"),
        ("capella", "random", "minimal"),
        ("capella", "rewards", "mainnet"),
        ("capella", "rewards", "minimal"),
        ("capella", "fork_choice", "mainnet"),
        ("capella", "fork_choice", "minimal"),
        // Capella light_client
        ("capella", "light_client", "mainnet"),
        ("capella", "light_client", "minimal"),
        // Engine API YAML conformance
        ("engine", "yaml", "-"),
    ]
    .iter()
    .copied()
    .collect();

    for (fork, cat, preset) in all_categories() {
        if !implemented.contains(&(fork, cat, preset)) {
            report.rows.push(Row::placeholder(fork, cat, preset));
        }
    }
}

/// All (fork, category, preset) rows that appear in the conformance table.
fn all_categories() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("general", "bls", "-"),
        ("phase0", "ssz_generic", "-"),
        ("phase0", "ssz_static", "mainnet"),
        ("phase0", "ssz_static", "minimal"),
        ("phase0", "operations", "mainnet"),
        ("phase0", "operations", "minimal"),
        ("phase0", "epoch_processing", "mainnet"),
        ("phase0", "epoch_processing", "minimal"),
        ("phase0", "sanity", "mainnet"),
        ("phase0", "sanity", "minimal"),
        ("phase0", "finality", "mainnet"),
        ("phase0", "finality", "minimal"),
        ("phase0", "random", "mainnet"),
        ("phase0", "random", "minimal"),
        ("phase0", "rewards", "mainnet"),
        ("phase0", "rewards", "minimal"),
        // fork_choice: per-preset rows pointing at altair fixtures (Q1).
        ("phase0", "fork_choice", "mainnet"),
        ("phase0", "fork_choice", "minimal"),
        // genesis: only minimal fixtures exist upstream (no mainnet genesis fixtures in v1.6.1).
        ("phase0", "genesis", "minimal"),
        // shuffling: per-preset rows (legacy phase0/shuffling/- removed).
        ("phase0", "shuffling", "mainnet"),
        ("phase0", "shuffling", "minimal"),
        // altair categories
        ("altair", "transition", "mainnet"),
        ("altair", "transition", "minimal"),
        ("altair", "ssz_static", "mainnet"),
        ("altair", "ssz_static", "minimal"),
        ("altair", "operations", "mainnet"),
        ("altair", "operations", "minimal"),
        ("altair", "epoch_processing", "mainnet"),
        ("altair", "epoch_processing", "minimal"),
        ("altair", "sanity", "mainnet"),
        ("altair", "sanity", "minimal"),
        ("altair", "finality", "mainnet"),
        ("altair", "finality", "minimal"),
        ("altair", "random", "mainnet"),
        ("altair", "random", "minimal"),
        ("altair", "rewards", "mainnet"),
        ("altair", "rewards", "minimal"),
        ("altair", "light_client", "mainnet"),
        ("altair", "light_client", "minimal"),
        ("altair", "genesis", "mainnet"),
        ("altair", "genesis", "minimal"),
        // bellatrix categories
        ("bellatrix", "transition", "mainnet"),
        ("bellatrix", "transition", "minimal"),
        ("bellatrix", "ssz_static", "mainnet"),
        ("bellatrix", "ssz_static", "minimal"),
        ("bellatrix", "operations", "mainnet"),
        ("bellatrix", "operations", "minimal"),
        ("bellatrix", "epoch_processing", "mainnet"),
        ("bellatrix", "epoch_processing", "minimal"),
        ("bellatrix", "sanity", "mainnet"),
        ("bellatrix", "sanity", "minimal"),
        ("bellatrix", "finality", "mainnet"),
        ("bellatrix", "finality", "minimal"),
        ("bellatrix", "random", "mainnet"),
        ("bellatrix", "random", "minimal"),
        ("bellatrix", "rewards", "mainnet"),
        ("bellatrix", "rewards", "minimal"),
        ("bellatrix", "fork_choice", "mainnet"),
        ("bellatrix", "fork_choice", "minimal"),
        // capella categories
        ("capella", "transition", "mainnet"),
        ("capella", "transition", "minimal"),
        ("capella", "ssz_static", "mainnet"),
        ("capella", "ssz_static", "minimal"),
        ("capella", "operations", "mainnet"),
        ("capella", "operations", "minimal"),
        ("capella", "epoch_processing", "mainnet"),
        ("capella", "epoch_processing", "minimal"),
        ("capella", "sanity", "mainnet"),
        ("capella", "sanity", "minimal"),
        ("capella", "finality", "mainnet"),
        ("capella", "finality", "minimal"),
        ("capella", "random", "mainnet"),
        ("capella", "random", "minimal"),
        ("capella", "rewards", "mainnet"),
        ("capella", "rewards", "minimal"),
        ("capella", "fork_choice", "mainnet"),
        ("capella", "fork_choice", "minimal"),
        // capella light_client
        ("capella", "light_client", "mainnet"),
        ("capella", "light_client", "minimal"),
        // engine API YAML conformance
        ("engine", "yaml", "-"),
        // future forks (placeholders)
        ("deneb", "ssz_static", "-"),
        ("electra", "ssz_static", "-"),
        ("fulu", "ssz_static", "-"),
    ]
}

/// Returns the path to the Engine API YAML methods directory.
///
/// Checks `$EXECUTION_APIS_DIR/src/engine/openrpc/methods/` first,
/// then falls back to `~/dev/execution-apis/src/engine/openrpc/methods/`.
fn dirs_engine_yaml() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("EXECUTION_APIS_DIR") {
        let p = std::path::Path::new(&dir).join("src/engine/openrpc/methods");
        if p.is_dir() {
            return p;
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    std::path::PathBuf::from(home).join("dev/execution-apis/src/engine/openrpc/methods")
}

fn read_tag(root: &Path) -> String {
    // Try reading a `tag` file written by fetch-spec-tests.sh
    let tag_path = root.join("tag");
    std::fs::read_to_string(&tag_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn current_date() -> String {
    // Use env or fallback to a simple implementation.
    // We use std only (no chrono dep).
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Approximate: good enough for a report timestamp.
    let days_since_epoch = secs / 86400;
    // Convert to year/month/day via a simple algorithm.
    let (y, m, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Gregorian calendar computation (adequate for 2024-2100 range).
    let mut remaining = days as i64;
    let mut year = 1970i64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    while month < 12 && remaining >= month_days[month] {
        remaining -= month_days[month];
        month += 1;
    }
    (year as u64, (month + 1) as u64, (remaining + 1) as u64)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
