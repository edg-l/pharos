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
pub mod epoch_processing;
pub mod error;
pub mod filter;
pub mod fixture_walker;
pub mod fixtures;
pub mod genesis;
pub mod operations;
pub mod report;
pub mod shuffling;
pub mod snappy;
pub mod ssz_generic_types;
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
        ("phase0", "sanity", "-"),
        ("phase0", "finality", "-"),
        ("phase0", "random", "-"),
        ("phase0", "rewards", "-"),
        ("phase0", "fork_choice", "-"),
        // genesis: only minimal fixtures exist upstream (no mainnet genesis fixtures in v1.6.1).
        ("phase0", "genesis", "minimal"),
        // shuffling: per-preset rows (legacy phase0/shuffling/- removed).
        ("phase0", "shuffling", "mainnet"),
        ("phase0", "shuffling", "minimal"),
        ("altair", "ssz_static", "-"),
        ("bellatrix", "ssz_static", "-"),
        ("capella", "ssz_static", "-"),
        ("deneb", "ssz_static", "-"),
        ("electra", "ssz_static", "-"),
        ("fulu", "ssz_static", "-"),
    ]
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
