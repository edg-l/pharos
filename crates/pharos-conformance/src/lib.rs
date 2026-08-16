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
pub mod fulu_kzg;
pub mod genesis;
pub mod kzg;
pub mod light_client;
pub mod merkle_proof;
pub mod operations;
pub mod optimistic;
pub mod random;
pub mod report;
pub mod rewards;
pub mod rows;
pub mod sanity;
pub mod shuffling;
pub mod snappy;
pub mod ssz_generic_types;
pub mod task;
pub mod transition;
pub mod yaml_util;

mod fs_util;
mod ssz_generic;
mod ssz_static;

pub use error::ConformanceError;
pub use filter::Filter;
pub use report::{Report, Row, print_report, write_markdown};

use rayon::prelude::*;
use std::path::Path;

/// Run all conformance tests matching `filter` against the fixtures directory.
///
/// Collects every `CaseTask` from all matching rows into a single flat pool
/// and runs it via one top-level parallel iterator. `--bail` runs all tests and
/// exits non-zero if any failed; it no longer stops early.
///
/// If no fixtures are present, returns a `Report` with only placeholder rows.
pub fn run(filter: &Filter, bail: bool) -> Report {
    let date = current_date();
    let table = rows::row_table();

    let Some(root) = fixtures::fixtures_root() else {
        // No fixtures: emit all rows as placeholders.
        let mut report = Report {
            fixtures_path: "<not found>".into(),
            date,
            ..Report::default()
        };
        for spec in table {
            let mut row = Row::placeholder(spec.fork, spec.category, spec.preset);
            if let Some(footnote_text) = spec.footnote {
                let marker = report.add_footnote(footnote_text);
                row = row.with_footnote(marker);
            }
            report.rows.push(row);
        }
        return report;
    };

    let tag = read_tag(&root);
    let fixtures_path = root.display().to_string();

    // ── Phase 1: enumerate all CaseTasks across all matching rows ─────────────
    //
    // For each row in row_table(), check filter + fixtures-dir presence.
    // Rows that match get their enumerate_* called; the returned CaseTasks are
    // all collected into one flat Vec. Rows with no tasks become placeholders.
    let mut all_tasks: Vec<task::CaseTask> = Vec::new();
    // Track which row_ordinals the filter selected AND whose category is
    // implemented (enumerate_row returned Some). A filter-matched row with
    // zero tasks still becomes a live row (0/0/0) to preserve byte-identity
    // with the old sequential runner, which always produced 0/0/0 for a
    // filter-matched category (e.g. bls, altair/genesis). Rows where
    // enumerate_row returns None are unimplemented future placeholders and
    // stay as Row::placeholder regardless of filter matching.
    let mut row_active: Vec<bool> = vec![false; table.len()];

    for (row_ordinal, spec) in table.iter().enumerate() {
        let row_ordinal = row_ordinal as u32;
        if !filter.matches(spec.fork, spec.category, spec.preset) {
            continue;
        }
        if let Some(tasks) = enumerate_row(&root, spec, row_ordinal) {
            row_active[row_ordinal as usize] = true;
            all_tasks.extend(tasks);
        }
    }

    // ── Phase 2: run all tasks in ONE flat rayon pool ─────────────────────────
    let outcomes: Vec<(u32, u32, task::CaseOutcome)> = all_tasks
        .into_par_iter()
        .map(|t| (t.row_ordinal, t.case_ordinal, (t.run)()))
        .collect();

    // ── Phase 3: fold outcomes into per-row counts ────────────────────────────
    let fold_out = task::fold(outcomes, table);

    // Build a lookup: row_ordinal → RowCounts.
    let mut counts_by_row: std::collections::HashMap<u32, &task::RowCounts> =
        std::collections::HashMap::new();
    for rc in &fold_out.rows {
        counts_by_row.insert(rc.row_ordinal, rc);
    }

    // ── Phase 4: assemble the Report ─────────────────────────────────────────
    let mut report = Report {
        fixtures_path,
        tag,
        date,
        ..Report::default()
    };

    // Register all footnotes up front in row_table() order so that markers are
    // assigned before we build rows (add_footnote deduplicates by text).
    for spec in table {
        if let Some(footnote_text) = spec.footnote {
            let _ = report.add_footnote(footnote_text);
        }
    }

    // Build rows in row_table() order.
    for (row_ordinal, spec) in table.iter().enumerate() {
        let row_ordinal = row_ordinal as u32;
        let row = if let Some(rc) = counts_by_row.get(&row_ordinal) {
            // Tasks ran for this row; use folded counts.
            Row::live(
                spec.fork,
                spec.category,
                spec.preset,
                rc.pass,
                rc.fail,
                rc.skip,
            )
        } else if row_active[row_ordinal as usize] {
            // Filter matched and category is implemented, but produced zero
            // tasks (fixtures dir absent or category has zero cases). Show as a
            // live row with 0 counts to preserve byte-identity with the old
            // sequential runner, which always produced 0/0/0 for an implemented
            // but empty category (e.g. bls, altair/genesis with no fixtures).
            Row::live(spec.fork, spec.category, spec.preset, 0, 0, 0)
        } else {
            Row::placeholder(spec.fork, spec.category, spec.preset)
        };

        let row = if let Some(footnote_text) = spec.footnote {
            let marker = report.add_footnote(footnote_text);
            row.with_footnote(marker)
        } else {
            row
        };
        report.rows.push(row);
    }

    // Failures in (row_ordinal, case_ordinal) order (fold already sorted them).
    report.failures.extend(fold_out.failures);

    // bail: run-all, then exit non-zero if any failures (enforced by main.rs
    // checking report.has_failures(); no early cancel here).
    let _ = bail;

    report
}

/// Enumerate the `CaseTask`s for a single row.
///
/// Returns `Some(tasks)` when the category is implemented (even if `tasks` is
/// empty because the fixtures dir is absent). Returns `None` for rows whose
/// category is not yet implemented; those rows remain as placeholders in the
/// report regardless of filter matching.
fn enumerate_row(
    root: &Path,
    spec: &rows::RowSpec,
    row_ordinal: u32,
) -> Option<Vec<task::CaseTask>> {
    let fork = spec.fork;
    let category = spec.category;
    let preset = spec.preset;

    match (fork, category, preset) {
        // ── phase0/ssz_generic (preset-independent) ───────────────────────────
        ("phase0", "ssz_generic", "-") => {
            Some(ssz_generic::enumerate_ssz_generic(root, row_ordinal))
        }

        // ── ssz_static (any fork × mainnet|minimal only) ──────────────────────
        // Every fork's ssz_static is wired per-preset (mainnet|minimal) and runs
        // here, including fulu/ssz_static (M13-Fulu Phase 1).
        (_, "ssz_static", "mainnet" | "minimal") => Some(ssz_static::enumerate_ssz_static(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── general/bls ───────────────────────────────────────────────────────
        ("general", "bls", "-") => Some(bls::enumerate_bls(root, row_ordinal)),

        // ── shuffling ─────────────────────────────────────────────────────────
        ("phase0", "shuffling", preset) => {
            Some(shuffling::enumerate_shuffling(root, preset, row_ordinal))
        }

        // ── genesis ───────────────────────────────────────────────────────────
        (fork, "genesis", preset) => {
            Some(genesis::enumerate_genesis(root, fork, preset, row_ordinal))
        }

        // ── operations ────────────────────────────────────────────────────────
        (fork, "operations", preset) => Some(operations::enumerate_operations(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── epoch_processing ─────────────────────────────────────────────────
        (fork, "epoch_processing", preset) => Some(epoch_processing::enumerate_epoch_processing(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── sanity ────────────────────────────────────────────────────────────
        (fork, "sanity", preset) => Some(sanity::enumerate_sanity(root, fork, preset, row_ordinal)),

        // ── finality ──────────────────────────────────────────────────────────
        (fork, "finality", preset) => Some(finality::enumerate_finality(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── random ────────────────────────────────────────────────────────────
        (fork, "random", preset) => Some(random::enumerate_random(root, fork, preset, row_ordinal)),

        // ── rewards ───────────────────────────────────────────────────────────
        (fork, "rewards", preset) => {
            Some(rewards::enumerate_rewards(root, fork, preset, row_ordinal))
        }

        // ── fork_choice ───────────────────────────────────────────────────────
        (fork, "fork_choice", preset) => Some(fork_choice::enumerate_fork_choice(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── transition ────────────────────────────────────────────────────────
        (fork, "transition", preset) => Some(transition::enumerate_transition(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── electra/fork (upgrade_to_electra fixtures under electra/fork/fork) ──
        ("electra", "fork", preset) => Some(transition::enumerate_fork_upgrade(
            root,
            preset,
            row_ordinal,
        )),

        // ── light_client ──────────────────────────────────────────────────────
        (fork, "light_client", preset) => Some(light_client::enumerate_light_client(
            root,
            fork,
            preset,
            row_ordinal,
        )),

        // ── sync/optimistic ───────────────────────────────────────────────────
        ("sync", "optimistic", preset) => {
            Some(optimistic::enumerate_optimistic(root, preset, row_ordinal))
        }

        // ── engine/yaml ───────────────────────────────────────────────────────
        ("engine", "yaml", "-") => {
            let specs_dir = dirs_engine_yaml();
            if specs_dir.is_dir() {
                Some(engine::enumerate_engine_yaml(&specs_dir, row_ordinal))
            } else {
                Some(Vec::new())
            }
        }

        // ── deneb/kzg ─────────────────────────────────────────────────────────
        ("deneb", "kzg", "-") => Some(kzg::enumerate_kzg(root, row_ordinal)),

        // ── deneb/merkle_proof ────────────────────────────────────────────────
        ("deneb", "merkle_proof", preset) => Some(merkle_proof::enumerate_merkle_proof(
            root,
            "deneb",
            preset,
            row_ordinal,
        )),

        // ── electra/merkle_proof ──────────────────────────────────────────────
        ("electra", "merkle_proof", preset) => Some(merkle_proof::enumerate_merkle_proof(
            root,
            "electra",
            preset,
            row_ordinal,
        )),

        // ── fulu/kzg ──────────────────────────────────────────────────────────
        ("fulu", "kzg", "-") => Some(fulu_kzg::enumerate_fulu_kzg(root, row_ordinal)),

        // ── not yet implemented / future placeholder ──────────────────────────
        // Returning None keeps the row as Row::placeholder in the report.
        _ => None,
    }
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
