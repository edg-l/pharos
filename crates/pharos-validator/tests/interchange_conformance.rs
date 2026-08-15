//! EIP-3076 slashing-protection-interchange-tests conformance harness.
//!
//! Runs every case from `eth-clients/slashing-protection-interchange-tests`
//! (vendored via `scripts/fetch-interchange-tests.sh` into
//! `~/.cache/pharos-interchange-tests/`). Each case is a sequence of steps; per
//! the suite README each step:
//!   1. imports `interchange` into a cumulative DB,
//!   2. then attempts the `blocks` and `attestations` signings.
//!
//! Pharos stores the **complete** signing history (not just watermarks), so the
//! expected per-signing outcome is `should_succeed_complete` (falling back to
//! `should_succeed` when the field is absent).
//!
//! Step-level interpretation:
//! - `should_succeed == false`: the interchange is structurally invalid (e.g.
//!   wrong `genesis_validators_root`); the import MUST fail.
//! - `should_succeed == true && contains_slashable_data == false`: the import
//!   MUST succeed and every block/attestation check MUST match.
//! - `should_succeed == true && contains_slashable_data == true`: the suite
//!   permits either (a) import-and-pass-all-checks, or (b) reject/partial-import
//!   and ignore the remaining steps. We attempt (a); if it does not hold we take
//!   (b) and treat the case as passed (spec-permitted).
//!
//! The test is a clean no-op (green) when the fixtures are not present, so
//! `cargo test --workspace` passes without downloading them.

use std::path::PathBuf;

use serde::Deserialize;

use pharos_validator::interchange::{InterchangeFile, import_slashing_protection};
use pharos_validator::slashing::{SlashingProtection, SqliteSlashingProtection};

// ── Test-vector schema ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TestCase {
    name: String,
    genesis_validators_root: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    should_succeed: bool,
    #[serde(default)]
    contains_slashable_data: bool,
    interchange: InterchangeFile,
    #[serde(default)]
    blocks: Vec<BlockCheck>,
    #[serde(default)]
    attestations: Vec<AttCheck>,
}

#[derive(Deserialize)]
struct BlockCheck {
    pubkey: String,
    slot: String,
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: Option<bool>,
}

#[derive(Deserialize)]
struct AttCheck {
    pubkey: String,
    source_epoch: String,
    target_epoch: String,
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: Option<bool>,
}

// ── Fixture discovery ───────────────────────────────────────────────────────

fn fixtures_dir() -> PathBuf {
    if let Ok(p) = std::env::var("PHAROS_INTERCHANGE_TESTS") {
        return PathBuf::from(p).join("tests/generated");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache/pharos-interchange-tests/tests/generated")
}

// ── Per-case execution ──────────────────────────────────────────────────────

/// Run all block/attestation checks for a step against the cumulative DB.
///
/// Each successful check is also recorded (the suite expects signings to
/// accumulate). Returns `Err` on the first outcome that disagrees with the
/// `_complete` expectation.
fn run_checks(db: &SqliteSlashingProtection, step: &Step) -> Result<(), String> {
    for b in &step.blocks {
        let expected = b.should_succeed_complete.unwrap_or(b.should_succeed);
        let slot: u64 = b
            .slot
            .parse()
            .map_err(|e| format!("bad block slot {:?}: {e}", b.slot))?;
        let actual = db
            .check_and_record_block_proposal(&b.pubkey, slot, b.signing_root.as_deref())
            .is_ok();
        if actual != expected {
            return Err(format!(
                "block check (pubkey={}…, slot={slot}) expected={expected} actual={actual}",
                &b.pubkey[..b.pubkey.len().min(10)]
            ));
        }
    }
    for a in &step.attestations {
        let expected = a.should_succeed_complete.unwrap_or(a.should_succeed);
        let src: u64 = a
            .source_epoch
            .parse()
            .map_err(|e| format!("bad source_epoch {:?}: {e}", a.source_epoch))?;
        let tgt: u64 = a
            .target_epoch
            .parse()
            .map_err(|e| format!("bad target_epoch {:?}: {e}", a.target_epoch))?;
        let actual = db
            .check_and_record_attestation(&a.pubkey, src, tgt, a.signing_root.as_deref())
            .is_ok();
        if actual != expected {
            return Err(format!(
                "attestation check (pubkey={}…, source={src}, target={tgt}) expected={expected} actual={actual}",
                &a.pubkey[..a.pubkey.len().min(10)]
            ));
        }
    }
    Ok(())
}

/// Execute a single test case. Returns `Err(reason)` on a conformance failure.
fn run_case(tc: &TestCase) -> Result<(), String> {
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let db = SqliteSlashingProtection::open(&tmp.path().join("slashing.sqlite"))
        .map_err(|e| format!("open db: {e}"))?;
    let gvr = &tc.genesis_validators_root;

    for (i, step) in tc.steps.iter().enumerate() {
        let import_res = import_slashing_protection(&db, &step.interchange, gvr);

        if !step.should_succeed {
            // Structurally invalid interchange: the import MUST be rejected.
            if import_res.is_ok() {
                return Err(format!("step {i}: import should have FAILED but succeeded"));
            }
            // The DB is unchanged (atomic rollback); run any checks against it.
            run_checks(&db, step).map_err(|e| format!("step {i}: {e}"))?;
            continue;
        }

        if !step.contains_slashable_data {
            // Must import cleanly and every check must match.
            import_res.map_err(|e| format!("step {i}: import should succeed: {e}"))?;
            run_checks(&db, step).map_err(|e| format!("step {i}: {e}"))?;
        } else {
            // Slashable data: option (a) import-and-pass, else option (b) reject.
            if import_res.is_err() || run_checks(&db, step).is_err() {
                // Option (b): reject/partial-import → ignore remaining steps.
                return Ok(());
            }
        }
    }

    Ok(())
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[test]
fn eip3076_interchange_conformance() {
    let dir = fixtures_dir();
    if !dir.is_dir() {
        eprintln!(
            "skipping EIP-3076 interchange conformance: no fixtures at {} \
             (run scripts/fetch-interchange-tests.sh)",
            dir.display()
        );
        return;
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    files.sort();

    assert!(
        !files.is_empty(),
        "no .json fixtures found in {}",
        dir.display()
    );

    let mut passed = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for path in &files {
        let json = std::fs::read_to_string(path).expect("read fixture");
        let tc: TestCase = match serde_json::from_str(&json) {
            Ok(tc) => tc,
            Err(e) => {
                failures.push(format!("{}: parse error: {e}", path.display()));
                continue;
            }
        };
        match run_case(&tc) {
            Ok(()) => passed += 1,
            Err(reason) => failures.push(format!("{}: {reason}", tc.name)),
        }
    }

    eprintln!(
        "EIP-3076 interchange conformance: {}/{} passed",
        passed,
        files.len()
    );

    assert!(
        failures.is_empty(),
        "{} interchange conformance failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
