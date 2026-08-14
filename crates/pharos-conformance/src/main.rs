//! `pharos-conformance` binary.
//!
//! Walks consensus-spec-tests fixtures and tallies pass/fail per
//! (fork, category). Optionally writes `docs/conformance.md`.
//!
//! Usage: `pharos-conformance [--fork <NAME>] [--category <NAME>] [--preset <NAME>] [--write]`

mod cli;

use std::path::PathBuf;

use pharos_conformance::report::print_report;
use pharos_conformance::{run, write_markdown};

fn main() {
    let args = match cli::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pharos-conformance: error: {e}");
            std::process::exit(1);
        }
    };

    let report = run(&args.filter);
    print_report(&report);

    if args.write {
        let md_path = conformance_md_path();
        match write_markdown(&report, &md_path) {
            Ok(()) => println!("\nWrote {}", md_path.display()),
            Err(e) => {
                eprintln!(
                    "pharos-conformance: failed to write {}: {e}",
                    md_path.display()
                );
                std::process::exit(1);
            }
        }
    }

    if report.has_failures() {
        std::process::exit(1);
    }
}

/// Locate `docs/conformance.md` relative to the workspace root.
///
/// `CARGO_MANIFEST_DIR` points to `crates/pharos-conformance/`; we go up two
/// levels to the workspace root, then into `docs/`.
fn conformance_md_path() -> PathBuf {
    let manifest = std::env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .join("../../docs/conformance.md")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(manifest).join("../../docs/conformance.md"))
}
