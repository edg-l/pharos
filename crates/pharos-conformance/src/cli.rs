//! Hand-rolled CLI argument parser for `pharos-conformance`.
//!
//! Usage: `pharos-conformance [--fork <NAME>] [--category <NAME>] [--preset <NAME>] [--write]`

use pharos_conformance::filter::Filter;

/// Parsed command-line arguments.
pub struct Args {
    pub filter: Filter,
    /// If true, write `docs/conformance.md` after running.
    pub write: bool,
}

/// Parse `std::env::args()`, skipping argv[0].
pub fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    parse_args_from(&raw)
}

pub fn parse_args_from(args: &[String]) -> Result<Args, String> {
    let mut filter = Filter::default();
    let mut write = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--write" => {
                write = true;
            }
            "--fork" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--fork requires a value".to_string())?;
                filter.fork = Some(val.clone());
            }
            "--category" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--category requires a value".to_string())?;
                filter.category = Some(val.clone());
            }
            "--preset" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--preset requires a value".to_string())?;
                filter.preset = Some(val.clone());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(Args { filter, write })
}

fn print_usage() {
    eprintln!(
        "pharos-conformance — Ethereum consensus-spec-tests harness

Usage: pharos-conformance [OPTIONS]

Options:
  --fork <NAME>      Filter by fork name (e.g. phase0, altair, bellatrix)
  --category <NAME>  Filter by test category (e.g. ssz_generic, ssz_static,
                     operations, epoch_processing)
  --preset <NAME>    Filter by preset (mainnet or minimal)
  --write            Write pass/fail/skip counts to docs/conformance.md
  --help, -h         Show this help message and exit

Exit codes:
  0  All executed tests passed
  1  One or more tests failed or an argument error occurred

Environment:
  PHAROS_SPEC_TESTS  Path to the spec-test fixtures root directory.
                     Default: ~/.cache/pharos-spec-tests/
                     Fetch fixtures with: scripts/fetch-spec-tests.sh

Examples:
  pharos-conformance
  pharos-conformance --fork phase0
  pharos-conformance --fork phase0 --category ssz_static --preset mainnet
  pharos-conformance --fork phase0 --write
"
    );
}
