//! Hand-rolled CLI argument parser for `pharos-conformance`.
//!
//! Usage:
//!   pharos-conformance [OPTIONS]
//!
//! Filter grammar (--filter):
//!   PATTERN   := fork [ '/' category [ '/' preset ] ]
//!   PATTERNS  := PATTERN ( ',' PATTERN )*
//!
//! `--filter` is mutually exclusive with `--fork`, `--category`, `--preset`.
//! Mixing them is a parse error (exit 2).

use pharos_conformance::filter::{Filter, FilterPattern, parse_filter_patterns};

/// Parsed command-line arguments.
pub struct Args {
    pub filter: Filter,
    /// If true, write `docs/conformance.md` after running.
    pub write: bool,
    /// If true, stop on first failing test case with non-zero exit.
    pub bail: bool,
}

/// Parse `std::env::args()`, skipping argv[0].
pub fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    parse_args_from(&raw)
}

pub fn parse_args_from(args: &[String]) -> Result<Args, String> {
    let mut filter = Filter::default();
    let mut write = false;
    let mut bail = false;
    let mut filter_patterns: Option<Vec<FilterPattern>> = None;
    let mut has_legacy = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--write" => {
                write = true;
            }
            "--bail" => {
                bail = true;
            }
            "--fork" => {
                has_legacy = true;
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--fork requires a value".to_string())?;
                filter.fork = Some(val.clone());
            }
            "--category" => {
                has_legacy = true;
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--category requires a value".to_string())?;
                filter.category = Some(val.clone());
            }
            "--preset" => {
                has_legacy = true;
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--preset requires a value".to_string())?;
                filter.preset = Some(val.clone());
            }
            "--filter" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "--filter requires a value".to_string())?;
                match parse_filter_patterns(val) {
                    Ok(patterns) => filter_patterns = Some(patterns),
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(2);
                    }
                }
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

    // Mutual exclusion: --filter and --fork/--category/--preset cannot coexist.
    if filter_patterns.is_some() && has_legacy {
        eprintln!("--filter is mutually exclusive with --fork/--category/--preset");
        std::process::exit(2);
    }

    if let Some(patterns) = filter_patterns {
        // --filter path: leave legacy fields None.
        filter.patterns = patterns;
    } else {
        // Legacy path: synthesise one pattern from --fork/--category/--preset.
        if filter.fork.is_some() || filter.category.is_some() || filter.preset.is_some() {
            filter.patterns.push(FilterPattern {
                fork: filter.fork.clone().unwrap_or_default(),
                category: filter.category.clone(),
                preset: filter.preset.clone(),
            });
        }
    }

    Ok(Args {
        filter,
        write,
        bail,
    })
}

fn print_usage() {
    eprintln!(
        "pharos-conformance — Ethereum consensus-spec-tests harness

Usage: pharos-conformance [OPTIONS]

Options:
  --fork <NAME>          Filter by fork name (e.g. phase0, altair, bellatrix)
  --category <NAME>      Filter by test category (e.g. ssz_generic, ssz_static,
                         operations, epoch_processing)
  --preset <NAME>        Filter by preset (mainnet or minimal)
  --filter <PATTERNS>    Comma-separated list of fork[/category[/preset]] patterns.
                         Patterns combine as logical OR. No regex, no globs.
                         Mutually exclusive with --fork/--category/--preset.
                         Example: --filter phase0/ssz_static,altair/fork_choice
  --bail                 Stop on first failing test case and exit non-zero.
  --write                Write pass/fail/skip counts to docs/conformance.md
  --help, -h             Show this help message and exit

Filter grammar:
  PATTERN  = fork [ '/' category [ '/' preset ] ]
  PATTERNS = PATTERN ( ',' PATTERN )*

  A 1-segment pattern matches every category under that fork.
  A 2-segment pattern matches every preset under that fork/category.
  A 3-segment pattern matches exactly one (fork, category, preset) row.
  --filter is mutually exclusive with --fork, --category, and --preset (exit 2).

Exit codes:
  0  All executed tests passed
  1  One or more tests failed or an argument error occurred
  2  Invalid arguments (--filter malformed or mutually-exclusive flags combined)

Environment:
  PHAROS_SPEC_TESTS  Path to the spec-test fixtures root directory.
                     Default: ~/.cache/pharos-spec-tests/
                     Fetch fixtures with: scripts/fetch-spec-tests.sh

Examples:
  pharos-conformance
  pharos-conformance --fork phase0
  pharos-conformance --fork phase0 --category ssz_static --preset mainnet
  pharos-conformance --filter phase0/ssz_static,phase0/ssz_generic
  pharos-conformance --filter phase0 --bail
  pharos-conformance --fork phase0 --write
"
    );
}
