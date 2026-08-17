//! Build-time version metadata.
//!
//! All values are baked in by `build.rs`. Source of truth for the package
//! version is the workspace `Cargo.toml`; everything else is derived.
//!
//! Use [`AGENT_STRING`] for any wire-visible identifier (libp2p identify,
//! Beacon API `/eth/v1/node/version`, log lines that tag a release).
//! Use [`LONG_VERSION`] for the human-readable `--version` block.

/// The package version (e.g. `"0.1.0"`).
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git SHA captured at build time. `-dirty` suffix when the working
/// tree had uncommitted changes; `"unknown"` when not built inside a repo.
pub const GIT_SHA: &str = env!("PHAROS_GIT_SHA");

/// Rust target triple (e.g. `"x86_64-unknown-linux-gnu"`).
pub const TARGET: &str = env!("PHAROS_TARGET");

/// Cargo build profile (e.g. `"dev"`, `"release"`).
pub const BUILD_PROFILE: &str = env!("PHAROS_PROFILE");

/// Canonical wire agent string: `Pharos/v<pkg>-<sha>/<target>`.
///
/// Matches the convention other CL clients follow (e.g.
/// `<client>/v4.0.0-abc1234/x86_64-linux`).
pub const AGENT_STRING: &str = env!("PHAROS_AGENT_STRING");

/// Multi-line block used as clap `long_version` (binaries that wire this
/// into `#[command(long_version = ...)]`). Clap already prepends the
/// binary name + package version, so this only carries the extras.
/// Keep parsable: one `key: value` per line.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n",
    "agent:   ",
    env!("PHAROS_AGENT_STRING"),
    "\n",
    "commit:  ",
    env!("PHAROS_GIT_SHA"),
    "\n",
    "target:  ",
    env!("PHAROS_TARGET"),
    "\n",
    "profile: ",
    env!("PHAROS_PROFILE"),
);
