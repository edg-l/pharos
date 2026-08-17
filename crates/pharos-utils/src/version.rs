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

/// Two-letter client code per `execution-apis/src/engine/identification.md`.
/// Not (yet) reserved in the upstream `ClientCode` enum, but does not collide
/// with any reserved code. Used for both the Engine API `ClientVersionV1` and
/// the Beacon API `/eth/v1/node/version` v2 response.
pub const CLIENT_CODE: &str = "PH";

/// Human-readable client name, paired with [`CLIENT_CODE`].
pub const CLIENT_NAME: &str = "Pharos";

/// Package version with the conventional `v` prefix (e.g. `"v0.21.0"`), the
/// form used for the `version` field of `ClientVersionV1`.
pub const CLIENT_VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Short git SHA captured at build time. `-dirty` suffix when the working
/// tree had uncommitted changes; `"unknown"` when not built inside a repo.
pub const GIT_SHA: &str = env!("PHAROS_GIT_SHA");

/// First 4 bytes of the HEAD commit hash as an 8-char lowercase hex string,
/// no `0x` prefix and no `-dirty` suffix (e.g. `"fa4ff922"`). `"00000000"`
/// when not built inside a repo.
///
/// This is the value the Engine API `ClientVersionV1.commit` field expects
/// (`execution-apis/src/engine/identification.md`): exactly 4 bytes, so it
/// fits in block `graffiti` alongside the 2-letter client code.
pub const GIT_COMMIT_4BYTE: &str = env!("PHAROS_GIT_COMMIT_4BYTE");

/// `GIT_COMMIT_4BYTE` with a `0x` prefix (e.g. `"0xfa4ff922"`), the exact
/// `DATA` encoding used for `ClientVersionV1.commit` on the wire and in the
/// Beacon API `/eth/v1/node/version` v2 response.
pub const COMMIT_4BYTE_HEX: &str = concat!("0x", env!("PHAROS_GIT_COMMIT_4BYTE"));

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
