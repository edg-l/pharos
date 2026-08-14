//! Resolves the spec-test fixtures root directory.
//!
//! Priority:
//! 1. `$PHAROS_SPEC_TESTS` env var (if set and the directory exists)
//! 2. `~/.cache/pharos-spec-tests/` (default download location)
//!
//! Returns `None` if the path is absent or empty; callers should skip cleanly.

use std::path::PathBuf;

/// Returns the fixtures root, or `None` if absent.
///
/// Prints an actionable message when the directory is missing.
pub fn fixtures_root() -> Option<PathBuf> {
    let path = if let Ok(val) = std::env::var("PHAROS_SPEC_TESTS") {
        PathBuf::from(val)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".cache/pharos-spec-tests")
    };

    if path.is_dir() {
        // Verify it is non-empty (has at least one entry)
        if std::fs::read_dir(&path).ok()?.next().is_some() {
            return Some(path);
        }
    }

    eprintln!(
        "pharos-conformance: spec tests not found at {}; run scripts/fetch-spec-tests.sh to download",
        path.display()
    );
    None
}
