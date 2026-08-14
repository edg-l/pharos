//! Filesystem helpers shared by `ssz_generic` and `ssz_static` runners.
//!
//! Both runners walk fixture directories in deterministic sorted order and
//! extract the trailing component as the case/type/suite name.

use std::path::{Path, PathBuf};

/// List immediate subdirectories of `path`, sorted lexicographically.
pub(crate) fn read_dir_sorted(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    Ok(entries)
}

/// Final path component as a `String`, or empty if the path has no name.
pub(crate) fn dir_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}
