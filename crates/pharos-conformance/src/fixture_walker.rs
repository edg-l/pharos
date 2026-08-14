//! Generic fixture walker used by every conformance category.
//!
//! Provides a consistent way to enumerate `(case_dir, meta)` pairs across
//! categories that may or may not have a `pyspec_tests/` level and may or
//! may not have a `meta.yaml` file.

use std::path::{Path, PathBuf};

use pharos_ssz::Decode;

use crate::fs_util::read_dir_sorted;
use crate::snappy::decompress_raw;

// ── WalkOpts ──────────────────────────────────────────────────────────────────

/// Options controlling how `walk_category` traverses fixture directories.
pub struct WalkOpts {
    /// Whether a `meta.yaml` file is expected in each case directory.
    ///
    /// When `true` (default), cases without `meta.yaml` are skipped.
    /// When `false` (e.g. shuffling), absence of `meta.yaml` is not an error.
    pub meta_required: bool,

    /// Optional extra directory level between the category dir and the case dirs.
    ///
    /// Most categories: `Some("pyspec_tests")`.
    /// Exception (S4 — shuffling): `None` (case dirs live directly under `shuffle/`).
    pub inner_dir: Option<&'static str>,
}

impl Default for WalkOpts {
    fn default() -> Self {
        WalkOpts {
            meta_required: true,
            inner_dir: Some("pyspec_tests"),
        }
    }
}

// ── MetaYaml ──────────────────────────────────────────────────────────────────

/// Parsed fields from `meta.yaml` that callers actually read.
///
/// Fields are optional at the type level; callers assert the ones they need.
pub struct MetaYaml {
    /// `bls_setting: u8` per `consensus-specs/tests/formats/README.md`:
    /// `0` = default (run with verify ON),
    /// `1` = BLS required (verify ON; case fails if signatures wrong),
    /// `2` = BLS ignored (verify OFF; signatures may be placeholders).
    pub bls_setting: Option<u8>,
    /// `deposits_count: u64` — expected number of deposit files.
    pub deposits_count: Option<u64>,
}

impl MetaYaml {
    fn parse(text: &str) -> Result<Self, String> {
        let val: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?;

        let bls_setting = val
            .get("bls_setting")
            .and_then(|v| v.as_u64())
            .map(|n| n as u8);

        let deposits_count = val.get("deposits_count").and_then(|v| v.as_u64());

        Ok(MetaYaml {
            bls_setting,
            deposits_count,
        })
    }
}

// ── walk_category ─────────────────────────────────────────────────────────────

/// Enumerate `(case_dir, meta)` pairs for a given category.
///
/// Path structure (plain notation; angle brackets denote variable segments):
///
/// `root/tests/preset/fork/category[/sub_category][/inner_dir]/case/`
///
/// For categories with `opts.inner_dir = Some("pyspec_tests")` (default):
///
/// `root/tests/minimal/phase0/genesis/initialization/pyspec_tests/case/`
///
/// For shuffling (S4 exception, `opts.inner_dir = None`, `sub_category = Some("core/shuffle")`):
///
/// `root/tests/minimal/phase0/shuffling/core/shuffle/case/`
pub fn walk_category<'a>(
    root: &'a Path,
    preset: &'a str,
    fork: &'a str,
    category: &'a str,
    sub_category: Option<&'a str>,
    opts: WalkOpts,
) -> impl Iterator<Item = (PathBuf, Option<MetaYaml>)> + 'a {
    let mut base = root.join("tests").join(preset).join(fork).join(category);

    if let Some(sub) = sub_category {
        // sub_category may contain path separators (e.g. "core/shuffle").
        for part in sub.split('/') {
            base = base.join(part);
        }
    }

    if let Some(inner) = opts.inner_dir {
        base = base.join(inner);
    }

    let cases: Vec<PathBuf> = if base.is_dir() {
        read_dir_sorted(&base).unwrap_or_default()
    } else {
        vec![]
    };

    cases.into_iter().filter_map(move |case_dir| {
        if !case_dir.is_dir() {
            return None;
        }

        let meta_path = case_dir.join("meta.yaml");
        let meta = if meta_path.exists() {
            match std::fs::read_to_string(&meta_path) {
                Ok(text) => match MetaYaml::parse(&text) {
                    Ok(m) => Some(m),
                    Err(_) => return None,
                },
                Err(_) => return None,
            }
        } else if opts.meta_required {
            return None;
        } else {
            None
        };

        Some((case_dir, meta))
    })
}

// ── load_pre_post ─────────────────────────────────────────────────────────────

/// Load `pre.ssz_snappy` (required) and `post.ssz_snappy` (optional) from a case dir.
///
/// Returns `Ok((pre, Some(post)))` when both exist, `Ok((pre, None))` when only
/// `pre.ssz_snappy` is present (negative test: expected operation failure).
pub fn load_pre_post<S: Decode>(dir: &Path) -> Result<(S, Option<S>), String> {
    let pre = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let post = if dir.join("post.ssz_snappy").exists() {
        Some(load_ssz_snappy(dir, "post.ssz_snappy")?)
    } else {
        None
    };
    Ok((pre, post))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Decode a single `<name>.ssz_snappy` file inside `dir`.
pub fn load_ssz_snappy<S: Decode>(dir: &Path, name: &str) -> Result<S, String> {
    let path = dir.join(name);
    let compressed = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let raw = decompress_raw(&compressed)
        .map_err(|e| format!("snappy decompress {}: {e}", path.display()))?;
    S::from_ssz_bytes(&raw).map_err(|e| format!("ssz decode {}: {e:?}", path.display()))
}
