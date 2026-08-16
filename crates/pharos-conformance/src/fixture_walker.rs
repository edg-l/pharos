//! Generic fixture walker used by every conformance category.
//!
//! Provides a consistent way to enumerate `(case_dir, meta)` pairs across
//! categories that may or may not have a `pyspec_tests/` level and may or
//! may not have a `meta.yaml` file.

use std::path::{Path, PathBuf};

use pharos_ssz::Decode;
use pharos_types::EthSpec;

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
    /// `blocks_count: u64` — number of `blocks_<i>.ssz_snappy` files in the case dir.
    ///
    /// Used by sanity/blocks, finality, and random fixtures.
    pub blocks_count: Option<u64>,
    /// `fork_epoch: u64` — the epoch at which the fork transition occurs.
    ///
    /// Used by altair/transition fixtures.
    pub fork_epoch: Option<u64>,
}

impl MetaYaml {
    fn parse(text: &str) -> Result<Self, String> {
        let val: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?;

        let bls_setting = val
            .get("bls_setting")
            .and_then(|v| v.as_u64())
            .map(|n| n as u8);

        let deposits_count = val.get("deposits_count").and_then(|v| v.as_u64());

        let blocks_count = val.get("blocks_count").and_then(|v| v.as_u64());
        let fork_epoch = val.get("fork_epoch").and_then(|v| v.as_u64());

        Ok(MetaYaml {
            bls_setting,
            deposits_count,
            blocks_count,
            fork_epoch,
        })
    }
}

// ── walk_category ─────────────────────────────────────────────────────────────

/// Enumerate `(case_dir, meta)` pairs for a given category.
///
/// Path structure (plain notation; angle brackets denote variable segments):
///
/// `root/preset/fork/category[/sub_category][/inner_dir]/case/`
///
/// For categories with `opts.inner_dir = Some("pyspec_tests")` (default):
///
/// `root/minimal/phase0/genesis/initialization/pyspec_tests/case/`
///
/// For shuffling (S4 exception, `opts.inner_dir = None`, `sub_category = Some("core/shuffle")`):
///
/// `root/minimal/phase0/shuffling/core/shuffle/case/`
pub fn walk_category<'a>(
    root: &'a Path,
    preset: &'a str,
    fork: &'a str,
    category: &'a str,
    sub_category: Option<&'a str>,
    opts: WalkOpts,
) -> impl Iterator<Item = (PathBuf, Option<MetaYaml>)> + 'a {
    let mut base = root.join(preset).join(fork).join(category);

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

/// Load `pre.ssz_snappy` and `post.ssz_snappy` as phase0 `BeaconState`s, then
/// wrap each in the fork-enum `E::BeaconState` via `E::phase0_into_state`.
///
/// Phase0 fixture files contain raw phase0 SSZ without a fork-discriminant
/// prefix. This helper decodes them as `E::Phase0BeaconState` and promotes to
/// the fork-enum so they can be passed to STF functions.
pub fn load_pre_post_phase0_state<E: EthSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::Phase0BeaconState: Decode,
{
    let pre_inner: E::Phase0BeaconState = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = E::phase0_into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: E::Phase0BeaconState = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(E::phase0_into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Decode a single `<name>.ssz_snappy` file as a phase0 `SignedBeaconBlock`,
/// then wrap it in the fork-enum `E::SignedBeaconBlock`.
///
/// Phase0 fixture block files contain raw phase0 SSZ without a fork-discriminant
/// prefix. This helper decodes them as `E::Phase0SignedBeaconBlock` and promotes
/// to the fork-enum so they can be passed to STF functions.
pub fn load_phase0_signed_block<E: EthSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::Phase0SignedBeaconBlock: Decode,
{
    let inner: E::Phase0SignedBeaconBlock = load_ssz_snappy(dir, name)?;
    Ok(E::phase0_into_signed_block(inner))
}

/// Decode a single `<name>.ssz_snappy` file as a phase0 `BeaconState`,
/// then wrap it in the fork-enum `E::BeaconState`.
///
/// For use when a single raw phase0 state file (not a pre/post pair) needs to
/// be decoded and promoted to the fork-enum.
pub fn load_phase0_state<E: EthSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::Phase0BeaconState: Decode,
{
    let inner: E::Phase0BeaconState = load_ssz_snappy(dir, name)?;
    Ok(E::phase0_into_state(inner))
}

/// Load `pre.ssz_snappy` and `post.ssz_snappy` as altair `BeaconState`s, then
/// wrap each in the fork-enum `E::BeaconState` via `E::altair_into_state`.
///
/// Altair fixture files contain raw altair SSZ without a fork-discriminant
/// prefix. This helper decodes them as `E::AltairBeaconState` and promotes to
/// the fork-enum so they can be passed to STF functions.
pub fn load_pre_post_altair_state<E: EthSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::AltairBeaconState: Decode,
{
    let pre_inner: E::AltairBeaconState = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = E::altair_into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: E::AltairBeaconState = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(E::altair_into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Load `pre.ssz_snappy` as an altair `BeaconState`, wrapped in the fork-enum.
pub fn load_altair_state<E: EthSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::AltairBeaconState: Decode,
{
    let inner: E::AltairBeaconState = load_ssz_snappy(dir, name)?;
    Ok(E::altair_into_state(inner))
}

/// Decode a single `<name>.ssz_snappy` file as an altair `SignedBeaconBlock`,
/// then wrap it in the fork-enum `E::SignedBeaconBlock`.
///
/// Altair fixture block files contain raw altair SSZ without a fork-discriminant
/// prefix. This helper decodes them as `E::AltairSignedBeaconBlock` and promotes
/// to the fork-enum so they can be passed to STF functions.
pub fn load_altair_signed_block<E: EthSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::AltairSignedBeaconBlock: Decode,
{
    let inner: E::AltairSignedBeaconBlock = load_ssz_snappy(dir, name)?;
    Ok(E::altair_into_signed_block(inner))
}

/// Load `pre.ssz_snappy` and `post.ssz_snappy` as bellatrix `BeaconState`s, then
/// wrap each in the fork-enum `E::BeaconState` via `E::bellatrix_into_state`.
///
/// Bellatrix fixture files contain raw bellatrix SSZ without a fork-discriminant
/// prefix. This helper decodes them as `E::BellatrixBeaconState` and promotes to
/// the fork-enum so they can be passed to STF functions.
pub fn load_pre_post_bellatrix_state<E: EthSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::BellatrixBeaconState: Decode,
{
    let pre_inner: E::BellatrixBeaconState = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = E::bellatrix_into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: E::BellatrixBeaconState = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(E::bellatrix_into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Load `pre.ssz_snappy` as a bellatrix `BeaconState`, wrapped in the fork-enum.
pub fn load_bellatrix_state<E: EthSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::BellatrixBeaconState: Decode,
{
    let inner: E::BellatrixBeaconState = load_ssz_snappy(dir, name)?;
    Ok(E::bellatrix_into_state(inner))
}

/// Decode a single `<name>.ssz_snappy` file as a bellatrix `SignedBeaconBlock`,
/// then wrap it in the fork-enum `E::SignedBeaconBlock`.
pub fn load_bellatrix_signed_block<E: EthSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::BellatrixSignedBeaconBlock: Decode,
{
    let inner: E::BellatrixSignedBeaconBlock = load_ssz_snappy(dir, name)?;
    Ok(E::bellatrix_into_signed_block(inner))
}

/// Load `pre.ssz_snappy` and optionally `post.ssz_snappy` as capella
/// `BeaconState`s, wrapped in the fork-enum.
pub fn load_pre_post_capella_state<E: EthSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::CapellaBeaconState: Decode,
{
    let pre_inner: E::CapellaBeaconState = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = E::capella_into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: E::CapellaBeaconState = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(E::capella_into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Load `<name>.ssz_snappy` as a capella `BeaconState`, wrapped in the fork-enum.
pub fn load_capella_state<E: EthSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::CapellaBeaconState: Decode,
{
    let inner: E::CapellaBeaconState = load_ssz_snappy(dir, name)?;
    Ok(E::capella_into_state(inner))
}

/// Decode a single `<name>.ssz_snappy` file as a capella `SignedBeaconBlock`,
/// then wrap it in the fork-enum `E::SignedBeaconBlock`.
pub fn load_capella_signed_block<E: EthSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::CapellaSignedBeaconBlock: Decode,
{
    let inner: E::CapellaSignedBeaconBlock = load_ssz_snappy(dir, name)?;
    Ok(E::capella_into_signed_block(inner))
}

/// Load `pre.ssz_snappy` and optionally `post.ssz_snappy` as deneb
/// `BeaconState`s, wrapped in the fork-enum.
pub fn load_pre_post_deneb_state<E: EthSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::DenebBeaconState: Decode,
{
    let pre_inner: E::DenebBeaconState = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = E::deneb_into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: E::DenebBeaconState = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(E::deneb_into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Load `<name>.ssz_snappy` as a deneb `BeaconState`, wrapped in the fork-enum.
pub fn load_deneb_state<E: EthSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::DenebBeaconState: Decode,
{
    let inner: E::DenebBeaconState = load_ssz_snappy(dir, name)?;
    Ok(E::deneb_into_state(inner))
}

/// Decode a single `<name>.ssz_snappy` file as a deneb `SignedBeaconBlock`,
/// then wrap it in the fork-enum `E::SignedBeaconBlock`.
pub fn load_deneb_signed_block<E: EthSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::DenebSignedBeaconBlock: Decode,
{
    let inner: E::DenebSignedBeaconBlock = load_ssz_snappy(dir, name)?;
    Ok(E::deneb_into_signed_block(inner))
}

/// Load `pre.ssz_snappy` and optionally `post.ssz_snappy` as electra
/// `BeaconState`s, wrapped in the fork-enum.
pub fn load_pre_post_electra_state<E: EthSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::ElectraBeaconState: Decode,
{
    let pre_inner: E::ElectraBeaconState = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = E::electra_into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: E::ElectraBeaconState = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(E::electra_into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Load `<name>.ssz_snappy` as an electra `BeaconState`, wrapped in the fork-enum.
pub fn load_electra_state<E: EthSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::ElectraBeaconState: Decode,
{
    let inner: E::ElectraBeaconState = load_ssz_snappy(dir, name)?;
    Ok(E::electra_into_state(inner))
}

/// Decode a single `<name>.ssz_snappy` file as an electra `SignedBeaconBlock`,
/// then wrap it in the fork-enum `E::SignedBeaconBlock`.
pub fn load_electra_signed_block<E: EthSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::ElectraSignedBeaconBlock: Decode,
{
    let inner: E::ElectraSignedBeaconBlock = load_ssz_snappy(dir, name)?;
    Ok(E::electra_into_signed_block(inner))
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
