//! Generic fixture walker used by every conformance category.
//!
//! Provides a consistent way to enumerate `(case_dir, meta)` pairs across
//! categories that may or may not have a `pyspec_tests/` level and may or
//! may not have a `meta.yaml` file.

use std::path::{Path, PathBuf};

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_stf::phase0::BeaconStateWrite;
use pharos_stf::{
    AltairProcessSlotsDispatch, AltairUpgradeDispatch, BellatrixProcessSlotsDispatch,
    BellatrixUpgradeDispatch, CapellaProcessSlotsDispatch, CapellaUpgradeDispatch,
    DenebProcessSlotsDispatch, Phase0UpgradeDispatch, state_transition,
};
use pharos_types::BeaconSpec;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::{Attestation, AttesterSlashing, Deposit};
use pharos_types::views::{BeaconBlockBodyView, BeaconBlockView, SignedBeaconBlockView};

use crate::fs_util::read_dir_sorted;
use crate::snappy::decompress_raw;
use crate::task::CaseOutcome;

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

// ── Generic fork-state / fork-block loaders ─────────────────────────────────────
//
// Per-fork fixture files contain raw SSZ for that fork without a fork-discriminant
// prefix. The two generic helpers below decode the inner per-fork type via the
// caller-supplied `into_state` / `into_block` promotion closure (typically one of
// `E::<fork>_into_state` / `E::<fork>_into_signed_block`) and wrap the result in
// the fork-enum so it can be passed to STF functions. Decoding the inner type is
// driven entirely by type inference at the call site, so the `S: Decode` bound is
// what each per-fork wrapper specialises (e.g. `E::AltairBeaconState: Decode`).

/// Load `pre.ssz_snappy` (required) and `post.ssz_snappy` (optional) as the inner
/// per-fork state type `S`, promoting each to the fork-enum via `into_state`.
pub fn load_pre_post_state<E, S, F>(
    dir: &Path,
    into_state: F,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E: BeaconSpec,
    S: Decode,
    F: Fn(S) -> E::BeaconState,
{
    let pre_inner: S = load_ssz_snappy(dir, "pre.ssz_snappy")?;
    let pre = into_state(pre_inner);
    let post = if dir.join("post.ssz_snappy").exists() {
        let post_inner: S = load_ssz_snappy(dir, "post.ssz_snappy")?;
        Some(into_state(post_inner))
    } else {
        None
    };
    Ok((pre, post))
}

/// Decode `<name>.ssz_snappy` as the inner per-fork state type `S`, promoting it
/// to the fork-enum via `into_state`.
pub fn load_state<E, S, F>(dir: &Path, name: &str, into_state: F) -> Result<E::BeaconState, String>
where
    E: BeaconSpec,
    S: Decode,
    F: Fn(S) -> E::BeaconState,
{
    let inner: S = load_ssz_snappy(dir, name)?;
    Ok(into_state(inner))
}

/// Decode `<name>.ssz_snappy` as the inner per-fork block type `S`, promoting it
/// to the fork-enum via `into_block`.
pub fn load_signed_block<E, S, F>(
    dir: &Path,
    name: &str,
    into_block: F,
) -> Result<E::SignedBeaconBlock, String>
where
    E: BeaconSpec,
    S: Decode,
    F: Fn(S) -> E::SignedBeaconBlock,
{
    let inner: S = load_ssz_snappy(dir, name)?;
    Ok(into_block(inner))
}

// ── Per-fork loader wrappers ────────────────────────────────────────────────────
//
// Thin one-line specialisations of the generic loaders above, kept `pub` because
// they are called from every conformance category dispatcher (and the
// `pharos-ssz` bench). Each fixes the inner per-fork type and the promotion fn.

pub fn load_pre_post_phase0_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::Phase0BeaconState: Decode,
{
    load_pre_post_state::<E, E::Phase0BeaconState, _>(dir, E::phase0_into_state)
}

pub fn load_phase0_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::Phase0SignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::Phase0SignedBeaconBlock, _>(dir, name, E::phase0_into_signed_block)
}

pub fn load_phase0_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::Phase0BeaconState: Decode,
{
    load_state::<E, E::Phase0BeaconState, _>(dir, name, E::phase0_into_state)
}

pub fn load_pre_post_altair_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::AltairBeaconState: Decode,
{
    load_pre_post_state::<E, E::AltairBeaconState, _>(dir, E::altair_into_state)
}

pub fn load_altair_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::AltairBeaconState: Decode,
{
    load_state::<E, E::AltairBeaconState, _>(dir, name, E::altair_into_state)
}

pub fn load_altair_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::AltairSignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::AltairSignedBeaconBlock, _>(dir, name, E::altair_into_signed_block)
}

pub fn load_pre_post_bellatrix_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::BellatrixBeaconState: Decode,
{
    load_pre_post_state::<E, E::BellatrixBeaconState, _>(dir, E::bellatrix_into_state)
}

pub fn load_bellatrix_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::BellatrixBeaconState: Decode,
{
    load_state::<E, E::BellatrixBeaconState, _>(dir, name, E::bellatrix_into_state)
}

pub fn load_bellatrix_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::BellatrixSignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::BellatrixSignedBeaconBlock, _>(
        dir,
        name,
        E::bellatrix_into_signed_block,
    )
}

pub fn load_pre_post_capella_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::CapellaBeaconState: Decode,
{
    load_pre_post_state::<E, E::CapellaBeaconState, _>(dir, E::capella_into_state)
}

pub fn load_capella_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::CapellaBeaconState: Decode,
{
    load_state::<E, E::CapellaBeaconState, _>(dir, name, E::capella_into_state)
}

pub fn load_capella_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::CapellaSignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::CapellaSignedBeaconBlock, _>(dir, name, E::capella_into_signed_block)
}

pub fn load_pre_post_deneb_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::DenebBeaconState: Decode,
{
    load_pre_post_state::<E, E::DenebBeaconState, _>(dir, E::deneb_into_state)
}

pub fn load_deneb_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::DenebBeaconState: Decode,
{
    load_state::<E, E::DenebBeaconState, _>(dir, name, E::deneb_into_state)
}

pub fn load_deneb_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::DenebSignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::DenebSignedBeaconBlock, _>(dir, name, E::deneb_into_signed_block)
}

pub fn load_pre_post_electra_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::ElectraBeaconState: Decode,
{
    load_pre_post_state::<E, E::ElectraBeaconState, _>(dir, E::electra_into_state)
}

pub fn load_pre_post_fulu_state<E: BeaconSpec>(
    dir: &Path,
) -> Result<(E::BeaconState, Option<E::BeaconState>), String>
where
    E::FuluBeaconState: Decode,
{
    load_pre_post_state::<E, E::FuluBeaconState, _>(dir, E::fulu_into_state)
}

pub fn load_electra_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::ElectraBeaconState: Decode,
{
    load_state::<E, E::ElectraBeaconState, _>(dir, name, E::electra_into_state)
}

pub fn load_electra_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::ElectraSignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::ElectraSignedBeaconBlock, _>(dir, name, E::electra_into_signed_block)
}

pub fn load_fulu_state<E: BeaconSpec>(dir: &Path, name: &str) -> Result<E::BeaconState, String>
where
    E::FuluBeaconState: Decode,
{
    load_state::<E, E::FuluBeaconState, _>(dir, name, E::fulu_into_state)
}

pub fn load_fulu_signed_block<E: BeaconSpec>(
    dir: &Path,
    name: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::FuluSignedBeaconBlock: Decode,
{
    load_signed_block::<E, E::FuluSignedBeaconBlock, _>(dir, name, E::fulu_into_signed_block)
}

// ── Generic block-sequence case runner ──────────────────────────────────────────

/// Run one block-sequence conformance case (the shared shape of `sanity/blocks`,
/// `random`, and `finality`).
///
/// Loads `(pre, post)` via `load_pre_post`, then applies `blocks_<i>.ssz_snappy`
/// for `i in 0..blocks_count` through `state_transition` (with the supplied
/// `runtime_cfg` and `validate_result`), loading each block via `load_block`.
///
/// Verdict, byte-for-byte identical to the former per-fork copies:
/// - all blocks applied + `post` present → compare final state SSZ to `post`.
/// - all blocks applied + no `post`       → `Fail` (a block was expected to fail).
/// - a block failed + no `post`           → `Pass` (negative test).
/// - a block failed + `post` present      → `Fail` (unexpected block failure).
///
/// `load_pre_post` and `load_block` are passed as `fn`/closure so the caller fixes
/// the per-fork fixture decode; `runtime_cfg` is passed by the caller so each call
/// site preserves the exact config it used previously (see the per-category
/// dispatchers for which forks pass `RuntimeConfig::default()` vs
/// `E::default_runtime_config()`).
#[allow(clippy::type_complexity)]
pub fn run_blocks_case<E, FState, FBlock>(
    case_dir: &Path,
    case_name: &str,
    blocks_count: u64,
    validate_result: bool,
    runtime_cfg: &RuntimeConfig,
    load_pre_post: FState,
    load_block: FBlock,
) -> CaseOutcome
where
    E: BeaconSpec,
    E::BeaconState: BeaconStateWrite + TreeHash,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>
        + Decode,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + TreeHash
        + Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>
        + CapellaUpgradeDispatch<E>
        + Decode,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, pharos_stf::NullExecutionEngine>
        + DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + TreeHash
        + Decode,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_stf::ElectraUpgradeDispatch<E>
        + TreeHash
        + Decode,
    E::FuluBeaconState: pharos_stf::FuluDispatch<E, pharos_stf::NullExecutionEngine>
        + pharos_stf::FuluJaFDispatch<E>
        + pharos_stf::FuluProcessSlotsDispatch<E>
        + TreeHash
        + Decode,
    E::Phase0BeaconState: Decode + Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    FState: Fn(&Path) -> Result<(E::BeaconState, Option<E::BeaconState>), String>,
    FBlock: Fn(&Path, &str) -> Result<E::SignedBeaconBlock, String>,
{
    let (pre, post) = match load_pre_post(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseOutcome::Fail(format!("{case_name}: {e}")),
    };

    let mut current: Option<E::BeaconState> = Some(pre);
    let mut block_error: Option<String> = None;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block = match load_block(case_dir, &block_file) {
            Ok(v) => v,
            Err(e) => return CaseOutcome::Fail(format!("{case_name}: {e}")),
        };
        let state = current.take().unwrap();
        match state_transition::<E, pharos_stf::NullExecutionEngine>(
            state,
            &block,
            &pharos_stf::NullExecutionEngine,
            validate_result,
            runtime_cfg,
        ) {
            Ok((new_state, _)) => current = Some(new_state),
            Err(e) => {
                block_error = Some(format!("{e}"));
                break;
            }
        }
    }

    match (block_error, post) {
        // All blocks applied, post present — compare states.
        (None, Some(expected)) => {
            let state = current.unwrap();
            if state.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseOutcome::Pass
            } else {
                CaseOutcome::Fail(format!("{case_name}: state mismatch after block sequence"))
            }
        }
        // All blocks applied but no post expected — should have failed.
        (None, None) => CaseOutcome::Fail(format!(
            "{case_name}: expected a block to fail but all blocks applied successfully"
        )),
        // A block failed and we expected it (no post) — negative test passed.
        (Some(_), None) => CaseOutcome::Pass,
        // A block failed unexpectedly (post was present).
        (Some(e), Some(_)) => {
            CaseOutcome::Fail(format!("{case_name}: expected Ok but block failed: {e}"))
        }
    }
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
