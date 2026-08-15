//! Operations conformance dispatcher.
//!
//! Covers six sub-categories of `phase0/operations` for both presets:
//!   - `attestation`
//!   - `attester_slashing`
//!   - `block_header`
//!   - `deposit`
//!   - `proposer_slashing`
//!   - `voluntary_exit`
//!
//! For each case:
//! - `pre.ssz_snappy` is the input state.
//! - An operation-specific file holds the operation to apply.
//! - `post.ssz_snappy` present → expect `Ok(())` and state matches post.
//! - `post.ssz_snappy` absent → expect `Err(_)`.
//! - `meta.yaml` with `bls_setting: 1` → `verify_signatures = false`.
//!   Absence of `meta.yaml` → `verify_signatures = true` (spec default).

use std::path::Path;

use pharos_ssz::{Decode, Encode};
use pharos_stf::phase0::{
    BeaconStateWrite,
    operations::{
        process_attestation, process_attester_slashing, process_block_header, process_deposit,
        process_proposer_slashing, process_voluntary_exit,
    },
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, AttesterSlashing, Deposit, ProposerSlashing, SignedVoluntaryExit},
    views::{BeaconBlockBodyView, BeaconBlockView},
};

use rayon::prelude::*;

use crate::fixture_walker::{WalkOpts, load_pre_post_phase0_state, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;

/// Result of running all operation tests for a single operation sub-category
/// and preset.
pub struct OpsResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl OpsResult {
    fn new() -> Self {
        OpsResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: OpsResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

/// Run all six operation sub-categories for the mainnet preset.
pub fn run_operations_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_block_header_mainnet(root));
    total.merge(run_proposer_slashing_mainnet(root));
    total.merge(run_attester_slashing_mainnet(root));
    total.merge(run_deposit_mainnet(root));
    total.merge(run_attestation_mainnet(root));
    total.merge(run_voluntary_exit_mainnet(root));
    total
}

/// Run all six operation sub-categories for the minimal preset.
pub fn run_operations_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_block_header_minimal(root));
    total.merge(run_proposer_slashing_minimal(root));
    total.merge(run_attester_slashing_minimal(root));
    total.merge(run_deposit_minimal(root));
    total.merge(run_attestation_minimal(root));
    total.merge(run_voluntary_exit_minimal(root));
    total
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Walk options for operation fixtures: `pyspec_tests/` inner dir, no required meta.yaml
/// (many block_header and proposer_slashing cases have no meta.yaml).
fn ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

/// Resolve `verify_signatures` from an optional `meta.yaml`.
///
/// Per consensus-spec-tests format README:
/// - `bls_setting: 0` or absent — BLS outcome doesn't affect test; run with verification on.
/// - `bls_setting: 1` — "BLS required": test validity depends on BLS being ON. Verify signatures.
/// - `bls_setting: 2` — "BLS ignored": test validity depends on BLS being OFF. Skip BLS.
fn bls_verify(meta: &Option<crate::fixture_walker::MetaYaml>) -> bool {
    match meta {
        Some(m) => m.bls_setting.unwrap_or(0) != 2,
        None => true,
    }
}

#[allow(dead_code)]
enum CaseResult {
    Pass,
    Fail(String),
    Skip,
}

fn tally(result: CaseResult, out: &mut OpsResult) {
    match result {
        CaseResult::Pass => out.pass += 1,
        CaseResult::Fail(msg) => {
            out.fail += 1;
            out.failures.push(msg);
        }
        CaseResult::Skip => out.skip += 1,
    }
}

// ── block_header ──────────────────────────────────────────────────────────────

fn run_block_header_preset<E>(root: &Path, preset: &str) -> OpsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlock: BeaconBlockView + Decode,
    <E::Phase0BeaconBlock as BeaconBlockView>::Body: pharos_ssz::TreeHash,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("block_header"),
        ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "phase0/operations/{preset}/block_header/{}",
                dir_name(&case_dir)
            );
            run_block_header_case::<E>(&case_dir, &case_name, meta)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_block_header_case<E>(
    case_dir: &Path,
    case_name: &str,
    _meta: Option<crate::fixture_walker::MetaYaml>,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlock: BeaconBlockView + Decode,
    <E::Phase0BeaconBlock as BeaconBlockView>::Body: pharos_ssz::TreeHash,
{
    // block_header fixture uses block.ssz_snappy (not block_header.ssz_snappy).
    // Decode as the concrete phase0 block (raw SSZ, no discriminant prefix).
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let block = match load_ssz_snappy::<E::Phase0BeaconBlock>(case_dir, "block.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let result = process_block_header::<E>(&mut pre, &block);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block_header"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_block_header_mainnet(root: &Path) -> OpsResult {
    run_block_header_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_block_header_minimal(root: &Path) -> OpsResult {
    run_block_header_preset::<MinimalEthSpec>(root, "minimal")
}

// ── proposer_slashing ─────────────────────────────────────────────────────────

fn run_proposer_slashing_preset<E>(root: &Path, preset: &str) -> OpsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("proposer_slashing"),
        ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "phase0/operations/{preset}/proposer_slashing/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_proposer_slashing_case::<E>(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_proposer_slashing_case<E>(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let slashing =
        match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let result = process_proposer_slashing::<E>(&mut pre, &slashing, verify_signatures);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after proposer_slashing"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_proposer_slashing_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_proposer_slashing_preset::<MinimalEthSpec>(root, "minimal")
}

// ── attester_slashing ─────────────────────────────────────────────────────────

fn run_attester_slashing_preset<E>(root: &Path, preset: &str) -> OpsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("attester_slashing"),
        ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "phase0/operations/{preset}/attester_slashing/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_attester_slashing_case::<E>(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_attester_slashing_case<E>(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let slashing =
        match load_ssz_snappy::<AttesterSlashing<2048>>(case_dir, "attester_slashing.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let result = process_attester_slashing::<E>(&mut pre, &slashing, verify_signatures);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!(
                    "{case_name}: state mismatch after attester_slashing"
                ))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_attester_slashing_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_attester_slashing_preset::<MinimalEthSpec>(root, "minimal")
}

// ── deposit ───────────────────────────────────────────────────────────────────

fn run_deposit_preset<E>(root: &Path, preset: &str) -> OpsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("deposit"),
        ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("phase0/operations/{preset}/deposit/{}", dir_name(&case_dir));
            let verify_signatures = bls_verify(&meta);
            run_deposit_case::<E>(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_deposit_case<E>(case_dir: &Path, case_name: &str, verify_signatures: bool) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let result = process_deposit::<E>(&mut pre, &deposit, verify_signatures);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after deposit"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_deposit_mainnet(root: &Path) -> OpsResult {
    run_deposit_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_deposit_minimal(root: &Path) -> OpsResult {
    run_deposit_preset::<MinimalEthSpec>(root, "minimal")
}

// ── attestation ───────────────────────────────────────────────────────────────

fn run_attestation_preset<E>(root: &Path, preset: &str) -> OpsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("attestation"),
        ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "phase0/operations/{preset}/attestation/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_attestation_case::<E>(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_attestation_case<E>(case_dir: &Path, case_name: &str, verify_signatures: bool) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let attestation = match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy")
    {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let result = process_attestation::<E>(&mut pre, &attestation, verify_signatures);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after attestation"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_attestation_mainnet(root: &Path) -> OpsResult {
    run_attestation_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_attestation_minimal(root: &Path) -> OpsResult {
    run_attestation_preset::<MinimalEthSpec>(root, "minimal")
}

// ── voluntary_exit ────────────────────────────────────────────────────────────

fn run_voluntary_exit_preset<E>(root: &Path, preset: &str) -> OpsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("voluntary_exit"),
        ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "phase0/operations/{preset}/voluntary_exit/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_voluntary_exit_case::<E>(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_voluntary_exit_case<E>(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let (mut pre, post) = match load_pre_post_phase0_state::<E>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let signed_exit =
        match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let result = process_voluntary_exit::<E>(&mut pre, &signed_exit, verify_signatures);

    match (result, post) {
        (Ok(()), Some(expected)) => {
            if pre.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after voluntary_exit"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_voluntary_exit_preset::<MainnetEthSpec>(root, "mainnet")
}

fn run_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_voluntary_exit_preset::<MinimalEthSpec>(root, "minimal")
}

// ── Altair operations ─────────────────────────────────────────────────────────

/// Run all altair operation sub-categories for the mainnet preset.
pub fn run_operations_altair_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_altair_block_header_mainnet(root));
    total.merge(run_altair_proposer_slashing_mainnet(root));
    total.merge(run_altair_attester_slashing_mainnet(root));
    total.merge(run_altair_deposit_mainnet(root));
    total.merge(run_altair_attestation_mainnet(root));
    total.merge(run_altair_voluntary_exit_mainnet(root));
    total.merge(run_altair_sync_aggregate_mainnet(root));
    total
}

/// Run all altair operation sub-categories for the minimal preset.
pub fn run_operations_altair_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_altair_block_header_minimal(root));
    total.merge(run_altair_proposer_slashing_minimal(root));
    total.merge(run_altair_attester_slashing_minimal(root));
    total.merge(run_altair_deposit_minimal(root));
    total.merge(run_altair_attestation_minimal(root));
    total.merge(run_altair_voluntary_exit_minimal(root));
    total.merge(run_altair_sync_aggregate_minimal(root));
    total
}

// ── Altair helpers ────────────────────────────────────────────────────────────

/// Walk options for altair operation fixtures.
fn altair_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

// ── altair/block_header ───────────────────────────────────────────────────────

fn run_altair_block_header_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "altair",
        "operations",
        Some("block_header"),
        altair_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "altair/operations/mainnet/block_header/{}",
                dir_name(&case_dir)
            );
            run_altair_block_header_case_mainnet(&case_dir, &case_name)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_altair_block_header_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::altair::block::process_block_header_altair;
    use pharos_types::{MainnetEthSpec as E, altair::MainnetBeaconBlock};

    let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::altair_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let block = match load_ssz_snappy::<MainnetBeaconBlock>(case_dir, "block.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut pre = pre_inner;
    let result = process_block_header_altair::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut pre, &block);
    let current = E::altair_into_state(pre);

    match (result, post_inner) {
        (Ok(()), Some(expected)) => {
            if current.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block_header"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

fn run_altair_block_header_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "altair",
        "operations",
        Some("block_header"),
        altair_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "altair/operations/minimal/block_header/{}",
                dir_name(&case_dir)
            );
            run_altair_block_header_case_minimal(&case_dir, &case_name)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_altair_block_header_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::altair::block::process_block_header_altair;
    use pharos_types::{MinimalEthSpec as E, altair::MinimalBeaconBlock};

    let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::altair_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let block = match load_ssz_snappy::<MinimalBeaconBlock>(case_dir, "block.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut pre = pre_inner;
    let result = process_block_header_altair::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        32,
        E,
    >(&mut pre, &block);
    let current = E::altair_into_state(pre);

    match (result, post_inner) {
        (Ok(()), Some(expected)) => {
            if current.as_ssz_bytes() == expected.as_ssz_bytes() {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after block_header"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── altair/proposer_slashing ──────────────────────────────────────────────────

fn run_altair_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "mainnet",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_proposer_slashing;
            use pharos_types::{MainnetEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };

            let mut pre = pre_inner;
            let result = process_proposer_slashing::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut pre, &slashing, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

fn run_altair_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "minimal",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_proposer_slashing;
            use pharos_types::{MinimalEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };

            let mut pre = pre_inner;
            let result = process_proposer_slashing::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

// ── altair/attester_slashing ──────────────────────────────────────────────────

fn run_altair_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "mainnet",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attester_slashing;
            use pharos_types::{MainnetEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };

            let mut pre = pre_inner;
            let result = process_attester_slashing::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut pre, &slashing, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

fn run_altair_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "minimal",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attester_slashing;
            use pharos_types::{MinimalEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };

            let mut pre = pre_inner;
            let result = process_attester_slashing::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

// ── altair/deposit ────────────────────────────────────────────────────────────

fn run_altair_deposit_mainnet(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "mainnet",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_types::{MainnetEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };

            let mut pre = pre_inner;
            let result = process_deposit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut pre, &deposit, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

fn run_altair_deposit_minimal(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "minimal",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_types::{MinimalEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };

            let mut pre = pre_inner;
            let result = process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut pre,
                &deposit,
                verify_signatures,
            );
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

// ── altair/attestation ────────────────────────────────────────────────────────

fn run_altair_attestation_mainnet(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "mainnet",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_types::{MainnetEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };

            let mut pre = pre_inner;
            let result = process_attestation::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut pre, &attestation, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

fn run_altair_attestation_minimal(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "minimal",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_types::{MinimalEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };

            let mut pre = pre_inner;
            let result =
                process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut pre,
                    &attestation,
                    verify_signatures,
                );
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

// ── altair/voluntary_exit ─────────────────────────────────────────────────────

fn run_altair_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "mainnet",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_types::{MainnetEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };

            let mut pre = pre_inner;
            let result = process_voluntary_exit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut pre, &exit, verify_signatures);
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

fn run_altair_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_altair_op_preset(
        root,
        "minimal",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_types::{MinimalEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::altair_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };

            let mut pre = pre_inner;
            let result =
                process_voluntary_exit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut pre,
                    &exit,
                    verify_signatures,
                );
            let current = E::altair_into_state(pre);
            cmp_altair_result(
                result,
                current.as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

// ── altair/sync_aggregate ─────────────────────────────────────────────────────

fn run_altair_sync_aggregate_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "altair",
        "operations",
        Some("sync_aggregate"),
        altair_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "altair/operations/mainnet/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_altair_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_altair_sync_aggregate_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_types::{MainnetEthSpec as E, altair::MainnetSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::altair::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::altair_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MainnetSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let mut pre = pre_inner;
    let result = process_sync_aggregate::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut pre, &sync_aggregate, verify_signatures);
    let current = E::altair_into_state(pre);
    cmp_altair_result(
        result,
        current.as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

fn run_altair_sync_aggregate_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "altair",
        "operations",
        Some("sync_aggregate"),
        altair_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "altair/operations/minimal/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_altair_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_altair_sync_aggregate_case_minimal(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_types::{MinimalEthSpec as E, altair::MinimalSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::altair::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::altair_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MinimalSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };

    let mut pre = pre_inner;
    let result = process_sync_aggregate::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut pre,
        &sync_aggregate,
        verify_signatures,
    );
    let current = E::altair_into_state(pre);
    cmp_altair_result(
        result,
        current.as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

// ── Bellatrix operations ──────────────────────────────────────────────────────

/// Run all bellatrix operation sub-categories for the mainnet preset.
pub fn run_operations_bellatrix_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_bellatrix_block_header_mainnet(root));
    total.merge(run_bellatrix_proposer_slashing_mainnet(root));
    total.merge(run_bellatrix_attester_slashing_mainnet(root));
    total.merge(run_bellatrix_deposit_mainnet(root));
    total.merge(run_bellatrix_attestation_mainnet(root));
    total.merge(run_bellatrix_voluntary_exit_mainnet(root));
    total.merge(run_bellatrix_sync_aggregate_mainnet(root));
    total.merge(run_bellatrix_execution_payload_mainnet(root));
    total
}

/// Run all bellatrix operation sub-categories for the minimal preset.
pub fn run_operations_bellatrix_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_bellatrix_block_header_minimal(root));
    total.merge(run_bellatrix_proposer_slashing_minimal(root));
    total.merge(run_bellatrix_attester_slashing_minimal(root));
    total.merge(run_bellatrix_deposit_minimal(root));
    total.merge(run_bellatrix_attestation_minimal(root));
    total.merge(run_bellatrix_voluntary_exit_minimal(root));
    total.merge(run_bellatrix_sync_aggregate_minimal(root));
    total.merge(run_bellatrix_execution_payload_minimal(root));
    total
}

// ── Bellatrix helpers ─────────────────────────────────────────────────────────

fn bellatrix_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

fn run_bellatrix_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    run_case: impl Fn(&Path, &str, bool) -> CaseResult + Sync + Send,
) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "bellatrix",
        "operations",
        Some(sub),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/operations/{preset}/{sub}/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_case(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

// ── bellatrix/block_header ────────────────────────────────────────────────────

fn run_bellatrix_block_header_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(root, "mainnet", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::bellatrix::helpers::{
            bellatrix_state_to_altair, update_bellatrix_from_altair,
        };
        use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::bellatrix_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MainnetBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = bellatrix_state_to_altair(&pre);
        let altair_block = pharos_stf::bellatrix::bellatrix_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            8192,
            16_777_216,
            2048,
            1_099_511_627_776,
            65536,
            8192,
            4,
            512,
            E,
        >(&mut altair_state, &altair_block);
        // Patch body_root to the Bellatrix block body hash (includes execution_payload),
        // matching what `process_block` does per spec line 214 in bellatrix/block.rs.
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_bellatrix_from_altair(&mut pre, altair_state);
        cmp_bellatrix_result(
            result,
            E::bellatrix_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

fn run_bellatrix_block_header_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(root, "minimal", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::bellatrix::helpers::{
            bellatrix_state_to_altair, update_bellatrix_from_altair,
        };
        use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::bellatrix_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MinimalBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = bellatrix_state_to_altair(&pre);
        let altair_block = pharos_stf::bellatrix::bellatrix_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            64,
            16_777_216,
            32,
            1_099_511_627_776,
            64,
            64,
            4,
            32,
            E,
        >(&mut altair_state, &altair_block);
        // Patch body_root to the Bellatrix block body hash (includes execution_payload).
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_bellatrix_from_altair(&mut pre, altair_state);
        cmp_bellatrix_result(
            result,
            E::bellatrix_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

// ── bellatrix/proposer_slashing ───────────────────────────────────────────────

fn run_bellatrix_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_proposer_slashing_bellatrix;
            use pharos_types::{MainnetEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_bellatrix::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

fn run_bellatrix_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_proposer_slashing_bellatrix;
            use pharos_types::{MinimalEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_bellatrix::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

// ── bellatrix/attester_slashing ───────────────────────────────────────────────

fn run_bellatrix_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_attester_slashing_bellatrix;
            use pharos_types::{MainnetEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_bellatrix::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

fn run_bellatrix_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::bellatrix::operations::process_attester_slashing_bellatrix;
            use pharos_types::{MinimalEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_bellatrix::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

// ── bellatrix/deposit ─────────────────────────────────────────────────────────

fn run_bellatrix_deposit_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_deposit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &deposit, verify_signatures);
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

fn run_bellatrix_deposit_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut altair_state,
                &deposit,
                verify_signatures,
            );
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

// ── bellatrix/attestation ─────────────────────────────────────────────────────

fn run_bellatrix_attestation_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_attestation::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &attestation, verify_signatures);
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

fn run_bellatrix_attestation_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result =
                process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &attestation,
                    verify_signatures,
                );
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

// ── bellatrix/voluntary_exit ──────────────────────────────────────────────────

fn run_bellatrix_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "mainnet",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result = process_voluntary_exit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &exit, verify_signatures);
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

fn run_bellatrix_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_bellatrix_op_preset(
        root,
        "minimal",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::bellatrix::helpers::{
                bellatrix_state_to_altair, update_bellatrix_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::bellatrix_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = bellatrix_state_to_altair(&pre);
            let result =
                process_voluntary_exit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &exit,
                    verify_signatures,
                );
            update_bellatrix_from_altair(&mut pre, altair_state);
            cmp_bellatrix_result(
                result,
                E::bellatrix_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

// ── bellatrix/sync_aggregate ──────────────────────────────────────────────────

fn run_bellatrix_sync_aggregate_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "bellatrix",
        "operations",
        Some("sync_aggregate"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/operations/mainnet/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_bellatrix_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_sync_aggregate_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
    use pharos_types::{MainnetEthSpec as E, altair::MainnetSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MainnetSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = bellatrix_state_to_altair(&pre);
    let result = process_sync_aggregate::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut altair_state, &sync_aggregate, verify_signatures);
    update_bellatrix_from_altair(&mut pre, altair_state);
    cmp_bellatrix_result(
        result,
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

fn run_bellatrix_sync_aggregate_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "bellatrix",
        "operations",
        Some("sync_aggregate"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "bellatrix/operations/minimal/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_bellatrix_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_sync_aggregate_case_minimal(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
    use pharos_types::{MinimalEthSpec as E, altair::MinimalSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MinimalSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = bellatrix_state_to_altair(&pre);
    let result = process_sync_aggregate::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut altair_state,
        &sync_aggregate,
        verify_signatures,
    );
    update_bellatrix_from_altair(&mut pre, altair_state);
    cmp_bellatrix_result(
        result,
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

// ── bellatrix/execution_payload ───────────────────────────────────────────────

fn run_bellatrix_execution_payload_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "bellatrix",
        "operations",
        Some("execution_payload"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "bellatrix/operations/mainnet/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_bellatrix_execution_payload_case_mainnet(&case_dir, &case_name)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_execution_payload_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::bellatrix::operations::process_execution_payload;
    use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MainnetBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        256,
        32,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_bellatrix_result(
        result.map(|_| ()),
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

fn run_bellatrix_execution_payload_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "bellatrix",
        "operations",
        Some("execution_payload"),
        bellatrix_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "bellatrix/operations/minimal/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_bellatrix_execution_payload_case_minimal(&case_dir, &case_name)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_bellatrix_execution_payload_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::bellatrix::operations::process_execution_payload;
    use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::bellatrix::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::bellatrix_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MinimalBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        256,
        32,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_bellatrix_result(
        result.map(|_| ()),
        E::bellatrix_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

// ── Bellatrix shared helpers ──────────────────────────────────────────────────

/// Read `execution.yaml` from `case_dir`, returning `execution_valid` field.
///
/// Defaults to `true` when the file is absent or the field cannot be parsed,
/// matching the behaviour expected for spec-test cases without EL interaction.
fn read_execution_valid(case_dir: &Path) -> bool {
    let path = case_dir.join("execution.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return true;
    };
    // Format: `{execution_valid: true}` or `{execution_valid: false}`.
    !text.contains("execution_valid: false")
}

fn cmp_bellatrix_result(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> CaseResult {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── Altair shared helpers ─────────────────────────────────────────────────────

/// Walk altair operation sub-category and run each case with a closure.
fn run_altair_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    run_case: impl Fn(&Path, &str, bool) -> CaseResult + Sync + Send,
) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "altair",
        "operations",
        Some(sub),
        altair_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("altair/operations/{preset}/{sub}/{}", dir_name(&case_dir));
            let verify_signatures = bls_verify(&meta);
            run_case(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

/// Compare altair operation result against expected post-state (bytes-level comparison).
fn cmp_altair_result(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> CaseResult {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── Capella operations ────────────────────────────────────────────────────────

/// Run all capella operation sub-categories for the mainnet preset.
pub fn run_operations_capella_mainnet(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_capella_block_header_mainnet(root));
    total.merge(run_capella_proposer_slashing_mainnet(root));
    total.merge(run_capella_attester_slashing_mainnet(root));
    total.merge(run_capella_deposit_mainnet(root));
    total.merge(run_capella_attestation_mainnet(root));
    total.merge(run_capella_voluntary_exit_mainnet(root));
    total.merge(run_capella_sync_aggregate_mainnet(root));
    total.merge(run_capella_execution_payload_mainnet(root));
    total.merge(run_capella_withdrawals_mainnet(root));
    total.merge(run_capella_bls_to_execution_change_mainnet(root));
    total
}

/// Run all capella operation sub-categories for the minimal preset.
pub fn run_operations_capella_minimal(root: &Path) -> OpsResult {
    let mut total = OpsResult::new();
    total.merge(run_capella_block_header_minimal(root));
    total.merge(run_capella_proposer_slashing_minimal(root));
    total.merge(run_capella_attester_slashing_minimal(root));
    total.merge(run_capella_deposit_minimal(root));
    total.merge(run_capella_attestation_minimal(root));
    total.merge(run_capella_voluntary_exit_minimal(root));
    total.merge(run_capella_sync_aggregate_minimal(root));
    total.merge(run_capella_execution_payload_minimal(root));
    total.merge(run_capella_withdrawals_minimal(root));
    total.merge(run_capella_bls_to_execution_change_minimal(root));
    total
}

fn capella_ops_walk_opts() -> WalkOpts {
    WalkOpts {
        meta_required: false,
        inner_dir: Some("pyspec_tests"),
    }
}

fn run_capella_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    run_case: impl Fn(&Path, &str, bool) -> CaseResult + Sync + Send,
) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "capella",
        "operations",
        Some(sub),
        capella_ops_walk_opts(),
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("capella/operations/{preset}/{sub}/{}", dir_name(&case_dir));
            let verify_signatures = bls_verify(&meta);
            run_case(&case_dir, &case_name, verify_signatures)
        })
        .collect();

    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn cmp_capella_result(
    result: Result<(), pharos_stf::StateTransitionError>,
    current_bytes: Vec<u8>,
    post_bytes: Option<Vec<u8>>,
    case_name: &str,
    op: &str,
) -> CaseResult {
    match (result, post_bytes) {
        (Ok(()), Some(expected)) => {
            if current_bytes == expected {
                CaseResult::Pass
            } else {
                CaseResult::Fail(format!("{case_name}: state mismatch after {op}"))
            }
        }
        (Ok(()), None) => CaseResult::Fail(format!("{case_name}: expected Err but got Ok")),
        (Err(_), None) => CaseResult::Pass,
        (Err(e), Some(_)) => CaseResult::Fail(format!("{case_name}: expected Ok but got Err: {e}")),
    }
}

// ── capella/block_header ──────────────────────────────────────────────────────

fn run_capella_block_header_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(root, "mainnet", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        use pharos_types::{MainnetEthSpec as E, capella::MainnetBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::capella_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MainnetBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = capella_state_to_altair(&pre);
        let altair_block = pharos_stf::capella::capella_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            8192,
            16_777_216,
            2048,
            1_099_511_627_776,
            65536,
            8192,
            4,
            512,
            E,
        >(&mut altair_state, &altair_block);
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_capella_from_altair(&mut pre, altair_state);
        cmp_capella_result(
            result,
            E::capella_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

fn run_capella_block_header_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(root, "minimal", "block_header", |case_dir, case_name, _| {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::altair::block::process_block_header_altair;
        use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
        use pharos_types::{MinimalEthSpec as E, capella::MinimalBeaconBlock};

        let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "pre.ssz_snappy",
        ) {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let post_inner = if case_dir.join("post.ssz_snappy").exists() {
            match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "post.ssz_snappy",
            ) {
                Ok(v) => Some(E::capella_into_state(v)),
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            }
        } else {
            None
        };
        let block = match load_ssz_snappy::<MinimalBeaconBlock>(case_dir, "block.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
        let mut pre = pre_inner;
        let mut altair_state = capella_state_to_altair(&pre);
        let altair_block = pharos_stf::capella::capella_block_to_altair_block(&block);
        let result = process_block_header_altair::<
            16,
            2,
            128,
            16,
            16,
            2048,
            33,
            64,
            16_777_216,
            32,
            1_099_511_627_776,
            64,
            64,
            4,
            32,
            E,
        >(&mut altair_state, &altair_block);
        if result.is_ok() {
            altair_state.latest_block_header.body_root = block.body.tree_hash_root();
        }
        update_capella_from_altair(&mut pre, altair_state);
        cmp_capella_result(
            result,
            E::capella_into_state(pre).as_ssz_bytes(),
            post_inner.map(|s| s.as_ssz_bytes()),
            case_name,
            "block_header",
        )
    })
}

// ── capella/proposer_slashing ─────────────────────────────────────────────────

fn run_capella_proposer_slashing_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_proposer_slashing_capella;
            use pharos_types::{MainnetEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_capella::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

fn run_capella_proposer_slashing_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "proposer_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_proposer_slashing_capella;
            use pharos_types::{MinimalEthSpec as E, phase0::ProposerSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing =
                match load_ssz_snappy::<ProposerSlashing>(case_dir, "proposer_slashing.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let result = process_proposer_slashing_capella::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "proposer_slashing",
            )
        },
    )
}

// ── capella/attester_slashing ─────────────────────────────────────────────────

fn run_capella_attester_slashing_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_attester_slashing_capella;
            use pharos_types::{MainnetEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_capella::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

fn run_capella_attester_slashing_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "attester_slashing",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_attester_slashing_capella;
            use pharos_types::{MinimalEthSpec as E, phase0::AttesterSlashing};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let slashing = match load_ssz_snappy::<AttesterSlashing<2048>>(
                case_dir,
                "attester_slashing.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_attester_slashing_capella::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                256,
                32,
                E,
            >(&mut pre, &slashing, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attester_slashing",
            )
        },
    )
}

// ── capella/deposit ───────────────────────────────────────────────────────────

fn run_capella_deposit_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_deposit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &deposit, verify_signatures);
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

fn run_capella_deposit_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "deposit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_deposit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Deposit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let deposit = match load_ssz_snappy::<Deposit<33>>(case_dir, "deposit.ssz_snappy") {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_deposit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                &mut altair_state,
                &deposit,
                verify_signatures,
            );
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "deposit",
            )
        },
    )
}

// ── capella/attestation ───────────────────────────────────────────────────────

fn run_capella_attestation_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_attestation::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &attestation, verify_signatures);
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

fn run_capella_attestation_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "attestation",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_attestation;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::Attestation};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let attestation =
                match load_ssz_snappy::<Attestation<2048>>(case_dir, "attestation.ssz_snappy") {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result =
                process_attestation::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &attestation,
                    verify_signatures,
                );
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "attestation",
            )
        },
    )
}

// ── capella/voluntary_exit ────────────────────────────────────────────────────

fn run_capella_voluntary_exit_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MainnetEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result = process_voluntary_exit::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                E,
            >(&mut altair_state, &exit, verify_signatures);
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

fn run_capella_voluntary_exit_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "voluntary_exit",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::altair::operations::process_voluntary_exit;
            use pharos_stf::capella::helpers::{
                capella_state_to_altair, update_capella_from_altair,
            };
            use pharos_types::{MinimalEthSpec as E, phase0::SignedVoluntaryExit};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let exit =
                match load_ssz_snappy::<SignedVoluntaryExit>(case_dir, "voluntary_exit.ssz_snappy")
                {
                    Ok(v) => v,
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                };
            let mut pre = pre_inner;
            let mut altair_state = capella_state_to_altair(&pre);
            let result =
                process_voluntary_exit::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
                    &mut altair_state,
                    &exit,
                    verify_signatures,
                );
            update_capella_from_altair(&mut pre, altair_state);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "voluntary_exit",
            )
        },
    )
}

// ── capella/sync_aggregate ────────────────────────────────────────────────────

fn run_capella_sync_aggregate_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "operations",
        Some("sync_aggregate"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "capella/operations/mainnet/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_capella_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_sync_aggregate_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_types::{MainnetEthSpec as E, altair::MainnetSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MainnetSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = capella_state_to_altair(&pre);
    let result = process_sync_aggregate::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        E,
    >(&mut altair_state, &sync_aggregate, verify_signatures);
    update_capella_from_altair(&mut pre, altair_state);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

fn run_capella_sync_aggregate_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "operations",
        Some("sync_aggregate"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!(
                "capella/operations/minimal/sync_aggregate/{}",
                dir_name(&case_dir)
            );
            let verify_signatures = bls_verify(&meta);
            run_capella_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_sync_aggregate_case_minimal(
    case_dir: &Path,
    case_name: &str,
    verify_signatures: bool,
) -> CaseResult {
    use pharos_stf::altair::operations::process_sync_aggregate;
    use pharos_stf::capella::helpers::{capella_state_to_altair, update_capella_from_altair};
    use pharos_types::{MinimalEthSpec as E, altair::MinimalSyncAggregate};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let sync_aggregate =
        match load_ssz_snappy::<MinimalSyncAggregate>(case_dir, "sync_aggregate.ssz_snappy") {
            Ok(v) => v,
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        };
    let mut pre = pre_inner;
    let mut altair_state = capella_state_to_altair(&pre);
    let result = process_sync_aggregate::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, E>(
        &mut altair_state,
        &sync_aggregate,
        verify_signatures,
    );
    update_capella_from_altair(&mut pre, altair_state);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "sync_aggregate",
    )
}

// ── capella/execution_payload ─────────────────────────────────────────────────

fn run_capella_execution_payload_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "operations",
        Some("execution_payload"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/mainnet/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_capella_execution_payload_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_execution_payload_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::capella::operations::process_execution_payload;
    use pharos_types::{MainnetEthSpec as E, capella::MainnetBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MainnetBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        256,
        32,
        16, // MAX_WITHDRAWALS_PER_PAYLOAD mainnet
        16, // MAX_BLS_TO_EXECUTION_CHANGES mainnet
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_capella_result(
        result.map(|_| ()),
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

fn run_capella_execution_payload_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "operations",
        Some("execution_payload"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/minimal/execution_payload/{}",
                dir_name(&case_dir)
            );
            run_capella_execution_payload_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_execution_payload_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::FixedExecutionEngine;
    use pharos_stf::capella::operations::process_execution_payload;
    use pharos_types::{MinimalEthSpec as E, capella::MinimalBeaconBlockBody};

    let execution_valid = read_execution_valid(case_dir);
    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let body = match load_ssz_snappy::<MinimalBeaconBlockBody>(case_dir, "body.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let engine = FixedExecutionEngine(execution_valid);
    let mut pre = pre_inner;
    let result = process_execution_payload::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        256,
        32,
        4,  // MAX_WITHDRAWALS_PER_PAYLOAD minimal
        16, // MAX_BLS_TO_EXECUTION_CHANGES minimal
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        E,
        FixedExecutionEngine,
    >(&mut pre, &body, &engine, &E::default_runtime_config());
    cmp_capella_result(
        result.map(|_| ()),
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "execution_payload",
    )
}

// ── capella/withdrawals ───────────────────────────────────────────────────────

fn run_capella_withdrawals_mainnet(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "capella",
        "operations",
        Some("withdrawals"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/mainnet/withdrawals/{}",
                dir_name(&case_dir)
            );
            run_capella_withdrawals_case_mainnet(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_withdrawals_case_mainnet(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::operations::process_withdrawals;
    use pharos_types::{MainnetEthSpec as E, capella::MainnetExecutionPayload};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let payload = match load_ssz_snappy::<MainnetExecutionPayload>(
        case_dir,
        "execution_payload.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre = pre_inner;
    let result = process_withdrawals::<
        8192,
        16_777_216,
        2048,
        1_099_511_627_776,
        65536,
        8192,
        4,
        512,
        256,
        32,
        1_073_741_824,
        1_048_576,
        16, // MAX_WITHDRAWALS_PER_PAYLOAD mainnet
        E,
    >(&mut pre, &payload);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "withdrawals",
    )
}

fn run_capella_withdrawals_minimal(root: &Path) -> OpsResult {
    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "capella",
        "operations",
        Some("withdrawals"),
        capella_ops_walk_opts(),
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!(
                "capella/operations/minimal/withdrawals/{}",
                dir_name(&case_dir)
            );
            run_capella_withdrawals_case_minimal(&case_dir, &case_name)
        })
        .collect();
    let mut out = OpsResult::new();
    for result in outcomes {
        tally(result, &mut out);
    }
    out
}

fn run_capella_withdrawals_case_minimal(case_dir: &Path, case_name: &str) -> CaseResult {
    use pharos_stf::capella::operations::process_withdrawals;
    use pharos_types::{MinimalEthSpec as E, capella::MinimalExecutionPayload};

    let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
        case_dir,
        "pre.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let post_inner = if case_dir.join("post.ssz_snappy").exists() {
        match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
            case_dir,
            "post.ssz_snappy",
        ) {
            Ok(v) => Some(E::capella_into_state(v)),
            Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
        }
    } else {
        None
    };
    let payload = match load_ssz_snappy::<MinimalExecutionPayload>(
        case_dir,
        "execution_payload.ssz_snappy",
    ) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let mut pre = pre_inner;
    let result = process_withdrawals::<
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        4,
        32,
        256,
        32,
        1_073_741_824,
        1_048_576,
        4, // MAX_WITHDRAWALS_PER_PAYLOAD minimal
        E,
    >(&mut pre, &payload);
    cmp_capella_result(
        result,
        E::capella_into_state(pre).as_ssz_bytes(),
        post_inner.map(|s| s.as_ssz_bytes()),
        case_name,
        "withdrawals",
    )
}

// ── capella/bls_to_execution_change ──────────────────────────────────────────

fn run_capella_bls_to_execution_change_mainnet(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "mainnet",
        "bls_to_execution_change",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_bls_to_execution_change;
            use pharos_types::{MainnetEthSpec as E, capella::SignedBLSToExecutionChange};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MainnetBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let signed_change = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                case_dir,
                "address_change.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_bls_to_execution_change::<
                8192,
                16_777_216,
                2048,
                1_099_511_627_776,
                65536,
                8192,
                4,
                512,
                256,
                32,
                E,
            >(&mut pre, &signed_change, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "bls_to_execution_change",
            )
        },
    )
}

fn run_capella_bls_to_execution_change_minimal(root: &Path) -> OpsResult {
    run_capella_op_preset(
        root,
        "minimal",
        "bls_to_execution_change",
        |case_dir, case_name, verify_signatures| {
            use pharos_stf::capella::operations::process_bls_to_execution_change;
            use pharos_types::{MinimalEthSpec as E, capella::SignedBLSToExecutionChange};

            let pre_inner = match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                case_dir,
                "pre.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let post_inner = if case_dir.join("post.ssz_snappy").exists() {
                match load_ssz_snappy::<pharos_types::capella::MinimalBeaconState>(
                    case_dir,
                    "post.ssz_snappy",
                ) {
                    Ok(v) => Some(E::capella_into_state(v)),
                    Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
                }
            } else {
                None
            };
            let signed_change = match load_ssz_snappy::<SignedBLSToExecutionChange>(
                case_dir,
                "address_change.ssz_snappy",
            ) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            let mut pre = pre_inner;
            let result = process_bls_to_execution_change::<
                64,
                16_777_216,
                32,
                1_099_511_627_776,
                64,
                64,
                4,
                32,
                256,
                32,
                E,
            >(&mut pre, &signed_change, verify_signatures);
            cmp_capella_result(
                result,
                E::capella_into_state(pre).as_ssz_bytes(),
                post_inner.map(|s| s.as_ssz_bytes()),
                case_name,
                "bls_to_execution_change",
            )
        },
    )
}
