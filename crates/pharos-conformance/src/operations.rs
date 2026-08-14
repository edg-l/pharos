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

use crate::fixture_walker::{WalkOpts, load_pre_post, load_ssz_snappy, walk_category};
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
    E::BeaconBlock: BeaconBlockView + Decode,
    <E::BeaconBlock as BeaconBlockView>::Body: pharos_ssz::TreeHash,
{
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("block_header"),
        ops_walk_opts(),
    ) {
        let case_name = format!(
            "phase0/operations/{preset}/block_header/{}",
            dir_name(&case_dir)
        );
        let result = run_block_header_case::<E>(&case_dir, &case_name, meta);
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
    E::BeaconBlock: BeaconBlockView + Decode,
    <E::BeaconBlock as BeaconBlockView>::Body: pharos_ssz::TreeHash,
{
    // block_header fixture uses block.ssz_snappy (not block_header.ssz_snappy).
    let (mut pre, post) = match load_pre_post::<E::BeaconState>(case_dir) {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let block = match load_ssz_snappy::<E::BeaconBlock>(case_dir, "block.ssz_snappy") {
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
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("proposer_slashing"),
        ops_walk_opts(),
    ) {
        let case_name = format!(
            "phase0/operations/{preset}/proposer_slashing/{}",
            dir_name(&case_dir)
        );
        let verify_signatures = bls_verify(&meta);
        let result = run_proposer_slashing_case::<E>(&case_dir, &case_name, verify_signatures);
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
    let (mut pre, post) = match load_pre_post::<E::BeaconState>(case_dir) {
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
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("attester_slashing"),
        ops_walk_opts(),
    ) {
        let case_name = format!(
            "phase0/operations/{preset}/attester_slashing/{}",
            dir_name(&case_dir)
        );
        let verify_signatures = bls_verify(&meta);
        let result = run_attester_slashing_case::<E>(&case_dir, &case_name, verify_signatures);
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
    let (mut pre, post) = match load_pre_post::<E::BeaconState>(case_dir) {
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
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("deposit"),
        ops_walk_opts(),
    ) {
        let case_name = format!("phase0/operations/{preset}/deposit/{}", dir_name(&case_dir));
        let verify_signatures = bls_verify(&meta);
        let result = run_deposit_case::<E>(&case_dir, &case_name, verify_signatures);
        tally(result, &mut out);
    }
    out
}

fn run_deposit_case<E>(case_dir: &Path, case_name: &str, verify_signatures: bool) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
{
    let (mut pre, post) = match load_pre_post::<E::BeaconState>(case_dir) {
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
    E::BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("attestation"),
        ops_walk_opts(),
    ) {
        let case_name = format!(
            "phase0/operations/{preset}/attestation/{}",
            dir_name(&case_dir)
        );
        let verify_signatures = bls_verify(&meta);
        let result = run_attestation_case::<E>(&case_dir, &case_name, verify_signatures);
        tally(result, &mut out);
    }
    out
}

fn run_attestation_case<E>(case_dir: &Path, case_name: &str, verify_signatures: bool) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let (mut pre, post) = match load_pre_post::<E::BeaconState>(case_dir) {
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
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "phase0",
        "operations",
        Some("voluntary_exit"),
        ops_walk_opts(),
    ) {
        let case_name = format!(
            "phase0/operations/{preset}/voluntary_exit/{}",
            dir_name(&case_dir)
        );
        let verify_signatures = bls_verify(&meta);
        let result = run_voluntary_exit_case::<E>(&case_dir, &case_name, verify_signatures);
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
    let (mut pre, post) = match load_pre_post::<E::BeaconState>(case_dir) {
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
