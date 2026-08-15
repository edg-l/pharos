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
    let mut out = OpsResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        "mainnet",
        "altair",
        "operations",
        Some("block_header"),
        altair_ops_walk_opts(),
    ) {
        let case_name = format!(
            "altair/operations/mainnet/block_header/{}",
            dir_name(&case_dir)
        );
        let result = run_altair_block_header_case_mainnet(&case_dir, &case_name);
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
    let mut out = OpsResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        "minimal",
        "altair",
        "operations",
        Some("block_header"),
        altair_ops_walk_opts(),
    ) {
        let case_name = format!(
            "altair/operations/minimal/block_header/{}",
            dir_name(&case_dir)
        );
        let result = run_altair_block_header_case_minimal(&case_dir, &case_name);
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
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        "mainnet",
        "altair",
        "operations",
        Some("sync_aggregate"),
        altair_ops_walk_opts(),
    ) {
        let case_name = format!(
            "altair/operations/mainnet/sync_aggregate/{}",
            dir_name(&case_dir)
        );
        let verify_signatures = bls_verify(&meta);
        let result =
            run_altair_sync_aggregate_case_mainnet(&case_dir, &case_name, verify_signatures);
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
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        "minimal",
        "altair",
        "operations",
        Some("sync_aggregate"),
        altair_ops_walk_opts(),
    ) {
        let case_name = format!(
            "altair/operations/minimal/sync_aggregate/{}",
            dir_name(&case_dir)
        );
        let verify_signatures = bls_verify(&meta);
        let result =
            run_altair_sync_aggregate_case_minimal(&case_dir, &case_name, verify_signatures);
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

// ── Altair shared helpers ─────────────────────────────────────────────────────

/// Walk altair operation sub-category and run each case with a closure.
fn run_altair_op_preset(
    root: &Path,
    preset: &str,
    sub: &str,
    mut run_case: impl FnMut(&Path, &str, bool) -> CaseResult,
) -> OpsResult {
    let mut out = OpsResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "altair",
        "operations",
        Some(sub),
        altair_ops_walk_opts(),
    ) {
        let case_name = format!("altair/operations/{preset}/{sub}/{}", dir_name(&case_dir));
        let verify_signatures = bls_verify(&meta);
        let result = run_case(&case_dir, &case_name, verify_signatures);
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
