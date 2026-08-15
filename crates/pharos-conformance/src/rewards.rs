//! Rewards conformance dispatcher.
//!
//! Walks `phase0/rewards/{basic,leak,random}/pyspec_tests/<case>/` for both
//! presets. Each case has:
//! - `pre.ssz_snappy` — input `BeaconState`.
//! - `source_deltas.ssz_snappy`, `target_deltas.ssz_snappy`,
//!   `head_deltas.ssz_snappy`, `inclusion_delay_deltas.ssz_snappy`,
//!   `inactivity_penalty_deltas.ssz_snappy` — expected `Deltas` outputs.
//!
//! No `meta.yaml` or `post.ssz_snappy`. For each case, each of the five
//! `get_*_deltas` functions is called on a clone of the pre-state and the
//! result is byte-compared to the corresponding fixture file.
//!
//! Sub-categories `basic`, `leak`, `random` are walked as three separate sweeps
//! that contribute to a single tallied result.

use std::path::Path;

use pharos_ssz::{Decode, Encode};
use pharos_stf::phase0::{
    BeaconStateWrite,
    epoch::{
        get_head_deltas, get_inactivity_penalty_deltas, get_inclusion_delay_deltas,
        get_source_deltas, get_target_deltas,
    },
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Attestation, Deltas},
    views::BeaconBlockBodyView,
};

use crate::fixture_walker::{WalkOpts, load_phase0_state, load_ssz_snappy, walk_category};
use crate::fs_util::dir_name;

/// Result tally for a single rewards preset run.
pub struct RewardsResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl RewardsResult {
    fn new() -> Self {
        RewardsResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }

    fn merge(&mut self, other: RewardsResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.skip += other.skip;
        self.failures.extend(other.failures);
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run all rewards sub-categories for the mainnet preset.
pub fn run_rewards_mainnet(root: &Path) -> RewardsResult {
    run_rewards_preset::<MainnetEthSpec>(root, "mainnet")
}

/// Run all rewards sub-categories for the minimal preset.
pub fn run_rewards_minimal(root: &Path) -> RewardsResult {
    run_rewards_preset::<MinimalEthSpec>(root, "minimal")
}

/// Run all rewards sub-categories (`basic`, `leak`, `random`) for a single preset.
pub fn run_rewards_preset<E>(root: &Path, preset: &'static str) -> RewardsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + Clone,
    E::Phase0BeaconState: Decode,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let mut total = RewardsResult::new();
    for sub in ["basic", "leak", "random"] {
        total.merge(run_rewards_sub::<E>(root, preset, sub));
    }
    total
}

// ── Sub-category sweep ────────────────────────────────────────────────────────

fn run_rewards_sub<E>(root: &Path, preset: &'static str, sub: &str) -> RewardsResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite + Clone,
    E::Phase0BeaconState: Decode,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let mut out = RewardsResult::new();
    for (case_dir, _meta) in walk_category(
        root,
        preset,
        "phase0",
        "rewards",
        Some(sub),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    ) {
        let case_name = format!("phase0/rewards/{sub}/{preset}/{}", dir_name(&case_dir));
        let result = run_rewards_case::<E>(&case_dir, &case_name);
        match result {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

// ── Single-case runner ────────────────────────────────────────────────────────

fn run_rewards_case<E>(case_dir: &Path, case_name: &str) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconState: Decode,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let pre = match load_phase0_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    // Five sub-assertions; first failure short-circuits and fails the whole case.
    // The delta functions all take `&BeaconState`, so we borrow `pre` for each
    // call rather than cloning it.
    macro_rules! check_deltas {
        ($fn:expr, $file:literal) => {{
            let actual = match $fn(&pre) {
                Ok(d) => d,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {} failed: {e}", $file)),
            };
            let expected = match load_ssz_snappy::<Deltas<1_099_511_627_776u64>>(case_dir, $file) {
                Ok(d) => d,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            if actual.as_ssz_bytes() != expected.as_ssz_bytes() {
                return CaseResult::Fail(format!("{case_name}: {} mismatch", $file));
            }
        }};
    }

    check_deltas!(get_source_deltas::<E>, "source_deltas.ssz_snappy");
    check_deltas!(get_target_deltas::<E>, "target_deltas.ssz_snappy");
    check_deltas!(get_head_deltas::<E>, "head_deltas.ssz_snappy");
    check_deltas!(
        get_inclusion_delay_deltas::<E>,
        "inclusion_delay_deltas.ssz_snappy"
    );
    check_deltas!(
        get_inactivity_penalty_deltas::<E>,
        "inactivity_penalty_deltas.ssz_snappy"
    );

    CaseResult::Pass
}

// ── Internal result type ──────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
}
