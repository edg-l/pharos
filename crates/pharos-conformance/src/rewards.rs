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

use pharos_ssz::{Decode, Encode, SszList};
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
use pharos_utils::Gwei;

use rayon::prelude::*;

use crate::fixture_walker::{
    WalkOpts, load_altair_state, load_bellatrix_state, load_phase0_state, load_ssz_snappy,
    walk_category,
};
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
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "phase0",
        "rewards",
        Some(sub),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("phase0/rewards/{sub}/{preset}/{}", dir_name(&case_dir));
            run_rewards_case::<E>(&case_dir, &case_name)
        })
        .collect();
    let mut out = RewardsResult::new();
    for outcome in outcomes {
        match outcome {
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

// ── Altair entry points ───────────────────────────────────────────────────────

/// Run all altair rewards sub-categories for the mainnet preset.
pub fn run_rewards_altair_mainnet(root: &Path) -> RewardsResult {
    let mut total = RewardsResult::new();
    for sub in ["basic", "leak", "random"] {
        total.merge(run_altair_rewards_sub_mainnet(root, sub));
    }
    total
}

/// Run all altair rewards sub-categories for the minimal preset.
pub fn run_rewards_altair_minimal(root: &Path) -> RewardsResult {
    let mut total = RewardsResult::new();
    for sub in ["basic", "leak", "random"] {
        total.merge(run_altair_rewards_sub_minimal(root, sub));
    }
    total
}

fn run_altair_rewards_sub_mainnet(root: &Path, sub: &str) -> RewardsResult {
    use pharos_stf::altair::helpers::{get_flag_index_deltas, get_inactivity_penalty_deltas};
    use pharos_types::{MainnetEthSpec as E, altair::MainnetBeaconState};

    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "altair",
        "rewards",
        Some(sub),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("altair/rewards/{sub}/mainnet/{}", dir_name(&case_dir));
            run_altair_rewards_case_mainnet::<E, MainnetBeaconState>(
                &case_dir,
                &case_name,
                |s, fi| {
                    get_flag_index_deltas::<
                        8192,
                        16_777_216,
                        2048,
                        1_099_511_627_776,
                        65536,
                        8192,
                        4,
                        512,
                        E,
                    >(s, fi)
                },
                |s| {
                    get_inactivity_penalty_deltas::<
                        8192,
                        16_777_216,
                        2048,
                        1_099_511_627_776,
                        65536,
                        8192,
                        4,
                        512,
                        E,
                    >(s)
                },
            )
        })
        .collect();
    let mut out = RewardsResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

fn run_altair_rewards_sub_minimal(root: &Path, sub: &str) -> RewardsResult {
    use pharos_stf::altair::helpers::{get_flag_index_deltas, get_inactivity_penalty_deltas};
    use pharos_types::{MinimalEthSpec as E, altair::MinimalBeaconState};

    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "altair",
        "rewards",
        Some(sub),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> =
        cases
            .into_par_iter()
            .map(|(case_dir, _meta)| {
                let case_name = format!("altair/rewards/{sub}/minimal/{}", dir_name(&case_dir));
                run_altair_rewards_case_mainnet::<E, MinimalBeaconState>(
                    &case_dir,
                    &case_name,
                    |s, fi| {
                        get_flag_index_deltas::<
                            64,
                            16_777_216,
                            32,
                            1_099_511_627_776,
                            64,
                            64,
                            4,
                            32,
                            E,
                        >(s, fi)
                    },
                    |s| {
                        get_inactivity_penalty_deltas::<
                            64,
                            16_777_216,
                            32,
                            1_099_511_627_776,
                            64,
                            64,
                            4,
                            32,
                            E,
                        >(s)
                    },
                )
            })
            .collect();
    let mut out = RewardsResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

fn run_altair_rewards_case_mainnet<E, S>(
    case_dir: &Path,
    case_name: &str,
    get_flag_deltas: impl Fn(&S, usize) -> (Vec<Gwei>, Vec<Gwei>),
    get_inactivity_deltas: impl Fn(&S) -> (Vec<Gwei>, Vec<Gwei>),
) -> CaseResult
where
    E: EthSpec<AltairBeaconState = S>,
    S: pharos_ssz::Decode,
{
    let pre = match load_altair_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let pre_inner = match E::into_altair_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not altair state")),
    };

    macro_rules! check_flag_deltas {
        ($flag_index:expr, $file:literal, $flag_name:literal) => {{
            let (rewards, penalties) = get_flag_deltas(&pre_inner, $flag_index);
            let actual = make_deltas(rewards, penalties);
            let expected = match load_ssz_snappy::<Deltas<1_099_511_627_776u64>>(case_dir, $file) {
                Ok(d) => d,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            if actual.as_ssz_bytes() != expected.as_ssz_bytes() {
                return CaseResult::Fail(format!("{case_name}: {} mismatch", $flag_name));
            }
        }};
    }

    // SOURCE_FLAG_INDEX = 0, TARGET_FLAG_INDEX = 1, HEAD_FLAG_INDEX = 2
    check_flag_deltas!(0, "source_deltas.ssz_snappy", "source_deltas");
    check_flag_deltas!(1, "target_deltas.ssz_snappy", "target_deltas");
    check_flag_deltas!(2, "head_deltas.ssz_snappy", "head_deltas");

    // Inactivity penalty deltas.
    let (rewards, penalties) = get_inactivity_deltas(&pre_inner);
    let actual_inactivity = make_deltas(rewards, penalties);
    let expected_inactivity = match load_ssz_snappy::<Deltas<1_099_511_627_776u64>>(
        case_dir,
        "inactivity_penalty_deltas.ssz_snappy",
    ) {
        Ok(d) => d,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    if actual_inactivity.as_ssz_bytes() != expected_inactivity.as_ssz_bytes() {
        return CaseResult::Fail(format!("{case_name}: inactivity_penalty_deltas mismatch"));
    }

    CaseResult::Pass
}

/// Pack `(Vec<Gwei>, Vec<Gwei>)` into `Deltas<VALIDATOR_REGISTRY_LIMIT>` for comparison.
fn make_deltas(rewards: Vec<Gwei>, penalties: Vec<Gwei>) -> Deltas<1_099_511_627_776u64> {
    Deltas {
        rewards: SszList::from_vec(rewards)
            .expect("rewards vec length exceeds VALIDATOR_REGISTRY_LIMIT"),
        penalties: SszList::from_vec(penalties)
            .expect("penalties vec length exceeds VALIDATOR_REGISTRY_LIMIT"),
    }
}

// ── Bellatrix entry points ────────────────────────────────────────────────────

/// Run all bellatrix rewards sub-categories for the mainnet preset.
pub fn run_rewards_bellatrix_mainnet(root: &Path) -> RewardsResult {
    let mut total = RewardsResult::new();
    for sub in ["basic", "leak", "random"] {
        total.merge(run_bellatrix_rewards_sub_mainnet(root, sub));
    }
    total
}

/// Run all bellatrix rewards sub-categories for the minimal preset.
pub fn run_rewards_bellatrix_minimal(root: &Path) -> RewardsResult {
    let mut total = RewardsResult::new();
    for sub in ["basic", "leak", "random"] {
        total.merge(run_bellatrix_rewards_sub_minimal(root, sub));
    }
    total
}

fn run_bellatrix_rewards_sub_mainnet(root: &Path, sub: &str) -> RewardsResult {
    use pharos_stf::altair::helpers::get_flag_index_deltas;
    use pharos_stf::bellatrix::helpers::{
        bellatrix_state_to_altair, get_inactivity_penalty_deltas_bellatrix,
    };
    use pharos_types::{MainnetEthSpec as E, bellatrix::MainnetBeaconState};

    let cases: Vec<_> = walk_category(
        root,
        "mainnet",
        "bellatrix",
        "rewards",
        Some(sub),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, _meta)| {
            let case_name = format!("bellatrix/rewards/{sub}/mainnet/{}", dir_name(&case_dir));
            run_bellatrix_rewards_case::<E, MainnetBeaconState>(
                &case_dir,
                &case_name,
                |s, fi| {
                    let a = bellatrix_state_to_altair(s);
                    get_flag_index_deltas::<
                        8192,
                        16_777_216,
                        2048,
                        1_099_511_627_776,
                        65536,
                        8192,
                        4,
                        512,
                        E,
                    >(&a, fi)
                },
                |s| {
                    get_inactivity_penalty_deltas_bellatrix::<
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
                    >(s)
                },
            )
        })
        .collect();
    let mut out = RewardsResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

fn run_bellatrix_rewards_sub_minimal(root: &Path, sub: &str) -> RewardsResult {
    use pharos_stf::altair::helpers::get_flag_index_deltas;
    use pharos_stf::bellatrix::helpers::{
        bellatrix_state_to_altair, get_inactivity_penalty_deltas_bellatrix,
    };
    use pharos_types::{MinimalEthSpec as E, bellatrix::MinimalBeaconState};

    let cases: Vec<_> = walk_category(
        root,
        "minimal",
        "bellatrix",
        "rewards",
        Some(sub),
        WalkOpts {
            meta_required: false,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();
    let outcomes: Vec<CaseResult> =
        cases
            .into_par_iter()
            .map(|(case_dir, _meta)| {
                let case_name = format!("bellatrix/rewards/{sub}/minimal/{}", dir_name(&case_dir));
                run_bellatrix_rewards_case::<E, MinimalBeaconState>(
                    &case_dir,
                    &case_name,
                    |s, fi| {
                        let a = bellatrix_state_to_altair(s);
                        get_flag_index_deltas::<
                            64,
                            16_777_216,
                            32,
                            1_099_511_627_776,
                            64,
                            64,
                            4,
                            32,
                            E,
                        >(&a, fi)
                    },
                    |s| {
                        get_inactivity_penalty_deltas_bellatrix::<
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
                        >(s)
                    },
                )
            })
            .collect();
    let mut out = RewardsResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
        }
    }
    out
}

fn run_bellatrix_rewards_case<E, S>(
    case_dir: &Path,
    case_name: &str,
    get_flag_deltas: impl Fn(&S, usize) -> (Vec<Gwei>, Vec<Gwei>),
    get_inactivity_deltas: impl Fn(&S) -> (Vec<Gwei>, Vec<Gwei>),
) -> CaseResult
where
    E: EthSpec<BellatrixBeaconState = S>,
    S: pharos_ssz::Decode,
{
    let pre = match load_bellatrix_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let pre_inner = match E::into_bellatrix_state(pre) {
        Some(s) => s,
        None => return CaseResult::Fail(format!("{case_name}: pre is not bellatrix state")),
    };

    macro_rules! check_flag_deltas {
        ($flag_index:expr, $file:literal, $flag_name:literal) => {{
            let (rewards, penalties) = get_flag_deltas(&pre_inner, $flag_index);
            let actual = make_deltas(rewards, penalties);
            let expected = match load_ssz_snappy::<Deltas<1_099_511_627_776u64>>(case_dir, $file) {
                Ok(d) => d,
                Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
            };
            if actual.as_ssz_bytes() != expected.as_ssz_bytes() {
                return CaseResult::Fail(format!("{case_name}: {} mismatch", $flag_name));
            }
        }};
    }

    check_flag_deltas!(0, "source_deltas.ssz_snappy", "source_deltas");
    check_flag_deltas!(1, "target_deltas.ssz_snappy", "target_deltas");
    check_flag_deltas!(2, "head_deltas.ssz_snappy", "head_deltas");

    let (rewards, penalties) = get_inactivity_deltas(&pre_inner);
    let actual_inactivity = make_deltas(rewards, penalties);
    let expected_inactivity = match load_ssz_snappy::<Deltas<1_099_511_627_776u64>>(
        case_dir,
        "inactivity_penalty_deltas.ssz_snappy",
    ) {
        Ok(d) => d,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    if actual_inactivity.as_ssz_bytes() != expected_inactivity.as_ssz_bytes() {
        return CaseResult::Fail(format!("{case_name}: inactivity_penalty_deltas mismatch"));
    }

    CaseResult::Pass
}

// ── Internal result type ──────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
}
