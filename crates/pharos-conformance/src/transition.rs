//! Altair and Bellatrix transition conformance dispatchers.
//!
//! Altair: walks `tests/{preset}/altair/transition/core/pyspec_tests/<case>/`,
//! loads `meta.yaml` for `fork_epoch` and `blocks_count`, applies pre-fork
//! phase0 blocks, calls `upgrade_to_altair`, applies post-fork altair blocks,
//! and compares the final state to `post.ssz_snappy`.
//!
//! Bellatrix: walks `tests/{preset}/bellatrix/transition/core/pyspec_tests/<case>/`,
//! loads pre-state as altair `BeaconState`, applies pre-fork altair blocks,
//! calls `upgrade_to_bellatrix`, applies post-fork bellatrix blocks, and
//! compares the final state to `post.ssz_snappy`.
//!
//! Per `D-altair-transition-test-strategy` (docs/m3b-plan.md).
//!
//! # Fixture format (altair)
//!
//! - `pre.ssz_snappy` — raw phase0 `BeaconState` SSZ (no fork discriminant).
//! - `blocks_<i>.ssz_snappy` — phase0 or altair `SignedBeaconBlock`, depending
//!   on block slot relative to fork_epoch.
//! - `meta.yaml` — `fork_epoch: u64`, `blocks_count: u64`, `post_fork: altair`.
//! - `post.ssz_snappy` — raw altair `BeaconState` SSZ (no fork discriminant).
//!
//! # Fixture format (bellatrix)
//!
//! - `pre.ssz_snappy` — raw altair `BeaconState` SSZ (no fork discriminant).
//! - `blocks_<i>.ssz_snappy` — altair or bellatrix `SignedBeaconBlock`.
//! - `meta.yaml` — `fork_epoch: u64`, `blocks_count: u64`, `post_fork: bellatrix`.
//! - `post.ssz_snappy` — raw bellatrix `BeaconState` SSZ (no fork discriminant).
//!
//! Hard constraint: no YAML loader (plan Phase 4 constraint 1). We use
//! compile-time `MainnetEthSpec` / `MinimalEthSpec` preset constants for
//! fork versions and override fork_epoch from `meta.yaml`.

use std::path::Path;

use pharos_ssz::Encode;
use pharos_stf::altair::upgrade::upgrade_to_altair;
use pharos_stf::bellatrix::upgrade::upgrade_to_bellatrix;
use pharos_stf::capella::upgrade::upgrade_to_capella;
use pharos_stf::{
    AltairProcessSlotsDispatch, AltairUpgradeDispatch, BellatrixProcessSlotsDispatch,
    BellatrixUpgradeDispatch, CapellaProcessSlotsDispatch, Phase0UpgradeDispatch,
};
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Epoch, Slot},
    views::BeaconStateView,
};
use rayon::prelude::*;

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_bellatrix_signed_block,
    load_bellatrix_state, load_capella_signed_block, load_capella_state, load_phase0_signed_block,
    load_phase0_state, walk_category,
};
use crate::fs_util::dir_name;
use crate::snappy::decompress_raw;

/// Result tally for a single transition preset run.
pub struct TransitionResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

impl TransitionResult {
    fn new() -> Self {
        TransitionResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
        }
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run altair transition tests for the mainnet preset.
pub fn run_transition_mainnet(root: &Path) -> TransitionResult {
    run_transition_impl(root, "mainnet", &run_case_mainnet)
}

/// Run altair transition tests for the minimal preset.
pub fn run_transition_minimal(root: &Path) -> TransitionResult {
    run_transition_impl(root, "minimal", &run_case_minimal)
}

/// Run bellatrix transition tests for the mainnet preset.
pub fn run_transition_bellatrix_mainnet(root: &Path) -> TransitionResult {
    run_bellatrix_transition_impl(root, "mainnet", &run_bellatrix_case_mainnet)
}

/// Run bellatrix transition tests for the minimal preset.
pub fn run_transition_bellatrix_minimal(root: &Path) -> TransitionResult {
    run_bellatrix_transition_impl(root, "minimal", &run_bellatrix_case_minimal)
}

// ── Internal runner ───────────────────────────────────────────────────────────

fn run_transition_impl(
    root: &Path,
    preset: &'static str,
    run_case: &(dyn Fn(&Path, &str, Epoch, u64) -> CaseResult + Sync),
) -> TransitionResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "altair",
        "transition",
        Some("core"),
        WalkOpts {
            meta_required: true,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("altair/transition/core/{preset}/{}", dir_name(&case_dir));

            let fork_epoch = match meta.as_ref().and_then(|m| m.fork_epoch) {
                Some(e) => Epoch(e),
                None => return CaseResult::Skip,
            };
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            run_case(&case_dir, &case_name, fork_epoch, blocks_count)
        })
        .collect();

    let mut out = TransitionResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
            CaseResult::Skip => out.skip += 1,
        }
    }
    out
}

fn run_bellatrix_transition_impl(
    root: &Path,
    preset: &'static str,
    run_case: &(dyn Fn(&Path, &str, Epoch, u64) -> CaseResult + Sync),
) -> TransitionResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "bellatrix",
        "transition",
        Some("core"),
        WalkOpts {
            meta_required: true,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("bellatrix/transition/core/{preset}/{}", dir_name(&case_dir));

            let fork_epoch = match meta.as_ref().and_then(|m| m.fork_epoch) {
                Some(e) => Epoch(e),
                None => return CaseResult::Skip,
            };
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };

            run_case(&case_dir, &case_name, fork_epoch, blocks_count)
        })
        .collect();

    let mut out = TransitionResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
            CaseResult::Skip => out.skip += 1,
        }
    }
    out
}

// ── Slot-peek helper ──────────────────────────────────────────────────────────

/// Peek at the `slot` field of a raw `SignedBeaconBlock` SSZ blob.
///
/// `SignedBeaconBlock` is `{ message: BeaconBlock (variable), signature: BLSSignature (96 fixed) }`.
/// SSZ encoding: `[offset_to_message: u32 (4 bytes)] [signature: 96 bytes] [message_bytes]`.
/// `BeaconBlock` starts with `slot: Slot (u64)` → message_bytes[0..8].
/// So the slot lives at bytes `[offset..offset+8]` in the full encoding,
/// where `offset = u32::from_le_bytes(bytes[0..4]) as usize`.
fn peek_block_slot(case_dir: &Path, block_file: &str) -> Option<Slot> {
    let path = case_dir.join(block_file);
    let compressed = std::fs::read(&path).ok()?;
    let raw = decompress_raw(&compressed).ok()?;
    // Parse offset to message (first 4 bytes).
    if raw.len() < 4 {
        return None;
    }
    let offset = u32::from_le_bytes(raw[0..4].try_into().ok()?) as usize;
    // slot is u64 at beginning of message.
    if raw.len() < offset + 8 {
        return None;
    }
    let slot = u64::from_le_bytes(raw[offset..offset + 8].try_into().ok()?);
    Some(Slot(slot))
}

// ── Mainnet case runner ───────────────────────────────────────────────────────

fn run_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    fork_epoch: Epoch,
    blocks_count: u64,
) -> CaseResult {
    type E = MainnetEthSpec;

    let pre = match load_phase0_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_altair_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut cfg = E::default_runtime_config();
    cfg.altair_fork_epoch = fork_epoch.0;
    let fork_slot = Slot(fork_epoch.0 * E::SLOTS_PER_EPOCH);

    run_case_blocks::<E, _>(
        case_dir,
        case_name,
        BlocksCaseParams {
            current: pre,
            expected,
            fork_slot,
            blocks_count,
        },
        |phase0_inner, cfg| {
            upgrade_to_altair::<
                8192,              // SLOTS_PER_HISTORICAL_ROOT mainnet
                16_777_216,        // HISTORICAL_ROOTS_LIMIT
                2048,              // ETH1_DATA_VOTES_LIMIT
                1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
                65536,             // EPOCHS_PER_HISTORICAL_VECTOR
                8192,              // EPOCHS_PER_SLASHINGS_VECTOR
                4096,              // MAX_PENDING_ATTESTATIONS
                4,                 // JUSTIFICATION_BITS_LENGTH
                2048,              // MAX_VALIDATORS_PER_COMMITTEE
                512,               // SYNC_COMMITTEE_SIZE
                E,
            >(phase0_inner, cfg)
            .map(E::altair_into_state)
            .map_err(|e| format!("{e}"))
        },
        &cfg,
    )
}

// ── Minimal case runner ───────────────────────────────────────────────────────

fn run_case_minimal(
    case_dir: &Path,
    case_name: &str,
    fork_epoch: Epoch,
    blocks_count: u64,
) -> CaseResult {
    type E = MinimalEthSpec;

    let pre = match load_phase0_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_altair_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut cfg = E::default_runtime_config();
    cfg.altair_fork_epoch = fork_epoch.0;
    let fork_slot = Slot(fork_epoch.0 * E::SLOTS_PER_EPOCH);

    run_case_blocks::<E, _>(
        case_dir,
        case_name,
        BlocksCaseParams {
            current: pre,
            expected,
            fork_slot,
            blocks_count,
        },
        |phase0_inner, cfg| {
            upgrade_to_altair::<
                64,                // SLOTS_PER_HISTORICAL_ROOT minimal
                16_777_216,        // HISTORICAL_ROOTS_LIMIT
                32,                // ETH1_DATA_VOTES_LIMIT
                1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
                64,                // EPOCHS_PER_HISTORICAL_VECTOR
                64,                // EPOCHS_PER_SLASHINGS_VECTOR
                1024,              // MAX_PENDING_ATTESTATIONS
                4,                 // JUSTIFICATION_BITS_LENGTH
                2048,              // MAX_VALIDATORS_PER_COMMITTEE
                32,                // SYNC_COMMITTEE_SIZE
                E,
            >(phase0_inner, cfg)
            .map(E::altair_into_state)
            .map_err(|e| format!("{e}"))
        },
        &cfg,
    )
}

// ── Bellatrix case runners ────────────────────────────────────────────────────

fn run_bellatrix_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    fork_epoch: Epoch,
    blocks_count: u64,
) -> CaseResult {
    type E = MainnetEthSpec;

    let pre = match load_altair_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_bellatrix_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut cfg = E::default_runtime_config();
    cfg.bellatrix_fork_epoch = fork_epoch.0;
    let fork_slot = Slot(fork_epoch.0 * E::SLOTS_PER_EPOCH);

    run_bellatrix_transition_blocks::<E, _>(
        case_dir,
        case_name,
        BellatrixBlocksCaseParams {
            current: pre,
            expected,
            fork_slot,
            blocks_count,
        },
        |altair_inner, cfg| {
            upgrade_to_bellatrix::<
                8192,              // SLOTS_PER_HISTORICAL_ROOT
                16_777_216,        // HISTORICAL_ROOTS_LIMIT
                2048,              // ETH1_DATA_VOTES_LIMIT
                1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
                65536,             // EPOCHS_PER_HISTORICAL_VECTOR
                8192,              // EPOCHS_PER_SLASHINGS_VECTOR
                4,                 // JUSTIFICATION_BITS_LENGTH
                512,               // SYNC_COMMITTEE_SIZE
                256,               // BYTES_PER_LOGS_BLOOM
                32,                // MAX_EXTRA_DATA_BYTES
                E,
            >(altair_inner, cfg)
            .map(E::bellatrix_into_state)
            .map_err(|e| format!("{e}"))
        },
        &cfg,
    )
}

fn run_bellatrix_case_minimal(
    case_dir: &Path,
    case_name: &str,
    fork_epoch: Epoch,
    blocks_count: u64,
) -> CaseResult {
    type E = MinimalEthSpec;

    let pre = match load_altair_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_bellatrix_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut cfg = E::default_runtime_config();
    cfg.bellatrix_fork_epoch = fork_epoch.0;
    let fork_slot = Slot(fork_epoch.0 * E::SLOTS_PER_EPOCH);

    run_bellatrix_transition_blocks::<E, _>(
        case_dir,
        case_name,
        BellatrixBlocksCaseParams {
            current: pre,
            expected,
            fork_slot,
            blocks_count,
        },
        |altair_inner, cfg| {
            upgrade_to_bellatrix::<
                64,                // SLOTS_PER_HISTORICAL_ROOT
                16_777_216,        // HISTORICAL_ROOTS_LIMIT
                32,                // ETH1_DATA_VOTES_LIMIT
                1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
                64,                // EPOCHS_PER_HISTORICAL_VECTOR
                64,                // EPOCHS_PER_SLASHINGS_VECTOR
                4,                 // JUSTIFICATION_BITS_LENGTH
                32,                // SYNC_COMMITTEE_SIZE
                256,               // BYTES_PER_LOGS_BLOOM
                32,                // MAX_EXTRA_DATA_BYTES
                E,
            >(altair_inner, cfg)
            .map(E::bellatrix_into_state)
            .map_err(|e| format!("{e}"))
        },
        &cfg,
    )
}

// ── Bellatrix shared block-sequence runner ────────────────────────────────────

/// Parameters for `run_bellatrix_transition_blocks`.
struct BellatrixBlocksCaseParams<S> {
    current: S,
    expected: S,
    fork_slot: Slot,
    blocks_count: u64,
}

/// Drive the block sequence through the altair → bellatrix fork transition.
///
/// Uses `peek_block_slot` to determine whether each block is pre-fork (altair)
/// or post-fork (bellatrix). The upgrade is applied exactly once, just before
/// the first post-fork block (after advancing to `fork_slot` if necessary).
fn run_bellatrix_transition_blocks<E, F>(
    case_dir: &Path,
    case_name: &str,
    params: BellatrixBlocksCaseParams<E::BeaconState>,
    do_upgrade: F,
    cfg: &pharos_types::config::RuntimeConfig,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateView,
    E::AltairBeaconState: pharos_ssz::Decode
        + pharos_types::views::BeaconStateView
        + pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_ssz::Decode
        + pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
    E::BeaconState:
        pharos_stf::phase0::BeaconStateWrite + pharos_ssz::TreeHash + pharos_ssz::Encode,
    E::Phase0BeaconBlock: pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    F: Fn(
        E::AltairBeaconState,
        &pharos_types::config::RuntimeConfig,
    ) -> Result<E::BeaconState, String>,
{
    let BellatrixBlocksCaseParams {
        mut current,
        expected,
        fork_slot,
        blocks_count,
    } = params;
    let mut did_upgrade = false;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");

        let block_slot = match peek_block_slot(case_dir, &block_file) {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!(
                    "{case_name}: failed to peek slot from {block_file}"
                ));
            }
        };

        // Upgrade state before the first post-fork block.
        if !did_upgrade && block_slot >= fork_slot {
            // Extract altair inner to advance slots altair-style.
            let mut altair_inner = match E::into_altair_state(current) {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: state is already bellatrix before upgrade"
                    ));
                }
            };
            if altair_inner.slot() < fork_slot {
                if let Err(e) = altair_inner.process_slots_altair(fork_slot) {
                    return CaseResult::Fail(format!(
                        "{case_name}: process_slots to fork before block {i}: {e}"
                    ));
                }
            }
            match do_upgrade(altair_inner, cfg) {
                Ok(s) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: upgrade_to_bellatrix: {e}"));
                }
            }
            did_upgrade = true;
        }

        if !did_upgrade {
            // Pre-fork: apply as altair block.
            let block = match load_altair_signed_block::<E>(case_dir, &block_file) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: block {i}: {e}")),
            };
            match pharos_stf::state_transition::<E, pharos_stf::NullExecutionEngine>(
                current,
                &block,
                &pharos_stf::NullExecutionEngine,
                false,
                cfg,
            ) {
                Ok((s, _)) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: block {i} (altair): {e}"));
                }
            }
        } else {
            // Post-fork: apply as bellatrix block.
            let block = match load_bellatrix_signed_block::<E>(case_dir, &block_file) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: block {i}: {e}")),
            };
            match pharos_stf::state_transition::<E, pharos_stf::NullExecutionEngine>(
                current,
                &block,
                &pharos_stf::NullExecutionEngine,
                false,
                cfg,
            ) {
                Ok((s, _)) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: block {i} (bellatrix): {e}"));
                }
            }
        }
    }

    // If all blocks were pre-fork (or blocks_count == 0), advance and upgrade now.
    if !did_upgrade {
        let mut altair_inner = match E::into_altair_state(current) {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: already bellatrix before upgrade"));
            }
        };
        if altair_inner.slot() < fork_slot {
            if let Err(e) = altair_inner.process_slots_altair(fork_slot) {
                return CaseResult::Fail(format!("{case_name}: process_slots to fork: {e}"));
            }
        }
        match do_upgrade(altair_inner, cfg) {
            Ok(s) => current = s,
            Err(e) => return CaseResult::Fail(format!("{case_name}: upgrade_to_bellatrix: {e}")),
        }
    }

    let expected_bytes = {
        let bellatrix = match E::into_bellatrix_state(expected) {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: expected state not bellatrix")),
        };
        E::bellatrix_into_state(bellatrix).as_ssz_bytes()
    };

    if current.as_ssz_bytes() == expected_bytes {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!(
            "{case_name}: state mismatch after bellatrix transition"
        ))
    }
}

/// Parameters for `run_case_blocks` (grouped to stay under the 7-arg limit).
struct BlocksCaseParams<S> {
    current: S,
    expected: S,
    fork_slot: Slot,
    blocks_count: u64,
}

/// Drive the block sequence through the phase0 → altair fork transition.
///
/// Uses `peek_block_slot` to determine whether each block is pre-fork (phase0)
/// or post-fork (altair). The upgrade is applied exactly once, just before the
/// first post-fork block (after advancing to `fork_slot` if necessary).
fn run_case_blocks<E, F>(
    case_dir: &Path,
    case_name: &str,
    params: BlocksCaseParams<E::BeaconState>,
    do_upgrade: F,
    cfg: &pharos_types::config::RuntimeConfig,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateView,
    E::Phase0BeaconState: pharos_ssz::Decode + Phase0UpgradeDispatch<E>,
    E::AltairBeaconState: pharos_ssz::Decode
        + pharos_stf::AltairDispatch<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconBlock: pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>,
    E::BeaconState:
        pharos_stf::phase0::BeaconStateWrite + pharos_ssz::TreeHash + pharos_ssz::Encode,
    F: Fn(
        E::Phase0BeaconState,
        &pharos_types::config::RuntimeConfig,
    ) -> Result<E::BeaconState, String>,
{
    let BlocksCaseParams {
        mut current,
        expected,
        fork_slot,
        blocks_count,
    } = params;
    let mut did_upgrade = false;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");

        // Peek at the block slot to determine whether this is pre- or post-fork.
        let block_slot = match peek_block_slot(case_dir, &block_file) {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!(
                    "{case_name}: failed to peek slot from {block_file}"
                ));
            }
        };

        // Upgrade state before the first post-fork block.
        if !did_upgrade && block_slot >= fork_slot {
            // Advance state to fork_slot (process any slots between last block and fork).
            if current.slot() < fork_slot {
                if let Err(e) = pharos_stf::process_slots::<E>(&mut current, fork_slot) {
                    return CaseResult::Fail(format!(
                        "{case_name}: process_slots to fork before block {i}: {e}"
                    ));
                }
            }
            let phase0_inner = match E::into_phase0_state(current) {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: state is already altair before upgrade"
                    ));
                }
            };
            match do_upgrade(phase0_inner, cfg) {
                Ok(s) => current = s,
                Err(e) => return CaseResult::Fail(format!("{case_name}: upgrade_to_altair: {e}")),
            }
            did_upgrade = true;
        }

        if !did_upgrade {
            // Pre-fork: apply as phase0 block.
            let block = match load_phase0_signed_block::<E>(case_dir, &block_file) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: block {i}: {e}")),
            };
            match pharos_stf::state_transition::<E, pharos_stf::NullExecutionEngine>(
                current,
                &block,
                &pharos_stf::NullExecutionEngine,
                false,
                &pharos_types::config::RuntimeConfig::default(),
            ) {
                Ok((s, _)) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: block {i} (phase0): {e}"));
                }
            }
        } else {
            // Post-fork: apply as altair block.
            let block = match load_altair_signed_block::<E>(case_dir, &block_file) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: block {i}: {e}")),
            };
            match pharos_stf::state_transition::<E, pharos_stf::NullExecutionEngine>(
                current,
                &block,
                &pharos_stf::NullExecutionEngine,
                false,
                &pharos_types::config::RuntimeConfig::default(),
            ) {
                Ok((s, _)) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: block {i} (altair): {e}"));
                }
            }
        }
    }

    // If all blocks were pre-fork (or blocks_count == 0), advance and upgrade now.
    if !did_upgrade {
        if current.slot() < fork_slot {
            if let Err(e) = pharos_stf::process_slots::<E>(&mut current, fork_slot) {
                return CaseResult::Fail(format!("{case_name}: process_slots to fork: {e}"));
            }
        }
        let phase0_inner = match E::into_phase0_state(current) {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: already altair before upgrade")),
        };
        match do_upgrade(phase0_inner, cfg) {
            Ok(s) => current = s,
            Err(e) => return CaseResult::Fail(format!("{case_name}: upgrade_to_altair: {e}")),
        }
    }

    if current.as_ssz_bytes() == expected.as_ssz_bytes() {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!("{case_name}: state mismatch after transition"))
    }
}

// ── Internal result type ──────────────────────────────────────────────────────

enum CaseResult {
    Pass,
    Fail(String),
    #[allow(dead_code)]
    Skip,
}

// ── Capella transition entry points ──────────────────────────────────────────

/// Run capella transition tests for the mainnet preset.
pub fn run_transition_capella_mainnet(root: &Path) -> TransitionResult {
    run_capella_transition_impl(root, "mainnet", &run_capella_case_mainnet)
}

/// Run capella transition tests for the minimal preset.
pub fn run_transition_capella_minimal(root: &Path) -> TransitionResult {
    run_capella_transition_impl(root, "minimal", &run_capella_case_minimal)
}

fn run_capella_transition_impl(
    root: &Path,
    preset: &'static str,
    run_case: &(dyn Fn(&Path, &str, Epoch, u64) -> CaseResult + Sync),
) -> TransitionResult {
    let cases: Vec<_> = walk_category(
        root,
        preset,
        "capella",
        "transition",
        Some("core"),
        WalkOpts {
            meta_required: true,
            inner_dir: Some("pyspec_tests"),
        },
    )
    .collect();

    let outcomes: Vec<CaseResult> = cases
        .into_par_iter()
        .map(|(case_dir, meta)| {
            let case_name = format!("capella/transition/core/{preset}/{}", dir_name(&case_dir));
            let fork_epoch = match meta.as_ref().and_then(|m| m.fork_epoch) {
                Some(e) => Epoch(e),
                None => return CaseResult::Skip,
            };
            let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
                Some(n) => n,
                None => return CaseResult::Skip,
            };
            run_case(&case_dir, &case_name, fork_epoch, blocks_count)
        })
        .collect();

    let mut out = TransitionResult::new();
    for outcome in outcomes {
        match outcome {
            CaseResult::Pass => out.pass += 1,
            CaseResult::Fail(msg) => {
                out.fail += 1;
                out.failures.push(msg);
            }
            CaseResult::Skip => out.skip += 1,
        }
    }
    out
}

fn run_capella_case_mainnet(
    case_dir: &Path,
    case_name: &str,
    fork_epoch: Epoch,
    blocks_count: u64,
) -> CaseResult {
    type E = MainnetEthSpec;

    let pre = match load_bellatrix_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_capella_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut cfg = E::default_runtime_config();
    cfg.capella_fork_epoch = fork_epoch.0;
    let fork_slot = Slot(fork_epoch.0 * E::SLOTS_PER_EPOCH);

    run_capella_transition_blocks::<E, _>(
        case_dir,
        case_name,
        CapellaBlocksCaseParams {
            current: pre,
            expected,
            fork_slot,
            blocks_count,
        },
        |bellatrix_inner, cfg| {
            upgrade_to_capella::<
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
            >(bellatrix_inner, cfg)
            .map(E::capella_into_state)
            .map_err(|e| format!("{e}"))
        },
        &cfg,
    )
}

fn run_capella_case_minimal(
    case_dir: &Path,
    case_name: &str,
    fork_epoch: Epoch,
    blocks_count: u64,
) -> CaseResult {
    type E = MinimalEthSpec;

    let pre = match load_bellatrix_state::<E>(case_dir, "pre.ssz_snappy") {
        Ok(v) => v,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };
    let expected = match load_capella_state::<E>(case_dir, "post.ssz_snappy") {
        Ok(s) => s,
        Err(e) => return CaseResult::Fail(format!("{case_name}: {e}")),
    };

    let mut cfg = E::default_runtime_config();
    cfg.capella_fork_epoch = fork_epoch.0;
    let fork_slot = Slot(fork_epoch.0 * E::SLOTS_PER_EPOCH);

    run_capella_transition_blocks::<E, _>(
        case_dir,
        case_name,
        CapellaBlocksCaseParams {
            current: pre,
            expected,
            fork_slot,
            blocks_count,
        },
        |bellatrix_inner, cfg| {
            upgrade_to_capella::<64, 16_777_216, 32, 1_099_511_627_776, 64, 64, 4, 32, 256, 32, E>(
                bellatrix_inner,
                cfg,
            )
            .map(E::capella_into_state)
            .map_err(|e| format!("{e}"))
        },
        &cfg,
    )
}

// ── Capella shared block-sequence runner ──────────────────────────────────────

struct CapellaBlocksCaseParams<S> {
    current: S,
    expected: S,
    fork_slot: Slot,
    blocks_count: u64,
}

/// Drive the block sequence through the bellatrix → capella fork transition.
fn run_capella_transition_blocks<E, F>(
    case_dir: &Path,
    case_name: &str,
    params: CapellaBlocksCaseParams<E::BeaconState>,
    do_upgrade: F,
    cfg: &pharos_types::config::RuntimeConfig,
) -> CaseResult
where
    E: EthSpec,
    E::BeaconState: BeaconStateView,
    E::AltairBeaconState:
        pharos_stf::AltairDispatch<E> + AltairProcessSlotsDispatch<E> + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_ssz::Decode
        + pharos_types::views::BeaconStateView
        + pharos_stf::BellatrixDispatch<E, pharos_stf::NullExecutionEngine>
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_ssz::Decode
        + pharos_stf::CapellaDispatch<E, pharos_stf::NullExecutionEngine>
        + CapellaProcessSlotsDispatch<E>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode,
    E::CapellaSignedBeaconBlock: pharos_ssz::Decode,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
    E::BeaconState:
        pharos_stf::phase0::BeaconStateWrite + pharos_ssz::TreeHash + pharos_ssz::Encode,
    E::Phase0BeaconBlock: pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    F: Fn(
        E::BellatrixBeaconState,
        &pharos_types::config::RuntimeConfig,
    ) -> Result<E::BeaconState, String>,
{
    let CapellaBlocksCaseParams {
        mut current,
        expected,
        fork_slot,
        blocks_count,
    } = params;
    let mut did_upgrade = false;

    for i in 0..blocks_count {
        let block_file = format!("blocks_{i}.ssz_snappy");
        let block_slot = match peek_block_slot(case_dir, &block_file) {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!(
                    "{case_name}: failed to peek slot from {block_file}"
                ));
            }
        };

        if !did_upgrade && block_slot >= fork_slot {
            let mut bellatrix_inner = match E::into_bellatrix_state(current) {
                Some(s) => s,
                None => {
                    return CaseResult::Fail(format!(
                        "{case_name}: state is already capella before upgrade"
                    ));
                }
            };
            if bellatrix_inner.slot() < fork_slot {
                if let Err(e) = bellatrix_inner.process_slots_bellatrix(fork_slot) {
                    return CaseResult::Fail(format!(
                        "{case_name}: process_slots to fork before block {i}: {e}"
                    ));
                }
            }
            match do_upgrade(bellatrix_inner, cfg) {
                Ok(s) => current = s,
                Err(e) => return CaseResult::Fail(format!("{case_name}: upgrade_to_capella: {e}")),
            }
            did_upgrade = true;
        }

        if !did_upgrade {
            let block = match load_bellatrix_signed_block::<E>(case_dir, &block_file) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: block {i}: {e}")),
            };
            match pharos_stf::state_transition::<E, pharos_stf::NullExecutionEngine>(
                current,
                &block,
                &pharos_stf::NullExecutionEngine,
                false,
                cfg,
            ) {
                Ok((s, _)) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: block {i} (bellatrix): {e}"));
                }
            }
        } else {
            let block = match load_capella_signed_block::<E>(case_dir, &block_file) {
                Ok(v) => v,
                Err(e) => return CaseResult::Fail(format!("{case_name}: block {i}: {e}")),
            };
            match pharos_stf::state_transition::<E, pharos_stf::NullExecutionEngine>(
                current,
                &block,
                &pharos_stf::NullExecutionEngine,
                false,
                cfg,
            ) {
                Ok((s, _)) => current = s,
                Err(e) => {
                    return CaseResult::Fail(format!("{case_name}: block {i} (capella): {e}"));
                }
            }
        }
    }

    if !did_upgrade {
        let mut bellatrix_inner = match E::into_bellatrix_state(current) {
            Some(s) => s,
            None => {
                return CaseResult::Fail(format!("{case_name}: already capella before upgrade"));
            }
        };
        if bellatrix_inner.slot() < fork_slot {
            if let Err(e) = bellatrix_inner.process_slots_bellatrix(fork_slot) {
                return CaseResult::Fail(format!("{case_name}: process_slots to fork: {e}"));
            }
        }
        match do_upgrade(bellatrix_inner, cfg) {
            Ok(s) => current = s,
            Err(e) => return CaseResult::Fail(format!("{case_name}: upgrade_to_capella: {e}")),
        }
    }

    let expected_bytes = {
        let capella = match E::into_capella_state(expected) {
            Some(s) => s,
            None => return CaseResult::Fail(format!("{case_name}: expected state not capella")),
        };
        E::capella_into_state(capella).as_ssz_bytes()
    };

    if current.as_ssz_bytes() == expected_bytes {
        CaseResult::Pass
    } else {
        CaseResult::Fail(format!(
            "{case_name}: state mismatch after capella transition"
        ))
    }
}
