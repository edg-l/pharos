//! Altair transition conformance dispatcher.
//!
//! Walks `tests/{preset}/altair/transition/core/pyspec_tests/<case>/`,
//! loads `meta.yaml` for `fork_epoch` and `blocks_count`, applies pre-fork
//! phase0 blocks, calls `upgrade_to_altair`, applies post-fork altair blocks,
//! and compares the final state to `post.ssz_snappy`.
//!
//! Per `D-altair-transition-test-strategy` (docs/m3b-plan.md).
//!
//! # Fixture format
//!
//! - `pre.ssz_snappy` — raw phase0 `BeaconState` SSZ (no fork discriminant).
//! - `blocks_<i>.ssz_snappy` — phase0 or altair `SignedBeaconBlock`, depending
//!   on block slot relative to fork_epoch.
//! - `meta.yaml` — `fork_epoch: u64`, `blocks_count: u64`, `post_fork: altair`.
//! - `post.ssz_snappy` — raw altair `BeaconState` SSZ (no fork discriminant).
//!
//! Hard constraint: no YAML loader (plan Phase 4 constraint 1). We use
//! compile-time `MainnetEthSpec` / `MinimalEthSpec` preset constants for
//! `altair_fork_version` and override `altair_fork_epoch` from `meta.yaml`.

use std::path::Path;

use pharos_ssz::Encode;
use pharos_stf::altair::upgrade::upgrade_to_altair;
use pharos_types::{
    EthSpec, MainnetEthSpec, MinimalEthSpec,
    phase0::{Epoch, Slot},
    views::BeaconStateView,
};

use crate::fixture_walker::{
    WalkOpts, load_altair_signed_block, load_altair_state, load_phase0_signed_block,
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

// ── Internal runner ───────────────────────────────────────────────────────────

fn run_transition_impl(
    root: &Path,
    preset: &'static str,
    run_case: &dyn Fn(&Path, &str, Epoch, u64) -> CaseResult,
) -> TransitionResult {
    let mut out = TransitionResult::new();
    for (case_dir, meta) in walk_category(
        root,
        preset,
        "altair",
        "transition",
        Some("core"),
        WalkOpts {
            meta_required: true,
            inner_dir: Some("pyspec_tests"),
        },
    ) {
        let case_name = format!("altair/transition/core/{preset}/{}", dir_name(&case_dir));

        let fork_epoch = match meta.as_ref().and_then(|m| m.fork_epoch) {
            Some(e) => Epoch(e),
            None => {
                out.skip += 1;
                continue;
            }
        };
        let blocks_count = match meta.as_ref().and_then(|m| m.blocks_count) {
            Some(n) => n,
            None => {
                out.skip += 1;
                continue;
            }
        };

        match run_case(&case_dir, &case_name, fork_epoch, blocks_count) {
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

// ── Shared block-sequence runner ──────────────────────────────────────────────

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
    E::Phase0BeaconState: pharos_ssz::Decode,
    E::AltairBeaconState: pharos_ssz::Decode,
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
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>,
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
            match pharos_stf::state_transition::<E>(current, &block, false) {
                Ok(s) => current = s,
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
            match pharos_stf::state_transition::<E>(current, &block, false) {
                Ok(s) => current = s,
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
