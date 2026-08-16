//! Networking conformance runner.
//!
//! Handles two flavours of networking fixture:
//!
//! - **DAS-core custody helpers** (`get_custody_groups`,
//!   `compute_columns_for_custody_group`) — deterministic functions with a
//!   `result` list in `meta.yaml`; runs for real for fulu.
//!
//! - **Gossip-validator condition fixtures** (`gossip_beacon_block`,
//!   `gossip_beacon_attestation`, etc.) — for phase0..fulu. Each case
//!   carries a `state.ssz_snappy`, an optional list of pre-imported
//!   `blocks`, an optional `current_time_ms` base (absent for time-independent
//!   topics like attester_slashing, proposer_slashing, voluntary_exit), and a
//!   sequence of messages with optional `offset_ms` + `expected: valid|ignore|reject`.
//!   The runner builds a `HostImpl<E>`, seeds it with the fixture state, sets the
//!   injectable clock, and calls the appropriate gossip validator per topic.
//!   Per `D-gossip-conformance-runner`.
//!
//! Fixture layout: `<root>/<preset>/<fork>/networking/<handler>/<suite>/<case>/`.
//!
//! ## Pre-block import strategy
//!
//! The fixture only provides one `state.ssz_snappy`, which is the post-state
//! of the LAST valid pre-block. Pre-blocks are inserted into `fc.blocks`
//! directly (no STF needed): the gossip validators only walk `fc.blocks` via
//! `parent_root` chains (for ancestor checks) and look up `fc.block_states` at
//! the message's parent root (= anchor_root = last valid pre-block root).
//! Failed pre-blocks are registered in `host.invalid_block_roots` so step-1
//! of `validate_beacon_block` fires correctly.
//!
//! ## Anchor root computation
//!
//! The anchor root is the root of the last valid pre-block, computed as
//! `block_msg.tree_hash_root()` (the ACTUAL block root including real state_root).
//! This differs from `anchor_root_from_state_header` which re-zeroes state_root
//! before hashing (matching the spec's intermediate form, NOT the filename hash).
//! When no pre-blocks exist, we use the zeroed-header form as a synthetic anchor.
//!
//! ## Fork-aware topic dispatch
//!
//! Electra+ renames `beacon_attestation` to carry `SingleAttestation` (EIP-7549).
//! The `fork_str` parameter is threaded into `dispatch_gossip_message` so the
//! correct type is decoded for each fork.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use pharos_fork_choice::{PayloadStatus, Store as FcStore};
use pharos_network::host::{GossipValidator, GossipVerdict};
use pharos_node::host_impl::HostImpl;
use pharos_ssz::{Decode, TreeHash};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::{
    BeaconSpec, MainnetBeaconSpec, MinimalBeaconSpec, RuntimeConfig, altair, capella, deneb,
    fork::ForkSchedule,
    phase0::{
        AttesterSlashing, Checkpoint, ProposerSlashing, Root, SignedAggregateAndProof,
        SignedVoluntaryExit,
        operations::BeaconBlockHeader,
        primitives::{Epoch, Version},
    },
    views::{BeaconBlockView, BeaconStateView},
};
use pharos_utils::Hash256;

use crate::fixture_walker::{
    load_altair_state, load_bellatrix_state, load_capella_state, load_deneb_state,
    load_electra_state, load_fulu_state, load_phase0_state, load_ssz_snappy,
};
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::task::{CaseFn, CaseOutcome, CaseTask};

// ── Custody helpers (fulu only) ─────────────────────────────────────────────

use pharos_stf::fulu::data_columns::{compute_columns_for_custody_group, get_custody_groups};

/// Handlers whose cases are custody helpers (fulu only).
const CUSTODY_HANDLERS: &[&str] = &["compute_columns_for_custody_group", "get_custody_groups"];

/// Prefix shared by all gossip-validator handler directories.
const GOSSIP_PREFIX: &str = "gossip_";

// ── Top-level enumerate_networking ──────────────────────────────────────────

/// Produce one `CaseTask` per `<preset>/<fork>/networking/` case.
///
/// Custody helpers run for real (fulu only). Gossip handlers run through the
/// real `HostImpl<E>` gossip validators for all forks. Unknown handlers fail.
pub fn enumerate_networking(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let base = root.join(preset).join(fork).join("networking");
    if !base.is_dir() {
        return Vec::new();
    }

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    let handlers = match read_dir_sorted(&base) {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    for handler_dir in handlers {
        if !handler_dir.is_dir() {
            continue;
        }
        let handler = dir_name(&handler_dir);

        let suites = match read_dir_sorted(&handler_dir) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for suite_dir in suites {
            if !suite_dir.is_dir() {
                continue;
            }
            let suite_name = dir_name(&suite_dir);
            let cases = match read_dir_sorted(&suite_dir) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for case_dir in cases {
                if !case_dir.is_dir() {
                    continue;
                }
                let case_ordinal = ordinal;
                ordinal += 1;

                let case_name = format!(
                    "{preset}/{fork}/networking/{}/{}/{}",
                    handler,
                    suite_name,
                    dir_name(&case_dir)
                );
                let handler_owned = handler.clone();
                let case_dir_owned = case_dir.clone();

                let run: CaseFn = if CUSTODY_HANDLERS.contains(&handler.as_str()) {
                    let meta_path = case_dir.join("meta.yaml");
                    Box::new(move || {
                        if !meta_path.exists() {
                            return CaseOutcome::Skip;
                        }
                        let text = match std::fs::read_to_string(&meta_path) {
                            Ok(t) => t,
                            Err(e) => {
                                return CaseOutcome::Fail(format!("{case_name}: read error: {e}"));
                            }
                        };
                        let val: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
                            Ok(v) => v,
                            Err(e) => {
                                return CaseOutcome::Fail(format!(
                                    "{case_name}: yaml parse error: {e}"
                                ));
                            }
                        };
                        let result = match handler_owned.as_str() {
                            "get_custody_groups" => {
                                run_get_custody_groups(preset, &case_name, &text, &val)
                            }
                            "compute_columns_for_custody_group" => {
                                run_compute_columns_for_custody_group(preset, &case_name, &val)
                            }
                            _ => unreachable!("checked by CUSTODY_HANDLERS"),
                        };
                        match result {
                            Ok(()) => CaseOutcome::Pass,
                            Err(msg) => CaseOutcome::Fail(msg),
                        }
                    })
                } else if handler.starts_with(GOSSIP_PREFIX) {
                    Box::new(move || run_gossip_case(fork, preset, &case_dir_owned, &case_name))
                } else {
                    let handler_fail = handler.clone();
                    Box::new(move || {
                        CaseOutcome::Fail(format!(
                            "{case_name}: unknown networking handler '{handler_fail}'"
                        ))
                    })
                };

                tasks.push(CaseTask {
                    row_ordinal,
                    case_ordinal,
                    run,
                });
            }
        }
    }

    tasks
}

// ── Gossip case runner ────────────────────────────────────────────────────────

fn run_gossip_case(fork: &str, preset: &str, case_dir: &Path, case_name: &str) -> CaseOutcome {
    match (preset, fork) {
        ("mainnet", "phase0") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "phase0")
        }
        ("minimal", "phase0") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "phase0")
        }
        ("mainnet", "altair") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "altair")
        }
        ("minimal", "altair") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "altair")
        }
        ("mainnet", "bellatrix") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "bellatrix")
        }
        ("minimal", "bellatrix") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "bellatrix")
        }
        ("mainnet", "capella") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "capella")
        }
        ("minimal", "capella") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "capella")
        }
        ("mainnet", "deneb") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "deneb")
        }
        ("minimal", "deneb") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "deneb")
        }
        ("mainnet", "electra") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "electra")
        }
        ("minimal", "electra") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "electra")
        }
        ("mainnet", "fulu") => {
            run_gossip_case_typed::<MainnetBeaconSpec>(case_dir, case_name, "fulu")
        }
        ("minimal", "fulu") => {
            run_gossip_case_typed::<MinimalBeaconSpec>(case_dir, case_name, "fulu")
        }
        _ => CaseOutcome::Fail(format!(
            "{case_name}: unknown (preset={preset}, fork={fork})"
        )),
    }
}

// ── Meta.yaml parsing ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct GossipMeta {
    topic: String,
    blocks: Vec<GossipBlockEntry>,
    finalized_checkpoint: Option<FinalizedCheckpointOverride>,
    current_time_ms: u64,
    messages: Vec<GossipMessage>,
}

#[derive(Debug)]
struct GossipBlockEntry {
    block: String,
    /// `failed: true` means the block failed consensus validation (goes into
    /// `invalid_block_roots` so descendant-block step 1 fires correctly).
    failed: bool,
    /// Optional execution-layer payload status string from the fixture meta:
    /// `VALID`, `INVALIDATED`, `NOT_VALIDATED`, `SYNCING`.
    payload_status: Option<String>,
}

#[derive(Debug)]
struct FinalizedCheckpointOverride {
    epoch: u64,
    root: Option<Root>,
}

#[derive(Debug)]
struct GossipMessage {
    offset_ms: u64,
    subnet_id: Option<u64>,
    message: String,
    expected: GossipExpected,
}

#[derive(Debug, PartialEq, Eq)]
enum GossipExpected {
    Valid,
    Ignore,
    Reject,
}

fn parse_gossip_meta(yaml: &serde_yaml_ng::Value, case_name: &str) -> Result<GossipMeta, String> {
    let topic = yaml
        .get("topic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{case_name}: missing topic"))?
        .to_string();

    let mut blocks = Vec::new();
    if let Some(block_list) = yaml.get("blocks").and_then(|v| v.as_sequence()) {
        for entry in block_list {
            let block_name = entry
                .get("block")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("{case_name}: block entry missing 'block' field"))?
                .to_string();
            let failed = entry
                .get("failed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let payload_status = entry
                .get("payload_status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            blocks.push(GossipBlockEntry {
                block: block_name,
                failed,
                payload_status,
            });
        }
    }

    let finalized_checkpoint = if let Some(fc_yaml) = yaml.get("finalized_checkpoint") {
        let epoch = fc_yaml
            .get("epoch")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{case_name}: finalized_checkpoint missing epoch"))?;
        // The root may come from either a `root: 0x...` hex field OR a
        // `block: block_0x<hex>...` filename field (both appear in fixtures).
        let root = fc_yaml
            .get("root")
            .and_then(|v| v.as_str())
            .and_then(|s| {
                let hex = s.trim_start_matches("0x");
                let bytes = hex::decode(hex).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(Root::from_array(arr))
                } else {
                    None
                }
            })
            .or_else(|| {
                // `block: block_0x<hex>` form: strip the "block_0x" prefix.
                fc_yaml.get("block").and_then(|v| v.as_str()).and_then(|s| {
                    let hex = s.trim_start_matches("block_").trim_start_matches("0x");
                    let bytes = hex::decode(hex).ok()?;
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(Root::from_array(arr))
                    } else {
                        None
                    }
                })
            });
        Some(FinalizedCheckpointOverride { epoch, root })
    } else {
        None
    };

    // `current_time_ms` is absent for time-independent topics (attester_slashing,
    // proposer_slashing, voluntary_exit). Default to 0 in that case.
    let current_time_ms = yaml
        .get("current_time_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let msg_list = yaml
        .get("messages")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| format!("{case_name}: missing messages list"))?;

    let mut messages = Vec::new();
    for msg_yaml in msg_list {
        // `offset_ms` is absent for time-independent topics; default to 0.
        let offset_ms = msg_yaml
            .get("offset_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let subnet_id = msg_yaml.get("subnet_id").and_then(|v| v.as_u64());
        let message = msg_yaml
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{case_name}: message missing 'message' field"))?
            .to_string();
        let expected_str = msg_yaml
            .get("expected")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{case_name}: message missing 'expected'"))?;
        let expected = match expected_str {
            "valid" => GossipExpected::Valid,
            "ignore" => GossipExpected::Ignore,
            "reject" => GossipExpected::Reject,
            other => {
                return Err(format!("{case_name}: unknown expected value '{other}'"));
            }
        };
        messages.push(GossipMessage {
            offset_ms,
            subnet_id,
            message,
            expected,
        });
    }

    Ok(GossipMeta {
        topic,
        blocks,
        finalized_checkpoint,
        current_time_ms,
        messages,
    })
}

// ── Build ForkSchedule for a fixture fork ────────────────────────────────────

/// Build a `ForkSchedule` for the given fork name.
///
/// Sets all fork epochs at or before `fork_str` to 0 (active from genesis)
/// and all later fork epochs to `u64::MAX` (inactive). Fork versions use the
/// preset-appropriate values from the default `RuntimeConfig`.
fn fork_schedule_for<E: BeaconSpec>(fork_str: &str) -> ForkSchedule {
    let cfg = E::default_runtime_config();
    let genesis_v = Version::from_array(cfg.genesis_fork_version);
    let altair_v = Version::from_array(cfg.altair_fork_version);
    let bellatrix_v = Version::from_array(cfg.bellatrix_fork_version);
    let capella_v = Version::from_array(cfg.capella_fork_version);
    let deneb_v = Version::from_array(cfg.deneb_fork_version);
    let electra_v = Version::from_array(cfg.electra_fork_version);
    let fulu_v = Version::from_array(cfg.fulu_fork_version);

    let (altair_e, bellatrix_e, capella_e, deneb_e, electra_e, fulu_e) = match fork_str {
        "phase0" => (u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        "altair" => (0, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        "bellatrix" => (0, 0, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        "capella" => (0, 0, 0, u64::MAX, u64::MAX, u64::MAX),
        "deneb" => (0, 0, 0, 0, u64::MAX, u64::MAX),
        "electra" => (0, 0, 0, 0, 0, u64::MAX),
        "fulu" => (0, 0, 0, 0, 0, 0),
        other => unreachable!("unexpected fork: {other}"),
    };

    ForkSchedule {
        genesis_fork_version: genesis_v,
        altair_fork_version: altair_v,
        altair_fork_epoch: Epoch(altair_e),
        bellatrix_fork_version: bellatrix_v,
        bellatrix_fork_epoch: Epoch(bellatrix_e),
        capella_fork_version: capella_v,
        capella_fork_epoch: Epoch(capella_e),
        deneb_fork_version: deneb_v,
        deneb_fork_epoch: Epoch(deneb_e),
        electra_fork_version: electra_v,
        electra_fork_epoch: Epoch(electra_e),
        fulu_fork_version: fulu_v,
        fulu_fork_epoch: Epoch(fulu_e),
        blob_schedule: Vec::new(),
        genesis_validators_root: Root::default(),
    }
}

// ── Fork-schedule override from config.yaml ──────────────────────────────────

/// Apply fork-epoch overrides from a fixture `config.yaml` to `sched`.
///
/// Some fixtures (e.g. `gossip_bls_to_execution_change__ignore_pre_capella`)
/// set `CAPELLA_FORK_EPOCH: 1` so that the fixture state (at epoch 0) is
/// pre-capella even though the fixture lives under `capella/networking/`. The
/// runner's default `fork_schedule_for` would set `capella_epoch = 0`, making
/// the check trivially pass. Reading the fixture's own `config.yaml` gives the
/// correct epoch so the pre-capella IGNORE fires.
///
/// Only the keys that exist in `config.yaml` are overridden; absent keys keep
/// the value from `fork_schedule_for`.
fn apply_config_yaml_overrides(sched: &mut ForkSchedule, case_dir: &Path) {
    let config_path = case_dir.join("config.yaml");
    if !config_path.exists() {
        return;
    }
    let text = match std::fs::read_to_string(&config_path) {
        Ok(t) => t,
        Err(_) => return,
    };
    // serde_yaml_ng fails on mainnet config.yaml because `TERMINAL_TOTAL_DIFFICULTY:
    // 58750000000000000000000` is larger than u128 (the crate errors with "invalid
    // type: integer X as u128, expected any YAML value"). Use a line scanner: for each
    // `KEY: VALUE` line where KEY is one of the fork-epoch keys, parse the u64 directly.
    for line in text.lines() {
        let line = line.trim();
        // Extract `key: value` pairs for fork epoch fields only.
        let Some((key, val_str)) = line.split_once(':') else {
            continue;
        };
        let Ok(epoch_val) = val_str.trim().parse::<u64>() else {
            continue;
        };
        match key.trim() {
            "ALTAIR_FORK_EPOCH" => sched.altair_fork_epoch = Epoch(epoch_val),
            "BELLATRIX_FORK_EPOCH" => sched.bellatrix_fork_epoch = Epoch(epoch_val),
            "CAPELLA_FORK_EPOCH" => sched.capella_fork_epoch = Epoch(epoch_val),
            "DENEB_FORK_EPOCH" => sched.deneb_fork_epoch = Epoch(epoch_val),
            "ELECTRA_FORK_EPOCH" => sched.electra_fork_epoch = Epoch(epoch_val),
            "FULU_FORK_EPOCH" => sched.fulu_fork_epoch = Epoch(epoch_val),
            _ => {}
        }
    }
}

// ── Anchor root derivation ────────────────────────────────────────────────────

/// Compute the block root of the latest block header from the fixture state.
///
/// The spec zeroes `state_root` in `latest_block_header` during `process_block`
/// before hashing; so the signed block root IS `hash_tree_root(header_with_zero_state_root)`.
fn anchor_root_from_state_header(hdr: &BeaconBlockHeader) -> Root {
    let zeroed = BeaconBlockHeader {
        slot: hdr.slot,
        proposer_index: hdr.proposer_index,
        parent_root: hdr.parent_root,
        state_root: Root::default(),
        body_root: hdr.body_root,
    };
    zeroed.tree_hash_root()
}

// ── Load fixture state ────────────────────────────────────────────────────────

fn load_fixture_state<E: BeaconSpec>(
    case_dir: &Path,
    fork: &str,
) -> Result<E::BeaconState, String> {
    match fork {
        "phase0" => load_phase0_state::<E>(case_dir, "state.ssz_snappy"),
        "altair" => load_altair_state::<E>(case_dir, "state.ssz_snappy"),
        "bellatrix" => load_bellatrix_state::<E>(case_dir, "state.ssz_snappy"),
        "capella" => load_capella_state::<E>(case_dir, "state.ssz_snappy"),
        "deneb" => load_deneb_state::<E>(case_dir, "state.ssz_snappy"),
        "electra" => load_electra_state::<E>(case_dir, "state.ssz_snappy"),
        "fulu" => load_fulu_state::<E>(case_dir, "state.ssz_snappy"),
        other => Err(format!("unknown fork for state load: {other}")),
    }
}

// ── Load a signed block for a specific fork ───────────────────────────────────

/// Decode `<file>.ssz_snappy` as `E::SignedBeaconBlock`, trying the type for
/// `fork_str` first before falling back to `load_signed_block_any_fork`.
///
/// This prevents electra fixture blocks from being decoded as the fulu variant
/// (since `FuluSignedBeaconBlock = ElectraSignedBeaconBlock` as a type alias).
fn load_signed_block_for_fork<E: BeaconSpec>(
    case_dir: &Path,
    file: &str,
    fork_str: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::FuluSignedBeaconBlock: Decode,
    E::ElectraSignedBeaconBlock: Decode,
    E::DenebSignedBeaconBlock: Decode,
    E::CapellaSignedBeaconBlock: Decode,
    E::BellatrixSignedBeaconBlock: Decode,
    E::AltairSignedBeaconBlock: Decode,
    E::Phase0SignedBeaconBlock: Decode,
{
    let name = format!("{file}.ssz_snappy");
    // Try the fork-specific type first.
    match fork_str {
        "fulu" => {
            if let Ok(b) = load_ssz_snappy::<E::FuluSignedBeaconBlock>(case_dir, &name) {
                return Ok(E::fulu_into_signed_block(b));
            }
        }
        "electra" => {
            if let Ok(b) = load_ssz_snappy::<E::ElectraSignedBeaconBlock>(case_dir, &name) {
                return Ok(E::electra_into_signed_block(b));
            }
        }
        "deneb" => {
            if let Ok(b) = load_ssz_snappy::<E::DenebSignedBeaconBlock>(case_dir, &name) {
                return Ok(E::deneb_into_signed_block(b));
            }
        }
        "capella" => {
            if let Ok(b) = load_ssz_snappy::<E::CapellaSignedBeaconBlock>(case_dir, &name) {
                return Ok(E::capella_into_signed_block(b));
            }
        }
        "bellatrix" => {
            if let Ok(b) = load_ssz_snappy::<E::BellatrixSignedBeaconBlock>(case_dir, &name) {
                return Ok(E::bellatrix_into_signed_block(b));
            }
        }
        "altair" => {
            if let Ok(b) = load_ssz_snappy::<E::AltairSignedBeaconBlock>(case_dir, &name) {
                return Ok(E::altair_into_signed_block(b));
            }
        }
        _ => {
            if let Ok(b) = load_ssz_snappy::<E::Phase0SignedBeaconBlock>(case_dir, &name) {
                return Ok(E::phase0_into_signed_block(b));
            }
        }
    }
    // Fall back to any-fork probe (catches cross-fork pre-blocks, future forks, etc.)
    load_signed_block_any_fork::<E>(case_dir, file)
}

// ── Load a signed block any-fork ─────────────────────────────────────────────

/// Try to decode `<file>.ssz_snappy` as `E::SignedBeaconBlock`, attempting
/// all fork variants from newest to oldest.
fn load_signed_block_any_fork<E: BeaconSpec>(
    case_dir: &Path,
    file: &str,
) -> Result<E::SignedBeaconBlock, String>
where
    E::FuluSignedBeaconBlock: Decode,
    E::ElectraSignedBeaconBlock: Decode,
    E::DenebSignedBeaconBlock: Decode,
    E::CapellaSignedBeaconBlock: Decode,
    E::BellatrixSignedBeaconBlock: Decode,
    E::AltairSignedBeaconBlock: Decode,
    E::Phase0SignedBeaconBlock: Decode,
{
    let name = format!("{file}.ssz_snappy");
    if let Ok(b) = load_ssz_snappy::<E::FuluSignedBeaconBlock>(case_dir, &name) {
        return Ok(E::fulu_into_signed_block(b));
    }
    if let Ok(b) = load_ssz_snappy::<E::ElectraSignedBeaconBlock>(case_dir, &name) {
        return Ok(E::electra_into_signed_block(b));
    }
    if let Ok(b) = load_ssz_snappy::<E::DenebSignedBeaconBlock>(case_dir, &name) {
        return Ok(E::deneb_into_signed_block(b));
    }
    if let Ok(b) = load_ssz_snappy::<E::CapellaSignedBeaconBlock>(case_dir, &name) {
        return Ok(E::capella_into_signed_block(b));
    }
    if let Ok(b) = load_ssz_snappy::<E::BellatrixSignedBeaconBlock>(case_dir, &name) {
        return Ok(E::bellatrix_into_signed_block(b));
    }
    if let Ok(b) = load_ssz_snappy::<E::AltairSignedBeaconBlock>(case_dir, &name) {
        return Ok(E::altair_into_signed_block(b));
    }
    if let Ok(b) = load_ssz_snappy::<E::Phase0SignedBeaconBlock>(case_dir, &name) {
        return Ok(E::phase0_into_signed_block(b));
    }
    Err(format!(
        "could not decode block '{file}' for any fork variant"
    ))
}

// ── Typed gossip case runner ──────────────────────────────────────────────────

/// Run a gossip validation case for preset `E` and fixture fork `fork_str`.
///
/// The where-clause replicates the bounds from `impl GossipValidator<E> for HostImpl<E>`
/// in host_impl.rs, plus the `Decode` bounds needed for block + contrib loading.
fn run_gossip_case_typed<E: BeaconSpec>(
    case_dir: &Path,
    case_name: &str,
    fork_str: &str,
) -> CaseOutcome
where
    E::BeaconBlock: BeaconBlockView,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite
        + pharos_ssz::TreeHash
        + BeaconStateView
        + Clone,
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState:
        pharos_stf::CapellaProcessSlotsDispatch<E> + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState:
        pharos_stf::DenebProcessSlotsDispatch<E> + pharos_stf::DenebUpgradeDispatch<E>,
    E::ElectraBeaconState:
        pharos_stf::ElectraProcessSlotsDispatch<E> + pharos_stf::ElectraUpgradeDispatch<E>,
    E::FuluBeaconState: pharos_stf::FuluProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
    E::Phase0SignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock> + Decode,
    E::AltairSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock> + Decode,
    E::BellatrixSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock> + Decode,
    E::AltairSignedContributionAndProof: pharos_types::SignedContributionAndProofView + Decode,
    E::FuluSignedBeaconBlock: Decode,
    E::ElectraSignedBeaconBlock: Decode,
    E::DenebSignedBeaconBlock: Decode,
    E::CapellaSignedBeaconBlock: Decode,
{
    // ── Parse meta.yaml ──────────────────────────────────────────────────────
    let meta_path = case_dir.join("meta.yaml");
    let meta_text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) => return CaseOutcome::Fail(format!("{case_name}: meta.yaml read: {e}")),
    };
    let meta_yaml: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&meta_text) {
        Ok(v) => v,
        Err(e) => return CaseOutcome::Fail(format!("{case_name}: meta.yaml parse: {e}")),
    };
    let meta = match parse_gossip_meta(&meta_yaml, case_name) {
        Ok(m) => m,
        Err(e) => return CaseOutcome::Fail(e),
    };

    // ── Load fixture state ───────────────────────────────────────────────────
    let state = match load_fixture_state::<E>(case_dir, fork_str) {
        Ok(s) => s,
        Err(e) => return CaseOutcome::Fail(format!("{case_name}: state load: {e}")),
    };

    let genesis_time = state.genesis_time();

    // ── Load pre-blocks into fc.blocks (no STF) ───────────────────────────────
    //
    // We track the ACTUAL block root of the last valid pre-block, not the
    // zeroed-state_root form from `anchor_root_from_state_header`.  The gossip
    // validators look up `fc.block_states[parent_root]` where `parent_root` is
    // the actual block root (= `block_msg.tree_hash_root()` including real state_root).
    // Using the zeroed form would produce a different hash and miss the lookup.
    let mut failed_block_roots: Vec<Root> = Vec::new();
    let mut fc_blocks: HashMap<Root, E::BeaconBlock> = HashMap::new();
    let mut fc_payload_statuses: HashMap<Root, PayloadStatus> = HashMap::new();
    let mut last_valid_block_root: Option<Root> = None;
    // Non-failed pre-block roots (including EL-invalid ones): need a state entry.
    let mut non_failed_block_roots: Vec<Root> = Vec::new();
    // The `parent_root` of the very first pre-block = the block root of the block
    // BEFORE any pre-blocks. This is what `get_ancestor` returns when walking back
    // through all pre-blocks. It is the ACTUAL block root (including real state_root
    // in the block header), NOT the zeroed-header form from `latest_block_header`.
    let mut first_pre_block_parent: Option<Root> = None;

    for entry in &meta.blocks {
        let signed_block = match load_signed_block_any_fork::<E>(case_dir, &entry.block) {
            Ok(b) => b,
            Err(e) => {
                return CaseOutcome::Fail(format!("{case_name}: pre-block load error: {e}"));
            }
        };

        let block_msg = E::signed_block_message(&signed_block);
        let block_root = block_msg.tree_hash_root();

        // Capture parent root of the first pre-block: this is the "state anchor"
        // (the block root before any pre-blocks) that `get_ancestor` terminates at.
        if first_pre_block_parent.is_none() {
            first_pre_block_parent = Some(block_msg.parent_root());
        }

        // Only insert NON-failed blocks into fc_blocks.
        // Failed (consensus-failed) blocks are kept out of the LMD-GHOST tree so
        // that `get_head` always resolves to a root that has a state entry.
        // The failed block root is registered in `host.invalid_block_roots` below,
        // which is the authoritative "seen but failed" marker used by the pre-step
        // in `validate_attestation` / `validate_aggregate_and_proof` / etc. to
        // produce the correct REJECT verdict without needing fc.blocks.
        if !entry.failed {
            fc_blocks.insert(block_root, block_msg.clone());
        }

        // Map `payload_status` string to `PayloadStatus` enum.
        //
        // The spec initialises `parent_payload_status = NOT_VALIDATED` and only
        // overrides it when the block root is in `block_payload_statuses`. So:
        //   - absent `payload_status` field → `NOT_VALIDATED` (EL has not been called)
        //   - `VALID`       → `Valid`
        //   - `INVALIDATED` → `Invalid`
        //   - `NOT_VALIDATED` / `SYNCING` → `NotValidated`
        //
        // Failed blocks (`failed: true`) also use their `payload_status` value
        // directly so that step 1 of `validate_beacon_block` correctly returns
        // REJECT (NotValidated → unknown EL result) or IGNORE (Valid/Invalid →
        // EL result known) per the spec.
        let ps = match entry.payload_status.as_deref() {
            Some("VALID") => PayloadStatus::Valid,
            Some("INVALIDATED") => PayloadStatus::Invalid,
            Some("NOT_VALIDATED") | Some("SYNCING") => PayloadStatus::NotValidated,
            // No explicit payload_status ≡ block never submitted to the EL.
            None => PayloadStatus::NotValidated,
            _ => PayloadStatus::NotValidated,
        };

        // A block with `failed: true` failed consensus validation:
        //   - NOT inserted into `fc_block_states` (no state for consensus failures)
        //   - Added to `failed_block_roots` → goes into `host.invalid_block_roots`
        //   - `payload_status` kept as-is so step 1 of `validate_beacon_block`
        //     correctly returns REJECT (NotValidated) or IGNORE (Valid/Invalid).
        //
        // A block without `failed` (including `payload_status: INVALIDATED` blocks)
        // passed consensus validation:
        //   - Added to `non_failed_block_roots` so we can insert a state after
        //     `anchor_root` is computed.
        //   - `last_valid_block_root` updated (used as anchor_root).
        //
        // `payload_status: INVALIDATED` without `failed: true` = block passed
        // consensus but the EL returned INVALID. The child should IGNORE (EL-invalid
        // parent, not consensus-failed), handled by the updated step 7 in host_impl.
        if entry.failed {
            failed_block_roots.push(block_root);
        } else {
            last_valid_block_root = Some(block_root);
            non_failed_block_roots.push(block_root);
        }

        fc_payload_statuses.insert(block_root, ps);
    }

    // Two distinct "anchor" concepts:
    //
    // `state_anchor_root` — the block root BEFORE any pre-blocks. Computed as:
    //   - `first_pre_block.parent_root` when pre-blocks exist (the ACTUAL block root,
    //     including real state_root in the header — NOT the zeroed-header form)
    //   - `anchor_root_from_state_header(state.latest_block_header())` as fallback
    //     when no pre-blocks exist (for topics without beacon_block checks, e.g.
    //     voluntary_exit; the finalized-ancestor check doesn't apply there).
    //
    // `head_anchor_root` — the root to use for `justified_checkpoint.root` and
    //   `fc_block_states`. This is the last valid (non-failed) pre-block root,
    //   so `effective_base` → `get_head` returns a root with a known state.
    //   Falls back to `state_anchor_root` when no pre-blocks exist.
    //
    // `finalized_root` — the block root that `get_ancestor` returns when asked
    //   for the finalized epoch boundary. Computed by walking backward from
    //   `head_anchor_root` through `fc_blocks` until a block with
    //   `slot ≤ finalized_epoch_start_slot`. This must equal
    //   `finalized_checkpoint.root` for step 9 of `validate_beacon_block` to pass.
    //
    //   For genesis-epoch fixtures (`finalized_epoch = 0`, the anchor block is at
    //   slot 0): `get_ancestor(store, head_anchor_root, 0)` returns `head_anchor_root`
    //   directly (slot 0 ≤ 0). So `finalized_root = head_anchor_root`. The previous
    //   approach of using `first_pre_block.parent_root` (which is zero for a genesis
    //   block) produced a mismatch, causing 17 "finalized not ancestor" failures.
    let state_anchor_root = first_pre_block_parent
        .unwrap_or_else(|| anchor_root_from_state_header(state.latest_block_header()));
    let head_anchor_root = last_valid_block_root.unwrap_or(state_anchor_root);

    // ── Build fork-choice store ──────────────────────────────────────────────
    let seconds_per_slot = E::SLOT_DURATION_MS / 1000;
    let fc_time = genesis_time + state.slot().0 * seconds_per_slot;

    // Compute `finalized_root` by walking backward from `head_anchor_root`
    // through `fc_blocks` until a block with `slot ≤ finalized_epoch_start_slot`.
    // This mirrors what `get_ancestor` returns and must equal `finalized_checkpoint.root`.
    let finalized_epoch_start_slot = state
        .finalized_checkpoint()
        .epoch
        .0
        .saturating_mul(E::SLOTS_PER_EPOCH);
    let finalized_root = {
        let mut cur = head_anchor_root;
        loop {
            match fc_blocks.get(&cur) {
                Some(b) if b.slot().0 > finalized_epoch_start_slot => {
                    cur = b.parent_root();
                }
                _ => break cur,
            }
        }
    };

    // `finalized_checkpoint`: epoch from state, root = `finalized_root`.
    //   The meta override (for `ignore_slot_not_greater_than_finalized` etc.) can
    //   raise the epoch; if the override also provides an explicit root, use it.
    let finalized = if let Some(ov) = &meta.finalized_checkpoint {
        let root = ov.root.unwrap_or(finalized_root);
        Checkpoint {
            epoch: Epoch(ov.epoch),
            root,
        }
    } else {
        Checkpoint {
            epoch: state.finalized_checkpoint().epoch,
            root: finalized_root,
        }
    };

    // `justified_checkpoint`: epoch from state, root = `head_anchor_root`.
    //   `effective_base` needs `justified_checkpoint.root` to be in `fc.blocks`
    //   so it doesn't fall back to `finalized_checkpoint.root`. The last valid
    //   pre-block is in `fc.blocks`; the state anchor (before pre-blocks) is not.
    let justified_epoch = state.current_justified_checkpoint().epoch;
    let justified = Checkpoint {
        epoch: justified_epoch,
        root: head_anchor_root,
    };

    let mut fc_block_states: HashMap<Root, E::BeaconState> = HashMap::new();
    let mut fc_checkpoint_states: HashMap<Checkpoint, E::BeaconState> = HashMap::new();
    let mut fc_unrealized_justifications: HashMap<Root, Checkpoint> = HashMap::new();

    // Seed `fc_block_states` at every root that `get_head` might return.
    //
    // Failed (consensus-failed) blocks are NOT in `fc_blocks`, so `get_head`
    // can only land on non-failed pre-block roots or the synthetic anchor roots.
    // We seed the state at all of those so that `lookup_or_compute_committee` and
    // `get_state_at_slot` can always resolve the head root to a state.
    //
    // NOTE: we deliberately do NOT seed failed block roots in `fc_block_states`.
    // Steps 10/11 of the attestation validators (fc.block_states.contains_key)
    // must remain absent for consensus-failed blocks so that any attestation voting
    // for a known-but-failed block hits the pre-step `invalid_block_roots` REJECT
    // path (not a stale Accept from a seeded entry).
    fc_block_states.insert(head_anchor_root, state.clone());
    fc_block_states.insert(state_anchor_root, state.clone());
    fc_block_states.insert(finalized_root, state.clone());
    // Catch-all for genesis-epoch states where finalized_checkpoint.root == ZERO.
    fc_block_states.insert(Root::default(), state.clone());
    // Seed state at all non-failed pre-block roots.
    for &root in &non_failed_block_roots {
        fc_block_states.insert(root, state.clone());
    }
    fc_checkpoint_states.insert(justified.clone(), state.clone());
    fc_unrealized_justifications.insert(head_anchor_root, justified.clone());
    // Use `entry().or_insert()` to avoid overwriting the pre-block loop's payload_status.
    // The pre-block loop sets the correct status per the fixture (e.g. `Invalid` for
    // `payload_status: INVALIDATED`). The forced `Valid` here is only a fallback for
    // synthetic anchor roots (no-pre-block cases where no status was set).
    fc_payload_statuses
        .entry(head_anchor_root)
        .or_insert(PayloadStatus::Valid);
    fc_payload_statuses
        .entry(state_anchor_root)
        .or_insert(PayloadStatus::Valid);

    let fc = FcStore::<E> {
        time: fc_time,
        genesis_time,
        justified_checkpoint: justified.clone(),
        finalized_checkpoint: finalized.clone(),
        unrealized_justified_checkpoint: justified,
        unrealized_finalized_checkpoint: finalized,
        proposer_boost_root: Root::default(),
        equivocating_indices: HashSet::new(),
        blocks: fc_blocks,
        block_states: fc_block_states,
        block_timeliness: HashMap::new(),
        checkpoint_states: fc_checkpoint_states,
        latest_messages: HashMap::new(),
        unrealized_justifications: fc_unrealized_justifications,
        payload_statuses: fc_payload_statuses,
        terminal_total_difficulty: pharos_utils::Uint256::ZERO,
        terminal_block_hash: Hash256::default(),
        terminal_block_hash_activation_epoch: u64::MAX,
        altair_fork_epoch: u64::MAX,
        bellatrix_fork_epoch: u64::MAX,
        capella_fork_epoch: u64::MAX,
        runtime_cfg: RuntimeConfig {
            seconds_per_slot,
            ..RuntimeConfig::default()
        },
    };

    // ── Build HostImpl ───────────────────────────────────────────────────────
    let tmp_dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(e) => return CaseOutcome::Fail(format!("{case_name}: tempdir: {e}")),
    };
    let store = match RocksStore::open::<E>(RocksStoreConfig {
        path: tmp_dir.path().join("db"),
        create_if_missing: true,
    }) {
        Ok(s) => Arc::new(s),
        Err(e) => return CaseOutcome::Fail(format!("{case_name}: RocksStore: {e}")),
    };

    let mut fork_schedule = fork_schedule_for::<E>(fork_str);
    apply_config_yaml_overrides(&mut fork_schedule, case_dir);
    let fork_choice = Arc::new(RwLock::new(fc));

    let runtime_cfg = Arc::new(RuntimeConfig {
        seconds_per_slot,
        ..RuntimeConfig::default()
    });

    // Use the fixture state's genesis_validators_root so that fork-agnostic
    // domains (DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_VOLUNTARY_EXIT, etc.)
    // are computed with the same value that was used for signing in the fixture.
    // Passing Root::default() (zeros) breaks all signature checks that incorporate
    // genesis_validators_root in the domain.
    use pharos_types::views::BeaconStateView as _;
    let genesis_validators_root = state.genesis_validators_root();

    let mut host = HostImpl::<E>::new(
        store,
        fork_choice,
        genesis_validators_root,
        fork_schedule,
        genesis_time,
        runtime_cfg,
    );

    // Register failed pre-block roots in the host's invalid-roots LRU cache.
    // `validate_beacon_block` step 1 checks this cache (not fc.payload_statuses).
    for root in &failed_block_roots {
        host.register_invalid_block_root(*root);
    }

    // Install the injectable clock override.
    let clock_arc = Arc::new(AtomicU64::new(0));
    host.now_ms_override = Some(Arc::clone(&clock_arc));

    // ── Run messages in fixture order (seen-caches carry across messages) ─────
    for msg in &meta.messages {
        // Clock = genesis_time (s) × 1000 + current_time_ms + offset_ms.
        let abs_now_ms = genesis_time
            .saturating_mul(1000)
            .saturating_add(meta.current_time_ms)
            .saturating_add(msg.offset_ms);
        clock_arc.store(abs_now_ms, Ordering::Relaxed);

        let verdict = match dispatch_gossip_message::<E>(
            &host,
            case_dir,
            &meta.topic,
            &msg.message,
            msg.subnet_id,
            case_name,
            fork_str,
        ) {
            Ok(v) => v,
            Err(e) => return CaseOutcome::Fail(e),
        };

        let outcome_str = match &verdict {
            GossipVerdict::Accept => "valid",
            GossipVerdict::Ignore(_) => "ignore",
            GossipVerdict::Reject(_) => "reject",
        };
        let expected_str = match msg.expected {
            GossipExpected::Valid => "valid",
            GossipExpected::Ignore => "ignore",
            GossipExpected::Reject => "reject",
        };

        if outcome_str != expected_str {
            return CaseOutcome::Fail(format!(
                "{case_name}: message '{}': expected {expected_str}, got {outcome_str} ({verdict:?})",
                msg.message,
            ));
        }
    }

    CaseOutcome::Pass
}

// ── Gossip message dispatch ───────────────────────────────────────────────────

fn dispatch_gossip_message<E: BeaconSpec>(
    host: &HostImpl<E>,
    case_dir: &Path,
    topic: &str,
    message_file: &str,
    subnet_id: Option<u64>,
    case_name: &str,
    fork_str: &str,
) -> Result<GossipVerdict, String>
where
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite
        + pharos_ssz::TreeHash
        + BeaconStateView
        + Clone,
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState:
        pharos_stf::CapellaProcessSlotsDispatch<E> + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState:
        pharos_stf::DenebProcessSlotsDispatch<E> + pharos_stf::DenebUpgradeDispatch<E>,
    E::ElectraBeaconState:
        pharos_stf::ElectraProcessSlotsDispatch<E> + pharos_stf::ElectraUpgradeDispatch<E>,
    E::FuluBeaconState: pharos_stf::FuluProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
    E::Phase0SignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock> + Decode,
    E::AltairSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock> + Decode,
    E::BellatrixSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock> + Decode,
    E::AltairSignedContributionAndProof: pharos_types::SignedContributionAndProofView + Decode,
    E::FuluSignedBeaconBlock: Decode,
    E::ElectraSignedBeaconBlock: Decode,
    E::DenebSignedBeaconBlock: Decode,
    E::CapellaSignedBeaconBlock: Decode,
{
    let file_name = format!("{message_file}.ssz_snappy");

    match topic {
        "beacon_block" => {
            // Use fork-aware loading: try the specific fork variant first so that
            // electra blocks are not decoded as the fulu variant.  Since
            // `FuluSignedBeaconBlock = ElectraSignedBeaconBlock` (type alias), a
            // blind fulu-first probe would wrap an electra block in the Fulu enum
            // variant and `E::unwrap_electra_block()` would return None, causing
            // the KZG commitment count check for electra (max 9) to be skipped.
            let block = load_signed_block_for_fork::<E>(case_dir, message_file, fork_str)
                .map_err(|e| format!("{case_name}: block decode: {e}"))?;
            Ok(host.validate_beacon_block(&block))
        }

        "beacon_attestation" => {
            let subnet = subnet_id
                .ok_or_else(|| format!("{case_name}: beacon_attestation missing subnet_id"))?;
            // Electra+ (EIP-7549): the subnet topic carries `SingleAttestation`.
            // Phase0..deneb carry the legacy `Attestation<MAX_VALIDATORS_PER_COMMITTEE>`.
            match fork_str {
                "electra" | "fulu" => {
                    let att = load_ssz_snappy::<pharos_types::electra::SingleAttestation>(
                        case_dir, &file_name,
                    )
                    .map_err(|e| format!("{case_name}: single_attestation decode: {e}"))?;
                    Ok(host.validate_single_attestation(subnet, &att))
                }
                _ => {
                    let att = load_ssz_snappy::<pharos_types::phase0::Attestation<2048>>(
                        case_dir, &file_name,
                    )
                    .map_err(|e| format!("{case_name}: attestation decode: {e}"))?;
                    Ok(host.validate_attestation(subnet, &att))
                }
            }
        }

        "beacon_aggregate_and_proof" => {
            // Electra (EIP-7549): use the electra aggregate type (committee_bits field).
            // Phase0..deneb: use the legacy SignedAggregateAndProof<2048>.
            match fork_str {
                "electra" | "fulu" => {
                    let agg =
                        load_ssz_snappy::<E::ElectraSignedAggregateAndProof>(case_dir, &file_name)
                            .map_err(|e| format!("{case_name}: electra aggregate decode: {e}"))?;
                    Ok(host.validate_aggregate_and_proof_electra(&agg))
                }
                _ => {
                    let agg =
                        load_ssz_snappy::<SignedAggregateAndProof<2048>>(case_dir, &file_name)
                            .map_err(|e| format!("{case_name}: aggregate decode: {e}"))?;
                    Ok(host.validate_aggregate_and_proof(&agg))
                }
            }
        }

        "voluntary_exit" => {
            let exit = load_ssz_snappy::<SignedVoluntaryExit>(case_dir, &file_name)
                .map_err(|e| format!("{case_name}: voluntary_exit decode: {e}"))?;
            Ok(host.validate_voluntary_exit(&exit))
        }

        "proposer_slashing" => {
            let slashing = load_ssz_snappy::<ProposerSlashing>(case_dir, &file_name)
                .map_err(|e| format!("{case_name}: proposer_slashing decode: {e}"))?;
            Ok(host.validate_proposer_slashing(&slashing))
        }

        "attester_slashing" => {
            let slashing = load_ssz_snappy::<AttesterSlashing<2048>>(case_dir, &file_name)
                .map_err(|e| format!("{case_name}: attester_slashing decode: {e}"))?;
            Ok(host.validate_attester_slashing(&slashing))
        }

        "sync_committee" => {
            let msg = load_ssz_snappy::<altair::SyncCommitteeMessage>(case_dir, &file_name)
                .map_err(|e| format!("{case_name}: sync_committee decode: {e}"))?;
            let subnet = subnet_id
                .ok_or_else(|| format!("{case_name}: sync_committee missing subnet_id"))?;
            Ok(host.validate_sync_committee_message(subnet, &msg))
        }

        "sync_committee_contribution_and_proof" => {
            let contrib =
                load_ssz_snappy::<E::AltairSignedContributionAndProof>(case_dir, &file_name)
                    .map_err(|e| format!("{case_name}: contribution decode: {e}"))?;
            Ok(host.validate_sync_committee_contribution_and_proof(&contrib))
        }

        "bls_to_execution_change" => {
            let change = load_ssz_snappy::<capella::operations::SignedBLSToExecutionChange>(
                case_dir, &file_name,
            )
            .map_err(|e| format!("{case_name}: bls_to_execution_change decode: {e}"))?;
            Ok(host.validate_bls_to_execution_change(&change))
        }

        "blob_sidecar" => {
            let sidecar = load_ssz_snappy::<deneb::BlobSidecar>(case_dir, &file_name)
                .map_err(|e| format!("{case_name}: blob_sidecar decode: {e}"))?;
            let subnet =
                subnet_id.ok_or_else(|| format!("{case_name}: blob_sidecar missing subnet_id"))?;
            Ok(host.validate_blob_sidecar(subnet, &sidecar))
        }

        other => Err(format!("{case_name}: unknown gossip topic '{other}'")),
    }
}

// ── Custody helpers (fulu only) ──────────────────────────────────────────────

fn run_get_custody_groups(
    preset: &'static str,
    case_name: &str,
    raw: &str,
    val: &serde_yaml_ng::Value,
) -> Result<(), String> {
    let node_id = parse_node_id(raw, case_name)?;
    let custody_group_count = val
        .get("custody_group_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{case_name}: missing/invalid custody_group_count"))?;
    let expected = parse_u64_seq(val.get("result"), case_name)?;

    let got = match preset {
        "mainnet" => get_custody_groups::<MainnetBeaconSpec>(node_id, custody_group_count),
        "minimal" => get_custody_groups::<MinimalBeaconSpec>(node_id, custody_group_count),
        other => unreachable!("unexpected preset {other}"),
    };
    if got == expected {
        Ok(())
    } else {
        Err(format!(
            "{case_name}: get_custody_groups mismatch: got {got:?}, want {expected:?}"
        ))
    }
}

fn run_compute_columns_for_custody_group(
    preset: &'static str,
    case_name: &str,
    val: &serde_yaml_ng::Value,
) -> Result<(), String> {
    let custody_group = val
        .get("custody_group")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{case_name}: missing/invalid custody_group"))?;
    let expected = parse_u64_seq(val.get("result"), case_name)?;

    let got = match preset {
        "mainnet" => compute_columns_for_custody_group::<MainnetBeaconSpec>(custody_group),
        "minimal" => compute_columns_for_custody_group::<MinimalBeaconSpec>(custody_group),
        other => unreachable!("unexpected preset {other}"),
    };
    if got == expected {
        Ok(())
    } else {
        Err(format!(
            "{case_name}: compute_columns_for_custody_group mismatch: got {got:?}, want {expected:?}"
        ))
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn parse_node_id(raw: &str, case_name: &str) -> Result<[u8; 32], String> {
    let digits = extract_scalar_digits(raw, "node_id")
        .ok_or_else(|| format!("{case_name}: missing/unreadable node_id"))?;
    decimal_to_be_bytes::<32>(&digits).ok_or_else(|| format!("{case_name}: bad node_id '{digits}'"))
}

fn extract_scalar_digits(raw: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    let start = raw.find(&needle)? + needle.len();
    let rest = &raw[start..];
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn decimal_to_be_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut buf = [0u8; N];
    for ch in s.chars() {
        let digit = ch.to_digit(10)? as u16;
        let mut carry = digit;
        for byte in buf.iter_mut().rev() {
            let acc = (*byte as u16) * 10 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(buf)
}

fn parse_u64_seq(seq: Option<&serde_yaml_ng::Value>, case_name: &str) -> Result<Vec<u64>, String> {
    let seq = seq
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| format!("{case_name}: missing/invalid 'result' sequence"))?;
    seq.iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("{case_name}: result entry is not u64"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_to_be_bytes_small() {
        let b = decimal_to_be_bytes::<32>("1048576").unwrap();
        assert_eq!(b[29], 0x10);
        assert!(b[..29].iter().all(|&x| x == 0));
        assert_eq!(b[30], 0x00);
        assert_eq!(b[31], 0x00);
    }

    #[test]
    fn decimal_to_be_bytes_max_uint256() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let b = decimal_to_be_bytes::<32>(max).unwrap();
        assert!(b.iter().all(|&x| x == 0xff));
    }

    #[test]
    fn parse_gossip_meta_valid_block() {
        let yaml_text = r#"
topic: beacon_block
blocks:
- {block: block_0xabc}
current_time_ms: 6000
messages:
- {offset_ms: 500, message: block_0xdef, expected: valid}
"#;
        let val: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml_text).unwrap();
        let meta = parse_gossip_meta(&val, "test_case").unwrap();
        assert_eq!(meta.topic, "beacon_block");
        assert_eq!(meta.current_time_ms, 6000);
        assert_eq!(meta.messages.len(), 1);
        assert_eq!(meta.messages[0].expected, GossipExpected::Valid);
    }

    #[test]
    fn parse_gossip_meta_unknown_expected_fails() {
        let yaml_text = r#"
topic: beacon_block
current_time_ms: 0
messages:
- {offset_ms: 0, message: block_0xabc, expected: unknown_value}
"#;
        let val: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml_text).unwrap();
        let result = parse_gossip_meta(&val, "test_case");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown expected value"));
    }
}
