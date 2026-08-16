//! Runner for the `ssz_static` test category.
//!
//! Fixture path: `<root>/<preset>/phase0/ssz_static/<TypeName>/<suite>/<case>/`
//!
//! Each case:
//! - Decode `serialized.ssz_snappy` via SSZ.
//! - Check `tree_hash_root` against `roots.yaml`.
//! - Re-encode and assert bytes match original.
//!
//! Dispatch covers all 27 Phase 0 containers (24 from beacon-chain.md + 3 from
//! validator.md) for both `mainnet` and `minimal` presets using the
//! preset-specific type aliases from `pharos-types`.

use std::path::Path;

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_types::altair::{
    ContributionAndProof, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate, SignedContributionAndProof, SyncAggregate,
    SyncAggregatorSelectionData, SyncCommittee, SyncCommitteeContribution, SyncCommitteeMessage,
};
use pharos_types::altair::{
    MainnetBeaconBlock as AltairMainnetBeaconBlock,
    MainnetBeaconBlockBody as AltairMainnetBeaconBlockBody,
    MainnetBeaconState as AltairMainnetBeaconState,
    MainnetSignedBeaconBlock as AltairMainnetSignedBeaconBlock,
};
use pharos_types::altair::{
    MinimalBeaconBlock as AltairMinimalBeaconBlock,
    MinimalBeaconBlockBody as AltairMinimalBeaconBlockBody,
    MinimalBeaconState as AltairMinimalBeaconState,
    MinimalSignedBeaconBlock as AltairMinimalSignedBeaconBlock,
};
use pharos_types::bellatrix::{
    MainnetBeaconBlock as BellatrixMainnetBeaconBlock,
    MainnetBeaconBlockBody as BellatrixMainnetBeaconBlockBody,
    MainnetBeaconState as BellatrixMainnetBeaconState,
    MainnetExecutionPayload as BellatrixMainnetExecutionPayload,
    MainnetExecutionPayloadHeader as BellatrixMainnetExecutionPayloadHeader,
    MainnetSignedBeaconBlock as BellatrixMainnetSignedBeaconBlock,
    MinimalBeaconBlock as BellatrixMinimalBeaconBlock,
    MinimalBeaconBlockBody as BellatrixMinimalBeaconBlockBody,
    MinimalBeaconState as BellatrixMinimalBeaconState,
    MinimalExecutionPayload as BellatrixMinimalExecutionPayload,
    MinimalExecutionPayloadHeader as BellatrixMinimalExecutionPayloadHeader,
    MinimalSignedBeaconBlock as BellatrixMinimalSignedBeaconBlock,
};
use pharos_types::capella::{
    BLSToExecutionChange, HistoricalSummary, MainnetBeaconBlock as CapellaMainnetBeaconBlock,
    MainnetBeaconBlockBody as CapellaMainnetBeaconBlockBody,
    MainnetBeaconState as CapellaMainnetBeaconState,
    MainnetExecutionPayload as CapellaMainnetExecutionPayload,
    MainnetExecutionPayloadHeader as CapellaMainnetExecutionPayloadHeader,
    MainnetSignedBeaconBlock as CapellaMainnetSignedBeaconBlock,
    MinimalBeaconBlock as CapellaMinimalBeaconBlock,
    MinimalBeaconBlockBody as CapellaMinimalBeaconBlockBody,
    MinimalBeaconState as CapellaMinimalBeaconState,
    MinimalExecutionPayload as CapellaMinimalExecutionPayload,
    MinimalExecutionPayloadHeader as CapellaMinimalExecutionPayloadHeader,
    MinimalSignedBeaconBlock as CapellaMinimalSignedBeaconBlock, SignedBLSToExecutionChange,
    Withdrawal,
    light_client::{
        MainnetLightClientBootstrap as CapellaMainnetLCBootstrap,
        MainnetLightClientFinalityUpdate as CapellaMainnetLCFinalityUpdate,
        MainnetLightClientHeader as CapellaMainnetLCHeader,
        MainnetLightClientOptimisticUpdate as CapellaMainnetLCOptimisticUpdate,
        MainnetLightClientUpdate as CapellaMainnetLCUpdate,
        MinimalLightClientBootstrap as CapellaMinimalLCBootstrap,
        MinimalLightClientFinalityUpdate as CapellaMinimalLCFinalityUpdate,
        MinimalLightClientHeader as CapellaMinimalLCHeader,
        MinimalLightClientOptimisticUpdate as CapellaMinimalLCOptimisticUpdate,
        MinimalLightClientUpdate as CapellaMinimalLCUpdate,
    },
};
use pharos_types::phase0::{
    AggregateAndProof, AttestationData, BeaconBlockHeader, Checkpoint, DepositData, DepositMessage,
    Eth1Block, Eth1Data, Fork, ForkData, ProposerSlashing, SignedAggregateAndProof,
    SignedBeaconBlockHeader, SignedVoluntaryExit, SigningData, Validator, VoluntaryExit,
};
use pharos_types::phase0::{
    MainnetAttestation, MainnetAttesterSlashing, MainnetBeaconBlock, MainnetBeaconBlockBody,
    MainnetBeaconState, MainnetDeposit, MainnetHistoricalBatch, MainnetIndexedAttestation,
    MainnetPendingAttestation, MainnetSignedBeaconBlock,
};
use pharos_types::phase0::{
    MinimalAttestation, MinimalAttesterSlashing, MinimalBeaconBlock, MinimalBeaconBlockBody,
    MinimalBeaconState, MinimalDeposit, MinimalHistoricalBatch, MinimalIndexedAttestation,
    MinimalPendingAttestation, MinimalSignedBeaconBlock,
};
use pharos_utils::Hash256;

use crate::error::ConformanceError;
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::snappy::decompress_raw;
use crate::task::{CaseFn, CaseOutcome, CaseTask};
use crate::yaml_util::read_root_from_file;

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per ssz_static case in the same walk-order as the
/// corresponding `run_*_ssz_static_*` function. Called by the Phase 7 flat
/// work-pool.
///
/// `fork` must be one of `"phase0"`, `"altair"`, `"bellatrix"`, `"capella"`,
/// `"deneb"`, or `"electra"`. The walk mirrors the relevant
/// `run_*_ssz_static_*` function exactly: type → suite → case, sorted.
///
/// - `Ok(true)`  → `CaseOutcome::Pass`
/// - `Ok(false)` → `CaseOutcome::Skip`
/// - `Err(e)`    → `CaseOutcome::Fail("`{case_label}`: {e}")`
pub fn enumerate_ssz_static(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    // Resolve the base directory for this (fork, preset) pair, mirroring how
    // lib.rs builds the path for each `run_*` variant.
    let base = match fork {
        "phase0" | "altair" => root.join(preset).join(fork).join("ssz_static"),
        _ => root.join(preset).join(fork).join("ssz_static"),
    };
    if !base.is_dir() {
        return Vec::new();
    }

    let type_dirs = read_dir_sorted(&base).unwrap_or_default();
    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    for type_dir in type_dirs {
        let type_name: String = dir_name(&type_dir);
        let suite_dirs = read_dir_sorted(&type_dir).unwrap_or_default();
        for suite_dir in suite_dirs {
            let suite_name: String = dir_name(&suite_dir);
            let case_dirs = read_dir_sorted(&suite_dir).unwrap_or_default();
            for case_dir in case_dirs {
                let case_name = dir_name(&case_dir);
                let case_label =
                    format!("{preset}/{fork}/ssz_static/{type_name}/{suite_name}/{case_name}");
                let case_ordinal = ordinal;
                ordinal += 1;

                let preset_owned = preset;
                let type_name_owned = type_name.clone();
                let run: CaseFn = Box::new(move || {
                    let result = dispatch_for_fork(
                        fork,
                        preset_owned,
                        &type_name_owned,
                        &case_dir,
                        &case_label,
                    );
                    match result {
                        Ok(true) => CaseOutcome::Pass,
                        Ok(false) => CaseOutcome::Skip,
                        Err(e) => CaseOutcome::Fail(format!("`{case_label}`: {e}")),
                    }
                });
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

/// Route a single case to the correct per-fork dispatch function.
///
/// Reads `serialized.ssz_snappy` + `roots.yaml` and calls the relevant
/// `dispatch_*` function.
fn dispatch_for_fork(
    fork: &str,
    preset: &str,
    type_name: &str,
    case_dir: &std::path::Path,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    let ssz_snappy = case_dir.join("serialized.ssz_snappy");
    if !ssz_snappy.exists() {
        return Ok(false);
    }
    let roots_yaml = case_dir.join("roots.yaml");
    if !roots_yaml.exists() {
        return Ok(false);
    }

    let compressed = std::fs::read(&ssz_snappy)?;
    let ssz_bytes = decompress_raw(&compressed)?;
    let expected_root = read_root_from_file(&roots_yaml)?;

    match fork {
        "phase0" => dispatch(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "altair" => dispatch_altair(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "bellatrix" => {
            dispatch_bellatrix(preset, type_name, &ssz_bytes, &expected_root, case_label)
        }
        "capella" => dispatch_capella(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "deneb" => dispatch_deneb(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "electra" => dispatch_electra(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "fulu" => dispatch_fulu(preset, type_name, &ssz_bytes, &expected_root, case_label),
        _ => {
            eprintln!("enumerate_ssz_static: unknown fork {fork}");
            Ok(false)
        }
    }
}

/// Run all phase0 ssz_static tests for a given preset.
///
/// `preset_dir`: the top-level directory for this preset (e.g. `<root>/mainnet`).
/// Run a single ssz_static case. Returns `Ok(true)` = pass, `Ok(false)` = skip.
/// Core SSZ round-trip + hash assertion for any type.
///
/// Returns `Ok(true)` on success.
fn check<T>(
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError>
where
    T: Encode + Decode + TreeHash,
{
    let value = T::from_ssz_bytes(ssz_bytes)?;
    let got_root = value.tree_hash_root();
    if got_root != *expected_root {
        return Err(ConformanceError::HashTreeRoot {
            case: case_label.into(),
            got: format!("0x{}", hex::encode(got_root.as_ref())),
            want: format!("0x{}", hex::encode(expected_root.as_ref())),
        });
    }
    let re_encoded = value.as_ssz_bytes();
    if re_encoded != ssz_bytes {
        return Err(ConformanceError::EncodeRoundTrip {
            case: case_label.into(),
            got_hex: hex::encode(&re_encoded),
            want_hex: hex::encode(ssz_bytes),
        });
    }
    Ok(true)
}

// ── Dispatch table ────────────────────────────────────────────────────────────

/// Dispatch (preset, type_name) to the correct concrete type and run the check.
///
/// Returns `Ok(true)` = pass, `Ok(false)` = skip (unknown type).
fn dispatch(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => {
            eprintln!("skipping ssz_static for unknown preset: {preset}");
            Ok(false)
        }
    }
}

fn dispatch_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match type_name {
        // Preset-independent types (beacon-chain.md)
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        // Preset-independent types (validator.md)
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Preset-specific types (mainnet, beacon-chain.md)
        "HistoricalBatch" => check::<MainnetHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MainnetPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        "BeaconBlockBody" => check::<MainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label),
        "BeaconBlock" => check::<MainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<MainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<MainnetBeaconState>(ssz_bytes, expected_root, case_label),
        // Preset-specific types (mainnet, validator.md)
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping mainnet/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match type_name {
        // Preset-independent types (beacon-chain.md)
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        // Preset-independent types (validator.md)
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Preset-specific types (minimal, beacon-chain.md)
        "HistoricalBatch" => check::<MinimalHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MinimalPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        "BeaconBlockBody" => check::<MinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label),
        "BeaconBlock" => check::<MinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<MinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<MinimalBeaconState>(ssz_bytes, expected_root, case_label),
        // Preset-specific types (minimal, validator.md)
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping minimal/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_altair(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_altair_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_altair_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Ok(false),
    }
}

fn dispatch_altair_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Preset-specific phase0-inherited types (mainnet)
        "HistoricalBatch" => check::<MainnetHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MainnetPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-specific types (mainnet, SYNC_COMMITTEE_SIZE=512, SYNC_SUBCOMMITTEE_SIZE=128)
        "BeaconBlockBody" => {
            check::<AltairMainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<AltairMainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<AltairMainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<AltairMainnetBeaconState>(ssz_bytes, expected_root, case_label),
        "SyncAggregate" => check::<SyncAggregate<512>>(ssz_bytes, expected_root, case_label),
        "SyncCommittee" => check::<SyncCommittee<512>>(ssz_bytes, expected_root, case_label),
        "SyncCommitteeMessage" => {
            check::<SyncCommitteeMessage>(ssz_bytes, expected_root, case_label)
        }
        "SyncAggregatorSelectionData" => {
            check::<SyncAggregatorSelectionData>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeContribution" => {
            check::<SyncCommitteeContribution<128>>(ssz_bytes, expected_root, case_label)
        }
        "ContributionAndProof" => {
            check::<ContributionAndProof<128>>(ssz_bytes, expected_root, case_label)
        }
        "SignedContributionAndProof" => {
            check::<SignedContributionAndProof<128>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientHeader" => check::<LightClientHeader>(ssz_bytes, expected_root, case_label),
        "LightClientBootstrap" => {
            check::<LightClientBootstrap<512>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            check::<LightClientUpdate<512>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            check::<LightClientFinalityUpdate<512>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            check::<LightClientOptimisticUpdate<512>>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping mainnet/altair/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_altair_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Preset-specific phase0-inherited types (minimal)
        "HistoricalBatch" => check::<MinimalHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MinimalPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-specific types (minimal, SYNC_COMMITTEE_SIZE=32, SYNC_SUBCOMMITTEE_SIZE=8)
        "BeaconBlockBody" => {
            check::<AltairMinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<AltairMinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<AltairMinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<AltairMinimalBeaconState>(ssz_bytes, expected_root, case_label),
        "SyncAggregate" => check::<SyncAggregate<32>>(ssz_bytes, expected_root, case_label),
        "SyncCommittee" => check::<SyncCommittee<32>>(ssz_bytes, expected_root, case_label),
        "SyncCommitteeMessage" => {
            check::<SyncCommitteeMessage>(ssz_bytes, expected_root, case_label)
        }
        "SyncAggregatorSelectionData" => {
            check::<SyncAggregatorSelectionData>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeContribution" => {
            check::<SyncCommitteeContribution<8>>(ssz_bytes, expected_root, case_label)
        }
        "ContributionAndProof" => {
            check::<ContributionAndProof<8>>(ssz_bytes, expected_root, case_label)
        }
        "SignedContributionAndProof" => {
            check::<SignedContributionAndProof<8>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientHeader" => check::<LightClientHeader>(ssz_bytes, expected_root, case_label),
        "LightClientBootstrap" => {
            check::<LightClientBootstrap<32>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => check::<LightClientUpdate<32>>(ssz_bytes, expected_root, case_label),
        "LightClientFinalityUpdate" => {
            check::<LightClientFinalityUpdate<32>>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            check::<LightClientOptimisticUpdate<32>>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping minimal/altair/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_bellatrix(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_bellatrix_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_bellatrix_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Ok(false),
    }
}

fn dispatch_bellatrix_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (mainnet)
        "HistoricalBatch" => check::<MainnetHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MainnetPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-inherited types (mainnet)
        "SyncAggregate" => check::<SyncAggregate<512>>(ssz_bytes, expected_root, case_label),
        "SyncCommittee" => check::<SyncCommittee<512>>(ssz_bytes, expected_root, case_label),
        "SyncCommitteeMessage" => {
            check::<SyncCommitteeMessage>(ssz_bytes, expected_root, case_label)
        }
        "SyncAggregatorSelectionData" => {
            check::<SyncAggregatorSelectionData>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeContribution" => {
            check::<SyncCommitteeContribution<128>>(ssz_bytes, expected_root, case_label)
        }
        "ContributionAndProof" => {
            check::<ContributionAndProof<128>>(ssz_bytes, expected_root, case_label)
        }
        "SignedContributionAndProof" => {
            check::<SignedContributionAndProof<128>>(ssz_bytes, expected_root, case_label)
        }
        // Bellatrix-new types (mainnet)
        "ExecutionPayload" => {
            check::<BellatrixMainnetExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<BellatrixMainnetExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlockBody" => {
            check::<BellatrixMainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<BellatrixMainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<BellatrixMainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<BellatrixMainnetBeaconState>(ssz_bytes, expected_root, case_label),
        _ => {
            eprintln!("skipping mainnet/bellatrix/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_bellatrix_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (minimal)
        "HistoricalBatch" => check::<MinimalHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MinimalPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-inherited types (minimal)
        "SyncAggregate" => check::<SyncAggregate<32>>(ssz_bytes, expected_root, case_label),
        "SyncCommittee" => check::<SyncCommittee<32>>(ssz_bytes, expected_root, case_label),
        "SyncCommitteeMessage" => {
            check::<SyncCommitteeMessage>(ssz_bytes, expected_root, case_label)
        }
        "SyncAggregatorSelectionData" => {
            check::<SyncAggregatorSelectionData>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeContribution" => {
            check::<SyncCommitteeContribution<8>>(ssz_bytes, expected_root, case_label)
        }
        "ContributionAndProof" => {
            check::<ContributionAndProof<8>>(ssz_bytes, expected_root, case_label)
        }
        "SignedContributionAndProof" => {
            check::<SignedContributionAndProof<8>>(ssz_bytes, expected_root, case_label)
        }
        // Bellatrix-new types (minimal)
        "ExecutionPayload" => {
            check::<BellatrixMinimalExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<BellatrixMinimalExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlockBody" => {
            check::<BellatrixMinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<BellatrixMinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<BellatrixMinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<BellatrixMinimalBeaconState>(ssz_bytes, expected_root, case_label),
        _ => {
            eprintln!("skipping minimal/bellatrix/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_capella(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_capella_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_capella_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Ok(false),
    }
}

fn dispatch_capella_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::phase0::{AggregateAndProof, SignedAggregateAndProof};

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (mainnet)
        "HistoricalBatch" => check::<MainnetHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MainnetPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => {
            check::<pharos_types::altair::SyncCommitteeContribution<128>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<128>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => check::<
            pharos_types::altair::SignedContributionAndProof<128>,
        >(ssz_bytes, expected_root, case_label),
        // Capella-new types (mainnet)
        "Withdrawal" => check::<Withdrawal>(ssz_bytes, expected_root, case_label),
        "BLSToExecutionChange" => {
            check::<BLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "SignedBLSToExecutionChange" => {
            check::<SignedBLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "HistoricalSummary" => check::<HistoricalSummary>(ssz_bytes, expected_root, case_label),
        "ExecutionPayload" => {
            check::<CapellaMainnetExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<CapellaMainnetExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlockBody" => {
            check::<CapellaMainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<CapellaMainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<CapellaMainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<CapellaMainnetBeaconState>(ssz_bytes, expected_root, case_label),
        // Capella LC types (shipped in Phase 5).
        "LightClientHeader" => {
            check::<CapellaMainnetLCHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            check::<CapellaMainnetLCBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            check::<CapellaMainnetLCUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            check::<CapellaMainnetLCFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            check::<CapellaMainnetLCOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping mainnet/capella/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_capella_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::phase0::{AggregateAndProof, SignedAggregateAndProof};

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (minimal)
        "HistoricalBatch" => check::<MinimalHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MinimalPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => check::<pharos_types::altair::SyncCommitteeContribution<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => {
            check::<pharos_types::altair::SignedContributionAndProof<8>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        // Capella-new types (minimal)
        "Withdrawal" => check::<Withdrawal>(ssz_bytes, expected_root, case_label),
        "BLSToExecutionChange" => {
            check::<BLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "SignedBLSToExecutionChange" => {
            check::<SignedBLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "HistoricalSummary" => check::<HistoricalSummary>(ssz_bytes, expected_root, case_label),
        "ExecutionPayload" => {
            check::<CapellaMinimalExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<CapellaMinimalExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlockBody" => {
            check::<CapellaMinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<CapellaMinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<CapellaMinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<CapellaMinimalBeaconState>(ssz_bytes, expected_root, case_label),
        // Capella LC types (shipped in Phase 5).
        "LightClientHeader" => {
            check::<CapellaMinimalLCHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            check::<CapellaMinimalLCBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            check::<CapellaMinimalLCUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            check::<CapellaMinimalLCFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            check::<CapellaMinimalLCOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping minimal/capella/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_deneb(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_deneb_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_deneb_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Ok(false),
    }
}

fn dispatch_deneb_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::deneb::{
        BlobIdentifier, BlobSidecar, MainnetBeaconBlock as DenebMainnetBeaconBlock,
        MainnetBeaconBlockBody as DenebMainnetBeaconBlockBody,
        MainnetBeaconState as DenebMainnetBeaconState,
        MainnetExecutionPayload as DenebMainnetExecutionPayload,
        MainnetExecutionPayloadHeader as DenebMainnetExecutionPayloadHeader,
        MainnetSignedBeaconBlock as DenebMainnetSignedBeaconBlock,
    };
    use pharos_types::phase0::AggregateAndProof;
    use pharos_types::phase0::SignedAggregateAndProof;

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (mainnet)
        "HistoricalBatch" => check::<MainnetHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MainnetPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => {
            check::<pharos_types::altair::SyncCommitteeContribution<128>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<128>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => check::<
            pharos_types::altair::SignedContributionAndProof<128>,
        >(ssz_bytes, expected_root, case_label),
        // Capella-inherited types (mainnet)
        "Withdrawal" => check::<Withdrawal>(ssz_bytes, expected_root, case_label),
        "BLSToExecutionChange" => {
            check::<BLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "SignedBLSToExecutionChange" => {
            check::<SignedBLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "HistoricalSummary" => check::<HistoricalSummary>(ssz_bytes, expected_root, case_label),
        // Deneb-new types (mainnet)
        "BlobIdentifier" => check::<BlobIdentifier>(ssz_bytes, expected_root, case_label),
        "BlobSidecar" => check::<BlobSidecar>(ssz_bytes, expected_root, case_label),
        "ExecutionPayload" => {
            check::<DenebMainnetExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<DenebMainnetExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlockBody" => {
            check::<DenebMainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<DenebMainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<DenebMainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<DenebMainnetBeaconState>(ssz_bytes, expected_root, case_label),
        // Deneb LC types (mainnet)
        "LightClientHeader" => {
            use pharos_types::deneb::light_client::MainnetLightClientHeader as DenebMainnetLCHeader;
            check::<DenebMainnetLCHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            use pharos_types::deneb::light_client::MainnetLightClientBootstrap as DenebMainnetLCBootstrap;
            check::<DenebMainnetLCBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            use pharos_types::deneb::light_client::MainnetLightClientUpdate as DenebMainnetLCUpdate;
            check::<DenebMainnetLCUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            use pharos_types::deneb::light_client::MainnetLightClientFinalityUpdate as DenebMainnetLCFinalityUpdate;
            check::<DenebMainnetLCFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            use pharos_types::deneb::light_client::MainnetLightClientOptimisticUpdate as DenebMainnetLCOptimisticUpdate;
            check::<DenebMainnetLCOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping mainnet/deneb/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_deneb_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::deneb::{
        BlobIdentifier, BlobSidecar, MinimalBeaconBlock as DenebMinimalBeaconBlock,
        MinimalBeaconBlockBody as DenebMinimalBeaconBlockBody,
        MinimalBeaconState as DenebMinimalBeaconState,
        MinimalExecutionPayload as DenebMinimalExecutionPayload,
        MinimalExecutionPayloadHeader as DenebMinimalExecutionPayloadHeader,
        MinimalSignedBeaconBlock as DenebMinimalSignedBeaconBlock,
    };
    use pharos_types::phase0::AggregateAndProof;
    use pharos_types::phase0::SignedAggregateAndProof;

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (minimal)
        "HistoricalBatch" => check::<MinimalHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "PendingAttestation" => {
            check::<MinimalPendingAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        "AggregateAndProof" => {
            check::<AggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<SignedAggregateAndProof<2048>>(ssz_bytes, expected_root, case_label)
        }
        // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => check::<pharos_types::altair::SyncCommitteeContribution<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => {
            check::<pharos_types::altair::SignedContributionAndProof<8>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        // Capella-inherited types (minimal)
        "Withdrawal" => check::<Withdrawal>(ssz_bytes, expected_root, case_label),
        "BLSToExecutionChange" => {
            check::<BLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "SignedBLSToExecutionChange" => {
            check::<SignedBLSToExecutionChange>(ssz_bytes, expected_root, case_label)
        }
        "HistoricalSummary" => check::<HistoricalSummary>(ssz_bytes, expected_root, case_label),
        // Deneb-new types (minimal)
        "BlobIdentifier" => check::<BlobIdentifier>(ssz_bytes, expected_root, case_label),
        "BlobSidecar" => check::<BlobSidecar>(ssz_bytes, expected_root, case_label),
        "ExecutionPayload" => {
            check::<DenebMinimalExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<DenebMinimalExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlockBody" => {
            check::<DenebMinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<DenebMinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<DenebMinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<DenebMinimalBeaconState>(ssz_bytes, expected_root, case_label),
        // Deneb LC types (minimal)
        "LightClientHeader" => {
            use pharos_types::deneb::light_client::MinimalLightClientHeader as DenebMinimalLCHeader;
            check::<DenebMinimalLCHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            use pharos_types::deneb::light_client::MinimalLightClientBootstrap as DenebMinimalLCBootstrap;
            check::<DenebMinimalLCBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            use pharos_types::deneb::light_client::MinimalLightClientUpdate as DenebMinimalLCUpdate;
            check::<DenebMinimalLCUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            use pharos_types::deneb::light_client::MinimalLightClientFinalityUpdate as DenebMinimalLCFinalityUpdate;
            check::<DenebMinimalLCFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            use pharos_types::deneb::light_client::MinimalLightClientOptimisticUpdate as DenebMinimalLCOptimisticUpdate;
            check::<DenebMinimalLCOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping minimal/deneb/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_electra(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_electra_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_electra_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Ok(false),
    }
}

fn dispatch_electra_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::deneb::{
        MainnetExecutionPayload as DenebMainnetExecutionPayload,
        MainnetExecutionPayloadHeader as DenebMainnetExecutionPayloadHeader,
    };
    use pharos_types::electra::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, MainnetAggregateAndProof,
        MainnetAttestation, MainnetAttesterSlashing,
        MainnetBeaconBlock as ElectraMainnetBeaconBlock,
        MainnetBeaconBlockBody as ElectraMainnetBeaconBlockBody,
        MainnetBeaconState as ElectraMainnetBeaconState, MainnetIndexedAttestation,
        MainnetSignedAggregateAndProof,
        MainnetSignedBeaconBlock as ElectraMainnetSignedBeaconBlock, PendingConsolidation,
        PendingDeposit, PendingPartialWithdrawal, SingleAttestation, WithdrawalRequest,
    };

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (mainnet)
        "HistoricalBatch" => check::<MainnetHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => {
            check::<pharos_types::altair::SyncCommitteeContribution<128>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<128>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => check::<
            pharos_types::altair::SignedContributionAndProof<128>,
        >(ssz_bytes, expected_root, case_label),
        // Capella-inherited types (mainnet)
        "Withdrawal" => {
            check::<pharos_types::capella::Withdrawal>(ssz_bytes, expected_root, case_label)
        }
        "BLSToExecutionChange" => check::<pharos_types::capella::BLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedBLSToExecutionChange" => check::<pharos_types::capella::SignedBLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "HistoricalSummary" => {
            check::<pharos_types::capella::HistoricalSummary>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited types (mainnet) — execution payload identical to deneb
        "ExecutionPayload" => {
            check::<DenebMainnetExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<DenebMainnetExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited blob types
        "BlobIdentifier" => {
            check::<pharos_types::deneb::BlobIdentifier>(ssz_bytes, expected_root, case_label)
        }
        "BlobSidecar" => {
            check::<pharos_types::deneb::BlobSidecar>(ssz_bytes, expected_root, case_label)
        }
        // Electra-modified types: Attestation, IndexedAttestation, AttesterSlashing,
        // AggregateAndProof, SignedAggregateAndProof (EIP-7549 widened)
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "AggregateAndProof" => {
            check::<MainnetAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<MainnetSignedAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        // Electra-new types: EL request containers and CL pending queues
        "SingleAttestation" => check::<SingleAttestation>(ssz_bytes, expected_root, case_label),
        "DepositRequest" => check::<DepositRequest>(ssz_bytes, expected_root, case_label),
        "WithdrawalRequest" => check::<WithdrawalRequest>(ssz_bytes, expected_root, case_label),
        "ConsolidationRequest" => {
            check::<ConsolidationRequest>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionRequests" => {
            // mainnet: MAX_DEPOSIT_REQUESTS=8192, MAX_WITHDRAWAL_REQUESTS=16,
            //          MAX_CONSOLIDATION_REQUESTS=2
            check::<ExecutionRequests<8192, 16, 2>>(ssz_bytes, expected_root, case_label)
        }
        "PendingDeposit" => check::<PendingDeposit>(ssz_bytes, expected_root, case_label),
        "PendingPartialWithdrawal" => {
            check::<PendingPartialWithdrawal>(ssz_bytes, expected_root, case_label)
        }
        "PendingConsolidation" => {
            check::<PendingConsolidation>(ssz_bytes, expected_root, case_label)
        }
        // Electra block/state types (mainnet)
        "BeaconBlockBody" => {
            check::<ElectraMainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<ElectraMainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<ElectraMainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<ElectraMainnetBeaconState>(ssz_bytes, expected_root, case_label),
        // Electra LC types (mainnet) — identical to Deneb LC types
        "LightClientHeader" => {
            use pharos_types::electra::light_client::MainnetLightClientHeader;
            check::<MainnetLightClientHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            use pharos_types::electra::light_client::MainnetLightClientBootstrap;
            check::<MainnetLightClientBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            use pharos_types::electra::light_client::MainnetLightClientUpdate;
            check::<MainnetLightClientUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            use pharos_types::electra::light_client::MainnetLightClientFinalityUpdate;
            check::<MainnetLightClientFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            use pharos_types::electra::light_client::MainnetLightClientOptimisticUpdate;
            check::<MainnetLightClientOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        // Phase0-inherited phase0-specific types not superseded (AggregateAndProof uses
        // electra version above; these are kept for phase0-inherited non-attestation types)
        _ => {
            eprintln!("skipping mainnet/electra/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_electra_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::deneb::{
        MinimalExecutionPayload as DenebMinimalExecutionPayload,
        MinimalExecutionPayloadHeader as DenebMinimalExecutionPayloadHeader,
    };
    use pharos_types::electra::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, MinimalAggregateAndProof,
        MinimalAttestation, MinimalAttesterSlashing,
        MinimalBeaconBlock as ElectraMinimalBeaconBlock,
        MinimalBeaconBlockBody as ElectraMinimalBeaconBlockBody,
        MinimalBeaconState as ElectraMinimalBeaconState, MinimalIndexedAttestation,
        MinimalSignedAggregateAndProof,
        MinimalSignedBeaconBlock as ElectraMinimalSignedBeaconBlock, PendingConsolidation,
        PendingDeposit, PendingPartialWithdrawal, SingleAttestation, WithdrawalRequest,
    };

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (minimal)
        "HistoricalBatch" => check::<MinimalHistoricalBatch>(ssz_bytes, expected_root, case_label),
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => check::<pharos_types::altair::SyncCommitteeContribution<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => {
            check::<pharos_types::altair::SignedContributionAndProof<8>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        // Capella-inherited types (minimal)
        "Withdrawal" => {
            check::<pharos_types::capella::Withdrawal>(ssz_bytes, expected_root, case_label)
        }
        "BLSToExecutionChange" => check::<pharos_types::capella::BLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedBLSToExecutionChange" => check::<pharos_types::capella::SignedBLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "HistoricalSummary" => {
            check::<pharos_types::capella::HistoricalSummary>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited types (minimal) — execution payload identical to deneb
        "ExecutionPayload" => {
            check::<DenebMinimalExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<DenebMinimalExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited blob types
        "BlobIdentifier" => {
            check::<pharos_types::deneb::BlobIdentifier>(ssz_bytes, expected_root, case_label)
        }
        "BlobSidecar" => {
            check::<pharos_types::deneb::BlobSidecar>(ssz_bytes, expected_root, case_label)
        }
        // Electra-modified types (EIP-7549 widened, minimal params)
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "AggregateAndProof" => {
            check::<MinimalAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<MinimalSignedAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        // Electra-new types (preset-independent)
        "SingleAttestation" => check::<SingleAttestation>(ssz_bytes, expected_root, case_label),
        "DepositRequest" => check::<DepositRequest>(ssz_bytes, expected_root, case_label),
        "WithdrawalRequest" => check::<WithdrawalRequest>(ssz_bytes, expected_root, case_label),
        "ConsolidationRequest" => {
            check::<ConsolidationRequest>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionRequests" => {
            // minimal: same limits as mainnet
            check::<ExecutionRequests<8192, 16, 2>>(ssz_bytes, expected_root, case_label)
        }
        "PendingDeposit" => check::<PendingDeposit>(ssz_bytes, expected_root, case_label),
        "PendingPartialWithdrawal" => {
            check::<PendingPartialWithdrawal>(ssz_bytes, expected_root, case_label)
        }
        "PendingConsolidation" => {
            check::<PendingConsolidation>(ssz_bytes, expected_root, case_label)
        }
        // Electra block/state types (minimal)
        "BeaconBlockBody" => {
            check::<ElectraMinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<ElectraMinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<ElectraMinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<ElectraMinimalBeaconState>(ssz_bytes, expected_root, case_label),
        // Electra LC types (minimal) — identical to Deneb LC types
        "LightClientHeader" => {
            use pharos_types::electra::light_client::MinimalLightClientHeader;
            check::<MinimalLightClientHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            use pharos_types::electra::light_client::MinimalLightClientBootstrap;
            check::<MinimalLightClientBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            use pharos_types::electra::light_client::MinimalLightClientUpdate;
            check::<MinimalLightClientUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            use pharos_types::electra::light_client::MinimalLightClientFinalityUpdate;
            check::<MinimalLightClientFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            use pharos_types::electra::light_client::MinimalLightClientOptimisticUpdate;
            check::<MinimalLightClientOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping minimal/electra/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_fulu(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_fulu_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_fulu_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Ok(false),
    }
}

fn dispatch_fulu_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::deneb::{
        MainnetExecutionPayload as DenebMainnetExecutionPayload,
        MainnetExecutionPayloadHeader as DenebMainnetExecutionPayloadHeader,
    };
    use pharos_types::electra::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, MainnetAggregateAndProof,
        MainnetAttestation, MainnetAttesterSlashing, MainnetIndexedAttestation,
        MainnetSignedAggregateAndProof, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, SingleAttestation, WithdrawalRequest,
    };
    use pharos_types::fulu::{
        MainnetBeaconBlock as FuluMainnetBeaconBlock,
        MainnetBeaconBlockBody as FuluMainnetBeaconBlockBody,
        MainnetBeaconState as FuluMainnetBeaconState, MainnetDataColumnSidecar,
        MainnetDataColumnsByRootIdentifier, MainnetPartialDataColumnHeader,
        MainnetPartialDataColumnPartsMetadata, MainnetPartialDataColumnSidecar,
        MainnetSignedBeaconBlock as FuluMainnetSignedBeaconBlock, MatrixEntry,
    };

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (mainnet)
        "Deposit" => check::<MainnetDeposit>(ssz_bytes, expected_root, case_label),
        // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<512>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => {
            check::<pharos_types::altair::SyncCommitteeContribution<128>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<128>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => check::<
            pharos_types::altair::SignedContributionAndProof<128>,
        >(ssz_bytes, expected_root, case_label),
        // Capella-inherited types (mainnet)
        "Withdrawal" => {
            check::<pharos_types::capella::Withdrawal>(ssz_bytes, expected_root, case_label)
        }
        "BLSToExecutionChange" => check::<pharos_types::capella::BLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedBLSToExecutionChange" => check::<pharos_types::capella::SignedBLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "HistoricalSummary" => {
            check::<pharos_types::capella::HistoricalSummary>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited types (mainnet) — execution payload identical to deneb
        "ExecutionPayload" => {
            check::<DenebMainnetExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<DenebMainnetExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited blob types
        "BlobIdentifier" => {
            check::<pharos_types::deneb::BlobIdentifier>(ssz_bytes, expected_root, case_label)
        }
        "BlobSidecar" => {
            check::<pharos_types::deneb::BlobSidecar>(ssz_bytes, expected_root, case_label)
        }
        // Electra-modified attestation types (EIP-7549 widened, inherited unchanged by fulu)
        "Attestation" => check::<MainnetAttestation>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MainnetIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MainnetAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "AggregateAndProof" => {
            check::<MainnetAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<MainnetSignedAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        "SingleAttestation" => check::<SingleAttestation>(ssz_bytes, expected_root, case_label),
        // Electra-inherited EL request containers and CL pending queues
        "DepositRequest" => check::<DepositRequest>(ssz_bytes, expected_root, case_label),
        "WithdrawalRequest" => check::<WithdrawalRequest>(ssz_bytes, expected_root, case_label),
        "ConsolidationRequest" => {
            check::<ConsolidationRequest>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionRequests" => {
            check::<ExecutionRequests<8192, 16, 2>>(ssz_bytes, expected_root, case_label)
        }
        "PendingDeposit" => check::<PendingDeposit>(ssz_bytes, expected_root, case_label),
        "PendingPartialWithdrawal" => {
            check::<PendingPartialWithdrawal>(ssz_bytes, expected_root, case_label)
        }
        "PendingConsolidation" => {
            check::<PendingConsolidation>(ssz_bytes, expected_root, case_label)
        }
        // Fulu block/state types (mainnet) — BeaconState gains proposer_lookahead
        "BeaconBlockBody" => {
            check::<FuluMainnetBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<FuluMainnetBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<FuluMainnetSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<FuluMainnetBeaconState>(ssz_bytes, expected_root, case_label),
        // Fulu-new DAS containers (EIP-7594 PeerDAS)
        "DataColumnSidecar" => {
            check::<MainnetDataColumnSidecar>(ssz_bytes, expected_root, case_label)
        }
        "MatrixEntry" => check::<MatrixEntry>(ssz_bytes, expected_root, case_label),
        "DataColumnsByRootIdentifier" => {
            check::<MainnetDataColumnsByRootIdentifier>(ssz_bytes, expected_root, case_label)
        }
        "PartialDataColumnSidecar" => {
            check::<MainnetPartialDataColumnSidecar>(ssz_bytes, expected_root, case_label)
        }
        "PartialDataColumnHeader" => {
            check::<MainnetPartialDataColumnHeader>(ssz_bytes, expected_root, case_label)
        }
        "PartialDataColumnPartsMetadata" => {
            check::<MainnetPartialDataColumnPartsMetadata>(ssz_bytes, expected_root, case_label)
        }
        // Fulu LC types (mainnet) — identical to electra LC types
        "LightClientHeader" => {
            use pharos_types::fulu::light_client::MainnetLightClientHeader;
            check::<MainnetLightClientHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            use pharos_types::fulu::light_client::MainnetLightClientBootstrap;
            check::<MainnetLightClientBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            use pharos_types::fulu::light_client::MainnetLightClientUpdate;
            check::<MainnetLightClientUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            use pharos_types::fulu::light_client::MainnetLightClientFinalityUpdate;
            check::<MainnetLightClientFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            use pharos_types::fulu::light_client::MainnetLightClientOptimisticUpdate;
            check::<MainnetLightClientOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping mainnet/fulu/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

fn dispatch_fulu_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    use pharos_types::deneb::{
        MinimalExecutionPayload as DenebMinimalExecutionPayload,
        MinimalExecutionPayloadHeader as DenebMinimalExecutionPayloadHeader,
    };
    use pharos_types::electra::{
        ConsolidationRequest, DepositRequest, ExecutionRequests, MinimalAggregateAndProof,
        MinimalAttestation, MinimalAttesterSlashing, MinimalIndexedAttestation,
        MinimalSignedAggregateAndProof, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, SingleAttestation, WithdrawalRequest,
    };
    use pharos_types::fulu::{
        MatrixEntry, MinimalBeaconBlock as FuluMinimalBeaconBlock,
        MinimalBeaconBlockBody as FuluMinimalBeaconBlockBody,
        MinimalBeaconState as FuluMinimalBeaconState, MinimalDataColumnSidecar,
        MinimalDataColumnsByRootIdentifier, MinimalPartialDataColumnHeader,
        MinimalPartialDataColumnPartsMetadata, MinimalPartialDataColumnSidecar,
        MinimalSignedBeaconBlock as FuluMinimalSignedBeaconBlock,
    };

    match type_name {
        // Phase0-inherited preset-independent types
        "Fork" => check::<Fork>(ssz_bytes, expected_root, case_label),
        "ForkData" => check::<ForkData>(ssz_bytes, expected_root, case_label),
        "Checkpoint" => check::<Checkpoint>(ssz_bytes, expected_root, case_label),
        "Validator" => check::<Validator>(ssz_bytes, expected_root, case_label),
        "AttestationData" => check::<AttestationData>(ssz_bytes, expected_root, case_label),
        "Eth1Data" => check::<Eth1Data>(ssz_bytes, expected_root, case_label),
        "DepositMessage" => check::<DepositMessage>(ssz_bytes, expected_root, case_label),
        "DepositData" => check::<DepositData>(ssz_bytes, expected_root, case_label),
        "BeaconBlockHeader" => check::<BeaconBlockHeader>(ssz_bytes, expected_root, case_label),
        "SigningData" => check::<SigningData>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlockHeader" => {
            check::<SignedBeaconBlockHeader>(ssz_bytes, expected_root, case_label)
        }
        "ProposerSlashing" => check::<ProposerSlashing>(ssz_bytes, expected_root, case_label),
        "VoluntaryExit" => check::<VoluntaryExit>(ssz_bytes, expected_root, case_label),
        "SignedVoluntaryExit" => check::<SignedVoluntaryExit>(ssz_bytes, expected_root, case_label),
        "Eth1Block" => check::<Eth1Block>(ssz_bytes, expected_root, case_label),
        // Phase0-inherited preset-specific types (minimal)
        "Deposit" => check::<MinimalDeposit>(ssz_bytes, expected_root, case_label),
        // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
        "SyncAggregate" => {
            check::<pharos_types::altair::SyncAggregate<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommittee" => {
            check::<pharos_types::altair::SyncCommittee<32>>(ssz_bytes, expected_root, case_label)
        }
        "SyncCommitteeMessage" => check::<pharos_types::altair::SyncCommitteeMessage>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SyncAggregatorSelectionData" => {
            check::<pharos_types::altair::SyncAggregatorSelectionData>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        "SyncCommitteeContribution" => check::<pharos_types::altair::SyncCommitteeContribution<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "ContributionAndProof" => check::<pharos_types::altair::ContributionAndProof<8>>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedContributionAndProof" => {
            check::<pharos_types::altair::SignedContributionAndProof<8>>(
                ssz_bytes,
                expected_root,
                case_label,
            )
        }
        // Capella-inherited types (minimal)
        "Withdrawal" => {
            check::<pharos_types::capella::Withdrawal>(ssz_bytes, expected_root, case_label)
        }
        "BLSToExecutionChange" => check::<pharos_types::capella::BLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "SignedBLSToExecutionChange" => check::<pharos_types::capella::SignedBLSToExecutionChange>(
            ssz_bytes,
            expected_root,
            case_label,
        ),
        "HistoricalSummary" => {
            check::<pharos_types::capella::HistoricalSummary>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited types (minimal) — execution payload identical to deneb
        "ExecutionPayload" => {
            check::<DenebMinimalExecutionPayload>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionPayloadHeader" => {
            check::<DenebMinimalExecutionPayloadHeader>(ssz_bytes, expected_root, case_label)
        }
        // Deneb-inherited blob types
        "BlobIdentifier" => {
            check::<pharos_types::deneb::BlobIdentifier>(ssz_bytes, expected_root, case_label)
        }
        "BlobSidecar" => {
            check::<pharos_types::deneb::BlobSidecar>(ssz_bytes, expected_root, case_label)
        }
        // Electra-modified attestation types (EIP-7549 widened, inherited unchanged by fulu)
        "Attestation" => check::<MinimalAttestation>(ssz_bytes, expected_root, case_label),
        "IndexedAttestation" => {
            check::<MinimalIndexedAttestation>(ssz_bytes, expected_root, case_label)
        }
        "AttesterSlashing" => {
            check::<MinimalAttesterSlashing>(ssz_bytes, expected_root, case_label)
        }
        "AggregateAndProof" => {
            check::<MinimalAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        "SignedAggregateAndProof" => {
            check::<MinimalSignedAggregateAndProof>(ssz_bytes, expected_root, case_label)
        }
        "SingleAttestation" => check::<SingleAttestation>(ssz_bytes, expected_root, case_label),
        // Electra-inherited EL request containers and CL pending queues
        "DepositRequest" => check::<DepositRequest>(ssz_bytes, expected_root, case_label),
        "WithdrawalRequest" => check::<WithdrawalRequest>(ssz_bytes, expected_root, case_label),
        "ConsolidationRequest" => {
            check::<ConsolidationRequest>(ssz_bytes, expected_root, case_label)
        }
        "ExecutionRequests" => {
            check::<ExecutionRequests<8192, 16, 2>>(ssz_bytes, expected_root, case_label)
        }
        "PendingDeposit" => check::<PendingDeposit>(ssz_bytes, expected_root, case_label),
        "PendingPartialWithdrawal" => {
            check::<PendingPartialWithdrawal>(ssz_bytes, expected_root, case_label)
        }
        "PendingConsolidation" => {
            check::<PendingConsolidation>(ssz_bytes, expected_root, case_label)
        }
        // Fulu block/state types (minimal) — BeaconState gains proposer_lookahead
        "BeaconBlockBody" => {
            check::<FuluMinimalBeaconBlockBody>(ssz_bytes, expected_root, case_label)
        }
        "BeaconBlock" => check::<FuluMinimalBeaconBlock>(ssz_bytes, expected_root, case_label),
        "SignedBeaconBlock" => {
            check::<FuluMinimalSignedBeaconBlock>(ssz_bytes, expected_root, case_label)
        }
        "BeaconState" => check::<FuluMinimalBeaconState>(ssz_bytes, expected_root, case_label),
        // Fulu-new DAS containers (EIP-7594 PeerDAS)
        "DataColumnSidecar" => {
            check::<MinimalDataColumnSidecar>(ssz_bytes, expected_root, case_label)
        }
        "MatrixEntry" => check::<MatrixEntry>(ssz_bytes, expected_root, case_label),
        "DataColumnsByRootIdentifier" => {
            check::<MinimalDataColumnsByRootIdentifier>(ssz_bytes, expected_root, case_label)
        }
        "PartialDataColumnSidecar" => {
            check::<MinimalPartialDataColumnSidecar>(ssz_bytes, expected_root, case_label)
        }
        "PartialDataColumnHeader" => {
            check::<MinimalPartialDataColumnHeader>(ssz_bytes, expected_root, case_label)
        }
        "PartialDataColumnPartsMetadata" => {
            check::<MinimalPartialDataColumnPartsMetadata>(ssz_bytes, expected_root, case_label)
        }
        // Fulu LC types (minimal) — identical to electra LC types
        "LightClientHeader" => {
            use pharos_types::fulu::light_client::MinimalLightClientHeader;
            check::<MinimalLightClientHeader>(ssz_bytes, expected_root, case_label)
        }
        "LightClientBootstrap" => {
            use pharos_types::fulu::light_client::MinimalLightClientBootstrap;
            check::<MinimalLightClientBootstrap>(ssz_bytes, expected_root, case_label)
        }
        "LightClientUpdate" => {
            use pharos_types::fulu::light_client::MinimalLightClientUpdate;
            check::<MinimalLightClientUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientFinalityUpdate" => {
            use pharos_types::fulu::light_client::MinimalLightClientFinalityUpdate;
            check::<MinimalLightClientFinalityUpdate>(ssz_bytes, expected_root, case_label)
        }
        "LightClientOptimisticUpdate" => {
            use pharos_types::fulu::light_client::MinimalLightClientOptimisticUpdate;
            check::<MinimalLightClientOptimisticUpdate>(ssz_bytes, expected_root, case_label)
        }
        _ => {
            eprintln!("skipping minimal/fulu/ssz_static/{type_name}: not in dispatch table");
            Ok(false)
        }
    }
}

// Helpers `read_dir_sorted` and `dir_name` are shared via the `fs_util` module.
