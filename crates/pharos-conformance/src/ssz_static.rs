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

use rayon::prelude::*;

use crate::error::ConformanceError;
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::snappy::decompress_raw;
use crate::yaml_util::read_root_from_file;

/// Result of running all ssz_static tests for one preset.
pub struct StaticResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

/// Run all phase0 ssz_static tests for a given preset.
///
/// `preset_dir`: the top-level directory for this preset (e.g. `<root>/mainnet`).
pub fn run_ssz_static_preset(preset_dir: &Path, preset_name: &str) -> StaticResult {
    let base = preset_dir.join("phase0/ssz_static");
    if !base.is_dir() {
        eprintln!("ssz_static/{preset_name} dir not found: {}", base.display());
        return StaticResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: vec![],
        };
    }

    let type_dirs = read_dir_sorted(&base).unwrap_or_default();

    // Collect all (type_name, case_dir, case_label) tuples first.
    let mut all_cases: Vec<(String, std::path::PathBuf, String)> = Vec::new();
    for type_dir in type_dirs {
        let type_name = dir_name(&type_dir);
        let suite_dirs = read_dir_sorted(&type_dir).unwrap_or_default();
        for suite_dir in suite_dirs {
            let suite_name = dir_name(&suite_dir);
            let case_dirs = read_dir_sorted(&suite_dir).unwrap_or_default();
            for case_dir in case_dirs {
                let case_name = dir_name(&case_dir);
                let case_label =
                    format!("{preset_name}/phase0/ssz_static/{type_name}/{suite_name}/{case_name}");
                all_cases.push((type_name.clone(), case_dir, case_label));
            }
        }
    }

    let results: Vec<(bool, Option<String>)> = all_cases
        .into_par_iter()
        .map(|(type_name, case_dir, case_label)| {
            let result = run_static_case(preset_name, &type_name, &case_dir, &case_label);
            match result {
                Ok(true) => (true, None),
                Ok(false) => (false, None),
                Err(e) => (false, Some(format!("`{case_label}`: {e}"))),
            }
        })
        .collect();

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();
    for (passed, err) in results {
        match (passed, err) {
            (true, _) => pass += 1,
            (false, None) => skip += 1,
            (false, Some(msg)) => {
                fail += 1;
                failures.push(msg);
            }
        }
    }

    StaticResult {
        pass,
        fail,
        skip,
        failures,
    }
}

/// Run a single ssz_static case. Returns `Ok(true)` = pass, `Ok(false)` = skip.
fn run_static_case(
    preset: &str,
    type_name: &str,
    case_dir: &Path,
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

    // Dispatch on (preset, type_name) to the matching monomorphized type.
    // Returns Ok(true) = pass, Ok(false) = skip (unknown type).
    dispatch(preset, type_name, &ssz_bytes, &expected_root, case_label)
}

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

// ── Altair ssz_static runner ──────────────────────────────────────────────────

/// Run all altair ssz_static tests for a given preset.
///
/// `preset_dir`: the top-level directory for this preset (e.g. `<root>/mainnet`).
pub fn run_altair_ssz_static_preset(preset_dir: &Path, preset_name: &str) -> StaticResult {
    let base = preset_dir.join("altair/ssz_static");
    if !base.is_dir() {
        return StaticResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: vec![],
        };
    }

    let type_dirs = read_dir_sorted(&base).unwrap_or_default();

    let mut all_cases: Vec<(String, std::path::PathBuf, String)> = Vec::new();
    for type_dir in type_dirs {
        let type_name = dir_name(&type_dir);
        let suite_dirs = read_dir_sorted(&type_dir).unwrap_or_default();
        for suite_dir in suite_dirs {
            let suite_name = dir_name(&suite_dir);
            let case_dirs = read_dir_sorted(&suite_dir).unwrap_or_default();
            for case_dir in case_dirs {
                let case_name = dir_name(&case_dir);
                let case_label =
                    format!("{preset_name}/altair/ssz_static/{type_name}/{suite_name}/{case_name}");
                all_cases.push((type_name.clone(), case_dir, case_label));
            }
        }
    }

    let results: Vec<(bool, Option<String>)> = all_cases
        .into_par_iter()
        .map(|(type_name, case_dir, case_label)| {
            let result = run_altair_static_case(preset_name, &type_name, &case_dir, &case_label);
            match result {
                Ok(true) => (true, None),
                Ok(false) => (false, None),
                Err(e) => (false, Some(format!("`{case_label}`: {e}"))),
            }
        })
        .collect();

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();
    for (passed, err) in results {
        match (passed, err) {
            (true, _) => pass += 1,
            (false, None) => skip += 1,
            (false, Some(msg)) => {
                fail += 1;
                failures.push(msg);
            }
        }
    }

    StaticResult {
        pass,
        fail,
        skip,
        failures,
    }
}

fn run_altair_static_case(
    preset: &str,
    type_name: &str,
    case_dir: &Path,
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

    dispatch_altair(preset, type_name, &ssz_bytes, &expected_root, case_label)
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

// ── Bellatrix ssz_static runner ───────────────────────────────────────────────

/// Run all bellatrix ssz_static tests for the mainnet preset.
pub fn run_ssz_static_bellatrix_mainnet(root: &Path) -> StaticResult {
    run_bellatrix_ssz_static_preset(&root.join("mainnet"), "mainnet")
}

/// Run all bellatrix ssz_static tests for the minimal preset.
pub fn run_ssz_static_bellatrix_minimal(root: &Path) -> StaticResult {
    run_bellatrix_ssz_static_preset(&root.join("minimal"), "minimal")
}

fn run_bellatrix_ssz_static_preset(preset_dir: &Path, preset_name: &str) -> StaticResult {
    let base = preset_dir.join("bellatrix/ssz_static");
    if !base.is_dir() {
        return StaticResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: vec![],
        };
    }

    let type_dirs = read_dir_sorted(&base).unwrap_or_default();

    let mut all_cases: Vec<(String, std::path::PathBuf, String)> = Vec::new();
    for type_dir in type_dirs {
        let type_name = dir_name(&type_dir);
        let suite_dirs = read_dir_sorted(&type_dir).unwrap_or_default();
        for suite_dir in suite_dirs {
            let suite_name = dir_name(&suite_dir);
            let case_dirs = read_dir_sorted(&suite_dir).unwrap_or_default();
            for case_dir in case_dirs {
                let case_name = dir_name(&case_dir);
                let case_label = format!(
                    "{preset_name}/bellatrix/ssz_static/{type_name}/{suite_name}/{case_name}"
                );
                all_cases.push((type_name.clone(), case_dir, case_label));
            }
        }
    }

    let results: Vec<(bool, Option<String>)> = all_cases
        .into_par_iter()
        .map(|(type_name, case_dir, case_label)| {
            let result = run_bellatrix_static_case(preset_name, &type_name, &case_dir, &case_label);
            match result {
                Ok(true) => (true, None),
                Ok(false) => (false, None),
                Err(e) => (false, Some(format!("`{case_label}`: {e}"))),
            }
        })
        .collect();

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();
    for (passed, err) in results {
        match (passed, err) {
            (true, _) => pass += 1,
            (false, None) => skip += 1,
            (false, Some(msg)) => {
                fail += 1;
                failures.push(msg);
            }
        }
    }

    StaticResult {
        pass,
        fail,
        skip,
        failures,
    }
}

fn run_bellatrix_static_case(
    preset: &str,
    type_name: &str,
    case_dir: &Path,
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

    dispatch_bellatrix(preset, type_name, &ssz_bytes, &expected_root, case_label)
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

// Helpers `read_dir_sorted` and `dir_name` are shared via the `fs_util` module.
