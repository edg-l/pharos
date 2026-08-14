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

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();

    let type_dirs = read_dir_sorted(&base).unwrap_or_default();

    for type_dir in type_dirs {
        let type_name = dir_name(&type_dir);
        // Each type_dir contains suite dirs (e.g. "ssz_random", "ssz_random_chaos", etc.)
        let suite_dirs = read_dir_sorted(&type_dir).unwrap_or_default();
        for suite_dir in suite_dirs {
            let suite_name = dir_name(&suite_dir);
            let case_dirs = read_dir_sorted(&suite_dir).unwrap_or_default();
            for case_dir in case_dirs {
                let case_name = dir_name(&case_dir);
                let case_label =
                    format!("{preset_name}/phase0/ssz_static/{type_name}/{suite_name}/{case_name}");

                let result = run_static_case(preset_name, &type_name, &case_dir, &case_label);
                match result {
                    Ok(true) => pass += 1,
                    Ok(false) => skip += 1,
                    Err(e) => {
                        fail += 1;
                        failures.push(format!("`{case_label}`: {e}"));
                    }
                }
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

// Helpers `read_dir_sorted` and `dir_name` are shared via the `fs_util` module.
