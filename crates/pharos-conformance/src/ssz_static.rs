//! Runner for the `ssz_static` test category.
//!
//! Fixture path: `<root>/<preset>/phase0/ssz_static/<TypeName>/<suite>/<case>/`
//!
//! Each case:
//! - Decode `serialized.ssz_snappy` via SSZ.
//! - Check `tree_hash_root` against `roots.yaml`.
//! - Re-encode and assert bytes match original.
//!
//! Dispatch covers all containers across phase0..fulu for both `mainnet` and
//! `minimal` presets using the preset-specific type aliases from `pharos-types`.

use std::path::Path;

use pharos_fork_choice::pow_block::PowBlock;
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
use pharos_types::deneb::{
    BlobIdentifier, BlobSidecar, MainnetBeaconBlock as DenebMainnetBeaconBlock,
    MainnetBeaconBlockBody as DenebMainnetBeaconBlockBody,
    MainnetBeaconState as DenebMainnetBeaconState,
    MainnetExecutionPayload as DenebMainnetExecutionPayload,
    MainnetExecutionPayloadHeader as DenebMainnetExecutionPayloadHeader,
    MainnetSignedBeaconBlock as DenebMainnetSignedBeaconBlock,
    MinimalBeaconBlock as DenebMinimalBeaconBlock,
    MinimalBeaconBlockBody as DenebMinimalBeaconBlockBody,
    MinimalBeaconState as DenebMinimalBeaconState,
    MinimalExecutionPayload as DenebMinimalExecutionPayload,
    MinimalExecutionPayloadHeader as DenebMinimalExecutionPayloadHeader,
    MinimalSignedBeaconBlock as DenebMinimalSignedBeaconBlock,
    light_client::{
        MainnetLightClientBootstrap as DenebMainnetLCBootstrap,
        MainnetLightClientFinalityUpdate as DenebMainnetLCFinalityUpdate,
        MainnetLightClientHeader as DenebMainnetLCHeader,
        MainnetLightClientOptimisticUpdate as DenebMainnetLCOptimisticUpdate,
        MainnetLightClientUpdate as DenebMainnetLCUpdate,
        MinimalLightClientBootstrap as DenebMinimalLCBootstrap,
        MinimalLightClientFinalityUpdate as DenebMinimalLCFinalityUpdate,
        MinimalLightClientHeader as DenebMinimalLCHeader,
        MinimalLightClientOptimisticUpdate as DenebMinimalLCOptimisticUpdate,
        MinimalLightClientUpdate as DenebMinimalLCUpdate,
    },
};
use pharos_types::electra::{
    ConsolidationRequest, DepositRequest, ExecutionRequests,
    MainnetAggregateAndProof as ElectraMainnetAggregateAndProof,
    MainnetAttestation as ElectraMainnetAttestation,
    MainnetAttesterSlashing as ElectraMainnetAttesterSlashing,
    MainnetBeaconBlock as ElectraMainnetBeaconBlock,
    MainnetBeaconBlockBody as ElectraMainnetBeaconBlockBody,
    MainnetBeaconState as ElectraMainnetBeaconState,
    MainnetIndexedAttestation as ElectraMainnetIndexedAttestation,
    MainnetSignedAggregateAndProof as ElectraMainnetSignedAggregateAndProof,
    MainnetSignedBeaconBlock as ElectraMainnetSignedBeaconBlock,
    MinimalAggregateAndProof as ElectraMinimalAggregateAndProof,
    MinimalAttestation as ElectraMinimalAttestation,
    MinimalAttesterSlashing as ElectraMinimalAttesterSlashing,
    MinimalBeaconBlock as ElectraMinimalBeaconBlock,
    MinimalBeaconBlockBody as ElectraMinimalBeaconBlockBody,
    MinimalBeaconState as ElectraMinimalBeaconState,
    MinimalIndexedAttestation as ElectraMinimalIndexedAttestation,
    MinimalSignedAggregateAndProof as ElectraMinimalSignedAggregateAndProof,
    MinimalSignedBeaconBlock as ElectraMinimalSignedBeaconBlock, PendingConsolidation,
    PendingDeposit, PendingPartialWithdrawal, SingleAttestation, WithdrawalRequest,
    light_client::{
        MainnetLightClientBootstrap as ElectraMainnetLCBootstrap,
        MainnetLightClientFinalityUpdate as ElectraMainnetLCFinalityUpdate,
        MainnetLightClientHeader as ElectraMainnetLCHeader,
        MainnetLightClientOptimisticUpdate as ElectraMainnetLCOptimisticUpdate,
        MainnetLightClientUpdate as ElectraMainnetLCUpdate,
        MinimalLightClientBootstrap as ElectraMinimalLCBootstrap,
        MinimalLightClientFinalityUpdate as ElectraMinimalLCFinalityUpdate,
        MinimalLightClientHeader as ElectraMinimalLCHeader,
        MinimalLightClientOptimisticUpdate as ElectraMinimalLCOptimisticUpdate,
        MinimalLightClientUpdate as ElectraMinimalLCUpdate,
    },
};
use pharos_types::fulu::{
    MainnetBeaconBlock as FuluMainnetBeaconBlock,
    MainnetBeaconBlockBody as FuluMainnetBeaconBlockBody,
    MainnetBeaconState as FuluMainnetBeaconState, MainnetDataColumnSidecar,
    MainnetDataColumnsByRootIdentifier, MainnetPartialDataColumnHeader,
    MainnetPartialDataColumnPartsMetadata, MainnetPartialDataColumnSidecar,
    MainnetSignedBeaconBlock as FuluMainnetSignedBeaconBlock, MatrixEntry,
    MinimalBeaconBlock as FuluMinimalBeaconBlock,
    MinimalBeaconBlockBody as FuluMinimalBeaconBlockBody,
    MinimalBeaconState as FuluMinimalBeaconState, MinimalDataColumnSidecar,
    MinimalDataColumnsByRootIdentifier, MinimalPartialDataColumnHeader,
    MinimalPartialDataColumnPartsMetadata, MinimalPartialDataColumnSidecar,
    MinimalSignedBeaconBlock as FuluMinimalSignedBeaconBlock,
    light_client::{
        MainnetLightClientBootstrap as FuluMainnetLCBootstrap,
        MainnetLightClientFinalityUpdate as FuluMainnetLCFinalityUpdate,
        MainnetLightClientHeader as FuluMainnetLCHeader,
        MainnetLightClientOptimisticUpdate as FuluMainnetLCOptimisticUpdate,
        MainnetLightClientUpdate as FuluMainnetLCUpdate,
        MinimalLightClientBootstrap as FuluMinimalLCBootstrap,
        MinimalLightClientFinalityUpdate as FuluMinimalLCFinalityUpdate,
        MinimalLightClientHeader as FuluMinimalLCHeader,
        MinimalLightClientOptimisticUpdate as FuluMinimalLCOptimisticUpdate,
        MinimalLightClientUpdate as FuluMinimalLCUpdate,
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

// ── dispatch_type! macro ──────────────────────────────────────────────────────

/// Match `$type_name` against a list of `"TypeName" => ConcreteType` entries and
/// call `check::<ConcreteType>`. Any unknown type name returns
/// `Err(ConformanceError::UnknownSszStaticType)` rather than silently skipping.
macro_rules! dispatch_type {
    (
        $type_name:expr, $ssz_bytes:expr, $expected_root:expr, $case_label:expr,
        $fork:expr, $preset:expr,
        { $( $name:literal => $ty:ty ),* $(,)? }
    ) => {
        match $type_name {
            $( $name => check::<$ty>($ssz_bytes, $expected_root, $case_label), )*
            _ => Err(ConformanceError::UnknownSszStaticType {
                fork: $fork.to_string(),
                preset: $preset.to_string(),
                type_name: $type_name.to_string(),
            }),
        }
    };
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per ssz_static case in the same walk-order as the
/// corresponding `run_*_ssz_static_*` function. Called by the flat
/// work-pool.
///
/// `fork` must be one of `"phase0"`, `"altair"`, `"bellatrix"`, `"capella"`,
/// `"deneb"`, `"electra"`, or `"fulu"`. The walk mirrors the relevant
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
    let base = root.join(preset).join(fork).join("ssz_static");
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
        "phase0" => dispatch_phase0(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "altair" => dispatch_altair(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "bellatrix" => {
            dispatch_bellatrix(preset, type_name, &ssz_bytes, &expected_root, case_label)
        }
        "capella" => dispatch_capella(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "deneb" => dispatch_deneb(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "electra" => dispatch_electra(preset, type_name, &ssz_bytes, &expected_root, case_label),
        "fulu" => dispatch_fulu(preset, type_name, &ssz_bytes, &expected_root, case_label),
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: fork.to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
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

fn dispatch_phase0(
    preset: &str,
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    match preset {
        "mainnet" => dispatch_phase0_mainnet(type_name, ssz_bytes, expected_root, case_label),
        "minimal" => dispatch_phase0_minimal(type_name, ssz_bytes, expected_root, case_label),
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "phase0".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_phase0_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "phase0", "mainnet",
        {
            // Preset-independent types (beacon-chain.md)
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            // Preset-independent types (validator.md)
            "Eth1Block" => Eth1Block,
            // Preset-specific types (mainnet, beacon-chain.md)
            "HistoricalBatch" => MainnetHistoricalBatch,
            "IndexedAttestation" => MainnetIndexedAttestation,
            "PendingAttestation" => MainnetPendingAttestation,
            "AttesterSlashing" => MainnetAttesterSlashing,
            "Attestation" => MainnetAttestation,
            "Deposit" => MainnetDeposit,
            "BeaconBlockBody" => MainnetBeaconBlockBody,
            "BeaconBlock" => MainnetBeaconBlock,
            "SignedBeaconBlock" => MainnetSignedBeaconBlock,
            "BeaconState" => MainnetBeaconState,
            // Preset-specific types (mainnet, validator.md)
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
        }
    )
}

fn dispatch_phase0_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "phase0", "minimal",
        {
            // Preset-independent types (beacon-chain.md)
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            // Preset-independent types (validator.md)
            "Eth1Block" => Eth1Block,
            // Preset-specific types (minimal, beacon-chain.md)
            "HistoricalBatch" => MinimalHistoricalBatch,
            "IndexedAttestation" => MinimalIndexedAttestation,
            "PendingAttestation" => MinimalPendingAttestation,
            "AttesterSlashing" => MinimalAttesterSlashing,
            "Attestation" => MinimalAttestation,
            "Deposit" => MinimalDeposit,
            "BeaconBlockBody" => MinimalBeaconBlockBody,
            "BeaconBlock" => MinimalBeaconBlock,
            "SignedBeaconBlock" => MinimalSignedBeaconBlock,
            "BeaconState" => MinimalBeaconState,
            // Preset-specific types (minimal, validator.md)
            // NOTE: AggregateAndProof uses mainnet MAX_VALIDATORS_PER_COMMITTEE=2048
            // for both presets (the preset constant is MAX_COMMITTEES_PER_SLOT, not
            // MAX_VALIDATORS_PER_COMMITTEE which is 2048 in both).
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
        }
    )
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
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "altair".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_altair_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "altair", "mainnet",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Preset-specific phase0-inherited types (mainnet)
            "HistoricalBatch" => MainnetHistoricalBatch,
            "IndexedAttestation" => MainnetIndexedAttestation,
            "PendingAttestation" => MainnetPendingAttestation,
            "AttesterSlashing" => MainnetAttesterSlashing,
            "Attestation" => MainnetAttestation,
            "Deposit" => MainnetDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-specific types (mainnet, SYNC_COMMITTEE_SIZE=512, SYNC_SUBCOMMITTEE_SIZE=128)
            "BeaconBlockBody" => AltairMainnetBeaconBlockBody,
            "BeaconBlock" => AltairMainnetBeaconBlock,
            "SignedBeaconBlock" => AltairMainnetSignedBeaconBlock,
            "BeaconState" => AltairMainnetBeaconState,
            "SyncAggregate" => SyncAggregate<512>,
            "SyncCommittee" => SyncCommittee<512>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<128>,
            "ContributionAndProof" => ContributionAndProof<128>,
            "SignedContributionAndProof" => SignedContributionAndProof<128>,
            "LightClientHeader" => LightClientHeader,
            "LightClientBootstrap" => LightClientBootstrap<512>,
            "LightClientUpdate" => LightClientUpdate<512>,
            "LightClientFinalityUpdate" => LightClientFinalityUpdate<512>,
            "LightClientOptimisticUpdate" => LightClientOptimisticUpdate<512>,
        }
    )
}

fn dispatch_altair_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "altair", "minimal",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Preset-specific phase0-inherited types (minimal)
            "HistoricalBatch" => MinimalHistoricalBatch,
            "IndexedAttestation" => MinimalIndexedAttestation,
            "PendingAttestation" => MinimalPendingAttestation,
            "AttesterSlashing" => MinimalAttesterSlashing,
            "Attestation" => MinimalAttestation,
            "Deposit" => MinimalDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-specific types (minimal, SYNC_COMMITTEE_SIZE=32, SYNC_SUBCOMMITTEE_SIZE=8)
            "BeaconBlockBody" => AltairMinimalBeaconBlockBody,
            "BeaconBlock" => AltairMinimalBeaconBlock,
            "SignedBeaconBlock" => AltairMinimalSignedBeaconBlock,
            "BeaconState" => AltairMinimalBeaconState,
            "SyncAggregate" => SyncAggregate<32>,
            "SyncCommittee" => SyncCommittee<32>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<8>,
            "ContributionAndProof" => ContributionAndProof<8>,
            "SignedContributionAndProof" => SignedContributionAndProof<8>,
            "LightClientHeader" => LightClientHeader,
            "LightClientBootstrap" => LightClientBootstrap<32>,
            "LightClientUpdate" => LightClientUpdate<32>,
            "LightClientFinalityUpdate" => LightClientFinalityUpdate<32>,
            "LightClientOptimisticUpdate" => LightClientOptimisticUpdate<32>,
        }
    )
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
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "bellatrix".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_bellatrix_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "bellatrix", "mainnet",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (mainnet)
            "HistoricalBatch" => MainnetHistoricalBatch,
            "IndexedAttestation" => MainnetIndexedAttestation,
            "PendingAttestation" => MainnetPendingAttestation,
            "AttesterSlashing" => MainnetAttesterSlashing,
            "Attestation" => MainnetAttestation,
            "Deposit" => MainnetDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512, SYNC_SUBCOMMITTEE_SIZE=128)
            "SyncAggregate" => SyncAggregate<512>,
            "SyncCommittee" => SyncCommittee<512>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<128>,
            "ContributionAndProof" => ContributionAndProof<128>,
            "SignedContributionAndProof" => SignedContributionAndProof<128>,
            // Altair-inherited LC types (bellatrix uses altair LC shapes)
            "LightClientHeader" => LightClientHeader,
            "LightClientBootstrap" => LightClientBootstrap<512>,
            "LightClientUpdate" => LightClientUpdate<512>,
            "LightClientFinalityUpdate" => LightClientFinalityUpdate<512>,
            "LightClientOptimisticUpdate" => LightClientOptimisticUpdate<512>,
            // Bellatrix-new types (mainnet)
            "ExecutionPayload" => BellatrixMainnetExecutionPayload,
            "ExecutionPayloadHeader" => BellatrixMainnetExecutionPayloadHeader,
            "BeaconBlockBody" => BellatrixMainnetBeaconBlockBody,
            "BeaconBlock" => BellatrixMainnetBeaconBlock,
            "SignedBeaconBlock" => BellatrixMainnetSignedBeaconBlock,
            "BeaconState" => BellatrixMainnetBeaconState,
            // Bellatrix-new: PoW block (merge transition)
            "PowBlock" => PowBlock,
        }
    )
}

fn dispatch_bellatrix_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "bellatrix", "minimal",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (minimal)
            "HistoricalBatch" => MinimalHistoricalBatch,
            "IndexedAttestation" => MinimalIndexedAttestation,
            "PendingAttestation" => MinimalPendingAttestation,
            "AttesterSlashing" => MinimalAttesterSlashing,
            "Attestation" => MinimalAttestation,
            "Deposit" => MinimalDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32, SYNC_SUBCOMMITTEE_SIZE=8)
            "SyncAggregate" => SyncAggregate<32>,
            "SyncCommittee" => SyncCommittee<32>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<8>,
            "ContributionAndProof" => ContributionAndProof<8>,
            "SignedContributionAndProof" => SignedContributionAndProof<8>,
            // Altair-inherited LC types (bellatrix uses altair LC shapes)
            "LightClientHeader" => LightClientHeader,
            "LightClientBootstrap" => LightClientBootstrap<32>,
            "LightClientUpdate" => LightClientUpdate<32>,
            "LightClientFinalityUpdate" => LightClientFinalityUpdate<32>,
            "LightClientOptimisticUpdate" => LightClientOptimisticUpdate<32>,
            // Bellatrix-new types (minimal)
            "ExecutionPayload" => BellatrixMinimalExecutionPayload,
            "ExecutionPayloadHeader" => BellatrixMinimalExecutionPayloadHeader,
            "BeaconBlockBody" => BellatrixMinimalBeaconBlockBody,
            "BeaconBlock" => BellatrixMinimalBeaconBlock,
            "SignedBeaconBlock" => BellatrixMinimalSignedBeaconBlock,
            "BeaconState" => BellatrixMinimalBeaconState,
            // Bellatrix-new: PoW block (merge transition)
            "PowBlock" => PowBlock,
        }
    )
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
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "capella".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_capella_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "capella", "mainnet",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (mainnet)
            "HistoricalBatch" => MainnetHistoricalBatch,
            "IndexedAttestation" => MainnetIndexedAttestation,
            "PendingAttestation" => MainnetPendingAttestation,
            "AttesterSlashing" => MainnetAttesterSlashing,
            "Attestation" => MainnetAttestation,
            "Deposit" => MainnetDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
            "SyncAggregate" => SyncAggregate<512>,
            "SyncCommittee" => SyncCommittee<512>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<128>,
            "ContributionAndProof" => ContributionAndProof<128>,
            "SignedContributionAndProof" => SignedContributionAndProof<128>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-new types (mainnet)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            "ExecutionPayload" => CapellaMainnetExecutionPayload,
            "ExecutionPayloadHeader" => CapellaMainnetExecutionPayloadHeader,
            "BeaconBlockBody" => CapellaMainnetBeaconBlockBody,
            "BeaconBlock" => CapellaMainnetBeaconBlock,
            "SignedBeaconBlock" => CapellaMainnetSignedBeaconBlock,
            "BeaconState" => CapellaMainnetBeaconState,
            // Capella LC types (capella header includes execution payload branch)
            "LightClientHeader" => CapellaMainnetLCHeader,
            "LightClientBootstrap" => CapellaMainnetLCBootstrap,
            "LightClientUpdate" => CapellaMainnetLCUpdate,
            "LightClientFinalityUpdate" => CapellaMainnetLCFinalityUpdate,
            "LightClientOptimisticUpdate" => CapellaMainnetLCOptimisticUpdate,
        }
    )
}

fn dispatch_capella_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "capella", "minimal",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (minimal)
            "HistoricalBatch" => MinimalHistoricalBatch,
            "IndexedAttestation" => MinimalIndexedAttestation,
            "PendingAttestation" => MinimalPendingAttestation,
            "AttesterSlashing" => MinimalAttesterSlashing,
            "Attestation" => MinimalAttestation,
            "Deposit" => MinimalDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
            "SyncAggregate" => SyncAggregate<32>,
            "SyncCommittee" => SyncCommittee<32>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<8>,
            "ContributionAndProof" => ContributionAndProof<8>,
            "SignedContributionAndProof" => SignedContributionAndProof<8>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-new types (minimal)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            "ExecutionPayload" => CapellaMinimalExecutionPayload,
            "ExecutionPayloadHeader" => CapellaMinimalExecutionPayloadHeader,
            "BeaconBlockBody" => CapellaMinimalBeaconBlockBody,
            "BeaconBlock" => CapellaMinimalBeaconBlock,
            "SignedBeaconBlock" => CapellaMinimalSignedBeaconBlock,
            "BeaconState" => CapellaMinimalBeaconState,
            // Capella LC types
            "LightClientHeader" => CapellaMinimalLCHeader,
            "LightClientBootstrap" => CapellaMinimalLCBootstrap,
            "LightClientUpdate" => CapellaMinimalLCUpdate,
            "LightClientFinalityUpdate" => CapellaMinimalLCFinalityUpdate,
            "LightClientOptimisticUpdate" => CapellaMinimalLCOptimisticUpdate,
        }
    )
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
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "deneb".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_deneb_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "deneb", "mainnet",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (mainnet)
            "HistoricalBatch" => MainnetHistoricalBatch,
            "IndexedAttestation" => MainnetIndexedAttestation,
            "PendingAttestation" => MainnetPendingAttestation,
            "AttesterSlashing" => MainnetAttesterSlashing,
            "Attestation" => MainnetAttestation,
            "Deposit" => MainnetDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
            "SyncAggregate" => SyncAggregate<512>,
            "SyncCommittee" => SyncCommittee<512>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<128>,
            "ContributionAndProof" => ContributionAndProof<128>,
            "SignedContributionAndProof" => SignedContributionAndProof<128>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-inherited types (mainnet)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            // Deneb-new types (mainnet)
            "BlobIdentifier" => BlobIdentifier,
            "BlobSidecar" => BlobSidecar,
            "ExecutionPayload" => DenebMainnetExecutionPayload,
            "ExecutionPayloadHeader" => DenebMainnetExecutionPayloadHeader,
            "BeaconBlockBody" => DenebMainnetBeaconBlockBody,
            "BeaconBlock" => DenebMainnetBeaconBlock,
            "SignedBeaconBlock" => DenebMainnetSignedBeaconBlock,
            "BeaconState" => DenebMainnetBeaconState,
            // Deneb LC types (mainnet)
            "LightClientHeader" => DenebMainnetLCHeader,
            "LightClientBootstrap" => DenebMainnetLCBootstrap,
            "LightClientUpdate" => DenebMainnetLCUpdate,
            "LightClientFinalityUpdate" => DenebMainnetLCFinalityUpdate,
            "LightClientOptimisticUpdate" => DenebMainnetLCOptimisticUpdate,
        }
    )
}

fn dispatch_deneb_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "deneb", "minimal",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (minimal)
            "HistoricalBatch" => MinimalHistoricalBatch,
            "IndexedAttestation" => MinimalIndexedAttestation,
            "PendingAttestation" => MinimalPendingAttestation,
            "AttesterSlashing" => MinimalAttesterSlashing,
            "Attestation" => MinimalAttestation,
            "Deposit" => MinimalDeposit,
            "AggregateAndProof" => AggregateAndProof<2048>,
            "SignedAggregateAndProof" => SignedAggregateAndProof<2048>,
            // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
            "SyncAggregate" => SyncAggregate<32>,
            "SyncCommittee" => SyncCommittee<32>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<8>,
            "ContributionAndProof" => ContributionAndProof<8>,
            "SignedContributionAndProof" => SignedContributionAndProof<8>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-inherited types (minimal)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            // Deneb-new types (minimal)
            "BlobIdentifier" => BlobIdentifier,
            "BlobSidecar" => BlobSidecar,
            "ExecutionPayload" => DenebMinimalExecutionPayload,
            "ExecutionPayloadHeader" => DenebMinimalExecutionPayloadHeader,
            "BeaconBlockBody" => DenebMinimalBeaconBlockBody,
            "BeaconBlock" => DenebMinimalBeaconBlock,
            "SignedBeaconBlock" => DenebMinimalSignedBeaconBlock,
            "BeaconState" => DenebMinimalBeaconState,
            // Deneb LC types (minimal)
            "LightClientHeader" => DenebMinimalLCHeader,
            "LightClientBootstrap" => DenebMinimalLCBootstrap,
            "LightClientUpdate" => DenebMinimalLCUpdate,
            "LightClientFinalityUpdate" => DenebMinimalLCFinalityUpdate,
            "LightClientOptimisticUpdate" => DenebMinimalLCOptimisticUpdate,
        }
    )
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
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "electra".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_electra_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "electra", "mainnet",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (mainnet)
            "HistoricalBatch" => MainnetHistoricalBatch,
            "Deposit" => MainnetDeposit,
            // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
            "SyncAggregate" => SyncAggregate<512>,
            "SyncCommittee" => SyncCommittee<512>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<128>,
            "ContributionAndProof" => ContributionAndProof<128>,
            "SignedContributionAndProof" => SignedContributionAndProof<128>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-inherited types (mainnet)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            // Deneb-inherited types (mainnet) — execution payload identical to deneb
            "ExecutionPayload" => DenebMainnetExecutionPayload,
            "ExecutionPayloadHeader" => DenebMainnetExecutionPayloadHeader,
            // Deneb-inherited blob types
            "BlobIdentifier" => BlobIdentifier,
            "BlobSidecar" => BlobSidecar,
            // Electra-modified types: Attestation, IndexedAttestation, AttesterSlashing,
            // AggregateAndProof, SignedAggregateAndProof (EIP-7549 widened)
            "Attestation" => ElectraMainnetAttestation,
            "IndexedAttestation" => ElectraMainnetIndexedAttestation,
            "AttesterSlashing" => ElectraMainnetAttesterSlashing,
            "AggregateAndProof" => ElectraMainnetAggregateAndProof,
            "SignedAggregateAndProof" => ElectraMainnetSignedAggregateAndProof,
            // Electra-new types: EL request containers and CL pending queues
            "SingleAttestation" => SingleAttestation,
            "DepositRequest" => DepositRequest,
            "WithdrawalRequest" => WithdrawalRequest,
            "ConsolidationRequest" => ConsolidationRequest,
            // mainnet: MAX_DEPOSIT_REQUESTS=8192, MAX_WITHDRAWAL_REQUESTS=16,
            //          MAX_CONSOLIDATION_REQUESTS=2
            "ExecutionRequests" => ExecutionRequests<8192, 16, 2>,
            "PendingDeposit" => PendingDeposit,
            "PendingPartialWithdrawal" => PendingPartialWithdrawal,
            "PendingConsolidation" => PendingConsolidation,
            // Electra block/state types (mainnet)
            "BeaconBlockBody" => ElectraMainnetBeaconBlockBody,
            "BeaconBlock" => ElectraMainnetBeaconBlock,
            "SignedBeaconBlock" => ElectraMainnetSignedBeaconBlock,
            "BeaconState" => ElectraMainnetBeaconState,
            // Electra LC types (mainnet) — identical to Deneb LC types
            "LightClientHeader" => ElectraMainnetLCHeader,
            "LightClientBootstrap" => ElectraMainnetLCBootstrap,
            "LightClientUpdate" => ElectraMainnetLCUpdate,
            "LightClientFinalityUpdate" => ElectraMainnetLCFinalityUpdate,
            "LightClientOptimisticUpdate" => ElectraMainnetLCOptimisticUpdate,
        }
    )
}

fn dispatch_electra_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "electra", "minimal",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (minimal)
            "HistoricalBatch" => MinimalHistoricalBatch,
            "Deposit" => MinimalDeposit,
            // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
            "SyncAggregate" => SyncAggregate<32>,
            "SyncCommittee" => SyncCommittee<32>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<8>,
            "ContributionAndProof" => ContributionAndProof<8>,
            "SignedContributionAndProof" => SignedContributionAndProof<8>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-inherited types (minimal)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            // Deneb-inherited types (minimal) — execution payload identical to deneb
            "ExecutionPayload" => DenebMinimalExecutionPayload,
            "ExecutionPayloadHeader" => DenebMinimalExecutionPayloadHeader,
            // Deneb-inherited blob types
            "BlobIdentifier" => BlobIdentifier,
            "BlobSidecar" => BlobSidecar,
            // Electra-modified types (EIP-7549 widened, minimal params)
            "Attestation" => ElectraMinimalAttestation,
            "IndexedAttestation" => ElectraMinimalIndexedAttestation,
            "AttesterSlashing" => ElectraMinimalAttesterSlashing,
            "AggregateAndProof" => ElectraMinimalAggregateAndProof,
            "SignedAggregateAndProof" => ElectraMinimalSignedAggregateAndProof,
            // Electra-new types (preset-independent)
            "SingleAttestation" => SingleAttestation,
            "DepositRequest" => DepositRequest,
            "WithdrawalRequest" => WithdrawalRequest,
            "ConsolidationRequest" => ConsolidationRequest,
            // minimal: same limits as mainnet
            "ExecutionRequests" => ExecutionRequests<8192, 16, 2>,
            "PendingDeposit" => PendingDeposit,
            "PendingPartialWithdrawal" => PendingPartialWithdrawal,
            "PendingConsolidation" => PendingConsolidation,
            // Electra block/state types (minimal)
            "BeaconBlockBody" => ElectraMinimalBeaconBlockBody,
            "BeaconBlock" => ElectraMinimalBeaconBlock,
            "SignedBeaconBlock" => ElectraMinimalSignedBeaconBlock,
            "BeaconState" => ElectraMinimalBeaconState,
            // Electra LC types (minimal) — identical to Deneb LC types
            "LightClientHeader" => ElectraMinimalLCHeader,
            "LightClientBootstrap" => ElectraMinimalLCBootstrap,
            "LightClientUpdate" => ElectraMinimalLCUpdate,
            "LightClientFinalityUpdate" => ElectraMinimalLCFinalityUpdate,
            "LightClientOptimisticUpdate" => ElectraMinimalLCOptimisticUpdate,
        }
    )
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
        _ => Err(ConformanceError::UnknownSszStaticType {
            fork: "fulu".to_string(),
            preset: preset.to_string(),
            type_name: type_name.to_string(),
        }),
    }
}

fn dispatch_fulu_mainnet(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "fulu", "mainnet",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (mainnet)
            "Deposit" => MainnetDeposit,
            // Altair-inherited types (mainnet, SYNC_COMMITTEE_SIZE=512)
            "SyncAggregate" => SyncAggregate<512>,
            "SyncCommittee" => SyncCommittee<512>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<128>,
            "ContributionAndProof" => ContributionAndProof<128>,
            "SignedContributionAndProof" => SignedContributionAndProof<128>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-inherited types (mainnet)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            // Deneb-inherited types (mainnet) — execution payload identical to deneb
            "ExecutionPayload" => DenebMainnetExecutionPayload,
            "ExecutionPayloadHeader" => DenebMainnetExecutionPayloadHeader,
            // Deneb-inherited blob types
            "BlobIdentifier" => BlobIdentifier,
            "BlobSidecar" => BlobSidecar,
            // Electra-modified attestation types (EIP-7549 widened, inherited unchanged by fulu)
            "Attestation" => ElectraMainnetAttestation,
            "IndexedAttestation" => ElectraMainnetIndexedAttestation,
            "AttesterSlashing" => ElectraMainnetAttesterSlashing,
            "AggregateAndProof" => ElectraMainnetAggregateAndProof,
            "SignedAggregateAndProof" => ElectraMainnetSignedAggregateAndProof,
            "SingleAttestation" => SingleAttestation,
            // Electra-inherited EL request containers and CL pending queues
            "DepositRequest" => DepositRequest,
            "WithdrawalRequest" => WithdrawalRequest,
            "ConsolidationRequest" => ConsolidationRequest,
            "ExecutionRequests" => ExecutionRequests<8192, 16, 2>,
            "PendingDeposit" => PendingDeposit,
            "PendingPartialWithdrawal" => PendingPartialWithdrawal,
            "PendingConsolidation" => PendingConsolidation,
            // Fulu block/state types (mainnet) — BeaconState gains proposer_lookahead
            "BeaconBlockBody" => FuluMainnetBeaconBlockBody,
            "BeaconBlock" => FuluMainnetBeaconBlock,
            "SignedBeaconBlock" => FuluMainnetSignedBeaconBlock,
            "BeaconState" => FuluMainnetBeaconState,
            // Fulu-new DAS containers (EIP-7594 PeerDAS)
            "DataColumnSidecar" => MainnetDataColumnSidecar,
            "MatrixEntry" => MatrixEntry,
            "DataColumnsByRootIdentifier" => MainnetDataColumnsByRootIdentifier,
            "PartialDataColumnSidecar" => MainnetPartialDataColumnSidecar,
            "PartialDataColumnHeader" => MainnetPartialDataColumnHeader,
            "PartialDataColumnPartsMetadata" => MainnetPartialDataColumnPartsMetadata,
            // Fulu LC types (mainnet) — identical to electra LC types
            "LightClientHeader" => FuluMainnetLCHeader,
            "LightClientBootstrap" => FuluMainnetLCBootstrap,
            "LightClientUpdate" => FuluMainnetLCUpdate,
            "LightClientFinalityUpdate" => FuluMainnetLCFinalityUpdate,
            "LightClientOptimisticUpdate" => FuluMainnetLCOptimisticUpdate,
        }
    )
}

fn dispatch_fulu_minimal(
    type_name: &str,
    ssz_bytes: &[u8],
    expected_root: &Hash256,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    dispatch_type!(
        type_name, ssz_bytes, expected_root, case_label, "fulu", "minimal",
        {
            // Phase0-inherited preset-independent types
            "Fork" => Fork,
            "ForkData" => ForkData,
            "Checkpoint" => Checkpoint,
            "Validator" => Validator,
            "AttestationData" => AttestationData,
            "Eth1Data" => Eth1Data,
            "DepositMessage" => DepositMessage,
            "DepositData" => DepositData,
            "BeaconBlockHeader" => BeaconBlockHeader,
            "SigningData" => SigningData,
            "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
            "ProposerSlashing" => ProposerSlashing,
            "VoluntaryExit" => VoluntaryExit,
            "SignedVoluntaryExit" => SignedVoluntaryExit,
            "Eth1Block" => Eth1Block,
            // Phase0-inherited preset-specific types (minimal)
            "Deposit" => MinimalDeposit,
            // Altair-inherited types (minimal, SYNC_COMMITTEE_SIZE=32)
            "SyncAggregate" => SyncAggregate<32>,
            "SyncCommittee" => SyncCommittee<32>,
            "SyncCommitteeMessage" => SyncCommitteeMessage,
            "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
            "SyncCommitteeContribution" => SyncCommitteeContribution<8>,
            "ContributionAndProof" => ContributionAndProof<8>,
            "SignedContributionAndProof" => SignedContributionAndProof<8>,
            // Bellatrix-inherited: PowBlock
            "PowBlock" => PowBlock,
            // Capella-inherited types (minimal)
            "Withdrawal" => Withdrawal,
            "BLSToExecutionChange" => BLSToExecutionChange,
            "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
            "HistoricalSummary" => HistoricalSummary,
            // Deneb-inherited types (minimal) — execution payload identical to deneb
            "ExecutionPayload" => DenebMinimalExecutionPayload,
            "ExecutionPayloadHeader" => DenebMinimalExecutionPayloadHeader,
            // Deneb-inherited blob types
            "BlobIdentifier" => BlobIdentifier,
            "BlobSidecar" => BlobSidecar,
            // Electra-modified attestation types (EIP-7549 widened, inherited unchanged by fulu)
            "Attestation" => ElectraMinimalAttestation,
            "IndexedAttestation" => ElectraMinimalIndexedAttestation,
            "AttesterSlashing" => ElectraMinimalAttesterSlashing,
            "AggregateAndProof" => ElectraMinimalAggregateAndProof,
            "SignedAggregateAndProof" => ElectraMinimalSignedAggregateAndProof,
            "SingleAttestation" => SingleAttestation,
            // Electra-inherited EL request containers and CL pending queues
            "DepositRequest" => DepositRequest,
            "WithdrawalRequest" => WithdrawalRequest,
            "ConsolidationRequest" => ConsolidationRequest,
            "ExecutionRequests" => ExecutionRequests<8192, 16, 2>,
            "PendingDeposit" => PendingDeposit,
            "PendingPartialWithdrawal" => PendingPartialWithdrawal,
            "PendingConsolidation" => PendingConsolidation,
            // Fulu block/state types (minimal) — BeaconState gains proposer_lookahead
            "BeaconBlockBody" => FuluMinimalBeaconBlockBody,
            "BeaconBlock" => FuluMinimalBeaconBlock,
            "SignedBeaconBlock" => FuluMinimalSignedBeaconBlock,
            "BeaconState" => FuluMinimalBeaconState,
            // Fulu-new DAS containers (EIP-7594 PeerDAS)
            "DataColumnSidecar" => MinimalDataColumnSidecar,
            "MatrixEntry" => MatrixEntry,
            "DataColumnsByRootIdentifier" => MinimalDataColumnsByRootIdentifier,
            "PartialDataColumnSidecar" => MinimalPartialDataColumnSidecar,
            "PartialDataColumnHeader" => MinimalPartialDataColumnHeader,
            "PartialDataColumnPartsMetadata" => MinimalPartialDataColumnPartsMetadata,
            // Fulu LC types (minimal) — identical to electra LC types
            "LightClientHeader" => FuluMinimalLCHeader,
            "LightClientBootstrap" => FuluMinimalLCBootstrap,
            "LightClientUpdate" => FuluMinimalLCUpdate,
            "LightClientFinalityUpdate" => FuluMinimalLCFinalityUpdate,
            "LightClientOptimisticUpdate" => FuluMinimalLCOptimisticUpdate,
        }
    )
}

// Helpers `read_dir_sorted` and `dir_name` are shared via the `fs_util` module.
