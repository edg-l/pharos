//! Altair beacon-chain type containers.
//!
//! All containers are defined per `specs/altair/beacon-chain.md` and
//! `specs/altair/light-client/sync-protocol.md`.
//!
//! ## Stable-Rust const-generic constraint
//!
//! On stable Rust, the `generic_const_exprs` feature is not available, which
//! means associated consts from a generic `E: EthSpec` type parameter cannot
//! be used directly as const-generic arguments in struct field types. The
//! same resolution as phase0 applies: explicit `const` parameters on each
//! generic container struct, with preset-specific type aliases.

pub mod block;
pub mod body;
pub mod constants;
pub mod light_client;
pub mod operations;
pub mod state;

// Re-export all container types.
pub use block::{BeaconBlock, SignedBeaconBlock};
pub use body::BeaconBlockBody;
pub use constants::{
    ParticipationFlags, SYNC_COMMITTEE_SUBNET_COUNT, TIMELY_HEAD_FLAG_INDEX,
    TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};
pub use light_client::{
    CURRENT_SYNC_COMMITTEE_GINDEX, FINALIZED_ROOT_GINDEX, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate, LightClientStore,
    LightClientUpdate, NEXT_SYNC_COMMITTEE_GINDEX,
};
pub use operations::{
    ContributionAndProof, SignedContributionAndProof, SyncAggregate, SyncAggregatorSelectionData,
    SyncCommittee, SyncCommitteeContribution, SyncCommitteeMessage,
};
pub use state::BeaconState;

// ── Preset-specific type aliases ───────────────────────────────────────────────
//
// All constant values are verified against the preset YAML files in
// `presets/mainnet/altair.yaml`, `presets/minimal/altair.yaml`, and the
// phase0 preset files.

// ── Mainnet type aliases ───────────────────────────────────────────────────────

/// Mainnet altair `BeaconState`.
///
/// Const parameters, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT = 8192` (`presets/mainnet/phase0.yaml:42`)
/// 2. `HISTORICAL_ROOTS_LIMIT = 16_777_216` (`presets/mainnet/phase0.yaml:53`)
/// 3. `ETH1_DATA_VOTES_LIMIT = 2048` (= 64 * 32, derived)
/// 4. `VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776` (`presets/mainnet/phase0.yaml:55`)
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR = 65536` (`presets/mainnet/phase0.yaml:49`)
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR = 8192` (`presets/mainnet/phase0.yaml:51`)
/// 7. `JUSTIFICATION_BITS_LENGTH = 4` (`specs/phase0/beacon-chain.md:195`)
/// 8. `SYNC_COMMITTEE_SIZE = 512` (`presets/mainnet/altair.yaml:15`)
pub type MainnetBeaconState = BeaconState<
    8192,              // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    2048,              // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    65536,             // EPOCHS_PER_HISTORICAL_VECTOR
    8192,              // EPOCHS_PER_SLASHINGS_VECTOR
    4,                 // JUSTIFICATION_BITS_LENGTH
    512,               // SYNC_COMMITTEE_SIZE
>;

/// Mainnet altair `BeaconBlockBody`.
///
/// Const parameters, in order:
/// 1. `MAX_PROPOSER_SLASHINGS = 16` (`presets/mainnet/phase0.yaml:75`)
/// 2. `MAX_ATTESTER_SLASHINGS = 2` (`presets/mainnet/phase0.yaml:77`)
/// 3. `MAX_ATTESTATIONS = 128` (`presets/mainnet/phase0.yaml:79`)
/// 4. `MAX_DEPOSITS = 16` (`presets/mainnet/phase0.yaml:81`)
/// 5. `MAX_VOLUNTARY_EXITS = 16` (`presets/mainnet/phase0.yaml:83`)
/// 6. `MAX_VALIDATORS_PER_COMMITTEE = 2048` (`presets/mainnet/phase0.yaml:10`)
/// 7. `DEPOSIT_PROOF_LENGTH = 33` (`specs/phase0/beacon-chain.md:194`)
/// 8. `SYNC_COMMITTEE_SIZE = 512` (`presets/mainnet/altair.yaml:15`)
pub type MainnetBeaconBlockBody = BeaconBlockBody<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
    512,  // SYNC_COMMITTEE_SIZE
>;

/// Mainnet altair `BeaconBlock`.
pub type MainnetBeaconBlock = BeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
    512,  // SYNC_COMMITTEE_SIZE
>;

/// Mainnet altair `SignedBeaconBlock`.
pub type MainnetSignedBeaconBlock = SignedBeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
    512,  // SYNC_COMMITTEE_SIZE
>;

/// Mainnet altair `SyncAggregate`.
pub type MainnetSyncAggregate = SyncAggregate<512>;

/// Mainnet altair `SyncCommittee`.
pub type MainnetSyncCommittee = SyncCommittee<512>;

/// Mainnet altair `SyncCommitteeContribution` (`SYNC_SUBCOMMITTEE_SIZE = 128`).
pub type MainnetSyncCommitteeContribution = SyncCommitteeContribution<128>;

/// Mainnet altair `LightClientBootstrap`.
pub type MainnetLightClientBootstrap = LightClientBootstrap<512>;

/// Mainnet altair `LightClientUpdate`.
pub type MainnetLightClientUpdate = LightClientUpdate<512>;

/// Mainnet altair `LightClientFinalityUpdate`.
pub type MainnetLightClientFinalityUpdate = LightClientFinalityUpdate<512>;

/// Mainnet altair `LightClientOptimisticUpdate`.
pub type MainnetLightClientOptimisticUpdate = LightClientOptimisticUpdate<512>;

/// Mainnet altair `LightClientStore`.
pub type MainnetLightClientStore = LightClientStore<512>;

// ── Minimal type aliases ───────────────────────────────────────────────────────

/// Minimal altair `BeaconState`.
///
/// Const parameters, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT = 64` (`presets/minimal/phase0.yaml:42`)
/// 2. `HISTORICAL_ROOTS_LIMIT = 16_777_216` (`presets/minimal/phase0.yaml:53`)
/// 3. `ETH1_DATA_VOTES_LIMIT = 32` (= 4 * 8, derived)
/// 4. `VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776` (`presets/minimal/phase0.yaml:55`)
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR = 64` (`presets/minimal/phase0.yaml:49`)
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR = 64` (`presets/minimal/phase0.yaml:51`)
/// 7. `JUSTIFICATION_BITS_LENGTH = 4` (`specs/phase0/beacon-chain.md:195`)
/// 8. `SYNC_COMMITTEE_SIZE = 32` (`presets/minimal/altair.yaml:15`)
pub type MinimalBeaconState = BeaconState<
    64,                // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    32,                // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    64,                // EPOCHS_PER_HISTORICAL_VECTOR
    64,                // EPOCHS_PER_SLASHINGS_VECTOR
    4,                 // JUSTIFICATION_BITS_LENGTH
    32,                // SYNC_COMMITTEE_SIZE
>;

/// Minimal altair `BeaconBlockBody`.
pub type MinimalBeaconBlockBody = BeaconBlockBody<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
    32,   // SYNC_COMMITTEE_SIZE
>;

/// Minimal altair `BeaconBlock`.
pub type MinimalBeaconBlock = BeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
    32,   // SYNC_COMMITTEE_SIZE
>;

/// Minimal altair `SignedBeaconBlock`.
pub type MinimalSignedBeaconBlock = SignedBeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
    32,   // SYNC_COMMITTEE_SIZE
>;

/// Minimal altair `SyncAggregate`.
pub type MinimalSyncAggregate = SyncAggregate<32>;

/// Minimal altair `SyncCommittee`.
pub type MinimalSyncCommittee = SyncCommittee<32>;

/// Minimal altair `SyncCommitteeContribution` (`SYNC_SUBCOMMITTEE_SIZE = 8`).
pub type MinimalSyncCommitteeContribution = SyncCommitteeContribution<8>;

/// Minimal altair `LightClientBootstrap`.
pub type MinimalLightClientBootstrap = LightClientBootstrap<32>;

/// Minimal altair `LightClientUpdate`.
pub type MinimalLightClientUpdate = LightClientUpdate<32>;

/// Minimal altair `LightClientFinalityUpdate`.
pub type MinimalLightClientFinalityUpdate = LightClientFinalityUpdate<32>;

/// Minimal altair `LightClientOptimisticUpdate`.
pub type MinimalLightClientOptimisticUpdate = LightClientOptimisticUpdate<32>;

/// Minimal altair `LightClientStore`.
pub type MinimalLightClientStore = LightClientStore<32>;
