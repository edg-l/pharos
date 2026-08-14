//! Phase 0 beacon-chain type containers.
//!
//! All containers are defined per `specs/phase0/beacon-chain.md:351-614`.
//!
//! ## Stable-Rust const-generic constraint
//!
//! On stable Rust, the `generic_const_exprs` feature is not available, which
//! means associated consts from a generic `E: EthSpec` type parameter cannot
//! be used directly as const-generic arguments in struct field types (e.g.,
//! `SszList<T, { E::CONST }>` does not compile). The plan's B2/B3 resolution
//! specifies flat associated consts on `EthSpec`; this module implements those
//! as explicit `const` parameters on each generic container struct.
//!
//! Preset-specific type aliases (`MainnetBeaconState`, `MinimalBeaconState`,
//! etc.) provide the ergonomic API that callers use.

pub mod block;
pub mod misc;
pub mod operations;
pub mod primitives;
pub mod state;

// Re-export all container types.
pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use misc::{
    AttestationData, Checkpoint, Eth1Data, Fork, ForkData, HistoricalBatch, IndexedAttestation,
    PendingAttestation, Validator,
};
pub use operations::{
    Attestation, AttesterSlashing, BeaconBlockHeader, Deposit, DepositData, DepositMessage,
    ProposerSlashing, SignedBeaconBlockHeader, SignedVoluntaryExit, SigningData, VoluntaryExit,
};
pub use primitives::*;
pub use state::BeaconState;

// ── Preset-specific type aliases ──────────────────────────────────────────────
//
// These aliases bind each generic container to a concrete set of preset
// constants. All constant values are verified against the preset YAML files
// in `presets/mainnet/phase0.yaml` and `presets/minimal/phase0.yaml`.

// ── Mainnet type aliases ──────────────────────────────────────────────────────

/// Mainnet `BeaconState` with all preset constants from
/// `presets/mainnet/phase0.yaml`.
///
/// `BeaconState` const params, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT = 8192` (`presets/mainnet/phase0.yaml:42`)
/// 2. `HISTORICAL_ROOTS_LIMIT = 16_777_216` (`presets/mainnet/phase0.yaml:53`)
/// 3. `ETH1_DATA_VOTES_LIMIT = 2048` (= 64 * 32, derived)
/// 4. `VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776` (`presets/mainnet/phase0.yaml:55`)
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR = 65536` (`presets/mainnet/phase0.yaml:49`)
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR = 8192` (`presets/mainnet/phase0.yaml:51`)
/// 7. `MAX_PENDING_ATTESTATIONS = 4096` (= 128 * 32, derived)
/// 8. `JUSTIFICATION_BITS_LENGTH = 4` (`specs/phase0/beacon-chain.md:195`)
/// 9. `MAX_VALIDATORS_PER_COMMITTEE = 2048` (`presets/mainnet/phase0.yaml:10`)
pub type MainnetBeaconState = BeaconState<
    8192,              // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    2048,              // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    65536,             // EPOCHS_PER_HISTORICAL_VECTOR
    8192,              // EPOCHS_PER_SLASHINGS_VECTOR
    4096,              // MAX_PENDING_ATTESTATIONS
    4,                 // JUSTIFICATION_BITS_LENGTH
    2048,              // MAX_VALIDATORS_PER_COMMITTEE
>;

/// Mainnet `HistoricalBatch` per `presets/mainnet/phase0.yaml:42`
/// (`SLOTS_PER_HISTORICAL_ROOT = 8192`).
pub type MainnetHistoricalBatch = HistoricalBatch<8192>;

/// Mainnet `IndexedAttestation` per `presets/mainnet/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MainnetIndexedAttestation = IndexedAttestation<2048>;

/// Mainnet `PendingAttestation` per `presets/mainnet/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MainnetPendingAttestation = PendingAttestation<2048>;

/// Mainnet `AttesterSlashing` per `presets/mainnet/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MainnetAttesterSlashing = AttesterSlashing<2048>;

/// Mainnet `Attestation` per `presets/mainnet/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MainnetAttestation = Attestation<2048>;

/// Mainnet `Deposit` with `DEPOSIT_PROOF_LENGTH = 33`
/// (`specs/phase0/beacon-chain.md:194`: `DEPOSIT_CONTRACT_TREE_DEPTH = 32`).
pub type MainnetDeposit = Deposit<33>;

/// Mainnet `BeaconBlockBody` with all mainnet operation limits.
pub type MainnetBeaconBlockBody = BeaconBlockBody<
    16,   // MAX_PROPOSER_SLASHINGS (presets/mainnet/phase0.yaml:75)
    2,    // MAX_ATTESTER_SLASHINGS (presets/mainnet/phase0.yaml:77)
    128,  // MAX_ATTESTATIONS (presets/mainnet/phase0.yaml:79)
    16,   // MAX_DEPOSITS (presets/mainnet/phase0.yaml:81)
    16,   // MAX_VOLUNTARY_EXITS (presets/mainnet/phase0.yaml:83)
    2048, // MAX_VALIDATORS_PER_COMMITTEE (presets/mainnet/phase0.yaml:10)
    33,   // DEPOSIT_PROOF_LENGTH (specs/phase0/beacon-chain.md:194)
>;

/// Mainnet `BeaconBlock` with all mainnet limits.
pub type MainnetBeaconBlock = BeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
>;

/// Mainnet `SignedBeaconBlock` with all mainnet limits.
pub type MainnetSignedBeaconBlock = SignedBeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
>;

// ── Minimal type aliases ──────────────────────────────────────────────────────

/// Minimal `BeaconState` with all preset constants from
/// `presets/minimal/phase0.yaml`.
///
/// `BeaconState` const params, in order:
/// 1. `SLOTS_PER_HISTORICAL_ROOT = 64` (`presets/minimal/phase0.yaml:42`)
/// 2. `HISTORICAL_ROOTS_LIMIT = 16_777_216` (`presets/minimal/phase0.yaml:53`)
/// 3. `ETH1_DATA_VOTES_LIMIT = 32` (= 4 * 8, derived)
/// 4. `VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776` (`presets/minimal/phase0.yaml:55`)
/// 5. `EPOCHS_PER_HISTORICAL_VECTOR = 64` (`presets/minimal/phase0.yaml:49`)
/// 6. `EPOCHS_PER_SLASHINGS_VECTOR = 64` (`presets/minimal/phase0.yaml:51`)
/// 7. `MAX_PENDING_ATTESTATIONS = 1024` (= 128 * 8, derived)
/// 8. `JUSTIFICATION_BITS_LENGTH = 4` (`specs/phase0/beacon-chain.md:195`)
/// 9. `MAX_VALIDATORS_PER_COMMITTEE = 2048` (`presets/minimal/phase0.yaml:10`)
pub type MinimalBeaconState = BeaconState<
    64,                // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    32,                // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    64,                // EPOCHS_PER_HISTORICAL_VECTOR
    64,                // EPOCHS_PER_SLASHINGS_VECTOR
    1024,              // MAX_PENDING_ATTESTATIONS
    4,                 // JUSTIFICATION_BITS_LENGTH
    2048,              // MAX_VALIDATORS_PER_COMMITTEE
>;

/// Minimal `HistoricalBatch` per `presets/minimal/phase0.yaml:42`
/// (`SLOTS_PER_HISTORICAL_ROOT = 64`).
pub type MinimalHistoricalBatch = HistoricalBatch<64>;

/// Minimal `IndexedAttestation` per `presets/minimal/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MinimalIndexedAttestation = IndexedAttestation<2048>;

/// Minimal `PendingAttestation` per `presets/minimal/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MinimalPendingAttestation = PendingAttestation<2048>;

/// Minimal `AttesterSlashing` per `presets/minimal/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MinimalAttesterSlashing = AttesterSlashing<2048>;

/// Minimal `Attestation` per `presets/minimal/phase0.yaml:10`
/// (`MAX_VALIDATORS_PER_COMMITTEE = 2048`).
pub type MinimalAttestation = Attestation<2048>;

/// Minimal `Deposit` with `DEPOSIT_PROOF_LENGTH = 33`
/// (`specs/phase0/beacon-chain.md:194`: `DEPOSIT_CONTRACT_TREE_DEPTH = 32`).
pub type MinimalDeposit = Deposit<33>;

/// Minimal `BeaconBlockBody` with all minimal operation limits.
pub type MinimalBeaconBlockBody = BeaconBlockBody<
    16,   // MAX_PROPOSER_SLASHINGS (presets/minimal/phase0.yaml:75)
    2,    // MAX_ATTESTER_SLASHINGS (presets/minimal/phase0.yaml:77)
    128,  // MAX_ATTESTATIONS (presets/minimal/phase0.yaml:79)
    16,   // MAX_DEPOSITS (presets/minimal/phase0.yaml:81)
    16,   // MAX_VOLUNTARY_EXITS (presets/minimal/phase0.yaml:83)
    2048, // MAX_VALIDATORS_PER_COMMITTEE (presets/minimal/phase0.yaml:10)
    33,   // DEPOSIT_PROOF_LENGTH
>;

/// Minimal `BeaconBlock` with all minimal limits.
pub type MinimalBeaconBlock = BeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
>;

/// Minimal `SignedBeaconBlock` with all minimal limits.
pub type MinimalSignedBeaconBlock = SignedBeaconBlock<
    16,   // MAX_PROPOSER_SLASHINGS
    2,    // MAX_ATTESTER_SLASHINGS
    128,  // MAX_ATTESTATIONS
    16,   // MAX_DEPOSITS
    16,   // MAX_VOLUNTARY_EXITS
    2048, // MAX_VALIDATORS_PER_COMMITTEE
    33,   // DEPOSIT_PROOF_LENGTH
>;
