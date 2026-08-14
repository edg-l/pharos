//! `EthSpec` trait and preset implementations.
//!
//! Constants are sourced from:
//! - `presets/mainnet/phase0.yaml` and `presets/minimal/phase0.yaml` (preset constants).
//! - `specs/phase0/beacon-chain.md:186-196` (non-configurable spec constants).

use std::fmt::Debug;

/// Trait carrying all Phase 0 preset constants and derived limits.
///
/// Every constant is `u64` so it can be used directly as a const-generic
/// parameter (`SszList<T, { E::SOME_CONST }>`) without type conversions (B4).
///
/// The three derived constants (`ETH1_DATA_VOTES_LIMIT`, `MAX_PENDING_ATTESTATIONS`,
/// `DEPOSIT_PROOF_LENGTH`) exist so container field types never contain compound
/// expressions `A * B` or `A + 1` in const-generic positions (B2/B3).
pub trait EthSpec: 'static + Send + Sync + Clone + Debug + PartialEq + Eq + Default {
    // -- Misc --
    // Source: presets/mainnet/phase0.yaml:6, presets/minimal/phase0.yaml:6
    /// `MAX_COMMITTEES_PER_SLOT` from `presets/mainnet/phase0.yaml:6` /
    /// `presets/minimal/phase0.yaml:6`.
    const MAX_COMMITTEES_PER_SLOT: u64;

    /// `TARGET_COMMITTEE_SIZE` from `presets/mainnet/phase0.yaml:8` /
    /// `presets/minimal/phase0.yaml:8`.
    const TARGET_COMMITTEE_SIZE: u64;

    /// `MAX_VALIDATORS_PER_COMMITTEE` from `presets/mainnet/phase0.yaml:10` /
    /// `presets/minimal/phase0.yaml:10`.
    const MAX_VALIDATORS_PER_COMMITTEE: u64;

    /// `SHUFFLE_ROUND_COUNT` from `presets/mainnet/phase0.yaml:12` /
    /// `presets/minimal/phase0.yaml:12`.
    const SHUFFLE_ROUND_COUNT: u64;

    /// `HYSTERESIS_QUOTIENT` from `presets/mainnet/phase0.yaml:14` /
    /// `presets/minimal/phase0.yaml:14`.
    const HYSTERESIS_QUOTIENT: u64;

    /// `HYSTERESIS_DOWNWARD_MULTIPLIER` from `presets/mainnet/phase0.yaml:16` /
    /// `presets/minimal/phase0.yaml:16`.
    const HYSTERESIS_DOWNWARD_MULTIPLIER: u64;

    /// `HYSTERESIS_UPWARD_MULTIPLIER` from `presets/mainnet/phase0.yaml:18` /
    /// `presets/minimal/phase0.yaml:18`.
    const HYSTERESIS_UPWARD_MULTIPLIER: u64;

    // -- Gwei values --
    /// `MIN_DEPOSIT_AMOUNT` from `presets/mainnet/phase0.yaml:23` /
    /// `presets/minimal/phase0.yaml:23`.
    const MIN_DEPOSIT_AMOUNT: u64;

    /// `MAX_EFFECTIVE_BALANCE` from `presets/mainnet/phase0.yaml:25` /
    /// `presets/minimal/phase0.yaml:25`.
    const MAX_EFFECTIVE_BALANCE: u64;

    /// `EFFECTIVE_BALANCE_INCREMENT` from `presets/mainnet/phase0.yaml:27` /
    /// `presets/minimal/phase0.yaml:27`.
    const EFFECTIVE_BALANCE_INCREMENT: u64;

    // -- Time parameters --
    /// `MIN_ATTESTATION_INCLUSION_DELAY` from `presets/mainnet/phase0.yaml:32` /
    /// `presets/minimal/phase0.yaml:32`.
    const MIN_ATTESTATION_INCLUSION_DELAY: u64;

    /// `SLOTS_PER_EPOCH` from `presets/mainnet/phase0.yaml:34` /
    /// `presets/minimal/phase0.yaml:34`.
    const SLOTS_PER_EPOCH: u64;

    /// `MIN_SEED_LOOKAHEAD` from `presets/mainnet/phase0.yaml:36` /
    /// `presets/minimal/phase0.yaml:36`.
    const MIN_SEED_LOOKAHEAD: u64;

    /// `MAX_SEED_LOOKAHEAD` from `presets/mainnet/phase0.yaml:38` /
    /// `presets/minimal/phase0.yaml:38`.
    const MAX_SEED_LOOKAHEAD: u64;

    /// `EPOCHS_PER_ETH1_VOTING_PERIOD` from `presets/mainnet/phase0.yaml:40` /
    /// `presets/minimal/phase0.yaml:40`.
    const EPOCHS_PER_ETH1_VOTING_PERIOD: u64;

    /// `SLOTS_PER_HISTORICAL_ROOT` from `presets/mainnet/phase0.yaml:42` /
    /// `presets/minimal/phase0.yaml:42`.
    const SLOTS_PER_HISTORICAL_ROOT: u64;

    /// `MIN_EPOCHS_TO_INACTIVITY_PENALTY` from `presets/mainnet/phase0.yaml:44` /
    /// `presets/minimal/phase0.yaml:44`.
    const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64;

    // -- State list lengths --
    /// `EPOCHS_PER_HISTORICAL_VECTOR` from `presets/mainnet/phase0.yaml:49` /
    /// `presets/minimal/phase0.yaml:49`.
    const EPOCHS_PER_HISTORICAL_VECTOR: u64;

    /// `EPOCHS_PER_SLASHINGS_VECTOR` from `presets/mainnet/phase0.yaml:51` /
    /// `presets/minimal/phase0.yaml:51`.
    const EPOCHS_PER_SLASHINGS_VECTOR: u64;

    /// `HISTORICAL_ROOTS_LIMIT` from `presets/mainnet/phase0.yaml:53` /
    /// `presets/minimal/phase0.yaml:53`.
    const HISTORICAL_ROOTS_LIMIT: u64;

    /// `VALIDATOR_REGISTRY_LIMIT` from `presets/mainnet/phase0.yaml:55` /
    /// `presets/minimal/phase0.yaml:55`.
    const VALIDATOR_REGISTRY_LIMIT: u64;

    // -- Reward and penalty quotients --
    /// `BASE_REWARD_FACTOR` from `presets/mainnet/phase0.yaml:60` /
    /// `presets/minimal/phase0.yaml:60`.
    const BASE_REWARD_FACTOR: u64;

    /// `WHISTLEBLOWER_REWARD_QUOTIENT` from `presets/mainnet/phase0.yaml:62` /
    /// `presets/minimal/phase0.yaml:62`.
    const WHISTLEBLOWER_REWARD_QUOTIENT: u64;

    /// `PROPOSER_REWARD_QUOTIENT` from `presets/mainnet/phase0.yaml:64` /
    /// `presets/minimal/phase0.yaml:64`.
    const PROPOSER_REWARD_QUOTIENT: u64;

    /// `INACTIVITY_PENALTY_QUOTIENT` from `presets/mainnet/phase0.yaml:66` /
    /// `presets/minimal/phase0.yaml:66`.
    const INACTIVITY_PENALTY_QUOTIENT: u64;

    /// `MIN_SLASHING_PENALTY_QUOTIENT` from `presets/mainnet/phase0.yaml:68` /
    /// `presets/minimal/phase0.yaml:68`.
    const MIN_SLASHING_PENALTY_QUOTIENT: u64;

    /// `PROPORTIONAL_SLASHING_MULTIPLIER` from `presets/mainnet/phase0.yaml:70` /
    /// `presets/minimal/phase0.yaml:70`.
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64;

    // -- Max operations per block --
    /// `MAX_PROPOSER_SLASHINGS` from `presets/mainnet/phase0.yaml:75` /
    /// `presets/minimal/phase0.yaml:75`.
    const MAX_PROPOSER_SLASHINGS: u64;

    /// `MAX_ATTESTER_SLASHINGS` from `presets/mainnet/phase0.yaml:77` /
    /// `presets/minimal/phase0.yaml:77`.
    const MAX_ATTESTER_SLASHINGS: u64;

    /// `MAX_ATTESTATIONS` from `presets/mainnet/phase0.yaml:79` /
    /// `presets/minimal/phase0.yaml:79`.
    const MAX_ATTESTATIONS: u64;

    /// `MAX_DEPOSITS` from `presets/mainnet/phase0.yaml:81` /
    /// `presets/minimal/phase0.yaml:81`.
    const MAX_DEPOSITS: u64;

    /// `MAX_VOLUNTARY_EXITS` from `presets/mainnet/phase0.yaml:83` /
    /// `presets/minimal/phase0.yaml:83`.
    const MAX_VOLUNTARY_EXITS: u64;

    // -- Non-configurable spec constants (from specs/phase0/beacon-chain.md:186-196) --
    /// `JUSTIFICATION_BITS_LENGTH` per `specs/phase0/beacon-chain.md:195`.
    const JUSTIFICATION_BITS_LENGTH: u64;

    /// `DEPOSIT_CONTRACT_TREE_DEPTH` per `specs/phase0/beacon-chain.md:194`.
    const DEPOSIT_CONTRACT_TREE_DEPTH: u64;

    /// `BASE_REWARDS_PER_EPOCH` per `specs/phase0/beacon-chain.md:193`.
    const BASE_REWARDS_PER_EPOCH: u64;

    // -- Derived/compound constants (B2/B3 fix) --
    // These are pre-computed literals so container field types never use
    // compound expressions (`A * B`) in const-generic positions.

    /// `ETH1_DATA_VOTES_LIMIT` = `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`.
    ///
    /// Used by `BeaconState::eth1_data_votes` limit per
    /// `specs/phase0/beacon-chain.md:576`.
    const ETH1_DATA_VOTES_LIMIT: u64;

    /// `MAX_PENDING_ATTESTATIONS` = `MAX_ATTESTATIONS * SLOTS_PER_EPOCH`.
    ///
    /// Used by `BeaconState::previous/current_epoch_attestations` per
    /// `specs/phase0/beacon-chain.md:582-583`.
    const MAX_PENDING_ATTESTATIONS: u64;

    /// `DEPOSIT_PROOF_LENGTH` = `DEPOSIT_CONTRACT_TREE_DEPTH + 1`.
    ///
    /// Used by `Deposit::proof` per `specs/phase0/beacon-chain.md:522`.
    const DEPOSIT_PROOF_LENGTH: u64;

    /// Human-readable preset name (e.g. `"mainnet"`, `"minimal"`).
    fn name() -> &'static str;
}

// ── MainnetEthSpec ─────────────────────────────────────────────────────────────

/// Mainnet Phase 0 preset.
///
/// All constants sourced from `presets/mainnet/phase0.yaml`.
/// Non-configurable constants from `specs/phase0/beacon-chain.md:186-196`.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct MainnetEthSpec;

impl EthSpec for MainnetEthSpec {
    // -- Misc --
    /// `MAX_COMMITTEES_PER_SLOT` from `presets/mainnet/phase0.yaml:6`.
    const MAX_COMMITTEES_PER_SLOT: u64 = 64;
    /// `TARGET_COMMITTEE_SIZE` from `presets/mainnet/phase0.yaml:8`.
    const TARGET_COMMITTEE_SIZE: u64 = 128;
    /// `MAX_VALIDATORS_PER_COMMITTEE` from `presets/mainnet/phase0.yaml:10`.
    const MAX_VALIDATORS_PER_COMMITTEE: u64 = 2048;
    /// `SHUFFLE_ROUND_COUNT` from `presets/mainnet/phase0.yaml:12`.
    const SHUFFLE_ROUND_COUNT: u64 = 90;
    /// `HYSTERESIS_QUOTIENT` from `presets/mainnet/phase0.yaml:14`.
    const HYSTERESIS_QUOTIENT: u64 = 4;
    /// `HYSTERESIS_DOWNWARD_MULTIPLIER` from `presets/mainnet/phase0.yaml:16`.
    const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;
    /// `HYSTERESIS_UPWARD_MULTIPLIER` from `presets/mainnet/phase0.yaml:18`.
    const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;

    // -- Gwei values --
    /// `MIN_DEPOSIT_AMOUNT` from `presets/mainnet/phase0.yaml:23`.
    const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000_000;
    /// `MAX_EFFECTIVE_BALANCE` from `presets/mainnet/phase0.yaml:25`.
    const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
    /// `EFFECTIVE_BALANCE_INCREMENT` from `presets/mainnet/phase0.yaml:27`.
    const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;

    // -- Time parameters --
    /// `MIN_ATTESTATION_INCLUSION_DELAY` from `presets/mainnet/phase0.yaml:32`.
    const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;
    /// `SLOTS_PER_EPOCH` from `presets/mainnet/phase0.yaml:34`.
    const SLOTS_PER_EPOCH: u64 = 32;
    /// `MIN_SEED_LOOKAHEAD` from `presets/mainnet/phase0.yaml:36`.
    const MIN_SEED_LOOKAHEAD: u64 = 1;
    /// `MAX_SEED_LOOKAHEAD` from `presets/mainnet/phase0.yaml:38`.
    const MAX_SEED_LOOKAHEAD: u64 = 4;
    /// `EPOCHS_PER_ETH1_VOTING_PERIOD` from `presets/mainnet/phase0.yaml:40`.
    const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 64;
    /// `SLOTS_PER_HISTORICAL_ROOT` from `presets/mainnet/phase0.yaml:42`.
    const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
    /// `MIN_EPOCHS_TO_INACTIVITY_PENALTY` from `presets/mainnet/phase0.yaml:44`.
    const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;

    // -- State list lengths --
    /// `EPOCHS_PER_HISTORICAL_VECTOR` from `presets/mainnet/phase0.yaml:49`.
    const EPOCHS_PER_HISTORICAL_VECTOR: u64 = 65536;
    /// `EPOCHS_PER_SLASHINGS_VECTOR` from `presets/mainnet/phase0.yaml:51`.
    const EPOCHS_PER_SLASHINGS_VECTOR: u64 = 8192;
    /// `HISTORICAL_ROOTS_LIMIT` from `presets/mainnet/phase0.yaml:53`.
    const HISTORICAL_ROOTS_LIMIT: u64 = 16_777_216;
    /// `VALIDATOR_REGISTRY_LIMIT` from `presets/mainnet/phase0.yaml:55`.
    const VALIDATOR_REGISTRY_LIMIT: u64 = 1_099_511_627_776;

    // -- Reward and penalty quotients --
    /// `BASE_REWARD_FACTOR` from `presets/mainnet/phase0.yaml:60`.
    const BASE_REWARD_FACTOR: u64 = 64;
    /// `WHISTLEBLOWER_REWARD_QUOTIENT` from `presets/mainnet/phase0.yaml:62`.
    const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 512;
    /// `PROPOSER_REWARD_QUOTIENT` from `presets/mainnet/phase0.yaml:64`.
    const PROPOSER_REWARD_QUOTIENT: u64 = 8;
    /// `INACTIVITY_PENALTY_QUOTIENT` from `presets/mainnet/phase0.yaml:66`.
    const INACTIVITY_PENALTY_QUOTIENT: u64 = 67_108_864;
    /// `MIN_SLASHING_PENALTY_QUOTIENT` from `presets/mainnet/phase0.yaml:68`.
    const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 128;
    /// `PROPORTIONAL_SLASHING_MULTIPLIER` from `presets/mainnet/phase0.yaml:70`.
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 1;

    // -- Max operations per block --
    /// `MAX_PROPOSER_SLASHINGS` from `presets/mainnet/phase0.yaml:75`.
    const MAX_PROPOSER_SLASHINGS: u64 = 16;
    /// `MAX_ATTESTER_SLASHINGS` from `presets/mainnet/phase0.yaml:77`.
    const MAX_ATTESTER_SLASHINGS: u64 = 2;
    /// `MAX_ATTESTATIONS` from `presets/mainnet/phase0.yaml:79`.
    const MAX_ATTESTATIONS: u64 = 128;
    /// `MAX_DEPOSITS` from `presets/mainnet/phase0.yaml:81`.
    const MAX_DEPOSITS: u64 = 16;
    /// `MAX_VOLUNTARY_EXITS` from `presets/mainnet/phase0.yaml:83`.
    const MAX_VOLUNTARY_EXITS: u64 = 16;

    // -- Non-configurable spec constants --
    /// `JUSTIFICATION_BITS_LENGTH` per `specs/phase0/beacon-chain.md:195`.
    const JUSTIFICATION_BITS_LENGTH: u64 = 4;
    /// `DEPOSIT_CONTRACT_TREE_DEPTH` per `specs/phase0/beacon-chain.md:194`.
    const DEPOSIT_CONTRACT_TREE_DEPTH: u64 = 32;
    /// `BASE_REWARDS_PER_EPOCH` per `specs/phase0/beacon-chain.md:193`.
    const BASE_REWARDS_PER_EPOCH: u64 = 4;

    // -- Derived constants --
    /// `ETH1_DATA_VOTES_LIMIT` = 64 * 32 = 2048.
    /// Sources: `presets/mainnet/phase0.yaml:40` (EPOCHS_PER_ETH1_VOTING_PERIOD=64),
    ///          `presets/mainnet/phase0.yaml:34` (SLOTS_PER_EPOCH=32).
    const ETH1_DATA_VOTES_LIMIT: u64 = 2048;
    /// `MAX_PENDING_ATTESTATIONS` = 128 * 32 = 4096.
    /// Sources: `presets/mainnet/phase0.yaml:79` (MAX_ATTESTATIONS=128),
    ///          `presets/mainnet/phase0.yaml:34` (SLOTS_PER_EPOCH=32).
    const MAX_PENDING_ATTESTATIONS: u64 = 4096;
    /// `DEPOSIT_PROOF_LENGTH` = 32 + 1 = 33.
    /// Source: `specs/phase0/beacon-chain.md:194` (DEPOSIT_CONTRACT_TREE_DEPTH=32).
    const DEPOSIT_PROOF_LENGTH: u64 = 33;

    fn name() -> &'static str {
        "mainnet"
    }
}

// ── MinimalEthSpec ─────────────────────────────────────────────────────────────

/// Minimal Phase 0 preset (for testing; smaller list bounds).
///
/// All constants sourced from `presets/minimal/phase0.yaml`.
/// Non-configurable constants from `specs/phase0/beacon-chain.md:186-196`.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct MinimalEthSpec;

impl EthSpec for MinimalEthSpec {
    // -- Misc --
    /// `MAX_COMMITTEES_PER_SLOT` from `presets/minimal/phase0.yaml:6`.
    const MAX_COMMITTEES_PER_SLOT: u64 = 4;
    /// `TARGET_COMMITTEE_SIZE` from `presets/minimal/phase0.yaml:8`.
    const TARGET_COMMITTEE_SIZE: u64 = 4;
    /// `MAX_VALIDATORS_PER_COMMITTEE` from `presets/minimal/phase0.yaml:10`.
    const MAX_VALIDATORS_PER_COMMITTEE: u64 = 2048;
    /// `SHUFFLE_ROUND_COUNT` from `presets/minimal/phase0.yaml:12`.
    const SHUFFLE_ROUND_COUNT: u64 = 10;
    /// `HYSTERESIS_QUOTIENT` from `presets/minimal/phase0.yaml:14`.
    const HYSTERESIS_QUOTIENT: u64 = 4;
    /// `HYSTERESIS_DOWNWARD_MULTIPLIER` from `presets/minimal/phase0.yaml:16`.
    const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;
    /// `HYSTERESIS_UPWARD_MULTIPLIER` from `presets/minimal/phase0.yaml:18`.
    const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;

    // -- Gwei values --
    /// `MIN_DEPOSIT_AMOUNT` from `presets/minimal/phase0.yaml:23`.
    const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000_000;
    /// `MAX_EFFECTIVE_BALANCE` from `presets/minimal/phase0.yaml:25`.
    const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
    /// `EFFECTIVE_BALANCE_INCREMENT` from `presets/minimal/phase0.yaml:27`.
    const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;

    // -- Time parameters --
    /// `MIN_ATTESTATION_INCLUSION_DELAY` from `presets/minimal/phase0.yaml:32`.
    const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;
    /// `SLOTS_PER_EPOCH` from `presets/minimal/phase0.yaml:34`.
    const SLOTS_PER_EPOCH: u64 = 8;
    /// `MIN_SEED_LOOKAHEAD` from `presets/minimal/phase0.yaml:36`.
    const MIN_SEED_LOOKAHEAD: u64 = 1;
    /// `MAX_SEED_LOOKAHEAD` from `presets/minimal/phase0.yaml:38`.
    const MAX_SEED_LOOKAHEAD: u64 = 4;
    /// `EPOCHS_PER_ETH1_VOTING_PERIOD` from `presets/minimal/phase0.yaml:40`.
    const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 4;
    /// `SLOTS_PER_HISTORICAL_ROOT` from `presets/minimal/phase0.yaml:42`.
    const SLOTS_PER_HISTORICAL_ROOT: u64 = 64;
    /// `MIN_EPOCHS_TO_INACTIVITY_PENALTY` from `presets/minimal/phase0.yaml:44`.
    const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;

    // -- State list lengths --
    /// `EPOCHS_PER_HISTORICAL_VECTOR` from `presets/minimal/phase0.yaml:49`.
    const EPOCHS_PER_HISTORICAL_VECTOR: u64 = 64;
    /// `EPOCHS_PER_SLASHINGS_VECTOR` from `presets/minimal/phase0.yaml:51`.
    const EPOCHS_PER_SLASHINGS_VECTOR: u64 = 64;
    /// `HISTORICAL_ROOTS_LIMIT` from `presets/minimal/phase0.yaml:53`.
    const HISTORICAL_ROOTS_LIMIT: u64 = 16_777_216;
    /// `VALIDATOR_REGISTRY_LIMIT` from `presets/minimal/phase0.yaml:55`.
    const VALIDATOR_REGISTRY_LIMIT: u64 = 1_099_511_627_776;

    // -- Reward and penalty quotients --
    /// `BASE_REWARD_FACTOR` from `presets/minimal/phase0.yaml:60`.
    const BASE_REWARD_FACTOR: u64 = 64;
    /// `WHISTLEBLOWER_REWARD_QUOTIENT` from `presets/minimal/phase0.yaml:62`.
    const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 512;
    /// `PROPOSER_REWARD_QUOTIENT` from `presets/minimal/phase0.yaml:64`.
    const PROPOSER_REWARD_QUOTIENT: u64 = 8;
    /// `INACTIVITY_PENALTY_QUOTIENT` from `presets/minimal/phase0.yaml:66`.
    const INACTIVITY_PENALTY_QUOTIENT: u64 = 33_554_432;
    /// `MIN_SLASHING_PENALTY_QUOTIENT` from `presets/minimal/phase0.yaml:68`.
    const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 64;
    /// `PROPORTIONAL_SLASHING_MULTIPLIER` from `presets/minimal/phase0.yaml:70`.
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 2;

    // -- Max operations per block --
    /// `MAX_PROPOSER_SLASHINGS` from `presets/minimal/phase0.yaml:75`.
    const MAX_PROPOSER_SLASHINGS: u64 = 16;
    /// `MAX_ATTESTER_SLASHINGS` from `presets/minimal/phase0.yaml:77`.
    const MAX_ATTESTER_SLASHINGS: u64 = 2;
    /// `MAX_ATTESTATIONS` from `presets/minimal/phase0.yaml:79`.
    const MAX_ATTESTATIONS: u64 = 128;
    /// `MAX_DEPOSITS` from `presets/minimal/phase0.yaml:81`.
    const MAX_DEPOSITS: u64 = 16;
    /// `MAX_VOLUNTARY_EXITS` from `presets/minimal/phase0.yaml:83`.
    const MAX_VOLUNTARY_EXITS: u64 = 16;

    // -- Non-configurable spec constants --
    /// `JUSTIFICATION_BITS_LENGTH` per `specs/phase0/beacon-chain.md:195`.
    const JUSTIFICATION_BITS_LENGTH: u64 = 4;
    /// `DEPOSIT_CONTRACT_TREE_DEPTH` per `specs/phase0/beacon-chain.md:194`.
    const DEPOSIT_CONTRACT_TREE_DEPTH: u64 = 32;
    /// `BASE_REWARDS_PER_EPOCH` per `specs/phase0/beacon-chain.md:193`.
    const BASE_REWARDS_PER_EPOCH: u64 = 4;

    // -- Derived constants --
    /// `ETH1_DATA_VOTES_LIMIT` = 4 * 8 = 32.
    /// Sources: `presets/minimal/phase0.yaml:40` (EPOCHS_PER_ETH1_VOTING_PERIOD=4),
    ///          `presets/minimal/phase0.yaml:34` (SLOTS_PER_EPOCH=8).
    const ETH1_DATA_VOTES_LIMIT: u64 = 32;
    /// `MAX_PENDING_ATTESTATIONS` = 128 * 8 = 1024.
    /// Sources: `presets/minimal/phase0.yaml:79` (MAX_ATTESTATIONS=128),
    ///          `presets/minimal/phase0.yaml:34` (SLOTS_PER_EPOCH=8).
    const MAX_PENDING_ATTESTATIONS: u64 = 1024;
    /// `DEPOSIT_PROOF_LENGTH` = 32 + 1 = 33.
    /// Source: `specs/phase0/beacon-chain.md:194` (DEPOSIT_CONTRACT_TREE_DEPTH=32).
    const DEPOSIT_PROOF_LENGTH: u64 = 33;

    fn name() -> &'static str {
        "minimal"
    }
}
