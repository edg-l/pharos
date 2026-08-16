//! Preset constant assertion tests for `MainnetBeaconSpec` and `MinimalBeaconSpec`.
//!
//! Each assertion is hardcoded against the preset YAML files:
//! - `presets/mainnet/phase0.yaml`
//! - `presets/minimal/phase0.yaml`
//!
//! The non-configurable constants come from `specs/phase0/beacon-chain.md:186-196`.
//!
//! If any value here fails, it indicates a typo in the `BeaconSpec` impl.

use pharos_types::{BeaconSpec, MainnetBeaconSpec, MinimalBeaconSpec};

// ── Mainnet assertions ────────────────────────────────────────────────────────

#[test]
fn mainnet_slots_per_epoch() {
    // `presets/mainnet/phase0.yaml:34`
    assert_eq!(MainnetBeaconSpec::SLOTS_PER_EPOCH, 32);
}

#[test]
fn mainnet_max_effective_balance() {
    // `presets/mainnet/phase0.yaml:25`
    assert_eq!(MainnetBeaconSpec::MAX_EFFECTIVE_BALANCE, 32_000_000_000);
}

#[test]
fn mainnet_eth1_data_votes_limit() {
    // Derived: EPOCHS_PER_ETH1_VOTING_PERIOD(64) * SLOTS_PER_EPOCH(32) = 2048
    // `presets/mainnet/phase0.yaml:40,34`
    assert_eq!(MainnetBeaconSpec::ETH1_DATA_VOTES_LIMIT, 2048);
}

#[test]
fn mainnet_max_committees_per_slot() {
    // `presets/mainnet/phase0.yaml:6`
    assert_eq!(MainnetBeaconSpec::MAX_COMMITTEES_PER_SLOT, 64);
}

#[test]
fn mainnet_target_committee_size() {
    // `presets/mainnet/phase0.yaml:8`
    assert_eq!(MainnetBeaconSpec::TARGET_COMMITTEE_SIZE, 128);
}

#[test]
fn mainnet_max_validators_per_committee() {
    // `presets/mainnet/phase0.yaml:10`
    assert_eq!(MainnetBeaconSpec::MAX_VALIDATORS_PER_COMMITTEE, 2048);
}

#[test]
fn mainnet_shuffle_round_count() {
    // `presets/mainnet/phase0.yaml:12`
    assert_eq!(MainnetBeaconSpec::SHUFFLE_ROUND_COUNT, 90);
}

#[test]
fn mainnet_hysteresis_quotient() {
    // `presets/mainnet/phase0.yaml:14`
    assert_eq!(MainnetBeaconSpec::HYSTERESIS_QUOTIENT, 4);
}

#[test]
fn mainnet_hysteresis_downward_multiplier() {
    // `presets/mainnet/phase0.yaml:16`
    assert_eq!(MainnetBeaconSpec::HYSTERESIS_DOWNWARD_MULTIPLIER, 1);
}

#[test]
fn mainnet_hysteresis_upward_multiplier() {
    // `presets/mainnet/phase0.yaml:18`
    assert_eq!(MainnetBeaconSpec::HYSTERESIS_UPWARD_MULTIPLIER, 5);
}

#[test]
fn mainnet_min_deposit_amount() {
    // `presets/mainnet/phase0.yaml:23`
    assert_eq!(MainnetBeaconSpec::MIN_DEPOSIT_AMOUNT, 1_000_000_000);
}

#[test]
fn mainnet_effective_balance_increment() {
    // `presets/mainnet/phase0.yaml:27`
    assert_eq!(
        MainnetBeaconSpec::EFFECTIVE_BALANCE_INCREMENT,
        1_000_000_000
    );
}

#[test]
fn mainnet_min_attestation_inclusion_delay() {
    // `presets/mainnet/phase0.yaml:32`
    assert_eq!(MainnetBeaconSpec::MIN_ATTESTATION_INCLUSION_DELAY, 1);
}

#[test]
fn mainnet_min_seed_lookahead() {
    // `presets/mainnet/phase0.yaml:36`
    assert_eq!(MainnetBeaconSpec::MIN_SEED_LOOKAHEAD, 1);
}

#[test]
fn mainnet_max_seed_lookahead() {
    // `presets/mainnet/phase0.yaml:38`
    assert_eq!(MainnetBeaconSpec::MAX_SEED_LOOKAHEAD, 4);
}

#[test]
fn mainnet_epochs_per_eth1_voting_period() {
    // `presets/mainnet/phase0.yaml:40`
    assert_eq!(MainnetBeaconSpec::EPOCHS_PER_ETH1_VOTING_PERIOD, 64);
}

#[test]
fn mainnet_slots_per_historical_root() {
    // `presets/mainnet/phase0.yaml:42`
    assert_eq!(MainnetBeaconSpec::SLOTS_PER_HISTORICAL_ROOT, 8192);
}

#[test]
fn mainnet_min_epochs_to_inactivity_penalty() {
    // `presets/mainnet/phase0.yaml:44`
    assert_eq!(MainnetBeaconSpec::MIN_EPOCHS_TO_INACTIVITY_PENALTY, 4);
}

#[test]
fn mainnet_epochs_per_historical_vector() {
    // `presets/mainnet/phase0.yaml:49`
    assert_eq!(MainnetBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR, 65536);
}

#[test]
fn mainnet_epochs_per_slashings_vector() {
    // `presets/mainnet/phase0.yaml:51`
    assert_eq!(MainnetBeaconSpec::EPOCHS_PER_SLASHINGS_VECTOR, 8192);
}

#[test]
fn mainnet_historical_roots_limit() {
    // `presets/mainnet/phase0.yaml:53`
    assert_eq!(MainnetBeaconSpec::HISTORICAL_ROOTS_LIMIT, 16_777_216);
}

#[test]
fn mainnet_validator_registry_limit() {
    // `presets/mainnet/phase0.yaml:55`
    assert_eq!(
        MainnetBeaconSpec::VALIDATOR_REGISTRY_LIMIT,
        1_099_511_627_776
    );
}

#[test]
fn mainnet_base_reward_factor() {
    // `presets/mainnet/phase0.yaml:60`
    assert_eq!(MainnetBeaconSpec::BASE_REWARD_FACTOR, 64);
}

#[test]
fn mainnet_whistleblower_reward_quotient() {
    // `presets/mainnet/phase0.yaml:62`
    assert_eq!(MainnetBeaconSpec::WHISTLEBLOWER_REWARD_QUOTIENT, 512);
}

#[test]
fn mainnet_proposer_reward_quotient() {
    // `presets/mainnet/phase0.yaml:64`
    assert_eq!(MainnetBeaconSpec::PROPOSER_REWARD_QUOTIENT, 8);
}

#[test]
fn mainnet_inactivity_penalty_quotient() {
    // `presets/mainnet/phase0.yaml:66`
    assert_eq!(MainnetBeaconSpec::INACTIVITY_PENALTY_QUOTIENT, 67_108_864);
}

#[test]
fn mainnet_min_slashing_penalty_quotient() {
    // `presets/mainnet/phase0.yaml:68`
    assert_eq!(MainnetBeaconSpec::MIN_SLASHING_PENALTY_QUOTIENT, 128);
}

#[test]
fn mainnet_proportional_slashing_multiplier() {
    // `presets/mainnet/phase0.yaml:70`
    assert_eq!(MainnetBeaconSpec::PROPORTIONAL_SLASHING_MULTIPLIER, 1);
}

#[test]
fn mainnet_max_proposer_slashings() {
    // `presets/mainnet/phase0.yaml:75`
    assert_eq!(MainnetBeaconSpec::MAX_PROPOSER_SLASHINGS, 16);
}

#[test]
fn mainnet_max_attester_slashings() {
    // `presets/mainnet/phase0.yaml:77`
    assert_eq!(MainnetBeaconSpec::MAX_ATTESTER_SLASHINGS, 2);
}

#[test]
fn mainnet_max_attestations() {
    // `presets/mainnet/phase0.yaml:79`
    assert_eq!(MainnetBeaconSpec::MAX_ATTESTATIONS, 128);
}

#[test]
fn mainnet_max_deposits() {
    // `presets/mainnet/phase0.yaml:81`
    assert_eq!(MainnetBeaconSpec::MAX_DEPOSITS, 16);
}

#[test]
fn mainnet_max_voluntary_exits() {
    // `presets/mainnet/phase0.yaml:83`
    assert_eq!(MainnetBeaconSpec::MAX_VOLUNTARY_EXITS, 16);
}

#[test]
fn mainnet_justification_bits_length() {
    // `specs/phase0/beacon-chain.md:195`
    assert_eq!(MainnetBeaconSpec::JUSTIFICATION_BITS_LENGTH, 4);
}

#[test]
fn mainnet_deposit_contract_tree_depth() {
    // `specs/phase0/beacon-chain.md:194`
    assert_eq!(MainnetBeaconSpec::DEPOSIT_CONTRACT_TREE_DEPTH, 32);
}

#[test]
fn mainnet_base_rewards_per_epoch() {
    // `specs/phase0/beacon-chain.md:193`
    assert_eq!(MainnetBeaconSpec::BASE_REWARDS_PER_EPOCH, 4);
}

#[test]
fn mainnet_max_pending_attestations() {
    // Derived: MAX_ATTESTATIONS(128) * SLOTS_PER_EPOCH(32) = 4096
    // `presets/mainnet/phase0.yaml:79,34`
    assert_eq!(MainnetBeaconSpec::MAX_PENDING_ATTESTATIONS, 4096);
}

#[test]
fn mainnet_deposit_proof_length() {
    // Derived: DEPOSIT_CONTRACT_TREE_DEPTH(32) + 1 = 33
    // `specs/phase0/beacon-chain.md:194`
    assert_eq!(MainnetBeaconSpec::DEPOSIT_PROOF_LENGTH, 33);
}

// ── Minimal assertions ────────────────────────────────────────────────────────

#[test]
fn minimal_slots_per_epoch() {
    // `presets/minimal/phase0.yaml:34`
    assert_eq!(MinimalBeaconSpec::SLOTS_PER_EPOCH, 8);
}

#[test]
fn minimal_max_effective_balance() {
    // `presets/minimal/phase0.yaml:25`
    assert_eq!(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE, 32_000_000_000);
}

#[test]
fn minimal_eth1_data_votes_limit() {
    // Derived: EPOCHS_PER_ETH1_VOTING_PERIOD(4) * SLOTS_PER_EPOCH(8) = 32
    // `presets/minimal/phase0.yaml:40,34`
    assert_eq!(MinimalBeaconSpec::ETH1_DATA_VOTES_LIMIT, 32);
}

#[test]
fn minimal_epochs_per_eth1_voting_period() {
    // `presets/minimal/phase0.yaml:40`. Tested directly so a typo here
    // is not masked by the product test on ETH1_DATA_VOTES_LIMIT.
    assert_eq!(MinimalBeaconSpec::EPOCHS_PER_ETH1_VOTING_PERIOD, 4);
}

#[test]
fn minimal_max_committees_per_slot() {
    // `presets/minimal/phase0.yaml:6`
    assert_eq!(MinimalBeaconSpec::MAX_COMMITTEES_PER_SLOT, 4);
}

#[test]
fn minimal_target_committee_size() {
    // `presets/minimal/phase0.yaml:8`
    assert_eq!(MinimalBeaconSpec::TARGET_COMMITTEE_SIZE, 4);
}

#[test]
fn minimal_max_validators_per_committee() {
    // `presets/minimal/phase0.yaml:10`
    assert_eq!(MinimalBeaconSpec::MAX_VALIDATORS_PER_COMMITTEE, 2048);
}

#[test]
fn minimal_shuffle_round_count() {
    // `presets/minimal/phase0.yaml:12`
    assert_eq!(MinimalBeaconSpec::SHUFFLE_ROUND_COUNT, 10);
}

#[test]
fn minimal_slots_per_historical_root() {
    // `presets/minimal/phase0.yaml:42`
    assert_eq!(MinimalBeaconSpec::SLOTS_PER_HISTORICAL_ROOT, 64);
}

#[test]
fn minimal_epochs_per_historical_vector() {
    // `presets/minimal/phase0.yaml:49`
    assert_eq!(MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR, 64);
}

#[test]
fn minimal_epochs_per_slashings_vector() {
    // `presets/minimal/phase0.yaml:51`
    assert_eq!(MinimalBeaconSpec::EPOCHS_PER_SLASHINGS_VECTOR, 64);
}

#[test]
fn minimal_inactivity_penalty_quotient() {
    // `presets/minimal/phase0.yaml:66`
    assert_eq!(MinimalBeaconSpec::INACTIVITY_PENALTY_QUOTIENT, 33_554_432);
}

#[test]
fn minimal_min_slashing_penalty_quotient() {
    // `presets/minimal/phase0.yaml:68`
    assert_eq!(MinimalBeaconSpec::MIN_SLASHING_PENALTY_QUOTIENT, 64);
}

#[test]
fn minimal_proportional_slashing_multiplier() {
    // `presets/minimal/phase0.yaml:70`
    assert_eq!(MinimalBeaconSpec::PROPORTIONAL_SLASHING_MULTIPLIER, 2);
}

#[test]
fn minimal_max_pending_attestations() {
    // Derived: MAX_ATTESTATIONS(128) * SLOTS_PER_EPOCH(8) = 1024
    // `presets/minimal/phase0.yaml:79,34`
    assert_eq!(MinimalBeaconSpec::MAX_PENDING_ATTESTATIONS, 1024);
}

#[test]
fn minimal_deposit_proof_length() {
    // Derived: DEPOSIT_CONTRACT_TREE_DEPTH(32) + 1 = 33
    // Same as mainnet — DEPOSIT_CONTRACT_TREE_DEPTH is non-configurable.
    assert_eq!(MinimalBeaconSpec::DEPOSIT_PROOF_LENGTH, 33);
}

#[test]
fn minimal_justification_bits_length() {
    // `specs/phase0/beacon-chain.md:195` — same for all presets
    assert_eq!(MinimalBeaconSpec::JUSTIFICATION_BITS_LENGTH, 4);
}

#[test]
fn minimal_name() {
    assert_eq!(MinimalBeaconSpec::name(), "minimal");
}

#[test]
fn mainnet_name() {
    assert_eq!(MainnetBeaconSpec::name(), "mainnet");
}
