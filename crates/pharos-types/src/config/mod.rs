//! Runtime configuration overlay for Pharos.
//!
//! `RuntimeConfig` holds the full set of preset numeric constants and the fork
//! schedule. It is a runtime-owned value so the node can be pointed at an
//! arbitrary network (mainnet, devnet, etc.) without recompiling.
//!
//! The `EthSpec` trait consts are compile-time bounds on container sizes; this
//! struct carries the same values as a flat struct that can be loaded from YAML
//! at startup.
//!
//! Default impl returns the mainnet configuration via
//! `MainnetEthSpec::default_runtime_config()`.

pub mod loader;
pub use loader::{ConfigError, load_config_dir};

use crate::eth_spec::{EthSpec, MainnetEthSpec};

/// Runtime configuration snapshot.
///
/// Carries the full preset numeric set (altair constants included) plus the
/// fork schedule. Numeric fields mirror the corresponding `EthSpec` associated
/// consts; fork-schedule fields come from `configs/<network>.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    // -- Altair sync committee preset --
    /// `SYNC_COMMITTEE_SIZE` — per `presets/{mainnet,minimal}/altair.yaml`.
    pub sync_committee_size: u64,
    /// `SYNC_COMMITTEE_SUBNET_COUNT` — per `specs/altair/validator.md:80`.
    pub sync_committee_subnet_count: u64,
    /// `SYNC_SUBCOMMITTEE_SIZE` = `sync_committee_size / sync_committee_subnet_count`.
    pub sync_subcommittee_size: u64,
    /// `MIN_SYNC_COMMITTEE_PARTICIPANTS` — per `presets/{mainnet,minimal}/altair.yaml`.
    pub min_sync_committee_participants: u64,
    /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` — per `presets/{mainnet,minimal}/altair.yaml`.
    pub epochs_per_sync_committee_period: u64,
    /// `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE` — per `specs/altair/validator.md:79`.
    pub target_aggregators_per_sync_subcommittee: u64,
    /// `UPDATE_TIMEOUT` — `SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
    pub update_timeout: u64,

    // -- Altair reward and penalty quotients --
    /// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR` — per `presets/{mainnet,minimal}/altair.yaml`.
    pub inactivity_penalty_quotient_altair: u64,
    /// `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR` — per `presets/{mainnet,minimal}/altair.yaml`.
    pub min_slashing_penalty_quotient_altair: u64,
    /// `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR` — per `presets/{mainnet,minimal}/altair.yaml`.
    pub proportional_slashing_multiplier_altair: u64,

    // -- Altair validator cycle constants --
    /// `INACTIVITY_SCORE_BIAS` — per `configs/{mainnet,minimal}.yaml`.
    pub inactivity_score_bias: u64,
    /// `INACTIVITY_SCORE_RECOVERY_RATE` — per `configs/{mainnet,minimal}.yaml`.
    pub inactivity_score_recovery_rate: u64,

    // -- Time parameters --
    /// Slot duration in seconds, derived from `SLOT_DURATION_MS / 1000`.
    ///
    /// Mainnet: 12. Minimal: 6.
    pub seconds_per_slot: u64,

    // -- Fork schedule --
    /// `GENESIS_FORK_VERSION` from `configs/{mainnet,minimal}.yaml`.
    pub genesis_fork_version: [u8; 4],
    /// `ALTAIR_FORK_VERSION` from `configs/{mainnet,minimal}.yaml`.
    pub altair_fork_version: [u8; 4],
    /// `ALTAIR_FORK_EPOCH` from `configs/{mainnet,minimal}.yaml`.
    pub altair_fork_epoch: u64,
    /// `GENESIS_VALIDATORS_ROOT` — typically set at genesis; zero-default before genesis.
    pub genesis_validators_root: [u8; 32],
}

impl Default for RuntimeConfig {
    /// Returns the mainnet configuration.
    fn default() -> Self {
        MainnetEthSpec::default_runtime_config()
    }
}

impl RuntimeConfig {
    /// Assert that every numeric field that is shared between `RuntimeConfig`
    /// and `E: EthSpec` matches the compile-time constant value.
    ///
    /// Per `D-ethspec-yaml-loader`, dimension-bearing fields
    /// (`SYNC_COMMITTEE_SIZE`, `VALIDATOR_REGISTRY_LIMIT`, etc.) cannot be
    /// overridden at runtime; mismatches here indicate that the operator must
    /// recompile with the appropriate `EthSpec` preset binding. Non-dimension
    /// fields (fork epochs, slot durations, churn limits) may differ — the
    /// YAML values take precedence at runtime.
    ///
    /// Returns `Err` with a descriptive message on any dimension-field mismatch.
    pub fn assert_matches_preset<E: EthSpec>(&self) -> Result<(), loader::ConfigError> {
        macro_rules! check_field {
            ($field:expr, $cfg_val:expr, $spec_val:expr) => {
                if $cfg_val != $spec_val {
                    return Err(loader::ConfigError::InvalidValue {
                        field: $field,
                        value: format!(
                            "YAML value {} does not match compile-time EthSpec constant {} \
                             — recompile with the appropriate EthSpec preset to use this config",
                            $cfg_val, $spec_val
                        ),
                    });
                }
            };
        }

        // Dimension-bearing fields: a mismatch means the SSZ container sizes
        // in the binary are wrong for this network config.
        check_field!(
            "SYNC_COMMITTEE_SIZE",
            self.sync_committee_size,
            E::SYNC_COMMITTEE_SIZE
        );

        // Non-dimension preset fields that should also match the compiled preset.
        // These are not dimension-bearing but a mismatch signals preset confusion.
        check_field!(
            "SYNC_COMMITTEE_SUBNET_COUNT",
            self.sync_committee_subnet_count,
            E::SYNC_COMMITTEE_SUBNET_COUNT
        );
        check_field!(
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD",
            self.epochs_per_sync_committee_period,
            E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
        );
        check_field!(
            "INACTIVITY_PENALTY_QUOTIENT_ALTAIR",
            self.inactivity_penalty_quotient_altair,
            E::INACTIVITY_PENALTY_QUOTIENT_ALTAIR
        );
        check_field!(
            "MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR",
            self.min_slashing_penalty_quotient_altair,
            E::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR
        );
        check_field!(
            "PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR",
            self.proportional_slashing_multiplier_altair,
            E::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR
        );
        check_field!(
            "MIN_SYNC_COMMITTEE_PARTICIPANTS",
            self.min_sync_committee_participants,
            E::MIN_SYNC_COMMITTEE_PARTICIPANTS
        );
        check_field!("UPDATE_TIMEOUT", self.update_timeout, E::UPDATE_TIMEOUT);
        check_field!(
            "INACTIVITY_SCORE_BIAS",
            self.inactivity_score_bias,
            E::INACTIVITY_SCORE_BIAS
        );
        check_field!(
            "INACTIVITY_SCORE_RECOVERY_RATE",
            self.inactivity_score_recovery_rate,
            E::INACTIVITY_SCORE_RECOVERY_RATE
        );
        check_field!(
            "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE",
            self.target_aggregators_per_sync_subcommittee,
            E::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::eth_spec::{EthSpec, MainnetEthSpec, MinimalEthSpec};

    #[test]
    fn mainnet_altair_fork_epoch() {
        assert_eq!(
            MainnetEthSpec::default_runtime_config().altair_fork_epoch,
            74_240,
        );
    }

    #[test]
    fn minimal_altair_fork_epoch() {
        assert_eq!(
            MinimalEthSpec::default_runtime_config().altair_fork_epoch,
            0,
        );
    }

    #[test]
    fn mainnet_sync_committee_size() {
        assert_eq!(<MainnetEthSpec as EthSpec>::SYNC_COMMITTEE_SIZE, 512);
    }

    #[test]
    fn minimal_sync_committee_size() {
        assert_eq!(<MinimalEthSpec as EthSpec>::SYNC_COMMITTEE_SIZE, 32);
    }
}
