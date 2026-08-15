//! Runtime configuration overlay for Pharos.
//!
//! `RuntimeConfig` holds the full set of preset numeric constants and the fork
//! schedule. It is a runtime-owned value so the node can be pointed at an
//! arbitrary network (mainnet, devnet, etc.) without recompiling.
//!
//! The `EthSpec` trait consts are compile-time bounds on container sizes; this
//! struct carries the same values as a flat struct that can be loaded from YAML
//! at startup (Phase 8 adds the YAML loader).
//!
//! Default impl returns the mainnet configuration via
//! `MainnetEthSpec::default_runtime_config()`.

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
