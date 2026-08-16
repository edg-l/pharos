//! `EthSpec` trait and preset implementations.
//!
//! Constants are sourced from:
//! - `presets/mainnet/phase0.yaml` and `presets/minimal/phase0.yaml` (preset constants).
//! - `presets/mainnet/altair.yaml` and `presets/minimal/altair.yaml` (altair preset constants).
//! - `configs/mainnet.yaml` and `configs/minimal.yaml` (config constants incl. fork schedule).
//! - `specs/phase0/beacon-chain.md:186-196` (non-configurable spec constants).
//! - `specs/altair/beacon-chain.md` (altair participation flag weights).
//! - `specs/altair/validator.md:79-80` (sync committee subnet count, aggregator target).

use std::fmt::Debug;
use std::str::FromStr;

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

    // -- Genesis / config constants (from configs/mainnet.yaml, configs/minimal.yaml) --

    /// `GENESIS_FORK_VERSION` — first 4 bytes of the fork version at genesis.
    ///
    /// Sources: `configs/mainnet.yaml:30`, `configs/minimal.yaml:27`.
    const GENESIS_FORK_VERSION: [u8; 4];

    /// `GENESIS_DELAY` in seconds between the Eth1 block timestamp and genesis.
    ///
    /// Sources: `configs/mainnet.yaml:32`, `configs/minimal.yaml:29`.
    const GENESIS_DELAY: u64;

    /// `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` — minimum active validators to trigger genesis.
    ///
    /// Sources: `configs/mainnet.yaml:26`, `configs/minimal.yaml:23`.
    const MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: u64;

    /// `MIN_GENESIS_TIME` — earliest allowed `genesis_time`.
    ///
    /// Sources: `configs/mainnet.yaml:28`, `configs/minimal.yaml:25`.
    const MIN_GENESIS_TIME: u64;

    /// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` in epochs.
    ///
    /// Sources: `configs/mainnet.yaml` (256), `configs/minimal.yaml` (256).
    const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64;

    /// `SHARD_COMMITTEE_PERIOD` in epochs.
    ///
    /// Sources: `configs/mainnet.yaml` (256), `configs/minimal.yaml` (64).
    const SHARD_COMMITTEE_PERIOD: u64;

    /// `MIN_PER_EPOCH_CHURN_LIMIT` — minimum validator churn per epoch.
    ///
    /// Sources: `configs/mainnet.yaml:119` (4), `configs/minimal.yaml:115` (2).
    const MIN_PER_EPOCH_CHURN_LIMIT: u64;

    /// `CHURN_LIMIT_QUOTIENT` — active validator count divisor for churn limit.
    ///
    /// Sources: `configs/mainnet.yaml` (65536), `configs/minimal.yaml` (32).
    const CHURN_LIMIT_QUOTIENT: u64;

    /// `SLOT_DURATION_MS` — slot duration in milliseconds.
    ///
    /// Sources: `configs/mainnet.yaml:68` (12000), `configs/minimal.yaml:64` (6000).
    /// Used by fork-choice `on_tick` and proposer-boost timing.
    const SLOT_DURATION_MS: u64;

    /// `ATTESTATION_DUE_BPS` — attestation deadline as basis points of `SLOT_DURATION_MS`.
    ///
    /// Sources: `configs/mainnet.yaml:80` (3333), `configs/minimal.yaml:76` (3333).
    /// Used by `record_block_timeliness` and proposer-boost timing.
    const ATTESTATION_DUE_BPS: u64;

    /// `BASIS_POINTS` — the basis-points denominator (10000).
    ///
    /// Per `specs/phase0/fork-choice.md` "Constant" section.
    const BASIS_POINTS: u64 = 10_000;

    // ── Altair preset constants ────────────────────────────────────────────────

    // -- Altair sync committee --
    // Source: `presets/mainnet/altair.yaml:15`, `presets/minimal/altair.yaml:15`

    /// `SYNC_COMMITTEE_SIZE` from `presets/mainnet/altair.yaml:15` /
    /// `presets/minimal/altair.yaml:15`.
    const SYNC_COMMITTEE_SIZE: u64;

    /// `SYNC_COMMITTEE_SUBNET_COUNT` from `specs/altair/validator.md:80`.
    ///
    /// Uniform across presets (always 4).
    const SYNC_COMMITTEE_SUBNET_COUNT: u64;

    /// `SYNC_SUBCOMMITTEE_SIZE` = `SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT`.
    ///
    /// Pre-computed literal (B2/B3) so SSZ bitvectors compile on stable Rust 1.85:
    /// a trait-level `const A / B` expression is not stabilised in this position.
    /// Mainnet: 512 / 4 = 128. Minimal: 32 / 4 = 8.
    const SYNC_SUBCOMMITTEE_SIZE: u64;

    /// `MIN_SYNC_COMMITTEE_PARTICIPANTS` from `presets/mainnet/altair.yaml:22` /
    /// `presets/minimal/altair.yaml:22`.
    const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64;

    /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` from `presets/mainnet/altair.yaml:17` /
    /// `presets/minimal/altair.yaml:17`.
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64;

    /// `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE` from `specs/altair/validator.md:79`.
    ///
    /// Uniform across presets (always 16).
    const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64;

    /// `UPDATE_TIMEOUT` from `presets/mainnet/altair.yaml:24` /
    /// `presets/minimal/altair.yaml:24`.
    ///
    /// Equals `SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
    const UPDATE_TIMEOUT: u64;

    // -- Altair reward and penalty quotients --
    // Source: `presets/mainnet/altair.yaml:6,8,10`, `presets/minimal/altair.yaml:6,8,10`

    /// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR` from `presets/mainnet/altair.yaml:6` /
    /// `presets/minimal/altair.yaml:6`.
    const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64;

    /// `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR` from `presets/mainnet/altair.yaml:8` /
    /// `presets/minimal/altair.yaml:8`.
    const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64;

    /// `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR` from `presets/mainnet/altair.yaml:10` /
    /// `presets/minimal/altair.yaml:10`.
    const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64;

    // -- Altair validator cycle constants --
    // Source: `configs/mainnet.yaml:113,115`, `configs/minimal.yaml:109,111`

    /// `INACTIVITY_SCORE_BIAS` from `configs/mainnet.yaml:113` /
    /// `configs/minimal.yaml:109`.
    const INACTIVITY_SCORE_BIAS: u64;

    /// `INACTIVITY_SCORE_RECOVERY_RATE` from `configs/mainnet.yaml:115` /
    /// `configs/minimal.yaml:111`.
    const INACTIVITY_SCORE_RECOVERY_RATE: u64;

    // -- Altair fork schedule --
    // Source: `configs/mainnet.yaml:41-42`, `configs/minimal.yaml:37-38`

    /// `ALTAIR_FORK_VERSION` from `configs/mainnet.yaml:41` /
    /// `configs/minimal.yaml:37`.
    const ALTAIR_FORK_VERSION: [u8; 4];

    /// `ALTAIR_FORK_EPOCH` from `configs/mainnet.yaml:42` /
    /// `configs/minimal.yaml:38`.
    const ALTAIR_FORK_EPOCH: u64;

    // ── Bellatrix preset constants ─────────────────────────────────────────────

    // -- Bellatrix reward and penalty quotients --
    // Source: `presets/mainnet/bellatrix.yaml`, `presets/minimal/bellatrix.yaml`

    /// `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `2**24 = 16,777,216`.
    const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64;

    /// `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `2**5 = 32`.
    const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64;

    /// `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `3`.
    const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64;

    // -- Bellatrix execution limits --
    // Source: `presets/mainnet/bellatrix.yaml`, `presets/minimal/bellatrix.yaml`

    /// `MAX_BYTES_PER_TRANSACTION` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `2**30 = 1,073,741,824`.
    const MAX_BYTES_PER_TRANSACTION: u64;

    /// `MAX_TRANSACTIONS_PER_PAYLOAD` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `2**20 = 1,048,576`.
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64;

    /// `BYTES_PER_LOGS_BLOOM` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `2**8 = 256`.
    const BYTES_PER_LOGS_BLOOM: u64;

    /// `MAX_EXTRA_DATA_BYTES` from `presets/{mainnet,minimal}/bellatrix.yaml`.
    ///
    /// `2**5 = 32`.
    const MAX_EXTRA_DATA_BYTES: u64;

    // -- Bellatrix fork schedule --
    // Source: `configs/mainnet.yaml:44-45`, `configs/minimal.yaml:40-41`

    /// `BELLATRIX_FORK_VERSION` from `configs/mainnet.yaml:44` /
    /// `configs/minimal.yaml:40`.
    const BELLATRIX_FORK_VERSION: [u8; 4];

    /// `BELLATRIX_FORK_EPOCH` from `configs/mainnet.yaml:45` /
    /// `configs/minimal.yaml:41`.
    const BELLATRIX_FORK_EPOCH: u64;

    // ── Capella preset constants ───────────────────────────────────────────────

    /// `MAX_BLS_TO_EXECUTION_CHANGES` from `presets/{mainnet,minimal}/capella.yaml`.
    ///
    /// Both presets: `2**4 = 16`.
    const MAX_BLS_TO_EXECUTION_CHANGES: u64;

    /// `MAX_WITHDRAWALS_PER_PAYLOAD` from `presets/{mainnet,minimal}/capella.yaml`.
    ///
    /// Mainnet: `2**4 = 16`. Minimal: `2**2 = 4`.
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64;

    /// `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` from `presets/{mainnet,minimal}/capella.yaml`.
    ///
    /// Mainnet: `2**14 = 16384`. Minimal: `2**4 = 16`.
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64;

    /// `CAPELLA_FORK_VERSION` from `configs/mainnet.yaml` / `configs/minimal.yaml`.
    ///
    /// Mainnet: `0x03000000`. Minimal: `0x03000001`.
    const CAPELLA_FORK_VERSION: [u8; 4];

    // ── Deneb preset constants ─────────────────────────────────────────────────

    /// `DENEB_FORK_VERSION` from `configs/mainnet.yaml` / `configs/minimal.yaml`.
    ///
    /// Mainnet: `0x04000000`. Minimal: `0x04000001`.
    const DENEB_FORK_VERSION: [u8; 4];

    /// `MAX_BLOB_COMMITMENTS_PER_BLOCK` from `presets/{mainnet,minimal}/deneb.yaml`.
    ///
    /// Both presets: `4096`.
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64;

    /// `FIELD_ELEMENTS_PER_BLOB` from `presets/{mainnet,minimal}/deneb.yaml`.
    ///
    /// Both presets: `4096`.
    const FIELD_ELEMENTS_PER_BLOB: u64;

    /// `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` from `presets/{mainnet,minimal}/deneb.yaml`.
    ///
    /// Both presets: `17`.
    const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: u64;

    /// `BLOB_SIDECAR_SUBNET_COUNT` from `configs/mainnet.yaml` / `configs/minimal.yaml`.
    ///
    /// Both presets: `6`.
    const BLOB_SIDECAR_SUBNET_COUNT: u64;

    /// `MAX_REQUEST_BLOCKS_DENEB` from `configs/mainnet.yaml` / `configs/minimal.yaml`.
    ///
    /// Both presets: `128`.
    const MAX_REQUEST_BLOCKS_DENEB: u64;

    /// `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` from `configs/mainnet.yaml` / `configs/minimal.yaml`.
    ///
    /// Both presets: `4096`.
    const MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: u64;

    // -- Altair participation flag weights --
    // Source: `specs/altair/beacon-chain.md:84-89,105`
    // These are non-configurable spec constants, uniform across all presets.
    // Provided as associated consts with default values so impls need not repeat them.

    /// `[TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, TIMELY_HEAD_WEIGHT]`
    /// per `specs/altair/beacon-chain.md:84-86,105`.
    const PARTICIPATION_FLAG_WEIGHTS: [u64; 3] = [14, 26, 14];

    /// `WEIGHT_DENOMINATOR` per `specs/altair/beacon-chain.md:89`.
    ///
    /// Sum of all five incentivization weights (the three participation-flag
    /// weights plus `SYNC_REWARD_WEIGHT=2` and `PROPOSER_WEIGHT=8`).
    const WEIGHT_DENOMINATOR: u64 = 64;

    /// Human-readable preset name (e.g. `"mainnet"`, `"minimal"`).
    fn name() -> &'static str;

    /// Returns a `RuntimeConfig` snapshot populated from this preset's consts.
    ///
    /// Used as the `Default` impl for `RuntimeConfig` (mainnet) and as the
    /// starting point for runtime YAML overrides (Phase 8).
    fn default_runtime_config() -> crate::config::RuntimeConfig;

    /// Wrap a concrete phase0 `BeaconState` into the fork-enum `BeaconState`.
    ///
    /// Used by the conformance runner and any code that decodes raw phase0 SSZ
    /// (which has no fork-discriminant prefix) and needs to pass the result to
    /// STF functions that accept `E::BeaconState`.
    fn phase0_into_state(s: Self::Phase0BeaconState) -> Self::BeaconState;

    /// Wrap a concrete phase0 `SignedBeaconBlock` into the fork-enum `SignedBeaconBlock`.
    ///
    /// Used by the conformance runner when loading raw phase0 SSZ blocks from
    /// fixture files.
    fn phase0_into_signed_block(s: Self::Phase0SignedBeaconBlock) -> Self::SignedBeaconBlock;

    /// Wrap a concrete phase0 `BeaconBlock` into the fork-enum `BeaconBlock`.
    ///
    /// Used by the conformance runner when loading raw phase0 SSZ blocks from
    /// fixture files.
    fn phase0_into_block(s: Self::Phase0BeaconBlock) -> Self::BeaconBlock;

    /// Extract the block message from a fork-enum `SignedBeaconBlock` as a
    /// fork-enum `BeaconBlock`, dispatching on the signed block's variant.
    ///
    /// This is the fork-safe replacement for the
    /// `if let Some(_) = E::unwrap_<fork>_signed_block(..) { .. } else { .. }`
    /// chains: generic code cannot `match` on the associated type
    /// `Self::SignedBeaconBlock`, so those chains had no exhaustiveness check and
    /// a missing fork arm silently fell through to a wrong default (this is how
    /// the capella `beacon_block` gossip-validation bug — every capella block
    /// rejected as "unrecognised fork variant" — slipped in). The per-preset
    /// impl here is an EXHAUSTIVE `match` on the concrete enum, so adding a fork
    /// variant is a compile error in one place and every caller stays correct.
    fn signed_block_message(signed: &Self::SignedBeaconBlock) -> Self::BeaconBlock;

    /// Unwrap a fork-enum `SignedBeaconBlock` to the inner phase0 variant.
    ///
    /// Returns `Some` if the block is a `Phase0` variant, `None` otherwise.
    /// Used by the phase0 STF dispatcher to access the concrete inner block
    /// without going through `SignedBeaconBlockView::message()` (which panics
    /// on the fork-enum since it cannot return a reference to the contained
    /// concrete type as the fork-enum return type).
    fn unwrap_phase0_signed_block(
        s: &Self::SignedBeaconBlock,
    ) -> Option<&Self::Phase0SignedBeaconBlock>;

    /// Unwrap a fork-enum `SignedBeaconBlock` to the inner altair variant.
    ///
    /// Returns `Some` if the block is an `Altair` variant, `None` otherwise.
    /// Used by the altair STF dispatcher in `pharos-stf::lib`.
    fn unwrap_altair_signed_block(
        s: &Self::SignedBeaconBlock,
    ) -> Option<&Self::AltairSignedBeaconBlock>;

    /// Unwrap a fork-enum `BeaconState` to the inner altair variant.
    ///
    /// Returns `Some` if the state is an `Altair` variant, `None` otherwise.
    /// Used by the altair STF dispatcher in `pharos-stf::lib`.
    fn unwrap_altair_state(s: &Self::BeaconState) -> Option<&Self::AltairBeaconState>;

    /// Unwrap a fork-enum `BeaconState` to the inner phase0 variant (by value).
    fn into_phase0_state(s: Self::BeaconState) -> Option<Self::Phase0BeaconState>;

    /// Unwrap a fork-enum `BeaconState` to the inner altair variant (by value).
    fn into_altair_state(s: Self::BeaconState) -> Option<Self::AltairBeaconState>;

    /// Unwrap a fork-enum `BeaconState` to the inner bellatrix variant (by value).
    fn into_bellatrix_state(s: Self::BeaconState) -> Option<Self::BellatrixBeaconState>;

    /// Wrap a concrete altair `BeaconState` into the fork-enum `BeaconState`.
    fn altair_into_state(s: Self::AltairBeaconState) -> Self::BeaconState;

    /// Wrap a concrete altair `BeaconBlock` into the fork-enum `BeaconBlock`.
    ///
    /// Used by the conformance runner when loading raw altair SSZ blocks from
    /// fixture files (e.g. fork-choice anchor block).
    fn altair_into_block(s: Self::AltairBeaconBlock) -> Self::BeaconBlock;

    /// Wrap a concrete altair `SignedBeaconBlock` into the fork-enum `SignedBeaconBlock`.
    ///
    /// Used by the conformance runner when loading raw altair SSZ blocks from
    /// fixture files.
    fn altair_into_signed_block(s: Self::AltairSignedBeaconBlock) -> Self::SignedBeaconBlock;

    /// Unwrap a fork-enum `SignedBeaconBlock` to the inner bellatrix variant.
    ///
    /// Returns `Some` if the block is a `Bellatrix` variant, `None` otherwise.
    fn unwrap_bellatrix_signed_block(
        s: &Self::SignedBeaconBlock,
    ) -> Option<&Self::BellatrixSignedBeaconBlock>;

    /// Unwrap a fork-enum `BeaconState` to the inner bellatrix variant.
    ///
    /// Returns `Some` if the state is a `Bellatrix` variant, `None` otherwise.
    fn unwrap_bellatrix_state(s: &Self::BeaconState) -> Option<&Self::BellatrixBeaconState>;

    /// Wrap a concrete bellatrix `BeaconState` into the fork-enum `BeaconState`.
    fn bellatrix_into_state(s: Self::BellatrixBeaconState) -> Self::BeaconState;

    /// Wrap a concrete bellatrix `BeaconBlock` into the fork-enum `BeaconBlock`.
    fn bellatrix_into_block(s: Self::BellatrixBeaconBlock) -> Self::BeaconBlock;

    /// Wrap a concrete bellatrix `SignedBeaconBlock` into the fork-enum `SignedBeaconBlock`.
    fn bellatrix_into_signed_block(s: Self::BellatrixSignedBeaconBlock) -> Self::SignedBeaconBlock;

    /// Unwrap a fork-enum `BeaconBlock` to the inner phase0 variant.
    ///
    /// Returns `Some` if the block is a `Phase0` variant, `None` otherwise.
    /// Used by the light-client snapshot dispatcher to fetch unsigned phase0
    /// blocks from `fc_store.blocks`.
    fn unwrap_phase0_block(s: &Self::BeaconBlock) -> Option<&Self::Phase0BeaconBlock>;

    /// Unwrap a fork-enum `BeaconBlock` to the inner altair variant.
    ///
    /// Returns `Some` if the block is an `Altair` variant, `None` otherwise.
    /// Used by the light-client snapshot dispatcher to fetch unsigned altair
    /// blocks from `fc_store.blocks`.
    fn unwrap_altair_block(s: &Self::BeaconBlock) -> Option<&Self::AltairBeaconBlock>;

    /// Unwrap a fork-enum `BeaconBlock` to the inner bellatrix variant.
    ///
    /// Returns `Some` if the block is a `Bellatrix` variant, `None` otherwise.
    /// Used by merge-transition helpers in `pharos-fork-choice`.
    fn unwrap_bellatrix_block(s: &Self::BeaconBlock) -> Option<&Self::BellatrixBeaconBlock>;

    /// Check whether `block` is a merge-transition block relative to `pre_state`.
    ///
    /// Per `specs/bellatrix/beacon-chain.md:209-210`:
    /// returns `true` when the merge transition has not yet completed
    /// (`pre_state.latest_execution_payload_header == default()`) AND the
    /// block carries a non-default `ExecutionPayload`.
    ///
    /// Returns `false` for Phase0 / Altair blocks (no execution payload).
    fn is_merge_transition_block(pre_state: &Self::BeaconState, block: &Self::BeaconBlock) -> bool;

    /// Extract the EL `block_hash` from a Bellatrix fork-enum block.
    ///
    /// Returns `Some(hash)` for Bellatrix blocks; `None` for Phase0 / Altair
    /// (pre-merge, no execution payload).
    ///
    /// Used by the engine driver to compute `safe_block_hash` and
    /// `finalized_block_hash` per `specs/bellatrix/fork-choice.md:93-100`.
    fn get_execution_block_hash(block: &Self::BeaconBlock) -> Option<pharos_utils::Hash256>;

    /// Extract the EL `parent_hash` from a Bellatrix fork-enum block.
    ///
    /// Returns `Some(hash)` for Bellatrix blocks; `None` for Phase0 / Altair.
    ///
    /// Used by the merge-transition guard in `on_block` to obtain the
    /// `payload.parent_hash` needed for `validate_merge_block`.
    fn get_execution_payload_parent_hash(
        block: &Self::BeaconBlock,
    ) -> Option<pharos_utils::Hash256>;

    /// Extract a clone of the `ExecutionPayload` from a fork-enum `SignedBeaconBlock`.
    ///
    /// Returns `Some(payload)` for Bellatrix blocks; `None` for Phase0/Altair/Capella.
    ///
    /// Used by the block-ingestion loop to push the wire-format Bellatrix payload to the
    /// engine driver via `engine_newPayloadV1`. The clone is unavoidable because
    /// the ingestion loop needs ownership to pass across a `spawn_blocking` boundary.
    fn get_execution_payload(signed: &Self::SignedBeaconBlock) -> Option<Self::ExecutionPayload>;

    /// Extract a clone of the Capella `ExecutionPayload` from a fork-enum `SignedBeaconBlock`.
    ///
    /// Returns `Some(payload)` for Capella blocks; `None` for Phase0/Altair/Bellatrix.
    ///
    /// Used by the block-ingestion loop to push the wire-format Capella payload
    /// (with withdrawals) to the engine driver via `engine_newPayloadV2`.
    /// Wired in Phase 4 (`D-engine-v2-dispatch`).
    fn get_capella_execution_payload(
        signed: &Self::SignedBeaconBlock,
    ) -> Option<Self::CapellaExecutionPayload>;

    /// Extract the slot from a fork-enum `SignedBeaconBlock` without knowing the fork.
    ///
    /// The fork-enum `SignedBeaconBlockView::message()` is intentionally unimplemented
    /// (it cannot return a reference to a fork-enum `BeaconBlock` from a reference to the
    /// inner concrete type). This method matches on each variant directly so callers can
    /// obtain the block slot in a fork-agnostic way — necessary for `state_transition` to
    /// advance the pre-state to the target slot before dispatch (`D-live-fork-upgrade-trigger`).
    fn signed_block_slot(signed: &Self::SignedBeaconBlock) -> crate::phase0::Slot;

    // -- Container associated types (D7) --
    // These allow STF code to be generic over `<E: EthSpec>` and reference
    // `E::BeaconState`, `E::BeaconBlock`, etc. without naming the concrete
    // preset-stamped struct directly.
    //
    // `BeaconState`, `BeaconBlock`, `SignedBeaconBlock`, and `BeaconBlockBody`
    // are the fork-enum types from `crate::state`. The concrete phase0 and
    // altair inner types are exposed via `Phase0BeaconState` / `AltairBeaconState`
    // etc. so that STF code can unwrap to the per-fork concrete type.

    /// Fork-enum `BeaconState` for this preset (wraps Phase0 and Altair variants).
    type BeaconState: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconStateView;

    /// Phase0 inner `BeaconState` (unwrapped; used by phase0 STF entry).
    type Phase0BeaconState: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconStateView;

    /// Altair inner `BeaconState` (unwrapped; used by altair STF entry).
    type AltairBeaconState: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconStateView;

    /// Fork-enum `BeaconBlock` for this preset.
    type BeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockView;

    /// Phase0 inner `BeaconBlock` (unwrapped).
    type Phase0BeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockView;

    /// Altair inner `BeaconBlock` (unwrapped).
    type AltairBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockView;

    /// Fork-enum `SignedBeaconBlock` for this preset.
    type SignedBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::SignedBeaconBlockView;

    /// Phase0 inner `SignedBeaconBlock` (unwrapped).
    type Phase0SignedBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::SignedBeaconBlockView;

    /// Altair inner `SignedBeaconBlock` (unwrapped).
    type AltairSignedBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::SignedBeaconBlockView;

    /// Fork-enum `BeaconBlockBody` for this preset.
    type BeaconBlockBody: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockBodyView;

    /// Phase0 inner `BeaconBlockBody` (unwrapped).
    type Phase0BeaconBlockBody: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockBodyView;

    /// Altair inner `BeaconBlockBody` (unwrapped).
    type AltairBeaconBlockBody: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockBodyView;

    /// Bellatrix inner `BeaconState` (unwrapped; used by bellatrix STF entry).
    type BellatrixBeaconState: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconStateView;

    /// Bellatrix inner `BeaconBlock` (unwrapped).
    type BellatrixBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockView;

    /// Bellatrix inner `SignedBeaconBlock` (unwrapped).
    type BellatrixSignedBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::SignedBeaconBlockView<Message = Self::BellatrixBeaconBlock>;

    /// Bellatrix inner `BeaconBlockBody` (unwrapped).
    type BellatrixBeaconBlockBody: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockBodyView;

    /// Bellatrix `ExecutionPayload` for this preset.
    type ExecutionPayload: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Bellatrix `ExecutionPayloadHeader` for this preset.
    type ExecutionPayloadHeader: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Capella inner `BeaconState` (unwrapped; used by capella STF entry).
    type CapellaBeaconState: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconStateView;

    /// Capella inner `BeaconBlock` (unwrapped).
    type CapellaBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockView;

    /// Capella inner `SignedBeaconBlock` (unwrapped).
    type CapellaSignedBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::SignedBeaconBlockView<Message = Self::CapellaBeaconBlock>;

    /// Capella inner `BeaconBlockBody` (unwrapped).
    type CapellaBeaconBlockBody: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockBodyView;

    /// Capella `ExecutionPayload` for this preset.
    type CapellaExecutionPayload: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Capella `ExecutionPayloadHeader` for this preset.
    type CapellaExecutionPayloadHeader: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Wrap a concrete capella `BeaconState` into the fork-enum `BeaconState`.
    fn capella_into_state(s: Self::CapellaBeaconState) -> Self::BeaconState;

    /// Wrap a concrete capella `BeaconBlock` into the fork-enum `BeaconBlock`.
    fn capella_into_block(s: Self::CapellaBeaconBlock) -> Self::BeaconBlock;

    /// Wrap a concrete capella `SignedBeaconBlock` into the fork-enum `SignedBeaconBlock`.
    fn capella_into_signed_block(s: Self::CapellaSignedBeaconBlock) -> Self::SignedBeaconBlock;

    /// Unwrap a fork-enum `SignedBeaconBlock` to the inner capella variant.
    fn unwrap_capella_signed_block(
        s: &Self::SignedBeaconBlock,
    ) -> Option<&Self::CapellaSignedBeaconBlock>;

    /// Unwrap a fork-enum `BeaconState` to the inner capella variant.
    fn unwrap_capella_state(s: &Self::BeaconState) -> Option<&Self::CapellaBeaconState>;

    /// Unwrap a fork-enum `BeaconState` to the inner capella variant (by value).
    fn into_capella_state(s: Self::BeaconState) -> Option<Self::CapellaBeaconState>;

    /// Unwrap a fork-enum `BeaconBlock` to the inner capella variant.
    fn unwrap_capella_block(s: &Self::BeaconBlock) -> Option<&Self::CapellaBeaconBlock>;

    /// Altair `SignedContributionAndProof` for this preset.
    ///
    /// Mainnet: `SYNC_SUBCOMMITTEE_SIZE = 128` (`SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT`).
    /// Minimal: `SYNC_SUBCOMMITTEE_SIZE = 8`.
    type AltairSignedContributionAndProof: pharos_ssz::Encode
        + pharos_ssz::Decode
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Altair `LightClientBootstrap` for this preset.
    ///
    /// Mainnet: `SYNC_COMMITTEE_SIZE = 512`. Minimal: `SYNC_COMMITTEE_SIZE = 32`.
    type AltairLightClientBootstrap: pharos_ssz::Encode
        + pharos_ssz::Decode
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Altair `LightClientUpdate` for this preset.
    ///
    /// Mainnet: `SYNC_COMMITTEE_SIZE = 512`. Minimal: `SYNC_COMMITTEE_SIZE = 32`.
    type AltairLightClientUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Altair `LightClientFinalityUpdate` for this preset.
    type AltairLightClientFinalityUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + crate::views::LightClientFinalityUpdateView
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Altair `LightClientOptimisticUpdate` for this preset.
    type AltairLightClientOptimisticUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + crate::views::LightClientOptimisticUpdateView
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    // ── Capella light-client assoc types ──────────────────────────────────────

    /// Capella `LightClientBootstrap` for this preset.
    type CapellaLightClientBootstrap: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Capella `LightClientUpdate` for this preset.
    type CapellaLightClientUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Capella `LightClientFinalityUpdate` for this preset.
    type CapellaLightClientFinalityUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + crate::views::LightClientFinalityUpdateView
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Capella `LightClientOptimisticUpdate` for this preset.
    type CapellaLightClientOptimisticUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + crate::views::LightClientOptimisticUpdateView
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    // ── Deneb light-client assoc types ────────────────────────────────────────

    /// Deneb `LightClientBootstrap` for this preset.
    type DenebLightClientBootstrap: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Deneb `LightClientUpdate` for this preset.
    type DenebLightClientUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Deneb `LightClientFinalityUpdate` for this preset.
    type DenebLightClientFinalityUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + crate::views::LightClientFinalityUpdateView
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Deneb `LightClientOptimisticUpdate` for this preset.
    type DenebLightClientOptimisticUpdate: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + crate::views::LightClientOptimisticUpdateView
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    // ── Deneb associated types ─────────────────────────────────────────────────

    /// Deneb inner `BeaconState` (unwrapped; used by deneb STF entry).
    type DenebBeaconState: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconStateView;

    /// Deneb inner `BeaconBlock` (unwrapped).
    type DenebBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockView;

    /// Deneb inner `SignedBeaconBlock` (unwrapped).
    type DenebSignedBeaconBlock: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::SignedBeaconBlockView<Message = Self::DenebBeaconBlock>;

    /// Deneb inner `BeaconBlockBody` (unwrapped).
    type DenebBeaconBlockBody: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static
        + crate::views::BeaconBlockBodyView;

    /// Deneb `ExecutionPayload` for this preset.
    type DenebExecutionPayload: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Deneb `ExecutionPayloadHeader` for this preset.
    type DenebExecutionPayloadHeader: pharos_ssz::Encode
        + pharos_ssz::Decode
        + pharos_ssz::TreeHash
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync
        + 'static;

    /// Unwrap a fork-enum `BeaconState` to the inner deneb variant.
    fn unwrap_deneb_state(s: &Self::BeaconState) -> Option<&Self::DenebBeaconState>;

    /// Unwrap a fork-enum `BeaconState` to the inner deneb variant (by value).
    fn into_deneb_state(s: Self::BeaconState) -> Option<Self::DenebBeaconState>;

    /// Wrap a concrete deneb `BeaconState` into the fork-enum `BeaconState`.
    fn deneb_into_state(s: Self::DenebBeaconState) -> Self::BeaconState;

    /// Unwrap a fork-enum `BeaconBlock` to the inner deneb variant.
    fn unwrap_deneb_block(s: &Self::BeaconBlock) -> Option<&Self::DenebBeaconBlock>;

    /// Wrap a concrete deneb `BeaconBlock` into the fork-enum `BeaconBlock`.
    fn deneb_into_block(s: Self::DenebBeaconBlock) -> Self::BeaconBlock;

    /// Unwrap a fork-enum `SignedBeaconBlock` to the inner deneb variant.
    fn unwrap_deneb_signed_block(
        s: &Self::SignedBeaconBlock,
    ) -> Option<&Self::DenebSignedBeaconBlock>;

    /// Wrap a concrete deneb `SignedBeaconBlock` into the fork-enum `SignedBeaconBlock`.
    fn deneb_into_signed_block(s: Self::DenebSignedBeaconBlock) -> Self::SignedBeaconBlock;
}

// ── MainnetEthSpec ─────────────────────────────────────────────────────────────

/// Mainnet Phase 0 preset.
///
/// All constants sourced from `presets/mainnet/phase0.yaml`.
/// Non-configurable constants from `specs/phase0/beacon-chain.md:186-196`.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct MainnetEthSpec;

/// Emit the fork-enum dispatch methods of the `EthSpec` impl. These method
/// bodies are identical for every preset (they only plumb the preset's
/// concrete `BeaconState`/`BeaconBlock`/`SignedBeaconBlock`/`ExecutionPayload`
/// enum types), so each preset impl invokes this rather than re-typing them.
macro_rules! impl_fork_dispatch {
    ($state:ident, $block:ident, $signed:ident, $exec:ident) => {
        fn phase0_into_state(s: Self::Phase0BeaconState) -> Self::BeaconState {
            crate::state::$state::Phase0(s)
        }

        fn phase0_into_signed_block(s: Self::Phase0SignedBeaconBlock) -> Self::SignedBeaconBlock {
            crate::state::$signed::Phase0(s)
        }

        fn phase0_into_block(s: Self::Phase0BeaconBlock) -> Self::BeaconBlock {
            crate::state::$block::Phase0(s)
        }

        fn signed_block_message(signed: &Self::SignedBeaconBlock) -> Self::BeaconBlock {
            use crate::state::{$block as B, $signed as S};
            match signed {
                S::Phase0(b) => B::Phase0(b.message.clone()),
                S::Altair(b) => B::Altair(b.message.clone()),
                S::Bellatrix(b) => B::Bellatrix(b.message.clone()),
                S::Capella(b) => B::Capella(b.message.clone()),
                S::Deneb(b) => B::Deneb(b.message.clone()),
            }
        }

        fn unwrap_phase0_signed_block(
            s: &Self::SignedBeaconBlock,
        ) -> Option<&Self::Phase0SignedBeaconBlock> {
            match s {
                crate::state::$signed::Phase0(inner) => Some(inner),
                crate::state::$signed::Altair(_) => None,
                crate::state::$signed::Bellatrix(_) => None,
                crate::state::$signed::Capella(_) => None,
                crate::state::$signed::Deneb(_) => None,
            }
        }

        fn unwrap_altair_signed_block(
            s: &Self::SignedBeaconBlock,
        ) -> Option<&Self::AltairSignedBeaconBlock> {
            match s {
                crate::state::$signed::Altair(inner) => Some(inner),
                crate::state::$signed::Phase0(_) => None,
                crate::state::$signed::Bellatrix(_) => None,
                crate::state::$signed::Capella(_) => None,
                crate::state::$signed::Deneb(_) => None,
            }
        }

        fn unwrap_altair_state(s: &Self::BeaconState) -> Option<&Self::AltairBeaconState> {
            match s {
                crate::state::$state::Altair(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Capella(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn into_phase0_state(s: Self::BeaconState) -> Option<Self::Phase0BeaconState> {
            match s {
                crate::state::$state::Phase0(inner) => Some(inner),
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Capella(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn into_altair_state(s: Self::BeaconState) -> Option<Self::AltairBeaconState> {
            match s {
                crate::state::$state::Altair(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Capella(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn into_bellatrix_state(s: Self::BeaconState) -> Option<Self::BellatrixBeaconState> {
            match s {
                crate::state::$state::Bellatrix(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Capella(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn altair_into_state(s: Self::AltairBeaconState) -> Self::BeaconState {
            crate::state::$state::Altair(s)
        }

        fn altair_into_block(s: Self::AltairBeaconBlock) -> Self::BeaconBlock {
            crate::state::$block::Altair(s)
        }

        fn altair_into_signed_block(s: Self::AltairSignedBeaconBlock) -> Self::SignedBeaconBlock {
            crate::state::$signed::Altair(s)
        }

        fn unwrap_bellatrix_signed_block(
            s: &Self::SignedBeaconBlock,
        ) -> Option<&Self::BellatrixSignedBeaconBlock> {
            match s {
                crate::state::$signed::Bellatrix(inner) => Some(inner),
                crate::state::$signed::Phase0(_) => None,
                crate::state::$signed::Altair(_) => None,
                crate::state::$signed::Capella(_) => None,
                crate::state::$signed::Deneb(_) => None,
            }
        }

        fn unwrap_bellatrix_state(s: &Self::BeaconState) -> Option<&Self::BellatrixBeaconState> {
            match s {
                crate::state::$state::Bellatrix(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Capella(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn bellatrix_into_state(s: Self::BellatrixBeaconState) -> Self::BeaconState {
            crate::state::$state::Bellatrix(s)
        }

        fn bellatrix_into_block(s: Self::BellatrixBeaconBlock) -> Self::BeaconBlock {
            crate::state::$block::Bellatrix(s)
        }

        fn bellatrix_into_signed_block(
            s: Self::BellatrixSignedBeaconBlock,
        ) -> Self::SignedBeaconBlock {
            crate::state::$signed::Bellatrix(s)
        }

        fn unwrap_phase0_block(s: &Self::BeaconBlock) -> Option<&Self::Phase0BeaconBlock> {
            match s {
                crate::state::$block::Phase0(inner) => Some(inner),
                crate::state::$block::Altair(_) => None,
                crate::state::$block::Bellatrix(_) => None,
                crate::state::$block::Capella(_) => None,
                crate::state::$block::Deneb(_) => None,
            }
        }

        fn unwrap_altair_block(s: &Self::BeaconBlock) -> Option<&Self::AltairBeaconBlock> {
            match s {
                crate::state::$block::Altair(inner) => Some(inner),
                crate::state::$block::Phase0(_) => None,
                crate::state::$block::Bellatrix(_) => None,
                crate::state::$block::Capella(_) => None,
                crate::state::$block::Deneb(_) => None,
            }
        }

        fn unwrap_bellatrix_block(s: &Self::BeaconBlock) -> Option<&Self::BellatrixBeaconBlock> {
            match s {
                crate::state::$block::Bellatrix(inner) => Some(inner),
                crate::state::$block::Phase0(_) => None,
                crate::state::$block::Altair(_) => None,
                crate::state::$block::Capella(_) => None,
                crate::state::$block::Deneb(_) => None,
            }
        }

        fn is_merge_transition_block(
            pre_state: &Self::BeaconState,
            block: &Self::BeaconBlock,
        ) -> bool {
            use crate::bellatrix::ExecutionPayloadHeader;
            let bellatrix_state = match Self::unwrap_bellatrix_state(pre_state) {
                Some(s) => s,
                None => return false,
            };
            let bellatrix_block = match Self::unwrap_bellatrix_block(block) {
                Some(b) => b,
                None => return false,
            };
            let header_default = ExecutionPayloadHeader::<256, 32>::default();
            let merge_complete = bellatrix_state.latest_execution_payload_header != header_default;
            let empty_payload = crate::bellatrix::$exec::default();
            !merge_complete && bellatrix_block.body.execution_payload != empty_payload
        }

        fn get_execution_block_hash(block: &Self::BeaconBlock) -> Option<pharos_utils::Hash256> {
            match block {
                crate::state::$block::Bellatrix(b) => Some(b.body.execution_payload.block_hash),
                crate::state::$block::Capella(b) => Some(b.body.execution_payload.block_hash),
                crate::state::$block::Deneb(b) => Some(b.body.execution_payload.block_hash),
                crate::state::$block::Phase0(_) => None,
                crate::state::$block::Altair(_) => None,
            }
        }

        fn get_execution_payload_parent_hash(
            block: &Self::BeaconBlock,
        ) -> Option<pharos_utils::Hash256> {
            match block {
                crate::state::$block::Bellatrix(b) => Some(b.body.execution_payload.parent_hash),
                crate::state::$block::Capella(b) => Some(b.body.execution_payload.parent_hash),
                crate::state::$block::Deneb(b) => Some(b.body.execution_payload.parent_hash),
                crate::state::$block::Phase0(_) => None,
                crate::state::$block::Altair(_) => None,
            }
        }

        fn get_execution_payload(
            signed: &Self::SignedBeaconBlock,
        ) -> Option<Self::ExecutionPayload> {
            match signed {
                crate::state::$signed::Bellatrix(b) => {
                    Some(b.message.body.execution_payload.clone())
                }
                crate::state::$signed::Capella(_) => None,
                crate::state::$signed::Deneb(_) => None,
                crate::state::$signed::Phase0(_) => None,
                crate::state::$signed::Altair(_) => None,
            }
        }

        fn get_capella_execution_payload(
            signed: &Self::SignedBeaconBlock,
        ) -> Option<Self::CapellaExecutionPayload> {
            match signed {
                crate::state::$signed::Capella(b) => Some(b.message.body.execution_payload.clone()),
                crate::state::$signed::Bellatrix(_) => None,
                crate::state::$signed::Deneb(_) => None,
                crate::state::$signed::Phase0(_) => None,
                crate::state::$signed::Altair(_) => None,
            }
        }

        fn signed_block_slot(signed: &Self::SignedBeaconBlock) -> crate::phase0::Slot {
            match signed {
                crate::state::$signed::Phase0(b) => b.message.slot,
                crate::state::$signed::Altair(b) => b.message.slot,
                crate::state::$signed::Bellatrix(b) => b.message.slot,
                crate::state::$signed::Capella(b) => b.message.slot,
                crate::state::$signed::Deneb(b) => b.message.slot,
            }
        }

        fn capella_into_state(s: Self::CapellaBeaconState) -> Self::BeaconState {
            crate::state::$state::Capella(s)
        }

        fn capella_into_block(s: Self::CapellaBeaconBlock) -> Self::BeaconBlock {
            crate::state::$block::Capella(s)
        }

        fn capella_into_signed_block(s: Self::CapellaSignedBeaconBlock) -> Self::SignedBeaconBlock {
            crate::state::$signed::Capella(s)
        }

        fn unwrap_capella_signed_block(
            s: &Self::SignedBeaconBlock,
        ) -> Option<&Self::CapellaSignedBeaconBlock> {
            match s {
                crate::state::$signed::Capella(inner) => Some(inner),
                crate::state::$signed::Phase0(_) => None,
                crate::state::$signed::Altair(_) => None,
                crate::state::$signed::Bellatrix(_) => None,
                crate::state::$signed::Deneb(_) => None,
            }
        }

        fn unwrap_capella_state(s: &Self::BeaconState) -> Option<&Self::CapellaBeaconState> {
            match s {
                crate::state::$state::Capella(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn into_capella_state(s: Self::BeaconState) -> Option<Self::CapellaBeaconState> {
            match s {
                crate::state::$state::Capella(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Deneb(_) => None,
            }
        }

        fn unwrap_capella_block(s: &Self::BeaconBlock) -> Option<&Self::CapellaBeaconBlock> {
            match s {
                crate::state::$block::Capella(inner) => Some(inner),
                crate::state::$block::Phase0(_) => None,
                crate::state::$block::Altair(_) => None,
                crate::state::$block::Bellatrix(_) => None,
                crate::state::$block::Deneb(_) => None,
            }
        }

        fn unwrap_deneb_state(s: &Self::BeaconState) -> Option<&Self::DenebBeaconState> {
            match s {
                crate::state::$state::Deneb(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Capella(_) => None,
            }
        }

        fn into_deneb_state(s: Self::BeaconState) -> Option<Self::DenebBeaconState> {
            match s {
                crate::state::$state::Deneb(inner) => Some(inner),
                crate::state::$state::Phase0(_) => None,
                crate::state::$state::Altair(_) => None,
                crate::state::$state::Bellatrix(_) => None,
                crate::state::$state::Capella(_) => None,
            }
        }

        fn deneb_into_state(s: Self::DenebBeaconState) -> Self::BeaconState {
            crate::state::$state::Deneb(s)
        }

        fn unwrap_deneb_block(s: &Self::BeaconBlock) -> Option<&Self::DenebBeaconBlock> {
            match s {
                crate::state::$block::Deneb(inner) => Some(inner),
                crate::state::$block::Phase0(_) => None,
                crate::state::$block::Altair(_) => None,
                crate::state::$block::Bellatrix(_) => None,
                crate::state::$block::Capella(_) => None,
            }
        }

        fn deneb_into_block(s: Self::DenebBeaconBlock) -> Self::BeaconBlock {
            crate::state::$block::Deneb(s)
        }

        fn unwrap_deneb_signed_block(
            s: &Self::SignedBeaconBlock,
        ) -> Option<&Self::DenebSignedBeaconBlock> {
            match s {
                crate::state::$signed::Deneb(inner) => Some(inner),
                crate::state::$signed::Phase0(_) => None,
                crate::state::$signed::Altair(_) => None,
                crate::state::$signed::Bellatrix(_) => None,
                crate::state::$signed::Capella(_) => None,
            }
        }

        fn deneb_into_signed_block(s: Self::DenebSignedBeaconBlock) -> Self::SignedBeaconBlock {
            crate::state::$signed::Deneb(s)
        }
    };
}

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

    // -- Genesis / config constants --
    /// `GENESIS_FORK_VERSION` from `configs/mainnet.yaml:30`.
    const GENESIS_FORK_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    /// `GENESIS_DELAY` from `configs/mainnet.yaml:32` (604800 = 7 days).
    const GENESIS_DELAY: u64 = 604_800;
    /// `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` from `configs/mainnet.yaml:26`.
    const MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: u64 = 16_384;
    /// `MIN_GENESIS_TIME` from `configs/mainnet.yaml:28`.
    const MIN_GENESIS_TIME: u64 = 1_606_824_000;
    /// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` from `configs/mainnet.yaml`.
    const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
    /// `SHARD_COMMITTEE_PERIOD` from `configs/mainnet.yaml`.
    const SHARD_COMMITTEE_PERIOD: u64 = 256;
    /// `MIN_PER_EPOCH_CHURN_LIMIT` from `configs/mainnet.yaml:119`.
    const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 4;
    /// `CHURN_LIMIT_QUOTIENT` from `configs/mainnet.yaml`.
    const CHURN_LIMIT_QUOTIENT: u64 = 65_536;
    /// `SLOT_DURATION_MS` from `configs/mainnet.yaml:68`.
    const SLOT_DURATION_MS: u64 = 12_000;
    /// `ATTESTATION_DUE_BPS` from `configs/mainnet.yaml:80`.
    const ATTESTATION_DUE_BPS: u64 = 3_333;

    // ── Altair preset constants ────────────────────────────────────────────────

    // -- Altair sync committee --
    /// `SYNC_COMMITTEE_SIZE` from `presets/mainnet/altair.yaml:15`.
    const SYNC_COMMITTEE_SIZE: u64 = 512;
    /// `SYNC_COMMITTEE_SUBNET_COUNT` from `specs/altair/validator.md:80`.
    const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;
    /// `SYNC_SUBCOMMITTEE_SIZE` = 512 / 4 = 128.
    const SYNC_SUBCOMMITTEE_SIZE: u64 = 128;
    /// `MIN_SYNC_COMMITTEE_PARTICIPANTS` from `presets/mainnet/altair.yaml:22`.
    const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;
    /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` from `presets/mainnet/altair.yaml:17`.
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
    /// `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE` from `specs/altair/validator.md:79`.
    const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;
    /// `UPDATE_TIMEOUT` from `presets/mainnet/altair.yaml:24` (32 * 256 = 8192).
    const UPDATE_TIMEOUT: u64 = 8_192;

    // -- Altair reward and penalty quotients --
    /// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR` from `presets/mainnet/altair.yaml:6`.
    const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = 50_331_648;
    /// `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR` from `presets/mainnet/altair.yaml:8`.
    const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64 = 64;
    /// `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR` from `presets/mainnet/altair.yaml:10`.
    const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64 = 2;

    // -- Altair validator cycle constants --
    /// `INACTIVITY_SCORE_BIAS` from `configs/mainnet.yaml:113`.
    const INACTIVITY_SCORE_BIAS: u64 = 4;
    /// `INACTIVITY_SCORE_RECOVERY_RATE` from `configs/mainnet.yaml:115`.
    const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;

    // -- Altair fork schedule --
    /// `ALTAIR_FORK_VERSION` from `configs/mainnet.yaml:41`.
    const ALTAIR_FORK_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
    /// `ALTAIR_FORK_EPOCH` from `configs/mainnet.yaml:42`.
    const ALTAIR_FORK_EPOCH: u64 = 74_240;

    // ── Bellatrix preset constants ────────────────────────────────────────────

    // -- Bellatrix reward and penalty quotients --
    /// `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` from `presets/mainnet/bellatrix.yaml`.
    const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 16_777_216;
    /// `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX` from `presets/mainnet/bellatrix.yaml`.
    const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64 = 32;
    /// `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` from `presets/mainnet/bellatrix.yaml`.
    const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;

    // -- Bellatrix execution limits --
    /// `MAX_BYTES_PER_TRANSACTION` from `presets/mainnet/bellatrix.yaml`.
    const MAX_BYTES_PER_TRANSACTION: u64 = 1_073_741_824;
    /// `MAX_TRANSACTIONS_PER_PAYLOAD` from `presets/mainnet/bellatrix.yaml`.
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64 = 1_048_576;
    /// `BYTES_PER_LOGS_BLOOM` from `presets/mainnet/bellatrix.yaml`.
    const BYTES_PER_LOGS_BLOOM: u64 = 256;
    /// `MAX_EXTRA_DATA_BYTES` from `presets/mainnet/bellatrix.yaml`.
    const MAX_EXTRA_DATA_BYTES: u64 = 32;

    // -- Bellatrix fork schedule --
    /// `BELLATRIX_FORK_VERSION` from `configs/mainnet.yaml:44`.
    const BELLATRIX_FORK_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
    /// `BELLATRIX_FORK_EPOCH` from `configs/mainnet.yaml:45`.
    const BELLATRIX_FORK_EPOCH: u64 = 144_896;

    // ── Capella preset constants ─────────────────────────────────────────────

    // -- Capella max operations --
    /// `MAX_BLS_TO_EXECUTION_CHANGES` from `presets/mainnet/capella.yaml`.
    const MAX_BLS_TO_EXECUTION_CHANGES: u64 = 16;
    /// `MAX_WITHDRAWALS_PER_PAYLOAD` from `presets/mainnet/capella.yaml`.
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64 = 16;
    /// `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` from `presets/mainnet/capella.yaml`.
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16_384;

    // -- Capella fork schedule --
    /// `CAPELLA_FORK_VERSION` from `configs/mainnet.yaml`.
    const CAPELLA_FORK_VERSION: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

    // ── Deneb preset constants ────────────────────────────────────────────────

    /// `DENEB_FORK_VERSION` from `configs/mainnet.yaml`.
    const DENEB_FORK_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    /// `MAX_BLOB_COMMITMENTS_PER_BLOCK` from `presets/mainnet/deneb.yaml`.
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64 = 4096;
    /// `FIELD_ELEMENTS_PER_BLOB` from `presets/mainnet/deneb.yaml`.
    const FIELD_ELEMENTS_PER_BLOB: u64 = 4096;
    /// `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` from `presets/mainnet/deneb.yaml`.
    const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: u64 = 17;
    /// `BLOB_SIDECAR_SUBNET_COUNT` from `configs/mainnet.yaml`.
    const BLOB_SIDECAR_SUBNET_COUNT: u64 = 6;
    /// `MAX_REQUEST_BLOCKS_DENEB` from `configs/mainnet.yaml`.
    const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;
    /// `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` from `configs/mainnet.yaml`.
    const MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: u64 = 4096;

    fn name() -> &'static str {
        "mainnet"
    }

    fn default_runtime_config() -> crate::config::RuntimeConfig {
        crate::config::RuntimeConfig {
            sync_committee_size: Self::SYNC_COMMITTEE_SIZE,
            sync_committee_subnet_count: Self::SYNC_COMMITTEE_SUBNET_COUNT,
            sync_subcommittee_size: Self::SYNC_SUBCOMMITTEE_SIZE,
            min_sync_committee_participants: Self::MIN_SYNC_COMMITTEE_PARTICIPANTS,
            epochs_per_sync_committee_period: Self::EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
            target_aggregators_per_sync_subcommittee:
                Self::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
            update_timeout: Self::UPDATE_TIMEOUT,
            inactivity_penalty_quotient_altair: Self::INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
            min_slashing_penalty_quotient_altair: Self::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
            proportional_slashing_multiplier_altair: Self::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
            inactivity_score_bias: Self::INACTIVITY_SCORE_BIAS,
            inactivity_score_recovery_rate: Self::INACTIVITY_SCORE_RECOVERY_RATE,
            seconds_per_slot: Self::SLOT_DURATION_MS / 1000,
            genesis_fork_version: Self::GENESIS_FORK_VERSION,
            altair_fork_version: Self::ALTAIR_FORK_VERSION,
            altair_fork_epoch: Self::ALTAIR_FORK_EPOCH,
            genesis_validators_root: [0u8; 32],
            bellatrix_fork_version: Self::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: Self::BELLATRIX_FORK_EPOCH,
            capella_fork_version: Self::CAPELLA_FORK_VERSION,
            capella_fork_epoch: u64::MAX, // FAR_FUTURE_EPOCH (mainnet real epoch loaded from config at runtime)
            deneb_fork_version: Self::DENEB_FORK_VERSION,
            deneb_fork_epoch: u64::MAX, // FAR_FUTURE_EPOCH (mainnet real epoch loaded from config at runtime)
            max_blobs_per_block: 6, // mainnet default (configs/mainnet.yaml: MAX_BLOBS_PER_BLOCK_EL)
            max_per_epoch_activation_churn_limit: 8, // configs/mainnet.yaml: MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT
            // configs/mainnet.yaml: TERMINAL_TOTAL_DIFFICULTY: 58750000000000000000000
            terminal_total_difficulty: pharos_utils::Uint256::from_str("58750000000000000000000")
                .expect("valid TTD literal"),
            terminal_block_hash: pharos_utils::Hash256::default(),
            terminal_block_hash_activation_epoch: u64::MAX,
            inactivity_penalty_quotient_bellatrix: Self::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
            min_slashing_penalty_quotient_bellatrix: Self::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
            proportional_slashing_multiplier_bellatrix:
                Self::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
            max_bytes_per_transaction: Self::MAX_BYTES_PER_TRANSACTION,
            max_transactions_per_payload: Self::MAX_TRANSACTIONS_PER_PAYLOAD,
            bytes_per_logs_bloom: Self::BYTES_PER_LOGS_BLOOM,
            max_extra_data_bytes: Self::MAX_EXTRA_DATA_BYTES,
            // configs/mainnet.yaml: DEPOSIT_CONTRACT_ADDRESS
            deposit_contract_address: [
                0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe,
                0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
            ],
            // configs/mainnet.yaml: DEPOSIT_CHAIN_ID: 1 (Ethereum mainnet)
            deposit_chain_id: 1,
            slots_per_epoch: Self::SLOTS_PER_EPOCH,
        }
    }

    impl_fork_dispatch!(
        MainnetBeaconState,
        MainnetBeaconBlock,
        MainnetSignedBeaconBlock,
        MainnetExecutionPayload
    );

    // Fork-enum types (D7 / Task 1.9)
    type BeaconState = crate::state::MainnetBeaconState;
    type Phase0BeaconState = crate::phase0::MainnetBeaconState;
    type AltairBeaconState = crate::altair::MainnetBeaconState;

    type BeaconBlock = crate::state::BeaconBlock<
        16,            // MAX_PROPOSER_SLASHINGS
        2,             // MAX_ATTESTER_SLASHINGS
        128,           // MAX_ATTESTATIONS
        16,            // MAX_DEPOSITS
        16,            // MAX_VOLUNTARY_EXITS
        2048,          // MAX_VALIDATORS_PER_COMMITTEE
        33,            // DEPOSIT_PROOF_LENGTH
        512,           // SYNC_COMMITTEE_SIZE
        1_073_741_824, // MAX_BYTES_PER_TRANSACTION
        1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
        256,           // BYTES_PER_LOGS_BLOOM
        32,            // MAX_EXTRA_DATA_BYTES
        16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet capella)
        16,            // MAX_BLS_TO_EXECUTION_CHANGES
        4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK (deneb)
    >;
    type Phase0BeaconBlock = crate::phase0::MainnetBeaconBlock;
    type AltairBeaconBlock = crate::altair::MainnetBeaconBlock;

    type SignedBeaconBlock = crate::state::SignedBeaconBlock<
        16,            // MAX_PROPOSER_SLASHINGS
        2,             // MAX_ATTESTER_SLASHINGS
        128,           // MAX_ATTESTATIONS
        16,            // MAX_DEPOSITS
        16,            // MAX_VOLUNTARY_EXITS
        2048,          // MAX_VALIDATORS_PER_COMMITTEE
        33,            // DEPOSIT_PROOF_LENGTH
        512,           // SYNC_COMMITTEE_SIZE
        1_073_741_824, // MAX_BYTES_PER_TRANSACTION
        1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
        256,           // BYTES_PER_LOGS_BLOOM
        32,            // MAX_EXTRA_DATA_BYTES
        16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet capella)
        16,            // MAX_BLS_TO_EXECUTION_CHANGES
        4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK (deneb)
    >;
    type Phase0SignedBeaconBlock = crate::phase0::MainnetSignedBeaconBlock;
    type AltairSignedBeaconBlock = crate::altair::MainnetSignedBeaconBlock;

    type BeaconBlockBody = crate::state::BeaconBlockBody<
        16,            // MAX_PROPOSER_SLASHINGS
        2,             // MAX_ATTESTER_SLASHINGS
        128,           // MAX_ATTESTATIONS
        16,            // MAX_DEPOSITS
        16,            // MAX_VOLUNTARY_EXITS
        2048,          // MAX_VALIDATORS_PER_COMMITTEE
        33,            // DEPOSIT_PROOF_LENGTH
        512,           // SYNC_COMMITTEE_SIZE
        1_073_741_824, // MAX_BYTES_PER_TRANSACTION
        1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
        256,           // BYTES_PER_LOGS_BLOOM
        32,            // MAX_EXTRA_DATA_BYTES
        16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet capella)
        16,            // MAX_BLS_TO_EXECUTION_CHANGES
        4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK (deneb)
    >;
    type Phase0BeaconBlockBody = crate::phase0::MainnetBeaconBlockBody;
    type AltairBeaconBlockBody = crate::altair::MainnetBeaconBlockBody;
    type BellatrixBeaconState = crate::bellatrix::MainnetBeaconState;
    type BellatrixBeaconBlock = crate::bellatrix::MainnetBeaconBlock;
    type BellatrixSignedBeaconBlock = crate::bellatrix::MainnetSignedBeaconBlock;
    type BellatrixBeaconBlockBody = crate::bellatrix::MainnetBeaconBlockBody;
    type CapellaBeaconState = crate::capella::MainnetBeaconState;
    type CapellaBeaconBlock = crate::capella::MainnetBeaconBlock;
    type CapellaSignedBeaconBlock = crate::capella::MainnetSignedBeaconBlock;
    type CapellaBeaconBlockBody = crate::capella::MainnetBeaconBlockBody;
    /// Mainnet: `ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>` (bellatrix).
    type ExecutionPayload = crate::bellatrix::MainnetExecutionPayload;
    /// Mainnet: `ExecutionPayloadHeader<256, 32>` (bellatrix).
    type ExecutionPayloadHeader = crate::bellatrix::MainnetExecutionPayloadHeader;
    /// Mainnet capella `ExecutionPayload`.
    type CapellaExecutionPayload = crate::capella::MainnetExecutionPayload;
    /// Mainnet capella `ExecutionPayloadHeader`.
    type CapellaExecutionPayloadHeader = crate::capella::MainnetExecutionPayloadHeader;
    /// Mainnet: `SYNC_SUBCOMMITTEE_SIZE = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT = 512 / 4 = 128`.
    type AltairSignedContributionAndProof = crate::altair::SignedContributionAndProof<128>;
    /// Mainnet: `SYNC_COMMITTEE_SIZE = 512`.
    type AltairLightClientBootstrap = crate::altair::LightClientBootstrap<512>;
    /// Mainnet: `SYNC_COMMITTEE_SIZE = 512`.
    type AltairLightClientUpdate = crate::altair::LightClientUpdate<512>;
    /// Mainnet: `SYNC_COMMITTEE_SIZE = 512`.
    type AltairLightClientFinalityUpdate = crate::altair::LightClientFinalityUpdate<512>;
    /// Mainnet: `SYNC_COMMITTEE_SIZE = 512`.
    type AltairLightClientOptimisticUpdate = crate::altair::LightClientOptimisticUpdate<512>;
    /// Mainnet capella `LightClientBootstrap` (`SYNC_COMMITTEE_SIZE=512, BYTES_PER_LOGS_BLOOM=256, MAX_EXTRA_DATA_BYTES=32`).
    type CapellaLightClientBootstrap = crate::capella::MainnetLightClientBootstrap;
    /// Mainnet capella `LightClientUpdate`.
    type CapellaLightClientUpdate = crate::capella::MainnetLightClientUpdate;
    /// Mainnet capella `LightClientFinalityUpdate`.
    type CapellaLightClientFinalityUpdate = crate::capella::MainnetLightClientFinalityUpdate;
    /// Mainnet capella `LightClientOptimisticUpdate`.
    type CapellaLightClientOptimisticUpdate = crate::capella::MainnetLightClientOptimisticUpdate;
    /// Mainnet deneb `LightClientBootstrap`.
    type DenebLightClientBootstrap = crate::deneb::light_client::MainnetLightClientBootstrap;
    /// Mainnet deneb `LightClientUpdate`.
    type DenebLightClientUpdate = crate::deneb::light_client::MainnetLightClientUpdate;
    /// Mainnet deneb `LightClientFinalityUpdate`.
    type DenebLightClientFinalityUpdate =
        crate::deneb::light_client::MainnetLightClientFinalityUpdate;
    /// Mainnet deneb `LightClientOptimisticUpdate`.
    type DenebLightClientOptimisticUpdate =
        crate::deneb::light_client::MainnetLightClientOptimisticUpdate;

    // ── Deneb associated types ────────────────────────────────────────────────

    type DenebBeaconState = crate::deneb::MainnetBeaconState;
    type DenebBeaconBlock = crate::deneb::MainnetBeaconBlock;
    type DenebSignedBeaconBlock = crate::deneb::MainnetSignedBeaconBlock;
    type DenebBeaconBlockBody = crate::deneb::MainnetBeaconBlockBody;
    type DenebExecutionPayload = crate::deneb::MainnetExecutionPayload;
    type DenebExecutionPayloadHeader = crate::deneb::MainnetExecutionPayloadHeader;
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

    // -- Genesis / config constants --
    /// `GENESIS_FORK_VERSION` from `configs/minimal.yaml:27`.
    const GENESIS_FORK_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    /// `GENESIS_DELAY` from `configs/minimal.yaml:29` (300 seconds).
    const GENESIS_DELAY: u64 = 300;
    /// `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` from `configs/minimal.yaml:23`.
    const MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: u64 = 64;
    /// `MIN_GENESIS_TIME` from `configs/minimal.yaml:25`.
    const MIN_GENESIS_TIME: u64 = 1_578_009_600;
    /// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` from `configs/minimal.yaml`.
    const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
    /// `SHARD_COMMITTEE_PERIOD` from `configs/minimal.yaml`.
    const SHARD_COMMITTEE_PERIOD: u64 = 64;
    /// `MIN_PER_EPOCH_CHURN_LIMIT` from `configs/minimal.yaml:115`.
    const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 2;
    /// `CHURN_LIMIT_QUOTIENT` from `configs/minimal.yaml`.
    const CHURN_LIMIT_QUOTIENT: u64 = 32;
    /// `SLOT_DURATION_MS` from `configs/minimal.yaml:64`.
    const SLOT_DURATION_MS: u64 = 6_000;
    /// `ATTESTATION_DUE_BPS` from `configs/minimal.yaml:76`.
    const ATTESTATION_DUE_BPS: u64 = 3_333;

    // ── Altair preset constants ────────────────────────────────────────────────

    // -- Altair sync committee --
    /// `SYNC_COMMITTEE_SIZE` from `presets/minimal/altair.yaml:15`.
    const SYNC_COMMITTEE_SIZE: u64 = 32;
    /// `SYNC_COMMITTEE_SUBNET_COUNT` from `specs/altair/validator.md:80`.
    const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;
    /// `SYNC_SUBCOMMITTEE_SIZE` = 32 / 4 = 8.
    const SYNC_SUBCOMMITTEE_SIZE: u64 = 8;
    /// `MIN_SYNC_COMMITTEE_PARTICIPANTS` from `presets/minimal/altair.yaml:22`.
    const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;
    /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` from `presets/minimal/altair.yaml:17`.
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8;
    /// `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE` from `specs/altair/validator.md:79`.
    const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;
    /// `UPDATE_TIMEOUT` from `presets/minimal/altair.yaml:24` (8 * 8 = 64).
    const UPDATE_TIMEOUT: u64 = 64;

    // -- Altair reward and penalty quotients --
    /// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR` from `presets/minimal/altair.yaml:6`.
    const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = 50_331_648;
    /// `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR` from `presets/minimal/altair.yaml:8`.
    const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64 = 64;
    /// `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR` from `presets/minimal/altair.yaml:10`.
    const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64 = 2;

    // -- Altair validator cycle constants --
    /// `INACTIVITY_SCORE_BIAS` from `configs/minimal.yaml:109`.
    const INACTIVITY_SCORE_BIAS: u64 = 4;
    /// `INACTIVITY_SCORE_RECOVERY_RATE` from `configs/minimal.yaml:111`.
    const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;

    // -- Altair fork schedule --
    /// `ALTAIR_FORK_VERSION` from `configs/minimal.yaml:37`.
    const ALTAIR_FORK_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x01];
    /// `ALTAIR_FORK_EPOCH` from plan Task 0.3 (minimal preset activates altair at genesis).
    ///
    /// NOTE: `configs/minimal.yaml:38` sets this to FAR_FUTURE_EPOCH (2^64-1) for generic
    /// spec-test runs. The plan specifies `0` for the minimal preset to reflect a test
    /// configuration where altair is active from genesis. Use `RuntimeConfig` to override
    /// at runtime.
    const ALTAIR_FORK_EPOCH: u64 = 0;

    // ── Bellatrix preset constants ────────────────────────────────────────────

    // -- Bellatrix reward and penalty quotients --
    /// `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` from `presets/minimal/bellatrix.yaml`.
    const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 16_777_216;
    /// `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX` from `presets/minimal/bellatrix.yaml`.
    const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64 = 32;
    /// `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` from `presets/minimal/bellatrix.yaml`.
    const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;

    // -- Bellatrix execution limits --
    /// `MAX_BYTES_PER_TRANSACTION` from `presets/minimal/bellatrix.yaml`.
    const MAX_BYTES_PER_TRANSACTION: u64 = 1_073_741_824;
    /// `MAX_TRANSACTIONS_PER_PAYLOAD` from `presets/minimal/bellatrix.yaml`.
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64 = 1_048_576;
    /// `BYTES_PER_LOGS_BLOOM` from `presets/minimal/bellatrix.yaml`.
    const BYTES_PER_LOGS_BLOOM: u64 = 256;
    /// `MAX_EXTRA_DATA_BYTES` from `presets/minimal/bellatrix.yaml`.
    const MAX_EXTRA_DATA_BYTES: u64 = 32;

    // -- Bellatrix fork schedule --
    /// `BELLATRIX_FORK_VERSION` from `configs/minimal.yaml:40`.
    const BELLATRIX_FORK_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x01];
    /// `BELLATRIX_FORK_EPOCH` from `configs/minimal.yaml:41` (FAR_FUTURE_EPOCH).
    const BELLATRIX_FORK_EPOCH: u64 = u64::MAX;

    // ── Capella preset constants ─────────────────────────────────────────────

    // -- Capella max operations --
    /// `MAX_BLS_TO_EXECUTION_CHANGES` from `presets/minimal/capella.yaml`.
    const MAX_BLS_TO_EXECUTION_CHANGES: u64 = 16;
    /// `MAX_WITHDRAWALS_PER_PAYLOAD` from `presets/minimal/capella.yaml`.
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64 = 4;
    /// `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` from `presets/minimal/capella.yaml`.
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16;

    // -- Capella fork schedule --
    /// `CAPELLA_FORK_VERSION` from `configs/minimal.yaml`.
    const CAPELLA_FORK_VERSION: [u8; 4] = [0x03, 0x00, 0x00, 0x01];

    // ── Deneb preset constants ────────────────────────────────────────────────

    /// `DENEB_FORK_VERSION` from `configs/minimal.yaml`.
    const DENEB_FORK_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x01];
    /// `MAX_BLOB_COMMITMENTS_PER_BLOCK` from `presets/minimal/deneb.yaml`.
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64 = 4096;
    /// `FIELD_ELEMENTS_PER_BLOB` from `presets/minimal/deneb.yaml`.
    const FIELD_ELEMENTS_PER_BLOB: u64 = 4096;
    /// `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` from `presets/minimal/deneb.yaml`.
    const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: u64 = 17;
    /// `BLOB_SIDECAR_SUBNET_COUNT` from `configs/minimal.yaml`.
    const BLOB_SIDECAR_SUBNET_COUNT: u64 = 6;
    /// `MAX_REQUEST_BLOCKS_DENEB` from `configs/minimal.yaml`.
    const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;
    /// `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` from `configs/minimal.yaml`.
    const MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: u64 = 4096;

    fn name() -> &'static str {
        "minimal"
    }

    fn default_runtime_config() -> crate::config::RuntimeConfig {
        crate::config::RuntimeConfig {
            sync_committee_size: Self::SYNC_COMMITTEE_SIZE,
            sync_committee_subnet_count: Self::SYNC_COMMITTEE_SUBNET_COUNT,
            sync_subcommittee_size: Self::SYNC_SUBCOMMITTEE_SIZE,
            min_sync_committee_participants: Self::MIN_SYNC_COMMITTEE_PARTICIPANTS,
            epochs_per_sync_committee_period: Self::EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
            target_aggregators_per_sync_subcommittee:
                Self::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
            update_timeout: Self::UPDATE_TIMEOUT,
            inactivity_penalty_quotient_altair: Self::INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
            min_slashing_penalty_quotient_altair: Self::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
            proportional_slashing_multiplier_altair: Self::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
            inactivity_score_bias: Self::INACTIVITY_SCORE_BIAS,
            inactivity_score_recovery_rate: Self::INACTIVITY_SCORE_RECOVERY_RATE,
            seconds_per_slot: Self::SLOT_DURATION_MS / 1000,
            genesis_fork_version: Self::GENESIS_FORK_VERSION,
            altair_fork_version: Self::ALTAIR_FORK_VERSION,
            altair_fork_epoch: Self::ALTAIR_FORK_EPOCH,
            genesis_validators_root: [0u8; 32],
            bellatrix_fork_version: Self::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: Self::BELLATRIX_FORK_EPOCH,
            capella_fork_version: Self::CAPELLA_FORK_VERSION,
            capella_fork_epoch: u64::MAX, // FAR_FUTURE_EPOCH (minimal real epoch loaded from config at runtime)
            deneb_fork_version: Self::DENEB_FORK_VERSION,
            deneb_fork_epoch: u64::MAX,              // FAR_FUTURE_EPOCH
            max_blobs_per_block: 6,                  // minimal default
            max_per_epoch_activation_churn_limit: 4, // configs/minimal.yaml: MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT
            // configs/minimal.yaml: large TTD to prevent accidental merge on test networks
            terminal_total_difficulty: pharos_utils::Uint256::from_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129638912",
            )
            .expect("valid TTD literal"),
            terminal_block_hash: pharos_utils::Hash256::default(),
            terminal_block_hash_activation_epoch: u64::MAX,
            inactivity_penalty_quotient_bellatrix: Self::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
            min_slashing_penalty_quotient_bellatrix: Self::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
            proportional_slashing_multiplier_bellatrix:
                Self::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
            max_bytes_per_transaction: Self::MAX_BYTES_PER_TRANSACTION,
            max_transactions_per_payload: Self::MAX_TRANSACTIONS_PER_PAYLOAD,
            bytes_per_logs_bloom: Self::BYTES_PER_LOGS_BLOOM,
            max_extra_data_bytes: Self::MAX_EXTRA_DATA_BYTES,
            // configs/minimal.yaml: DEPOSIT_CONTRACT_ADDRESS (same as mainnet)
            deposit_contract_address: [
                0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe,
                0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
            ],
            // configs/minimal.yaml: DEPOSIT_CHAIN_ID: 1
            deposit_chain_id: 1,
            slots_per_epoch: Self::SLOTS_PER_EPOCH,
        }
    }

    impl_fork_dispatch!(
        MinimalBeaconState,
        MinimalBeaconBlock,
        MinimalSignedBeaconBlock,
        MinimalExecutionPayload
    );

    // Fork-enum types (D7 / Task 1.9)
    type BeaconState = crate::state::MinimalBeaconState;
    type Phase0BeaconState = crate::phase0::MinimalBeaconState;
    type AltairBeaconState = crate::altair::MinimalBeaconState;

    type BeaconBlock = crate::state::BeaconBlock<
        16,            // MAX_PROPOSER_SLASHINGS
        2,             // MAX_ATTESTER_SLASHINGS
        128,           // MAX_ATTESTATIONS
        16,            // MAX_DEPOSITS
        16,            // MAX_VOLUNTARY_EXITS
        2048,          // MAX_VALIDATORS_PER_COMMITTEE
        33,            // DEPOSIT_PROOF_LENGTH
        32,            // SYNC_COMMITTEE_SIZE
        1_073_741_824, // MAX_BYTES_PER_TRANSACTION
        1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
        256,           // BYTES_PER_LOGS_BLOOM
        32,            // MAX_EXTRA_DATA_BYTES
        4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal capella)
        16,            // MAX_BLS_TO_EXECUTION_CHANGES
        4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK (deneb)
    >;
    type Phase0BeaconBlock = crate::phase0::MinimalBeaconBlock;
    type AltairBeaconBlock = crate::altair::MinimalBeaconBlock;

    type SignedBeaconBlock = crate::state::SignedBeaconBlock<
        16,            // MAX_PROPOSER_SLASHINGS
        2,             // MAX_ATTESTER_SLASHINGS
        128,           // MAX_ATTESTATIONS
        16,            // MAX_DEPOSITS
        16,            // MAX_VOLUNTARY_EXITS
        2048,          // MAX_VALIDATORS_PER_COMMITTEE
        33,            // DEPOSIT_PROOF_LENGTH
        32,            // SYNC_COMMITTEE_SIZE
        1_073_741_824, // MAX_BYTES_PER_TRANSACTION
        1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
        256,           // BYTES_PER_LOGS_BLOOM
        32,            // MAX_EXTRA_DATA_BYTES
        4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal capella)
        16,            // MAX_BLS_TO_EXECUTION_CHANGES
        4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK (deneb)
    >;
    type Phase0SignedBeaconBlock = crate::phase0::MinimalSignedBeaconBlock;
    type AltairSignedBeaconBlock = crate::altair::MinimalSignedBeaconBlock;

    type BeaconBlockBody = crate::state::BeaconBlockBody<
        16,            // MAX_PROPOSER_SLASHINGS
        2,             // MAX_ATTESTER_SLASHINGS
        128,           // MAX_ATTESTATIONS
        16,            // MAX_DEPOSITS
        16,            // MAX_VOLUNTARY_EXITS
        2048,          // MAX_VALIDATORS_PER_COMMITTEE
        33,            // DEPOSIT_PROOF_LENGTH
        32,            // SYNC_COMMITTEE_SIZE
        1_073_741_824, // MAX_BYTES_PER_TRANSACTION
        1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
        256,           // BYTES_PER_LOGS_BLOOM
        32,            // MAX_EXTRA_DATA_BYTES
        4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal capella)
        16,            // MAX_BLS_TO_EXECUTION_CHANGES
        4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK (deneb)
    >;
    type Phase0BeaconBlockBody = crate::phase0::MinimalBeaconBlockBody;
    type AltairBeaconBlockBody = crate::altair::MinimalBeaconBlockBody;
    type BellatrixBeaconState = crate::bellatrix::MinimalBeaconState;
    type BellatrixBeaconBlock = crate::bellatrix::MinimalBeaconBlock;
    type BellatrixSignedBeaconBlock = crate::bellatrix::MinimalSignedBeaconBlock;
    type BellatrixBeaconBlockBody = crate::bellatrix::MinimalBeaconBlockBody;
    type CapellaBeaconState = crate::capella::MinimalBeaconState;
    type CapellaBeaconBlock = crate::capella::MinimalBeaconBlock;
    type CapellaSignedBeaconBlock = crate::capella::MinimalSignedBeaconBlock;
    type CapellaBeaconBlockBody = crate::capella::MinimalBeaconBlockBody;
    /// Minimal: `ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>` (bellatrix).
    type ExecutionPayload = crate::bellatrix::MinimalExecutionPayload;
    /// Minimal: `ExecutionPayloadHeader<256, 32>` (bellatrix).
    type ExecutionPayloadHeader = crate::bellatrix::MinimalExecutionPayloadHeader;
    /// Minimal capella `ExecutionPayload`.
    type CapellaExecutionPayload = crate::capella::MinimalExecutionPayload;
    /// Minimal capella `ExecutionPayloadHeader`.
    type CapellaExecutionPayloadHeader = crate::capella::MinimalExecutionPayloadHeader;
    /// Minimal: `SYNC_SUBCOMMITTEE_SIZE = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT = 32 / 4 = 8`.
    type AltairSignedContributionAndProof = crate::altair::SignedContributionAndProof<8>;
    /// Minimal: `SYNC_COMMITTEE_SIZE = 32`.
    type AltairLightClientBootstrap = crate::altair::LightClientBootstrap<32>;
    /// Minimal: `SYNC_COMMITTEE_SIZE = 32`.
    type AltairLightClientUpdate = crate::altair::LightClientUpdate<32>;
    /// Minimal: `SYNC_COMMITTEE_SIZE = 32`.
    type AltairLightClientFinalityUpdate = crate::altair::LightClientFinalityUpdate<32>;
    /// Minimal: `SYNC_COMMITTEE_SIZE = 32`.
    type AltairLightClientOptimisticUpdate = crate::altair::LightClientOptimisticUpdate<32>;
    /// Minimal capella `LightClientBootstrap`.
    type CapellaLightClientBootstrap = crate::capella::MinimalLightClientBootstrap;
    /// Minimal capella `LightClientUpdate`.
    type CapellaLightClientUpdate = crate::capella::MinimalLightClientUpdate;
    /// Minimal capella `LightClientFinalityUpdate`.
    type CapellaLightClientFinalityUpdate = crate::capella::MinimalLightClientFinalityUpdate;
    /// Minimal capella `LightClientOptimisticUpdate`.
    type CapellaLightClientOptimisticUpdate = crate::capella::MinimalLightClientOptimisticUpdate;
    /// Minimal deneb `LightClientBootstrap`.
    type DenebLightClientBootstrap = crate::deneb::light_client::MinimalLightClientBootstrap;
    /// Minimal deneb `LightClientUpdate`.
    type DenebLightClientUpdate = crate::deneb::light_client::MinimalLightClientUpdate;
    /// Minimal deneb `LightClientFinalityUpdate`.
    type DenebLightClientFinalityUpdate =
        crate::deneb::light_client::MinimalLightClientFinalityUpdate;
    /// Minimal deneb `LightClientOptimisticUpdate`.
    type DenebLightClientOptimisticUpdate =
        crate::deneb::light_client::MinimalLightClientOptimisticUpdate;

    // ── Deneb associated types ────────────────────────────────────────────────

    type DenebBeaconState = crate::deneb::MinimalBeaconState;
    type DenebBeaconBlock = crate::deneb::MinimalBeaconBlock;
    type DenebSignedBeaconBlock = crate::deneb::MinimalSignedBeaconBlock;
    type DenebBeaconBlockBody = crate::deneb::MinimalBeaconBlockBody;
    type DenebExecutionPayload = crate::deneb::MinimalExecutionPayload;
    type DenebExecutionPayloadHeader = crate::deneb::MinimalExecutionPayloadHeader;
}
