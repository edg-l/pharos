//! Config namespace handler.
//!
//! - `GET /eth/v1/config/spec`
//!
//! Returns a flat string-map of all known preset and config constants.
//! Values are quoted integers or `0x`-hex for byte arrays, per the spec.
//!
//! Spec shape from `~/dev/beacon-APIs/apis/config/spec.yaml`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use pharos_types::BeaconSpec;
use serde::Serialize;

use crate::error::ApiError;
use crate::state::ApiState;

#[derive(Serialize)]
pub struct SpecResponse {
    data: BTreeMap<String, String>,
}

/// Format a `[u8; 4]` as `0x`-prefixed lowercase hex (fork version).
fn hex4(v: [u8; 4]) -> String {
    format!("0x{:02x}{:02x}{:02x}{:02x}", v[0], v[1], v[2], v[3])
}

/// Format a `[u8; 32]` as `0x`-prefixed lowercase hex (root / hash).
fn hex32(v: [u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in v {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// `GET /eth/v1/config/spec`
pub async fn get_spec<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
) -> Result<Json<SpecResponse>, ApiError> {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let cfg = chain.runtime_cfg();
        let mut data: BTreeMap<String, String> = BTreeMap::new();

        // ── Phase 0 preset constants ─────────────────────────────────────────
        data.insert(
            "MAX_COMMITTEES_PER_SLOT".into(),
            E::MAX_COMMITTEES_PER_SLOT.to_string(),
        );
        data.insert(
            "TARGET_COMMITTEE_SIZE".into(),
            E::TARGET_COMMITTEE_SIZE.to_string(),
        );
        data.insert(
            "MAX_VALIDATORS_PER_COMMITTEE".into(),
            E::MAX_VALIDATORS_PER_COMMITTEE.to_string(),
        );
        data.insert(
            "SHUFFLE_ROUND_COUNT".into(),
            E::SHUFFLE_ROUND_COUNT.to_string(),
        );
        data.insert(
            "HYSTERESIS_QUOTIENT".into(),
            E::HYSTERESIS_QUOTIENT.to_string(),
        );
        data.insert(
            "HYSTERESIS_DOWNWARD_MULTIPLIER".into(),
            E::HYSTERESIS_DOWNWARD_MULTIPLIER.to_string(),
        );
        data.insert(
            "HYSTERESIS_UPWARD_MULTIPLIER".into(),
            E::HYSTERESIS_UPWARD_MULTIPLIER.to_string(),
        );
        data.insert(
            "MIN_DEPOSIT_AMOUNT".into(),
            E::MIN_DEPOSIT_AMOUNT.to_string(),
        );
        data.insert(
            "MAX_EFFECTIVE_BALANCE".into(),
            E::MAX_EFFECTIVE_BALANCE.to_string(),
        );
        data.insert(
            "EFFECTIVE_BALANCE_INCREMENT".into(),
            E::EFFECTIVE_BALANCE_INCREMENT.to_string(),
        );
        data.insert(
            "MIN_ATTESTATION_INCLUSION_DELAY".into(),
            E::MIN_ATTESTATION_INCLUSION_DELAY.to_string(),
        );
        data.insert("SLOTS_PER_EPOCH".into(), E::SLOTS_PER_EPOCH.to_string());
        data.insert(
            "MIN_SEED_LOOKAHEAD".into(),
            E::MIN_SEED_LOOKAHEAD.to_string(),
        );
        data.insert(
            "MAX_SEED_LOOKAHEAD".into(),
            E::MAX_SEED_LOOKAHEAD.to_string(),
        );
        data.insert(
            "EPOCHS_PER_ETH1_VOTING_PERIOD".into(),
            E::EPOCHS_PER_ETH1_VOTING_PERIOD.to_string(),
        );
        data.insert(
            "SLOTS_PER_HISTORICAL_ROOT".into(),
            E::SLOTS_PER_HISTORICAL_ROOT.to_string(),
        );
        data.insert(
            "MIN_EPOCHS_TO_INACTIVITY_PENALTY".into(),
            E::MIN_EPOCHS_TO_INACTIVITY_PENALTY.to_string(),
        );
        data.insert(
            "EPOCHS_PER_HISTORICAL_VECTOR".into(),
            E::EPOCHS_PER_HISTORICAL_VECTOR.to_string(),
        );
        data.insert(
            "EPOCHS_PER_SLASHINGS_VECTOR".into(),
            E::EPOCHS_PER_SLASHINGS_VECTOR.to_string(),
        );
        data.insert(
            "HISTORICAL_ROOTS_LIMIT".into(),
            E::HISTORICAL_ROOTS_LIMIT.to_string(),
        );
        data.insert(
            "VALIDATOR_REGISTRY_LIMIT".into(),
            E::VALIDATOR_REGISTRY_LIMIT.to_string(),
        );
        data.insert(
            "BASE_REWARD_FACTOR".into(),
            E::BASE_REWARD_FACTOR.to_string(),
        );
        data.insert(
            "WHISTLEBLOWER_REWARD_QUOTIENT".into(),
            E::WHISTLEBLOWER_REWARD_QUOTIENT.to_string(),
        );
        data.insert(
            "PROPOSER_REWARD_QUOTIENT".into(),
            E::PROPOSER_REWARD_QUOTIENT.to_string(),
        );
        data.insert(
            "INACTIVITY_PENALTY_QUOTIENT".into(),
            E::INACTIVITY_PENALTY_QUOTIENT.to_string(),
        );
        data.insert(
            "MIN_SLASHING_PENALTY_QUOTIENT".into(),
            E::MIN_SLASHING_PENALTY_QUOTIENT.to_string(),
        );
        data.insert(
            "PROPORTIONAL_SLASHING_MULTIPLIER".into(),
            E::PROPORTIONAL_SLASHING_MULTIPLIER.to_string(),
        );
        data.insert(
            "MAX_PROPOSER_SLASHINGS".into(),
            E::MAX_PROPOSER_SLASHINGS.to_string(),
        );
        data.insert(
            "MAX_ATTESTER_SLASHINGS".into(),
            E::MAX_ATTESTER_SLASHINGS.to_string(),
        );
        data.insert("MAX_ATTESTATIONS".into(), E::MAX_ATTESTATIONS.to_string());
        data.insert("MAX_DEPOSITS".into(), E::MAX_DEPOSITS.to_string());
        data.insert(
            "MAX_VOLUNTARY_EXITS".into(),
            E::MAX_VOLUNTARY_EXITS.to_string(),
        );
        data.insert(
            "JUSTIFICATION_BITS_LENGTH".into(),
            E::JUSTIFICATION_BITS_LENGTH.to_string(),
        );
        data.insert(
            "BASE_REWARDS_PER_EPOCH".into(),
            E::BASE_REWARDS_PER_EPOCH.to_string(),
        );

        // ── Genesis / config constants ────────────────────────────────────────
        data.insert("GENESIS_FORK_VERSION".into(), hex4(E::GENESIS_FORK_VERSION));
        data.insert("GENESIS_DELAY".into(), E::GENESIS_DELAY.to_string());
        data.insert(
            "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT".into(),
            E::MIN_GENESIS_ACTIVE_VALIDATOR_COUNT.to_string(),
        );
        data.insert("MIN_GENESIS_TIME".into(), E::MIN_GENESIS_TIME.to_string());
        data.insert(
            "MIN_VALIDATOR_WITHDRAWABILITY_DELAY".into(),
            E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY.to_string(),
        );
        data.insert(
            "SHARD_COMMITTEE_PERIOD".into(),
            E::SHARD_COMMITTEE_PERIOD.to_string(),
        );
        data.insert(
            "MIN_PER_EPOCH_CHURN_LIMIT".into(),
            E::MIN_PER_EPOCH_CHURN_LIMIT.to_string(),
        );
        data.insert(
            "CHURN_LIMIT_QUOTIENT".into(),
            E::CHURN_LIMIT_QUOTIENT.to_string(),
        );

        // ── Altair preset constants ───────────────────────────────────────────
        data.insert(
            "SYNC_COMMITTEE_SIZE".into(),
            E::SYNC_COMMITTEE_SIZE.to_string(),
        );
        data.insert(
            "SYNC_COMMITTEE_SUBNET_COUNT".into(),
            E::SYNC_COMMITTEE_SUBNET_COUNT.to_string(),
        );
        data.insert(
            "MIN_SYNC_COMMITTEE_PARTICIPANTS".into(),
            E::MIN_SYNC_COMMITTEE_PARTICIPANTS.to_string(),
        );
        data.insert(
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD".into(),
            E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD.to_string(),
        );
        data.insert(
            "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE".into(),
            E::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE.to_string(),
        );
        data.insert("UPDATE_TIMEOUT".into(), E::UPDATE_TIMEOUT.to_string());
        data.insert(
            "INACTIVITY_PENALTY_QUOTIENT_ALTAIR".into(),
            E::INACTIVITY_PENALTY_QUOTIENT_ALTAIR.to_string(),
        );
        data.insert(
            "MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR".into(),
            E::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR.to_string(),
        );
        data.insert(
            "PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR".into(),
            E::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR.to_string(),
        );
        data.insert(
            "INACTIVITY_SCORE_BIAS".into(),
            E::INACTIVITY_SCORE_BIAS.to_string(),
        );
        data.insert(
            "INACTIVITY_SCORE_RECOVERY_RATE".into(),
            E::INACTIVITY_SCORE_RECOVERY_RATE.to_string(),
        );
        data.insert("ALTAIR_FORK_VERSION".into(), hex4(E::ALTAIR_FORK_VERSION));
        data.insert(
            "ALTAIR_FORK_EPOCH".into(),
            cfg.altair_fork_epoch.to_string(),
        );

        // ── Bellatrix preset constants ────────────────────────────────────────
        data.insert(
            "INACTIVITY_PENALTY_QUOTIENT_BELLATRIX".into(),
            E::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX.to_string(),
        );
        data.insert(
            "MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX".into(),
            E::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX.to_string(),
        );
        data.insert(
            "PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX".into(),
            E::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX.to_string(),
        );
        data.insert(
            "MAX_BYTES_PER_TRANSACTION".into(),
            E::MAX_BYTES_PER_TRANSACTION.to_string(),
        );
        data.insert(
            "MAX_TRANSACTIONS_PER_PAYLOAD".into(),
            E::MAX_TRANSACTIONS_PER_PAYLOAD.to_string(),
        );
        data.insert(
            "BYTES_PER_LOGS_BLOOM".into(),
            E::BYTES_PER_LOGS_BLOOM.to_string(),
        );
        data.insert(
            "MAX_EXTRA_DATA_BYTES".into(),
            E::MAX_EXTRA_DATA_BYTES.to_string(),
        );
        data.insert(
            "BELLATRIX_FORK_VERSION".into(),
            hex4(E::BELLATRIX_FORK_VERSION),
        );
        data.insert(
            "BELLATRIX_FORK_EPOCH".into(),
            cfg.bellatrix_fork_epoch.to_string(),
        );

        // ── Capella preset constants ──────────────────────────────────────────
        data.insert(
            "MAX_BLS_TO_EXECUTION_CHANGES".into(),
            E::MAX_BLS_TO_EXECUTION_CHANGES.to_string(),
        );
        data.insert(
            "MAX_WITHDRAWALS_PER_PAYLOAD".into(),
            E::MAX_WITHDRAWALS_PER_PAYLOAD.to_string(),
        );
        data.insert(
            "MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP".into(),
            E::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP.to_string(),
        );
        data.insert("CAPELLA_FORK_VERSION".into(), hex4(E::CAPELLA_FORK_VERSION));
        data.insert(
            "CAPELLA_FORK_EPOCH".into(),
            cfg.capella_fork_epoch.to_string(),
        );

        // ── Deneb preset constants ────────────────────────────────────────────
        data.insert(
            "MAX_BLOB_COMMITMENTS_PER_BLOCK".into(),
            E::MAX_BLOB_COMMITMENTS_PER_BLOCK.to_string(),
        );
        data.insert(
            "FIELD_ELEMENTS_PER_BLOB".into(),
            E::FIELD_ELEMENTS_PER_BLOB.to_string(),
        );
        data.insert(
            "KZG_COMMITMENT_INCLUSION_PROOF_DEPTH".into(),
            E::KZG_COMMITMENT_INCLUSION_PROOF_DEPTH.to_string(),
        );
        data.insert("DENEB_FORK_VERSION".into(), hex4(E::DENEB_FORK_VERSION));
        data.insert("DENEB_FORK_EPOCH".into(), cfg.deneb_fork_epoch.to_string());

        // ── Runtime config (dynamic, overridden by --config-dir) ─────────────
        data.insert("SECONDS_PER_SLOT".into(), cfg.seconds_per_slot.to_string());
        data.insert(
            "GENESIS_VALIDATORS_ROOT".into(),
            hex32(cfg.genesis_validators_root),
        );

        SpecResponse { data }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?;

    Ok(Json(result))
}
