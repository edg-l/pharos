//! Beacon states namespace handlers (Phase 2).
//!
//! - `GET /eth/v1/beacon/states/{state_id}/root`
//! - `GET /eth/v1/beacon/states/{state_id}/fork`
//! - `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints`
//! - `GET /eth/v1/beacon/states/{state_id}/validators`
//! - `GET /eth/v1/beacon/states/{state_id}/validators/{validator_id}`
//! - `GET /eth/v1/beacon/states/{state_id}/validator_balances`
//! - `GET /eth/v1/beacon/states/{state_id}/committees`
//! - `GET /eth/v1/beacon/states/{state_id}/randao`
//! - `GET /eth/v1/beacon/states/{state_id}/sync_committees`
//!
//! All responses carry `execution_optimistic` + `finalized` top-level booleans.
//!
//! ## ValidatorStatus derivation
//!
//! Per the Beacon API spec status table at
//! <https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ> and
//! `beacon-APIs/types/api.yaml#ValidatorStatus`:
//!
//! | Status                | Conditions (current epoch = E)                                   |
//! |-----------------------|------------------------------------------------------------------|
//! | pending_initialized   | activation_epoch > E and activation_eligibility == FAR_FUTURE   |
//! | pending_queued        | activation_epoch > E and eligibility already set                |
//! | active_ongoing        | active (activation ≤ E < exit), not slashed, no exit filed       |
//! | active_exiting        | active, exit_epoch < FAR_FUTURE, not slashed                     |
//! | active_slashed        | active, slashed                                                  |
//! | exited_unslashed      | exit_epoch ≤ E < withdrawable, not slashed                       |
//! | exited_slashed        | exit_epoch ≤ E < withdrawable, slashed                           |
//! | withdrawal_possible   | withdrawable_epoch ≤ E, not all-balance-withdrawn                |
//! | withdrawal_done       | withdrawable_epoch ≤ E, balance == 0                             |
//!
//! ## Committee helpers
//!
//! `GET /committees` uses `pharos_stf::phase0::accessors::get_beacon_committee`
//! and `get_committee_count_per_slot` (in
//! `crates/pharos-stf/src/phase0/accessors.rs`).
//!
//! ## Sync committees
//!
//! `GET /sync_committees` reads `current_sync_committee` / `next_sync_committee`
//! directly from the `BeaconState` enum variant (Altair/Bellatrix/Capella only).
//! A 400 is returned for Phase0 states, which have no sync committee.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_ssz::TreeHash;
use pharos_types::views::ForkVariant;
use pharos_types::{BeaconStateView, EthSpec, phase0::Validator};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::resolve::resolve_state_id;
use crate::respond::{ApiResponse, parse_accept};
use crate::serde_helpers::{
    hex_bytes, quoted_u64, serialize_hex4, serialize_hex32, serialize_hex48,
};
use crate::state::ApiState;

// ── FAR_FUTURE_EPOCH ──────────────────────────────────────────────────────────

/// Per `specs/phase0/beacon-chain.md`: FAR_FUTURE_EPOCH = 2^64 - 1.
const FAR_FUTURE_EPOCH: u64 = u64::MAX;

// ── ValidatorStatus ───────────────────────────────────────────────────────────

/// Validator lifecycle status.
///
/// Per beacon-APIs `types/api.yaml#ValidatorStatus` and the derivation table
/// at <https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ>.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    PendingInitialized,
    PendingQueued,
    ActiveOngoing,
    ActiveExiting,
    ActiveSlashed,
    ExitedUnslashed,
    ExitedSlashed,
    WithdrawalPossible,
    WithdrawalDone,
}

impl ValidatorStatus {
    /// Broad category string accepted by the `?status=` query parameter.
    ///
    /// `active` matches all `active_*`; `pending` all `pending_*`; etc.
    fn broad_category(&self) -> &'static str {
        match self {
            Self::PendingInitialized | Self::PendingQueued => "pending",
            Self::ActiveOngoing | Self::ActiveExiting | Self::ActiveSlashed => "active",
            Self::ExitedUnslashed | Self::ExitedSlashed => "exited",
            Self::WithdrawalPossible | Self::WithdrawalDone => "withdrawal",
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::PendingInitialized => "pending_initialized",
            Self::PendingQueued => "pending_queued",
            Self::ActiveOngoing => "active_ongoing",
            Self::ActiveExiting => "active_exiting",
            Self::ActiveSlashed => "active_slashed",
            Self::ExitedUnslashed => "exited_unslashed",
            Self::ExitedSlashed => "exited_slashed",
            Self::WithdrawalPossible => "withdrawal_possible",
            Self::WithdrawalDone => "withdrawal_done",
        }
    }

    fn matches_filter(&self, filter: &str) -> bool {
        // Exact match takes precedence (e.g. "active_ongoing").
        if self.as_str() == filter {
            return true;
        }
        // Broad-category match (e.g. "active").
        self.broad_category() == filter
    }
}

/// Derive the `ValidatorStatus` from a `Validator` and the current epoch.
///
/// Per beacon-APIs spec + <https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ>.
pub fn derive_validator_status(v: &Validator, current_epoch: u64, balance: u64) -> ValidatorStatus {
    let activation_eligibility = v.activation_eligibility_epoch.0;
    let activation = v.activation_epoch.0;
    let exit = v.exit_epoch.0;
    let withdrawable = v.withdrawable_epoch.0;
    let slashed = v.slashed;

    // The four lifecycle phases partition the epoch line:
    //   pending     : activation_epoch > current_epoch
    //   active      : activation_epoch ≤ current_epoch < exit_epoch
    //   exited      : exit_epoch ≤ current_epoch < withdrawable_epoch
    //   withdrawal  : withdrawable_epoch ≤ current_epoch
    // Because exit_epoch ≤ withdrawable_epoch always holds, these arms are
    // exhaustive for any validator with activation_epoch ≤ current_epoch.
    if activation > current_epoch {
        // Pending: eligibility==FAR_FUTURE means not yet queued for activation.
        if activation_eligibility == FAR_FUTURE_EPOCH {
            ValidatorStatus::PendingInitialized
        } else {
            ValidatorStatus::PendingQueued
        }
    } else if current_epoch < exit {
        // Active (slashed validators always carry a finite exit_epoch, so the
        // slashed check precedes the exit-set check).
        if slashed {
            ValidatorStatus::ActiveSlashed
        } else if exit < FAR_FUTURE_EPOCH {
            ValidatorStatus::ActiveExiting
        } else {
            ValidatorStatus::ActiveOngoing
        }
    } else if current_epoch < withdrawable {
        // Exited.
        if slashed {
            ValidatorStatus::ExitedSlashed
        } else {
            ValidatorStatus::ExitedUnslashed
        }
    } else {
        // Withdrawal: current_epoch ≥ withdrawable_epoch.
        if balance == 0 {
            ValidatorStatus::WithdrawalDone
        } else {
            ValidatorStatus::WithdrawalPossible
        }
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StateRootData {
    #[serde(serialize_with = "serialize_hex32")]
    pub root: [u8; 32],
}

#[derive(Serialize)]
pub struct StateRootResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: StateRootData,
}

#[derive(Serialize)]
pub struct ForkDto {
    #[serde(serialize_with = "serialize_hex4")]
    pub previous_version: [u8; 4],
    #[serde(serialize_with = "serialize_hex4")]
    pub current_version: [u8; 4],
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
}

#[derive(Serialize)]
pub struct ForkResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: ForkDto,
}

#[derive(Serialize)]
pub struct CheckpointDto {
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub root: [u8; 32],
}

#[derive(Serialize)]
pub struct FinalityCheckpointsData {
    pub previous_justified: CheckpointDto,
    pub current_justified: CheckpointDto,
    pub finalized: CheckpointDto,
}

#[derive(Serialize)]
pub struct FinalityCheckpointsResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: FinalityCheckpointsData,
}

#[derive(Serialize)]
pub struct ValidatorDto {
    #[serde(with = "quoted_u64")]
    pub index: u64,
    pub status: ValidatorStatus,
    #[serde(with = "quoted_u64")]
    pub balance: u64,
    pub validator: ValidatorFieldsDto,
}

#[derive(Serialize)]
pub struct ValidatorFieldsDto {
    #[serde(serialize_with = "serialize_hex48")]
    pub pubkey: [u8; 48],
    #[serde(serialize_with = "serialize_hex32")]
    pub withdrawal_credentials: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    #[serde(with = "quoted_u64")]
    pub activation_eligibility_epoch: u64,
    #[serde(with = "quoted_u64")]
    pub activation_epoch: u64,
    #[serde(with = "quoted_u64")]
    pub exit_epoch: u64,
    #[serde(with = "quoted_u64")]
    pub withdrawable_epoch: u64,
}

#[derive(Serialize)]
pub struct ValidatorsResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: Vec<ValidatorDto>,
}

#[derive(Serialize)]
pub struct SingleValidatorResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: ValidatorDto,
}

#[derive(Serialize)]
pub struct ValidatorBalanceDto {
    #[serde(with = "quoted_u64")]
    pub index: u64,
    #[serde(with = "quoted_u64")]
    pub balance: u64,
}

#[derive(Serialize)]
pub struct ValidatorBalancesResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: Vec<ValidatorBalanceDto>,
}

#[derive(Serialize)]
pub struct CommitteeDto {
    #[serde(with = "quoted_u64")]
    pub index: u64,
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    pub validators: Vec<String>, // quoted validator indices
}

#[derive(Serialize)]
pub struct CommitteesResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: Vec<CommitteeDto>,
}

#[derive(Serialize)]
pub struct RandaoData {
    #[serde(with = "hex_bytes")]
    pub randao: Vec<u8>,
}

#[derive(Serialize)]
pub struct RandaoResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: RandaoData,
}

#[derive(Serialize)]
pub struct SyncCommitteesData {
    pub validators: Vec<String>,                // quoted validator indices
    pub validator_aggregates: Vec<Vec<String>>, // sub-committees
}

#[derive(Serialize)]
pub struct SyncCommitteesResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: SyncCommitteesData,
}

// ── Query params ──────────────────────────────────────────────────────────────

/// Collect all values for `key` from a flat list of query key/value pairs,
/// accepting BOTH array style (`?id=0&id=1`) and comma-separated style
/// (`?id=0,1`), and any mix. Empty tokens are dropped. An absent key yields an
/// empty `Vec`.
///
/// This is the beacon-API `style: form, explode: true` array convention used by
/// the `?id=` / `?status=` filters on the validators endpoints.
fn collect_multi(pairs: &[(String, String)], key: &str) -> Vec<String> {
    pairs
        .iter()
        .filter(|(k, _)| k == key)
        .flat_map(|(_, v)| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Deserialize, Default)]
pub struct CommitteesQuery {
    pub epoch: Option<u64>,
    pub index: Option<u64>,
    pub slot: Option<u64>,
}

#[derive(Deserialize, Default)]
pub struct RandaoQuery {
    pub epoch: Option<u64>,
}

#[derive(Deserialize, Default)]
pub struct SyncCommitteesQuery {
    pub epoch: Option<u64>,
}

// ── Handler helpers ───────────────────────────────────────────────────────────

fn validator_to_dto(idx: usize, v: &Validator, balance: u64, current_epoch: u64) -> ValidatorDto {
    let status = derive_validator_status(v, current_epoch, balance);
    ValidatorDto {
        index: idx as u64,
        status,
        balance,
        validator: ValidatorFieldsDto {
            pubkey: v.pubkey.into_inner(),
            withdrawal_credentials: v.withdrawal_credentials.into_inner(),
            effective_balance: v.effective_balance.0,
            slashed: v.slashed,
            activation_eligibility_epoch: v.activation_eligibility_epoch.0,
            activation_epoch: v.activation_epoch.0,
            exit_epoch: v.exit_epoch.0,
            withdrawable_epoch: v.withdrawable_epoch.0,
        },
    }
}

/// Resolve a validator-id filter into a list of validator indices. Each id
/// token is either a decimal index or a `0x`-prefixed 48-byte BLS pubkey;
/// pubkeys are resolved against `beacon_state`.
///
/// `ids` is the already-collected, comma-and-repeated-key-expanded token list
/// (see [`collect_multi`]); callers pass an empty slice to mean "no filter".
/// Tokens that are syntactically valid but do not match any validator
/// (out-of-range index or unknown pubkey) are silently dropped, per the
/// beacon-API convention of returning only the validators that exist. A
/// malformed token is a 400.
fn resolve_validator_ids<S: BeaconStateView>(
    ids: &[String],
    beacon_state: &S,
) -> Result<Vec<usize>, ApiError> {
    let num_validators = beacon_state.num_validators();
    let mut indices = Vec::new();
    for part in ids {
        let part = part.as_str();
        if let Some(hex) = part.strip_prefix("0x") {
            // Pubkey form: 0x + 96 hex chars = 48 bytes.
            if hex.len() != 96 {
                return Err(ApiError::BadRequest(format!(
                    "validator pubkey must be 48 bytes (98 chars including 0x), got '{part}'"
                )));
            }
            let bytes = hex::decode(hex)
                .map_err(|e| ApiError::BadRequest(format!("invalid pubkey hex: {e}")))?;
            if let Some(idx) = beacon_state
                .validators_iter()
                .position(|v| v.pubkey.as_slice() == bytes.as_slice())
            {
                indices.push(idx);
            }
            // Unknown pubkey: drop silently.
        } else {
            let idx: usize = part
                .parse()
                .map_err(|_| ApiError::BadRequest(format!("invalid validator_id: '{part}'")))?;
            if idx < num_validators {
                indices.push(idx);
            }
        }
    }
    Ok(indices)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/states/{state_id}/root`
pub async fn get_state_root<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        // Get the post-state for this block root to compute the state root.
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;
        // Clone state out and drop lock before computing root.
        let state_root: pharos_types::phase0::Root = beacon_state.tree_hash_root();
        // The SSZ encoding of a Root (Bytes32) is its 32-byte representation.
        let ssz_bytes = state_root.as_slice().to_vec();
        let dto = StateRootResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: StateRootData {
                root: state_root.into_inner(),
            },
        };
        Ok::<_, ApiError>((dto, ssz_bytes))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((dto, ssz_bytes))) => ApiResponse::both(dto, ssz_bytes).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/fork`
pub async fn get_state_fork<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;
        let fork = beacon_state.fork().clone();
        Ok::<_, ApiError>(ForkResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: ForkDto {
                previous_version: fork.previous_version.into_inner(),
                current_version: fork.current_version.into_inner(),
                epoch: fork.epoch.0,
            },
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints`
pub async fn get_finality_checkpoints<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;
        let prev_just = beacon_state.previous_justified_checkpoint().clone();
        let curr_just = beacon_state.current_justified_checkpoint().clone();
        let finalized = beacon_state.finalized_checkpoint().clone();
        Ok::<_, ApiError>(FinalityCheckpointsResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: FinalityCheckpointsData {
                previous_justified: CheckpointDto {
                    epoch: prev_just.epoch.0,
                    root: prev_just.root.into_inner(),
                },
                current_justified: CheckpointDto {
                    epoch: curr_just.epoch.0,
                    root: curr_just.root.into_inner(),
                },
                finalized: CheckpointDto {
                    epoch: finalized.epoch.0,
                    root: finalized.root.into_inner(),
                },
            },
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/validators`
pub async fn get_validators<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let id_tokens = collect_multi(&query, "id");
    let status_filters = collect_multi(&query, "status");
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        let balances = beacon_state.balances().to_vec();
        let num_validators = beacon_state.num_validators();

        // Compute current epoch from state slot.
        let current_epoch = {
            use pharos_stf::phase0::accessors::compute_epoch_at_slot;
            compute_epoch_at_slot(beacon_state.slot(), E::SLOTS_PER_EPOCH).0
        };

        // Resolve the id filter (empty = all validators).
        let id_filter: Option<Vec<usize>> = if id_tokens.is_empty() {
            None
        } else {
            Some(resolve_validator_ids(&id_tokens, &beacon_state)?)
        };

        let mut data = Vec::new();
        // Use borrowing iterator to avoid materializing the full Vec<Validator>.
        let indices_to_check: Box<dyn Iterator<Item = usize>> = match id_filter {
            Some(ref ids) => Box::new(ids.iter().copied()),
            None => Box::new(0..num_validators),
        };
        for idx in indices_to_check {
            let v = match beacon_state.validator(idx) {
                Some(v) => v,
                None => continue,
            };
            let balance = balances.get(idx).map(|g| g.0).unwrap_or(0);
            let dto = validator_to_dto(idx, v, balance, current_epoch);
            // Apply status filter.
            if !status_filters.is_empty()
                && !status_filters.iter().any(|f| dto.status.matches_filter(f))
            {
                continue;
            }
            data.push(dto);
        }

        Ok::<_, ApiError>(ValidatorsResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/validators/{validator_id}`
pub async fn get_validator<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path((state_id, validator_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        let balances = beacon_state.balances().to_vec();
        let current_epoch = {
            use pharos_stf::phase0::accessors::compute_epoch_at_slot;
            compute_epoch_at_slot(beacon_state.slot(), E::SLOTS_PER_EPOCH).0
        };

        // Parse single validator id.
        let idx = if let Some(hex) = validator_id.strip_prefix("0x") {
            // Pubkey lookup: scan validators_iter for a matching pubkey.
            if hex.len() != 96 {
                return Err(ApiError::BadRequest(format!(
                    "validator pubkey must be 48 bytes (98 chars including 0x), got {}",
                    validator_id.len()
                )));
            }
            let bytes = hex::decode(hex)
                .map_err(|e| ApiError::BadRequest(format!("invalid pubkey hex: {e}")))?;
            beacon_state
                .validators_iter()
                .enumerate()
                .find_map(|(i, v)| {
                    if v.pubkey.as_slice() == bytes.as_slice() {
                        Some(i)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| ApiError::NotFound(format!("validator {validator_id} not found")))?
        } else {
            validator_id.parse::<usize>().map_err(|_| {
                ApiError::BadRequest(format!("invalid validator_id: '{validator_id}'"))
            })?
        };

        let v = beacon_state
            .validator(idx)
            .ok_or_else(|| ApiError::NotFound(format!("validator index {idx} out of range")))?;
        let balance = balances.get(idx).map(|g| g.0).unwrap_or(0);
        let dto = validator_to_dto(idx, v, balance, current_epoch);

        Ok::<_, ApiError>(SingleValidatorResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: dto,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/validator_balances`
pub async fn get_validator_balances<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let id_tokens = collect_multi(&query, "id");
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        let balances = beacon_state.balances().to_vec();

        let id_filter: Option<Vec<usize>> = if id_tokens.is_empty() {
            None
        } else {
            Some(resolve_validator_ids(&id_tokens, &beacon_state)?)
        };

        let data: Vec<ValidatorBalanceDto> = match id_filter {
            Some(ids) => ids
                .into_iter()
                .map(|idx| {
                    let balance = balances.get(idx).map(|g| g.0).unwrap_or(0);
                    ValidatorBalanceDto {
                        index: idx as u64,
                        balance,
                    }
                })
                .collect(),
            None => balances
                .iter()
                .enumerate()
                .map(|(idx, g)| ValidatorBalanceDto {
                    index: idx as u64,
                    balance: g.0,
                })
                .collect(),
        };

        Ok::<_, ApiError>(ValidatorBalancesResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/committees`
///
/// Uses `pharos_stf::phase0::accessors::get_beacon_committee` and
/// `get_committee_count_per_slot` sourced from
/// `crates/pharos-stf/src/phase0/accessors.rs`.
pub async fn get_committees<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    Query(query): Query<CommitteesQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        use pharos_stf::phase0::accessors::{
            compute_epoch_at_slot, compute_start_slot_at_epoch, get_beacon_committee,
            get_committee_count_per_slot,
        };
        use pharos_types::phase0::primitives::{Epoch, Slot};

        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        let state_epoch = compute_epoch_at_slot(beacon_state.slot(), E::SLOTS_PER_EPOCH);
        let target_epoch = Epoch(query.epoch.unwrap_or(state_epoch.0));
        let committees_per_slot = get_committee_count_per_slot::<E>(&beacon_state, target_epoch);

        let epoch_start = compute_start_slot_at_epoch(target_epoch, E::SLOTS_PER_EPOCH);

        // An explicit `?slot=` must fall within the target epoch (spec: 400
        // "Slot does not belong in epoch").
        if let Some(qs) = query.slot {
            if qs < epoch_start.0 || qs >= epoch_start.0 + E::SLOTS_PER_EPOCH {
                return Err(ApiError::BadRequest(format!(
                    "slot {qs} does not belong in epoch {}",
                    target_epoch.0
                )));
            }
        }

        let mut data = Vec::new();
        for slot_offset in 0..E::SLOTS_PER_EPOCH {
            let slot = Slot(epoch_start.0 + slot_offset);
            // Apply slot filter.
            if let Some(qs) = query.slot {
                if slot.0 != qs {
                    continue;
                }
            }
            for committee_index in 0..committees_per_slot {
                // Apply committee index filter.
                if let Some(qi) = query.index {
                    if committee_index != qi {
                        continue;
                    }
                }
                let validators = get_beacon_committee::<E>(&beacon_state, slot, committee_index);
                let validator_strs: Vec<String> =
                    validators.iter().map(|vi| vi.0.to_string()).collect();
                data.push(CommitteeDto {
                    index: committee_index,
                    slot: slot.0,
                    validators: validator_strs,
                });
            }
        }

        Ok::<_, ApiError>(CommitteesResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/randao`
pub async fn get_randao<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    Query(query): Query<RandaoQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        use pharos_stf::phase0::accessors::{compute_epoch_at_slot, get_randao_mix};
        use pharos_types::phase0::primitives::Epoch;

        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        let state_epoch = compute_epoch_at_slot(beacon_state.slot(), E::SLOTS_PER_EPOCH);
        let target_epoch = Epoch(query.epoch.unwrap_or(state_epoch.0));
        let mix = get_randao_mix::<E>(&beacon_state, target_epoch);

        Ok::<_, ApiError>(RandaoResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: RandaoData {
                randao: mix.as_slice().to_vec(),
            },
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/beacon/states/{state_id}/sync_committees`
///
/// Sources `current_sync_committee` / `next_sync_committee` from the
/// `BeaconState` enum variant (Altair/Bellatrix/Capella only).
/// Returns 400 for Phase0 states (the state is found, but has no sync committee).
pub async fn get_sync_committees<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(state_id): Path<String>,
    Query(query): Query<SyncCommitteesQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        use pharos_stf::phase0::accessors::compute_epoch_at_slot;
        use pharos_types::phase0::primitives::Epoch;

        let resolved = resolve_state_id(chain.as_ref(), &state_id)?;
        let beacon_state = chain
            .state_by_block_root(resolved.block_root)
            .ok_or_else(|| ApiError::NotFound(format!("state not found for id '{state_id}'")))?;

        // Phase0 states do not have sync committees. The state exists, so this
        // is a 400 (bad request for this state), not a 404.
        if beacon_state.fork_variant() == ForkVariant::Phase0 {
            return Err(ApiError::BadRequest(
                "sync committees are not available for pre-altair states".to_string(),
            ));
        }

        let state_epoch = compute_epoch_at_slot(beacon_state.slot(), E::SLOTS_PER_EPOCH);
        let target_epoch = Epoch(query.epoch.unwrap_or(state_epoch.0));

        // Determine if target epoch is in the current or next sync committee period.
        // EPOCHS_PER_SYNC_COMMITTEE_PERIOD is E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD.
        let current_period = state_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let target_period = target_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

        // Extract pubkeys via ChainStateApi::sync_committee_pubkeys which
        // accesses the concrete enum fields directly (not through the opaque
        // associated type, which doesn't expose struct fields).
        let (curr_pks, next_pks) = chain
            .sync_committee_pubkeys(resolved.block_root)
            .ok_or_else(|| {
                ApiError::NotFound("sync committees not available for this state".to_string())
            })?;

        let pubkeys: Vec<[u8; 48]> = if target_period == current_period {
            curr_pks
        } else if target_period == current_period + 1 {
            next_pks
        } else {
            return Err(ApiError::BadRequest(format!(
                "epoch period {target_period} is outside current ({current_period}) or next ({}) sync committee period",
                current_period + 1
            )));
        };

        // Build a mapping from pubkey → validator index for the current state.
        // This is O(n_validators) but only done when this endpoint is called.
        let mut pk_to_idx: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
        for (i, v) in beacon_state.validators_iter().enumerate() {
            pk_to_idx.insert(v.pubkey.as_slice().to_vec(), i);
        }

        // Every sync-committee member is, by construction, a validator in this
        // same state — a missing pubkey means the committee and the validator
        // registry are inconsistent, which we surface rather than masking with
        // a fallback index.
        let validators: Vec<String> = pubkeys
            .iter()
            .map(|pk| {
                pk_to_idx
                    .get(pk.as_slice())
                    .map(|i| i.to_string())
                    .ok_or_else(|| {
                        ApiError::Internal(format!(
                            "sync committee pubkey 0x{} not found in validator set",
                            hex::encode(pk)
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;

        // Split the committee into SYNC_COMMITTEE_SUBNET_COUNT subcommittees, each
        // of size SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT (altair spec).
        let subnet_count = E::SYNC_COMMITTEE_SUBNET_COUNT.max(1) as usize;
        let subcommittee_size = validators.len().div_ceil(subnet_count);
        let validator_aggregates: Vec<Vec<String>> = validators
            .chunks(subcommittee_size.max(1))
            .map(|chunk| chunk.to_vec())
            .collect();

        Ok::<_, ApiError>(SyncCommitteesResponse {
            execution_optimistic: resolved.execution_optimistic,
            finalized: resolved.finalized,
            data: SyncCommitteesData {
                validators,
                validator_aggregates,
            },
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(dto)) => ApiResponse::json(dto).render(format),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use pharos_types::phase0::Validator;
    use pharos_utils::Gwei;

    use super::*;

    fn make_validator(
        activation_eligibility_epoch: u64,
        activation_epoch: u64,
        exit_epoch: u64,
        withdrawable_epoch: u64,
        slashed: bool,
    ) -> Validator {
        use pharos_utils::{BLSPubkey, Bytes32};
        Validator {
            pubkey: BLSPubkey::default(),
            withdrawal_credentials: Bytes32::default(),
            effective_balance: Gwei(32_000_000_000),
            slashed,
            activation_eligibility_epoch: pharos_types::phase0::primitives::Epoch(
                activation_eligibility_epoch,
            ),
            activation_epoch: pharos_types::phase0::primitives::Epoch(activation_epoch),
            exit_epoch: pharos_types::phase0::primitives::Epoch(exit_epoch),
            withdrawable_epoch: pharos_types::phase0::primitives::Epoch(withdrawable_epoch),
            cached_root: Default::default(),
        }
    }

    #[test]
    fn pending_initialized_when_eligibility_far_future() {
        let v = make_validator(
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH,
            false,
        );
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::PendingInitialized
        );
    }

    #[test]
    fn pending_queued_when_activation_far_future() {
        let v = make_validator(
            5,
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH,
            false,
        );
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::PendingQueued
        );
    }

    #[test]
    fn pending_queued_when_activation_epoch_in_future() {
        // Eligibility set (not FAR_FUTURE), activation scheduled for a future
        // epoch (> current). Must be pending_queued, NOT pending_initialized.
        let v = make_validator(3, 20, FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH, false);
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::PendingQueued
        );
    }

    #[test]
    fn active_ongoing() {
        let v = make_validator(3, 5, FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH, false);
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::ActiveOngoing
        );
    }

    #[test]
    fn active_exiting() {
        let v = make_validator(3, 5, 15, FAR_FUTURE_EPOCH, false);
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::ActiveExiting
        );
    }

    #[test]
    fn active_slashed() {
        let v = make_validator(3, 5, FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH, true);
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::ActiveSlashed
        );
    }

    #[test]
    fn exited_unslashed() {
        let v = make_validator(3, 5, 8, 20, false);
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::ExitedUnslashed
        );
    }

    #[test]
    fn exited_slashed() {
        let v = make_validator(3, 5, 8, 20, true);
        assert_eq!(
            derive_validator_status(&v, 10, 1000),
            ValidatorStatus::ExitedSlashed
        );
    }

    #[test]
    fn withdrawal_possible() {
        let v = make_validator(3, 5, 8, 10, false);
        assert_eq!(
            derive_validator_status(&v, 15, 1000),
            ValidatorStatus::WithdrawalPossible
        );
    }

    #[test]
    fn withdrawal_done() {
        let v = make_validator(3, 5, 8, 10, false);
        assert_eq!(
            derive_validator_status(&v, 15, 0),
            ValidatorStatus::WithdrawalDone
        );
    }

    #[test]
    fn broad_category_matching() {
        assert!(ValidatorStatus::ActiveOngoing.matches_filter("active"));
        assert!(ValidatorStatus::ActiveOngoing.matches_filter("active_ongoing"));
        assert!(!ValidatorStatus::ActiveOngoing.matches_filter("pending"));
        assert!(ValidatorStatus::PendingInitialized.matches_filter("pending"));
        assert!(ValidatorStatus::ExitedSlashed.matches_filter("exited"));
        assert!(ValidatorStatus::WithdrawalDone.matches_filter("withdrawal"));
    }
}
