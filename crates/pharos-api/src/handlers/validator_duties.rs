//! Validator-duties namespace handlers (Task 5.3).
//!
//! - `GET  /eth/v1/validator/duties/proposer/{epoch}`
//! - `POST /eth/v1/validator/duties/attester/{epoch}`  (body: JSON array of validator indices)
//! - `POST /eth/v1/validator/duties/sync/{epoch}`      (body: JSON array of validator indices)
//!
//! Spec shapes from:
//! - `~/dev/beacon-APIs/apis/validator/duties/proposer.v2.yaml`
//! - `~/dev/beacon-APIs/apis/validator/duties/attester.yaml`
//! - `~/dev/beacon-APIs/apis/validator/duties/sync.yaml`
//!
//! ## Optimistic node behaviour
//!
//! Per `consensus-specs/sync/optimistic.md` "Validator assignments":
//! - Duty-READ endpoints (proposer/attester/sync duties) MUST return HTTP 200
//!   even when the node is optimistic, with `execution_optimistic: true` in the
//!   response body.  Validators may read duties to prepare; they just MUST NOT
//!   act on them while optimistic.
//! - Production/signing endpoints (produce_block, produce_attestation_data,
//!   aggregate selection, sync_committee_contribution) MUST return HTTP 503
//!   when `chain.is_optimistic_node()` is true.  Those endpoints are not yet
//!   implemented (deferred past M7); the 503 contract is documented in
//!   `Task 5.4` below and is wired at the point of implementation.
//!
//! The `execution_optimistic` field is sourced from `chain.is_optimistic_node()`
//! (node-level flag, not just head-level) so it correctly reflects the case
//! where all viable FFG branches are Invalid and the node is stuck.
//!
//! STF helpers used:
//! - `pharos_stf::phase0::accessors::get_beacon_proposer_index` — proposer for `state.slot`
//! - `pharos_stf::phase0::accessors::compute_start_slot_at_epoch` — epoch → start slot
//! - `pharos_stf::phase0::accessors::get_block_root_at_slot` — `dependent_root` computation
//! - `pharos_stf::phase0::accessors::get_beacon_committee` — attester committee
//! - `pharos_stf::phase0::accessors::get_committee_count_per_slot` — committees per slot
//! - `pharos_stf::phase0::accessors::get_active_validator_indices` — active validator set
//! - `pharos_stf::phase0::accessors::get_seed` — epoch seed for proposer computation
//! - `pharos_stf::phase0::accessors::compute_proposer_index` — VRF-based proposer selection
//! - `pharos_stf::phase0::helpers::uint_to_bytes` — slot → bytes for proposer seed hash
//!
//! `dependent_root` required field (reference CL VCs reject missing it):
//! - proposer: `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`
//! - attester: `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch - 1) - 1)`
//! - epoch == 0 underflow: genesis block root from `ChainStateApi::genesis_block_root`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use pharos_types::BeaconSpec;
use pharos_types::views::ForkVariant;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::respond::{AcceptFormat, ApiResponse};
use crate::serde_helpers::{quoted_u64, serialize_hex32, serialize_hex48};
use crate::state::ApiState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Proposer duty per `~/dev/beacon-APIs/types/duty.yaml#ProposerDuty`.
#[derive(Serialize)]
pub struct ProposerDutyDto {
    #[serde(serialize_with = "serialize_hex48")]
    pub pubkey: [u8; 48],
    #[serde(with = "quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "quoted_u64")]
    pub slot: u64,
}

/// Proposer duties response per `~/dev/beacon-APIs/apis/validator/duties/proposer.v2.yaml`.
///
/// `dependent_root` is a REQUIRED top-level field; reference CL VCs reject a response
/// missing it.  Computed as `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`
/// (or genesis block root on epoch 0 underflow).
#[derive(Serialize)]
pub struct ProposerDutiesResponse {
    #[serde(serialize_with = "serialize_hex32")]
    pub dependent_root: [u8; 32],
    pub execution_optimistic: bool,
    pub data: Vec<ProposerDutyDto>,
}

/// Attester duty per `~/dev/beacon-APIs/types/duty.yaml#AttesterDuty`.
#[derive(Serialize)]
pub struct AttesterDutyDto {
    #[serde(serialize_with = "serialize_hex48")]
    pub pubkey: [u8; 48],
    #[serde(with = "quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "quoted_u64")]
    pub committee_length: u64,
    #[serde(with = "quoted_u64")]
    pub committees_at_slot: u64,
    #[serde(with = "quoted_u64")]
    pub validator_committee_index: u64,
    #[serde(with = "quoted_u64")]
    pub slot: u64,
}

/// Attester duties response per `~/dev/beacon-APIs/apis/validator/duties/attester.yaml`.
///
/// `dependent_root` is a REQUIRED top-level field.  Computed as
/// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch - 1) - 1)`
/// (or genesis block root on epoch 0 underflow).
#[derive(Serialize)]
pub struct AttesterDutiesResponse {
    #[serde(serialize_with = "serialize_hex32")]
    pub dependent_root: [u8; 32],
    pub execution_optimistic: bool,
    pub data: Vec<AttesterDutyDto>,
}

/// Sync committee duty per `~/dev/beacon-APIs/types/duty.yaml#Altair/SyncDuty`.
#[derive(Serialize)]
pub struct SyncDutyDto {
    #[serde(serialize_with = "serialize_hex48")]
    pub pubkey: [u8; 48],
    #[serde(with = "quoted_u64")]
    pub validator_index: u64,
    /// Indices of the validator's positions within the sync committee (may appear
    /// multiple times in the committee per spec).
    pub validator_sync_committee_indices: Vec<String>,
}

/// Sync duties response per `~/dev/beacon-APIs/apis/validator/duties/sync.yaml`.
#[derive(Serialize)]
pub struct SyncDutiesResponse {
    pub execution_optimistic: bool,
    pub data: Vec<SyncDutyDto>,
}

// ── Body ──────────────────────────────────────────────────────────────────────

/// JSON body for POST duties endpoints: array of quoted validator indices.
///
/// Deserializes directly from a JSON array (not an object), e.g. `["0","1","2"]`.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct ValidatorIndicesBody(pub Vec<serde_json::Value>);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute the proposer index for a specific slot without requiring `state.slot == slot`.
///
/// Implements the same VRF as `get_beacon_proposer_index` but takes `slot`
/// explicitly.  Uses the epoch seed (derived from state.randao_mixes) and the
/// target slot bytes to match the spec.
fn proposer_index_at_slot<E: BeaconSpec>(
    state: &E::BeaconState,
    slot: pharos_types::phase0::Slot,
) -> pharos_types::phase0::ValidatorIndex {
    use pharos_stf::electra::helpers::compute_proposer_index_electra;
    use pharos_stf::phase0::accessors::{
        compute_epoch_at_slot, compute_proposer_index, get_active_validator_indices, get_seed,
    };
    use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, uint_to_bytes};
    use pharos_types::BeaconStateView;
    use pharos_types::views::ForkVariant;
    use pharos_utils::{Bytes4, hash};

    // RI-6: a Fulu state carries the EIP-7917 precomputed `proposer_lookahead`.
    // Read it directly rather than recomputing on-demand (the M12 16-bit-proposer
    // gotcha that bit production, lookahead, and duties). The lookahead covers
    // `(MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH` slots starting at the current
    // epoch's first slot; `slot - current_epoch_start` indexes into it. Slots
    // outside the window fall through to the on-demand computation (which the spec
    // never requests for proposer duties — only current/next epoch).
    if state.fork_variant() == ForkVariant::Fulu {
        if let Some(lookahead) = state.proposer_lookahead_vec() {
            let current_epoch = compute_epoch_at_slot(state.slot(), E::SLOTS_PER_EPOCH);
            let window_start = current_epoch.0 * E::SLOTS_PER_EPOCH;
            if slot.0 >= window_start {
                let offset = (slot.0 - window_start) as usize;
                if let Some(idx) = lookahead.get(offset).copied() {
                    return idx;
                }
            }
        }
    }

    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let seed_base = get_seed::<E>(state, epoch, Bytes4::from_array(DOMAIN_BEACON_PROPOSER));
    let slot_bytes = uint_to_bytes(slot.0);
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(seed_base.as_slice());
    input[32..].copy_from_slice(&slot_bytes);
    let seed = hash::hash(&input);
    let indices = get_active_validator_indices::<E>(state, epoch);
    // EIP-7251: electra (and Fulu, when outside the lookahead window) use the
    // 16-bit proposer selection. This MUST match `produce_block` /
    // `get_beacon_proposer_index_electra` and the STF, or the VC signs as the
    // wrong proposer and the block fails the step-2 signature check.
    if matches!(
        state.fork_variant(),
        ForkVariant::Electra | ForkVariant::Fulu
    ) {
        compute_proposer_index_electra::<E>(state, &indices, &seed)
    } else {
        compute_proposer_index::<E>(state, &indices, &seed)
    }
}

/// Compute the `dependent_root` for proposer duties.
///
/// **Pre-Fulu** (`Phase0`..`Electra`):
///   `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`
///
/// **Post-Fulu** (`Fulu`):
///   `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch - 1) - 1)`
///   (spec: `proposer.v2.yaml` — `dependent_root` shifts to the *previous* epoch's
///   start because the deterministic lookahead (EIP-7917) is computed at epoch − 1).
///
/// Falls back to genesis block root on underflow (epoch 0 or epoch 1 in the Fulu path).
///
/// ## Latent v1 bug fixed here
///
/// The original `proposer_dependent_root` used the pre-Fulu formula for all forks.
/// When a Fulu node served v1 proposer duties it returned the wrong `dependent_root`.
/// The exhaustive match below (no `_ =>` fallback) corrects this: both v1 and v2 now
/// route through this shared function and get the fork-correct value.
/// (ADR: `D-proposer-dependent-root-fulu-fix`)
fn proposer_dependent_root<E: BeaconSpec>(
    state: &E::BeaconState,
    epoch: pharos_types::phase0::Epoch,
    genesis_block_root: pharos_types::phase0::Root,
) -> pharos_types::phase0::Root {
    use pharos_stf::phase0::accessors::{compute_start_slot_at_epoch, get_block_root_at_slot};
    use pharos_types::views::BeaconStateView as _;

    match state.fork_variant() {
        ForkVariant::Phase0
        | ForkVariant::Altair
        | ForkVariant::Bellatrix
        | ForkVariant::Capella
        | ForkVariant::Deneb
        | ForkVariant::Electra => {
            // Pre-Fulu: dependent root is at `compute_start_slot_at_epoch(epoch) - 1`.
            let start = compute_start_slot_at_epoch(epoch, E::SLOTS_PER_EPOCH);
            if start.0 == 0 {
                return genesis_block_root;
            }
            let dep_slot = pharos_types::phase0::Slot(start.0 - 1);
            get_block_root_at_slot::<E>(state, dep_slot).unwrap_or(genesis_block_root)
        }
        ForkVariant::Fulu => {
            // Post-Fulu (EIP-7917): dependent root is at
            // `compute_start_slot_at_epoch(epoch - 1) - 1`.
            // Underflow: epoch 0 → genesis block root.
            if epoch.0 == 0 {
                return genesis_block_root;
            }
            let prev_epoch = pharos_types::phase0::Epoch(epoch.0 - 1);
            let start = compute_start_slot_at_epoch(prev_epoch, E::SLOTS_PER_EPOCH);
            if start.0 == 0 {
                return genesis_block_root;
            }
            let dep_slot = pharos_types::phase0::Slot(start.0 - 1);
            get_block_root_at_slot::<E>(state, dep_slot).unwrap_or(genesis_block_root)
        }
    }
}

/// Compute the `dependent_root` for attester duties.
///
/// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch - 1) - 1)`.
/// Falls back to genesis block root on epoch-0 or epoch-1 underflow.
fn attester_dependent_root<E: BeaconSpec>(
    state: &E::BeaconState,
    epoch: pharos_types::phase0::Epoch,
    genesis_block_root: pharos_types::phase0::Root,
) -> pharos_types::phase0::Root {
    use pharos_stf::phase0::accessors::{compute_start_slot_at_epoch, get_block_root_at_slot};

    if epoch.0 == 0 {
        return genesis_block_root;
    }
    let prev_epoch = pharos_types::phase0::Epoch(epoch.0 - 1);
    let start = compute_start_slot_at_epoch(prev_epoch, E::SLOTS_PER_EPOCH);
    if start.0 == 0 {
        return genesis_block_root;
    }
    let dep_slot = pharos_types::phase0::Slot(start.0 - 1);
    get_block_root_at_slot::<E>(state, dep_slot).unwrap_or(genesis_block_root)
}

/// Parse a JSON array of quoted/unquoted validator indices from the POST body.
///
/// Returns `ApiError::BadRequest` when the array is empty, per
/// `minItems: 1` on the attester and sync duty schemas.
fn parse_validator_indices(body: &ValidatorIndicesBody) -> Result<Vec<usize>, ApiError> {
    if body.0.is_empty() {
        return Err(ApiError::BadRequest(
            "validator indices array must not be empty (minItems: 1)".into(),
        ));
    }
    body.0
        .iter()
        .map(|v| {
            let idx: u64 = match v {
                serde_json::Value::String(s) => s
                    .parse()
                    .map_err(|_| ApiError::BadRequest(format!("invalid validator index: {s}")))?,
                serde_json::Value::Number(n) => n
                    .as_u64()
                    .ok_or_else(|| ApiError::BadRequest("invalid validator index number".into()))?,
                other => {
                    return Err(ApiError::BadRequest(format!(
                        "expected validator index, got: {other:?}"
                    )));
                }
            };
            Ok(idx as usize)
        })
        .collect()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/validator/duties/proposer/{epoch}`
///
/// Per `~/dev/beacon-APIs/apis/validator/duties/proposer.v2.yaml`.
/// Sets `Eth-Consensus-Version` response header (fork of the resolved state).
pub async fn get_proposer_duties<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(epoch): Path<u64>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        use pharos_stf::phase0::accessors::compute_start_slot_at_epoch;
        use pharos_types::phase0::{Epoch, Slot};
        use pharos_types::views::BeaconStateView;

        if chain.is_syncing() {
            return Err(ApiError::NotSynced(
                "node is syncing; proposer duties not yet available".into(),
            ));
        }

        let target_epoch = Epoch(epoch);
        let head_root = chain.head_root();
        let genesis_block_root = chain.genesis_block_root();
        // Duty reads stay 200 even when optimistic; reflect the flag in the
        // response body per `consensus-specs/sync/optimistic.md` "Validator
        // assignments". Use is_optimistic_node for node-level accuracy.
        let is_optimistic = chain.is_optimistic_node();

        // Use the head state for duty computation (best available view of shuffling).
        let beacon_state = chain
            .state_by_block_root(head_root)
            .ok_or_else(|| ApiError::NotFound("head state not available".into()))?;

        let epoch_start = compute_start_slot_at_epoch(target_epoch, E::SLOTS_PER_EPOCH);

        // Dependent root (required field).
        let dep_root =
            proposer_dependent_root::<E>(&beacon_state, target_epoch, genesis_block_root);

        // Compute proposer for each slot in the epoch.
        let mut duties = Vec::new();
        for slot_offset in 0..E::SLOTS_PER_EPOCH {
            let slot = Slot(epoch_start.0 + slot_offset);
            let proposer = proposer_index_at_slot::<E>(&beacon_state, slot);
            let idx = proposer.0 as usize;
            let pubkey = beacon_state
                .validator(idx)
                .ok_or_else(|| ApiError::Internal(format!("proposer index {idx} out of range")))?
                .pubkey
                .as_slice()
                .try_into()
                .map_err(|_| ApiError::Internal("pubkey length error".into()))?;
            duties.push(ProposerDutyDto {
                pubkey,
                validator_index: proposer.0,
                slot: slot.0,
            });
        }

        let fork_variant = beacon_state.fork_variant();
        Ok::<_, ApiError>((
            ProposerDutiesResponse {
                dependent_root: dep_root.into_inner(),
                execution_optimistic: is_optimistic,
                data: duties,
            },
            fork_variant,
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((resp, fork_variant))) => {
            use crate::fork_tag::{ETH_CONSENSUS_VERSION, fork_variant_str};
            let version = fork_variant_str(fork_variant);
            let body = match serde_json::to_vec(&resp) {
                Ok(b) => b,
                Err(e) => return ApiError::Internal(format!("JSON error: {e}")).into_response(),
            };
            let mut r = (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response();
            if let Ok(hv) = axum::http::HeaderValue::from_str(version) {
                r.headers_mut().insert(ETH_CONSENSUS_VERSION.clone(), hv);
            }
            r
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/validator/duties/proposer/{epoch}`
///
/// Per `~/dev/beacon-APIs/apis/validator/duties/proposer.v2.yaml`.
///
/// The v2 response schema is byte-identical to v1 (`{dependent_root,
/// execution_optimistic, data: [ProposerDuty]}`).  The only semantic change is
/// the `dependent_root` formula for Fulu states (EIP-7917), which is already
/// handled by the shared `proposer_dependent_root` helper (the same helper that
/// v1 now uses, fixing the latent v1 Fulu `dependent_root` bug).
///
/// `is_syncing()` 503 guard matches v1 exactly.  No `is_optimistic_node()` 503
/// per the M8 duty-read contract.
///
/// (ADR: `D-proposer-duties-v2-shares-v1`)
pub async fn get_proposer_duties_v2<E: BeaconSpec>(
    state: State<Arc<ApiState<E>>>,
    path: Path<u64>,
) -> Response {
    // v2 is a thin alias: the shared proposer_dependent_root already contains the
    // fork-correct formula (pre-Fulu vs Fulu), so both v1 and v2 delegate here.
    get_proposer_duties::<E>(state, path).await
}

/// `POST /eth/v1/validator/duties/attester/{epoch}`
///
/// Body: JSON array of validator indices (quoted or unquoted).
/// Per `~/dev/beacon-APIs/apis/validator/duties/attester.yaml`.
pub async fn post_attester_duties<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(epoch): Path<u64>,
    Json(body): Json<ValidatorIndicesBody>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        use pharos_stf::phase0::accessors::{
            compute_start_slot_at_epoch, get_beacon_committee, get_committee_count_per_slot,
        };
        use pharos_types::phase0::{Epoch, Slot};
        use pharos_types::views::BeaconStateView;

        if chain.is_syncing() {
            return Err(ApiError::NotSynced(
                "node is syncing; attester duties not yet available".into(),
            ));
        }

        let target_epoch = Epoch(epoch);
        let indices = parse_validator_indices(&body)?;
        let head_root = chain.head_root();
        let genesis_block_root = chain.genesis_block_root();
        // Duty reads stay 200 even when optimistic; reflect the flag in the
        // response body per `consensus-specs/sync/optimistic.md` "Validator
        // assignments". Use is_optimistic_node for node-level accuracy.
        let is_optimistic = chain.is_optimistic_node();

        let beacon_state = chain
            .state_by_block_root(head_root)
            .ok_or_else(|| ApiError::NotFound("head state not available".into()))?;

        let epoch_start = compute_start_slot_at_epoch(target_epoch, E::SLOTS_PER_EPOCH);

        // Dependent root (required field).
        let dep_root =
            attester_dependent_root::<E>(&beacon_state, target_epoch, genesis_block_root);

        let committees_per_slot = get_committee_count_per_slot::<E>(&beacon_state, target_epoch);

        // Build index → duty mapping for all requested validator indices.
        let mut duties = Vec::new();
        for target_idx in &indices {
            let target_idx = *target_idx;
            let v = beacon_state.validator(target_idx).ok_or_else(|| {
                ApiError::BadRequest(format!("validator index {target_idx} out of range"))
            })?;
            let pubkey: [u8; 48] = v
                .pubkey
                .as_slice()
                .try_into()
                .map_err(|_| ApiError::Internal("pubkey length error".into()))?;

            // Scan all slots in the epoch to find where this validator sits.
            let mut found = false;
            'outer: for slot_offset in 0..E::SLOTS_PER_EPOCH {
                let slot = Slot(epoch_start.0 + slot_offset);
                for committee_index in 0..committees_per_slot {
                    let committee = get_beacon_committee::<E>(&beacon_state, slot, committee_index);
                    if let Some(pos) = committee.iter().position(|vi| vi.0 as usize == target_idx) {
                        duties.push(AttesterDutyDto {
                            pubkey,
                            validator_index: target_idx as u64,
                            committee_index,
                            committee_length: committee.len() as u64,
                            committees_at_slot: committees_per_slot,
                            validator_committee_index: pos as u64,
                            slot: slot.0,
                        });
                        found = true;
                        break 'outer;
                    }
                }
            }
            // Validators not active in this epoch have no duty — skip silently.
            let _ = found;
        }

        Ok::<_, ApiError>(AttesterDutiesResponse {
            dependent_root: dep_root.into_inner(),
            execution_optimistic: is_optimistic,
            data: duties,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(resp)) => ApiResponse::json(resp).render(AcceptFormat::Json),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /eth/v1/validator/duties/sync/{epoch}`
///
/// Body: JSON array of validator indices (quoted or unquoted).
/// Per `~/dev/beacon-APIs/apis/validator/duties/sync.yaml`.
///
/// Phase0 states have no sync committee; returns empty data with a note.
pub async fn post_sync_duties<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(epoch): Path<u64>,
    Json(body): Json<ValidatorIndicesBody>,
) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || {
        use pharos_types::phase0::Epoch;
        use pharos_types::views::BeaconStateView;

        if chain.is_syncing() {
            return Err(ApiError::NotSynced(
                "node is syncing; sync duties not yet available".into(),
            ));
        }

        let target_epoch = Epoch(epoch);
        let indices = parse_validator_indices(&body)?;
        let head_root = chain.head_root();
        // Duty reads stay 200 even when optimistic; reflect the flag in the
        // response body per `consensus-specs/sync/optimistic.md` "Validator
        // assignments". Use is_optimistic_node for node-level accuracy.
        let is_optimistic = chain.is_optimistic_node();

        let beacon_state = chain
            .state_by_block_root(head_root)
            .ok_or_else(|| ApiError::NotFound("head state not available".into()))?;

        // Phase0 has no sync committee — return empty duties.
        if beacon_state.fork_variant() == ForkVariant::Phase0 {
            return Ok::<_, ApiError>(SyncDutiesResponse {
                execution_optimistic: is_optimistic,
                data: vec![],
            });
        }

        // Determine which sync committee period the target epoch falls into.
        let current_period = {
            use pharos_stf::phase0::accessors::compute_epoch_at_slot;
            let state_epoch = compute_epoch_at_slot(beacon_state.slot(), E::SLOTS_PER_EPOCH);
            state_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
        };
        let target_period = target_epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

        // Retrieve sync committee pubkeys via the chain API.
        let (curr_pks, next_pks) = chain
            .sync_committee_pubkeys(head_root)
            .ok_or_else(|| {
                ApiError::NotFound("sync committees not available for this state".into())
            })?;

        let sc_pubkeys: &Vec<[u8; 48]> = if target_period == current_period {
            &curr_pks
        } else if target_period == current_period + 1 {
            &next_pks
        } else {
            return Err(ApiError::BadRequest(format!(
                "epoch period {target_period} is outside current ({current_period}) or next ({}) sync committee period",
                current_period + 1
            )));
        };

        // Build pubkey → validator index mapping.
        let mut pk_to_idx: std::collections::HashMap<Vec<u8>, usize> =
            std::collections::HashMap::new();
        for (i, v) in beacon_state.validators_iter().enumerate() {
            pk_to_idx.insert(v.pubkey.as_slice().to_vec(), i);
        }

        let mut duties = Vec::new();
        for target_idx in &indices {
            let target_idx = *target_idx;
            let v = beacon_state
                .validator(target_idx)
                .ok_or_else(|| {
                    ApiError::BadRequest(format!("validator index {target_idx} out of range"))
                })?;
            let pubkey: [u8; 48] = v.pubkey.as_slice().try_into().map_err(|_| {
                ApiError::Internal("pubkey length error".into())
            })?;

            // Find all positions where this validator's pubkey appears in the committee.
            let positions: Vec<String> = sc_pubkeys
                .iter()
                .enumerate()
                .filter_map(|(pos, pk)| {
                    if pk.as_slice() == v.pubkey.as_slice() {
                        Some(pos.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            if !positions.is_empty() {
                duties.push(SyncDutyDto {
                    pubkey,
                    validator_index: target_idx as u64,
                    validator_sync_committee_indices: positions,
                });
            }
        }

        Ok::<_, ApiError>(SyncDutiesResponse {
            execution_optimistic: is_optimistic,
            data: duties,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(resp)) => ApiResponse::json(resp).render(AcceptFormat::Json),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
