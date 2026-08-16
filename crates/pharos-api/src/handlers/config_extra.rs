//! Extra config namespace handlers (Phase 3).
//!
//! - `GET /eth/v1/config/fork_schedule`
//! - `GET /eth/v1/config/deposit_contract`
//!
//! Spec shapes from:
//! - `~/dev/beacon-APIs/apis/config/fork_schedule.yaml`
//! - `~/dev/beacon-APIs/apis/config/deposit_contract.yaml`

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_types::EthSpec;
use serde::Serialize;

use crate::respond::{ApiResponse, parse_accept};
use crate::serde_helpers::{quoted_u64, serialize_hex4, serialize_hex20};
use crate::state::ApiState;

// ── Fork schedule ─────────────────────────────────────────────────────────────

/// A single entry in the fork schedule.
///
/// Per `~/dev/beacon-APIs/apis/config/fork_schedule.yaml` and the spec's `Fork`
/// container: `previous_version`, `current_version`, `epoch`.
#[derive(Serialize)]
struct ForkDto {
    #[serde(serialize_with = "serialize_hex4")]
    previous_version: [u8; 4],
    #[serde(serialize_with = "serialize_hex4")]
    current_version: [u8; 4],
    #[serde(with = "quoted_u64")]
    epoch: u64,
}

#[derive(Serialize)]
struct ForkScheduleResponse {
    data: Vec<ForkDto>,
}

/// `GET /eth/v1/config/fork_schedule`
///
/// Returns all known forks from the `RuntimeConfig` fork schedule.
/// Per `~/dev/beacon-APIs/apis/config/fork_schedule.yaml`.
pub async fn get_fork_schedule<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let dto = tokio::task::spawn_blocking(move || {
        let cfg = chain.runtime_cfg();
        // The beacon API spec returns forks in ascending epoch order.
        // Phase0 → Altair → Bellatrix → Capella.
        vec![
            ForkDto {
                previous_version: cfg.genesis_fork_version,
                current_version: cfg.genesis_fork_version,
                epoch: 0,
            },
            ForkDto {
                previous_version: cfg.genesis_fork_version,
                current_version: cfg.altair_fork_version,
                epoch: cfg.altair_fork_epoch,
            },
            ForkDto {
                previous_version: cfg.altair_fork_version,
                current_version: cfg.bellatrix_fork_version,
                epoch: cfg.bellatrix_fork_epoch,
            },
            ForkDto {
                previous_version: cfg.bellatrix_fork_version,
                current_version: cfg.capella_fork_version,
                epoch: cfg.capella_fork_epoch,
            },
            ForkDto {
                previous_version: cfg.capella_fork_version,
                current_version: cfg.deneb_fork_version,
                epoch: cfg.deneb_fork_epoch,
            },
        ]
    })
    .await;

    match dto {
        Ok(data) => ApiResponse::json(ForkScheduleResponse { data }).render(format),
        Err(e) => crate::error::ApiError::Internal(format!("spawn_blocking: {e}")).into_response(),
    }
}

// ── Deposit contract ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct DepositContractData {
    #[serde(with = "quoted_u64")]
    chain_id: u64,
    /// `0x`-prefixed hex encoding of the 20-byte deposit contract address.
    #[serde(serialize_with = "serialize_hex20")]
    address: [u8; 20],
}

#[derive(Serialize)]
struct DepositContractResponse {
    data: DepositContractData,
}

/// `GET /eth/v1/config/deposit_contract`
///
/// Returns the deposit contract address and chain ID from `RuntimeConfig`.
/// Per `~/dev/beacon-APIs/apis/config/deposit_contract.yaml`.
pub async fn get_deposit_contract<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let chain = Arc::clone(&state.chain);
    let dto = tokio::task::spawn_blocking(move || {
        let cfg = chain.runtime_cfg();
        DepositContractResponse {
            data: DepositContractData {
                chain_id: cfg.deposit_chain_id,
                address: cfg.deposit_contract_address,
            },
        }
    })
    .await;

    match dto {
        Ok(resp) => ApiResponse::json(resp).render(format),
        Err(e) => crate::error::ApiError::Internal(format!("spawn_blocking: {e}")).into_response(),
    }
}
