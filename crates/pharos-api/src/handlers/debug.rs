//! Debug namespace handlers (Task 5.4).
//!
//! - `GET /eth/v1/debug/fork_choice`     — fork-choice node dump
//! - `GET /eth/v2/debug/beacon/heads`    — fork-choice leaf nodes
//! - `GET /eth/v2/debug/beacon/states/{state_id}` — full BeaconState (fork-tagged, JSON + SSZ)
//! - `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}` — PeerDAS column sidecars (M15 Phase 5)
//!
//! Spec shapes from:
//! `~/dev/beacon-APIs/apis/debug/{fork_choice,heads.v2,state.v2,data_column_sidecars}.yaml`
//! `~/dev/beacon-APIs/types/fork_choice.yaml`
//! `~/dev/beacon-APIs/types/fulu/data_column_sidecar.yaml`
//!
//! The state endpoint reuses `resolve_state_id` + `ForkTagged<T>` from Phase 3
//! (Tasks 2.2 / 3.1) — no new resolution path.  The JSON serialization is
//! handled by `ChainStateApi::state_to_json`, whose default implementation uses
//! `BeaconStateView` accessors common to all forks; `NodeChainState` provides
//! the full per-fork field access where the concrete types are available.
//!
//! The data-column-sidecars endpoint (`getDebugDataColumnSidecars`) is
//! fork-tagged with `version: "fulu"` when the block is Fulu (column sidecars
//! only exist on Fulu+), or the block's actual fork string when pre-Fulu
//! (returns 200 `{data: []}`).  The optional `indices` query param filters the
//! returned sidecars to those whose `index` is in the supplied set.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_ssz::Encode as _;
use pharos_types::fulu::DataColumnSidecarView;
use pharos_types::{BeaconSpec, BeaconStateView};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::fork_tag::{ForkTagged, fork_variant_at_slot};
use crate::resolve::{resolve_block_id, resolve_state_id};
use crate::respond::{AcceptFormat, ApiResponse, parse_accept};
use crate::state::ApiState;

// ── Query params ─────────────────────────────────────────────────────────────

/// Query parameters for `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}`.
///
/// `indices` is a comma-separated list of `uint64` column indices.  When
/// present, only sidecars whose `index` is in the list are returned.
/// When absent, all custodied sidecars for the block are returned.
/// There are no ordering guarantees per the spec.
#[derive(Debug, Deserialize, Default)]
pub struct DataColumnSidecarsQuery {
    /// Optional filter: comma-separated column indices (`uint64`).
    #[serde(default)]
    pub indices: Option<String>,
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Format a byte slice as a `0x`-prefixed hex string.
fn hex_str(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Serialize a `DataColumnSidecar` to a `serde_json::Value` per
/// `~/dev/beacon-APIs/types/fulu/data_column_sidecar.yaml`.
///
/// Fields (all required):
/// - `index`: `Uint64` (quoted string)
/// - `column`: array of `DataColumn` (each `0x<4096 hex chars>`)
/// - `kzg_commitments`: array of `KZGCommitment` (`0x<96 hex chars>`)
/// - `kzg_proofs`: array of `KZGProof` (`0x<96 hex chars>`)
/// - `signed_block_header`: `SignedBeaconBlockHeader` nested object
/// - `kzg_commitments_inclusion_proof`: array of `Bytes32` (`0x<64 hex chars>`)
fn data_column_sidecar_to_json(s: &pharos_types::fulu::MainnetDataColumnSidecar) -> JsonValue {
    // column: each Cell = SszVector<u8, 2048> → 2048 raw bytes → 4096 hex chars.
    let column: Vec<JsonValue> = s
        .column_iter()
        .map(|cell| hex_str(cell.as_slice()).into())
        .collect();

    // kzg_commitments: each KZGCommitment = FixedBytes<48> → 48 bytes → 96 hex chars.
    let kzg_commitments: Vec<JsonValue> = s
        .kzg_commitments()
        .iter()
        .map(|c| hex_str(c.as_slice()).into())
        .collect();

    // kzg_proofs: each KZGProof = FixedBytes<48> → 48 bytes → 96 hex chars.
    let kzg_proofs: Vec<JsonValue> = s
        .kzg_proofs()
        .iter()
        .map(|p| hex_str(p.as_slice()).into())
        .collect();

    // signed_block_header: SignedBeaconBlockHeader.
    let hdr = s.signed_block_header();
    let signed_block_header = serde_json::json!({
        "message": {
            "slot":            hdr.message.slot.0.to_string(),
            "proposer_index":  hdr.message.proposer_index.0.to_string(),
            "parent_root":     hex_str(hdr.message.parent_root.as_slice()),
            "state_root":      hex_str(hdr.message.state_root.as_slice()),
            "body_root":       hex_str(hdr.message.body_root.as_slice()),
        },
        "signature": hex_str(hdr.signature.as_slice()),
    });

    // kzg_commitments_inclusion_proof: Vector[Bytes32, 4] → array of 0x<64 hex>.
    let kzg_commitments_inclusion_proof: Vec<JsonValue> = s
        .inclusion_proof_iter()
        .map(|b| hex_str(b.as_slice()).into())
        .collect();

    serde_json::json!({
        "index":                          s.index().to_string(),
        "column":                         column,
        "kzg_commitments":                kzg_commitments,
        "kzg_proofs":                     kzg_proofs,
        "signed_block_header":            signed_block_header,
        "kzg_commitments_inclusion_proof": kzg_commitments_inclusion_proof,
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/debug/fork_choice`
///
/// Dumps all in-memory fork-choice blocks.  Sources from
/// `ChainStateApi::fork_choice_dump`.
pub async fn get_fork_choice<E: BeaconSpec>(State(state): State<Arc<ApiState<E>>>) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.fork_choice_dump())
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(v)) => ApiResponse::json(v).render(AcceptFormat::Json),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/debug/beacon/heads`
///
/// Returns the set of leaf nodes in the in-memory fork-choice tree.
pub async fn get_beacon_heads<E: BeaconSpec>(State(state): State<Arc<ApiState<E>>>) -> Response {
    let chain = Arc::clone(&state.chain);
    let result = tokio::task::spawn_blocking(move || chain.fork_choice_heads())
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok(v)) => ApiResponse::json(v).render(AcceptFormat::Json),
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v2/debug/beacon/states/{state_id}`
///
/// Returns the full `BeaconState` for the resolved id, fork-tagged.
/// Reuses `resolve_state_id` + `ForkTagged<T>` from Phase 3.
///
/// JSON: `ChainStateApi::state_to_json` — required method, produces complete
/// fork-tagged fields via `beacon_state_to_json_full`.
/// SSZ: raw `Encode::as_ssz_bytes`.
pub async fn get_debug_state<E: BeaconSpec>(
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

        let variant = beacon_state.fork_variant();
        let ssz_bytes = beacon_state.as_ssz_bytes();
        let json_val = chain.state_to_json(beacon_state)?;

        Ok::<_, ApiError>((
            variant,
            resolved.execution_optimistic,
            resolved.finalized,
            json_val,
            ssz_bytes,
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((variant, eo, finalized, json_val, ssz_bytes))) => {
            ForkTagged::new(variant, eo, finalized, json_val).render(format, Some(ssz_bytes))
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}`
///
/// Per `~/dev/beacon-APIs/apis/debug/data_column_sidecars.yaml`
/// (`getDebugDataColumnSidecars`).
///
/// Returns all custodied `DataColumnSidecar`s for the given block, fork-tagged.
/// The `indices` query param (comma-separated `uint64`) optionally filters the
/// result to those column indices.
///
/// Responses:
/// - 200 JSON: `{version, execution_optimistic, finalized, data: [DataColumnSidecar, ...]}`
///   + `Eth-Consensus-Version` header.
///   - `version` is the block's fork (exhaustive match on `fork_variant_at_slot`).
///   - Pre-Fulu blocks (or blocks with no custodied columns) return `data: []`.
/// - 200 SSZ (`Accept: application/octet-stream`): concatenated SSZ bytes of
///   each `DataColumnSidecar` + `Eth-Consensus-Version` header.
/// - 400: unparseable block_id or malformed `indices` value.
/// - 404: block not found.
/// - 406: unsupported Accept.
pub async fn get_data_column_sidecars<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    Query(query): Query<DataColumnSidecarsQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    // Parse the optional `indices` CSV filter into a `Vec<u64>`.
    // A parse error means the caller provided a malformed index → 400.
    let indices_filter: Option<Vec<u64>> = match &query.indices {
        None => None,
        Some(csv) => {
            let tokens: Vec<&str> = csv
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if tokens.is_empty() {
                None
            } else {
                let mut parsed = Vec::with_capacity(tokens.len());
                for t in tokens {
                    match t.parse::<u64>() {
                        Ok(v) => parsed.push(v),
                        Err(_) => {
                            return ApiError::BadRequest(format!(
                                "indices: '{}' is not a valid uint64",
                                t
                            ))
                            .into_response();
                        }
                    }
                }
                Some(parsed)
            }
        }
    };

    let chain = Arc::clone(&state.chain);

    let result = tokio::task::spawn_blocking(move || {
        // 1. Resolve block_id → block_root (404 if unknown, 400 if malformed).
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;

        // 2. Determine the block's fork variant from its slot.
        //    `block_header_at` returns `Some` when the block is known (it was
        //    just resolved above), so this should always be `Some`.
        let slot = chain
            .block_header_at(resolved.block_root)
            .map(|h| h.slot.0)
            .unwrap_or(0);
        let cfg = chain.runtime_cfg();
        let variant =
            fork_variant_at_slot(&cfg, slot, <E as pharos_types::BeaconSpec>::SLOTS_PER_EPOCH);

        // 3. Fetch all stored data column sidecars for this block root.
        //    Pre-Fulu blocks carry zero sidecars — this is NOT a 404.
        let all_sidecars = chain.data_column_sidecars_by_root(resolved.block_root);

        // 4. Apply the optional `indices` filter.
        let sidecars: Vec<pharos_types::fulu::MainnetDataColumnSidecar> =
            if let Some(ref filter) = indices_filter {
                all_sidecars
                    .into_iter()
                    .filter(|s| filter.contains(&s.index))
                    .collect()
            } else {
                all_sidecars
            };

        Ok::<_, ApiError>((
            variant,
            resolved.execution_optimistic,
            resolved.finalized,
            sidecars,
        ))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((variant, execution_optimistic, finalized, sidecars))) => {
            // Build the JSON data array for both paths (SSZ also needs the
            // version header, which ForkTagged::render sets from the variant).
            let data: Vec<JsonValue> = sidecars.iter().map(data_column_sidecar_to_json).collect();

            match format {
                AcceptFormat::Json => {
                    // `ForkTagged::new(variant, eo, finalized, data)` serialises to:
                    // `{version, execution_optimistic, finalized, data: [...]}`
                    // which matches the spec schema exactly.
                    ForkTagged::new(variant, execution_optimistic, finalized, data)
                        .render(AcceptFormat::Json, None)
                }
                AcceptFormat::Ssz => {
                    // SSZ: concatenate the SSZ encoding of each sidecar.
                    let mut ssz_buf: Vec<u8> = Vec::new();
                    for s in &sidecars {
                        s.ssz_append(&mut ssz_buf);
                    }
                    // The `data` field of ForkTagged is not used on the SSZ
                    // path — `render(Ssz, Some(ssz_buf))` uses the raw bytes.
                    ForkTagged::new(
                        variant,
                        execution_optimistic,
                        finalized,
                        serde_json::json!(null),
                    )
                    .render(AcceptFormat::Ssz, Some(ssz_buf))
                }
            }
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}
