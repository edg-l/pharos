//! Fork-tagging envelope for `/eth/v2` responses.
//!
//! Per `D-api-fork-tag-envelope`:
//! - `/eth/v2` responses wrap the DTO in `{ version, execution_optimistic, finalized, data }`.
//! - The `Eth-Consensus-Version` response header is set to the same version string
//!   on BOTH the JSON and SSZ response paths.
//! - The version string is derived from the block/state `fork_variant()`.
//!
//! Also contains `fork_variant_at_slot` and `render_lc_envelope` helpers used
//! by the light-client REST handlers (per `D-api-lc-fork-tag-by-attested-slot`).

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pharos_types::config::RuntimeConfig;
use pharos_types::views::ForkVariant;
use serde::Serialize;

use crate::dto::light_client::LcEnvelope;
use crate::error::ApiError;
use crate::respond::AcceptFormat;

// ── Header constants ──────────────────────────────────────────────────────────

/// `Eth-Consensus-Version` response header name, as specified by the Beacon API.
pub static ETH_CONSENSUS_VERSION: HeaderName = HeaderName::from_static("eth-consensus-version");

/// Map a `ForkVariant` to its lowercase string as required by the Beacon API spec.
pub fn fork_variant_str(variant: ForkVariant) -> &'static str {
    match variant {
        ForkVariant::Phase0 => "phase0",
        ForkVariant::Altair => "altair",
        ForkVariant::Bellatrix => "bellatrix",
        ForkVariant::Capella => "capella",
        ForkVariant::Deneb => "deneb",
    }
}

// ── ForkTagged ────────────────────────────────────────────────────────────────

/// A fork-tagged response envelope.
///
/// Produces `{ "version": "...", "execution_optimistic": bool, "finalized": bool, "data": T }`
/// and sets the `Eth-Consensus-Version` response header on both JSON and SSZ paths.
#[derive(Serialize)]
pub struct ForkTagged<T: Serialize> {
    pub version: &'static str,
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: T,
}

impl<T: Serialize> ForkTagged<T> {
    pub fn new(variant: ForkVariant, execution_optimistic: bool, finalized: bool, data: T) -> Self {
        Self {
            version: fork_variant_str(variant),
            execution_optimistic,
            finalized,
            data,
        }
    }

    /// Render the fork-tagged response for the given `AcceptFormat`.
    ///
    /// JSON path: serialises `self` as JSON with `Content-Type: application/json`.
    /// SSZ path: uses the provided pre-encoded SSZ bytes with
    ///           `Content-Type: application/octet-stream`.
    /// Both paths set the `Eth-Consensus-Version` header.
    pub fn render(self, format: AcceptFormat, ssz_bytes: Option<Vec<u8>>) -> Response {
        let version_header = match HeaderValue::from_str(self.version) {
            Ok(v) => v,
            Err(_) => {
                return ApiError::Internal("invalid fork version string".to_string())
                    .into_response();
            }
        };

        let mut extra_headers = HeaderMap::new();
        extra_headers.insert(ETH_CONSENSUS_VERSION.clone(), version_header);

        match format {
            AcceptFormat::Json => {
                let body = match serde_json::to_vec(&self) {
                    Ok(b) => b,
                    Err(e) => {
                        return ApiError::Internal(format!("JSON serialization error: {e}"))
                            .into_response();
                    }
                };
                let mut resp = (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response();
                resp.headers_mut().insert(
                    ETH_CONSENSUS_VERSION.clone(),
                    extra_headers[&ETH_CONSENSUS_VERSION].clone(),
                );
                resp
            }
            AcceptFormat::Ssz => match ssz_bytes {
                Some(bytes) => {
                    let mut resp = (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/octet-stream")],
                        bytes,
                    )
                        .into_response();
                    resp.headers_mut().insert(
                        ETH_CONSENSUS_VERSION.clone(),
                        extra_headers[&ETH_CONSENSUS_VERSION].clone(),
                    );
                    resp
                }
                None => ApiError::NotAcceptable("SSZ not available for this endpoint".to_string())
                    .into_response(),
            },
        }
    }
}

// ── Light-client fork helpers ─────────────────────────────────────────────────

/// Determine the `ForkVariant` active at `slot`.
///
/// Converts `slot` to an epoch (`slot / SLOTS_PER_EPOCH`) and returns the
/// highest fork that has activated at or before that epoch.
///
/// `slots_per_epoch` is passed directly (caller uses `E::SLOTS_PER_EPOCH`) so
/// this function does not need to be generic over `E`.
///
/// Per `D-api-lc-fork-tag-by-attested-slot`.
pub fn fork_variant_at_slot(cfg: &RuntimeConfig, slot: u64, slots_per_epoch: u64) -> ForkVariant {
    let epoch = slot.checked_div(slots_per_epoch).unwrap_or(0);
    // Walk forks from highest to lowest; return the first that has activated.
    if cfg.deneb_fork_epoch != u64::MAX && epoch >= cfg.deneb_fork_epoch {
        ForkVariant::Deneb
    } else if cfg.capella_fork_epoch != u64::MAX && epoch >= cfg.capella_fork_epoch {
        ForkVariant::Capella
    } else if cfg.bellatrix_fork_epoch != u64::MAX && epoch >= cfg.bellatrix_fork_epoch {
        ForkVariant::Bellatrix
    } else if cfg.altair_fork_epoch != u64::MAX && epoch >= cfg.altair_fork_epoch {
        ForkVariant::Altair
    } else {
        ForkVariant::Phase0
    }
}

/// Render a single `LcEnvelope` as an HTTP response.
///
/// JSON: `{"version": "<fork>", "data": <json>}` — NO `execution_optimistic`
/// or `finalized` fields (per the light-client beacon-APIs spec).
/// SSZ: raw `ssz_bytes` (unframed; the caller does NOT length-prefix single
/// endpoint responses).
/// Both paths set the `Eth-Consensus-Version` response header.
///
/// Per `D-api-lc-bridge`: single LC endpoints use raw (unframed) SSZ bytes.
pub fn render_lc_envelope(env: LcEnvelope, format: AcceptFormat) -> Response {
    let version = fork_variant_str(env.variant);
    let version_hval = match HeaderValue::from_str(version) {
        Ok(v) => v,
        Err(_) => {
            return ApiError::Internal("invalid fork version string".to_string()).into_response();
        }
    };

    match format {
        AcceptFormat::Json => {
            let body_val = serde_json::json!({ "version": version, "data": env.json });
            let body = match serde_json::to_vec(&body_val) {
                Ok(b) => b,
                Err(e) => {
                    return ApiError::Internal(format!("JSON serialization error: {e}"))
                        .into_response();
                }
            };
            let mut resp = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response();
            resp.headers_mut()
                .insert(ETH_CONSENSUS_VERSION.clone(), version_hval);
            resp
        }
        AcceptFormat::Ssz => {
            let mut resp = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                env.ssz_bytes,
            )
                .into_response();
            resp.headers_mut()
                .insert(ETH_CONSENSUS_VERSION.clone(), version_hval);
            resp
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use pharos_types::views::ForkVariant;
    use serde::Serialize;

    use super::*;
    use crate::respond::AcceptFormat;

    #[derive(Serialize)]
    struct MockData {
        value: u32,
    }

    fn make_tagged(variant: ForkVariant) -> ForkTagged<MockData> {
        ForkTagged::new(variant, false, true, MockData { value: 42 })
    }

    #[tokio::test]
    async fn json_sets_version_field_and_header() {
        let tagged = make_tagged(ForkVariant::Bellatrix);
        let resp = tagged.render(AcceptFormat::Json, None);
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let hdr = resp
            .headers()
            .get("eth-consensus-version")
            .expect("Eth-Consensus-Version header missing")
            .to_str()
            .unwrap();
        assert_eq!(hdr, "bellatrix");

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["version"], "bellatrix");
        assert_eq!(v["execution_optimistic"], false);
        assert_eq!(v["finalized"], true);
        assert_eq!(v["data"]["value"], 42);
    }

    #[tokio::test]
    async fn ssz_sets_header_no_body_parsing() {
        let tagged = make_tagged(ForkVariant::Capella);
        let ssz = vec![0xde, 0xad, 0xbe, 0xef];
        let resp = tagged.render(AcceptFormat::Ssz, Some(ssz.clone()));
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let hdr = resp
            .headers()
            .get("eth-consensus-version")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(hdr, "capella");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.to_vec(), ssz);
    }

    #[tokio::test]
    async fn ssz_without_bytes_returns_406() {
        let tagged = make_tagged(ForkVariant::Phase0);
        let resp = tagged.render(AcceptFormat::Ssz, None);
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_ACCEPTABLE);
    }

    #[test]
    fn fork_variant_str_exhaustive() {
        assert_eq!(fork_variant_str(ForkVariant::Phase0), "phase0");
        assert_eq!(fork_variant_str(ForkVariant::Altair), "altair");
        assert_eq!(fork_variant_str(ForkVariant::Bellatrix), "bellatrix");
        assert_eq!(fork_variant_str(ForkVariant::Capella), "capella");
    }
}
