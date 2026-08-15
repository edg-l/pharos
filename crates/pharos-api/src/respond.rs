//! `ApiResponse<T>` — dual JSON / SSZ content-negotiation wrapper.
//!
//! Per `D-api-content-negotiation`:
//! - `Accept: application/octet-stream` → SSZ bytes via `pharos_ssz::Encode`,
//!   `Content-Type: application/octet-stream`.
//! - No `Accept` header / `Accept: */*` / `Accept: application/json` → JSON.
//! - Any other explicit `Accept` that is neither of the above → 406.
//!
//! `ApiResponse<T>` carries the DTO (for JSON) and, optionally, a separate
//! SSZ-encodable value.  In practice, callers use two type parameters:
//! the DTO type `D` (serde-serialisable) and a separate SSZ canonical type
//! when the SSZ encoding must come from the canonical type (not the DTO).
//! For simple endpoints where the SSZ object is tiny (e.g. a 32-byte root),
//! we embed the raw bytes directly.

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::error::ApiError;

// ── Content-type constants ────────────────────────────────────────────────────

const CT_JSON: &str = "application/json";
const CT_SSZ: &str = "application/octet-stream";

// ── Accept-header inspection ──────────────────────────────────────────────────

/// Parsed outcome of inspecting the `Accept` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptFormat {
    /// Respond with JSON (the default).
    Json,
    /// Respond with raw SSZ bytes.
    Ssz,
}

/// Parse the `Accept` header from a request header map.
///
/// The header is split on `,` into media ranges; each range's type is taken
/// up to the first `;` (parameters such as `q=` are ignored — we do not do
/// full quality-value weighting, just first-match). The first range that names
/// a supported type wins:
/// - `application/json`, `*/*`, `application/*`, or an empty/absent header → JSON.
/// - `application/octet-stream` → SSZ.
///
/// Returns `Err(ApiError::NotAcceptable(...))` when an explicit `Accept` names
/// no supported type (e.g. `text/csv`).
pub fn parse_accept(headers: &HeaderMap) -> Result<AcceptFormat, ApiError> {
    let Some(raw) = headers.get(header::ACCEPT) else {
        return Ok(AcceptFormat::Json);
    };
    let s = raw
        .to_str()
        .map_err(|_| ApiError::NotAcceptable("Accept header is not valid UTF-8".to_string()))?
        .trim();

    if s.is_empty() {
        return Ok(AcceptFormat::Json);
    }

    for range in s.split(',') {
        // Strip parameters (`;q=0.9`, `;charset=...`) and surrounding space.
        let media = range.split(';').next().unwrap_or("").trim();
        match media {
            "*/*" | "application/*" | CT_JSON => return Ok(AcceptFormat::Json),
            CT_SSZ => return Ok(AcceptFormat::Ssz),
            _ => {}
        }
    }

    Err(ApiError::NotAcceptable(format!(
        "unsupported Accept: {s}; supported: {CT_JSON}, {CT_SSZ}"
    )))
}

// ── ApiResponse ───────────────────────────────────────────────────────────────

/// A response that carries a pre-serialised JSON body and, optionally, raw SSZ
/// bytes for the `application/octet-stream` path.
///
/// Construct via [`ApiResponse::json`] for JSON-only responses or
/// [`ApiResponse::both`] when SSZ is also available.
pub struct ApiResponse<D: Serialize> {
    dto: D,
    ssz_bytes: Option<Vec<u8>>,
}

impl<D: Serialize> ApiResponse<D> {
    /// Build a response that can only be served as JSON.
    pub fn json(dto: D) -> Self {
        Self {
            dto,
            ssz_bytes: None,
        }
    }

    /// Build a response that can be served as JSON or SSZ.
    pub fn both(dto: D, ssz_bytes: Vec<u8>) -> Self {
        Self {
            dto,
            ssz_bytes: Some(ssz_bytes),
        }
    }

    /// Render based on the parsed `AcceptFormat`.
    pub fn render(self, format: AcceptFormat) -> Response {
        match format {
            AcceptFormat::Json => {
                let body = match serde_json::to_vec(&self.dto) {
                    Ok(b) => b,
                    Err(e) => {
                        return ApiError::Internal(format!("JSON serialization error: {e}"))
                            .into_response();
                    }
                };
                (StatusCode::OK, [(header::CONTENT_TYPE, CT_JSON)], body).into_response()
            }
            AcceptFormat::Ssz => match self.ssz_bytes {
                Some(bytes) => {
                    (StatusCode::OK, [(header::CONTENT_TYPE, CT_SSZ)], bytes).into_response()
                }
                None => ApiError::NotAcceptable("SSZ not available for this endpoint".to_string())
                    .into_response(),
            },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::response::IntoResponse;
    use serde::Serialize;
    use tower::ServiceExt as _;

    use super::*;

    // ── parse_accept ─────────────────────────────────────────────────────────

    fn headers_with_accept(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(header::ACCEPT, value.parse().unwrap());
        map
    }

    #[test]
    fn no_accept_defaults_to_json() {
        let map = HeaderMap::new();
        assert_eq!(parse_accept(&map).unwrap(), AcceptFormat::Json);
    }

    #[test]
    fn accept_star_star_is_json() {
        let map = headers_with_accept("*/*");
        assert_eq!(parse_accept(&map).unwrap(), AcceptFormat::Json);
    }

    #[test]
    fn accept_json_explicit() {
        let map = headers_with_accept("application/json");
        assert_eq!(parse_accept(&map).unwrap(), AcceptFormat::Json);
    }

    #[test]
    fn accept_ssz_returns_ssz() {
        let map = headers_with_accept("application/octet-stream");
        assert_eq!(parse_accept(&map).unwrap(), AcceptFormat::Ssz);
    }

    #[test]
    fn accept_unsupported_returns_406() {
        let map = headers_with_accept("text/html");
        let err = parse_accept(&map).unwrap_err();
        assert!(matches!(err, ApiError::NotAcceptable(_)));
    }

    #[test]
    fn accept_with_params_and_multiple_ranges() {
        // First supported range wins; parameters are ignored.
        let map = headers_with_accept("text/html, application/octet-stream;q=0.9");
        assert_eq!(parse_accept(&map).unwrap(), AcceptFormat::Ssz);
        let map = headers_with_accept("application/json; charset=utf-8");
        assert_eq!(parse_accept(&map).unwrap(), AcceptFormat::Json);
    }

    #[test]
    fn accept_json_lookalike_is_not_json() {
        // Substring matching used to mis-classify this as JSON.
        let map = headers_with_accept("application/json-patch+json");
        let err = parse_accept(&map).unwrap_err();
        assert!(matches!(err, ApiError::NotAcceptable(_)));
    }

    // ── ApiResponse rendering ─────────────────────────────────────────────────

    #[derive(Serialize)]
    struct Dto {
        value: u32,
    }

    #[tokio::test]
    async fn json_branch_produces_json_content_type() {
        let resp = ApiResponse::json(Dto { value: 42 }).render(AcceptFormat::Json);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json");
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["value"], 42);
    }

    #[tokio::test]
    async fn ssz_branch_produces_octet_stream() {
        let ssz_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let resp = ApiResponse::both(Dto { value: 0 }, ssz_bytes.clone()).render(AcceptFormat::Ssz);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/octet-stream");
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body.to_vec(), ssz_bytes);
    }

    #[tokio::test]
    async fn ssz_not_available_returns_406() {
        let resp = ApiResponse::json(Dto { value: 0 }).render(AcceptFormat::Ssz);
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn json_only_route_with_ssz_accept_returns_406() {
        use axum::{Router, routing::get};

        async fn handler(headers: axum::http::HeaderMap) -> Response {
            match parse_accept(&headers) {
                Ok(fmt) => ApiResponse::json(Dto { value: 1 }).render(fmt),
                Err(e) => e.into_response(),
            }
        }

        let router = Router::new().route("/test", get(handler));
        let req = Request::builder()
            .uri("/test")
            .header(header::ACCEPT, "text/html")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }
}
