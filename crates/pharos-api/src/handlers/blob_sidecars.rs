//! Blob sidecar retrieval handler (M15 Phase 4).
//!
//! - `GET /eth/v1/beacon/blobs/{block_id}` — retrieve blobs for a given block.
//!
//! Spec: `~/dev/beacon-APIs/apis/beacon/blobs/blobs.yaml` (`getBlobs`).
//!
//! Response shape (JSON):
//! ```json
//! {
//!   "execution_optimistic": bool,
//!   "finalized": bool,
//!   "data": ["0x<131072-byte blob hex>", ...]
//! }
//! ```
//!
//! Query param `versioned_hashes`: optional array of `0x`-prefixed 32-byte hex
//! strings. When present, only blobs whose KZG commitment hashes to one of the
//! supplied versioned hashes are returned, preserving block order.
//!
//! Pre-Deneb blocks (or blocks with no blobs) return 200 with `data: []`.
//! Unknown block_id returns 404.
//!
//! SSZ path (`Accept: application/octet-stream`):
//! `List[Blob, MAX_BLOB_COMMITMENTS_PER_BLOCK]` encoded bytes.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use pharos_kzg::kzg_commitment_to_versioned_hash;
use pharos_ssz::Encode as _;
use pharos_types::BeaconSpec;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::error::ApiError;
use crate::resolve::resolve_block_id;
use crate::respond::{AcceptFormat, ApiResponse, parse_accept};
use crate::state::ApiState;

// ── Query params ─────────────────────────────────────────────────────────────

/// Query parameters for `GET /eth/v1/beacon/blobs/{block_id}`.
///
/// `versioned_hashes` is serialized as a CSV string
/// (`?versioned_hashes=0xabc,0xdef`) because `serde_urlencoded` (axum's
/// default query extractor) does not support `Vec<T>` from repeated keys.
/// Callers may also pass a single hash without a comma.
#[derive(Debug, Deserialize, Default)]
pub struct BlobsQuery {
    /// Optional filter: comma-separated versioned hashes.
    ///
    /// Each comma-separated token is a `0x`-prefixed 32-byte hex string
    /// representing a versioned hash (spec type `VersionedHash` = `Bytes32`).
    /// When absent, all blobs in the block are returned.
    #[serde(default)]
    pub versioned_hashes: Option<String>,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// `GET /eth/v1/beacon/blobs/{block_id}`
///
/// Per `~/dev/beacon-APIs/apis/beacon/blobs/blobs.yaml`.
///
/// Responses:
/// - 200: `{execution_optimistic, finalized, data: [blob_hex, ...]}` (JSON)
///   or raw SSZ `List[Blob, MAX_BLOB_COMMITMENTS_PER_BLOCK]` (octet-stream).
/// - 400: unparseable block_id.
/// - 404: block not found.
/// - 406: unsupported Accept.
pub async fn get_blobs<E: BeaconSpec>(
    State(state): State<Arc<ApiState<E>>>,
    Path(block_id): Path<String>,
    Query(query): Query<BlobsQuery>,
    headers: HeaderMap,
) -> Response {
    let format = match parse_accept(&headers) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    // Parse the versioned_hashes CSV filter into `[u8; 32]` values.
    // A parse error means the caller provided a malformed hash → 400.
    let vh_filter: Option<Vec<[u8; 32]>> = match &query.versioned_hashes {
        None => None,
        Some(csv) => {
            let tokens: Vec<String> = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if tokens.is_empty() {
                None
            } else {
                match parse_versioned_hashes(&tokens) {
                    Ok(hashes) => Some(hashes),
                    Err(e) => return e.into_response(),
                }
            }
        }
    };

    let chain = Arc::clone(&state.chain);

    let result = tokio::task::spawn_blocking(move || {
        // 1. Resolve block_id → block_root (404 if unknown, 400 if malformed).
        let resolved = resolve_block_id(chain.as_ref(), &block_id)?;

        // 2. Fetch all stored blob sidecars for this block root.
        //    Pre-Deneb blocks or blocks with no blobs return an empty vec.
        let sidecars = chain.blob_sidecars_by_root(resolved.block_root);

        // 3. Extract blobs from sidecars, optionally filtering by versioned hash.
        //    Sidecars are ordered ascending by blob index (storage guarantee).
        //    `kzg_commitment_to_versioned_hash` computes the hash from the
        //    commitment in the sidecar and tests membership in the filter set.
        let blobs: Vec<pharos_types::deneb::blob::Blob> = if let Some(ref filter) = vh_filter {
            sidecars
                .into_iter()
                .filter(|s| {
                    // `KZGCommitment` is `FixedBytes<48>`; into_inner() yields [u8; 48].
                    let commitment_bytes: [u8; 48] = s.kzg_commitment.into_inner();
                    let vh = kzg_commitment_to_versioned_hash(&commitment_bytes);
                    filter.contains(&vh)
                })
                .map(|s| s.blob)
                .collect()
        } else {
            sidecars.into_iter().map(|s| s.blob).collect()
        };

        Ok::<_, ApiError>((resolved.execution_optimistic, resolved.finalized, blobs))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")));

    match result {
        Ok(Ok((execution_optimistic, finalized, blobs))) => {
            match format {
                AcceptFormat::Json => {
                    // Serialize each blob as `0x<262144 hex chars>`.
                    // `SszVector<u8, N>` encodes as raw bytes (no offset prefix
                    // since u8 is fixed-size). `ssz_bytes_len()` = N bytes.
                    let data: Vec<JsonValue> = blobs
                        .iter()
                        .map(|blob| {
                            let raw = blob.as_ssz_bytes();
                            format!("0x{}", hex::encode(&raw)).into()
                        })
                        .collect();
                    let dto = serde_json::json!({
                        "execution_optimistic": execution_optimistic,
                        "finalized": finalized,
                        "data": data,
                    });
                    ApiResponse::json(dto).render(AcceptFormat::Json)
                }
                AcceptFormat::Ssz => {
                    // SSZ: concatenated raw blob bytes (each blob is 131072 bytes).
                    // The wire format is `List[Blob, MAX_BLOB_COMMITMENTS_PER_BLOCK]`
                    // which for fixed-size elements is just concatenated items.
                    let mut ssz_buf: Vec<u8> = Vec::with_capacity(
                        blobs.len() * pharos_types::deneb::blob::BYTES_PER_BLOB as usize,
                    );
                    for blob in &blobs {
                        blob.ssz_append(&mut ssz_buf);
                    }
                    ApiResponse::both(
                        serde_json::json!(null), // not used on SSZ path
                        ssz_buf,
                    )
                    .render(AcceptFormat::Ssz)
                }
            }
        }
        Ok(Err(e)) => e.into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse an array of `0x`-prefixed 32-byte hex strings into `[u8; 32]` arrays.
///
/// Returns `Err(ApiError::BadRequest)` on the first malformed entry.
fn parse_versioned_hashes(raw: &[String]) -> Result<Vec<[u8; 32]>, ApiError> {
    raw.iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s.as_str());
            if s.len() != 64 {
                return Err(ApiError::BadRequest(format!(
                    "versioned_hash must be a 0x-prefixed 32-byte hex string, got length {}",
                    s.len() + 2
                )));
            }
            let bytes = hex::decode(s).map_err(|e| {
                ApiError::BadRequest(format!("versioned_hash hex decode failed: {e}"))
            })?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ApiError::BadRequest("versioned_hash is not 32 bytes".into()))?;
            Ok(arr)
        })
        .collect()
}
