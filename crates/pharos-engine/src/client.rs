//! `EngineClient` — async JSON-RPC client over HTTP, JWT-authenticated.
//!
//! One client per EL endpoint. Each call mints a fresh JWT (`iat = now`)
//! and POSTs a single JSON-RPC envelope. Method version dispatch is via the
//! `*Version` enums so callers can pin a Bellatrix-only V1 today and add
//! V2/V3 variants per fork later (Capella V2 lands in M5).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use reqwest::{Client as Http, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use pharos_utils::metrics::METRIC_ENGINE_CALL_LATENCY_SECONDS;

use crate::error::EngineError;
use crate::jwt::{JwtSecret, sign_token};
use crate::types::{
    BlobAndProofV1, BlobAndProofV2, BlobCellsAndProofs, BlockHeader, ExecutionPayloadBodyV1,
    ExecutionPayloadBodyV2, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3,
    ForkchoiceStateV1, ForkchoiceUpdatedV1Response, GetPayloadV2Response, GetPayloadV3Response,
    GetPayloadV4Response, GetPayloadV5Response, GetPayloadV6Response, PayloadAttributesV1,
    PayloadAttributesV2, PayloadAttributesV3, PayloadIdV1, PayloadStatusV1, SyncingStatus,
    TransitionConfigurationV1,
};

const ENGINE_RPC_TIMEOUT: Duration = Duration::from_secs(8);

/// Engine API methods advertised by pharos in `engine_exchangeCapabilities`.
///
/// Includes V1 (Bellatrix/Paris), V2 (Capella/Shanghai), and V3 (Deneb/Cancun) methods.
pub const DEFAULT_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_newPayloadV1",
    "engine_newPayloadV2",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_forkchoiceUpdatedV1",
    "engine_forkchoiceUpdatedV2",
    "engine_forkchoiceUpdatedV3",
    "engine_getPayloadV1",
    "engine_getPayloadV2",
    "engine_getPayloadV3",
    "engine_getPayloadV4",
    "engine_getPayloadV5",
    "engine_getBlobsV1",
    "engine_exchangeCapabilities",
    "engine_exchangeTransitionConfigurationV1",
];

// ── Version enums ────────────────────────────────────────────────────────────

/// Version selector for `engine_newPayload*`. Bellatrix uses V1; Capella uses V2; Deneb uses V3;
/// Electra / Prague / Fulu uses V4; Amsterdam uses V5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewPayloadVersion {
    V1,
    /// Capella / Shanghai: `engine_newPayloadV2` with `ExecutionPayloadV2` (+ withdrawals).
    V2,
    /// Deneb / Cancun: `engine_newPayloadV3` with `ExecutionPayloadV3` + versioned hashes
    /// + parent beacon block root.
    V3,
    /// Electra / Prague: `engine_newPayloadV4` — same payload type as V3 + `executionRequests`.
    V4,
    /// Amsterdam (post-Fulu): `engine_newPayloadV5` — same params as V4.
    V5,
}

/// Version selector for `engine_forkchoiceUpdated*`. Bellatrix uses V1; Capella uses V2;
/// Deneb / Electra / Fulu uses V3; Amsterdam uses V4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkchoiceUpdatedVersion {
    V1,
    /// Capella / Shanghai: `engine_forkchoiceUpdatedV2` with optional `PayloadAttributesV2`.
    V2,
    /// Deneb / Cancun: `engine_forkchoiceUpdatedV3` with optional `PayloadAttributesV3`.
    V3,
    /// Amsterdam (post-Fulu): `engine_forkchoiceUpdatedV4` with optional `PayloadAttributesV3`
    /// (same attributes type as V3) plus optional custody columns.
    V4,
}

/// Version selector for `engine_getPayload*`. Bellatrix uses V1; Capella uses V2;
/// Deneb uses V3; Electra / Prague uses V4; Fulu / Osaka uses V5;
/// Amsterdam uses V6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetPayloadVersion {
    V1,
    /// Capella / Shanghai: `engine_getPayloadV2` returning `{executionPayload, blockValue}`.
    V2,
    /// Deneb / Cancun: `engine_getPayloadV3` returning `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder}`.
    V3,
    /// Electra / Prague: `engine_getPayloadV4` — V3 + `executionRequests`.
    V4,
    /// Fulu / Osaka: `engine_getPayloadV5` — V4 envelope + `BlobsBundleV2`
    /// (cell proofs) per `execution-apis/src/engine/osaka.md`.
    V5,
    /// Amsterdam: `engine_getPayloadV6` — V5 envelope + `ExecutionPayloadV4`
    /// (includes `blockAccessList`) per `execution-apis/src/engine/amsterdam.md`.
    V6,
}

// ── NewPayloadWire ────────────────────────────────────────────────────────────

/// Fork-discriminated execution payload for `engine_newPayload*` dispatch.
///
/// V1 carries a Bellatrix payload; V2 carries a Capella payload with withdrawals;
/// V3 carries a Deneb payload with blob gas fields, versioned hashes, and parent
/// beacon block root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewPayloadWire {
    V1(ExecutionPayloadV1),
    V2(ExecutionPayloadV2),
    /// Deneb / Cancun: payload + `expectedBlobVersionedHashes` + `parentBeaconBlockRoot`.
    ///
    /// Per `execution-apis/src/engine/cancun.md` newPayloadV3:
    /// params[0] = executionPayload, params[1] = expectedBlobVersionedHashes,
    /// params[2] = parentBeaconBlockRoot.
    V3 {
        payload: ExecutionPayloadV3,
        /// `expectedBlobVersionedHashes`: array of 32-byte hex DATA strings.
        versioned_hashes: Vec<String>,
        /// `parentBeaconBlockRoot`: 32-byte hex DATA string.
        parent_beacon_block_root: String,
    },
    /// Electra / Prague: payload + versioned hashes + parent beacon block root +
    /// `executionRequests`.
    ///
    /// Per `execution-apis/src/engine/prague.md` newPayloadV4:
    /// params[0] = executionPayload (V3 type, byte-identical with Deneb),
    /// params[1] = expectedBlobVersionedHashes,
    /// params[2] = parentBeaconBlockRoot,
    /// params[3] = executionRequests (EIP-7685 hex-encoded request list).
    V4 {
        payload: ExecutionPayloadV3,
        versioned_hashes: Vec<String>,
        parent_beacon_block_root: String,
        /// `executionRequests`: `Array of DATA` — EIP-7685 encoded, one hex string per request
        /// type. Empty lists are omitted. Each entry: `0x || request_type_byte ||
        /// ssz_serialized_requests`.
        execution_requests: Vec<String>,
    },
    /// Amsterdam (post-Fulu): `engine_newPayloadV5` uses `ExecutionPayloadV4` (includes
    /// `blockAccessList`) alongside versioned hashes, parent beacon block root,
    /// and execution requests.
    V5 {
        payload: crate::types::ExecutionPayloadV4,
        versioned_hashes: Vec<String>,
        parent_beacon_block_root: String,
        execution_requests: Vec<String>,
    },
}

// ── EngineClient ─────────────────────────────────────────────────────────────

/// Async JSON-RPC client for an Engine API endpoint.
///
/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based and the JWT
/// secret + capability cache are shared. One instance per EL endpoint.
pub struct EngineClient {
    http: Http,
    endpoint: Url,
    jwt_secret: JwtSecret,
    capabilities: RwLock<Option<HashSet<String>>>,
    next_id: AtomicU64,
}

impl EngineClient {
    /// Build a new client targeting `endpoint`, authenticating with `jwt_secret`.
    pub fn new(endpoint: Url, jwt_secret: JwtSecret) -> Result<Self, EngineError> {
        let http = Http::builder().timeout(ENGINE_RPC_TIMEOUT).build()?;
        Ok(Self {
            http,
            endpoint,
            jwt_secret,
            capabilities: RwLock::new(None),
            next_id: AtomicU64::new(1),
        })
    }

    /// Endpoint URL (for logging/debug).
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    async fn rpc_call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, EngineError> {
        let _rpc_start = std::time::Instant::now();
        let result = self.rpc_call_inner(method, params).await;
        // Record latency regardless of success/error (label by Engine API method).
        // ADR cite: `D-metrics-prometheus-optin` (Phase 5).
        metrics::histogram!(METRIC_ENGINE_CALL_LATENCY_SECONDS, "method" => method.to_owned())
            .record(_rpc_start.elapsed().as_secs_f64());
        result
    }

    async fn rpc_call_inner<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, EngineError> {
        let token = sign_token(&self.jwt_secret)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });

        let resp = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    EngineError::Timeout
                } else {
                    EngineError::Transport(e)
                }
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(EngineError::Unauthenticated);
        }

        let envelope: Value = resp.json().await.map_err(|e| {
            if e.is_timeout() {
                EngineError::Timeout
            } else {
                EngineError::Transport(e)
            }
        })?;

        // NOTE: non-standard ELs might embed payload status (e.g. INVALID)
        // in `error.data` rather than `result`. geth/reth/ethrex put
        // INVALID in `result`, so we do not parse `error.data`. If an
        // EL that embeds status in error.data is encountered, add an
        // EngineError::PayloadStatus variant and inspect error.data here.
        if let Some(err) = envelope.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("<no message>")
                .to_owned();
            return Err(EngineError::JsonRpc { code, message });
        }

        let result = envelope.get("result").ok_or_else(|| {
            EngineError::UnexpectedResponse("envelope missing both `result` and `error`".into())
        })?;
        let parsed: R = serde_json::from_value(result.clone())?;
        Ok(parsed)
    }

    // ── Engine API methods ───────────────────────────────────────────────────

    /// `engine_newPayloadV1` — Bellatrix execution payload.
    pub async fn new_payload_v1(
        &self,
        payload: ExecutionPayloadV1,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.rpc_call("engine_newPayloadV1", [payload]).await
    }

    /// `engine_newPayloadV2` — Capella execution payload (with withdrawals).
    pub async fn new_payload_v2(
        &self,
        payload: ExecutionPayloadV2,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.rpc_call("engine_newPayloadV2", [payload]).await
    }

    /// `engine_newPayloadV3` — Deneb execution payload (with blob gas fields).
    ///
    /// Per `execution-apis/src/engine/cancun.md`:
    /// params: (executionPayload, expectedBlobVersionedHashes, parentBeaconBlockRoot)
    pub async fn new_payload_v3(
        &self,
        payload: ExecutionPayloadV3,
        versioned_hashes: Vec<String>,
        parent_beacon_block_root: String,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.rpc_call(
            "engine_newPayloadV3",
            serde_json::json!([payload, versioned_hashes, parent_beacon_block_root]),
        )
        .await
    }

    /// `engine_newPayloadV4` — Electra / Prague execution payload.
    ///
    /// Per `execution-apis/src/engine/prague.md`:
    /// params: (executionPayload, expectedBlobVersionedHashes, parentBeaconBlockRoot,
    ///          executionRequests)
    ///
    /// The payload type is `ExecutionPayloadV3` (byte-identical with Deneb);
    /// `executionRequests` is the EIP-7685 request list as hex DATA strings.
    pub async fn new_payload_v4(
        &self,
        payload: ExecutionPayloadV3,
        versioned_hashes: Vec<String>,
        parent_beacon_block_root: String,
        execution_requests: Vec<String>,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.rpc_call(
            "engine_newPayloadV4",
            serde_json::json!([
                payload,
                versioned_hashes,
                parent_beacon_block_root,
                execution_requests
            ]),
        )
        .await
    }

    /// `engine_newPayload*` dispatch per version.
    ///
    /// V1: Bellatrix; V2: Capella (withdrawals); V3: Deneb (blob gas + versioned hashes);
    /// V4: Electra / Prague (+ executionRequests).
    /// Returns an error if the version/payload combination is invalid.
    pub async fn new_payload(
        &self,
        v: NewPayloadVersion,
        payload: NewPayloadWire,
    ) -> Result<PayloadStatusV1, EngineError> {
        match (v, payload) {
            (NewPayloadVersion::V1, NewPayloadWire::V1(p)) => self.new_payload_v1(p).await,
            (NewPayloadVersion::V2, NewPayloadWire::V2(p)) => self.new_payload_v2(p).await,
            (
                NewPayloadVersion::V3,
                NewPayloadWire::V3 {
                    payload: p,
                    versioned_hashes,
                    parent_beacon_block_root,
                },
            ) => {
                self.new_payload_v3(p, versioned_hashes, parent_beacon_block_root)
                    .await
            }
            (
                NewPayloadVersion::V4,
                NewPayloadWire::V4 {
                    payload: p,
                    versioned_hashes,
                    parent_beacon_block_root,
                    execution_requests,
                },
            ) => {
                self.new_payload_v4(
                    p,
                    versioned_hashes,
                    parent_beacon_block_root,
                    execution_requests,
                )
                .await
            }
            (
                NewPayloadVersion::V5,
                NewPayloadWire::V5 {
                    payload: p,
                    versioned_hashes,
                    parent_beacon_block_root,
                    execution_requests,
                },
            ) => {
                self.new_payload_v5(
                    p,
                    versioned_hashes,
                    parent_beacon_block_root,
                    execution_requests,
                )
                .await
            }
            _ => Err(EngineError::UnexpectedResponse(
                "new_payload: version/payload mismatch".into(),
            )),
        }
    }

    /// `engine_forkchoiceUpdatedV1` — Bellatrix forkchoice update.
    pub async fn forkchoice_updated_v1(
        &self,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV1>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.rpc_call("engine_forkchoiceUpdatedV1", (state, attrs))
            .await
    }

    /// `engine_forkchoiceUpdatedV2` — Capella forkchoice update (withdrawals attributes).
    pub async fn forkchoice_updated_v2(
        &self,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV2>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.rpc_call("engine_forkchoiceUpdatedV2", (state, attrs))
            .await
    }

    /// `engine_forkchoiceUpdatedV3` — Deneb forkchoice update (optional V3 payload attributes).
    pub async fn forkchoice_updated_v3(
        &self,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV3>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.rpc_call("engine_forkchoiceUpdatedV3", (state, attrs))
            .await
    }

    /// `engine_forkchoiceUpdated*` dispatch per version.
    ///
    /// For the follow-only path (no payload attributes), all versions behave
    /// identically when attrs = null. Callers wanting attributes MUST use the
    /// version-specific method (`forkchoice_updated_v2`, `forkchoice_updated_v3`)
    /// because each version has a different `PayloadAttributes` type.
    pub async fn forkchoice_updated(
        &self,
        v: ForkchoiceUpdatedVersion,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV1>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        match v {
            ForkchoiceUpdatedVersion::V1 => self.forkchoice_updated_v1(state, attrs).await,
            ForkchoiceUpdatedVersion::V2 => {
                // The generic dispatch path drops V1 attrs for V2: V2 requires
                // `PayloadAttributesV2`, so a caller wanting attributes MUST use
                // `forkchoice_updated_v2` directly. The follow-only path always
                // passes `None` here. Guard against a future caller silently
                // losing attributes.
                debug_assert!(
                    attrs.is_none(),
                    "forkchoice_updated(V2, .., Some(attrs)) drops V1 attrs; \
                     call forkchoice_updated_v2 with PayloadAttributesV2 instead"
                );
                self.forkchoice_updated_v2(state, None).await
            }
            ForkchoiceUpdatedVersion::V3 => {
                // V3 requires `PayloadAttributesV3`; a caller wanting attributes MUST
                // use `forkchoice_updated_v3` directly. The follow-only path passes
                // `None` here.
                debug_assert!(
                    attrs.is_none(),
                    "forkchoice_updated(V3, .., Some(attrs)) drops V1 attrs; \
                     call forkchoice_updated_v3 with PayloadAttributesV3 instead"
                );
                self.forkchoice_updated_v3(state, None).await
            }
            ForkchoiceUpdatedVersion::V4 => {
                // V4 requires `PayloadAttributesV3` (same as V3) plus optional custody
                // columns. The follow-only path passes `None` for both here.
                debug_assert!(
                    attrs.is_none(),
                    "forkchoice_updated(V4, .., Some(attrs)) drops V1 attrs; \
                     call forkchoice_updated_v4 with PayloadAttributesV3 instead"
                );
                self.forkchoice_updated_v4(state, None, None).await
            }
        }
    }

    /// `engine_getPayloadV1` — Bellatrix (block production).
    pub async fn get_payload_v1(&self, id: PayloadIdV1) -> Result<ExecutionPayloadV1, EngineError> {
        self.rpc_call("engine_getPayloadV1", [id]).await
    }

    /// `engine_getPayloadV2` — Capella (block production).
    ///
    /// Returns `{executionPayload, blockValue}` per `execution-apis/src/engine/shanghai.md`.
    /// `blockValue` is the expected value (in wei) to be received by the fee recipient.
    pub async fn get_payload_v2(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV2Response, EngineError> {
        self.rpc_call("engine_getPayloadV2", [id]).await
    }

    /// `engine_getPayloadV3` — Deneb block production.
    ///
    /// Returns `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder}`
    /// per `execution-apis/src/engine/cancun.md`.
    pub async fn get_payload_v3(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV3Response, EngineError> {
        self.rpc_call("engine_getPayloadV3", [id]).await
    }

    /// `engine_getPayloadV4` — Electra / Prague block production.
    ///
    /// Returns `{executionPayload, blockValue, blobsBundle, shouldOverrideBuilder, executionRequests}`
    /// per `execution-apis/src/engine/prague.md`.
    pub async fn get_payload_v4(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV4Response, EngineError> {
        self.rpc_call("engine_getPayloadV4", [id]).await
    }

    /// `engine_getPayloadV5` — Fulu / Osaka block production.
    ///
    /// Returns `{executionPayload, blockValue, blobsBundle (V2), shouldOverrideBuilder,
    /// executionRequests}` per `execution-apis/src/engine/osaka.md`. The only
    /// envelope difference from V4 is the `blobsBundle` type (`BlobsBundleV2`,
    /// carrying `CELLS_PER_EXT_BLOB` cell proofs per blob).
    pub async fn get_payload_v5(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV5Response, EngineError> {
        self.rpc_call("engine_getPayloadV5", [id]).await
    }

    /// `engine_getBlobsV1` — retrieve blobs from the local EL blob pool.
    ///
    /// Per `execution-apis/src/engine/cancun.md`:
    /// - Responses are in the same order as the input versioned hashes.
    /// - Missing blobs are represented as `null` (→ `None` in the result).
    /// - The EL MUST support at least 128 versioned hashes; it returns
    ///   `-38004: Too large request` for larger inputs.
    ///
    /// Returns a `Vec<Option<BlobAndProofV1>>` preserving the request order.
    pub async fn get_blobs_v1(
        &self,
        versioned_hashes: Vec<String>,
    ) -> Result<Vec<Option<BlobAndProofV1>>, EngineError> {
        if versioned_hashes.len() > 128 {
            return Err(EngineError::JsonRpc {
                code: -38004,
                message: "too large request: more than 128 versioned hashes".into(),
            });
        }
        self.rpc_call("engine_getBlobsV1", [versioned_hashes]).await
    }

    /// `engine_getBlobsV2` — retrieve blobs with cell proofs from the local EL blob pool.
    ///
    /// Returns a `Vec<Option<BlobAndProofV2>>` where each element has `blob` and
    /// `proofs` (array of cell proofs). Missing blobs are `null` (→ `None`).
    pub async fn get_blobs_v2(
        &self,
        versioned_hashes: Vec<String>,
    ) -> Result<Vec<Option<BlobAndProofV2>>, EngineError> {
        self.rpc_call("engine_getBlobsV2", [versioned_hashes]).await
    }

    /// `engine_getBlobsV3` — retrieve blobs with cell proofs from the local EL blob pool.
    ///
    /// Same response shape as V2 (`BlobAndProofV2`). Returns a `Vec<Option<BlobAndProofV2>>`
    /// where missing blobs are `null` (→ `None`).
    pub async fn get_blobs_v3(
        &self,
        versioned_hashes: Vec<String>,
    ) -> Result<Vec<Option<BlobAndProofV2>>, EngineError> {
        self.rpc_call("engine_getBlobsV3", [versioned_hashes]).await
    }

    /// `engine_getBlobsV4` — retrieve blob cells and proofs from the local EL blob pool.
    ///
    /// Per `execution-apis/src/engine/amsterdam.md`: params are versioned hashes plus
    /// a `cellIndicesBitarray` (hex-encoded bitarray selecting which cells to return).
    /// Returns a `Vec<Option<BlobCellsAndProofs>>` where missing blobs are `null` (→ `None`).
    pub async fn get_blobs_v4(
        &self,
        versioned_hashes: Vec<String>,
        cell_indices_bitarray: String,
    ) -> Result<Vec<Option<BlobCellsAndProofs>>, EngineError> {
        self.rpc_call(
            "engine_getBlobsV4",
            serde_json::json!([versioned_hashes, cell_indices_bitarray]),
        )
        .await
    }

    /// `engine_getPayloadBodiesByHashV1` — retrieve execution payload bodies by block hash.
    ///
    /// Per `execution-apis/src/engine/shanghai.md`.
    /// Returns `Vec<Option<ExecutionPayloadBodyV1>>` — absent blocks are `null` (→ `None`).
    pub async fn get_payload_bodies_by_hash_v1(
        &self,
        block_hashes: Vec<String>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1>>, EngineError> {
        self.rpc_call("engine_getPayloadBodiesByHashV1", [block_hashes])
            .await
    }

    /// `engine_getPayloadBodiesByHashV2` — retrieve execution payload bodies by block hash.
    ///
    /// Per `execution-apis/src/engine/amsterdam.md`. Extends V1 with `blockAccessList`.
    /// Returns `Vec<Option<ExecutionPayloadBodyV2>>` — absent blocks are `null` (→ `None`).
    pub async fn get_payload_bodies_by_hash_v2(
        &self,
        block_hashes: Vec<String>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV2>>, EngineError> {
        self.rpc_call("engine_getPayloadBodiesByHashV2", [block_hashes])
            .await
    }

    /// `engine_getPayloadBodiesByRangeV1` — retrieve execution payload bodies by block range.
    ///
    /// Per `execution-apis/src/engine/shanghai.md`.
    /// `start` is the starting block number (hex QUANTITY), `count` is the number of blocks.
    /// Returns `Vec<Option<ExecutionPayloadBodyV1>>` — absent blocks are `null` (→ `None`).
    pub async fn get_payload_bodies_by_range_v1(
        &self,
        start: String,
        count: String,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1>>, EngineError> {
        self.rpc_call("engine_getPayloadBodiesByRangeV1", (start, count))
            .await
    }

    /// `engine_getPayloadBodiesByRangeV2` — retrieve execution payload bodies by block range.
    ///
    /// Per `execution-apis/src/engine/amsterdam.md`. Extends V1 with `blockAccessList`.
    /// `start` is the starting block number (hex QUANTITY), `count` is the number of blocks.
    /// Returns `Vec<Option<ExecutionPayloadBodyV2>>` — absent blocks are `null` (→ `None`).
    pub async fn get_payload_bodies_by_range_v2(
        &self,
        start: String,
        count: String,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV2>>, EngineError> {
        self.rpc_call("engine_getPayloadBodiesByRangeV2", (start, count))
            .await
    }

    /// `engine_forkchoiceUpdatedV4` — Amsterdam (post-Fulu) forkchoice update.
    ///
    /// Per `execution-apis/src/engine/amsterdam.md`: same payload attributes as V3
    /// (`PayloadAttributesV3`) plus an optional `custodyColumns` bitarray parameter.
    /// For the follow-only path (no payload attributes), `custodyColumns` may also be `None`.
    pub async fn forkchoice_updated_v4(
        &self,
        state: ForkchoiceStateV1,
        attrs: Option<PayloadAttributesV3>,
        custody_columns: Option<String>,
    ) -> Result<ForkchoiceUpdatedV1Response, EngineError> {
        self.rpc_call(
            "engine_forkchoiceUpdatedV4",
            serde_json::json!([state, attrs, custody_columns]),
        )
        .await
    }

    /// `engine_newPayloadV5` — Amsterdam (post-Fulu) execution payload.
    ///
    /// Per `execution-apis/src/engine/amsterdam.md`: uses `ExecutionPayloadV4`
    /// (includes `blockAccessList`) alongside versioned hashes, parent beacon
    /// block root, and execution requests.
    pub async fn new_payload_v5(
        &self,
        payload: crate::types::ExecutionPayloadV4,
        versioned_hashes: Vec<String>,
        parent_beacon_block_root: String,
        execution_requests: Vec<String>,
    ) -> Result<PayloadStatusV1, EngineError> {
        self.rpc_call(
            "engine_newPayloadV5",
            serde_json::json!([
                payload,
                versioned_hashes,
                parent_beacon_block_root,
                execution_requests
            ]),
        )
        .await
    }

    /// `engine_getPayloadV6` — Amsterdam block production.
    ///
    /// Returns `{executionPayload (V4), blockValue, blobsBundle (V2), shouldOverrideBuilder,
    /// executionRequests}` per `execution-apis/src/engine/amsterdam.md`.
    pub async fn get_payload_v6(
        &self,
        id: PayloadIdV1,
    ) -> Result<GetPayloadV6Response, EngineError> {
        self.rpc_call("engine_getPayloadV6", [id]).await
    }

    /// `engine_getPayload*` dispatch per version (V1 single-payload interface).
    pub async fn get_payload(
        &self,
        v: GetPayloadVersion,
        id: PayloadIdV1,
    ) -> Result<ExecutionPayloadV1, EngineError> {
        match v {
            GetPayloadVersion::V1 => self.get_payload_v1(id).await,
            GetPayloadVersion::V2 => {
                // V2 returns a {executionPayload, blockValue} envelope; callers
                // wanting the V2 path must use `get_payload_v2` directly.
                Err(EngineError::UnexpectedResponse(
                    "get_payload(V2): use get_payload_v2 directly for the V2 envelope".into(),
                ))
            }
            GetPayloadVersion::V3 => {
                // V3 returns a {executionPayload, blockValue, blobsBundle, ...} envelope;
                // callers wanting the V3 path must use `get_payload_v3` directly.
                Err(EngineError::UnexpectedResponse(
                    "get_payload(V3): use get_payload_v3 directly for the V3 envelope".into(),
                ))
            }
            GetPayloadVersion::V4 => {
                // V4 returns a V3-envelope + executionRequests; callers must use
                // `get_payload_v4` directly.
                Err(EngineError::UnexpectedResponse(
                    "get_payload(V4): use get_payload_v4 directly for the V4 envelope".into(),
                ))
            }
            GetPayloadVersion::V5 => {
                // V5 returns a V4-envelope with BlobsBundleV2; callers must use
                // `get_payload_v5` directly.
                Err(EngineError::UnexpectedResponse(
                    "get_payload(V5): use get_payload_v5 directly for the V5 envelope".into(),
                ))
            }
            GetPayloadVersion::V6 => {
                // V6 returns a V5-envelope with ExecutionPayloadV4; callers must use
                // `get_payload_v6` directly.
                Err(EngineError::UnexpectedResponse(
                    "get_payload(V6): use get_payload_v6 directly for the V6 envelope".into(),
                ))
            }
        }
    }

    /// `engine_exchangeTransitionConfigurationV1` — compares the CL's terminal
    /// configuration with the EL's and returns the EL's configuration.
    ///
    /// Both sides should agree on `terminalTotalDifficulty`, `terminalBlockHash`,
    /// and `terminalBlockNumber`.  A mismatch signals misconfiguration.
    pub async fn exchange_transition_configuration(
        &self,
        config: TransitionConfigurationV1,
    ) -> Result<TransitionConfigurationV1, EngineError> {
        self.rpc_call("engine_exchangeTransitionConfigurationV1", [config])
            .await
    }

    /// `engine_exchangeCapabilities` — caches the EL-advertised method set
    /// on first call. Subsequent calls return the cached value without an RPC.
    ///
    /// When `our_methods` is empty the client advertises the full default set
    /// (all V1 + V2 methods).
    pub async fn exchange_capabilities(
        &self,
        our_methods: &[&str],
    ) -> Result<HashSet<String>, EngineError> {
        if let Some(cached) = self.capabilities.read().as_ref() {
            return Ok(cached.clone());
        }
        let methods: Vec<String> = if our_methods.is_empty() {
            DEFAULT_ENGINE_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            our_methods.iter().map(|s| s.to_string()).collect()
        };
        let theirs: Vec<String> = self
            .rpc_call("engine_exchangeCapabilities", [methods])
            .await?;
        let set: HashSet<String> = theirs.into_iter().collect();
        *self.capabilities.write() = Some(set.clone());
        Ok(set)
    }

    // ── eth_* methods ────────────────────────────────────────────────────────

    /// `eth_chainId` — returns the EL chain ID as a `u64`.
    pub async fn chain_id(&self) -> Result<u64, EngineError> {
        let hex: String = self.rpc_call("eth_chainId", Vec::<Value>::new()).await?;
        crate::types::parse_hex_u64(&hex)
    }

    /// `eth_getBlockByHash` — returns `None` if the EL does not know the hash.
    pub async fn get_block_by_hash(
        &self,
        hash_hex: &str,
    ) -> Result<Option<BlockHeader>, EngineError> {
        self.rpc_call("eth_getBlockByHash", (hash_hex, false)).await
    }

    /// `eth_getBlockByNumber` — `number` is encoded as a hex quantity.
    pub async fn get_block_by_number(
        &self,
        number: u64,
    ) -> Result<Option<BlockHeader>, EngineError> {
        let hex = format!("0x{number:x}");
        self.rpc_call("eth_getBlockByNumber", (hex, false)).await
    }

    /// `eth_syncing` — returns `false` if up-to-date, else progress fields.
    pub async fn syncing(&self) -> Result<SyncingStatus, EngineError> {
        self.rpc_call("eth_syncing", Vec::<Value>::new()).await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{PayloadStatusStatus, PayloadStatusV1};

    /// Verify that `PayloadStatusStatus::Invalid` round-trips through JSON as
    /// the SCREAMING_SNAKE_CASE string `"INVALID"` (per Engine API spec).
    #[test]
    fn payload_status_invalid_round_trip() {
        let status = PayloadStatusV1 {
            status: PayloadStatusStatus::Invalid,
            latest_valid_hash: Some(
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ),
            validation_error: Some("New payload is invalid".to_string()),
        };

        let json = serde_json::to_string(&status).expect("serialize");
        assert!(
            json.contains("\"INVALID\""),
            "status must serialize as INVALID, got: {json}"
        );

        let decoded: PayloadStatusV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.status, PayloadStatusStatus::Invalid);
        assert_eq!(
            decoded.latest_valid_hash.as_deref(),
            Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        );
        assert_eq!(
            decoded.validation_error.as_deref(),
            Some("New payload is invalid")
        );
    }

    /// Verify all status variants serialize as SCREAMING_SNAKE_CASE.
    #[test]
    fn payload_status_all_variants_screaming_snake_case() {
        use PayloadStatusStatus::*;
        let cases = [
            (Valid, "VALID"),
            (Invalid, "INVALID"),
            (Syncing, "SYNCING"),
            (Accepted, "ACCEPTED"),
            (InvalidBlockHash, "INVALID_BLOCK_HASH"),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(
                json,
                format!("\"{expected}\""),
                "variant {expected} must serialize as SCREAMING_SNAKE_CASE"
            );
            let decoded: PayloadStatusStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, variant);
        }
    }
}
