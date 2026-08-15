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

use crate::error::EngineError;
use crate::jwt::{JwtSecret, sign_token};
use crate::types::{
    BlockHeader, ExecutionPayloadV1, ExecutionPayloadV2, ForkchoiceStateV1,
    ForkchoiceUpdatedV1Response, PayloadAttributesV1, PayloadAttributesV2, PayloadIdV1,
    PayloadStatusV1, SyncingStatus, TransitionConfigurationV1,
};

const ENGINE_RPC_TIMEOUT: Duration = Duration::from_secs(8);

/// Engine API methods advertised by pharos in `engine_exchangeCapabilities`.
///
/// Includes all V1 (Bellatrix/Paris) and V2 (Capella/Shanghai) methods.
/// V3+ (Deneb) will be added in M7.
pub const DEFAULT_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_newPayloadV1",
    "engine_newPayloadV2",
    "engine_forkchoiceUpdatedV1",
    "engine_forkchoiceUpdatedV2",
    "engine_getPayloadV1",
    "engine_getPayloadV2",
    "engine_exchangeCapabilities",
    "engine_exchangeTransitionConfigurationV1",
];

// ── Version enums ────────────────────────────────────────────────────────────

/// Version selector for `engine_newPayload*`. Bellatrix uses V1; Capella uses V2.
/// Deneb adds V3 (M7), Electra adds V4 (M8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewPayloadVersion {
    V1,
    /// Capella / Shanghai: `engine_newPayloadV2` with `ExecutionPayloadV2` (+ withdrawals).
    V2,
}

/// Version selector for `engine_forkchoiceUpdated*`. Bellatrix uses V1; Capella uses V2.
/// Deneb adds V3 (M7), Electra adds V4 (M8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkchoiceUpdatedVersion {
    V1,
    /// Capella / Shanghai: `engine_forkchoiceUpdatedV2` with optional `PayloadAttributesV2`.
    V2,
}

/// Version selector for `engine_getPayload*`. Bellatrix uses V1; Capella uses V2.
/// Deneb adds V3 (M7), Electra adds V4 (M8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetPayloadVersion {
    V1,
    /// Capella / Shanghai: `engine_getPayloadV2`. Wire type only; live driver
    /// wiring is block-production-only (deferred to M8 — follow-only node).
    V2,
}

// ── NewPayloadWire ────────────────────────────────────────────────────────────

/// Fork-discriminated execution payload for `engine_newPayload*` dispatch.
///
/// V1 carries a Bellatrix payload; V2 carries a Capella payload with withdrawals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewPayloadWire {
    V1(ExecutionPayloadV1),
    V2(ExecutionPayloadV2),
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

    /// `engine_newPayload*` dispatch per version.
    ///
    /// V1: Bellatrix; V2: Capella (withdrawals). Panics if the version/payload
    /// combination is invalid (caller is responsible for picking the right variant).
    pub async fn new_payload(
        &self,
        v: NewPayloadVersion,
        payload: NewPayloadWire,
    ) -> Result<PayloadStatusV1, EngineError> {
        match (v, payload) {
            (NewPayloadVersion::V1, NewPayloadWire::V1(p)) => self.new_payload_v1(p).await,
            (NewPayloadVersion::V2, NewPayloadWire::V2(p)) => self.new_payload_v2(p).await,
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

    /// `engine_forkchoiceUpdated*` dispatch per version.
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
        }
    }

    /// `engine_getPayloadV1` — Bellatrix (block production).
    pub async fn get_payload_v1(&self, id: PayloadIdV1) -> Result<ExecutionPayloadV1, EngineError> {
        self.rpc_call("engine_getPayloadV1", [id]).await
    }

    /// `engine_getPayloadV2` — Capella (block production).
    ///
    /// Returns an `ExecutionPayloadV2` (with withdrawals). This is the wire
    /// path only; live block-production driver wiring is deferred to M8.
    /// TODO(M8): wire `get_payload_v2` into the block-production path.
    pub async fn get_payload_v2(&self, id: PayloadIdV1) -> Result<ExecutionPayloadV2, EngineError> {
        self.rpc_call("engine_getPayloadV2", [id]).await
    }

    /// `engine_getPayload*` dispatch per version (legacy single-payload interface).
    pub async fn get_payload(
        &self,
        v: GetPayloadVersion,
        id: PayloadIdV1,
    ) -> Result<ExecutionPayloadV1, EngineError> {
        match v {
            GetPayloadVersion::V1 => self.get_payload_v1(id).await,
            GetPayloadVersion::V2 => {
                // V2 is block-production-only; deferred to M8. Should not be
                // reached on the follow-only path.
                Err(EngineError::UnexpectedResponse(
                    "engine_getPayloadV2 is not wired on the follow-only path (M8)".into(),
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
        parse_hex_u64(&hex)
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

fn parse_hex_u64(s: &str) -> Result<u64, EngineError> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(hex, 16)
        .map_err(|_| EngineError::UnexpectedResponse(format!("expected hex u64, got `{s}`")))
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
