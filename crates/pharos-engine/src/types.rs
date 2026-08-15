//! Engine API wire types.
//!
//! Per `execution-apis/src/engine/paris.md`. All fields use the Ethereum
//! JSON-RPC hex convention (`DATA` and `QUANTITY` are both hex-encoded
//! strings with a `0x` prefix). We keep wire types as `String` to avoid
//! coupling the codec to `pharos-types`; explicit converters between
//! `ExecutionPayloadV1` and `pharos_types::bellatrix::ExecutionPayload`
//! live in the STF<->engine boundary (Phase 4).

use serde::{Deserialize, Serialize};

// ── ExecutionPayloadV1 ────────────────────────────────────────────────────────

/// `ExecutionPayloadV1` per `execution-apis/src/engine/paris.md` (Bellatrix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV1 {
    pub parent_hash: String,
    pub fee_recipient: String,
    pub state_root: String,
    pub receipts_root: String,
    pub logs_bloom: String,
    pub prev_randao: String,
    pub block_number: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub timestamp: String,
    pub extra_data: String,
    pub base_fee_per_gas: String,
    pub block_hash: String,
    pub transactions: Vec<String>,
}

// ── ForkchoiceStateV1 ─────────────────────────────────────────────────────────

/// `ForkchoiceStateV1` per `execution-apis/src/engine/paris.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceStateV1 {
    pub head_block_hash: String,
    pub safe_block_hash: String,
    pub finalized_block_hash: String,
}

// ── PayloadAttributesV1 ───────────────────────────────────────────────────────

/// `PayloadAttributesV1` per `execution-apis/src/engine/paris.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV1 {
    pub timestamp: String,
    pub prev_randao: String,
    pub suggested_fee_recipient: String,
}

// ── PayloadStatusV1 ───────────────────────────────────────────────────────────

/// Status field of `PayloadStatusV1` per `execution-apis/src/engine/paris.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayloadStatusStatus {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

/// `PayloadStatusV1` per `execution-apis/src/engine/paris.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatusV1 {
    pub status: PayloadStatusStatus,
    pub latest_valid_hash: Option<String>,
    pub validation_error: Option<String>,
}

// ── PayloadIdV1 ───────────────────────────────────────────────────────────────

/// `PayloadIdV1` — opaque 8-byte identifier returned by `forkchoiceUpdated`
/// when payload attributes are supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadIdV1(pub [u8; 8]);

impl Serialize for PayloadIdV1 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(2 + 16);
        out.push_str("0x");
        for b in self.0 {
            use std::fmt::Write;
            let _ = write!(out, "{b:02x}");
        }
        s.serialize_str(&out)
    }
}

impl<'de> Deserialize<'de> for PayloadIdV1 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let hex = s.strip_prefix("0x").unwrap_or(&s);
        if hex.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "PayloadIdV1 must be 8 bytes (16 hex chars), got {}",
                hex.len()
            )));
        }
        let mut out = [0u8; 8];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(serde::de::Error::custom)?;
            out[i] = u8::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(Self(out))
    }
}

// ── ForkchoiceUpdatedV1Response ───────────────────────────────────────────────

/// `ForkchoiceUpdatedV1Response` per `execution-apis/src/engine/paris.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceUpdatedV1Response {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<PayloadIdV1>,
}

// ── eth_* response types ──────────────────────────────────────────────────────

/// Minimal `eth_getBlockByHash` / `eth_getBlockByNumber` response.
///
/// CL only consumes the fields needed for the Bellatrix transition + sanity
/// checks; we omit everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub hash: String,
    pub number: String,
    pub parent_hash: String,
    pub total_difficulty: Option<String>,
}

// ── TransitionConfigurationV1 ─────────────────────────────────────────────────

/// `TransitionConfigurationV1` per `execution-apis/src/engine/paris.md`.
///
/// Sent and received by `engine_exchangeTransitionConfigurationV1`.  Both the
/// CL and EL exchange the same struct so the two sides can verify they agree
/// on the terminal total difficulty and terminal block hash/number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionConfigurationV1 {
    /// Terminal total difficulty as a `QUANTITY` hex string.
    pub terminal_total_difficulty: String,
    /// Terminal block hash as a `DATA` hex string.
    pub terminal_block_hash: String,
    /// Terminal block number as a `QUANTITY` hex string.
    pub terminal_block_number: String,
}

/// `eth_syncing` response. Either `false` (not syncing) or an object with
/// progress fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SyncingStatus {
    NotSyncing(bool),
    Progress {
        #[serde(rename = "startingBlock")]
        starting_block: String,
        #[serde(rename = "currentBlock")]
        current_block: String,
        #[serde(rename = "highestBlock")]
        highest_block: String,
    },
}
