//! Engine API wire types.
//!
//! Per `execution-apis/src/engine/paris.md` (V1) and
//! `execution-apis/src/engine/shanghai.md` (V2). All fields use the Ethereum
//! JSON-RPC hex convention (`DATA` and `QUANTITY` are both hex-encoded
//! strings with a `0x` prefix). We keep wire types as `String` to avoid
//! coupling the codec to `pharos-types`; explicit converters between
//! `ExecutionPayloadV1`/`V2` and the SSZ payload types
//! live in the STF<->engine boundary in `pharos-node`.

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

// ── WithdrawalV1 ──────────────────────────────────────────────────────────────

/// `WithdrawalV1` per `execution-apis/src/engine/shanghai.md` (Capella / Shanghai).
///
/// Field names and encoding per the spec:
/// - `index`:          `QUANTITY`, 64 Bits
/// - `validatorIndex`: `QUANTITY`, 64 Bits
/// - `address`:        `DATA`, 20 Bytes
/// - `amount`:         `QUANTITY`, 64 Bits (gwei; big-endian per spec note)
///
/// Note: `validator_index` serialises as `validatorIndex` (camelCase via
/// `#[serde(rename_all = "camelCase")]`), matching the spec exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalV1 {
    pub index: String,
    pub validator_index: String,
    pub address: String,
    pub amount: String,
}

// ── ExecutionPayloadV2 ────────────────────────────────────────────────────────

/// `ExecutionPayloadV2` per `execution-apis/src/engine/shanghai.md` (Capella).
///
/// Extends `ExecutionPayloadV1` with `withdrawals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV2 {
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
    pub withdrawals: Vec<WithdrawalV1>,
}

// ── PayloadAttributesV2 ───────────────────────────────────────────────────────

/// `PayloadAttributesV2` per `execution-apis/src/engine/shanghai.md` (Capella).
///
/// Extends `PayloadAttributesV1` with `withdrawals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV2 {
    pub timestamp: String,
    pub prev_randao: String,
    pub suggested_fee_recipient: String,
    pub withdrawals: Vec<WithdrawalV1>,
}

// ── From<capella::ExecutionPayload> for ExecutionPayloadV2 ────────────────────

/// Convert a Capella SSZ `ExecutionPayload` to the Engine API `ExecutionPayloadV2`
/// wire format.
///
/// Generic over all five capella payload const parameters. The converter is in
/// `pharos-engine` because `pharos-engine` already depends on `pharos-types`
/// and the conversion is pure wire-type mapping.
///
/// Per `D-engine-v2-dispatch` (docs/decisions.md M6-Capella section).
impl<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
>
    From<
        pharos_types::capella::ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    > for ExecutionPayloadV2
{
    fn from(
        p: pharos_types::capella::ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    ) -> Self {
        let withdrawals = p
            .withdrawals
            .as_slice()
            .iter()
            .map(|w| WithdrawalV1 {
                index: hex_quantity_u64(w.index),
                validator_index: hex_quantity_u64(w.validator_index.0),
                address: hex_data(w.address.as_slice()),
                amount: hex_quantity_u64(w.amount.0),
            })
            .collect();
        ExecutionPayloadV2 {
            parent_hash: hex_data(p.parent_hash.as_slice()),
            fee_recipient: hex_data(p.fee_recipient.as_slice()),
            state_root: hex_data(p.state_root.as_slice()),
            receipts_root: hex_data(p.receipts_root.as_slice()),
            logs_bloom: hex_data(p.logs_bloom.as_slice()),
            prev_randao: hex_data(p.prev_randao.as_slice()),
            block_number: hex_quantity_u64(p.block_number),
            gas_limit: hex_quantity_u64(p.gas_limit),
            gas_used: hex_quantity_u64(p.gas_used),
            timestamp: hex_quantity_u64(p.timestamp),
            extra_data: hex_data(p.extra_data.as_slice()),
            base_fee_per_gas: hex_quantity_uint256(&p.base_fee_per_gas),
            block_hash: hex_data(p.block_hash.as_slice()),
            transactions: p
                .transactions
                .as_slice()
                .iter()
                .map(|tx| hex_data(tx.as_slice()))
                .collect(),
            withdrawals,
        }
    }
}

// ── helpers (used by the From impl above) ────────────────────────────────────

fn hex_data(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_quantity_u64(n: u64) -> String {
    format!("0x{n:x}")
}

fn hex_quantity_uint256(n: &pharos_utils::Uint256) -> String {
    // Engine API QUANTITY: minimal big-endian hex, NO leading-zero nibble
    // (strict ELs like geth/reth reject "0x07"; the value must be "0x7").
    let be_bytes: Vec<u8> = n.to_le_bytes().into_iter().rev().collect();
    match be_bytes.iter().position(|&b| b != 0) {
        None => "0x0".to_string(),
        Some(i) => {
            use std::fmt::Write as _;
            let mut hex = String::with_capacity(2 + (be_bytes.len() - i) * 2);
            hex.push_str("0x");
            // First significant byte without its leading zero nibble.
            let _ = write!(hex, "{:x}", be_bytes[i]);
            // Remaining bytes keep full two-nibble width.
            for b in &be_bytes[i + 1..] {
                let _ = write!(hex, "{b:02x}");
            }
            hex
        }
    }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// QUANTITY encoding must be minimal hex with NO leading-zero nibble
    /// (strict ELs like geth/reth reject `"0x07"`). Per the JSON-RPC QUANTITY
    /// spec referenced by `execution-apis`.
    #[test]
    fn hex_quantity_uint256_is_minimal() {
        use pharos_utils::Uint256;
        assert_eq!(hex_quantity_uint256(&Uint256::from(0u64)), "0x0");
        assert_eq!(hex_quantity_uint256(&Uint256::from(7u64)), "0x7");
        assert_eq!(hex_quantity_uint256(&Uint256::from(15u64)), "0xf");
        assert_eq!(hex_quantity_uint256(&Uint256::from(256u64)), "0x100");
        assert_eq!(
            hex_quantity_uint256(&Uint256::from(0xdeadbeefu64)),
            "0xdeadbeef"
        );
    }

    // ── WithdrawalV1 serde round-trip ─────────────────────────────────────────

    /// Verify `WithdrawalV1` serialises with camelCase field names per shanghai.md:
    /// `index`, `validatorIndex`, `address`, `amount`.
    #[test]
    fn withdrawal_v1_serde_camel_case() {
        let w = WithdrawalV1 {
            index: "0xf0".to_string(),
            validator_index: "0xf0".to_string(),
            address: "0x00000000000000000000000000000000000010f0".to_string(),
            amount: "0x1".to_string(),
        };
        let json = serde_json::to_string(&w).unwrap();
        // Verify camelCase field names.
        assert!(
            json.contains("\"validatorIndex\""),
            "must use validatorIndex: {json}"
        );
        assert!(json.contains("\"index\""), "must use index: {json}");
        assert!(json.contains("\"address\""), "must use address: {json}");
        assert!(json.contains("\"amount\""), "must use amount: {json}");

        let decoded: WithdrawalV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, w);
    }

    // ── ExecutionPayloadV2 serde round-trip ───────────────────────────────────

    /// Verify `ExecutionPayloadV2` round-trips against a shanghai.md-shaped JSON
    /// with two withdrawals.
    #[test]
    fn execution_payload_v2_serde_round_trip() {
        let json = serde_json::json!({
            "parentHash": "0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
            "feeRecipient": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "stateRoot": "0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "logsBloom": "0x00",
            "prevRandao": "0xc130d5e63c61c935f6089e61140ca9136172677cf6aa5800dcc1cf0a02152a14",
            "blockNumber": "0x112720f",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0xbad2e8",
            "timestamp": "0x64e7785b",
            "extraData": "0x",
            "baseFeePerGas": "0x7",
            "blockHash": "0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
            "transactions": ["0xdeadbeef"],
            "withdrawals": [
                {
                    "index": "0xf0",
                    "validatorIndex": "0xf0",
                    "address": "0x00000000000000000000000000000000000010f0",
                    "amount": "0x1"
                },
                {
                    "index": "0xf1",
                    "validatorIndex": "0xf1",
                    "address": "0x00000000000000000000000000000000000010f1",
                    "amount": "0x1"
                }
            ]
        });

        let payload: ExecutionPayloadV2 = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(payload.withdrawals.len(), 2);
        assert_eq!(payload.withdrawals[0].index, "0xf0");
        assert_eq!(payload.withdrawals[0].validator_index, "0xf0");
        assert_eq!(
            payload.withdrawals[0].address,
            "0x00000000000000000000000000000000000010f0"
        );
        assert_eq!(payload.withdrawals[1].index, "0xf1");

        // Round-trip: serialise back and deserialise again.
        let re_json = serde_json::to_value(&payload).unwrap();
        let re_decoded: ExecutionPayloadV2 = serde_json::from_value(re_json).unwrap();
        assert_eq!(re_decoded, payload);
    }

    // ── From<capella::ExecutionPayload> for ExecutionPayloadV2 ────────────────

    /// Verify the `From` conversion builds a correct V2 wire payload from a
    /// capella SSZ `ExecutionPayload`, including withdrawals.
    #[test]
    fn from_capella_execution_payload_conversion() {
        use pharos_ssz::{SszList, SszSequence};
        use pharos_types::capella::ExecutionPayload as CapellaPayload;
        use pharos_types::capella::execution_payload::Withdrawal;
        use pharos_types::phase0::primitives::{Gwei, ValidatorIndex};

        // Build a minimal Capella payload with two withdrawals.
        let withdrawals = SszList::<Withdrawal, 4>::default()
            .with_push(Withdrawal {
                index: 0xf0,
                validator_index: ValidatorIndex(0xf0),
                address: Default::default(),
                amount: Gwei(1),
            })
            .unwrap()
            .with_push(Withdrawal {
                index: 0xf1,
                validator_index: ValidatorIndex(0xf1),
                address: Default::default(),
                amount: Gwei(2),
            })
            .unwrap();
        let payload = CapellaPayload::<1_073_741_824, 1_048_576, 256, 32, 4> {
            block_number: 0x112720f,
            gas_limit: 0x1c9c380,
            timestamp: 0x64e7785b,
            withdrawals,
            ..Default::default()
        };

        let wire: ExecutionPayloadV2 = payload.into();

        assert_eq!(wire.block_number, "0x112720f");
        assert_eq!(wire.gas_limit, "0x1c9c380");
        assert_eq!(wire.timestamp, "0x64e7785b");
        assert_eq!(wire.withdrawals.len(), 2);
        assert_eq!(wire.withdrawals[0].index, "0xf0");
        assert_eq!(wire.withdrawals[0].validator_index, "0xf0");
        assert_eq!(wire.withdrawals[0].amount, "0x1");
        assert_eq!(wire.withdrawals[1].index, "0xf1");
        assert_eq!(wire.withdrawals[1].amount, "0x2");
    }

    // ── PayloadAttributesV2 serde round-trip ──────────────────────────────────

    /// Verify `PayloadAttributesV2` serialises and deserialises with `withdrawals`.
    #[test]
    fn payload_attributes_v2_serde_round_trip() {
        let attrs = PayloadAttributesV2 {
            timestamp: "0x64e7785b".to_string(),
            prev_randao: "0xc130d5e63c61c935f6089e61140ca9136172677cf6aa5800dcc1cf0a02152a14"
                .to_string(),
            suggested_fee_recipient: "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b".to_string(),
            withdrawals: vec![WithdrawalV1 {
                index: "0xf0".to_string(),
                validator_index: "0xf0".to_string(),
                address: "0x00000000000000000000000000000000000010f0".to_string(),
                amount: "0x1".to_string(),
            }],
        };
        let json = serde_json::to_string(&attrs).unwrap();
        assert!(
            json.contains("\"withdrawals\""),
            "must include withdrawals: {json}"
        );
        let decoded: PayloadAttributesV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, attrs);
    }
}
