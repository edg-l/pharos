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

// ── TryFrom<ExecutionPayloadV1> for bellatrix::ExecutionPayload ───────────────

/// Convert `ExecutionPayloadV1` wire type to the mainnet Bellatrix in-house
/// `ExecutionPayload`. Validates transaction count against
/// `MAX_TRANSACTIONS_PER_PAYLOAD = 1_048_576`.
///
/// This is the reverse of `PayloadToWire::to_execution_payload_v1`
/// (in `pharos-node`). Lives here in `pharos-engine` because `ExecutionPayloadV1`
/// is defined here; the orphan rule requires that either the trait, `Self`, or
/// the parameter type be from the current crate.
impl TryFrom<ExecutionPayloadV1>
    for pharos_types::bellatrix::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>
{
    type Error = crate::error::EngineError;

    fn try_from(p: ExecutionPayloadV1) -> Result<Self, Self::Error> {
        use pharos_ssz::{SszList, SszVector};
        if p.transactions.len() as u64 > 1_048_576 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "transactions count {} exceeds MAX_TRANSACTIONS_PER_PAYLOAD 1048576",
                p.transactions.len()
            )));
        }
        let txs: Vec<SszList<u8, 1_073_741_824>> = p
            .transactions
            .iter()
            .map(|h| decode_hex_bytes_into_sszlist(h))
            .collect::<Result<_, _>>()?;
        let transactions = SszList::from_items(txs).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("transactions overflow".into())
        })?;
        let extra_data = decode_hex_bytes_into_sszlist(&p.extra_data)?;
        let logs_bloom_bytes = parse_hex_fixed::<256>(&p.logs_bloom)?;
        let logs_bloom = SszVector::from_items(logs_bloom_bytes).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("logs_bloom size mismatch".into())
        })?;
        Ok(pharos_types::bellatrix::ExecutionPayload {
            parent_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.parent_hash)?),
            fee_recipient: pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                parse_hex_fixed::<20>(&p.fee_recipient)?,
            ),
            state_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.state_root)?),
            receipts_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(
                &p.receipts_root,
            )?),
            logs_bloom,
            prev_randao: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.prev_randao)?),
            block_number: parse_hex_u64(&p.block_number)?,
            gas_limit: parse_hex_u64(&p.gas_limit)?,
            gas_used: parse_hex_u64(&p.gas_used)?,
            timestamp: parse_hex_u64(&p.timestamp)?,
            extra_data,
            base_fee_per_gas: parse_hex_uint256(&p.base_fee_per_gas)?,
            block_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.block_hash)?),
            transactions,
        })
    }
}

// ── TryFrom<ExecutionPayloadV2> for capella::ExecutionPayload (mainnet) ───────

/// Convert `ExecutionPayloadV2` wire type to the mainnet Capella in-house
/// `ExecutionPayload` (MAX_WITHDRAWALS_PER_PAYLOAD = 16).
/// Validates transaction count (≤ 1_048_576) and withdrawal count (≤ 16).
impl TryFrom<ExecutionPayloadV2>
    for pharos_types::capella::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 16>
{
    type Error = crate::error::EngineError;

    fn try_from(p: ExecutionPayloadV2) -> Result<Self, Self::Error> {
        use pharos_ssz::{SszList, SszVector};
        use pharos_types::capella::execution_payload::Withdrawal;
        use pharos_types::phase0::primitives::{Gwei, ValidatorIndex};

        if p.transactions.len() as u64 > 1_048_576 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "transactions count {} exceeds MAX_TRANSACTIONS_PER_PAYLOAD 1048576",
                p.transactions.len()
            )));
        }
        if p.withdrawals.len() as u64 > 16 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "withdrawals count {} exceeds MAX_WITHDRAWALS_PER_PAYLOAD 16",
                p.withdrawals.len()
            )));
        }
        let txs: Vec<SszList<u8, 1_073_741_824>> = p
            .transactions
            .iter()
            .map(|h| decode_hex_bytes_into_sszlist(h))
            .collect::<Result<_, _>>()?;
        let transactions = SszList::from_items(txs).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("transactions overflow".into())
        })?;
        let withdrawals_vec: Vec<Withdrawal> = p
            .withdrawals
            .iter()
            .map(|w| {
                Ok(Withdrawal {
                    index: parse_hex_u64(&w.index)?,
                    validator_index: ValidatorIndex(parse_hex_u64(&w.validator_index)?),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            parse_hex_fixed::<20>(&w.address)?,
                        ),
                    amount: Gwei(parse_hex_u64(&w.amount)?),
                })
            })
            .collect::<Result<_, crate::error::EngineError>>()?;
        let withdrawals = SszList::from_items(withdrawals_vec).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("withdrawals overflow".into())
        })?;
        let extra_data = decode_hex_bytes_into_sszlist(&p.extra_data)?;
        let logs_bloom_bytes = parse_hex_fixed::<256>(&p.logs_bloom)?;
        let logs_bloom = SszVector::from_items(logs_bloom_bytes).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("logs_bloom size mismatch".into())
        })?;
        Ok(pharos_types::capella::ExecutionPayload {
            parent_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.parent_hash)?),
            fee_recipient: pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                parse_hex_fixed::<20>(&p.fee_recipient)?,
            ),
            state_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.state_root)?),
            receipts_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(
                &p.receipts_root,
            )?),
            logs_bloom,
            prev_randao: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.prev_randao)?),
            block_number: parse_hex_u64(&p.block_number)?,
            gas_limit: parse_hex_u64(&p.gas_limit)?,
            gas_used: parse_hex_u64(&p.gas_used)?,
            timestamp: parse_hex_u64(&p.timestamp)?,
            extra_data,
            base_fee_per_gas: parse_hex_uint256(&p.base_fee_per_gas)?,
            block_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.block_hash)?),
            transactions,
            withdrawals,
        })
    }
}

// ── TryFrom<ExecutionPayloadV2> for capella::ExecutionPayload (minimal) ───────

/// Convert `ExecutionPayloadV2` wire type to the minimal Capella in-house
/// `ExecutionPayload` (MAX_WITHDRAWALS_PER_PAYLOAD = 4).
/// Validates transaction count (≤ 1_048_576) and withdrawal count (≤ 4).
impl TryFrom<ExecutionPayloadV2>
    for pharos_types::capella::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 4>
{
    type Error = crate::error::EngineError;

    fn try_from(p: ExecutionPayloadV2) -> Result<Self, Self::Error> {
        use pharos_ssz::{SszList, SszVector};
        use pharos_types::capella::execution_payload::Withdrawal;
        use pharos_types::phase0::primitives::{Gwei, ValidatorIndex};

        if p.transactions.len() as u64 > 1_048_576 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "transactions count {} exceeds MAX_TRANSACTIONS_PER_PAYLOAD 1048576",
                p.transactions.len()
            )));
        }
        if p.withdrawals.len() as u64 > 4 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "withdrawals count {} exceeds MAX_WITHDRAWALS_PER_PAYLOAD 4",
                p.withdrawals.len()
            )));
        }
        let txs: Vec<SszList<u8, 1_073_741_824>> = p
            .transactions
            .iter()
            .map(|h| decode_hex_bytes_into_sszlist(h))
            .collect::<Result<_, _>>()?;
        let transactions = SszList::from_items(txs).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("transactions overflow".into())
        })?;
        let withdrawals_vec: Vec<Withdrawal> = p
            .withdrawals
            .iter()
            .map(|w| {
                Ok(Withdrawal {
                    index: parse_hex_u64(&w.index)?,
                    validator_index: ValidatorIndex(parse_hex_u64(&w.validator_index)?),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            parse_hex_fixed::<20>(&w.address)?,
                        ),
                    amount: Gwei(parse_hex_u64(&w.amount)?),
                })
            })
            .collect::<Result<_, crate::error::EngineError>>()?;
        let withdrawals = SszList::from_items(withdrawals_vec).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("withdrawals overflow".into())
        })?;
        let extra_data = decode_hex_bytes_into_sszlist(&p.extra_data)?;
        let logs_bloom_bytes = parse_hex_fixed::<256>(&p.logs_bloom)?;
        let logs_bloom = SszVector::from_items(logs_bloom_bytes).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("logs_bloom size mismatch".into())
        })?;
        Ok(pharos_types::capella::ExecutionPayload {
            parent_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.parent_hash)?),
            fee_recipient: pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                parse_hex_fixed::<20>(&p.fee_recipient)?,
            ),
            state_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.state_root)?),
            receipts_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(
                &p.receipts_root,
            )?),
            logs_bloom,
            prev_randao: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.prev_randao)?),
            block_number: parse_hex_u64(&p.block_number)?,
            gas_limit: parse_hex_u64(&p.gas_limit)?,
            gas_used: parse_hex_u64(&p.gas_used)?,
            timestamp: parse_hex_u64(&p.timestamp)?,
            extra_data,
            base_fee_per_gas: parse_hex_uint256(&p.base_fee_per_gas)?,
            block_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.block_hash)?),
            transactions,
            withdrawals,
        })
    }
}

// ── helpers (used by the From/TryFrom impls above) ───────────────────────────

/// Parse a `0x`-prefixed hex string as a `u64` QUANTITY.
pub(crate) fn parse_hex_u64(s: &str) -> Result<u64, crate::error::EngineError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16).map_err(|_| {
        crate::error::EngineError::UnexpectedResponse(format!("expected hex u64, got `{s}`"))
    })
}

/// Parse a `0x`-prefixed hex string as a fixed-size byte array.
pub(crate) fn parse_hex_fixed<const N: usize>(
    s: &str,
) -> Result<[u8; N], crate::error::EngineError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let padded = if stripped.len() % 2 == 1 {
        format!("0{stripped}")
    } else {
        stripped.to_string()
    };
    let hex_bytes: Vec<u8> = (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16).map_err(|_| {
                crate::error::EngineError::UnexpectedResponse(format!("invalid hex byte in `{s}`"))
            })
        })
        .collect::<Result<_, _>>()?;
    if hex_bytes.len() != N {
        return Err(crate::error::EngineError::UnexpectedResponse(format!(
            "expected {N} bytes, got {} from `{s}`",
            hex_bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&hex_bytes);
    Ok(out)
}

/// Parse a `0x`-prefixed hex string as a `pharos_utils::Uint256` QUANTITY.
pub(crate) fn parse_hex_uint256(
    s: &str,
) -> Result<pharos_utils::Uint256, crate::error::EngineError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let padded = if stripped.len() % 2 == 1 {
        format!("0{stripped}")
    } else {
        stripped.to_string()
    };
    let hex_bytes: Vec<u8> = (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16).map_err(|_| {
                crate::error::EngineError::UnexpectedResponse(format!("invalid hex byte in `{s}`"))
            })
        })
        .collect::<Result<_, _>>()?;
    if hex_bytes.len() > 32 {
        return Err(crate::error::EngineError::UnexpectedResponse(format!(
            "uint256 overflow in `{s}`"
        )));
    }
    // Copy big-endian hex_bytes into the tail of a 32-byte buffer.
    let mut be_bytes = [0u8; 32];
    let offset = 32 - hex_bytes.len();
    be_bytes[offset..].copy_from_slice(&hex_bytes);
    // Uint256 stores bytes little-endian.
    be_bytes.reverse();
    Ok(pharos_utils::Uint256::from_le_bytes(be_bytes))
}

/// Decode a `0x`-prefixed hex string into an `SszList<u8, N>`.
fn decode_hex_bytes_into_sszlist<const N: u64>(
    hex: &str,
) -> Result<pharos_ssz::SszList<u8, N>, crate::error::EngineError> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = if stripped.len() % 2 == 1 {
        format!("0{stripped}")
    } else {
        stripped.to_string()
    };
    let bytes: Vec<u8> = (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16).map_err(|_| {
                crate::error::EngineError::UnexpectedResponse(format!(
                    "invalid hex byte in `{hex}`"
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    pharos_ssz::SszList::from_items(bytes).map_err(|_| {
        crate::error::EngineError::UnexpectedResponse(format!("byte list overflow in `{hex}`"))
    })
}

// ── helpers (used by the capella From impl above) ────────────────────────────

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

// ── ExecutionPayloadV3 ────────────────────────────────────────────────────────

/// `ExecutionPayloadV3` per `execution-apis/src/engine/cancun.md` (Deneb).
///
/// Extends `ExecutionPayloadV2` with `blobGasUsed` and `excessBlobGas`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV3 {
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
    /// `blobGasUsed: QUANTITY`, 64 Bits — [New in Deneb].
    pub blob_gas_used: String,
    /// `excessBlobGas: QUANTITY`, 64 Bits — [New in Deneb].
    pub excess_blob_gas: String,
}

// ── BlobsBundleV1 ─────────────────────────────────────────────────────────────

/// `BlobsBundleV1` per `execution-apis/src/engine/cancun.md`.
///
/// Returned by `engine_getPayloadV3` alongside the execution payload.
/// All three arrays MUST be the same length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobsBundleV1 {
    /// KZG commitments, 48 bytes each (hex DATA).
    pub commitments: Vec<String>,
    /// KZG proofs, 48 bytes each (hex DATA).
    pub proofs: Vec<String>,
    /// Blob data, 131072 bytes each (hex DATA).
    pub blobs: Vec<String>,
}

// ── BlobsBundleV2 ─────────────────────────────────────────────────────────────

/// `BlobsBundleV2` per `execution-apis/src/engine/osaka.md` (Fulu / Osaka).
///
/// Returned by `engine_getPayloadV5` alongside the execution payload. The shape
/// is the same field names as `BlobsBundleV1` (`commitments`, `proofs`,
/// `blobs`), but the `proofs` semantics changed (EIP-7594): they are now CELL
/// proofs, and `proofs.len() == CELLS_PER_EXT_BLOB * blobs.len()` (128 cell
/// proofs per blob) rather than one proof per blob. `blobs` and `commitments`
/// arrays MUST be the same length.
///
/// This is the JSON-RPC wire type; conversion to the consensus-specs
/// `BlobsBundle` SSZ view happens at the engine-client boundary in
/// `pharos-node` (pharos does NOT compute the cell proofs — the EL returns them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobsBundleV2 {
    /// KZG commitments, 48 bytes each (hex DATA).
    pub commitments: Vec<String>,
    /// KZG cell proofs, 48 bytes each (hex DATA). `CELLS_PER_EXT_BLOB` per blob.
    pub proofs: Vec<String>,
    /// Blob data, 131072 bytes each (hex DATA).
    pub blobs: Vec<String>,
}

// ── BlobAndProofV1 ────────────────────────────────────────────────────────────

/// `BlobAndProofV1` per `execution-apis/src/engine/cancun.md`.
///
/// One element of the response from `engine_getBlobsV1`. An absent blob in the
/// pool is represented as a JSON `null` entry; callers handle that via
/// `Option<BlobAndProofV1>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobAndProofV1 {
    /// `blob`: 131072 bytes (DATA).
    pub blob: String,
    /// `proof`: KZGProof, 48 bytes (DATA).
    pub proof: String,
}

// ── PayloadAttributesV3 ───────────────────────────────────────────────────────

/// `PayloadAttributesV3` per `execution-apis/src/engine/cancun.md` (Deneb).
///
/// Extends `PayloadAttributesV2` with `parentBeaconBlockRoot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV3 {
    pub timestamp: String,
    pub prev_randao: String,
    pub suggested_fee_recipient: String,
    pub withdrawals: Vec<WithdrawalV1>,
    /// `parentBeaconBlockRoot: DATA`, 32 Bytes — Root of the parent beacon block.
    pub parent_beacon_block_root: String,
}

// ── GetPayloadV3Response ──────────────────────────────────────────────────────

/// Response to `engine_getPayloadV3` per `execution-apis/src/engine/cancun.md`.
///
/// Returns execution payload + block value + blobs bundle + builder override hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadV3Response {
    pub execution_payload: ExecutionPayloadV3,
    pub block_value: String,
    pub blobs_bundle: BlobsBundleV1,
    pub should_override_builder: bool,
}

// ── GetPayloadV4Response ──────────────────────────────────────────────────────

/// Response to `engine_getPayloadV4` per `execution-apis/src/engine/prague.md`.
///
/// Extends `GetPayloadV3Response` with `executionRequests` — the EIP-7685
/// encoded execution request list for the block. Each entry is `0x`-prefixed
/// hex DATA: `request_type_byte || ssz_serialized_request_list`.
/// An empty request list is represented as `[]` (per spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadV4Response {
    pub execution_payload: ExecutionPayloadV3,
    pub block_value: String,
    pub blobs_bundle: BlobsBundleV1,
    pub should_override_builder: bool,
    /// `executionRequests: Array of DATA` — EIP-7685 request list.
    pub execution_requests: Vec<String>,
}

// ── GetPayloadV5Response ──────────────────────────────────────────────────────

/// Response to `engine_getPayloadV5` per `execution-apis/src/engine/osaka.md`.
///
/// Identical envelope to `GetPayloadV4Response` (V3 payload + block value +
/// `shouldOverrideBuilder` + `executionRequests`) EXCEPT the blobs bundle is the
/// fulu `BlobsBundleV2` (cell proofs, `proofs.len() == CELLS_PER_EXT_BLOB *
/// blobs.len()`) instead of `BlobsBundleV1` (one proof per blob).
///
/// Per `execution-apis/src/engine/osaka.md` `engine_getPayloadV5` (lines 56-79):
/// > result: object
/// >   - executionPayload: ExecutionPayloadV3
/// >   - blockValue: QUANTITY
/// >   - blobsBundle: BlobsBundleV2
/// >   - shouldOverrideBuilder: BOOLEAN
/// >   - executionRequests: Array of DATA
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadV5Response {
    pub execution_payload: ExecutionPayloadV3,
    pub block_value: String,
    pub blobs_bundle: BlobsBundleV2,
    pub should_override_builder: bool,
    /// `executionRequests: Array of DATA` — EIP-7685 request list.
    pub execution_requests: Vec<String>,
}

// ── From<deneb::ExecutionPayload> for ExecutionPayloadV3 ──────────────────────

/// Convert a Deneb SSZ `ExecutionPayload` to the Engine API `ExecutionPayloadV3`
/// wire format.
///
/// Extends the Capella conversion with `blobGasUsed` and `excessBlobGas`.
impl<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
>
    From<
        pharos_types::deneb::ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    > for ExecutionPayloadV3
{
    fn from(
        p: pharos_types::deneb::ExecutionPayload<
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
        ExecutionPayloadV3 {
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
            blob_gas_used: hex_quantity_u64(p.blob_gas_used),
            excess_blob_gas: hex_quantity_u64(p.excess_blob_gas),
        }
    }
}

// ── TryFrom<ExecutionPayloadV3> for deneb::ExecutionPayload (mainnet) ─────────

/// Convert `ExecutionPayloadV3` wire type to the mainnet Deneb in-house
/// `ExecutionPayload` (MAX_WITHDRAWALS_PER_PAYLOAD = 16).
impl TryFrom<ExecutionPayloadV3>
    for pharos_types::deneb::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 16>
{
    type Error = crate::error::EngineError;

    fn try_from(p: ExecutionPayloadV3) -> Result<Self, Self::Error> {
        use pharos_ssz::{SszList, SszVector};
        use pharos_types::capella::execution_payload::Withdrawal;
        use pharos_types::phase0::primitives::{Gwei, ValidatorIndex};

        if p.transactions.len() as u64 > 1_048_576 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "transactions count {} exceeds MAX_TRANSACTIONS_PER_PAYLOAD 1048576",
                p.transactions.len()
            )));
        }
        if p.withdrawals.len() as u64 > 16 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "withdrawals count {} exceeds MAX_WITHDRAWALS_PER_PAYLOAD 16",
                p.withdrawals.len()
            )));
        }
        let txs: Vec<SszList<u8, 1_073_741_824>> = p
            .transactions
            .iter()
            .map(|h| decode_hex_bytes_into_sszlist(h))
            .collect::<Result<_, _>>()?;
        let transactions = SszList::from_items(txs).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("transactions overflow".into())
        })?;
        let withdrawals_vec: Vec<Withdrawal> = p
            .withdrawals
            .iter()
            .map(|w| {
                Ok(Withdrawal {
                    index: parse_hex_u64(&w.index)?,
                    validator_index: ValidatorIndex(parse_hex_u64(&w.validator_index)?),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            parse_hex_fixed::<20>(&w.address)?,
                        ),
                    amount: Gwei(parse_hex_u64(&w.amount)?),
                })
            })
            .collect::<Result<_, crate::error::EngineError>>()?;
        let withdrawals = SszList::from_items(withdrawals_vec).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("withdrawals overflow".into())
        })?;
        let extra_data = decode_hex_bytes_into_sszlist(&p.extra_data)?;
        let logs_bloom_bytes = parse_hex_fixed::<256>(&p.logs_bloom)?;
        let logs_bloom = SszVector::from_items(logs_bloom_bytes).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("logs_bloom size mismatch".into())
        })?;
        Ok(pharos_types::deneb::ExecutionPayload {
            parent_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.parent_hash)?),
            fee_recipient: pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                parse_hex_fixed::<20>(&p.fee_recipient)?,
            ),
            state_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.state_root)?),
            receipts_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(
                &p.receipts_root,
            )?),
            logs_bloom,
            prev_randao: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.prev_randao)?),
            block_number: parse_hex_u64(&p.block_number)?,
            gas_limit: parse_hex_u64(&p.gas_limit)?,
            gas_used: parse_hex_u64(&p.gas_used)?,
            timestamp: parse_hex_u64(&p.timestamp)?,
            extra_data,
            base_fee_per_gas: parse_hex_uint256(&p.base_fee_per_gas)?,
            block_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.block_hash)?),
            transactions,
            withdrawals,
            blob_gas_used: parse_hex_u64(&p.blob_gas_used)?,
            excess_blob_gas: parse_hex_u64(&p.excess_blob_gas)?,
        })
    }
}

// ── TryFrom<ExecutionPayloadV3> for deneb::ExecutionPayload (minimal) ─────────

/// Convert `ExecutionPayloadV3` wire type to the minimal Deneb in-house
/// `ExecutionPayload` (MAX_WITHDRAWALS_PER_PAYLOAD = 4).
impl TryFrom<ExecutionPayloadV3>
    for pharos_types::deneb::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 4>
{
    type Error = crate::error::EngineError;

    fn try_from(p: ExecutionPayloadV3) -> Result<Self, Self::Error> {
        use pharos_ssz::{SszList, SszVector};
        use pharos_types::capella::execution_payload::Withdrawal;
        use pharos_types::phase0::primitives::{Gwei, ValidatorIndex};

        if p.transactions.len() as u64 > 1_048_576 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "transactions count {} exceeds MAX_TRANSACTIONS_PER_PAYLOAD 1048576",
                p.transactions.len()
            )));
        }
        if p.withdrawals.len() as u64 > 4 {
            return Err(crate::error::EngineError::UnexpectedResponse(format!(
                "withdrawals count {} exceeds MAX_WITHDRAWALS_PER_PAYLOAD 4",
                p.withdrawals.len()
            )));
        }
        let txs: Vec<SszList<u8, 1_073_741_824>> = p
            .transactions
            .iter()
            .map(|h| decode_hex_bytes_into_sszlist(h))
            .collect::<Result<_, _>>()?;
        let transactions = SszList::from_items(txs).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("transactions overflow".into())
        })?;
        let withdrawals_vec: Vec<Withdrawal> = p
            .withdrawals
            .iter()
            .map(|w| {
                Ok(Withdrawal {
                    index: parse_hex_u64(&w.index)?,
                    validator_index: ValidatorIndex(parse_hex_u64(&w.validator_index)?),
                    address:
                        pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                            parse_hex_fixed::<20>(&w.address)?,
                        ),
                    amount: Gwei(parse_hex_u64(&w.amount)?),
                })
            })
            .collect::<Result<_, crate::error::EngineError>>()?;
        let withdrawals = SszList::from_items(withdrawals_vec).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("withdrawals overflow".into())
        })?;
        let extra_data = decode_hex_bytes_into_sszlist(&p.extra_data)?;
        let logs_bloom_bytes = parse_hex_fixed::<256>(&p.logs_bloom)?;
        let logs_bloom = SszVector::from_items(logs_bloom_bytes).map_err(|_| {
            crate::error::EngineError::UnexpectedResponse("logs_bloom size mismatch".into())
        })?;
        Ok(pharos_types::deneb::ExecutionPayload {
            parent_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.parent_hash)?),
            fee_recipient: pharos_types::bellatrix::execution_payload::ExecutionAddress::from_array(
                parse_hex_fixed::<20>(&p.fee_recipient)?,
            ),
            state_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.state_root)?),
            receipts_root: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(
                &p.receipts_root,
            )?),
            logs_bloom,
            prev_randao: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.prev_randao)?),
            block_number: parse_hex_u64(&p.block_number)?,
            gas_limit: parse_hex_u64(&p.gas_limit)?,
            gas_used: parse_hex_u64(&p.gas_used)?,
            timestamp: parse_hex_u64(&p.timestamp)?,
            extra_data,
            base_fee_per_gas: parse_hex_uint256(&p.base_fee_per_gas)?,
            block_hash: pharos_utils::Hash256::from_array(parse_hex_fixed::<32>(&p.block_hash)?),
            transactions,
            withdrawals,
            blob_gas_used: parse_hex_u64(&p.blob_gas_used)?,
            excess_blob_gas: parse_hex_u64(&p.excess_blob_gas)?,
        })
    }
}

// ── BlobAndProofV2 ────────────────────────────────────────────────────────────

/// `BlobAndProofV2` per `execution-apis/src/engine/osaka.md`.
///
/// One element of the response from `engine_getBlobsV2` / `engine_getBlobsV3`.
/// Differs from `BlobAndProofV1` in that `proofs` is a `Vec<String>` (cell
/// proofs, one per cell) rather than a single proof string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobAndProofV2 {
    /// `blob`: 131072 bytes (DATA).
    pub blob: String,
    /// `proofs`: array of KZG cell proofs (DATA, 48 bytes each).
    pub proofs: Vec<String>,
}

// ── BlobCellsAndProofs ────────────────────────────────────────────────────────

/// Response element for `engine_getBlobsV4` per `execution-apis/src/engine/amsterdam.md`.
///
/// Returns partial-column data (`blob_cells`) alongside KZG proofs.
/// The outer `Vec<Option<BlobCellsAndProofs>>` uses `null` for absent blob sets;
/// within each element, individual cells and proofs may be `null` when a specific
/// cell index is not available (partial-column case).
/// Note: the field names in the JSON wire format are `blob_cells` and `proofs` (snake_case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobCellsAndProofs {
    /// `blob_cells`: array of cell data hex strings; individual cells may be `null`.
    pub blob_cells: Vec<Option<String>>,
    /// `proofs`: array of KZG proofs (DATA, 48 bytes each); individual proofs may be `null`.
    pub proofs: Vec<Option<String>>,
}

// ── ExecutionPayloadBodyV1 ────────────────────────────────────────────────────

/// Response element for `engine_getPayloadBodiesByHashV1` and
/// `engine_getPayloadBodiesByRangeV1` per `execution-apis/src/engine/shanghai.md`.
///
/// An absent block body is represented as JSON `null` (→ `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadBodyV1 {
    pub transactions: Vec<String>,
    pub withdrawals: Option<Vec<WithdrawalV1>>,
}

// ── ExecutionPayloadBodyV2 ────────────────────────────────────────────────────

/// Response element for `engine_getPayloadBodiesByHashV2` and
/// `engine_getPayloadBodiesByRangeV2` per `execution-apis/src/engine/amsterdam.md`.
///
/// Extends `ExecutionPayloadBodyV1` with `blockAccessList`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadBodyV2 {
    pub transactions: Vec<String>,
    pub withdrawals: Option<Vec<WithdrawalV1>>,
    /// `blockAccessList`: optional RLP-encoded block access list (DATA).
    pub block_access_list: Option<String>,
}

// ── ExecutionPayloadV4 ────────────────────────────────────────────────────────

/// `ExecutionPayloadV4` per `execution-apis/src/engine/amsterdam.md`.
///
/// Extends `ExecutionPayloadV3` with `blockAccessList` (EIP-7709 / Amsterdam).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV4 {
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
    pub blob_gas_used: String,
    pub excess_blob_gas: String,
    /// `blockAccessList`: RLP-encoded block access list (DATA) — [New in Amsterdam].
    pub block_access_list: String,
}

// ── GetPayloadV6Response ──────────────────────────────────────────────────────

/// Response to `engine_getPayloadV6` per `execution-apis/src/engine/amsterdam.md`.
///
/// Identical envelope to `GetPayloadV5Response` except `executionPayload` is
/// `ExecutionPayloadV4` (includes `blockAccessList`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadV6Response {
    pub execution_payload: ExecutionPayloadV4,
    pub block_value: String,
    pub blobs_bundle: BlobsBundleV2,
    pub should_override_builder: bool,
    /// `executionRequests: Array of DATA` — EIP-7685 request list.
    pub execution_requests: Vec<String>,
}

// ── GetPayloadV2Response ──────────────────────────────────────────────────────

/// Response to `engine_getPayloadV2` per `execution-apis/src/engine/shanghai.md`.
///
/// Returns the execution payload AND the expected block value (priority fees) to
/// be received by the fee recipient, in wei. V1 returns a bare `ExecutionPayloadV1`;
/// V2 wraps it in this envelope.
///
/// Spec: "executionPayload: ExecutionPayloadV1 | ExecutionPayloadV2" +
///       "blockValue: QUANTITY, 256 Bits"
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadV2Response {
    pub execution_payload: ExecutionPayloadV2,
    pub block_value: String,
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

// ── ClientVersionV1 ───────────────────────────────────────────────────────────

/// `ClientVersionV1` per `execution-apis/src/engine/identification.md`.
///
/// Exchanged by `engine_getClientVersionV1`: the CL sends its own identity as
/// the single request param and the EL replies with an array of its identities
/// (one entry, or several behind a multiplexer). The same struct is reused for
/// both directions.
///
/// Field encoding per the spec:
/// - `code`:    2-letter [`ClientCode`], e.g. `"PH"` (Pharos) or `"GE"` (geth).
/// - `name`:    human-readable client name, e.g. `"Pharos"`.
/// - `version`: version string, e.g. `"v0.21.0"`.
/// - `commit`:  `DATA`, first 4 bytes of the build commit hash, `0x`-prefixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientVersionV1 {
    pub code: String,
    pub name: String,
    pub version: String,
    pub commit: String,
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

    // ── BlobsBundleV2 + GetPayloadV5Response serde round-trip ──────────────────

    /// `BlobsBundleV2` round-trips against an osaka.md-shaped JSON. Per
    /// `execution-apis/src/engine/osaka.md` `BlobsBundleV2`: `commitments`,
    /// `proofs`, `blobs`, with `proofs.len() == CELLS_PER_EXT_BLOB * blobs.len()`
    /// (128 cell proofs per blob). This sample uses 1 blob → 1 commitment → 2
    /// abbreviated proofs to exercise the length-asymmetry shape (the spec value
    /// 128 is not material to the serde mapping; the field names are).
    #[test]
    fn blobs_bundle_v2_serde_round_trip() {
        let json = serde_json::json!({
            "commitments": ["0xc0"],
            "proofs": ["0xp0", "0xp1"],
            "blobs": ["0xb0"],
        });
        let bundle: BlobsBundleV2 = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(bundle.commitments.len(), 1);
        assert_eq!(bundle.proofs.len(), 2);
        assert_eq!(bundle.blobs.len(), 1);

        let re_json = serde_json::to_value(&bundle).unwrap();
        let re_decoded: BlobsBundleV2 = serde_json::from_value(re_json).unwrap();
        assert_eq!(re_decoded, bundle);
    }

    /// `GetPayloadV5Response` round-trips against an osaka.md-shaped JSON
    /// envelope: `executionPayload`, `blockValue`, `blobsBundle` (V2),
    /// `shouldOverrideBuilder`, `executionRequests`.
    #[test]
    fn get_payload_v5_response_serde_round_trip() {
        let json = serde_json::json!({
            "executionPayload": {
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
                "withdrawals": [],
                "blobGasUsed": "0x0",
                "excessBlobGas": "0x0"
            },
            "blockValue": "0x1",
            "blobsBundle": {
                "commitments": ["0xc0"],
                "proofs": ["0xp0", "0xp1"],
                "blobs": ["0xb0"]
            },
            "shouldOverrideBuilder": false,
            "executionRequests": ["0x0100"]
        });

        let resp: GetPayloadV5Response = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(resp.block_value, "0x1");
        assert_eq!(resp.blobs_bundle.proofs.len(), 2);
        assert_eq!(resp.blobs_bundle.blobs.len(), 1);
        assert_eq!(resp.execution_requests, vec!["0x0100".to_string()]);
        assert!(!resp.should_override_builder);

        let re_json = serde_json::to_value(&resp).unwrap();
        let re_decoded: GetPayloadV5Response = serde_json::from_value(re_json).unwrap();
        assert_eq!(re_decoded, resp);
    }
}
