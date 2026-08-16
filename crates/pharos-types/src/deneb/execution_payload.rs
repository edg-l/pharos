//! Deneb `ExecutionPayload` and `ExecutionPayloadHeader` containers.
//!
//! Per `specs/deneb/beacon-chain.md` (Modified containers).
//!
//! ## Changes from Capella
//!
//! - `ExecutionPayload` adds `blob_gas_used: uint64` and `excess_blob_gas: uint64`.
//! - `ExecutionPayloadHeader` adds `blob_gas_used: uint64` and `excess_blob_gas: uint64`.
//!
//! ## Const parameters (ExecutionPayload)
//!
//! 1. `MAX_BYTES_PER_TRANSACTION` — `presets/*/bellatrix.yaml`
//! 2. `MAX_TRANSACTIONS_PER_PAYLOAD` — `presets/*/bellatrix.yaml`
//! 3. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
//! 4. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
//! 5. `MAX_WITHDRAWALS_PER_PAYLOAD` — `presets/*/capella.yaml`

use pharos_ssz::{Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::{Hash256, Uint256};

use crate::bellatrix::execution_payload::ExecutionAddress;
pub use crate::bellatrix::execution_payload::Transaction;
pub use crate::capella::execution_payload::Withdrawal;
use crate::phase0::primitives::Root;

// ── ExecutionPayload ──────────────────────────────────────────────────────────

/// Deneb `ExecutionPayload` per `specs/deneb/beacon-chain.md`.
///
/// Extends the Capella payload with `blob_gas_used` and `excess_blob_gas`.
///
/// Const parameters, in order:
/// 1. `MAX_BYTES_PER_TRANSACTION` — `presets/*/bellatrix.yaml`
/// 2. `MAX_TRANSACTIONS_PER_PAYLOAD` — `presets/*/bellatrix.yaml`
/// 3. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 4. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
/// 5. `MAX_WITHDRAWALS_PER_PAYLOAD` — `presets/*/capella.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPayload<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
> {
    /// `parent_hash: Hash32`.
    pub parent_hash: Hash256,
    /// `fee_recipient: ExecutionAddress`.
    pub fee_recipient: ExecutionAddress,
    /// `state_root: Bytes32`.
    pub state_root: Hash256,
    /// `receipts_root: Bytes32`.
    pub receipts_root: Hash256,
    /// `logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]`.
    pub logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    /// `prev_randao: Bytes32`.
    pub prev_randao: Hash256,
    /// `block_number: uint64`.
    pub block_number: u64,
    /// `gas_limit: uint64`.
    pub gas_limit: u64,
    /// `gas_used: uint64`.
    pub gas_used: u64,
    /// `timestamp: uint64`.
    pub timestamp: u64,
    /// `extra_data: ByteList[MAX_EXTRA_DATA_BYTES]`.
    pub extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// `base_fee_per_gas: uint256`.
    pub base_fee_per_gas: Uint256,
    /// `block_hash: Hash32`.
    pub block_hash: Hash256,
    /// `transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]`.
    pub transactions: SszList<Transaction<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    /// `withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]` (from Capella).
    pub withdrawals: SszList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
    /// `blob_gas_used: uint64` — [New in Deneb].
    pub blob_gas_used: u64,
    /// `excess_blob_gas: uint64` — [New in Deneb].
    pub excess_blob_gas: u64,
}

impl<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
> Default
    for ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >
{
    fn default() -> Self {
        Self {
            parent_hash: Hash256::default(),
            fee_recipient: ExecutionAddress::default(),
            state_root: Hash256::default(),
            receipts_root: Hash256::default(),
            logs_bloom: SszVector::default(),
            prev_randao: Hash256::default(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: SszList::default(),
            base_fee_per_gas: Uint256::default(),
            block_hash: Hash256::default(),
            transactions: SszList::default(),
            withdrawals: SszList::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }
}

// ── ExecutionPayloadHeader ────────────────────────────────────────────────────

/// Deneb `ExecutionPayloadHeader` per `specs/deneb/beacon-chain.md`.
///
/// Extends the Capella payload header with `blob_gas_used` and `excess_blob_gas`.
///
/// Const parameters, in order:
/// 1. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 2. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ExecutionPayloadHeader<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64>
{
    /// `parent_hash: Hash32`.
    pub parent_hash: Hash256,
    /// `fee_recipient: ExecutionAddress`.
    pub fee_recipient: ExecutionAddress,
    /// `state_root: Bytes32`.
    pub state_root: Hash256,
    /// `receipts_root: Bytes32`.
    pub receipts_root: Hash256,
    /// `logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]`.
    pub logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    /// `prev_randao: Bytes32`.
    pub prev_randao: Hash256,
    /// `block_number: uint64`.
    pub block_number: u64,
    /// `gas_limit: uint64`.
    pub gas_limit: u64,
    /// `gas_used: uint64`.
    pub gas_used: u64,
    /// `timestamp: uint64`.
    pub timestamp: u64,
    /// `extra_data: ByteList[MAX_EXTRA_DATA_BYTES]`.
    pub extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// `base_fee_per_gas: uint256`.
    pub base_fee_per_gas: Uint256,
    /// `block_hash: Hash32`.
    pub block_hash: Hash256,
    /// `transactions_root: Root`.
    pub transactions_root: Root,
    /// `withdrawals_root: Root` (from Capella).
    pub withdrawals_root: Root,
    /// `blob_gas_used: uint64` — [New in Deneb].
    pub blob_gas_used: u64,
    /// `excess_blob_gas: uint64` — [New in Deneb].
    pub excess_blob_gas: u64,
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet deneb `ExecutionPayload`.
pub type MainnetExecutionPayload = ExecutionPayload<
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
    16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet)
>;

/// Mainnet deneb `ExecutionPayloadHeader`.
pub type MainnetExecutionPayloadHeader = ExecutionPayloadHeader<256, 32>;

/// Minimal deneb `ExecutionPayload`.
pub type MinimalExecutionPayload = ExecutionPayload<
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
    4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal)
>;

/// Minimal deneb `ExecutionPayloadHeader`.
pub type MinimalExecutionPayloadHeader = ExecutionPayloadHeader<256, 32>;
