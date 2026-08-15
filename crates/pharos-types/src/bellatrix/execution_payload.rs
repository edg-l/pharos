//! Bellatrix `ExecutionPayload` and `ExecutionPayloadHeader` containers.
//!
//! Per `specs/bellatrix/beacon-chain.md:156-193`.
//!
//! ## Type aliases
//!
//! - `Transaction = ByteList[MAX_BYTES_PER_TRANSACTION]` per
//!   `specs/bellatrix/beacon-chain.md:58`.
//! - `ExecutionAddress = Bytes20` per `specs/bellatrix/beacon-chain.md:59`.
//!
//! ## Const parameters
//!
//! 1. `MAX_BYTES_PER_TRANSACTION` — `presets/*/bellatrix.yaml`
//! 2. `MAX_TRANSACTIONS_PER_PAYLOAD` — `presets/*/bellatrix.yaml`
//! 3. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
//! 4. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`

use pharos_ssz::{Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::{FixedBytes, Hash256, Uint256};

/// `Transaction = ByteList[MAX_BYTES_PER_TRANSACTION]`
/// per `specs/bellatrix/beacon-chain.md:58`.
pub type Transaction<const MAX_BYTES_PER_TRANSACTION: u64> = SszList<u8, MAX_BYTES_PER_TRANSACTION>;

/// `ExecutionAddress = Bytes20` per `specs/bellatrix/beacon-chain.md:59`.
pub type ExecutionAddress = FixedBytes<20>;

// ── ExecutionPayload ──────────────────────────────────────────────────────────

/// Bellatrix `ExecutionPayload` per `specs/bellatrix/beacon-chain.md:156-170`.
///
/// Const parameters, in order:
/// 1. `MAX_BYTES_PER_TRANSACTION` — `presets/*/bellatrix.yaml`
/// 2. `MAX_TRANSACTIONS_PER_PAYLOAD` — `presets/*/bellatrix.yaml`
/// 3. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 4. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPayload<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `parent_hash: Hash32` — `specs/bellatrix/beacon-chain.md:157`.
    pub parent_hash: Hash256,
    /// `fee_recipient: ExecutionAddress` — `specs/bellatrix/beacon-chain.md:158`.
    pub fee_recipient: ExecutionAddress,
    /// `state_root: Bytes32` — `specs/bellatrix/beacon-chain.md:159`.
    pub state_root: Hash256,
    /// `receipts_root: Bytes32` — `specs/bellatrix/beacon-chain.md:160`.
    pub receipts_root: Hash256,
    /// `logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]` — `specs/bellatrix/beacon-chain.md:161`.
    pub logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    /// `prev_randao: Bytes32` — `specs/bellatrix/beacon-chain.md:162`.
    pub prev_randao: Hash256,
    /// `block_number: uint64` — `specs/bellatrix/beacon-chain.md:163`.
    pub block_number: u64,
    /// `gas_limit: uint64` — `specs/bellatrix/beacon-chain.md:164`.
    pub gas_limit: u64,
    /// `gas_used: uint64` — `specs/bellatrix/beacon-chain.md:165`.
    pub gas_used: u64,
    /// `timestamp: uint64` — `specs/bellatrix/beacon-chain.md:166`.
    pub timestamp: u64,
    /// `extra_data: ByteList[MAX_EXTRA_DATA_BYTES]` — `specs/bellatrix/beacon-chain.md:167`.
    pub extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// `base_fee_per_gas: uint256` — `specs/bellatrix/beacon-chain.md:168`.
    pub base_fee_per_gas: Uint256,
    /// `block_hash: Hash32` — `specs/bellatrix/beacon-chain.md:169`.
    pub block_hash: Hash256,
    /// `transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]`
    /// — `specs/bellatrix/beacon-chain.md:170`.
    pub transactions: SszList<Transaction<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
}

impl<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> Default
    for ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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
        }
    }
}

// ── ExecutionPayloadHeader ────────────────────────────────────────────────────

/// Bellatrix `ExecutionPayloadHeader` per `specs/bellatrix/beacon-chain.md:178-193`.
///
/// Same fields as `ExecutionPayload` except `transactions` is replaced by
/// `transactions_root: Root`.
///
/// Const parameters, in order:
/// 1. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 2. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPayloadHeader<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64>
{
    /// `parent_hash: Hash32` — `specs/bellatrix/beacon-chain.md:179`.
    pub parent_hash: Hash256,
    /// `fee_recipient: ExecutionAddress` — `specs/bellatrix/beacon-chain.md:180`.
    pub fee_recipient: ExecutionAddress,
    /// `state_root: Bytes32` — `specs/bellatrix/beacon-chain.md:181`.
    pub state_root: Hash256,
    /// `receipts_root: Bytes32` — `specs/bellatrix/beacon-chain.md:182`.
    pub receipts_root: Hash256,
    /// `logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]` — `specs/bellatrix/beacon-chain.md:183`.
    pub logs_bloom: SszVector<u8, BYTES_PER_LOGS_BLOOM>,
    /// `prev_randao: Bytes32` — `specs/bellatrix/beacon-chain.md:184`.
    pub prev_randao: Hash256,
    /// `block_number: uint64` — `specs/bellatrix/beacon-chain.md:185`.
    pub block_number: u64,
    /// `gas_limit: uint64` — `specs/bellatrix/beacon-chain.md:186`.
    pub gas_limit: u64,
    /// `gas_used: uint64` — `specs/bellatrix/beacon-chain.md:187`.
    pub gas_used: u64,
    /// `timestamp: uint64` — `specs/bellatrix/beacon-chain.md:188`.
    pub timestamp: u64,
    /// `extra_data: ByteList[MAX_EXTRA_DATA_BYTES]` — `specs/bellatrix/beacon-chain.md:189`.
    pub extra_data: SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// `base_fee_per_gas: uint256` — `specs/bellatrix/beacon-chain.md:190`.
    pub base_fee_per_gas: Uint256,
    /// `block_hash: Hash32` — `specs/bellatrix/beacon-chain.md:191`.
    pub block_hash: Hash256,
    /// `transactions_root: Root` — `specs/bellatrix/beacon-chain.md:192`.
    pub transactions_root: Hash256,
}

impl<const BYTES_PER_LOGS_BLOOM: u64, const MAX_EXTRA_DATA_BYTES: u64> Default
    for ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
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
            transactions_root: Hash256::default(),
        }
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet `ExecutionPayload`.
pub type MainnetExecutionPayload = ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>;

/// Minimal `ExecutionPayload`.
pub type MinimalExecutionPayload = ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>;

/// Mainnet `ExecutionPayloadHeader`.
pub type MainnetExecutionPayloadHeader = ExecutionPayloadHeader<256, 32>;

/// Minimal `ExecutionPayloadHeader`.
pub type MinimalExecutionPayloadHeader = ExecutionPayloadHeader<256, 32>;

#[cfg(test)]
mod tests {
    use pharos_ssz::{Decode, Encode};

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(val: T) {
        let encoded = val.as_ssz_bytes();
        let decoded = T::from_ssz_bytes(&encoded).expect("SSZ decode failed");
        assert_eq!(val, decoded);
    }

    #[test]
    fn execution_payload_mainnet_roundtrip() {
        roundtrip(super::MainnetExecutionPayload::default());
    }

    #[test]
    fn execution_payload_minimal_roundtrip() {
        roundtrip(super::MinimalExecutionPayload::default());
    }

    #[test]
    fn execution_payload_header_mainnet_roundtrip() {
        roundtrip(super::MainnetExecutionPayloadHeader::default());
    }

    #[test]
    fn execution_payload_header_minimal_roundtrip() {
        roundtrip(super::MinimalExecutionPayloadHeader::default());
    }
}
