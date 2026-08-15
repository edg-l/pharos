//! Capella `ExecutionPayload`, `ExecutionPayloadHeader`, and `Withdrawal` containers.
//!
//! Per `specs/capella/beacon-chain.md` (Containers section).
//!
//! ## Changes from Bellatrix
//!
//! - `Withdrawal` is a new container.
//! - `ExecutionPayload` adds `withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]`.
//! - `ExecutionPayloadHeader` adds `withdrawals_root: Root`.
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
use crate::phase0::primitives::{Gwei, ValidatorIndex};

// ── Withdrawal ────────────────────────────────────────────────────────────────

/// `WithdrawalIndex = uint64` per `specs/capella/beacon-chain.md`.
pub type WithdrawalIndex = u64;

/// Capella `Withdrawal` per `specs/capella/beacon-chain.md`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Withdrawal {
    /// `index: WithdrawalIndex` — monotonic withdrawal counter.
    pub index: WithdrawalIndex,
    /// `validator_index: ValidatorIndex` — which validator is withdrawing.
    pub validator_index: ValidatorIndex,
    /// `address: ExecutionAddress` — EL address to send to.
    pub address: ExecutionAddress,
    /// `amount: Gwei` — amount in gwei.
    pub amount: Gwei,
}

// ── ExecutionPayload ──────────────────────────────────────────────────────────

/// Capella `ExecutionPayload` per `specs/capella/beacon-chain.md`.
///
/// Extends the Bellatrix payload with `withdrawals`.
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
    /// `withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]` — [New in Capella].
    pub withdrawals: SszList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
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
        }
    }
}

// ── ExecutionPayloadHeader ────────────────────────────────────────────────────

/// Capella `ExecutionPayloadHeader` per `specs/capella/beacon-chain.md`.
///
/// Extends the Bellatrix header with `withdrawals_root`.
///
/// Const parameters, in order:
/// 1. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 2. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
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
    pub transactions_root: Hash256,
    /// `withdrawals_root: Root` — [New in Capella].
    pub withdrawals_root: Hash256,
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
            withdrawals_root: Hash256::default(),
        }
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet `ExecutionPayload`.
pub type MainnetExecutionPayload = ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 16>;

/// Minimal `ExecutionPayload`.
pub type MinimalExecutionPayload = ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 4>;

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
    fn withdrawal_roundtrip() {
        roundtrip(super::Withdrawal::default());
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
