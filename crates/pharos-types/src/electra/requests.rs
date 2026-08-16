//! Electra execution-layer request containers.
//!
//! Per `specs/electra/beacon-chain.md`.
//!
//! ## New containers
//! - `DepositRequest` (EIP-6110): deposit requests from the EL execution layer.
//! - `WithdrawalRequest` (EIP-7002): withdrawal requests from the EL.
//! - `ConsolidationRequest` (EIP-7251): consolidation requests from the EL.
//! - `ExecutionRequests`: wrapper holding all three request lists per block.
//! - `PendingDeposit`: CL-side queue entry for a deposit.
//! - `PendingPartialWithdrawal`: CL-side queue entry for a partial withdrawal.
//! - `PendingConsolidation`: CL-side queue entry for a consolidation.

use pharos_ssz::{Decode, Encode, SszList, SszVector, TreeHash};
use pharos_utils::Gwei;

use crate::phase0::primitives::{Epoch, Slot, ValidatorIndex};

// ── DepositRequest ────────────────────────────────────────────────────────────

/// `DepositRequest` per EIP-6110 / `specs/electra/beacon-chain.md`.
///
/// Represents a deposit that was included in the EL block and needs to be
/// processed by the CL.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct DepositRequest {
    /// `pubkey: BLSPubkey` (48 bytes).
    pub pubkey: SszVector<u8, 48>,
    /// `withdrawal_credentials: Bytes32`.
    pub withdrawal_credentials: [u8; 32],
    /// `amount: Gwei`.
    pub amount: Gwei,
    /// `signature: BLSSignature` (96 bytes).
    pub signature: SszVector<u8, 96>,
    /// `index: uint64`.
    pub index: u64,
}

// ── WithdrawalRequest ─────────────────────────────────────────────────────────

/// `WithdrawalRequest` per EIP-7002 / `specs/electra/beacon-chain.md`.
///
/// Represents a validator withdrawal request triggered from the EL.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct WithdrawalRequest {
    /// `source_address: ExecutionAddress` (20 bytes).
    pub source_address: [u8; 20],
    /// `validator_pubkey: BLSPubkey` (48 bytes).
    pub validator_pubkey: SszVector<u8, 48>,
    /// `amount: Gwei` — `0` means full exit (`FULL_EXIT_REQUEST_AMOUNT`).
    pub amount: Gwei,
}

// ── ConsolidationRequest ──────────────────────────────────────────────────────

/// `ConsolidationRequest` per EIP-7251 / `specs/electra/beacon-chain.md`.
///
/// Represents a validator consolidation request triggered from the EL.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ConsolidationRequest {
    /// `source_address: ExecutionAddress` (20 bytes).
    pub source_address: [u8; 20],
    /// `source_pubkey: BLSPubkey` (48 bytes).
    pub source_pubkey: SszVector<u8, 48>,
    /// `target_pubkey: BLSPubkey` (48 bytes).
    pub target_pubkey: SszVector<u8, 48>,
}

// ── ExecutionRequests ─────────────────────────────────────────────────────────

/// `ExecutionRequests` per `specs/electra/beacon-chain.md`.
///
/// Collects all three EL→CL request types per block.
///
/// Const parameters, in order:
/// 1. `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD` — `presets/*/electra.yaml`
/// 2. `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD` — `presets/*/electra.yaml`
/// 3. `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD` — `presets/*/electra.yaml`
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ExecutionRequests<
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
> {
    /// `deposits: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD]`.
    pub deposits: SszList<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>,
    /// `withdrawals: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD]`.
    pub withdrawals: SszList<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>,
    /// `consolidations: List[ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD]`.
    pub consolidations: SszList<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>,
}

// ── PendingDeposit ────────────────────────────────────────────────────────────

/// `PendingDeposit` per `specs/electra/beacon-chain.md`.
///
/// CL-side queue entry for a pending deposit.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingDeposit {
    /// `pubkey: BLSPubkey` (48 bytes).
    pub pubkey: SszVector<u8, 48>,
    /// `withdrawal_credentials: Bytes32`.
    pub withdrawal_credentials: [u8; 32],
    /// `amount: Gwei`.
    pub amount: Gwei,
    /// `signature: BLSSignature` (96 bytes).
    pub signature: SszVector<u8, 96>,
    /// `slot: Slot` — the slot at which the deposit was included.
    pub slot: Slot,
}

// ── PendingPartialWithdrawal ──────────────────────────────────────────────────

/// `PendingPartialWithdrawal` per `specs/electra/beacon-chain.md`.
///
/// CL-side queue entry for a pending partial withdrawal.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingPartialWithdrawal {
    /// `validator_index: ValidatorIndex`.
    pub validator_index: ValidatorIndex,
    /// `amount: Gwei`.
    pub amount: Gwei,
    /// `withdrawable_epoch: Epoch`.
    pub withdrawable_epoch: Epoch,
}

// ── PendingConsolidation ──────────────────────────────────────────────────────

/// `PendingConsolidation` per `specs/electra/beacon-chain.md`.
///
/// CL-side queue entry for a pending validator consolidation.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingConsolidation {
    /// `source_index: ValidatorIndex`.
    pub source_index: ValidatorIndex,
    /// `target_index: ValidatorIndex`.
    pub target_index: ValidatorIndex,
}
