//! Capella beacon-chain type containers.
//!
//! All containers are defined per `specs/capella/beacon-chain.md`.
//!
//! ## Changes from Bellatrix
//!
//! - New `Withdrawal`, `BLSToExecutionChange`, `SignedBLSToExecutionChange`,
//!   and `HistoricalSummary` containers.
//! - `ExecutionPayload` gains `withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]`.
//! - `ExecutionPayloadHeader` gains `withdrawals_root: Root`.
//! - `BeaconBlockBody` gains `bls_to_execution_changes`.
//! - `BeaconState` re-types `latest_execution_payload_header`, adds
//!   `next_withdrawal_index`, `next_withdrawal_validator_index`,
//!   and `historical_summaries`.

pub mod block;
pub mod body;
pub mod execution_payload;
pub mod operations;
pub mod state;

// Re-export all container types.
pub use block::{BeaconBlock, SignedBeaconBlock};
pub use body::BeaconBlockBody;
pub use execution_payload::{
    ExecutionPayload, ExecutionPayloadHeader, Withdrawal, WithdrawalIndex,
};
pub use operations::{BLSToExecutionChange, HistoricalSummary, SignedBLSToExecutionChange};
pub use state::BeaconState;

// ── Preset-specific type aliases ───────────────────────────────────────────────

// ── Mainnet type aliases ───────────────────────────────────────────────────────

/// Mainnet capella `BeaconState`.
pub use state::MainnetBeaconState;

/// Mainnet capella `BeaconBlockBody`.
pub use body::MainnetBeaconBlockBody;

/// Mainnet capella `BeaconBlock`.
pub use block::MainnetBeaconBlock;

/// Mainnet capella `SignedBeaconBlock`.
pub use block::MainnetSignedBeaconBlock;

/// Mainnet capella `ExecutionPayload`.
pub use execution_payload::MainnetExecutionPayload;

/// Mainnet capella `ExecutionPayloadHeader`.
pub use execution_payload::MainnetExecutionPayloadHeader;

// ── Minimal type aliases ───────────────────────────────────────────────────────

/// Minimal capella `BeaconState`.
pub use state::MinimalBeaconState;

/// Minimal capella `BeaconBlockBody`.
pub use body::MinimalBeaconBlockBody;

/// Minimal capella `BeaconBlock`.
pub use block::MinimalBeaconBlock;

/// Minimal capella `SignedBeaconBlock`.
pub use block::MinimalSignedBeaconBlock;

/// Minimal capella `ExecutionPayload`.
pub use execution_payload::MinimalExecutionPayload;

/// Minimal capella `ExecutionPayloadHeader`.
pub use execution_payload::MinimalExecutionPayloadHeader;
