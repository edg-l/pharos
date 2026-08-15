//! Bellatrix beacon-chain type containers.
//!
//! All containers are defined per `specs/bellatrix/beacon-chain.md`.
//!
//! ## Stable-Rust const-generic constraint
//!
//! Same resolution as phase0 and altair applies: explicit `const` parameters
//! on each generic container struct, with preset-specific type aliases.
//! Bellatrix adds four new execution-layer const parameters:
//! `MAX_BYTES_PER_TRANSACTION`, `MAX_TRANSACTIONS_PER_PAYLOAD`,
//! `BYTES_PER_LOGS_BLOOM`, `MAX_EXTRA_DATA_BYTES`.

pub mod block;
pub mod body;
pub mod execution_payload;
pub mod state;

// Re-export all container types.
pub use block::{BeaconBlock, SignedBeaconBlock};
pub use body::BeaconBlockBody;
pub use execution_payload::{
    ExecutionAddress, ExecutionPayload, ExecutionPayloadHeader, Transaction,
};
pub use state::BeaconState;

// ── Preset-specific type aliases ───────────────────────────────────────────────

// ── Mainnet type aliases ───────────────────────────────────────────────────────

/// Mainnet bellatrix `BeaconState`.
pub use state::MainnetBeaconState;

/// Mainnet bellatrix `BeaconBlockBody`.
pub use body::MainnetBeaconBlockBody;

/// Mainnet bellatrix `BeaconBlock`.
pub use block::MainnetBeaconBlock;

/// Mainnet bellatrix `SignedBeaconBlock`.
pub use block::MainnetSignedBeaconBlock;

/// Mainnet bellatrix `ExecutionPayload`.
pub use execution_payload::MainnetExecutionPayload;

/// Mainnet bellatrix `ExecutionPayloadHeader`.
pub use execution_payload::MainnetExecutionPayloadHeader;

// ── Minimal type aliases ───────────────────────────────────────────────────────

/// Minimal bellatrix `BeaconState`.
pub use state::MinimalBeaconState;

/// Minimal bellatrix `BeaconBlockBody`.
pub use body::MinimalBeaconBlockBody;

/// Minimal bellatrix `BeaconBlock`.
pub use block::MinimalBeaconBlock;

/// Minimal bellatrix `SignedBeaconBlock`.
pub use block::MinimalSignedBeaconBlock;

/// Minimal bellatrix `ExecutionPayload`.
pub use execution_payload::MinimalExecutionPayload;

/// Minimal bellatrix `ExecutionPayloadHeader`.
pub use execution_payload::MinimalExecutionPayloadHeader;
