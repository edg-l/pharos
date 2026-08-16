//! Electra `ExecutionPayload` and `ExecutionPayloadHeader` containers.
//!
//! Per `specs/electra/beacon-chain.md`.
//!
//! The Electra execution payload is structurally identical to the Deneb payload
//! (no new fields); we re-export the Deneb types to avoid duplication.

pub use crate::deneb::execution_payload::{
    ExecutionPayload, ExecutionPayloadHeader, MainnetExecutionPayload,
    MainnetExecutionPayloadHeader, MinimalExecutionPayload, MinimalExecutionPayloadHeader,
    Transaction, Withdrawal,
};
