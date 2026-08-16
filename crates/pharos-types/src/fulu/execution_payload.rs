//! Fulu `ExecutionPayload` and `ExecutionPayloadHeader` containers.
//!
//! Per `specs/fulu/beacon-chain.md`. Fulu does NOT reshape the execution
//! payload (the only reshaped container is `BeaconState` + the new DAS
//! containers). The fulu execution payload is structurally identical to the
//! deneb/electra payload, so we re-export the deneb types.

pub use crate::deneb::execution_payload::{
    ExecutionPayload, ExecutionPayloadHeader, MainnetExecutionPayload,
    MainnetExecutionPayloadHeader, MinimalExecutionPayload, MinimalExecutionPayloadHeader,
    Transaction, Withdrawal,
};
