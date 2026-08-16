//! Fulu execution-layer request containers.
//!
//! Per `specs/fulu/beacon-chain.md`. Fulu does NOT reshape the EL request
//! containers (the only reshaped container is `BeaconState` + the new DAS
//! containers), so we re-export the electra types.

pub use crate::electra::requests::{
    ConsolidationRequest, DepositRequest, ExecutionRequests, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, WithdrawalRequest,
};
