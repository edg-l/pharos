//! Capella state transition function.
//!
//! Per `specs/capella/beacon-chain.md`.
//!
//! Capella is a Bellatrix derivative: epoch processing replaces
//! `process_historical_roots_update` with `process_historical_summaries_update`;
//! block processing adds `process_withdrawals` and `process_bls_to_execution_change`.

pub mod block;
pub mod epoch;
pub mod helpers;
pub mod light_client;
pub mod operations;
pub mod state_transition;
pub mod upgrade;

pub use block::capella_block_to_altair_block;
pub use state_transition::{
    CapellaDispatch, CapellaJaFDispatch, CapellaProcessSlotsDispatch,
    GetExpectedWithdrawalsDispatch,
};
