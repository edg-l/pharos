//! Bellatrix state transition function.
//!
//! Per `specs/bellatrix/beacon-chain.md:288-466`.
//!
//! Bellatrix is an Altair derivative: epoch processing is identical except for
//! the slashings multiplier; block processing adds `process_execution_payload`.

pub mod block;
pub mod epoch;
pub mod execution_engine;
pub mod helpers;
pub mod operations;
pub mod state_transition;
pub mod upgrade;
