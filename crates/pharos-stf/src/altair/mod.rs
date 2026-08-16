//! Altair beacon-chain state transition function.
//!
//! Mirrors `crates/pharos-stf/src/phase0/` layout.
//! Per `specs/altair/beacon-chain.md`.

pub mod block;
pub mod epoch;
pub mod helpers;
pub mod light_client;
pub mod light_client_dispatch;
pub mod operations;
pub mod slot;
pub mod state_transition;
pub mod upgrade;

pub use light_client_dispatch::{
    AltairDispatchBounds, BellatrixDispatchBounds, CapellaDispatchBounds, DenebDispatchBounds,
};
