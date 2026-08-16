//! Fulu `BeaconBlockBody` container.
//!
//! Per `specs/fulu/beacon-chain.md`. Fulu does NOT reshape the block body
//! container (the only reshaped container is `BeaconState` + the new DAS
//! containers). The fulu body is structurally identical to the electra body
//! (execution_requests retained), so we re-export the electra types.

pub use crate::electra::body::{BeaconBlockBody, MainnetBeaconBlockBody, MinimalBeaconBlockBody};
