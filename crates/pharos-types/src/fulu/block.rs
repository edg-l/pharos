//! Fulu `BeaconBlock` and `SignedBeaconBlock` containers.
//!
//! Per `specs/fulu/beacon-chain.md`. Fulu does NOT reshape the block envelope
//! (the only reshaped container is `BeaconState` + the new DAS containers).
//! The fulu block is structurally identical to the electra block, so we
//! re-export the electra types.

pub use crate::electra::block::{
    BeaconBlock, MainnetBeaconBlock, MainnetSignedBeaconBlock, MinimalBeaconBlock,
    MinimalSignedBeaconBlock, SignedBeaconBlock,
};
