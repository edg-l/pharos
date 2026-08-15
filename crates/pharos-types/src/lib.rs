//! Pharos beacon-chain types.
//!
//! Per-fork containers organized as `enum`-of-forks (`BeaconState`,
//! `BeaconBlock`, `BeaconBlockBody`, ...). Preset constants live behind the
//! `EthSpec` trait (`MainnetEthSpec`, `MinimalEthSpec`, ...).

pub mod config;
pub mod eth_spec;
pub mod fork;
pub mod phase0;
pub mod shuffling;
pub mod views;

pub use config::RuntimeConfig;
pub use eth_spec::{EthSpec, MainnetEthSpec, MinimalEthSpec};
pub use views::{BeaconBlockBodyView, BeaconBlockView, BeaconStateView, SignedBeaconBlockView};
