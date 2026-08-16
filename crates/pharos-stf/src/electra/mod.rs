//! Electra state transition function.
//!
//! Per `specs/electra/beacon-chain.md`, `specs/electra/fork.md`,
//! and `specs/electra/p2p-interface.md`.
//!
//! Electra is a Deneb sibling (EIP-7549/7251/6110/7002/7685/7691). The shared
//! STF helpers live in `helpers`; operations / block / epoch / upgrade land in
//! later phases.

pub mod block;
pub mod epoch;
pub mod helpers;
pub mod light_client;
pub mod operations;
pub mod state_transition;
pub mod upgrade;
