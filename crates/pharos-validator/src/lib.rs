//! Library surface for `pharos-validator`.
//!
//! Exposes internal modules so integration tests in `tests/` can access
//! the duty, slashing, signing, and run loop types without duplicating logic.

pub mod bn_client;
pub mod doppelganger;
pub mod duties;
pub mod interchange;
pub mod keystore;
pub mod run;
pub mod signing;
pub mod slashing;
