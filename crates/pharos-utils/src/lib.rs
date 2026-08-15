//! Pharos shared utilities.
//!
//! Base crate with no internal dependencies. Hosts cross-cutting types and
//! helpers used across the workspace.

pub mod bls;
pub mod bytes;
pub mod hash;
pub mod uint256;
pub mod units;
pub mod version;

pub use bytes::{BLSPubkey, BLSSignature, Bytes4, Bytes32, Bytes48, Bytes96, FixedBytes, Hash256};
pub use uint256::Uint256;
pub use units::{CommitteeIndex, Epoch, Gwei, Slot, ValidatorIndex};
