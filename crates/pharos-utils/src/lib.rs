//! Pharos shared utilities.
//!
//! Base crate with no internal dependencies. Hosts cross-cutting types and
//! helpers used across the workspace.

pub mod bls;
pub mod bytes;
pub mod cached_root;
pub mod hash;
pub mod uint256;
pub mod units;
pub mod version;

pub use bls::{
    BLS_DST, BLSSecretKey, BlsError, SignatureSet, aggregate, aggregate_pubkeys,
    fast_aggregate_verify, verify, verify_signature_sets,
};
pub use bytes::{BLSPubkey, BLSSignature, Bytes4, Bytes32, Bytes48, Bytes96, FixedBytes, Hash256};
pub use cached_root::CachedRoot;
pub use uint256::Uint256;
pub use units::{CommitteeIndex, Epoch, Gwei, Slot, ValidatorIndex};
