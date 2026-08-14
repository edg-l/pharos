//! Phase 0 primitive type aliases.
//!
//! All type aliases are sourced from `specs/phase0/beacon-chain.md:163-177`
//! (custom types table).

// Re-export primitive newtypes from `pharos_utils`.
// Source: `specs/phase0/beacon-chain.md:165-169`
pub use pharos_utils::{CommitteeIndex, Epoch, Gwei, Slot, ValidatorIndex};

// Re-export byte-array aliases from `pharos_utils`.
// Source: `specs/phase0/beacon-chain.md:176-177`
pub use pharos_utils::{BLSPubkey, BLSSignature};

// Re-export Hash256 as Root alias (Bytes32, per `specs/phase0/beacon-chain.md:170`).
pub use pharos_utils::Hash256;

/// `Root` — a Merkle root (Bytes32).
/// Source: `specs/phase0/beacon-chain.md:170`.
pub type Root = pharos_utils::Hash256;

/// `Domain` — a signature domain (Bytes32).
/// Source: `specs/phase0/beacon-chain.md:175`.
pub type Domain = pharos_utils::Bytes32;

/// `ForkDigest` — a digest of the current fork data (Bytes4).
/// Source: `specs/phase0/beacon-chain.md:174`.
pub type ForkDigest = pharos_utils::Bytes4;

/// `Version` — a fork version number (Bytes4).
/// Source: `specs/phase0/beacon-chain.md:172`.
pub type Version = pharos_utils::Bytes4;

/// `DomainType` — a domain type discriminant (Bytes4).
/// Source: `specs/phase0/beacon-chain.md:173`.
pub type DomainType = pharos_utils::Bytes4;

/// `DepositIndex` — a deposit contract index (uint64).
/// Used in `BeaconState::eth1_deposit_index`.
pub type DepositIndex = u64;
