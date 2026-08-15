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

/// `Root` — a Merkle root (Bytes32). Canonical Phase 0 spelling for
/// `pharos_utils::Hash256`; do not re-export `Hash256` under that name from
/// this module to avoid the same type having two import paths.
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

/// Number of attestation subnets per `specs/phase0/p2p-interface.md:382-387`.
///
/// `Bitvector<N>` uses `u64` const generics (B4 resolution), so this constant
/// is `u64`. Value is 64 for both mainnet and minimal presets.
pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

/// Maximum allowed clock disparity (ms) for gossip validation timing windows.
///
/// Per `specs/phase0/p2p-interface.md` (MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500 ms).
/// Applied symmetrically: a message may arrive up to this many ms before its
/// nominal send time as measured by the local clock.
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS: u64 = 500;

/// Maximum slot distance an attestation (or aggregate) may be from the current
/// slot and still be propagated.
///
/// Per `specs/phase0/p2p-interface.md` (ATTESTATION_PROPAGATION_SLOT_RANGE = 32).
pub const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;

/// Target number of aggregators per committee per slot.
///
/// Per `specs/phase0/validator.md` (TARGET_AGGREGATORS_PER_COMMITTEE = 16).
/// Used in `is_aggregator` to compute the modulo threshold.
pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

/// Number of intervals per slot used for light-client gossip timing windows.
///
/// Value is 3, meaning the sync message is "due" at 1/3 of the slot duration
/// after slot start. The Altair p2p spec defines this via
/// `SYNC_MESSAGE_DUE_BPS = 3333` basis points out of `BASIS_POINTS = 10000`,
/// giving `3333 * slot_ms / 10000 ≈ slot_ms / 3`. We use integer division
/// by 3 for spec parity (exact for all standard slot durations: 12 s, 6 s, 3 s).
pub const INTERVALS_PER_SLOT: u64 = 3;
