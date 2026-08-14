//! In-house SSZ encoding, decoding, and Merkleization.
//!
//! Implements the consensus-specs `ssz/` specification. Hosts the persistent
//! tree-backed `SszList` / `SszVector` types used by `BeaconState` fields.
//!
//! Conformance: `consensus-specs/tests/formats/ssz_generic` and `ssz_static`.
