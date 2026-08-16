//! Deneb blob and KZG primitive types.
//!
//! Per `specs/deneb/beacon-chain.md` and `specs/deneb/polynomial-commitments.md`.

use pharos_ssz::SszVector;
use pharos_utils::FixedBytes;

// ── Constants ──────────────────────────────────────────────────────────────────

/// `BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT = 4096 * 32 = 131072`.
///
/// Per `specs/deneb/polynomial-commitments.md`.
///
/// Expressed as `u64` to match the `const N: u64` bound on `SszVector<T, N>`.
pub const BYTES_PER_BLOB: u64 = 131_072;

/// Blob index within a block.
///
/// Per `specs/deneb/p2p-interface.md` (BlobIndex = uint64).
pub type BlobIndex = u64;

// ── KZGCommitment ─────────────────────────────────────────────────────────────

/// `KZGCommitment` — a 48-byte compressed G1 point.
///
/// Spec type: `ByteVector[48]` per `specs/deneb/beacon-chain.md`.
/// Uses a type alias so that `FixedBytes<48>`'s existing `Encode`, `Decode`,
/// and `TreeHash` impls are automatically used.
pub type KZGCommitment = FixedBytes<48>;

// ── KZGProof ──────────────────────────────────────────────────────────────────

/// `KZGProof` — a 48-byte compressed G1 point.
///
/// Spec type: `ByteVector[48]` per `specs/deneb/beacon-chain.md`.
pub type KZGProof = FixedBytes<48>;

// ── Blob ──────────────────────────────────────────────────────────────────────

/// `Blob` — a fixed-length vector of 131072 bytes.
///
/// Spec type: `Vector[Byte, BYTES_PER_BLOB]` per
/// `specs/deneb/polynomial-commitments.md`.
pub type Blob = SszVector<u8, BYTES_PER_BLOB>;
