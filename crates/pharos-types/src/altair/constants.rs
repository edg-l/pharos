//! Altair participation flag indices and related constants.
//!
//! Per `specs/altair/beacon-chain.md` — "Participation flag indices" section.

// ── Participation flag indices ────────────────────────────────────────────────
//
// Source: `specs/altair/beacon-chain.md` (Constants → Participation flag indices)

/// `TIMELY_SOURCE_FLAG_INDEX = 0` per `specs/altair/beacon-chain.md`.
pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;

/// `TIMELY_TARGET_FLAG_INDEX = 1` per `specs/altair/beacon-chain.md`.
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;

/// `TIMELY_HEAD_FLAG_INDEX = 2` per `specs/altair/beacon-chain.md`.
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;

// ── ParticipationFlags ────────────────────────────────────────────────────────

/// `ParticipationFlags` per `specs/altair/beacon-chain.md` (Types table).
///
/// SSZ equivalent: `uint8`. A succinct representation of 8 boolean
/// participation flags.
pub type ParticipationFlags = u8;
