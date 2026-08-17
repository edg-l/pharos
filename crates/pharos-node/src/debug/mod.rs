//! Offline diagnostic calculators exposed under `pharos debug <tool>`.
//!
//! These reuse the live consensus code paths (no reimplementation) so a
//! divergence between a tool's output and node behaviour is impossible by
//! construction. They exist because wire / custody / encoding bugs have
//! repeatedly cost live-devnet time that a 5-second offline
//! Check would have caught (e.g. the `get_custody_groups` big-endian bug,
//! `D-custody-uint-to-bytes-little-endian`).

pub mod das;
pub mod payload_bodies;
