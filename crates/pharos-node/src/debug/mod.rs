//! Offline diagnostic calculators exposed under `pharos debug <tool>`.
//!
//! These reuse the live consensus code paths (no reimplementation) so a
//! divergence between a tool's output and node behaviour is impossible by
//! construction. They exist because every networking milestone since M5 lost
//! live-devnet time to wire / custody / encoding bugs that a 5-second offline
//! check would have caught (e.g. the M13 `get_custody_groups` big-endian bug,
//! `D-custody-uint-to-bytes-little-endian`).

pub mod das;
