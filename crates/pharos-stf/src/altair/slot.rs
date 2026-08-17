//! Altair slot processing — delegates to phase0 slot processing.
//!
//! In Altair the per-slot state transition (process_slots) is identical to
//! phase0 for the shared fields. The altair-specific epoch routines are wired
//! through `process_epoch` in `altair/epoch/mod.rs`.
//!
//! This module is the home for any altair-specific per-slot helpers once needed.
