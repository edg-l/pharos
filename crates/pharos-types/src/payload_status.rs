//! EL payload validation status.
//!
//! Defined here (in `pharos-types`) rather than `pharos-fork-choice` so that
//! `pharos-storage` can store and retrieve statuses without introducing a
//! dependency cycle: `pharos-fork-choice` → `pharos-stf` → `pharos-storage`
//! → `pharos-fork-choice` would be circular.

/// Per-block EL payload validation status.
///
/// Written by `write_block_transition` when `payload_status` is `Some`.
/// Read at startup by `rehydrate_fork_choice_store` to seed the in-memory
/// `pharos_fork_choice::Store::payload_statuses` map.
///
/// Per `D-payload-status-store`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PayloadStatus {
    /// The EL confirmed the payload is valid.
    Valid,
    /// The EL rejected the payload.
    Invalid,
    /// The EL has not yet responded; status is unknown.
    NotValidated,
}
