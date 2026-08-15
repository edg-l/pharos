//! Fork digest and fork data root helpers.
//!
//! `compute_fork_data_root` is the canonical home for this function;
//! `pharos-stf` re-exports it from here.
//!
//! Spec: `specs/phase0/beacon-chain.md:936-948` (fork data root),
//!       `specs/phase0/p2p-interface.md:269-285` (fork digest).

use pharos_ssz::TreeHash;
use pharos_utils::Epoch;

use crate::phase0::misc::{Fork, ForkData};
use crate::phase0::primitives::{ForkDigest, Root, Version};

/// `compute_fork_data_root` per `specs/phase0/beacon-chain.md:936-948`.
///
/// Returns the `hash_tree_root` of a `ForkData` container built from
/// `current_version` and `genesis_validators_root`.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: &Root) -> Root {
    ForkData {
        current_version,
        genesis_validators_root: *genesis_validators_root,
    }
    .tree_hash_root()
}

/// `compute_fork_digest` per `specs/phase0/p2p-interface.md:269-285`.
///
/// Returns the first 4 bytes of `compute_fork_data_root(current_version,
/// genesis_validators_root)` as a `ForkDigest`.
pub fn compute_fork_digest(current_version: Version, genesis_validators_root: &Root) -> ForkDigest {
    let root = compute_fork_data_root(current_version, genesis_validators_root);
    let bytes = root.as_slice();
    ForkDigest::from_array([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// ── ForkSchedule ──────────────────────────────────────────────────────────────

/// Fork transition schedule shared by `pharos-node` and `pharos-network`.
///
/// Lives in `pharos-types::fork` so both crates can depend on it without a
/// back-edge through the node crate.
///
/// M3a shape: `altair_fork_epoch = FAR_FUTURE_EPOCH`; `fork_at_epoch` returns
/// Phase 0 for all epochs. M3b's YAML loader will write the real epoch value
/// once Altair containers exist; the struct does not change.
///
/// D-fork-schedule in `docs/m3a-plan.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkSchedule {
    /// Genesis (Phase 0) fork version.
    pub genesis_fork_version: Version,
    /// Altair fork version (placeholder at M3a; only `altair_fork_epoch` matters).
    pub altair_fork_version: Version,
    /// Epoch at which the Altair fork activates.
    ///
    /// Set to `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) at M3a so Phase 0 is
    /// returned for all epochs. M3b sets the real value.
    pub altair_fork_epoch: Epoch,
    /// Genesis validators root used in fork-digest computation.
    pub genesis_validators_root: Root,
}

impl ForkSchedule {
    /// The `Fork` container active at `epoch`.
    ///
    /// At M3a, `altair_fork_epoch = FAR_FUTURE_EPOCH`, so Phase 0 is returned
    /// for all epochs.
    pub fn fork_at_epoch(&self, epoch: Epoch) -> Fork {
        if epoch >= self.altair_fork_epoch {
            // Altair active: previous=genesis, current=altair.
            Fork {
                previous_version: self.genesis_fork_version,
                current_version: self.altair_fork_version,
                epoch: self.altair_fork_epoch,
            }
        } else {
            // Phase 0: previous=genesis, current=genesis.
            Fork {
                previous_version: self.genesis_fork_version,
                current_version: self.genesis_fork_version,
                epoch: Epoch(0),
            }
        }
    }

    /// The current fork version active at `epoch`.
    pub fn current_fork_version(&self, epoch: Epoch) -> Version {
        if epoch >= self.altair_fork_epoch {
            self.altair_fork_version
        } else {
            self.genesis_fork_version
        }
    }

    /// The next fork version after the fork active at `epoch`.
    ///
    /// Returns `altair_fork_version` when in Phase 0, because Altair is the
    /// next fork. Returns `altair_fork_version` again when already in Altair
    /// (no further forks in M3a scope; M3b updates as needed).
    pub fn next_fork_version(&self, _epoch: Epoch) -> Version {
        // M3a: only one fork transition known; next is always altair_fork_version.
        self.altair_fork_version
    }

    /// The epoch at which the next fork after `epoch` activates.
    ///
    /// Returns `altair_fork_epoch` when in Phase 0. Returns
    /// `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) when already in or past Altair.
    pub fn next_fork_epoch(&self, epoch: Epoch) -> Epoch {
        if epoch >= self.altair_fork_epoch {
            // Already in Altair; no further forks known at M3a.
            Epoch(u64::MAX)
        } else {
            self.altair_fork_epoch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phase0_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            genesis_validators_root: Root::default(),
        }
    }

    #[test]
    fn fork_at_epoch_returns_phase0_when_altair_far_future() {
        let sched = phase0_schedule();
        // All epochs should be Phase 0.
        for epoch_n in [0u64, 1, 100, 74240, u64::MAX - 1] {
            let fork = sched.fork_at_epoch(Epoch(epoch_n));
            assert_eq!(
                fork.current_version, sched.genesis_fork_version,
                "epoch {epoch_n}: expected Phase 0 fork version"
            );
        }
    }

    #[test]
    fn current_fork_version_is_genesis_when_no_altair() {
        let sched = phase0_schedule();
        assert_eq!(
            sched.current_fork_version(Epoch(0)),
            sched.genesis_fork_version
        );
        assert_eq!(
            sched.current_fork_version(Epoch(74240)),
            sched.genesis_fork_version
        );
    }

    #[test]
    fn next_fork_epoch_is_altair_when_in_phase0() {
        let sched = phase0_schedule();
        // altair_fork_epoch = FAR_FUTURE_EPOCH, so next_fork_epoch = FAR_FUTURE_EPOCH.
        assert_eq!(sched.next_fork_epoch(Epoch(0)), Epoch(u64::MAX));
    }
}
