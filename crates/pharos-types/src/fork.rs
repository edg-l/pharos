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

/// `DOMAIN_BLS_TO_EXECUTION_CHANGE` per `specs/capella/beacon-chain.md`.
///
/// Used by `bls_to_execution_change` signing domain (fork-agnostic: uses
/// `GENESIS_FORK_VERSION`, not the current fork version).
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: [u8; 4] = [0x0A, 0x00, 0x00, 0x00];

/// Fork transition schedule shared by `pharos-node` and `pharos-network`.
///
/// Lives in `pharos-types::fork` so both crates can depend on it without a
/// back-edge through the node crate.
///
/// Six-fork shape (Phase 0 → Altair → Bellatrix → Capella → Deneb → Electra). Accessors
/// use a `[(epoch, version)]` lookup table sorted ascending by activation epoch.
/// `FAR_FUTURE_EPOCH` (`Epoch(u64::MAX)`) deactivates a fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkSchedule {
    /// Genesis (Phase 0) fork version.
    pub genesis_fork_version: Version,
    /// Altair fork version.
    pub altair_fork_version: Version,
    /// Epoch at which the Altair fork activates.
    ///
    /// `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) keeps Phase 0 active for all epochs.
    pub altair_fork_epoch: Epoch,
    /// Bellatrix fork version.
    pub bellatrix_fork_version: Version,
    /// Epoch at which the Bellatrix fork activates.
    ///
    /// `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) keeps Altair active (no Bellatrix).
    pub bellatrix_fork_epoch: Epoch,
    /// Capella fork version.
    pub capella_fork_version: Version,
    /// Epoch at which the Capella fork activates.
    ///
    /// `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) keeps Bellatrix active (no Capella).
    pub capella_fork_epoch: Epoch,
    /// Deneb fork version.
    pub deneb_fork_version: Version,
    /// Epoch at which the Deneb fork activates.
    ///
    /// `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) keeps Capella active (no Deneb).
    pub deneb_fork_epoch: Epoch,
    /// Electra fork version.
    pub electra_fork_version: Version,
    /// Epoch at which the Electra fork activates.
    ///
    /// `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) keeps Deneb active (no Electra).
    pub electra_fork_epoch: Epoch,
    /// Genesis validators root used in fork-digest computation.
    pub genesis_validators_root: Root,
}

impl ForkSchedule {
    /// Ascending lookup table of `(activation_epoch, previous_version, current_version,
    /// fork_activation_epoch)` for all non-genesis forks.
    ///
    /// Used by `fork_at_epoch`, `current_fork_version`, `next_fork_version`,
    /// and `next_fork_epoch` to avoid per-fork `if` chains.
    fn fork_table(&self) -> [(Epoch, Version, Version, Epoch); 5] {
        [
            (
                self.altair_fork_epoch,
                self.genesis_fork_version,
                self.altair_fork_version,
                self.altair_fork_epoch,
            ),
            (
                self.bellatrix_fork_epoch,
                self.altair_fork_version,
                self.bellatrix_fork_version,
                self.bellatrix_fork_epoch,
            ),
            (
                self.capella_fork_epoch,
                self.bellatrix_fork_version,
                self.capella_fork_version,
                self.capella_fork_epoch,
            ),
            (
                self.deneb_fork_epoch,
                self.capella_fork_version,
                self.deneb_fork_version,
                self.deneb_fork_epoch,
            ),
            (
                self.electra_fork_epoch,
                self.deneb_fork_version,
                self.electra_fork_version,
                self.electra_fork_epoch,
            ),
        ]
    }

    /// The `Fork` container active at `epoch`.
    ///
    /// Scans the fork table from highest to lowest activation epoch and
    /// returns the first entry whose `activation_epoch <= epoch`.
    pub fn fork_at_epoch(&self, epoch: Epoch) -> Fork {
        let table = self.fork_table();
        for &(activation, prev_version, curr_version, fork_epoch) in table.iter().rev() {
            if epoch >= activation {
                return Fork {
                    previous_version: prev_version,
                    current_version: curr_version,
                    epoch: fork_epoch,
                };
            }
        }
        // Phase 0: no fork has activated.
        Fork {
            previous_version: self.genesis_fork_version,
            current_version: self.genesis_fork_version,
            epoch: Epoch(0),
        }
    }

    /// The current fork version active at `epoch`.
    pub fn current_fork_version(&self, epoch: Epoch) -> Version {
        self.fork_at_epoch(epoch).current_version
    }

    /// The next fork version after the fork active at `epoch`.
    ///
    /// Returns the version of the next scheduled fork, or the current version
    /// when no further forks are known.
    pub fn next_fork_version(&self, epoch: Epoch) -> Version {
        let table = self.fork_table();
        for &(activation, _prev, curr_version, _fork_epoch) in table.iter() {
            if epoch < activation {
                return curr_version;
            }
        }
        // Already at or past the last known fork.
        self.electra_fork_version
    }

    /// The epoch at which the next fork after `epoch` activates.
    ///
    /// Returns `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`) when no further forks are scheduled.
    pub fn next_fork_epoch(&self, epoch: Epoch) -> Epoch {
        let table = self.fork_table();
        for &(activation, _prev, _curr, _fork_epoch) in table.iter() {
            if epoch < activation {
                return activation;
            }
        }
        Epoch(u64::MAX)
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
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
            deneb_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
            electra_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            genesis_validators_root: Root::default(),
        }
    }

    fn three_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(10),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(20),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
            deneb_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
            electra_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            genesis_validators_root: Root::default(),
        }
    }

    fn four_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(10),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(20),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(30),
            deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
            deneb_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
            electra_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
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

    // ── Three-fork tests ──────────────────────────────────────────────────────

    #[test]
    fn three_fork_phase0_range() {
        let sched = three_fork_schedule();
        for epoch_n in [0u64, 1, 9] {
            let fork = sched.fork_at_epoch(Epoch(epoch_n));
            assert_eq!(
                fork.current_version,
                Version::from_array([0x00, 0x00, 0x00, 0x00]),
                "epoch {epoch_n}: expected Phase 0"
            );
            assert_eq!(fork.epoch, Epoch(0));
        }
    }

    #[test]
    fn three_fork_altair_range() {
        let sched = three_fork_schedule();
        for epoch_n in [10u64, 11, 19] {
            let fork = sched.fork_at_epoch(Epoch(epoch_n));
            assert_eq!(
                fork.current_version,
                Version::from_array([0x01, 0x00, 0x00, 0x00]),
                "epoch {epoch_n}: expected Altair"
            );
            assert_eq!(
                fork.previous_version,
                Version::from_array([0x00, 0x00, 0x00, 0x00])
            );
            assert_eq!(fork.epoch, Epoch(10));
        }
    }

    #[test]
    fn three_fork_bellatrix_range() {
        let sched = three_fork_schedule();
        for epoch_n in [20u64, 21, 144896, u64::MAX - 1] {
            let fork = sched.fork_at_epoch(Epoch(epoch_n));
            assert_eq!(
                fork.current_version,
                Version::from_array([0x02, 0x00, 0x00, 0x00]),
                "epoch {epoch_n}: expected Bellatrix"
            );
            assert_eq!(
                fork.previous_version,
                Version::from_array([0x01, 0x00, 0x00, 0x00])
            );
            assert_eq!(fork.epoch, Epoch(20));
        }
    }

    #[test]
    fn next_fork_version_crosses() {
        let sched = three_fork_schedule();
        // In Phase 0, next fork is Altair.
        assert_eq!(
            sched.next_fork_version(Epoch(0)),
            Version::from_array([0x01, 0x00, 0x00, 0x00])
        );
        // In Altair, next fork is Bellatrix.
        assert_eq!(
            sched.next_fork_version(Epoch(10)),
            Version::from_array([0x02, 0x00, 0x00, 0x00])
        );
        // In Bellatrix, next fork is Capella (capella_fork_epoch = FAR_FUTURE_EPOCH in three_fork_schedule).
        assert_eq!(
            sched.next_fork_version(Epoch(20)),
            Version::from_array([0x03, 0x00, 0x00, 0x00])
        );
    }

    #[test]
    fn next_fork_epoch_crosses() {
        let sched = three_fork_schedule();
        assert_eq!(sched.next_fork_epoch(Epoch(0)), Epoch(10));
        assert_eq!(sched.next_fork_epoch(Epoch(9)), Epoch(10));
        assert_eq!(sched.next_fork_epoch(Epoch(10)), Epoch(20));
        assert_eq!(sched.next_fork_epoch(Epoch(19)), Epoch(20));
        // In Bellatrix (epoch 20), next fork = capella (FAR_FUTURE_EPOCH).
        assert_eq!(sched.next_fork_epoch(Epoch(20)), Epoch(u64::MAX));
        assert_eq!(sched.next_fork_epoch(Epoch(100)), Epoch(u64::MAX));
    }

    // ── Fork-digest tests ─────────────────────────────────────────────────────

    #[test]
    fn bellatrix_fork_digest_differs_from_altair() {
        let gvr = Root::default();
        let phase0_version = Version::from_array([0x00, 0x00, 0x00, 0x00]);
        let altair_version = Version::from_array([0x01, 0x00, 0x00, 0x00]);
        let bellatrix_version = Version::from_array([0x02, 0x00, 0x00, 0x00]);

        let phase0_digest = compute_fork_digest(phase0_version, &gvr);
        let altair_digest = compute_fork_digest(altair_version, &gvr);
        let bellatrix_digest = compute_fork_digest(bellatrix_version, &gvr);

        assert_ne!(
            bellatrix_digest, altair_digest,
            "Bellatrix digest must differ from Altair digest"
        );
        assert_ne!(
            bellatrix_digest, phase0_digest,
            "Bellatrix digest must differ from Phase0 digest"
        );
        assert_ne!(
            altair_digest, phase0_digest,
            "Altair digest must differ from Phase0 digest"
        );
    }

    #[test]
    fn enr_next_fork_at_bellatrix_boundary() {
        let sched = three_fork_schedule();
        // altair_fork_epoch = 10, bellatrix_fork_epoch = 20

        // One epoch before bellatrix: next_fork_version == bellatrix, next_fork_epoch == 20.
        let pre_bellatrix_epoch = Epoch(sched.bellatrix_fork_epoch.0 - 1);
        assert_eq!(
            sched.next_fork_version(pre_bellatrix_epoch),
            sched.bellatrix_fork_version,
            "one epoch before bellatrix: next_fork_version must be bellatrix_fork_version"
        );
        assert_eq!(
            sched.next_fork_epoch(pre_bellatrix_epoch),
            sched.bellatrix_fork_epoch,
            "one epoch before bellatrix: next_fork_epoch must be bellatrix_fork_epoch"
        );

        // At the bellatrix epoch and beyond: no further fork, next_fork_epoch == FAR_FUTURE.
        for epoch_n in [
            sched.bellatrix_fork_epoch.0,
            sched.bellatrix_fork_epoch.0 + 1,
            100,
            u64::MAX - 1,
        ] {
            assert_eq!(
                sched.next_fork_epoch(Epoch(epoch_n)),
                Epoch(u64::MAX),
                "epoch {epoch_n}: after last fork, next_fork_epoch must be FAR_FUTURE"
            );
        }
    }

    #[test]
    fn mainnet_bellatrix_fork_epoch_crossing() {
        // Validate the mainnet fork epoch values from BeaconSpec consts.
        use crate::eth_spec::BeaconSpec;
        use crate::eth_spec::MainnetBeaconSpec;
        let sched = ForkSchedule {
            genesis_fork_version: Version::from_array(MainnetBeaconSpec::GENESIS_FORK_VERSION),
            altair_fork_version: Version::from_array(MainnetBeaconSpec::ALTAIR_FORK_VERSION),
            altair_fork_epoch: Epoch(MainnetBeaconSpec::ALTAIR_FORK_EPOCH),
            bellatrix_fork_version: Version::from_array(MainnetBeaconSpec::BELLATRIX_FORK_VERSION),
            bellatrix_fork_epoch: Epoch(MainnetBeaconSpec::BELLATRIX_FORK_EPOCH),
            capella_fork_version: Version::from_array(MainnetBeaconSpec::CAPELLA_FORK_VERSION),
            capella_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH for test
            deneb_fork_version: Version::from_array(MainnetBeaconSpec::DENEB_FORK_VERSION),
            deneb_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH for test
            electra_fork_version: Version::from_array(MainnetBeaconSpec::ELECTRA_FORK_VERSION),
            electra_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH for test
            genesis_validators_root: Root::default(),
        };
        // At epoch 144_896, Bellatrix is active.
        let fork = sched.fork_at_epoch(Epoch(144_896));
        assert_eq!(
            fork.current_version,
            Version::from_array([0x02, 0x00, 0x00, 0x00])
        );
        // At epoch 144_895, Altair is still active.
        let fork = sched.fork_at_epoch(Epoch(144_895));
        assert_eq!(
            fork.current_version,
            Version::from_array([0x01, 0x00, 0x00, 0x00])
        );
    }

    #[test]
    fn capella_fork_digest_differs_from_bellatrix() {
        let gvr = Root::default();
        let bellatrix_version = Version::from_array([0x02, 0x00, 0x00, 0x00]);
        let capella_version = Version::from_array([0x03, 0x00, 0x00, 0x00]);

        let bellatrix_digest = compute_fork_digest(bellatrix_version, &gvr);
        let capella_digest = compute_fork_digest(capella_version, &gvr);

        assert_ne!(
            capella_digest, bellatrix_digest,
            "Capella digest must differ from Bellatrix digest"
        );
    }

    #[test]
    fn four_fork_capella_range() {
        let sched = four_fork_schedule();
        for epoch_n in [30u64, 31, 194048, u64::MAX - 1] {
            let fork = sched.fork_at_epoch(Epoch(epoch_n));
            assert_eq!(
                fork.current_version,
                Version::from_array([0x03, 0x00, 0x00, 0x00]),
                "epoch {epoch_n}: expected Capella"
            );
            assert_eq!(
                fork.previous_version,
                Version::from_array([0x02, 0x00, 0x00, 0x00])
            );
            assert_eq!(fork.epoch, Epoch(30));
        }
    }

    #[test]
    fn four_fork_next_fork_epoch_after_capella() {
        let sched = four_fork_schedule();
        // After capella, no further fork: next_fork_epoch == FAR_FUTURE_EPOCH.
        assert_eq!(sched.next_fork_epoch(Epoch(30)), Epoch(u64::MAX));
        assert_eq!(sched.next_fork_epoch(Epoch(100)), Epoch(u64::MAX));
    }

    #[test]
    fn domain_bls_to_execution_change_value() {
        // Per specs/capella/beacon-chain.md, DOMAIN_BLS_TO_EXECUTION_CHANGE = 0x0A000000.
        assert_eq!(
            super::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            [0x0A, 0x00, 0x00, 0x00]
        );
    }
}
