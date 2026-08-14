//! `Deltas` container used by rewards conformance fixtures.
//!
//! Each `*_deltas.ssz_snappy` fixture encodes a pair of reward/penalty lists,
//! one entry per validator, as `Deltas<VALIDATOR_REGISTRY_LIMIT>`.
//!
//! Per `specs/phase0/beacon-chain.md` "Rewards and penalties" section; the
//! container is implicit in the pyspec but explicit in the test-vector format.

use pharos_ssz::{Decode, Encode, SszList, TreeHash};
use pharos_utils::Gwei;

/// Reward / penalty pair for one epoch-processing delta function.
///
/// Both lists have exactly `len(state.validators)` entries in the fixtures.
/// The generic const `N` is `VALIDATOR_REGISTRY_LIMIT`, which ensures the
/// `SszList` capacity matches the encoding used by the test-vector generator.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct Deltas<const N: u64> {
    /// Per-validator reward amounts in Gwei.
    pub rewards: SszList<Gwei, N>,
    /// Per-validator penalty amounts in Gwei.
    pub penalties: SszList<Gwei, N>,
}

impl<const N: u64> Default for Deltas<N>
where
    Gwei: Default + Clone,
{
    fn default() -> Self {
        Self {
            rewards: SszList::default(),
            penalties: SszList::default(),
        }
    }
}
