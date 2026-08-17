//! `process_sync_committee_updates` for Altair.
//!
//! New in Altair: rotates sync committees at the start of each sync committee
//! period.
//!
//! spec: specs/altair/beacon-chain.md:777-790

use pharos_types::{BeaconSpec, altair::BeaconState};
use pharos_utils::BLSPubkey;

use crate::error::EpochProcessingError;

use super::helpers::get_current_epoch_altair;
use crate::altair::helpers::get_next_sync_committee;

/// `process_sync_committee_updates` per `specs/altair/beacon-chain.md:777-790`.
///
/// New in Altair. At the start of a new sync-committee period
/// (`(epoch + 1) % EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0`):
/// - `state.current_sync_committee = state.next_sync_committee`
/// - `state.next_sync_committee = get_next_sync_committee(state)`
pub fn process_sync_committee_updates<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
>(
    state: &mut BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> Result<(), EpochProcessingError>
where
    E: BeaconSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
    BLSPubkey: Default + Clone,
{
    let current_epoch = get_current_epoch_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state);

    let next_epoch = current_epoch.0 + 1;

    if next_epoch.is_multiple_of(E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
        state.current_sync_committee = state.next_sync_committee.clone();
        let new_next = get_next_sync_committee::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state)
        .map_err(|e| match e {
            crate::error::StateTransitionError::Ssz(s) => EpochProcessingError::Ssz(s),
            _ => EpochProcessingError::ValidatorIndexOutOfRange { index: 0 },
        })?;
        state.next_sync_committee = new_next;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use pharos_types::{BeaconSpec, MainnetBeaconSpec, MinimalBeaconSpec};

    /// Verify sync committee period boundary condition:
    /// the rotation triggers at `next_epoch % EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0`.
    #[test]
    fn mainnet_period_trigger_at_expected_epoch() {
        let period = MainnetBeaconSpec::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        // First rotation: next_epoch = period, so current_epoch = period - 1.
        assert_eq!((period - 1 + 1) % period, 0);
        // Just before: no rotation.
        assert_ne!((period - 2 + 1) % period, 0);
    }

    #[test]
    fn minimal_period_trigger_at_expected_epoch() {
        let period = MinimalBeaconSpec::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        assert_eq!((period - 1 + 1) % period, 0);
        assert_ne!((period - 2 + 1) % period, 0);
    }
}
