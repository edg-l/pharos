//! `process_participation_flag_updates` for Altair.
//!
//! New in Altair: rotates participation flags at epoch boundaries.
//!
//! spec: specs/altair/beacon-chain.md:765-775

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::{BeaconState, constants::ParticipationFlags},
};

use crate::error::EpochProcessingError;

/// `process_participation_flag_updates` per `specs/altair/beacon-chain.md:765-775`.
///
/// New in Altair. At each epoch boundary:
/// - `state.previous_epoch_participation = state.current_epoch_participation`
/// - `state.current_epoch_participation` is reset to a zero-filled list of
///   length `len(state.validators)`.
pub fn process_participation_flag_updates<
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
{
    // Rotate: previous <- current.
    state.previous_epoch_participation = state.current_epoch_participation.clone();

    // Zero-fill current for the new epoch (length = number of validators).
    let n = state.validators.len();
    let zeroes: Vec<ParticipationFlags> = vec![0u8; n];
    state.current_epoch_participation =
        pharos_ssz::SszList::from_vec(zeroes).map_err(EpochProcessingError::Ssz)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use pharos_ssz::SszSequence;
    use pharos_types::{
        MainnetBeaconSpec,
        altair::{MainnetBeaconState, constants::ParticipationFlags},
        phase0::Validator,
    };

    use super::*;

    /// Helper: push a default validator into a mainnet altair state.
    fn push_validator(state: &mut MainnetBeaconState, flags: ParticipationFlags) {
        state.validators = state
            .validators
            .with_push(Validator::default())
            .expect("push_validator");
        state.current_epoch_participation = state
            .current_epoch_participation
            .with_push(flags)
            .expect("push current");
        state.previous_epoch_participation = state
            .previous_epoch_participation
            .with_push(0u8)
            .expect("push previous");
        state.inactivity_scores = state
            .inactivity_scores
            .with_push(0u64)
            .expect("push inactivity");
        state.balances = state
            .balances
            .with_push(pharos_utils::Gwei(0))
            .expect("push balance");
    }

    #[test]
    fn previous_becomes_current_and_current_zeroed() {
        let mut state = MainnetBeaconState::default();
        push_validator(&mut state, 0b0000_0111); // all three flags set
        push_validator(&mut state, 0b0000_0001); // only TIMELY_SOURCE

        process_participation_flag_updates::<
            8192,
            16777216,
            2048,
            1099511627776,
            65536,
            8192,
            4,
            512,
            MainnetBeaconSpec,
        >(&mut state)
        .expect("process_participation_flag_updates");

        // previous should now hold what current had.
        assert_eq!(
            state.previous_epoch_participation.as_slice(),
            &[0b0000_0111u8, 0b0000_0001u8]
        );
        // current should be zeroed.
        assert_eq!(state.current_epoch_participation.as_slice(), &[0u8, 0u8]);
    }

    #[test]
    fn current_length_matches_validators() {
        let mut state = MainnetBeaconState::default();
        for _ in 0..5 {
            push_validator(&mut state, 0u8);
        }

        process_participation_flag_updates::<
            8192,
            16777216,
            2048,
            1099511627776,
            65536,
            8192,
            4,
            512,
            MainnetBeaconSpec,
        >(&mut state)
        .expect("process_participation_flag_updates");

        assert_eq!(state.current_epoch_participation.len(), 5);
        assert!(state.current_epoch_participation.iter().all(|&f| f == 0u8));
    }
}
