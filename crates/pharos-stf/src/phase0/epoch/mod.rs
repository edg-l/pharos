//! Phase 0 epoch processing.
//!
//! `process_epoch` calls 10 sub-routines in the order specified by
//! `specs/phase0/beacon-chain.md:1422-1432`. Each sub-routine lives in its
//! own file and is re-exported so the conformance harness can drive them
//! individually.

pub mod final_updates;
pub mod helpers;
pub mod justification_and_finalization;
pub mod registry_updates;
pub mod rewards_and_penalties;
pub mod slashings;

// Re-export each sub-routine for individual conformance dispatch (Task 4.8).
pub use final_updates::{
    process_effective_balance_updates, process_eth1_data_reset, process_historical_roots_update,
    process_participation_record_updates, process_randao_mixes_reset, process_slashings_reset,
};
pub use justification_and_finalization::process_justification_and_finalization;
pub use registry_updates::process_registry_updates;
pub use rewards_and_penalties::{
    get_head_deltas, get_inactivity_penalty_deltas, get_inclusion_delay_deltas, get_source_deltas,
    get_target_deltas, process_rewards_and_penalties,
};
pub use slashings::process_slashings;

use pharos_types::{BeaconSpec, phase0::Attestation, views::BeaconBlockBodyView};

use crate::error::EpochProcessingError;
use crate::phase0::state_write::BeaconStateWrite;

/// `process_epoch` per `specs/phase0/beacon-chain.md:1422-1432`.
///
/// Calls the 10 sub-routines in spec order.
pub fn process_epoch<E: BeaconSpec>(state: &mut E::BeaconState) -> Result<(), EpochProcessingError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    process_justification_and_finalization::<E>(state)?;
    process_rewards_and_penalties::<E>(state)?;
    process_registry_updates::<E>(state)?;
    process_slashings::<E>(state)?;
    process_eth1_data_reset::<E>(state)?;
    process_effective_balance_updates::<E>(state)?;
    process_slashings_reset::<E>(state)?;
    process_randao_mixes_reset::<E>(state)?;
    process_historical_roots_update::<E>(state)?;
    process_participation_record_updates::<E>(state)?;
    Ok(())
}
