//! `process_eth1_data` per `specs/phase0/beacon-chain.md:1926-1956`.

use pharos_types::{EthSpec, views::BeaconBlockBodyView};

use crate::error::StateTransitionError;
use crate::phase0::state_write::BeaconStateWrite;

/// `process_eth1_data` per `specs/phase0/beacon-chain.md:1926-1956`.
pub fn process_eth1_data<E: EthSpec>(
    state: &mut E::BeaconState,
    body: &E::Phase0BeaconBlockBody,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView,
{
    let eth1_data = body.eth1_data().clone();
    state.push_eth1_data_vote(eth1_data.clone())?;

    // Set eth1_data when a vote crosses the majority threshold.
    // Threshold: count * 2 > EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH.
    let count = state.eth1_data_votes_count_matching(&eth1_data);
    let threshold = E::EPOCHS_PER_ETH1_VOTING_PERIOD * E::SLOTS_PER_EPOCH;
    if (count as u64) * 2 > threshold {
        state.set_eth1_data(eth1_data);
    }

    Ok(())
}
