//! `process_randao` per `specs/phase0/beacon-chain.md:1912-1924`.

use pharos_types::{BeaconStateView, EthSpec, views::BeaconBlockBodyView};

use crate::error::StateTransitionError;
use crate::phase0::{
    accessors::{
        compute_signing_root, get_beacon_proposer_index, get_current_epoch, get_domain,
        get_randao_mix,
    },
    helpers::{DOMAIN_RANDAO, xor},
    state_write::BeaconStateWrite,
};

/// `process_randao` per `specs/phase0/beacon-chain.md:1912-1924`.
pub fn process_randao<E: EthSpec>(
    state: &mut E::BeaconState,
    body: &E::BeaconBlockBody,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
    E::BeaconBlockBody: BeaconBlockBodyView,
{
    let epoch = get_current_epoch::<E>(state);

    if verify_signatures {
        let proposer_index = get_beacon_proposer_index::<E>(state);
        let proposer_pubkey = state
            .validators()
            .get(proposer_index.0 as usize)
            .ok_or(StateTransitionError::InvalidRandaoReveal)?
            .pubkey;

        let domain = get_domain::<E>(state, DOMAIN_RANDAO, Some(epoch));
        let signing_root = compute_signing_root(&epoch, domain);

        let valid = pharos_utils::bls::verify(
            &proposer_pubkey,
            signing_root.as_slice(),
            body.randao_reveal(),
        )
        .unwrap_or(false);
        if !valid {
            return Err(StateTransitionError::InvalidRandaoReveal);
        }
    }

    // Mix in RANDAO reveal: xor current mix with hash(randao_reveal).
    let prev_mix = get_randao_mix::<E>(state, epoch);
    let reveal_hash = pharos_utils::hash::hash(body.randao_reveal().as_slice());
    let new_mix = xor(&prev_mix, &reveal_hash);
    let mix_idx = (epoch.0 % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    state.set_randao_mix(mix_idx, new_mix)?;

    Ok(())
}
