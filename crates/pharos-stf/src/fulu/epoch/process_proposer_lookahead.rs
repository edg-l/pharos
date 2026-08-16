//! `process_proposer_lookahead` for Fulu (EIP-7917).
//!
//! Per `specs/fulu/beacon-chain.md` "Epoch processing" → modified `process_epoch`
//! adds `process_proposer_lookahead` at the end.
//!
//! The `proposer_lookahead` vector spans `(MIN_SEED_LOOKAHEAD + 1)` epochs of
//! proposer indices (`LOOKAHEAD_WINDOW` entries). At each epoch boundary the
//! window slides forward by `SLOTS_PER_EPOCH`: the leading
//! `LOOKAHEAD_WINDOW - SLOTS_PER_EPOCH` entries shift left, and the freed tail
//! is filled with the proposer indices for
//! `current_epoch + MIN_SEED_LOOKAHEAD + 1` (the newly-determinable epoch).

use pharos_ssz::{SszSequence, SszVector};
use pharos_types::{
    BeaconSpec,
    fulu::BeaconState as FuluBeaconState,
    phase0::{Epoch, ValidatorIndex},
};

use crate::error::EpochProcessingError;
use crate::fulu::helpers::get_beacon_proposer_indices;
use crate::phase0::accessors::compute_epoch_at_slot;

/// `process_proposer_lookahead` per `specs/fulu/beacon-chain.md` (new in
/// EIP-7917).
///
/// Slides the `proposer_lookahead` window forward by one epoch:
/// `proposer_lookahead[..last_epoch_start] = proposer_lookahead[SLOTS_PER_EPOCH..]`
/// then fills `proposer_lookahead[last_epoch_start..]` with
/// `get_beacon_proposer_indices(state, current_epoch + MIN_SEED_LOOKAHEAD + 1)`.
///
/// The proposer-index election reads validators / randao via `BeaconStateView`,
/// which requires the enum-wrapped `E::BeaconState`. Those fields are byte
/// identical between the inner fulu state and its enum wrapper, so the election
/// runs on a cheap (tree-backed, structurally shared) clone wrapped via
/// `E::fulu_into_state`; the result is written back into the inner state's
/// `proposer_lookahead`.
#[allow(clippy::type_complexity)]
pub fn process_proposer_lookahead<
    E,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    const LOOKAHEAD_WINDOW: u64,
>(
    inner: &mut FuluBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >,
) -> Result<(), EpochProcessingError>
where
    E: BeaconSpec<
        FuluBeaconState = FuluBeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
            LOOKAHEAD_WINDOW,
        >,
    >,
{
    let current_epoch = compute_epoch_at_slot(inner.slot, E::SLOTS_PER_EPOCH);
    let lookahead_epoch = Epoch(current_epoch.0 + E::MIN_SEED_LOOKAHEAD + 1);

    // Proposer indices for the newly-determinable epoch. The election reads only
    // fields preserved by the enum wrap, so a cheap clone is sufficient.
    let view_state = E::fulu_into_state(inner.clone());
    let new_tail: Vec<ValidatorIndex> =
        get_beacon_proposer_indices::<E>(&view_state, lookahead_epoch);

    // Shift the window left by SLOTS_PER_EPOCH: the existing tail becomes the new
    // head. `proposer_lookahead[..last_epoch_start] = proposer_lookahead[SLOTS_PER_EPOCH..]`.
    let mut next: Vec<ValidatorIndex> = inner
        .proposer_lookahead
        .iter()
        .skip(E::SLOTS_PER_EPOCH as usize)
        .copied()
        .collect();
    next.extend(new_tail);

    debug_assert_eq!(
        next.len(),
        LOOKAHEAD_WINDOW as usize,
        "lookahead window must remain LOOKAHEAD_WINDOW entries"
    );

    inner.proposer_lookahead = SszVector::from_vec(next).map_err(EpochProcessingError::Ssz)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fulu::test_support::build_test_fulu_minimal_state;
    use crate::phase0::accessors::get_current_epoch;
    use pharos_types::eth_spec::MinimalBeaconSpec;

    #[test]
    fn window_advances_and_new_tail_matches() {
        let mut inner = build_test_fulu_minimal_state();
        // Seed a non-zero leading window so the shift is observable.
        let seeded: Vec<_> = (0..MinimalBeaconSpec::LOOKAHEAD_WINDOW)
            .map(|i| pharos_types::phase0::ValidatorIndex(i % 64))
            .collect();
        inner.proposer_lookahead = SszVector::from_vec(seeded).expect("seed lookahead");
        let before: Vec<_> = inner.proposer_lookahead.iter().copied().collect();

        // Expected new tail from the un-shifted state.
        let view_state = MinimalBeaconSpec::fulu_into_state(inner.clone());
        let current_epoch = get_current_epoch::<MinimalBeaconSpec>(&view_state);
        let lookahead_epoch = Epoch(current_epoch.0 + MinimalBeaconSpec::MIN_SEED_LOOKAHEAD + 1);
        let expected_tail =
            get_beacon_proposer_indices::<MinimalBeaconSpec>(&view_state, lookahead_epoch);

        process_proposer_lookahead::<MinimalBeaconSpec, _, _, _, _, _, _, _, _, _, _, _, _, _, _>(
            &mut inner,
        )
        .expect("process_proposer_lookahead");

        let after: Vec<_> = inner.proposer_lookahead.iter().copied().collect();
        let spe = MinimalBeaconSpec::SLOTS_PER_EPOCH as usize;
        let win = MinimalBeaconSpec::LOOKAHEAD_WINDOW as usize;

        // The leading (win - spe) entries are the old tail (window slid by spe).
        assert_eq!(after[..win - spe], before[spe..]);
        // The freed tail equals get_beacon_proposer_indices for the lookahead epoch.
        assert_eq!(after[win - spe..], expected_tail[..]);
    }
}
