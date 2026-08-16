//! Fulu proposer-lookahead helpers (EIP-7917).
//!
//! Per `specs/fulu/beacon-chain.md` "Beacon state accessors" → modified
//! `get_beacon_proposer_index` + new `compute_proposer_indices` /
//! `get_beacon_proposer_indices`.
//!
//! EIP-7917 makes the proposer schedule deterministic for the whole lookahead
//! window: `compute_proposer_indices` elects one proposer per slot of an epoch,
//! `get_beacon_proposer_indices` is the seed-deriving wrapper, and the modified
//! `get_beacon_proposer_index` READS the precomputed
//! `state.proposer_lookahead[state.slot % SLOTS_PER_EPOCH]` rather than
//! re-electing on demand. This is the single source of truth for proposer
//! selection in Fulu (RI-6 — the M12 16-bit-proposer gotcha generalized; every
//! proposer-selection caller must route through `get_beacon_proposer_index` on
//! fulu states).
//!
//! The per-slot proposer election itself is unchanged from electra
//! (`compute_proposer_index_electra`, the 16-bit-random EIP-7251 variant); fulu
//! only changes WHEN it runs (once per epoch into the lookahead) and WHERE the
//! result is read from.

use pharos_types::{
    BeaconSpec,
    fulu::BeaconState as FuluBeaconState,
    phase0::{Epoch, ValidatorIndex},
};
use pharos_utils::{Bytes4, Hash256};

use crate::electra::helpers::compute_proposer_index_electra;
use crate::phase0::accessors::{
    compute_start_slot_at_epoch, get_active_validator_indices, get_seed,
};
use crate::phase0::helpers::{DOMAIN_BEACON_PROPOSER, uint_to_bytes};

/// `compute_proposer_indices` per `specs/fulu/beacon-chain.md` (new in EIP-7917).
///
/// Elects one proposer index per slot of `epoch`. For each slot `start_slot + i`
/// the per-slot seed is `hash(seed ++ uint_to_bytes(Slot(start_slot + i)))` and
/// the proposer is `compute_proposer_index_electra(state, indices, seed_i)`.
///
/// Returns a `Vec<ValidatorIndex>` of length `SLOTS_PER_EPOCH` (one entry per
/// slot in the epoch, in slot order). This is the 4-parameter spec form; it is
/// NOT re-exported under a 2-parameter name — callers use
/// `get_beacon_proposer_indices`.
pub fn compute_proposer_indices<E: BeaconSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
    seed: &Hash256,
    indices: &[ValidatorIndex],
) -> Vec<ValidatorIndex> {
    let start_slot = compute_start_slot_at_epoch(epoch, E::SLOTS_PER_EPOCH);
    (0..E::SLOTS_PER_EPOCH)
        .map(|i| {
            // seed_i = hash(seed ++ uint_to_bytes(Slot(start_slot + i))).
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(seed.as_slice());
            input[32..].copy_from_slice(&uint_to_bytes(start_slot.0 + i));
            let seed_i = pharos_utils::hash::hash(&input);
            compute_proposer_index_electra::<E>(state, indices, &seed_i)
        })
        .collect()
}

/// `get_beacon_proposer_indices` per `specs/fulu/beacon-chain.md` (new in EIP-7917).
///
/// 2-parameter wrapper: derives the active-validator indices and the
/// `DOMAIN_BEACON_PROPOSER` seed for `epoch`, then delegates to
/// `compute_proposer_indices`.
pub fn get_beacon_proposer_indices<E: BeaconSpec>(
    state: &E::BeaconState,
    epoch: Epoch,
) -> Vec<ValidatorIndex> {
    let indices = get_active_validator_indices::<E>(state, epoch);
    let seed = get_seed::<E>(state, epoch, Bytes4::from_array(DOMAIN_BEACON_PROPOSER));
    compute_proposer_indices::<E>(state, epoch, &seed, &indices)
}

/// `get_beacon_proposer_index` per `specs/fulu/beacon-chain.md` (modified in
/// EIP-7917).
///
/// Reads the precomputed lookahead instead of electing on demand:
/// `state.proposer_lookahead[state.slot % SLOTS_PER_EPOCH]`. Generic over the
/// concrete fulu `BeaconState` const-generic shape (the `proposer_lookahead`
/// field is fulu-only and not on the `BeaconStateView` trait).
#[allow(clippy::type_complexity)]
pub fn get_beacon_proposer_index<
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
    E: BeaconSpec,
>(
    state: &FuluBeaconState<
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
) -> ValidatorIndex {
    use pharos_ssz::SszSequence;

    let idx = (state.slot.0 % E::SLOTS_PER_EPOCH) as usize;
    state
        .proposer_lookahead
        .get(idx)
        .copied()
        .unwrap_or(ValidatorIndex(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electra::helpers::get_beacon_proposer_index_electra;
    use crate::fulu::{fulu_state_to_electra, test_support::build_test_fulu_minimal_state};
    use crate::phase0::accessors::{get_active_validator_indices, get_current_epoch, get_seed};
    use pharos_types::eth_spec::MinimalBeaconSpec;
    use pharos_types::phase0::Slot;

    /// `compute_proposer_indices` for the current epoch, evaluated at slot `s`,
    /// MUST equal `get_beacon_proposer_index_electra` run on the projected
    /// electra state whose `slot` is set to `s` (same validators, same randao,
    /// same fork). This proves the precomputed lookahead is consistent with the
    /// pre-EIP-7917 on-demand election.
    #[test]
    fn lookahead_matches_electra_on_demand_election() {
        let inner = build_test_fulu_minimal_state();
        let view_state = MinimalBeaconSpec::fulu_into_state(inner.clone());
        let current_epoch = get_current_epoch::<MinimalBeaconSpec>(&view_state);

        let indices = get_active_validator_indices::<MinimalBeaconSpec>(&view_state, current_epoch);
        let seed = get_seed::<MinimalBeaconSpec>(
            &view_state,
            current_epoch,
            Bytes4::from_array(DOMAIN_BEACON_PROPOSER),
        );
        let lookahead = compute_proposer_indices::<MinimalBeaconSpec>(
            &view_state,
            current_epoch,
            &seed,
            &indices,
        );

        let start_slot =
            compute_start_slot_at_epoch(current_epoch, MinimalBeaconSpec::SLOTS_PER_EPOCH);
        assert_eq!(lookahead.len(), MinimalBeaconSpec::SLOTS_PER_EPOCH as usize);
        for (i, &elected) in lookahead.iter().enumerate() {
            // Project to electra and set the slot to start_slot + i so the
            // electra on-demand election uses the same per-slot seed.
            let mut electra = fulu_state_to_electra(&inner);
            electra.slot = Slot(start_slot.0 + i as u64);
            let on_demand = get_beacon_proposer_index_electra::<MinimalBeaconSpec>(
                &MinimalBeaconSpec::electra_into_state(electra),
            );
            assert_eq!(
                elected,
                on_demand,
                "lookahead[{i}] must match electra on-demand election for slot {}",
                start_slot.0 + i as u64
            );
        }
    }
}
