//! `process_historical_roots_update` for Altair.
//!
//! Identical to phase0; operates on the concrete altair `BeaconState`.
//!
//! spec: specs/phase0/beacon-chain.md:1854-1865 (unchanged in Altair)

use pharos_ssz::{SszSequence, SszVector, TreeHash};
use pharos_types::{
    EthSpec,
    altair::BeaconState,
    phase0::{HistoricalBatch, Root},
};

use crate::error::EpochProcessingError;

use super::helpers::get_current_epoch_altair;

/// `process_historical_roots_update` per `specs/phase0/beacon-chain.md:1854-1865`.
///
/// Altair: identical to phase0. Appends the Merkle root of a `HistoricalBatch`
/// every `SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH` epochs.
pub fn process_historical_roots_update<
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
    E: EthSpec<
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
    let next_epoch = get_current_epoch_altair::<
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
    .0 + 1;
    let epochs_per_period = E::SLOTS_PER_HISTORICAL_ROOT / E::SLOTS_PER_EPOCH;
    if next_epoch % epochs_per_period == 0 {
        let historical_root = compute_historical_batch_root_altair::<
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
        state.historical_roots = state
            .historical_roots
            .with_push(historical_root)
            .map_err(EpochProcessingError::Ssz)?;
    }
    Ok(())
}

/// Compute `hash_tree_root(HistoricalBatch)` from the altair state's vectors.
///
/// `HistoricalBatch` is generic over `SLOTS_PER_HISTORICAL_ROOT`. We dispatch
/// to concrete branches (8192 mainnet, 64 minimal) to avoid `generic_const_exprs`.
/// If a future preset adds a new `SLOTS_PER_HISTORICAL_ROOT`, add a branch here.
fn compute_historical_batch_root_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: EthSpec,
>(
    state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> Root {
    let block_roots_slice = state.block_roots.as_slice();
    let state_roots_slice = state.state_roots.as_slice();

    match E::SLOTS_PER_HISTORICAL_ROOT {
        8192 => {
            let block_roots: SszVector<Root, 8192> =
                SszVector::from_vec(block_roots_slice.to_vec())
                    .expect("block_roots length matches");
            let state_roots: SszVector<Root, 8192> =
                SszVector::from_vec(state_roots_slice.to_vec())
                    .expect("state_roots length matches");
            HistoricalBatch::<8192> {
                block_roots,
                state_roots,
            }
            .tree_hash_root()
        }
        64 => {
            let block_roots: SszVector<Root, 64> = SszVector::from_vec(block_roots_slice.to_vec())
                .expect("block_roots length matches");
            let state_roots: SszVector<Root, 64> = SszVector::from_vec(state_roots_slice.to_vec())
                .expect("state_roots length matches");
            HistoricalBatch::<64> {
                block_roots,
                state_roots,
            }
            .tree_hash_root()
        }
        n => unreachable!(
            "SLOTS_PER_HISTORICAL_ROOT={n}: no HistoricalBatch branch; add one to compute_historical_batch_root_altair"
        ),
    }
}
