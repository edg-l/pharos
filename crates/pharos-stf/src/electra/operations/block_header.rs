//! `process_block_header` for Electra.
//!
//! Per `specs/phase0/beacon-chain.md:1886-1910` — the algorithm is unchanged
//! since phase0, but the proposer index MUST be computed with the Electra
//! effective-balance-weighted shuffle (`get_beacon_proposer_index_electra`,
//! 16-bit random value + `MAX_EFFECTIVE_BALANCE_ELECTRA`). Delegating to the
//! deneb/altair impl would compute the pre-electra 8-bit proposer index and
//! fail `block_header` / proposer-dependent fixtures.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    electra::BeaconState,
    phase0::{BeaconBlockHeader, Root, Slot, ValidatorIndex},
};

use crate::electra::helpers::get_beacon_proposer_index_electra;
use crate::error::{BlockHeaderInvalidReason, StateTransitionError};

/// `process_block_header` for Electra.
///
/// Accepts the block's pre-extracted header fields (`slot`, `proposer_index`,
/// `parent_root`) and `body_root`. The block signature is NOT verified here per
/// the spec NOTE at phase0 line 1886; the outer `state_transition` flow owns it.
#[allow(clippy::too_many_arguments)]
pub fn process_block_header_electra<
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
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    block_slot: Slot,
    block_proposer_index: ValidatorIndex,
    block_parent_root: Root,
    block_body_root: Root,
    proposer_override: Option<ValidatorIndex>,
) -> Result<(), StateTransitionError>
where
    E: BeaconSpec<
        ElectraBeaconState = BeaconState<
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
        >,
    >,
{
    use pharos_ssz::TreeHash;

    // Verify slot matches state.
    if block_slot != state.slot {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::SlotMismatch,
        });
    }

    // Verify block is newer than latest block header.
    if block_slot <= state.latest_block_header.slot {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::SlotNotLater,
        });
    }

    // Verify proposer index. Fulu (EIP-7917) passes the precomputed lookahead
    // proposer via `proposer_override`; electra re-elects on demand.
    let proposer_index = match proposer_override {
        Some(p) => p,
        None => get_beacon_proposer_index_electra::<E>(&E::electra_into_state(state.clone())),
    };
    if block_proposer_index != proposer_index {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ProposerIndexMismatch,
        });
    }

    // Verify parent root.
    let expected_parent_root = state.latest_block_header.tree_hash_root();
    if block_parent_root != expected_parent_root {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ParentRootMismatch,
        });
    }

    // Cache current block as the new latest block header.
    // state_root is zeroed here and filled in by the next process_slot call.
    state.latest_block_header = BeaconBlockHeader {
        slot: block_slot,
        proposer_index: block_proposer_index,
        parent_root: block_parent_root,
        state_root: Root::default(),
        body_root: block_body_root,
    };

    // Verify proposer is not slashed.
    let proposer_slashed = state
        .validators
        .get(proposer_index.0 as usize)
        .map(|v| v.slashed)
        .unwrap_or(false);
    if proposer_slashed {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ProposerSlashed,
        });
    }

    Ok(())
}
