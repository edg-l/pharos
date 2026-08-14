//! `process_block_header` per `specs/phase0/beacon-chain.md:1886-1910`.

use pharos_ssz::TreeHash;
use pharos_types::{BeaconStateView, EthSpec, phase0::BeaconBlockHeader, views::BeaconBlockView};

use crate::error::{BlockHeaderInvalidReason, StateTransitionError};
use crate::phase0::{accessors::get_beacon_proposer_index, state_write::BeaconStateWrite};

/// `process_block_header` per `specs/phase0/beacon-chain.md:1886-1910`.
///
/// Block signature is NOT verified here — the outer `state_transition` flow
/// is responsible per the spec NOTE at line 1886.
pub fn process_block_header<E: EthSpec>(
    state: &mut E::BeaconState,
    block: &E::BeaconBlock,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
    E::BeaconBlock: BeaconBlockView,
    <E::BeaconBlock as BeaconBlockView>::Body: TreeHash,
{
    // Verify slot matches state.
    if block.slot() != state.slot() {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::SlotMismatch,
        });
    }

    // Verify block is newer than latest block header.
    if block.slot() <= state.latest_block_header().slot {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::SlotNotLater,
        });
    }

    // Verify proposer index.
    let proposer_index = get_beacon_proposer_index::<E>(state);
    if block.proposer_index() != proposer_index {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ProposerIndexMismatch,
        });
    }

    // Verify parent root.
    let expected_parent_root = state.latest_block_header().tree_hash_root();
    if block.parent_root() != expected_parent_root {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ParentRootMismatch,
        });
    }

    // Cache current block as the new latest block header.
    // state_root is zeroed here and filled in by the next process_slot call.
    let body_root = block.body().tree_hash_root();
    state.set_latest_block_header(BeaconBlockHeader {
        slot: block.slot(),
        proposer_index: block.proposer_index(),
        parent_root: block.parent_root(),
        state_root: pharos_types::phase0::Root::default(),
        body_root,
    });

    // Verify proposer is not slashed.
    let proposer_slashed = state
        .validators()
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
