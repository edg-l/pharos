//! `process_block` and `process_operations` for Altair.
//!
//! Per `specs/altair/beacon-chain.md:492-506` (process_block) and the
//! modified `process_operations` which adds `process_sync_aggregate`.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    altair::{BeaconBlock, BeaconBlockBody, BeaconState},
    phase0::{Attestation, AttesterSlashing, Deposit},
};

use crate::altair::operations::{
    process_attestation, process_attester_slashing, process_deposit, process_proposer_slashing,
    process_sync_aggregate, process_voluntary_exit,
};
use crate::error::StateTransitionError;

/// `process_block` per `specs/altair/beacon-chain.md:492-506`.
///
/// Sequence (spec lines 493-500):
/// 1. `process_block_header`
/// 2. `process_randao`
/// 3. `process_eth1_data`
/// 4. `process_operations` (modified)
/// 5. `process_sync_aggregate` (new)
pub fn process_block<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
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
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
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
            AltairBeaconBlock = BeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
        >,
    BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    E::AltairBeaconState: pharos_ssz::TreeHash,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView,
    pharos_utils::BLSPubkey: Default + Clone,
{
    let body = &block.body;

    // Step 1: process_block_header
    process_block_header_altair::<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, block)?;

    // Step 2: process_randao
    process_randao_altair::<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, body, verify_signatures)?;

    // Step 3: process_eth1_data
    process_eth1_data_altair::<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, body)?;

    // Step 4: process_operations
    process_operations::<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, body, verify_signatures)?;

    // Step 5: process_sync_aggregate (new in Altair)
    process_sync_aggregate::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(state, &body.sync_aggregate, verify_signatures)?;

    Ok(())
}

/// `process_operations` (modified in Altair) per `specs/altair/beacon-chain.md:492-506`.
///
/// Exposed as `pub` so Bellatrix can reuse steps 3–4 while interleaving
/// `process_execution_payload` between `process_block_header` and
/// `process_randao` (spec `bellatrix/beacon-chain.md:362-364`).
///
/// The `BeaconBlockBodyView` bound on the altair body constrains
/// `MAX_VALIDATORS_PER_COMMITTEE = 2048` and `DEPOSIT_PROOF_LENGTH = 33` (the
/// only values used by all mainnet and minimal presets), so the per-op
/// processors that take `&Attestation<2048>` / `&Deposit<33>` accept the items.
pub fn process_operations<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
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
    BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    use pharos_types::views::BeaconBlockBodyView as _;

    // Verify deposit count.
    let expected_deposits = E::MAX_DEPOSITS.min(
        state
            .eth1_data
            .deposit_count
            .saturating_sub(state.eth1_deposit_index),
    );
    if body.deposits().len() as u64 != expected_deposits {
        return Err(StateTransitionError::InvalidDepositCount);
    }

    for slashing in body.proposer_slashings() {
        process_proposer_slashing::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, slashing, verify_signatures)?;
    }
    for slashing in body.attester_slashings() {
        process_attester_slashing::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, slashing, verify_signatures)?;
    }
    for attestation in body.attestations() {
        process_attestation::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, attestation, verify_signatures)?;
    }
    for deposit in body.deposits() {
        process_deposit::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, deposit, verify_signatures)?;
    }
    for exit in body.voluntary_exits() {
        process_voluntary_exit::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(state, exit, verify_signatures)?;
    }

    Ok(())
}

// ── Altair-local wrappers for phase0 operations ───────────────────────────────
//
// `process_block_header`, `process_randao`, and `process_eth1_data` from phase0
// are generic over `E::BeaconState: BeaconStateWrite + BeaconStateView`. The
// altair inner state does not implement those traits. We call them via a
// temporary fork-enum wrapper approach or re-implement directly.
//
// Since these operations only touch the shared fields (which exist verbatim in
// the altair state), we implement thin direct-field versions here.

/// `process_block_header` for Altair.
///
/// Exposed for the conformance harness (`altair/operations/block_header`).
/// Logic is identical to the phase0 version; the function operates directly on
/// the altair `BeaconState` fields.
pub fn process_block_header_altair<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
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
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> Result<(), StateTransitionError>
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
    use crate::error::BlockHeaderInvalidReason;
    use pharos_ssz::TreeHash;
    use pharos_types::phase0::BeaconBlockHeader;

    // Slot must match state.
    if block.slot != state.slot {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::SlotMismatch,
        });
    }

    // Block slot must be strictly after the latest block header slot.
    if block.slot <= state.latest_block_header.slot {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::SlotNotLater,
        });
    }

    // Parent root must match latest block header root.
    let latest_header_root = {
        let mut hdr = state.latest_block_header.clone();
        if hdr.state_root == pharos_types::phase0::Root::default() {
            hdr.state_root = state.tree_hash_root();
        }
        hdr.tree_hash_root()
    };
    if block.parent_root != latest_header_root {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ParentRootMismatch,
        });
    }

    // Proposer must not be slashed.
    let proposer = state
        .validators
        .get(block.proposer_index.0 as usize)
        .ok_or(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ProposerSlashed,
        })?;
    if proposer.slashed {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ProposerSlashed,
        });
    }

    // Proposer index must match computed proposer for the slot.
    let expected_proposer = crate::altair::helpers::get_proposer_index_altair::<
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
    if block.proposer_index != expected_proposer {
        return Err(StateTransitionError::InvalidBlockHeader {
            reason: BlockHeaderInvalidReason::ProposerIndexMismatch,
        });
    }

    // Update latest_block_header.
    state.latest_block_header = BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: pharos_types::phase0::Root::default(), // zeroed; filled at epoch end
        body_root: block.body.tree_hash_root(),
    };

    Ok(())
}

/// `process_randao` for Altair state.
///
/// Exposed as `pub` so Bellatrix can call it explicitly after
/// `process_execution_payload` per the spec ordering note at
/// `specs/bellatrix/beacon-chain.md:362-364`.
pub fn process_randao_altair<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
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
    use crate::phase0::{
        accessors::{compute_domain, compute_epoch_at_slot},
        helpers::{DOMAIN_RANDAO, xor},
    };
    use pharos_ssz::TreeHash;

    let epoch = compute_epoch_at_slot(state.slot, E::SLOTS_PER_EPOCH);

    if verify_signatures {
        let proposer = state
            .validators
            .get(
                crate::altair::helpers::get_proposer_index_altair::<
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
                .0 as usize,
            )
            .ok_or(StateTransitionError::InvalidRandaoReveal)?;

        let domain = {
            let fork_version = if epoch < state.fork.epoch {
                state.fork.previous_version.into_inner()
            } else {
                state.fork.current_version.into_inner()
            };
            compute_domain(DOMAIN_RANDAO, fork_version, &state.genesis_validators_root)
        };

        use pharos_types::phase0::SigningData;
        let signing_root = SigningData {
            object_root: epoch.tree_hash_root(),
            domain,
        }
        .tree_hash_root();

        let valid = pharos_utils::bls::verify(
            &proposer.pubkey,
            signing_root.as_slice(),
            &body.randao_reveal,
        )
        .unwrap_or(false);

        if !valid {
            return Err(StateTransitionError::InvalidRandaoReveal);
        }
    }

    // Mix in the RANDAO reveal hash.
    let reveal_root = pharos_utils::hash::hash(body.randao_reveal.as_slice());
    let mix_idx = (epoch.0 % E::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
    let cur_mix = state.randao_mixes.get(mix_idx).copied().unwrap_or_default();
    let new_mix = xor(&cur_mix, &reveal_root);
    state.randao_mixes = state
        .randao_mixes
        .with_set(mix_idx, new_mix)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}

/// `process_eth1_data` for Altair state.
///
/// Exposed as `pub` so Bellatrix can call it explicitly as part of the
/// interleaved block-processing sequence per
/// `specs/bellatrix/beacon-chain.md:362-364`.
pub fn process_eth1_data_altair<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: BeaconSpec,
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> Result<(), StateTransitionError> {
    // Add vote.
    state.eth1_data_votes = state
        .eth1_data_votes
        .with_push(body.eth1_data.clone())
        .map_err(StateTransitionError::Ssz)?;

    // Adopt eth1 data if it has strict majority support over SLOTS_PER_ETH1_VOTING_PERIOD.
    // Spec (process_eth1_data): if state.eth1_data_votes.count(body.eth1_data) * 2 > SLOTS_PER_ETH1_VOTING_PERIOD
    let votes_count = state
        .eth1_data_votes
        .as_slice()
        .iter()
        .filter(|v| *v == &body.eth1_data)
        .count() as u64;
    if votes_count * 2 > E::EPOCHS_PER_ETH1_VOTING_PERIOD * E::SLOTS_PER_EPOCH {
        state.eth1_data = body.eth1_data.clone();
    }

    Ok(())
}
