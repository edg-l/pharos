//! `process_block` for Bellatrix.
//!
//! Per `specs/bellatrix/beacon-chain.md:360-378`.
//!
//! spec line 362-364 (note):
//!   The call to `process_execution_payload` must happen before the call to
//!   `process_randao` as the former depends on the `randao_mix` computed with
//!   the reveal of the previous block.
//!
//! Spec order (lines 367-375):
//! 1. `process_block_header`
//! 2. `process_execution_payload`  — [New in Bellatrix]; runs BEFORE `process_randao`
//! 3. `process_randao`
//! 4. `process_eth1_data`
//! 5. `process_operations`         — uses `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`
//! 6. `process_sync_aggregate`

use pharos_ssz::TreeHash as _;
use pharos_types::{
    EthSpec,
    altair::BeaconState as AltairBeaconState,
    bellatrix::{BeaconBlock, BeaconState},
    config::RuntimeConfig,
};

use crate::altair::block::{
    process_block_header_altair, process_eth1_data_altair, process_randao_altair,
};
use crate::altair::operations::process_sync_aggregate;
use crate::bellatrix::helpers::{bellatrix_state_to_altair, update_bellatrix_from_altair};
use crate::bellatrix::operations::{
    is_execution_enabled, process_execution_payload, process_operations_bellatrix,
};
use crate::error::StateTransitionError;

/// `process_block` per `specs/bellatrix/beacon-chain.md:360-378`.
///
/// spec line 362-364:
///   The call to `process_execution_payload` must happen before the call to
///   `process_randao` as the former depends on the `randao_mix` computed with
///   the reveal of the previous block.
///
/// Sequence (spec lines 367-375):
/// 1. `process_block_header`          — spec line 368
/// 2. `process_execution_payload`     — spec lines 369-371 `[New in Bellatrix]`
///    (only when `is_execution_enabled`; BEFORE `process_randao`)
/// 3. `process_randao`                — spec line 372
/// 4. `process_eth1_data`             — spec line 373
/// 5. `process_operations`            — spec line 374
///    (Bellatrix-specific: uses `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`)
/// 6. `process_sync_aggregate`        — spec line 375
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    E,
    EE,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    execution_engine: &EE,
    verify_signatures: bool,
    runtime_cfg: &RuntimeConfig,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
            AltairBeaconState = AltairBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            BellatrixBeaconState = BeaconState<
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
            >,
            AltairBeaconBlock = pharos_types::altair::BeaconBlock<
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
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    pharos_types::bellatrix::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState: pharos_ssz::TreeHash,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView,
    pharos_utils::BLSPubkey: Default + Clone,
    EE: crate::bellatrix::execution_engine::ExecutionEngine,
{
    // Build an altair block from the bellatrix block (strips execution_payload).
    // Needed for process_block_header_altair / process_randao_altair /
    // process_eth1_data_altair which operate on altair types.
    let altair_block = bellatrix_block_to_altair_block(block);

    // Project the bellatrix state to an altair state for the altair-typed steps.
    // `latest_execution_payload_header` is preserved in the bellatrix state; the
    // altair projection does not include it.
    let mut altair_state = bellatrix_state_to_altair(state);

    // Step 1: process_block_header — spec line 368.
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
    >(&mut altair_state, &altair_block)?;

    // Patch `body_root` in `latest_block_header` to use the Bellatrix block body's
    // tree hash root (which includes `execution_payload`), not the altair-projected
    // body root that `process_block_header_altair` computed.
    //
    // Per spec: `process_block_header` sets
    //   `state.latest_block_header.body_root = hash_tree_root(block.body)`
    // where `block.body` is the full Bellatrix body (including execution_payload).
    // The altair projection strips `execution_payload`, so we must patch here.
    altair_state.latest_block_header.body_root = block.body.tree_hash_root();

    // Sync `latest_block_header` back to the bellatrix state so that
    // `process_execution_payload` (step 2) sees the updated block header.
    // (The execution payload check doesn't actually read latest_block_header,
    // but syncing eagerly avoids any ordering concern.)
    state.latest_block_header = altair_state.latest_block_header.clone();

    // Step 2: process_execution_payload — spec lines 369-371 [New in Bellatrix].
    //
    // spec line 362-364 (note): MUST run before `process_randao` because
    // `process_execution_payload` checks `payload.prev_randao` against the
    // randao mix from the PREVIOUS block (i.e. the current state before
    // `process_randao` mixes in the new reveal).
    if is_execution_enabled::<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >(state, &block.body)
    {
        process_execution_payload::<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            E,
            EE,
        >(state, &block.body, execution_engine, runtime_cfg)?;
    }

    // Step 3: process_randao — spec line 372.
    // Runs AFTER process_execution_payload (see spec note line 362-364).
    // Operates on the altair projection; mixes in the new RANDAO reveal.
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
    >(&mut altair_state, &altair_block.body, verify_signatures)?;

    // Step 4: process_eth1_data — spec line 373.
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
    >(&mut altair_state, &altair_block.body)?;

    // Sync altair-mutated shared fields (randao_mixes, eth1_data_votes, etc.)
    // back into the bellatrix state before step 5.
    update_bellatrix_from_altair(state, altair_state);

    // Step 5: process_operations — spec line 374.
    // Bellatrix-specific: calls `slash_validator_bellatrix` for proposer/attester
    // slashings (uses `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX` per
    // `specs/bellatrix/beacon-chain.md:253-276`). Attestations, deposits, and
    // voluntary exits delegate to Altair handlers via state projection.
    process_operations_bellatrix::<
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        E,
    >(state, &block.body, verify_signatures)?;

    // Step 6: process_sync_aggregate — spec line 375.
    // Re-project to altair for sync_aggregate (operates on altair state).
    let mut altair_state = bellatrix_state_to_altair(state);
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
    >(
        &mut altair_state,
        &block.body.sync_aggregate,
        verify_signatures,
    )?;

    // Final sync: copy altair-mutated fields (balances updated by sync_aggregate)
    // back into the bellatrix state.
    update_bellatrix_from_altair(state, altair_state);

    Ok(())
}

// ── Projection helper ─────────────────────────────────────────────────────────

/// Project a `bellatrix::BeaconBlock` into an equivalent `altair::BeaconBlock`.
///
/// The altair block body is the bellatrix body minus `execution_payload`.
/// Exposed `pub` so conformance runners can drive per-operation tests (e.g.
/// `process_block_header_altair`) against a bellatrix block fixture.
pub fn bellatrix_block_to_altair_block<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
) -> pharos_types::altair::BeaconBlock<
    MAX_PROPOSER_SLASHINGS,
    MAX_ATTESTER_SLASHINGS,
    MAX_ATTESTATIONS,
    MAX_DEPOSITS,
    MAX_VOLUNTARY_EXITS,
    MAX_VALIDATORS_PER_COMMITTEE,
    DEPOSIT_PROOF_LENGTH,
    SYNC_COMMITTEE_SIZE,
> {
    use pharos_types::altair::{BeaconBlock as AltairBlock, BeaconBlockBody as AltairBody};

    let body = &block.body;
    AltairBlock {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body: AltairBody {
            randao_reveal: body.randao_reveal,
            eth1_data: body.eth1_data.clone(),
            graffiti: body.graffiti,
            proposer_slashings: body.proposer_slashings.clone(),
            attester_slashings: body.attester_slashings.clone(),
            attestations: body.attestations.clone(),
            deposits: body.deposits.clone(),
            voluntary_exits: body.voluntary_exits.clone(),
            sync_aggregate: body.sync_aggregate.clone(),
        },
    }
}
