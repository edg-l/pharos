//! Fork-aware dispatcher traits for `update_light_client_snapshots`.
//!
//! Exposes `AltairDispatchBounds` and `BellatrixDispatchBounds`: dispatch
//! traits that hide the fifteen const-generic bounds on the concrete Altair /
//! Bellatrix state and block types. Callers in `pharos-node` use these traits
//! to call `update_light_client_snapshots` through the opaque
//! `E::AltairBeaconState` / `E::BellatrixBeaconState` associated types without
//! spelling out fifteen const-generic bounds at every call site (R3).
//!
//! `dispatch_update_light_client_snapshots` — the fork-dispatch entry point
//! that takes a `pharos_fork_choice::Store<E>` — lives in `pharos-node`
//! (in `block_ingestion.rs`) because `pharos-stf` cannot depend on
//! `pharos-fork-choice` (cycle: fork-choice already depends on stf).
//!
//! Per Phase 2 of M4c plan.

use pharos_ssz::{SszVector, TreeHash};
use pharos_types::{
    EthSpec,
    altair::{
        BeaconBlock as AltairBeaconBlock, BeaconState as AltairBeaconState,
        light_client::{
            CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH, CURRENT_SYNC_COMMITTEE_GINDEX,
            FINALITY_BRANCH_DEPTH, FINALIZED_ROOT_GINDEX, LightClientBootstrap,
            LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate,
            LightClientUpdate, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH, NEXT_SYNC_COMMITTEE_GINDEX,
        },
    },
    bellatrix::{BeaconBlock as BellatrixBeaconBlock, BeaconState as BellatrixBeaconState},
    capella::{
        BeaconBlock as CapellaBeaconBlock, BeaconState as CapellaBeaconState,
        light_client::{
            LightClientBootstrap as CapellaLCBootstrap,
            LightClientFinalityUpdate as CapellaLCFinalityUpdate,
            LightClientOptimisticUpdate as CapellaLCOptimisticUpdate,
            LightClientUpdate as CapellaLCUpdate,
        },
    },
    phase0::operations::BeaconBlockHeader,
};
use pharos_utils::Bytes32;

use crate::altair::light_client::{
    MIN_SYNC_COMMITTEE_PARTICIPANTS, compute_state_proof, compute_sync_committee_period_at_slot,
    count_participants, create_light_client_finality_update, create_light_client_optimistic_update,
    is_better_update, is_finality_update,
};
use crate::bellatrix::helpers::bellatrix_state_to_altair;
use crate::capella::helpers::capella_state_to_altair;
use crate::capella::light_client::capella_block_to_light_client_header;

// ── AltairDispatchBounds ──────────────────────────────────────────────────────

/// Dispatch trait for calling `update_light_client_snapshots` through the
/// opaque `E::AltairBeaconState` associated type.
///
/// Keeps the fifteen const-generic monomorphisation inside `pharos-stf` (R3).
pub trait AltairDispatchBounds<E: EthSpec>: Sized {
    /// Run `update_light_client_snapshots` using `self` as `post_state`.
    fn call_update_lc_snapshots<S: pharos_storage::Store<E>>(
        &self,
        block: &E::AltairBeaconBlock,
        attested_state: Option<&Self>,
        attested_block: Option<&E::AltairBeaconBlock>,
        finalized_block: Option<&E::AltairBeaconBlock>,
        store: &S,
    );
}

impl<
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
> AltairDispatchBounds<E>
    for AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >
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
            AltairBeaconBlock = AltairBeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            AltairLightClientBootstrap = LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
            AltairLightClientUpdate = LightClientUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientFinalityUpdate = LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientOptimisticUpdate = LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE>,
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
    >: TreeHash,
    Bytes32: Default + Clone,
{
    fn call_update_lc_snapshots<S: pharos_storage::Store<E>>(
        &self,
        block: &AltairBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
        attested_state: Option<&Self>,
        attested_block: Option<
            &AltairBeaconBlock<
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
        finalized_block: Option<
            &AltairBeaconBlock<
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
        store: &S,
    ) {
        crate::altair::light_client::update_light_client_snapshots::<
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
            S,
        >(
            self,
            block,
            attested_state,
            attested_block,
            finalized_block,
            store,
        );
    }
}

// ── BellatrixDispatchBounds ───────────────────────────────────────────────────

/// Dispatch trait for running the LC snapshot writes on bellatrix states.
///
/// Projects the bellatrix state to altair (via `bellatrix_state_to_altair`)
/// for the state fields, and uses a Bellatrix-specific body hash for the
/// `body_root` field in `LightClientHeader` (includes execution payload).
pub trait BellatrixDispatchBounds<E: EthSpec>: Sized {
    /// Run the LC snapshot writes using `self` (bellatrix post-state).
    fn call_update_lc_snapshots_bellatrix<S: pharos_storage::Store<E>>(
        &self,
        block: &E::BellatrixBeaconBlock,
        attested_state: Option<&Self>,
        attested_block: Option<&E::BellatrixBeaconBlock>,
        finalized_block: Option<&E::BellatrixBeaconBlock>,
        store: &S,
    );
}

impl<
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
> BellatrixDispatchBounds<E>
    for BellatrixBeaconState<
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
    >
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
            BellatrixBeaconState = BellatrixBeaconState<
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
            BellatrixBeaconBlock = BellatrixBeaconBlock<
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
            AltairLightClientBootstrap = LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
            AltairLightClientUpdate = LightClientUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientFinalityUpdate = LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientOptimisticUpdate = LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE>,
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
    >: TreeHash,
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
    >: TreeHash,
    Bytes32: Default + Clone,
{
    fn call_update_lc_snapshots_bellatrix<S: pharos_storage::Store<E>>(
        &self,
        block: &BellatrixBeaconBlock<
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
        attested_state: Option<&Self>,
        attested_block: Option<
            &BellatrixBeaconBlock<
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
        >,
        finalized_block: Option<
            &BellatrixBeaconBlock<
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
        >,
        store: &S,
    ) {
        use pharos_ssz::TreeHash as _;
        use pharos_storage::Store as StoreT;

        // Project bellatrix state to altair for state-based LC operations.
        let post_state_altair = bellatrix_state_to_altair(self);

        // Block root uses the full Bellatrix block hash (includes execution_payload).
        let block_root = block.tree_hash_root();

        // 1. Store LightClientBootstrap for this block.
        if let Some(bootstrap) = create_light_client_bootstrap_bellatrix::<
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
        >(&post_state_altair, block)
        {
            let _ = StoreT::put_light_client_bootstrap(store, block_root, &bootstrap);
        }

        // 2. Build update from (block, attested_state, attested_block).
        let maybe_update = attested_state
            .zip(attested_block)
            .and_then(|(att_s, att_b)| {
                let att_s_altair = bellatrix_state_to_altair(att_s);
                create_light_client_update_bellatrix::<
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
                >(
                    &post_state_altair,
                    block,
                    &att_s_altair,
                    att_b,
                    finalized_block,
                )
            });

        if let Some(update) = maybe_update {
            let period =
                compute_sync_committee_period_at_slot::<E>(update.attested_header.beacon.slot);
            let should_store = match StoreT::get_light_client_update(store, period) {
                Ok(Some(existing)) => {
                    is_better_update::<E, SYNC_COMMITTEE_SIZE>(&update, &existing)
                }
                _ => true,
            };
            if should_store {
                let _ = StoreT::put_light_client_update(store, period, &update);
            }

            if is_finality_update(&update) {
                let finality_update = create_light_client_finality_update(&update);
                let _ = StoreT::put_light_client_finality_update(store, &finality_update);
            }

            let optimistic_update = create_light_client_optimistic_update(&update);
            let _ = StoreT::put_light_client_optimistic_update(store, &optimistic_update);
        }
    }
}

// ── Bellatrix-specific LC header helper ───────────────────────────────────────

/// Build a `LightClientHeader` from a Bellatrix unsigned block.
///
/// Uses the Bellatrix body's `tree_hash_root()` for `body_root`, which
/// includes the `execution_payload` field (correct per the Bellatrix spec).
fn bellatrix_block_to_light_client_header<
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
    block: &BellatrixBeaconBlock<
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
) -> LightClientHeader
where
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
    >: TreeHash,
{
    use pharos_ssz::TreeHash as _;
    LightClientHeader {
        beacon: BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body_root: block.body.tree_hash_root(),
        },
    }
}

// ── Bellatrix bootstrap helper ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn create_light_client_bootstrap_bellatrix<
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
>(
    state: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &BellatrixBeaconBlock<
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
) -> Option<LightClientBootstrap<SYNC_COMMITTEE_SIZE>>
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
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
    >: TreeHash,
    Bytes32: Default + Clone,
{
    use pharos_ssz::TreeHash as _;

    if state.slot != state.latest_block_header.slot {
        return None;
    }

    // The block's `state_root` field commits to the full Bellatrix post-state
    // (including `execution_payload_header`); the `state` parameter here is an
    // Altair projection that has dropped that field. Recomputing
    // `state.tree_hash_root()` would yield the Altair-shape hash, never matching
    // the block's stored Bellatrix-shape root. Use the canonical `block.state_root`
    // directly — the STF already verified it against the post-state when this
    // block was applied.
    let mut header = state.latest_block_header.clone();
    header.state_root = block.state_root;
    let block_root = header.tree_hash_root();

    if block_root != block.tree_hash_root() {
        return None;
    }

    let branch_hashes = compute_state_proof(state, CURRENT_SYNC_COMMITTEE_GINDEX);
    debug_assert_eq!(
        branch_hashes.len(),
        CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH as usize
    );
    let mut branch_vec: Vec<Bytes32> = branch_hashes;
    while branch_vec.len() < CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH as usize {
        branch_vec.push(Bytes32::default());
    }
    let current_sync_committee_branch = SszVector::from_vec(branch_vec).unwrap_or_default();

    Some(LightClientBootstrap {
        header: bellatrix_block_to_light_client_header(block),
        current_sync_committee: state.current_sync_committee.clone(),
        current_sync_committee_branch,
    })
}

// ── Bellatrix LC update helper ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn create_light_client_update_bellatrix<
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
    E: EthSpec,
>(
    _post_state: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &BellatrixBeaconBlock<
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
    attested_state: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attested_block: &BellatrixBeaconBlock<
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
    finalized_block: Option<
        &BellatrixBeaconBlock<
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
    >,
) -> Option<LightClientUpdate<SYNC_COMMITTEE_SIZE>>
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
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
    >: TreeHash,
    Bytes32: Default + Clone,
{
    use pharos_ssz::TreeHash as _;

    let n_participants = count_participants(&block.body.sync_aggregate.sync_committee_bits);
    if n_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return None;
    }

    let update_signature_period = compute_sync_committee_period_at_slot::<E>(block.slot);

    if attested_state.slot != attested_state.latest_block_header.slot {
        return None;
    }
    // See `create_light_client_bootstrap_bellatrix` for the rationale:
    // `attested_state` is an Altair projection of a Bellatrix state, so its
    // tree-hash-root would not match the attested block's canonical Bellatrix
    // `state_root`. Use the block's stored value, which was verified by the STF
    // when this block was applied.
    let mut attested_header = attested_state.latest_block_header.clone();
    attested_header.state_root = attested_block.state_root;
    let attested_block_root = attested_header.tree_hash_root();
    if attested_block_root != attested_block.tree_hash_root() {
        return None;
    }
    if attested_block_root != block.parent_root {
        return None;
    }

    let update_attested_period = compute_sync_committee_period_at_slot::<E>(attested_block.slot);

    let (next_sync_committee, next_sync_committee_branch) =
        if update_attested_period == update_signature_period {
            let nsc_branch_hashes = compute_state_proof(attested_state, NEXT_SYNC_COMMITTEE_GINDEX);
            let mut nsc_vec: Vec<Bytes32> = nsc_branch_hashes;
            while nsc_vec.len() < NEXT_SYNC_COMMITTEE_BRANCH_DEPTH as usize {
                nsc_vec.push(Bytes32::default());
            }
            (
                attested_state.next_sync_committee.clone(),
                SszVector::from_vec(nsc_vec).unwrap_or_default(),
            )
        } else {
            Default::default()
        };

    let (finalized_header, finality_branch) = if let Some(fin_block) = finalized_block {
        let header = if fin_block.slot.0 != 0 {
            bellatrix_block_to_light_client_header(fin_block)
        } else {
            LightClientHeader::default()
        };
        let fin_branch_hashes = compute_state_proof(attested_state, FINALIZED_ROOT_GINDEX);
        let mut fin_vec: Vec<Bytes32> = fin_branch_hashes;
        while fin_vec.len() < FINALITY_BRANCH_DEPTH as usize {
            fin_vec.push(Bytes32::default());
        }
        (header, SszVector::from_vec(fin_vec).unwrap_or_default())
    } else {
        Default::default()
    };

    Some(LightClientUpdate {
        attested_header: bellatrix_block_to_light_client_header(attested_block),
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate: block.body.sync_aggregate.clone(),
        signature_slot: block.slot,
    })
}

// ── CapellaDispatchBounds ─────────────────────────────────────────────────────

/// Dispatch trait for running the LC snapshot writes on capella states.
///
/// Projects the capella state to altair (via `capella_state_to_altair`)
/// for the state fields, and uses a Capella-specific body hash for the
/// `body_root` field in `LightClientHeader` (includes execution payload
/// and bls_to_execution_changes).
///
/// Stores results using the capella LC column families.
pub trait CapellaDispatchBounds<E: EthSpec>: Sized {
    /// Run the LC snapshot writes using `self` (capella post-state).
    fn call_update_lc_snapshots_capella<S: pharos_storage::Store<E>>(
        &self,
        block: &E::CapellaBeaconBlock,
        attested_state: Option<&Self>,
        attested_block: Option<&E::CapellaBeaconBlock>,
        finalized_block: Option<&E::CapellaBeaconBlock>,
        store: &S,
    );
}

impl<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    E,
> CapellaDispatchBounds<E>
    for CapellaBeaconState<
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
    >
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
            CapellaBeaconState = CapellaBeaconState<
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
            CapellaBeaconBlock = CapellaBeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
            AltairLightClientBootstrap = LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
            AltairLightClientUpdate = LightClientUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientFinalityUpdate = LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientOptimisticUpdate = LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE>,
            CapellaLightClientBootstrap = CapellaLCBootstrap<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
            CapellaLightClientUpdate = CapellaLCUpdate<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
            CapellaLightClientFinalityUpdate = CapellaLCFinalityUpdate<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
            CapellaLightClientOptimisticUpdate = CapellaLCOptimisticUpdate<
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
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
    >: TreeHash,
    pharos_types::capella::BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >: TreeHash,
    pharos_types::capella::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >: TreeHash,
    pharos_types::bellatrix::Transaction<MAX_BYTES_PER_TRANSACTION>: Default + Clone,
    pharos_types::capella::Withdrawal: Default + Clone,
    pharos_types::capella::execution_payload::ExecutionPayloadHeader<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >: TreeHash,
    Bytes32: Default + Clone,
{
    fn call_update_lc_snapshots_capella<S: pharos_storage::Store<E>>(
        &self,
        block: &CapellaBeaconBlock<
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
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >,
        attested_state: Option<&Self>,
        attested_block: Option<
            &CapellaBeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
        >,
        finalized_block: Option<
            &CapellaBeaconBlock<
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
                MAX_WITHDRAWALS_PER_PAYLOAD,
                MAX_BLS_TO_EXECUTION_CHANGES,
            >,
        >,
        store: &S,
    ) {
        use pharos_ssz::TreeHash as _;
        use pharos_storage::Store as StoreT;

        // Project capella state to altair for state-based LC operations.
        let post_state_altair = capella_state_to_altair(self);

        // Block root uses the full capella block hash (includes execution_payload and bls_to_exec).
        let block_root = block.tree_hash_root();

        // 1. Store LightClientBootstrap for this block.
        if let Some(bootstrap) = create_lc_bootstrap_capella::<
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
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >(&post_state_altair, block)
        {
            let _ = StoreT::put_light_client_bootstrap_capella(store, block_root, &bootstrap);
        }

        // 2. Build update from (block, attested_state, attested_block).
        let maybe_update = attested_state
            .zip(attested_block)
            .and_then(|(att_s, att_b)| {
                let att_s_altair = capella_state_to_altair(att_s);
                create_lc_update_capella::<
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
                    MAX_WITHDRAWALS_PER_PAYLOAD,
                    MAX_BLS_TO_EXECUTION_CHANGES,
                    E,
                >(
                    &post_state_altair,
                    block,
                    &att_s_altair,
                    att_b,
                    finalized_block,
                )
            });

        if let Some(update) = maybe_update {
            let period =
                compute_sync_committee_period_at_slot::<E>(update.attested_header.beacon.slot);
            let should_store = match StoreT::get_light_client_update_capella(store, period) {
                Ok(Some(existing)) => is_better_capella_update::<
                    SYNC_COMMITTEE_SIZE,
                    BYTES_PER_LOGS_BLOOM,
                    MAX_EXTRA_DATA_BYTES,
                >(&update, &existing),
                _ => true,
            };
            if should_store {
                let _ = StoreT::put_light_client_update_capella(store, period, &update);
            }

            if is_finality_update_capella(&update) {
                let finality_update = create_lc_finality_update_capella(&update);
                let _ = StoreT::put_light_client_finality_update_capella(store, &finality_update);
            }

            let optimistic_update = create_lc_optimistic_update_capella(&update);
            let _ = StoreT::put_light_client_optimistic_update_capella(store, &optimistic_update);
        }
    }
}

// ── Capella LC helper functions ───────────────────────────────────────────────

/// Build a capella `LightClientBootstrap`.
#[allow(clippy::too_many_arguments)]
fn create_lc_bootstrap_capella<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
>(
    state: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &CapellaBeaconBlock<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >,
) -> Option<CapellaLCBootstrap<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
    pharos_types::capella::BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >: TreeHash,
    pharos_types::capella::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >: TreeHash,
    pharos_types::bellatrix::Transaction<MAX_BYTES_PER_TRANSACTION>: Default + Clone,
    pharos_types::capella::Withdrawal: Default + Clone,
    pharos_types::capella::execution_payload::ExecutionPayloadHeader<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >: TreeHash,
    Bytes32: Default + Clone,
{
    use pharos_ssz::TreeHash as _;

    if state.slot != state.latest_block_header.slot {
        return None;
    }

    // Use the STF-verified block.state_root (capella post-state includes withdrawals).
    let mut header = state.latest_block_header.clone();
    header.state_root = block.state_root;
    let block_root = header.tree_hash_root();

    if block_root != block.tree_hash_root() {
        return None;
    }

    let branch_hashes = compute_state_proof(state, CURRENT_SYNC_COMMITTEE_GINDEX);
    debug_assert_eq!(
        branch_hashes.len(),
        CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH as usize
    );
    let mut branch_vec: Vec<Bytes32> = branch_hashes;
    while branch_vec.len() < CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH as usize {
        branch_vec.push(Bytes32::default());
    }
    let current_sync_committee_branch = SszVector::from_vec(branch_vec).unwrap_or_default();

    Some(CapellaLCBootstrap {
        header: capella_block_to_light_client_header(block),
        current_sync_committee: state.current_sync_committee.clone(),
        current_sync_committee_branch,
    })
}

/// Build a capella `LightClientUpdate`.
#[allow(clippy::too_many_arguments)]
fn create_lc_update_capella<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    E: EthSpec,
>(
    _post_state: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &CapellaBeaconBlock<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >,
    attested_state: &AltairBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attested_block: &CapellaBeaconBlock<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >,
    finalized_block: Option<
        &CapellaBeaconBlock<
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
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >,
    >,
) -> Option<CapellaLCUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
    pharos_types::capella::BeaconBlockBody<
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
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
    >: TreeHash,
    pharos_types::capella::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >: TreeHash,
    pharos_types::bellatrix::Transaction<MAX_BYTES_PER_TRANSACTION>: Default + Clone,
    pharos_types::capella::Withdrawal: Default + Clone,
    pharos_types::capella::execution_payload::ExecutionPayloadHeader<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >: TreeHash,
    Bytes32: Default + Clone,
{
    use pharos_ssz::TreeHash as _;

    let n_participants = count_participants(&block.body.sync_aggregate.sync_committee_bits);
    if n_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return None;
    }

    let update_signature_period = compute_sync_committee_period_at_slot::<E>(block.slot);

    if attested_state.slot != attested_state.latest_block_header.slot {
        return None;
    }
    let mut attested_header = attested_state.latest_block_header.clone();
    attested_header.state_root = attested_block.state_root;
    let attested_block_root = attested_header.tree_hash_root();
    if attested_block_root != attested_block.tree_hash_root() {
        return None;
    }
    if attested_block_root != block.parent_root {
        return None;
    }

    let update_attested_period = compute_sync_committee_period_at_slot::<E>(attested_block.slot);

    let (next_sync_committee, next_sync_committee_branch) =
        if update_attested_period == update_signature_period {
            let nsc_branch_hashes = compute_state_proof(attested_state, NEXT_SYNC_COMMITTEE_GINDEX);
            let mut nsc_vec: Vec<Bytes32> = nsc_branch_hashes;
            while nsc_vec.len() < NEXT_SYNC_COMMITTEE_BRANCH_DEPTH as usize {
                nsc_vec.push(Bytes32::default());
            }
            (
                attested_state.next_sync_committee.clone(),
                SszVector::from_vec(nsc_vec).unwrap_or_default(),
            )
        } else {
            Default::default()
        };

    let (finalized_header, finality_branch) = if let Some(fin_block) = finalized_block {
        let header = if fin_block.slot.0 != 0 {
            capella_block_to_light_client_header(fin_block)
        } else {
            Default::default()
        };
        let fin_branch_hashes = compute_state_proof(attested_state, FINALIZED_ROOT_GINDEX);
        let mut fin_vec: Vec<Bytes32> = fin_branch_hashes;
        while fin_vec.len() < FINALITY_BRANCH_DEPTH as usize {
            fin_vec.push(Bytes32::default());
        }
        (header, SszVector::from_vec(fin_vec).unwrap_or_default())
    } else {
        Default::default()
    };

    Some(CapellaLCUpdate {
        attested_header: capella_block_to_light_client_header(attested_block),
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate: block.body.sync_aggregate.clone(),
        signature_slot: block.slot,
    })
}

fn is_finality_update_capella<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    update: &CapellaLCUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    update.finality_branch.as_slice()
        != vec![Bytes32::default(); FINALITY_BRANCH_DEPTH as usize].as_slice()
}

fn is_better_capella_update<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    new: &CapellaLCUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    existing: &CapellaLCUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
) -> bool
where
    Bytes32: Default + Clone + PartialEq,
{
    // Prefer updates with finality branch over those without.
    let new_has_fin = is_finality_update_capella(new);
    let existing_has_fin = is_finality_update_capella(existing);
    if new_has_fin != existing_has_fin {
        return new_has_fin;
    }
    // Both or neither have finality: prefer more participants.
    let new_bits = count_participants(&new.sync_aggregate.sync_committee_bits);
    let existing_bits = count_participants(&existing.sync_aggregate.sync_committee_bits);
    new_bits > existing_bits
}

fn create_lc_finality_update_capella<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    update: &CapellaLCUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
) -> CapellaLCFinalityUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    CapellaLCFinalityUpdate {
        attested_header: update.attested_header.clone(),
        finalized_header: update.finalized_header.clone(),
        finality_branch: update.finality_branch.clone(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    }
}

fn create_lc_optimistic_update_capella<
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    update: &CapellaLCUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
) -> CapellaLCOptimisticUpdate<SYNC_COMMITTEE_SIZE, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
where
    Bytes32: Default + Clone,
{
    CapellaLCOptimisticUpdate {
        attested_header: update.attested_header.clone(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    }
}
