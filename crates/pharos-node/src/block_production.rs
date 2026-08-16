//! CL BeaconBlock + AttestationData assembly.
//!
//! `produce_block` assembles a `BeaconBlock` on the current head state for a
//! given proposal slot by:
//!   (a) short read lock → clone head state + head root → release lock
//!   (b) `process_slots_fork` to the proposal slot
//!   (c) look up the proposer index
//!   (d) drain the sync aggregate (with real committee positions)
//!   (e) prepare the execution payload from the EL
//!   (f) drain operation pools
//!   (g) assemble the block (state_root = default)
//!   (h) run `process_block_for_production` (full STF, no BLS)
//!   (i) set `block.state_root = post_state.tree_hash_root()`
//!
//! `produce_attestation_data` returns an `AttestationData` for a given
//! `(slot, committee_index)` based on the current head state.
//!
//! Both functions are synchronous / blocking — callers wrap in
//! `tokio::task::spawn_blocking`.
//!
//! Per `D-produce-empty-then-fill-stf` and `D-process-block-verify-flag`
//! (M9-Validator Phase 4).

use std::sync::Arc;

use parking_lot::RwLock;
use pharos_engine::EngineHandle;
use pharos_fork_choice::Store as FcStore;
use pharos_fork_choice::{execution_block_hash_at_root, get_head};
use pharos_ssz::{Bitvector, SszList, TreeHash};
use pharos_stf::{
    AltairProcessBlockForProduction, AltairProcessSlotsDispatch, AltairUpgradeDispatch,
    BellatrixProcessBlockForProduction, BellatrixProcessSlotsDispatch, BellatrixUpgradeDispatch,
    CapellaProcessBlockForProduction, CapellaProcessSlotsDispatch, ForkEpochs,
    GetExpectedWithdrawalsDispatch, Phase0UpgradeDispatch, StateTransitionError,
    phase0::state_write::BeaconStateWrite, process_slots_fork,
};
use pharos_stf::{
    compute_epoch_at_slot, compute_start_slot_at_epoch, get_active_validator_indices,
    get_beacon_committee, get_beacon_proposer_index, get_block_root_at_slot,
    get_committee_count_per_slot, get_current_epoch, process_block_for_production,
};
use pharos_types::{
    BeaconStateView, EthSpec,
    altair::SyncAggregate,
    config::RuntimeConfig,
    phase0::misc::{AttestationData, Checkpoint, Eth1Data},
    phase0::operations::{Attestation, AttesterSlashing, ProposerSlashing, SignedVoluntaryExit},
    phase0::primitives::{CommitteeIndex, Root, Slot, ValidatorIndex},
    views::{BeaconBlockBodyView, BeaconBlockView, ForkVariant},
};
use pharos_utils::{BLSSignature, Bytes32};
use thiserror::Error;

use crate::engine_driver::{
    ExecutionEngineHandle, PreparePayloadError, build_payload_attributes_v1,
    build_payload_attributes_v2, compute_finalized_block_hash, compute_safe_block_hash,
    hash_to_hex, prepare_execution_payload_bellatrix, prepare_execution_payload_with_value,
};
use crate::op_pools::OperationPools;

// ── ProduceError ──────────────────────────────────────────────────────────────

/// Errors from `produce_block` and `produce_attestation_data`.
#[derive(Error, Debug)]
pub enum ProduceError {
    /// The node is still syncing; do not produce.
    #[error("node is syncing — block production is unavailable")]
    NotSynced,

    /// The node's head is optimistic; block production must be suppressed until
    /// the EL validates the head (per the 503 contract,
    /// `D-503-on-optimistic-or-syncing`).
    #[error("node head is optimistic — block production is unavailable")]
    Optimistic,

    /// The head state could not be read from the fork-choice store (store empty).
    #[error("head state unavailable")]
    HeadStateUnavailable,

    /// The STF rejected the assembled block.
    #[error("STF error: {0}")]
    Stf(#[from] StateTransitionError),

    /// Engine API call failed (FCU or getPayload).
    #[error("engine error: {0}")]
    Engine(String),

    /// EL was not ready to return a payload (`payloadId == null`).
    #[error("EL payload not ready")]
    PayloadNotReady,

    /// The head state's fork is incompatible with the production path requested.
    #[error("wrong fork variant for production")]
    WrongFork,

    /// The committee index is out of range for this slot.
    #[error("committee index {0} out of range for slot {1}")]
    BadCommitteeIndex(u64, u64),

    /// The head state has no active validators at the proposal epoch, so the
    /// proposer index cannot be computed (guards a `compute_proposer_index`
    /// `assert!` that would otherwise panic the live node).
    #[error("no active validators at proposal epoch")]
    NoActiveValidators,
}

impl From<PreparePayloadError> for ProduceError {
    fn from(e: PreparePayloadError) -> Self {
        match e {
            PreparePayloadError::PayloadNotReady => ProduceError::PayloadNotReady,
            PreparePayloadError::Engine(e) => ProduceError::Engine(e.to_string()),
        }
    }
}

// ── Per-fork block-assembly dispatch traits ───────────────────────────────────
//
// These traits allow `produce_block` — which is generic over `E: EthSpec` —
// to set fields on inner concrete signed-block types through the opaque
// associated types `E::CapellaSignedBeaconBlock` / `E::BellatrixSignedBeaconBlock`
// / `E::AltairSignedBeaconBlock`.
//
// The sync aggregate is passed as `(set_bits, signature)` to avoid using
// const-generic `E::SYNC_COMMITTEE_SIZE` in the trait method signature — stable
// Rust does not permit associated consts of type params in const-generic
// positions. The blanket impl converts to `SyncAggregate<SYNC_COMMITTEE_SIZE>`
// using the concrete const param it already has.
//
// Proposer slashings, attester slashings, attestations, and voluntary exits are
// passed as `Vec<T>` for the same reason. The blanket impl converts to
// `SszList<T, MAX_*>` using the concrete const params known at the impl site.
//
// Each trait provides:
//   - `assemble(...)` → `Self`: build the unsigned block from ingredients
//   - `set_state_root(&mut self, root)`: seal after STF
//   - `into_signed_block(self) -> E::SignedBeaconBlock`: wrap into fork-enum
//   - `message_clone(&self) -> E::*BeaconBlock`: get the inner block for STF

/// Assembly dispatch for Capella inner signed blocks.
pub trait CapellaBlockAssembler<E: EthSpec>: Sized + Default + Clone {
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: Vec<ProposerSlashing>,
        attester_slashings: Vec<AttesterSlashing<2048>>,
        attestations: Vec<Attestation<2048>>,
        voluntary_exits: Vec<SignedVoluntaryExit>,
        sync_committee_bits: Vec<usize>,
        sync_committee_signature: BLSSignature,
        execution_payload: E::CapellaExecutionPayload,
        bls_to_execution_changes: Vec<
            pharos_types::capella::operations::SignedBLSToExecutionChange,
        >,
    ) -> Result<Self, ProduceError>;

    fn set_state_root(&mut self, root: Root);
    fn into_signed_block(self) -> E::SignedBeaconBlock;
    fn message_clone(&self) -> E::CapellaBeaconBlock;
}

/// Assembly dispatch for Bellatrix inner signed blocks.
pub trait BellatrixBlockAssembler<E: EthSpec>: Sized + Default + Clone {
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: Vec<ProposerSlashing>,
        attester_slashings: Vec<AttesterSlashing<2048>>,
        attestations: Vec<Attestation<2048>>,
        voluntary_exits: Vec<SignedVoluntaryExit>,
        sync_committee_bits: Vec<usize>,
        sync_committee_signature: BLSSignature,
        execution_payload: E::ExecutionPayload,
    ) -> Result<Self, ProduceError>;

    fn set_state_root(&mut self, root: Root);
    fn into_signed_block(self) -> E::SignedBeaconBlock;
    fn message_clone(&self) -> E::BellatrixBeaconBlock;
}

/// Assembly dispatch for Altair inner signed blocks.
pub trait AltairBlockAssembler<E: EthSpec>: Sized + Default + Clone {
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: Vec<ProposerSlashing>,
        attester_slashings: Vec<AttesterSlashing<2048>>,
        attestations: Vec<Attestation<2048>>,
        voluntary_exits: Vec<SignedVoluntaryExit>,
        sync_committee_bits: Vec<usize>,
        sync_committee_signature: BLSSignature,
    ) -> Result<Self, ProduceError>;

    fn set_state_root(&mut self, root: Root);
    fn into_signed_block(self) -> E::SignedBeaconBlock;
    fn message_clone(&self) -> E::AltairBeaconBlock;
}

// ── Blanket impls ─────────────────────────────────────────────────────────────
//
// Each impl uses concrete const params (from `impl<const SYNC_COMMITTEE_SIZE: u64, ...>`)
// to construct `SyncAggregate<SYNC_COMMITTEE_SIZE>` and `SszList<T, MAX_*>`
// without hitting the stable-Rust const-generic-with-type-param limitation.

/// Build a `SyncAggregate<N>` from a set of global participating indices and
/// their aggregated BLS signature.
///
/// Indices outside `[0, N)` are silently ignored (defensive guard only;
/// the pool and committee lookup already enforce validity).
fn build_sync_aggregate<const N: u64>(
    set_bits: Vec<usize>,
    signature: BLSSignature,
) -> SyncAggregate<N> {
    let mut bits: Bitvector<N> = Bitvector::default();
    for idx in set_bits {
        if (idx as u64) < N {
            bits.set(idx, true);
        }
    }
    SyncAggregate {
        sync_committee_bits: bits,
        sync_committee_signature: signature,
    }
}

/// Reinterpret a `Vec<AttesterSlashing<2048>>` as `Vec<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>>`.
///
/// SAFETY: `AttesterSlashing<N>` is a plain struct whose fields do not change in size
/// with `N`. For all supported presets (mainnet and minimal), `MAX_VALIDATORS_PER_COMMITTEE`
/// equals `2048`, so both `AttesterSlashing<2048>` and `AttesterSlashing<MAX>` have
/// identical memory layouts when `MAX = 2048`. The const-generic is purely a type-level
/// phantom; no runtime padding or representation change occurs.
///
/// If a new preset were ever introduced with `MAX_VALIDATORS_PER_COMMITTEE != 2048`, this
/// transmute would be unsound. Adding that preset would require revisiting this function.
unsafe fn transmute_attester_slashings<const MAX: u64>(
    v: Vec<AttesterSlashing<2048>>,
) -> Vec<AttesterSlashing<MAX>> {
    // SAFETY: see doc above.
    unsafe { std::mem::transmute(v) }
}

/// Reinterpret a `Vec<Attestation<2048>>` as `Vec<Attestation<MAX_VALIDATORS_PER_COMMITTEE>>`.
///
/// SAFETY: same reasoning as `transmute_attester_slashings`.
unsafe fn transmute_attestations<const MAX: u64>(
    v: Vec<Attestation<2048>>,
) -> Vec<Attestation<MAX>> {
    // SAFETY: see doc above.
    unsafe { std::mem::transmute(v) }
}

impl<
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    E,
> CapellaBlockAssembler<E>
    for pharos_types::capella::SignedBeaconBlock<
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
    >
where
    E: EthSpec<
            CapellaSignedBeaconBlock = pharos_types::capella::SignedBeaconBlock<
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
            CapellaBeaconBlock = pharos_types::capella::BeaconBlock<
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
            CapellaExecutionPayload = pharos_types::capella::ExecutionPayload<
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                MAX_WITHDRAWALS_PER_PAYLOAD,
            >,
        >,
{
    fn assemble(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: Vec<ProposerSlashing>,
        attester_slashings: Vec<AttesterSlashing<2048>>,
        attestations: Vec<Attestation<2048>>,
        voluntary_exits: Vec<SignedVoluntaryExit>,
        sync_committee_bits: Vec<usize>,
        sync_committee_signature: BLSSignature,
        execution_payload: E::CapellaExecutionPayload,
        bls_to_execution_changes: Vec<
            pharos_types::capella::operations::SignedBLSToExecutionChange,
        >,
    ) -> Result<Self, ProduceError> {
        // SAFETY: See transmute_attester_slashings / transmute_attestations docs.
        let attester_slashings = unsafe {
            transmute_attester_slashings::<MAX_VALIDATORS_PER_COMMITTEE>(attester_slashings)
        };
        let attestations =
            unsafe { transmute_attestations::<MAX_VALIDATORS_PER_COMMITTEE>(attestations) };
        let mut b = Self::default();
        b.message.slot = slot;
        b.message.proposer_index = proposer_index;
        b.message.parent_root = parent_root;
        b.message.body.randao_reveal = randao_reveal;
        b.message.body.eth1_data = eth1_data;
        b.message.body.graffiti = graffiti;
        b.message.body.proposer_slashings =
            SszList::from_items(proposer_slashings).unwrap_or_default();
        b.message.body.attester_slashings =
            SszList::from_items(attester_slashings).unwrap_or_default();
        b.message.body.attestations = SszList::from_items(attestations).unwrap_or_default();
        b.message.body.deposits = SszList::default();
        b.message.body.voluntary_exits = SszList::from_items(voluntary_exits).unwrap_or_default();
        b.message.body.sync_aggregate = build_sync_aggregate::<SYNC_COMMITTEE_SIZE>(
            sync_committee_bits,
            sync_committee_signature,
        );
        b.message.body.execution_payload = execution_payload;
        b.message.body.bls_to_execution_changes =
            SszList::from_items(bls_to_execution_changes).unwrap_or_default();
        Ok(b)
    }

    fn set_state_root(&mut self, root: Root) {
        self.message.state_root = root;
    }

    fn into_signed_block(self) -> E::SignedBeaconBlock {
        E::capella_into_signed_block(self)
    }

    fn message_clone(&self) -> E::CapellaBeaconBlock {
        self.message.clone()
    }
}

impl<
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
    E,
> BellatrixBlockAssembler<E>
    for pharos_types::bellatrix::SignedBeaconBlock<
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
    >
where
    E: EthSpec<
            BellatrixSignedBeaconBlock = pharos_types::bellatrix::SignedBeaconBlock<
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
            BellatrixBeaconBlock = pharos_types::bellatrix::BeaconBlock<
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
            ExecutionPayload = pharos_types::bellatrix::ExecutionPayload<
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        >,
{
    fn assemble(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: Vec<ProposerSlashing>,
        attester_slashings: Vec<AttesterSlashing<2048>>,
        attestations: Vec<Attestation<2048>>,
        voluntary_exits: Vec<SignedVoluntaryExit>,
        sync_committee_bits: Vec<usize>,
        sync_committee_signature: BLSSignature,
        execution_payload: E::ExecutionPayload,
    ) -> Result<Self, ProduceError> {
        // SAFETY: See transmute_attester_slashings / transmute_attestations docs.
        let attester_slashings = unsafe {
            transmute_attester_slashings::<MAX_VALIDATORS_PER_COMMITTEE>(attester_slashings)
        };
        let attestations =
            unsafe { transmute_attestations::<MAX_VALIDATORS_PER_COMMITTEE>(attestations) };
        let mut b = Self::default();
        b.message.slot = slot;
        b.message.proposer_index = proposer_index;
        b.message.parent_root = parent_root;
        b.message.body.randao_reveal = randao_reveal;
        b.message.body.eth1_data = eth1_data;
        b.message.body.graffiti = graffiti;
        b.message.body.proposer_slashings =
            SszList::from_items(proposer_slashings).unwrap_or_default();
        b.message.body.attester_slashings =
            SszList::from_items(attester_slashings).unwrap_or_default();
        b.message.body.attestations = SszList::from_items(attestations).unwrap_or_default();
        b.message.body.deposits = SszList::default();
        b.message.body.voluntary_exits = SszList::from_items(voluntary_exits).unwrap_or_default();
        b.message.body.sync_aggregate = build_sync_aggregate::<SYNC_COMMITTEE_SIZE>(
            sync_committee_bits,
            sync_committee_signature,
        );
        b.message.body.execution_payload = execution_payload;
        Ok(b)
    }

    fn set_state_root(&mut self, root: Root) {
        self.message.state_root = root;
    }

    fn into_signed_block(self) -> E::SignedBeaconBlock {
        E::bellatrix_into_signed_block(self)
    }

    fn message_clone(&self) -> E::BellatrixBeaconBlock {
        self.message.clone()
    }
}

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
> AltairBlockAssembler<E>
    for pharos_types::altair::SignedBeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >
where
    E: EthSpec<
            AltairSignedBeaconBlock = pharos_types::altair::SignedBeaconBlock<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SYNC_COMMITTEE_SIZE,
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
{
    fn assemble(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: Vec<ProposerSlashing>,
        attester_slashings: Vec<AttesterSlashing<2048>>,
        attestations: Vec<Attestation<2048>>,
        voluntary_exits: Vec<SignedVoluntaryExit>,
        sync_committee_bits: Vec<usize>,
        sync_committee_signature: BLSSignature,
    ) -> Result<Self, ProduceError> {
        // SAFETY: See transmute_attester_slashings / transmute_attestations docs.
        let attester_slashings = unsafe {
            transmute_attester_slashings::<MAX_VALIDATORS_PER_COMMITTEE>(attester_slashings)
        };
        let attestations =
            unsafe { transmute_attestations::<MAX_VALIDATORS_PER_COMMITTEE>(attestations) };
        let mut b = Self::default();
        b.message.slot = slot;
        b.message.proposer_index = proposer_index;
        b.message.parent_root = parent_root;
        b.message.body.randao_reveal = randao_reveal;
        b.message.body.eth1_data = eth1_data;
        b.message.body.graffiti = graffiti;
        b.message.body.proposer_slashings =
            SszList::from_items(proposer_slashings).unwrap_or_default();
        b.message.body.attester_slashings =
            SszList::from_items(attester_slashings).unwrap_or_default();
        b.message.body.attestations = SszList::from_items(attestations).unwrap_or_default();
        b.message.body.deposits = SszList::default();
        b.message.body.voluntary_exits = SszList::from_items(voluntary_exits).unwrap_or_default();
        b.message.body.sync_aggregate = build_sync_aggregate::<SYNC_COMMITTEE_SIZE>(
            sync_committee_bits,
            sync_committee_signature,
        );
        Ok(b)
    }

    fn set_state_root(&mut self, root: Root) {
        self.message.state_root = root;
    }

    fn into_signed_block(self) -> E::SignedBeaconBlock {
        E::altair_into_signed_block(self)
    }

    fn message_clone(&self) -> E::AltairBeaconBlock {
        self.message.clone()
    }
}

// ── Helper: build FCU state ───────────────────────────────────────────────────

fn build_fcu_state<E: EthSpec>(
    fc_store: &Arc<RwLock<FcStore<E>>>,
    head_root: Root,
) -> pharos_engine::types::ForkchoiceStateV1
where
    E::BeaconBlock: BeaconBlockView,
{
    let store = fc_store.read();
    let head_block_hash = hash_to_hex(execution_block_hash_at_root(&store, head_root));
    let safe_hash = hash_to_hex(compute_safe_block_hash(&store));
    let finalized_hash = hash_to_hex(compute_finalized_block_hash(&store));
    pharos_engine::types::ForkchoiceStateV1 {
        head_block_hash,
        safe_block_hash: safe_hash,
        finalized_block_hash: finalized_hash,
    }
}

// ── produce_block ─────────────────────────────────────────────────────────────

/// Assemble a `BeaconBlock` for `slot` on top of the current fork-choice head.
///
/// The produced block's `state_root` is the `tree_hash_root()` of the post-STF
/// state — i.e. the block is self-consistent. It does NOT carry a valid BLS
/// block signature (the caller signs it after obtaining the `state_root`).
///
/// # Lock ordering
///
/// The fc_store read lock is held ONLY for the initial head snapshot (clone of
/// state + root) and the brief FCU-state read (execution hashes). Both locks
/// are released BEFORE the engine calls (`D-engine-head-driver` lock-ordering rule).
///
/// # Fork dispatch (Task 4.6)
///
/// - Capella head → Capella block (V2 execution payload)
/// - Bellatrix head → Bellatrix block (V1 execution payload)
/// - Altair head → Altair block (no execution payload)
/// - Phase0 head → `unreachable!()` (checkpoint-synced nodes always past Phase0)
// The block-production entry point genuinely needs all of these inputs (slot,
// randao, graffiti, fee recipient, fc-store, pools, engine, runtime cfg); a
// param struct would add indirection without clarifying the call site.
#[allow(clippy::too_many_arguments)]
pub fn produce_block<E: EthSpec>(
    fc_store: &Arc<RwLock<FcStore<E>>>,
    pools: &OperationPools<E>,
    engine: &EngineHandle,
    slot: Slot,
    randao_reveal: BLSSignature,
    graffiti: [u8; 32],
    fee_recipient: String,
    runtime_cfg: &RuntimeConfig,
) -> Result<(E::SignedBeaconBlock, E::BeaconState, pharos_utils::Uint256), ProduceError>
where
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: AltairProcessBlockForProduction<E>
        + AltairProcessSlotsDispatch<E>
        + AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixProcessBlockForProduction<E, ExecutionEngineHandle>
        + TreeHash
        + BellatrixProcessSlotsDispatch<E>
        + BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState: CapellaProcessBlockForProduction<E, ExecutionEngineHandle>
        + TreeHash
        + CapellaProcessSlotsDispatch<E>
        + GetExpectedWithdrawalsDispatch<E>,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::BeaconBlock: BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::CapellaSignedBeaconBlock: CapellaBlockAssembler<E>,
    E::BellatrixSignedBeaconBlock: BellatrixBlockAssembler<E>,
    E::AltairSignedBeaconBlock: AltairBlockAssembler<E>,
    E::CapellaExecutionPayload:
        TryFrom<pharos_engine::types::ExecutionPayloadV2, Error = pharos_engine::EngineError>,
    E::ExecutionPayload:
        TryFrom<pharos_engine::types::ExecutionPayloadV1, Error = pharos_engine::EngineError>,
{
    // ── Step (a): Short read lock — clone head state and head root ────────────

    let (mut state, head_root) = {
        let store = fc_store.read();
        let head_root = get_head::<E>(&store);
        let state = store
            .block_states
            .get(&head_root)
            .cloned()
            .ok_or(ProduceError::HeadStateUnavailable)?;
        (state, head_root)
    };
    // Lock released. No lock held across engine calls.

    // ── Step (b): Advance state to the proposal slot ──────────────────────────
    // Use `process_slots_fork` (not the Phase0-only `process_slots`) so that
    // Altair/Bellatrix/Capella states are handled correctly.

    let fork_epochs = ForkEpochs::from_runtime_cfg(runtime_cfg);
    process_slots_fork::<E>(&mut state, slot, fork_epochs, runtime_cfg)
        .map_err(ProduceError::Stf)?;

    // ── Step (c): Get proposer index ──────────────────────────────────────────
    // Guard the `compute_proposer_index` assert (empty active set → panic).
    if get_active_validator_indices::<E>(&state, get_current_epoch::<E>(&state)).is_empty() {
        return Err(ProduceError::NoActiveValidators);
    }
    let proposer_index = get_beacon_proposer_index::<E>(&state);

    // ── Shared inputs ─────────────────────────────────────────────────────────

    let graffiti_bytes = Bytes32::from_array(graffiti);
    let eth1_data = state.eth1_data().clone();

    // Sync committee pubkeys (None for Phase0, Some for Altair+).
    let (committee_pubkeys_cur, _) = state.sync_committee_pubkeys().unwrap_or_default();

    // Validator pubkey lookup closure.
    let validator_pubkey_fn =
        |idx: u64| -> Option<[u8; 48]> { state.validator(idx as usize).map(|v| v.pubkey.into()) };

    // parent_root = head_root (the block root this block extends).
    let parent_root = head_root;

    // Sync messages attest to the PARENT slot's block root.
    let sync_agg_slot = Slot(slot.0.saturating_sub(1));

    let fork = state.fork_variant();

    match fork {
        // ── Capella: V2 execution payload ─────────────────────────────────────
        ForkVariant::Capella => {
            // ── Step (d): Drain sync aggregate ────────────────────────────────
            let (sync_bits, sync_sig) = pools.drain_sync_aggregate_raw(
                sync_agg_slot,
                parent_root,
                &committee_pubkeys_cur,
                validator_pubkey_fn,
            );

            // ── Step (e): Prepare execution payload ───────────────────────────
            let capella_inner =
                E::into_capella_state(state.clone()).ok_or(ProduceError::WrongFork)?;
            let attrs = build_payload_attributes_v2::<E>(
                &state,
                &capella_inner,
                slot,
                fee_recipient,
                runtime_cfg,
            );
            let fcu_state = build_fcu_state::<E>(fc_store, head_root);
            let (wire_payload, exec_value) =
                prepare_execution_payload_with_value(engine, fcu_state, attrs)
                    .map_err(ProduceError::from)?;
            let execution_payload: E::CapellaExecutionPayload = wire_payload
                .try_into()
                .map_err(|e: pharos_engine::EngineError| ProduceError::Engine(e.to_string()))?;

            // ── Step (f): Drain operations ────────────────────────────────────
            let block_ops = pools.drain_for_block(slot.0);

            // ── Step (g): Assemble block ──────────────────────────────────────
            let mut block_inner = E::CapellaSignedBeaconBlock::assemble(
                slot,
                proposer_index,
                parent_root,
                randao_reveal,
                eth1_data,
                graffiti_bytes,
                block_ops.proposer_slashings,
                block_ops.attester_slashings,
                block_ops.attestations,
                block_ops.voluntary_exits,
                sync_bits,
                sync_sig,
                execution_payload,
                block_ops.bls_to_execution_changes,
            )?;

            // ── Step (h): Run STF ─────────────────────────────────────────────
            let block_enum = E::capella_into_block(block_inner.message_clone());
            let ee = ExecutionEngineHandle::new(engine.clone());
            let post_state = process_block_for_production::<E, ExecutionEngineHandle>(
                state,
                &block_enum,
                &ee,
                runtime_cfg,
            )?;

            // ── Step (i): Seal with state_root ────────────────────────────────
            block_inner.set_state_root(post_state.tree_hash_root());
            Ok((block_inner.into_signed_block(), post_state, exec_value))
        }

        // ── Bellatrix: V1 execution payload ───────────────────────────────────
        ForkVariant::Bellatrix => {
            let (sync_bits, sync_sig) = pools.drain_sync_aggregate_raw(
                sync_agg_slot,
                parent_root,
                &committee_pubkeys_cur,
                validator_pubkey_fn,
            );

            let attrs = build_payload_attributes_v1::<E>(&state, slot, fee_recipient, runtime_cfg);
            let fcu_state = build_fcu_state::<E>(fc_store, head_root);
            let wire_payload = prepare_execution_payload_bellatrix(engine, fcu_state, attrs)
                .map_err(ProduceError::from)?;
            let execution_payload: E::ExecutionPayload = wire_payload
                .try_into()
                .map_err(|e: pharos_engine::EngineError| ProduceError::Engine(e.to_string()))?;

            let block_ops = pools.drain_for_block(slot.0);

            let mut block_inner = E::BellatrixSignedBeaconBlock::assemble(
                slot,
                proposer_index,
                parent_root,
                randao_reveal,
                eth1_data,
                graffiti_bytes,
                block_ops.proposer_slashings,
                block_ops.attester_slashings,
                block_ops.attestations,
                block_ops.voluntary_exits,
                sync_bits,
                sync_sig,
                execution_payload,
            )?;

            let block_enum = E::bellatrix_into_block(block_inner.message_clone());
            let ee = ExecutionEngineHandle::new(engine.clone());
            let post_state = process_block_for_production::<E, ExecutionEngineHandle>(
                state,
                &block_enum,
                &ee,
                runtime_cfg,
            )?;

            block_inner.set_state_root(post_state.tree_hash_root());
            // Bellatrix getPayloadV1 carries no blockValue; use zero.
            Ok((
                block_inner.into_signed_block(),
                post_state,
                pharos_utils::Uint256::ZERO,
            ))
        }

        // ── Altair: no execution payload ──────────────────────────────────────
        ForkVariant::Altair => {
            let (sync_bits, sync_sig) = pools.drain_sync_aggregate_raw(
                sync_agg_slot,
                parent_root,
                &committee_pubkeys_cur,
                validator_pubkey_fn,
            );

            let block_ops = pools.drain_for_block(slot.0);

            let mut block_inner = E::AltairSignedBeaconBlock::assemble(
                slot,
                proposer_index,
                parent_root,
                randao_reveal,
                eth1_data,
                graffiti_bytes,
                block_ops.proposer_slashings,
                block_ops.attester_slashings,
                block_ops.attestations,
                block_ops.voluntary_exits,
                sync_bits,
                sync_sig,
            )?;

            let block_enum = E::altair_into_block(block_inner.message_clone());
            // Altair blocks have no execution payload; ExecutionEngineHandle will not
            // be called by process_block_for_production for the Altair arm.
            let ee = ExecutionEngineHandle::new(engine.clone());
            let post_state = process_block_for_production::<E, ExecutionEngineHandle>(
                state,
                &block_enum,
                &ee,
                runtime_cfg,
            )?;

            block_inner.set_state_root(post_state.tree_hash_root());
            // Altair has no execution payload; exec value is zero.
            Ok((
                block_inner.into_signed_block(),
                post_state,
                pharos_utils::Uint256::ZERO,
            ))
        }

        // Phase0 nodes are always past the Altair fork epoch (checkpoint sync);
        // a Phase0 head is unreachable in normal operation.
        ForkVariant::Phase0 => {
            unreachable!(
                "Phase0 head state in produce_block — \
                 checkpoint-synced nodes always past Phase0"
            )
        }
    }
}

// ── produce_attestation_data ──────────────────────────────────────────────────

/// Build `AttestationData` for a given `(slot, committee_index)`.
///
/// - `beacon_block_root` = current head root
/// - `source` = `state.current_justified_checkpoint`
/// - `target` = epoch-boundary block root at the start of the current epoch
///
/// If `slot > state.slot()`, advances the state to `slot` via `process_slots_fork`.
///
/// Returns `ProduceError::BadCommitteeIndex` if `committee_index >=
/// get_committee_count_per_slot(state, slot_epoch)`.
pub fn produce_attestation_data<E: EthSpec>(
    fc_store: &Arc<RwLock<FcStore<E>>>,
    slot: Slot,
    committee_index: CommitteeIndex,
    runtime_cfg: &RuntimeConfig,
) -> Result<AttestationData, ProduceError>
where
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: AltairProcessSlotsDispatch<E>,
    E::BellatrixBeaconState: BellatrixProcessSlotsDispatch<E>,
    E::CapellaBeaconState: CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
    E::AltairBeaconState: AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixUpgradeDispatch<E>,
    E::Phase0BeaconBlockBody:
        BeaconBlockBodyView<Attestation = pharos_types::phase0::Attestation<2048>>,
{
    let (mut state, head_root) = {
        let store = fc_store.read();
        let head_root = get_head::<E>(&store);
        let state = store
            .block_states
            .get(&head_root)
            .cloned()
            .ok_or(ProduceError::HeadStateUnavailable)?;
        (state, head_root)
    };

    if slot > state.slot() {
        let fork_epochs = ForkEpochs::from_runtime_cfg(runtime_cfg);
        process_slots_fork::<E>(&mut state, slot, fork_epochs, runtime_cfg)
            .map_err(ProduceError::Stf)?;
    }

    let slot_epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);

    let committee_count = get_committee_count_per_slot::<E>(&state, slot_epoch);
    if committee_index.0 >= committee_count {
        return Err(ProduceError::BadCommitteeIndex(committee_index.0, slot.0));
    }

    // Per phase0/validator.md get_attestation_data: target epoch is the
    // attestation slot's epoch (NOT the state's current epoch — they diverge
    // if the state is advanced past the slot's epoch).
    let target_epoch = slot_epoch;
    let epoch_start_slot = compute_start_slot_at_epoch(target_epoch, E::SLOTS_PER_EPOCH);
    let target_root = if epoch_start_slot == state.slot() {
        head_root
    } else {
        get_block_root_at_slot::<E>(&state, epoch_start_slot).unwrap_or(head_root)
    };

    Ok(AttestationData {
        slot,
        index: committee_index,
        beacon_block_root: head_root,
        source: state.current_justified_checkpoint().clone(),
        target: Checkpoint {
            epoch: target_epoch,
            root: target_root,
        },
    })
}

// ── get_committee_for_slot ────────────────────────────────────────────────────

/// Return the list of validator indices in `committee_index` for `slot`.
pub fn get_committee_for_slot<E: EthSpec>(
    fc_store: &Arc<RwLock<FcStore<E>>>,
    slot: Slot,
    committee_index: CommitteeIndex,
    runtime_cfg: &RuntimeConfig,
) -> Result<Vec<ValidatorIndex>, ProduceError>
where
    E::BeaconState: BeaconStateWrite + TreeHash + Clone,
    E::AltairBeaconState: AltairProcessSlotsDispatch<E>,
    E::BellatrixBeaconState: BellatrixProcessSlotsDispatch<E>,
    E::CapellaBeaconState: CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: Phase0UpgradeDispatch<E>,
    E::AltairBeaconState: AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: BellatrixUpgradeDispatch<E>,
    E::Phase0BeaconBlockBody:
        BeaconBlockBodyView<Attestation = pharos_types::phase0::Attestation<2048>>,
{
    let (mut state, _) = {
        let store = fc_store.read();
        let head_root = get_head::<E>(&store);
        let state = store
            .block_states
            .get(&head_root)
            .cloned()
            .ok_or(ProduceError::HeadStateUnavailable)?;
        (state, head_root)
    };

    if slot > state.slot() {
        let fork_epochs = ForkEpochs::from_runtime_cfg(runtime_cfg);
        process_slots_fork::<E>(&mut state, slot, fork_epochs, runtime_cfg)
            .map_err(ProduceError::Stf)?;
    }

    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let committee_count = get_committee_count_per_slot::<E>(&state, epoch);
    if committee_index.0 >= committee_count {
        return Err(ProduceError::BadCommitteeIndex(committee_index.0, slot.0));
    }
    Ok(get_beacon_committee::<E>(&state, slot, committee_index.0))
}
