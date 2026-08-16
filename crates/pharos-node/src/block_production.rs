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
use pharos_engine::types::BlobsBundleV1;
use pharos_fork_choice::Store as FcStore;
use pharos_fork_choice::{execution_block_hash_at_root, get_head};
use pharos_ssz::{Bitvector, SszList, TreeHash};
use pharos_stf::{
    AltairProcessBlockForProduction, AltairProcessSlotsDispatch, AltairUpgradeDispatch,
    BellatrixProcessBlockForProduction, BellatrixProcessSlotsDispatch, BellatrixUpgradeDispatch,
    CapellaProcessBlockForProduction, CapellaProcessSlotsDispatch, CapellaUpgradeDispatch,
    DenebProcessBlockForProduction, DenebProcessSlotsDispatch, ForkEpochs,
    GetExpectedWithdrawalsDispatch, Phase0UpgradeDispatch, StateTransitionError,
    deneb::build_blob_sidecar_inclusion_proof, phase0::state_write::BeaconStateWrite,
    process_slots_fork,
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
    build_payload_attributes_v2, build_payload_attributes_v3, bytes_to_data_hex,
    compute_finalized_block_hash, compute_safe_block_hash, hash_to_hex, hex_data_to_bytes,
    prepare_execution_payload_bellatrix, prepare_execution_payload_v3,
    prepare_execution_payload_with_value,
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

/// Assembly dispatch for Deneb inner signed blocks.
///
/// Extends `CapellaBlockAssembler` with `blob_kzg_commitments`: the
/// commitments decoded from the `BlobsBundleV1` returned by `getPayloadV3`.
pub trait DenebBlockAssembler<E: EthSpec>: Sized + Default + Clone {
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
        execution_payload: E::DenebExecutionPayload,
        bls_to_execution_changes: Vec<
            pharos_types::capella::operations::SignedBLSToExecutionChange,
        >,
        blob_kzg_commitments: Vec<pharos_types::deneb::KZGCommitment>,
    ) -> Result<Self, ProduceError>;

    fn set_state_root(&mut self, root: Root);
    fn into_signed_block(self) -> E::SignedBeaconBlock;
    fn message_clone(&self) -> E::DenebBeaconBlock;

    /// Return the 12 body field `tree_hash_root()` values (field order 0..11)
    /// for use by `build_blob_sidecars`.
    fn body_field_hashes(&self) -> [pharos_utils::Hash256; 12];

    /// Construct a `SignedBeaconBlockHeader` for this block (pre-seal).
    ///
    /// After `set_state_root` has been called, `body_root` is the body's
    /// `tree_hash_root()`. The returned header carries the correct slot,
    /// proposer_index, parent_root, state_root, and body_root fields.
    fn signed_block_header(&self) -> pharos_types::phase0::operations::SignedBeaconBlockHeader;

    /// Return the `kzg_commitments` slice from the block body.
    fn kzg_commitments_slice(&self) -> Vec<pharos_types::deneb::KZGCommitment>;
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
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    const MAX_BLS_TO_EXECUTION_CHANGES: u64,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64,
    E,
> DenebBlockAssembler<E>
    for pharos_types::deneb::SignedBeaconBlock<
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
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >
where
    E: EthSpec<
            DenebSignedBeaconBlock = pharos_types::deneb::SignedBeaconBlock<
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
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
            >,
            DenebBeaconBlock = pharos_types::deneb::BeaconBlock<
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
                MAX_BLOB_COMMITMENTS_PER_BLOCK,
            >,
            DenebExecutionPayload = pharos_types::deneb::ExecutionPayload<
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
        execution_payload: E::DenebExecutionPayload,
        bls_to_execution_changes: Vec<
            pharos_types::capella::operations::SignedBLSToExecutionChange,
        >,
        blob_kzg_commitments: Vec<pharos_types::deneb::KZGCommitment>,
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
        b.message.body.blob_kzg_commitments =
            SszList::from_items(blob_kzg_commitments).unwrap_or_default();
        Ok(b)
    }

    fn set_state_root(&mut self, root: Root) {
        self.message.state_root = root;
    }

    fn into_signed_block(self) -> E::SignedBeaconBlock {
        E::deneb_into_signed_block(self)
    }

    fn message_clone(&self) -> E::DenebBeaconBlock {
        self.message.clone()
    }

    fn body_field_hashes(&self) -> [pharos_utils::Hash256; 12] {
        let b = &self.message.body;
        [
            b.randao_reveal.tree_hash_root(),
            b.eth1_data.tree_hash_root(),
            b.graffiti.tree_hash_root(),
            b.proposer_slashings.tree_hash_root(),
            b.attester_slashings.tree_hash_root(),
            b.attestations.tree_hash_root(),
            b.deposits.tree_hash_root(),
            b.voluntary_exits.tree_hash_root(),
            b.sync_aggregate.tree_hash_root(),
            b.execution_payload.tree_hash_root(),
            b.bls_to_execution_changes.tree_hash_root(),
            b.blob_kzg_commitments.tree_hash_root(),
        ]
    }

    fn signed_block_header(&self) -> pharos_types::phase0::operations::SignedBeaconBlockHeader {
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
        SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: self.message.slot,
                proposer_index: self.message.proposer_index,
                parent_root: self.message.parent_root,
                state_root: self.message.state_root,
                body_root: self.message.body.tree_hash_root(),
            },
            signature: self.signature,
        }
    }

    fn kzg_commitments_slice(&self) -> Vec<pharos_types::deneb::KZGCommitment> {
        self.message.body.blob_kzg_commitments.as_slice().to_vec()
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

// ── build_sync_contribution ─────────────────────────────────────────────────

/// Build one subcommittee's `SyncCommitteeContribution` data from the pool for
/// `(slot, beacon_block_root, subcommittee_index)`, using the head state's
/// current sync committee for pubkey→position mapping. Returns the set bit
/// positions WITHIN the subcommittee and the aggregate signature, or `None`
/// when no pooled message matches. Non-draining (the GET must not consume
/// messages a later block drain needs). Backs
/// `GET /eth/v1/validator/sync_committee_contribution`.
pub fn build_sync_contribution<E: EthSpec>(
    fc_store: &Arc<RwLock<FcStore<E>>>,
    pools: &OperationPools<E>,
    slot: Slot,
    beacon_block_root: Root,
    subcommittee_index: u64,
) -> Option<(Vec<usize>, BLSSignature)>
where
    E::BeaconState: Clone,
{
    let state = {
        let store = fc_store.read();
        let head_root = get_head::<E>(&store);
        store.block_states.get(&head_root).cloned()?
    };
    let (committee_pubkeys, _) = state.sync_committee_pubkeys().unwrap_or_default();
    if committee_pubkeys.is_empty() {
        return None;
    }
    let subc_size = E::SYNC_SUBCOMMITTEE_SIZE as usize;
    let start = subcommittee_index as usize * subc_size;
    if start >= committee_pubkeys.len() {
        return None;
    }
    let end = (start + subc_size).min(committee_pubkeys.len());
    let subc = &committee_pubkeys[start..end];
    let validator_pubkey =
        |idx: u64| -> Option<[u8; 48]> { state.validator(idx as usize).map(|v| v.pubkey.into()) };
    pools.contribution_for(
        slot,
        subcommittee_index,
        beacon_block_root,
        subc,
        validator_pubkey,
    )
}

// ── build_blob_sidecars ───────────────────────────────────────────────────────

/// Build the full `Vec<BlobSidecar>` from a `BlobsBundleV1` returned by
/// `getPayloadV3` and the assembled, sealed Deneb signed block.
///
/// Each sidecar carries:
/// - `index` — position in `blob_kzg_commitments`
/// - `blob` — 131072-byte blob decoded from the bundle hex string
/// - `kzg_commitment` — decoded from the bundle
/// - `kzg_proof` — decoded from the bundle
/// - `signed_block_header` — from the sealed block (state_root already set)
/// - `kzg_commitment_inclusion_proof` — 17-element proof built via
///   `build_blob_sidecar_inclusion_proof`
///
/// Sidecars with decode errors are silently skipped (defensive; the engine
/// is trusted to produce well-formed hex and the commitments already passed
/// the block assembly validation).
pub fn build_blob_sidecars<E: EthSpec>(
    block: &E::DenebSignedBeaconBlock,
    blobs_bundle: BlobsBundleV1,
) -> Vec<pharos_types::deneb::BlobSidecar>
where
    E::DenebSignedBeaconBlock: DenebBlockAssembler<E>,
{
    use pharos_ssz::SszVector;
    use pharos_types::deneb::{BlobSidecar, blob::BYTES_PER_BLOB};

    let all_commitments = block.kzg_commitments_slice();
    let body_field_hashes = block.body_field_hashes();
    let signed_block_header = block.signed_block_header();

    let n = blobs_bundle
        .blobs
        .len()
        .min(blobs_bundle.commitments.len())
        .min(blobs_bundle.proofs.len());

    let mut sidecars = Vec::with_capacity(n);
    for i in 0..n {
        // Decode blob bytes (131072 bytes = 262144 hex chars + "0x").
        let blob_bytes = match hex_data_to_bytes(&blobs_bundle.blobs[i]) {
            Some(b) if b.len() == BYTES_PER_BLOB as usize => b,
            _ => continue,
        };
        let blob = match SszVector::<u8, BYTES_PER_BLOB>::from_items(blob_bytes) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Decode KZG commitment (48 bytes).
        let commitment = match hex_data_to_bytes(&blobs_bundle.commitments[i])
            .and_then(|b| <[u8; 48]>::try_from(b).ok())
        {
            Some(arr) => pharos_types::deneb::KZGCommitment::from_array(arr),
            None => continue,
        };

        // Decode KZG proof (48 bytes).
        let proof = match hex_data_to_bytes(&blobs_bundle.proofs[i])
            .and_then(|b| <[u8; 48]>::try_from(b).ok())
        {
            Some(arr) => pharos_types::deneb::KZGProof::from_array(arr),
            None => continue,
        };

        // Build the 17-element inclusion proof.
        let proof_arr = build_blob_sidecar_inclusion_proof(&all_commitments, &body_field_hashes, i);
        let kzg_commitment_inclusion_proof = match SszVector::from_items(proof_arr.iter().copied())
        {
            Ok(v) => v,
            Err(_) => continue,
        };

        sidecars.push(BlobSidecar {
            index: i as u64,
            blob,
            kzg_commitment: commitment,
            kzg_proof: proof,
            signed_block_header: signed_block_header.clone(),
            kzg_commitment_inclusion_proof,
        });
    }
    sidecars
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
// Block production legitimately needs all of these inputs; a param struct would
// add indirection without clarifying the call site.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn produce_block<E: EthSpec>(
    fc_store: &Arc<RwLock<FcStore<E>>>,
    pools: &OperationPools<E>,
    engine: &EngineHandle,
    slot: Slot,
    randao_reveal: BLSSignature,
    graffiti: [u8; 32],
    fee_recipient: String,
    runtime_cfg: &RuntimeConfig,
) -> Result<
    (
        E::SignedBeaconBlock,
        E::BeaconState,
        pharos_utils::Uint256,
        Vec<pharos_types::deneb::BlobSidecar>,
    ),
    ProduceError,
>
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
        + CapellaUpgradeDispatch<E>
        + GetExpectedWithdrawalsDispatch<E>,
    E::DenebBeaconState: DenebProcessBlockForProduction<E, ExecutionEngineHandle>
        + TreeHash
        + DenebProcessSlotsDispatch<E>
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
    E::DenebSignedBeaconBlock: DenebBlockAssembler<E>,
    E::CapellaExecutionPayload:
        TryFrom<pharos_engine::types::ExecutionPayloadV2, Error = pharos_engine::EngineError>,
    E::ExecutionPayload:
        TryFrom<pharos_engine::types::ExecutionPayloadV1, Error = pharos_engine::EngineError>,
    E::DenebExecutionPayload:
        TryFrom<pharos_engine::types::ExecutionPayloadV3, Error = pharos_engine::EngineError>,
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
            Ok((
                block_inner.into_signed_block(),
                post_state,
                exec_value,
                vec![],
            ))
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
                vec![],
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
                vec![],
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

        // ── Deneb: V3 execution payload + blob KZG commitments ───────────────
        ForkVariant::Deneb => {
            // ── Step (d): Drain sync aggregate ────────────────────────────────
            let (sync_bits, sync_sig) = pools.drain_sync_aggregate_raw(
                sync_agg_slot,
                parent_root,
                &committee_pubkeys_cur,
                validator_pubkey_fn,
            );

            // ── Step (e): Prepare execution payload (V3) ──────────────────────
            // `parent_beacon_block_root` = hash_tree_root(state.latest_block_header)
            // per `specs/deneb/validator.md:136`.
            let parent_beacon_block_root = state.latest_block_header().tree_hash_root();
            let deneb_inner = E::into_deneb_state(state.clone()).ok_or(ProduceError::WrongFork)?;
            // Compute expected withdrawals from the deneb state. The Deneb state carries
            // the same withdrawal fields as Capella (next_withdrawal_index,
            // next_withdrawal_validator_index, validators, balances). We obtain the
            // list via GetExpectedWithdrawalsDispatch on the deneb inner state.
            let withdrawals_v1: Vec<pharos_engine::types::WithdrawalV1> = deneb_inner
                .get_expected_withdrawals_dispatch()
                .into_iter()
                .map(|w| pharos_engine::types::WithdrawalV1 {
                    index: format!("0x{:x}", w.index),
                    validator_index: format!("0x{:x}", w.validator_index.0),
                    address: bytes_to_data_hex(w.address.as_slice()),
                    amount: format!("0x{:x}", w.amount.0),
                })
                .collect();
            let attrs = build_payload_attributes_v3::<E>(
                &state,
                withdrawals_v1,
                slot,
                fee_recipient,
                parent_beacon_block_root,
                runtime_cfg,
            );
            let fcu_state = build_fcu_state::<E>(fc_store, head_root);
            let (wire_payload, blobs_bundle, exec_value) =
                prepare_execution_payload_v3(engine, fcu_state, attrs)
                    .map_err(ProduceError::from)?;

            // Decode `blob_kzg_commitments` from the BlobsBundleV1.
            // Each commitment is a 0x-prefixed 96-hex-char (48-byte) DATA string.
            // Fail fast on any decode error: commitments must stay in 1:1
            // correspondence with the bundle's blobs/proofs, and a silently
            // dropped commitment would desync sidecar inclusion-proof indexing
            // (and panic the proof builder).
            let blob_kzg_commitments: Vec<pharos_types::deneb::KZGCommitment> = blobs_bundle
                .commitments
                .iter()
                .map(|hex| {
                    let bytes = hex_data_to_bytes(hex).ok_or_else(|| {
                        ProduceError::Engine(format!("bad commitment hex: {hex}"))
                    })?;
                    let arr: [u8; 48] = bytes
                        .try_into()
                        .map_err(|_| ProduceError::Engine("commitment not 48 bytes".into()))?;
                    Ok(pharos_types::deneb::KZGCommitment::from_array(arr))
                })
                .collect::<Result<Vec<_>, ProduceError>>()?;

            let execution_payload: E::DenebExecutionPayload = wire_payload
                .try_into()
                .map_err(|e: pharos_engine::EngineError| ProduceError::Engine(e.to_string()))?;

            // ── Step (f): Drain operations ────────────────────────────────────
            let block_ops = pools.drain_for_block(slot.0);

            // ── Step (g): Assemble block ──────────────────────────────────────
            let mut block_inner = E::DenebSignedBeaconBlock::assemble(
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
                blob_kzg_commitments,
            )?;

            // ── Step (h): Run STF ─────────────────────────────────────────────
            let block_enum = E::deneb_into_block(block_inner.message_clone());
            let ee = ExecutionEngineHandle::new(engine.clone());
            let post_state = process_block_for_production::<E, ExecutionEngineHandle>(
                state,
                &block_enum,
                &ee,
                runtime_cfg,
            )?;

            // ── Step (i): Seal with state_root ────────────────────────────────
            block_inner.set_state_root(post_state.tree_hash_root());

            // ── Step (j): Build blob sidecars ─────────────────────────────────
            // Must happen AFTER set_state_root so signed_block_header.state_root
            // and body_root are correct in the sidecar headers.
            let blob_sidecars = build_blob_sidecars::<E>(&block_inner, blobs_bundle);

            let _ = deneb_inner; // state was consumed by process_block_for_production
            Ok((
                block_inner.into_signed_block(),
                post_state,
                exec_value,
                blob_sidecars,
            ))
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
    E::CapellaBeaconState: CapellaProcessSlotsDispatch<E> + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: DenebProcessSlotsDispatch<E>,
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
    E::CapellaBeaconState: CapellaProcessSlotsDispatch<E> + CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: DenebProcessSlotsDispatch<E>,
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
