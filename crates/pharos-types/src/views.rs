//! Accessor traits for beacon-chain block containers.
//!
//! STF code is generic over `<E: EthSpec>` and receives `E::BeaconBlock`,
//! `E::BeaconBlockBody`, etc. as opaque associated types. These traits
//! expose the fields needed by the state transition function without forcing
//! STF call sites to name the concrete const-generic preset aliases.
//!
//! ## Implementation note — why `E` is absent from the view traits
//!
//! The plan's D8 specifies `type E: EthSpec` on each view trait and a
//! `BeaconBlockView<E = Self>` back-reference on `EthSpec::BeaconBlock`.
//! Both approach (A) (one impl per preset alias) and approach (B) (blanket
//! impl with `E: EthSpec<BeaconBlockBody = Self>`) fail on stable Rust 1.85:
//!
//! - (A): mainnet and minimal phase0 presets expand to identical const params
//!   (`BeaconBlockBody<16,2,128,16,16,2048,33>`), so the two impl blocks are
//!   duplicate impl E0119.
//! - (B): the `E` type parameter is unconstrained by the impl self-type
//!   (E0207), because `BeaconBlockBody<P1..P7>` does not uniquely determine
//!   `E`.
//!
//! Solution: remove `type E` from the view traits. The traits become pure
//! field-accessor interfaces with element associated types for the preset-
//! specific container types. The `EthSpec` bounds on `BeaconBlock` etc. drop
//! the `<E = Self>` constraint.  STF code still uses `<E: EthSpec>` at every
//! function boundary; the view traits supply the field-access layer.
//!
//! Defined per `specs/phase0/beacon-chain.md:534-614`.

use crate::altair::light_client::{LightClientFinalityUpdate, LightClientOptimisticUpdate};
use crate::phase0;
use crate::phase0::{
    BLSSignature, BeaconBlockHeader, Checkpoint, Eth1Data, Fork, ProposerSlashing, Root,
    SignedVoluntaryExit, Slot, Validator, ValidatorIndex,
};
use pharos_ssz::{SszError, SszSequence};
use pharos_utils::{Bytes32, Gwei, Hash256};

/// `(current_sync_committee_pubkeys, next_sync_committee_pubkeys)`, each a list
/// of 48-byte BLS public keys. Returned by [`BeaconStateView::sync_committee_pubkeys`]
/// and the Beacon API `sync_committees` endpoint.
pub type SyncCommitteePubkeys = (Vec<[u8; 48]>, Vec<[u8; 48]>);

// ── ForkVariant ───────────────────────────────────────────────────────────────

/// Identifies which fork a `BeaconState` (or block) belongs to.
///
/// Used by `BeaconStateView::fork_variant()` so that STF dispatch code can
/// branch on the fork without needing to pattern-match on the opaque
/// `E::BeaconState` associated type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkVariant {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
}

// ── SignedContributionAndProofView ────────────────────────────────────────────

/// Read-only accessors for `SignedContributionAndProof<SYNC_SUBCOMMITTEE_SIZE>`.
///
/// Replaces direct field access for generic gossip-validator code that cannot
/// name the const-generic `SYNC_SUBCOMMITTEE_SIZE` (= mainnet 128 / minimal 8).
///
/// Implemented by the blanket impl below over all concrete
/// `SignedContributionAndProof<N>`.
pub trait SignedContributionAndProofView {
    /// `contribution.slot`
    fn contribution_slot(&self) -> Slot;
    /// `contribution.beacon_block_root`
    fn contribution_beacon_block_root(&self) -> Root;
    /// `contribution.subcommittee_index`
    fn contribution_subcommittee_index(&self) -> u64;
    /// `contribution.aggregation_bits` materialized as a `Vec<bool>` (one entry
    /// per subcommittee slot).  No const-generic needed by the caller.
    fn contribution_aggregation_bits(&self) -> Vec<bool>;
    /// `contribution.signature`
    fn contribution_signature(&self) -> &BLSSignature;
    /// `message.aggregator_index`
    fn aggregator_index(&self) -> ValidatorIndex;
    /// `message.selection_proof`
    fn selection_proof(&self) -> &BLSSignature;
    /// `tree_hash_root(message)` — used by the gossip validator to compute the
    /// signing root of the `ContributionAndProof` without naming the generic type.
    fn message_tree_hash_root(&self) -> Root;
    /// `signature` — the outer signed wrapper signature.
    fn outer_signature(&self) -> &BLSSignature;
}

impl<const N: u64> SignedContributionAndProofView for crate::altair::SignedContributionAndProof<N> {
    fn contribution_slot(&self) -> Slot {
        self.message.contribution.slot
    }
    fn contribution_beacon_block_root(&self) -> Root {
        self.message.contribution.beacon_block_root
    }
    fn contribution_subcommittee_index(&self) -> u64 {
        self.message.contribution.subcommittee_index
    }
    fn contribution_aggregation_bits(&self) -> Vec<bool> {
        self.message.contribution.aggregation_bits.iter().collect()
    }
    fn contribution_signature(&self) -> &BLSSignature {
        &self.message.contribution.signature
    }
    fn aggregator_index(&self) -> ValidatorIndex {
        self.message.aggregator_index
    }
    fn selection_proof(&self) -> &BLSSignature {
        &self.message.selection_proof
    }
    fn message_tree_hash_root(&self) -> Root {
        use pharos_ssz::TreeHash as _;
        self.message.tree_hash_root()
    }
    fn outer_signature(&self) -> &BLSSignature {
        &self.signature
    }
}

// ── BeaconBlockBodyView ───────────────────────────────────────────────────────

/// Read-only accessors for `BeaconBlockBody` fields.
///
/// Element associated types (`Attestation`, `AttesterSlashing`, `Deposit`)
/// are used instead of const-generic return positions to avoid the unstable
/// `generic_const_exprs` feature, which is blocked by MSRV 1.85.
pub trait BeaconBlockBodyView {
    /// Concrete attestation type (e.g. `phase0::Attestation<2048>`).
    type Attestation;
    /// Concrete attester-slashing type (e.g. `phase0::AttesterSlashing<2048>`).
    type AttesterSlashing;
    /// Concrete deposit type (e.g. `phase0::Deposit<33>`).
    type Deposit;

    fn randao_reveal(&self) -> &BLSSignature;
    fn eth1_data(&self) -> &Eth1Data;
    fn graffiti(&self) -> &Bytes32;
    fn proposer_slashings(&self) -> &[ProposerSlashing];
    fn attester_slashings(&self) -> &[Self::AttesterSlashing];
    fn attestations(&self) -> &[Self::Attestation];
    fn deposits(&self) -> &[Self::Deposit];
    fn voluntary_exits(&self) -> &[SignedVoluntaryExit];

    /// Return the execution payload `block_hash` for Bellatrix+ bodies.
    ///
    /// Phase0 and Altair bodies return `None` (no execution payload).
    /// Default impl returns `None`; overridden in bellatrix/capella body impls.
    fn execution_block_hash(&self) -> Option<[u8; 32]> {
        None
    }

    /// Return the number of KZG commitments in the block body for Deneb+ bodies.
    ///
    /// Pre-Deneb bodies return `0` (no blob_kzg_commitments field).
    /// Overridden in the Deneb body impl.
    /// Used by the gossip validator C2 rule: REJECT if count > MAX_BLOBS_PER_BLOCK.
    fn num_blob_kzg_commitments(&self) -> usize {
        0
    }

    /// Return the `blob_kzg_commitments` slice for Deneb+ block bodies.
    ///
    /// Pre-Deneb bodies return an empty slice. Overridden in the Deneb body impl
    /// and in the fork-enum body `state.rs`. Used by the DA gate in `import_block`
    /// to extract commitments ONCE before passing to `DataAvailabilityChecker`
    /// (per W6: caller extracts, trait impl receives `&[KZGCommitment]`).
    fn blob_kzg_commitments_slice(&self) -> &[crate::deneb::KZGCommitment] {
        &[]
    }
}

// ── BeaconBlockView ───────────────────────────────────────────────────────────

/// Read-only accessors for `BeaconBlock` fields.
pub trait BeaconBlockView {
    type Body: BeaconBlockBodyView + pharos_ssz::TreeHash;

    fn slot(&self) -> Slot;
    fn proposer_index(&self) -> ValidatorIndex;
    fn parent_root(&self) -> Root;
    fn state_root(&self) -> Root;
    fn body(&self) -> &Self::Body;
}

// ── SignedBeaconBlockView ─────────────────────────────────────────────────────

/// Read-only accessors for `SignedBeaconBlock` fields.
pub trait SignedBeaconBlockView {
    type Message: BeaconBlockView;

    fn message(&self) -> &Self::Message;
    fn signature(&self) -> &BLSSignature;
}

// ── LightClientFinalityUpdateView ─────────────────────────────────────────────

/// Accessor trait for `LightClientFinalityUpdate` fields needed by gossip validation.
///
/// Allows gossip-validator code to remain generic over `E::AltairLightClientFinalityUpdate`
/// without naming the concrete const-generic preset alias.
pub trait LightClientFinalityUpdateView {
    /// `finalized_header.beacon.slot` — the monotonic-guard field for the
    /// `light_client_finality_update` gossip topic per
    /// `specs/altair/light-client/p2p-interface.md`.
    fn finalized_header_slot(&self) -> u64;
    /// `signature_slot` — used for the clock-window timing check.
    fn finality_signature_slot(&self) -> u64;
}

// ── LightClientOptimisticUpdateView ───────────────────────────────────────────

/// Accessor trait for `LightClientOptimisticUpdate` fields needed by gossip validation.
///
/// Allows gossip-validator code to remain generic over `E::AltairLightClientOptimisticUpdate`.
pub trait LightClientOptimisticUpdateView {
    /// `attested_header.beacon.slot` — the monotonic-guard field for the
    /// `light_client_optimistic_update` gossip topic per
    /// `specs/altair/light-client/p2p-interface.md`.
    fn optimistic_attested_slot(&self) -> u64;
    /// `signature_slot` — used for the clock-window timing check.
    fn optimistic_signature_slot(&self) -> u64;
}

// ── PendingAttestationRaw ─────────────────────────────────────────────────────

/// Raw field data from a `PendingAttestation`, avoiding const-generic type params.
pub struct PendingAttestationRaw {
    /// SSZ-encoded `aggregation_bits` Bitlist bytes (includes sentinel bit).
    pub aggregation_bits_ssz: Vec<u8>,
    pub data_slot: u64,
    pub data_index: u64,
    pub data_beacon_block_root: [u8; 32],
    pub data_source_epoch: u64,
    pub data_source_root: [u8; 32],
    pub data_target_epoch: u64,
    pub data_target_root: [u8; 32],
    pub inclusion_delay: u64,
    pub proposer_index: u64,
}

// ── ExecutionPayloadHeaderRaw ─────────────────────────────────────────────────

/// Raw field data from a `ExecutionPayloadHeader`, usable without a type parameter.
///
/// Used by `BeaconStateView::execution_payload_header_raw` so the debug-state
/// JSON serializer in `pharos-api` can produce the header object without
/// naming the const-generic header type.
pub struct ExecutionPayloadHeaderRaw {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: Vec<u8>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    /// Little-endian 32-byte representation of `base_fee_per_gas` (Uint256).
    pub base_fee_per_gas_le: [u8; 32],
    pub block_hash: [u8; 32],
    pub transactions_root: [u8; 32],
}

// ── BeaconStateView ───────────────────────────────────────────────────────────

/// Read-only accessors for `BeaconState` fields.
///
/// Exposes the subset of `BeaconState` fields needed by the STF accessors.
/// Collection fields are exposed as slices so the concrete const-generic
/// parameter does not appear at call sites.
pub trait BeaconStateView {
    /// Returns the fork variant of this state.
    ///
    /// Allows STF dispatch code to branch on the fork via the opaque
    /// `E::BeaconState` associated type (pattern-matching on a concrete enum
    /// through an associated type is not permitted on stable Rust 1.85).
    fn fork_variant(&self) -> ForkVariant;

    fn genesis_time(&self) -> u64;
    fn genesis_validators_root(&self) -> Root;
    fn slot(&self) -> Slot;
    fn fork(&self) -> &Fork;
    fn latest_block_header(&self) -> &BeaconBlockHeader;
    fn validators(&self) -> Vec<Validator>;
    /// Borrowing iterator over validators (no Vec materialization).
    fn validators_iter(&self) -> Box<dyn Iterator<Item = &Validator> + '_>;
    /// Borrowing access to a single validator by index (O(log N) on tree backend).
    fn validator(&self, idx: usize) -> Option<&Validator>;
    /// Number of validators (cheap on both Naive and Tree backends).
    fn num_validators(&self) -> usize;
    fn balances(&self) -> &[Gwei];
    fn block_roots(&self) -> Vec<Root>;
    /// Direct indexed block-root lookup (no Vec materialization).
    fn block_root_at(&self, idx: usize) -> Option<Root>;
    fn state_roots(&self) -> Vec<Root>;
    fn state_root_at(&self, idx: usize) -> Option<Root>;
    fn randao_mixes(&self) -> Vec<Hash256>;
    fn randao_mix_at(&self, idx: usize) -> Option<Hash256>;
    fn slashings(&self) -> &[Gwei];
    fn eth1_data(&self) -> &Eth1Data;
    /// `eth1_data_votes` as a materialized vec; needed by the debug-state JSON serializer.
    fn eth1_data_votes(&self) -> Vec<Eth1Data>;
    fn eth1_deposit_index_u64(&self) -> u64;
    fn historical_roots(&self) -> Vec<Root>;
    /// SSZ-encoded `justification_bits` bitvector bytes (for 0x-prefixed hex output).
    fn justification_bits_bytes(&self) -> Vec<u8>;
    fn previous_justified_checkpoint(&self) -> &Checkpoint;
    fn current_justified_checkpoint(&self) -> &Checkpoint;
    fn finalized_checkpoint(&self) -> &Checkpoint;

    /// Clear the cached top-level Merkle root.  STF entrypoints must call this
    /// after mutating any field; otherwise a subsequent `cached_tree_hash_root`
    /// call would return a stale value.
    fn invalidate_root_cache(&mut self);

    /// Return the current and next sync committee pubkeys as 48-byte arrays,
    /// or `None` for Phase0 states (which have no sync committee).
    ///
    /// Used by the Beacon API `sync_committees` endpoint to serve committee
    /// data without requiring the API layer to match on concrete enum variants.
    /// Default impl returns `None`; overridden on Altair/Bellatrix/Capella states.
    fn sync_committee_pubkeys(&self) -> Option<SyncCommitteePubkeys> {
        None
    }

    // ── Per-fork data accessors for the debug-state JSON serializer ───────────
    //
    // Default implementations return empty/None (Phase0 baseline).
    // Altair/Bellatrix/Capella states override as appropriate.

    /// Altair+ `previous_epoch_participation` as a vec of u8 flag bytes.
    /// Phase0 returns an empty vec.
    fn previous_epoch_participation_u8s(&self) -> Vec<u8> {
        vec![]
    }

    /// Altair+ `current_epoch_participation` as a vec of u8 flag bytes.
    /// Phase0 returns an empty vec.
    fn current_epoch_participation_u8s(&self) -> Vec<u8> {
        vec![]
    }

    /// Altair+ `inactivity_scores` as a vec of u64 values.
    /// Phase0 returns an empty vec.
    fn inactivity_scores_u64s(&self) -> Vec<u64> {
        vec![]
    }

    /// Altair+ aggregate pubkeys for current and next sync committee
    /// as raw 48-byte arrays, or `None` for Phase0.
    fn sync_committee_aggregate_pubkeys(&self) -> Option<([u8; 48], [u8; 48])> {
        None
    }

    /// Phase0 `previous_epoch_attestations` as raw structs.
    ///
    /// Returns `Some` only for Phase0 states; Altair+ returns `None`.
    fn previous_epoch_attestations_raw(&self) -> Option<Vec<PendingAttestationRaw>> {
        None
    }

    /// Phase0 `current_epoch_attestations` as raw structs.
    fn current_epoch_attestations_raw(&self) -> Option<Vec<PendingAttestationRaw>> {
        None
    }

    /// Bellatrix+ execution payload header fields as raw Rust primitives.
    ///
    /// Returns `None` for Phase0/Altair states.
    fn execution_payload_header_raw(&self) -> Option<ExecutionPayloadHeaderRaw> {
        None
    }

    /// Capella+ `next_withdrawal_index`, or `None` for earlier forks.
    fn next_withdrawal_index_u64(&self) -> Option<u64> {
        None
    }

    /// Capella+ `next_withdrawal_validator_index` as a u64, or `None`.
    fn next_withdrawal_validator_index_raw(&self) -> Option<u64> {
        None
    }

    /// Capella+ `withdrawals_root` on the execution payload header, or `None`.
    fn execution_payload_withdrawals_root(&self) -> Option<[u8; 32]> {
        None
    }

    /// Capella+ `historical_summaries` as pairs of (block_summary_root, state_summary_root).
    fn historical_summaries_raw(&self) -> Option<Vec<([u8; 32], [u8; 32])>> {
        None
    }

    /// Flip the seven hot list/vector fields (`validators`, `historical_roots`,
    /// `state_roots`, `block_roots`, `randao_mixes`, `previous/current_epoch_attestations`)
    /// from `Backend::Naive` to `Backend::Tree`. Live-node entry points
    /// (`Store::get_state`, `apply_anchor`, backfill genesis anchor write,
    /// genesis init) must call this after SSZ-decoding or constructing a fresh
    /// `BeaconState`; the decode path itself leaves states `Naive` per
    /// `D-no-tree-backend-on-decode`.
    fn into_tree_backend(self) -> Result<Self, SszError>
    where
        Self: Sized;
}

// ── Blanket impls over the generic phase0 structs ─────────────────────────────
//
// A single impl per trait, generic over all const params. Because all the
// const params are fully determined by the `Self` type, these impls are
// unambiguous and satisfy the coherence rules.

impl<
    const P1: u64,
    const P2: u64,
    const P3: u64,
    const P4: u64,
    const P5: u64,
    const P6: u64,
    const P7: u64,
> BeaconBlockBodyView for phase0::BeaconBlockBody<P1, P2, P3, P4, P5, P6, P7>
{
    type Attestation = phase0::Attestation<P6>;
    type AttesterSlashing = phase0::AttesterSlashing<P6>;
    type Deposit = phase0::Deposit<P7>;

    fn randao_reveal(&self) -> &BLSSignature {
        &self.randao_reveal
    }
    fn eth1_data(&self) -> &Eth1Data {
        &self.eth1_data
    }
    fn graffiti(&self) -> &Bytes32 {
        &self.graffiti
    }
    fn proposer_slashings(&self) -> &[ProposerSlashing] {
        self.proposer_slashings.as_slice()
    }
    fn attester_slashings(&self) -> &[Self::AttesterSlashing] {
        self.attester_slashings.as_slice()
    }
    fn attestations(&self) -> &[Self::Attestation] {
        self.attestations.as_slice()
    }
    fn deposits(&self) -> &[Self::Deposit] {
        self.deposits.as_slice()
    }
    fn voluntary_exits(&self) -> &[SignedVoluntaryExit] {
        self.voluntary_exits.as_slice()
    }
}

impl<
    const P1: u64,
    const P2: u64,
    const P3: u64,
    const P4: u64,
    const P5: u64,
    const P6: u64,
    const P7: u64,
> BeaconBlockView for phase0::BeaconBlock<P1, P2, P3, P4, P5, P6, P7>
{
    type Body = phase0::BeaconBlockBody<P1, P2, P3, P4, P5, P6, P7>;

    fn slot(&self) -> Slot {
        self.slot
    }
    fn proposer_index(&self) -> ValidatorIndex {
        self.proposer_index
    }
    fn parent_root(&self) -> Root {
        self.parent_root
    }
    fn state_root(&self) -> Root {
        self.state_root
    }
    fn body(&self) -> &Self::Body {
        &self.body
    }
}

impl<
    const P1: u64,
    const P2: u64,
    const P3: u64,
    const P4: u64,
    const P5: u64,
    const P6: u64,
    const P7: u64,
> SignedBeaconBlockView for phase0::SignedBeaconBlock<P1, P2, P3, P4, P5, P6, P7>
{
    type Message = phase0::BeaconBlock<P1, P2, P3, P4, P5, P6, P7>;

    fn message(&self) -> &Self::Message {
        &self.message
    }
    fn signature(&self) -> &BLSSignature {
        &self.signature
    }
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
> BeaconStateView
    for phase0::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        MAX_VALIDATORS_PER_COMMITTEE,
    >
{
    fn fork_variant(&self) -> ForkVariant {
        ForkVariant::Phase0
    }

    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }
    fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }
    fn slot(&self) -> Slot {
        self.slot
    }
    fn fork(&self) -> &Fork {
        &self.fork
    }
    fn latest_block_header(&self) -> &BeaconBlockHeader {
        &self.latest_block_header
    }
    fn validators(&self) -> Vec<Validator> {
        self.validators.iter().cloned().collect()
    }
    fn validators_iter(&self) -> Box<dyn Iterator<Item = &Validator> + '_> {
        Box::new(self.validators.iter())
    }
    fn validator(&self, idx: usize) -> Option<&Validator> {
        self.validators.get(idx)
    }
    fn num_validators(&self) -> usize {
        self.validators.len()
    }
    fn balances(&self) -> &[Gwei] {
        self.balances.as_slice()
    }
    fn block_roots(&self) -> Vec<Root> {
        self.block_roots.iter().cloned().collect()
    }
    fn block_root_at(&self, idx: usize) -> Option<Root> {
        self.block_roots.get(idx).copied()
    }
    fn state_roots(&self) -> Vec<Root> {
        self.state_roots.iter().cloned().collect()
    }
    fn state_root_at(&self, idx: usize) -> Option<Root> {
        self.state_roots.get(idx).copied()
    }
    fn randao_mixes(&self) -> Vec<Hash256> {
        self.randao_mixes.iter().cloned().collect()
    }
    fn randao_mix_at(&self, idx: usize) -> Option<Hash256> {
        self.randao_mixes.get(idx).copied()
    }
    fn slashings(&self) -> &[Gwei] {
        self.slashings.as_slice()
    }
    fn eth1_data(&self) -> &Eth1Data {
        &self.eth1_data
    }
    fn eth1_data_votes(&self) -> Vec<Eth1Data> {
        self.eth1_data_votes.iter().cloned().collect()
    }
    fn eth1_deposit_index_u64(&self) -> u64 {
        self.eth1_deposit_index
    }
    fn historical_roots(&self) -> Vec<Root> {
        self.historical_roots.iter().cloned().collect()
    }
    fn justification_bits_bytes(&self) -> Vec<u8> {
        use pharos_ssz::Encode as _;
        self.justification_bits.as_ssz_bytes()
    }
    fn previous_justified_checkpoint(&self) -> &Checkpoint {
        &self.previous_justified_checkpoint
    }
    fn current_justified_checkpoint(&self) -> &Checkpoint {
        &self.current_justified_checkpoint
    }
    fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }
    fn invalidate_root_cache(&mut self) {
        self.cached_root.invalidate();
    }
    fn into_tree_backend(self) -> Result<Self, SszError> {
        phase0::BeaconState::into_tree_backend(self)
    }

    fn previous_epoch_attestations_raw(&self) -> Option<Vec<PendingAttestationRaw>> {
        use pharos_ssz::Encode as _;
        Some(
            self.previous_epoch_attestations
                .iter()
                .map(|pa| PendingAttestationRaw {
                    aggregation_bits_ssz: pa.aggregation_bits.as_ssz_bytes(),
                    data_slot: pa.data.slot.0,
                    data_index: pa.data.index.0,
                    data_beacon_block_root: pa.data.beacon_block_root.into_inner(),
                    data_source_epoch: pa.data.source.epoch.0,
                    data_source_root: pa.data.source.root.into_inner(),
                    data_target_epoch: pa.data.target.epoch.0,
                    data_target_root: pa.data.target.root.into_inner(),
                    inclusion_delay: pa.inclusion_delay.0,
                    proposer_index: pa.proposer_index.0,
                })
                .collect(),
        )
    }

    fn current_epoch_attestations_raw(&self) -> Option<Vec<PendingAttestationRaw>> {
        use pharos_ssz::Encode as _;
        Some(
            self.current_epoch_attestations
                .iter()
                .map(|pa| PendingAttestationRaw {
                    aggregation_bits_ssz: pa.aggregation_bits.as_ssz_bytes(),
                    data_slot: pa.data.slot.0,
                    data_index: pa.data.index.0,
                    data_beacon_block_root: pa.data.beacon_block_root.into_inner(),
                    data_source_epoch: pa.data.source.epoch.0,
                    data_source_root: pa.data.source.root.into_inner(),
                    data_target_epoch: pa.data.target.epoch.0,
                    data_target_root: pa.data.target.root.into_inner(),
                    inclusion_delay: pa.inclusion_delay.0,
                    proposer_index: pa.proposer_index.0,
                })
                .collect(),
        )
    }
}

// ── Blanket impls for LC update accessor traits ───────────────────────────────

impl<const SYNC_COMMITTEE_SIZE: u64> LightClientFinalityUpdateView
    for LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>
{
    fn finalized_header_slot(&self) -> u64 {
        self.finalized_header.beacon.slot.0
    }
    fn finality_signature_slot(&self) -> u64 {
        self.signature_slot.0
    }
}

impl<const SYNC_COMMITTEE_SIZE: u64> LightClientOptimisticUpdateView
    for LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE>
{
    fn optimistic_attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
    fn optimistic_signature_slot(&self) -> u64 {
        self.signature_slot.0
    }
}
