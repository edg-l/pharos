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

use crate::phase0;
use crate::phase0::{
    BLSSignature, BeaconBlockHeader, Checkpoint, Eth1Data, Fork, ProposerSlashing, Root,
    SignedVoluntaryExit, Slot, Validator, ValidatorIndex,
};
use pharos_utils::{Bytes32, Gwei, Hash256};

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
}

// ── BeaconBlockView ───────────────────────────────────────────────────────────

/// Read-only accessors for `BeaconBlock` fields.
pub trait BeaconBlockView {
    type Body: BeaconBlockBodyView;

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
    fn validators(&self) -> &[Validator];
    fn balances(&self) -> &[Gwei];
    fn block_roots(&self) -> &[Root];
    fn state_roots(&self) -> &[Root];
    fn randao_mixes(&self) -> &[Hash256];
    fn slashings(&self) -> &[Gwei];
    fn eth1_data(&self) -> &Eth1Data;
    fn previous_justified_checkpoint(&self) -> &Checkpoint;
    fn current_justified_checkpoint(&self) -> &Checkpoint;
    fn finalized_checkpoint(&self) -> &Checkpoint;
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
    fn validators(&self) -> &[Validator] {
        self.validators.as_slice()
    }
    fn balances(&self) -> &[Gwei] {
        self.balances.as_slice()
    }
    fn block_roots(&self) -> &[Root] {
        self.block_roots.as_slice()
    }
    fn state_roots(&self) -> &[Root] {
        self.state_roots.as_slice()
    }
    fn randao_mixes(&self) -> &[Hash256] {
        self.randao_mixes.as_slice()
    }
    fn slashings(&self) -> &[Gwei] {
        self.slashings.as_slice()
    }
    fn eth1_data(&self) -> &Eth1Data {
        &self.eth1_data
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
}
