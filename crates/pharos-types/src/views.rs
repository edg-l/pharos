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
    BLSSignature, Eth1Data, ProposerSlashing, Root, SignedVoluntaryExit, Slot, ValidatorIndex,
};
use pharos_utils::Bytes32;

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
