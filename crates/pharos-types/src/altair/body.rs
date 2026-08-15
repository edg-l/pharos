//! Altair `BeaconBlockBody` container.
//!
//! Per `specs/altair/beacon-chain.md:143-156` (Modified containers →
//! BeaconBlockBody). Extends phase0 with `sync_aggregate`.

use pharos_ssz::{Decode, Encode, SszList, TreeHash};
use pharos_utils::{BLSSignature, Bytes32};

use crate::altair::operations::SyncAggregate;
use crate::phase0::misc::Eth1Data;
use crate::phase0::operations::{
    Attestation, AttesterSlashing, Deposit, ProposerSlashing, SignedVoluntaryExit,
};
use crate::views::BeaconBlockBodyView;

// ── BeaconBlockBody ───────────────────────────────────────────────────────────

/// Altair `BeaconBlockBody` per `specs/altair/beacon-chain.md:143-156`.
///
/// Extends the phase0 body with `sync_aggregate: SyncAggregate`.
/// Generic over operation list limits (same as phase0) plus `SYNC_COMMITTEE_SIZE`.
///
/// Use the preset-specific type aliases:
/// - `MainnetBeaconBlockBody` (all mainnet limits)
/// - `MinimalBeaconBlockBody` (all minimal limits)
#[allow(clippy::too_many_arguments)]
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlockBody<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> {
    /// `randao_reveal: BLSSignature` — `specs/altair/beacon-chain.md:144`.
    pub randao_reveal: BLSSignature,
    /// `eth1_data: Eth1Data` — `specs/altair/beacon-chain.md:145`.
    pub eth1_data: Eth1Data,
    /// `graffiti: Bytes32` — `specs/altair/beacon-chain.md:146`.
    pub graffiti: Bytes32,
    /// `proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]`
    /// — `specs/altair/beacon-chain.md:147`.
    pub proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    /// `attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]`
    /// — `specs/altair/beacon-chain.md:148`.
    pub attester_slashings:
        SszList<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTER_SLASHINGS>,
    /// `attestations: List[Attestation, MAX_ATTESTATIONS]`
    /// — `specs/altair/beacon-chain.md:149`.
    pub attestations: SszList<Attestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTATIONS>,
    /// `deposits: List[Deposit, MAX_DEPOSITS]`
    /// — `specs/altair/beacon-chain.md:150`.
    pub deposits: SszList<Deposit<DEPOSIT_PROOF_LENGTH>, MAX_DEPOSITS>,
    /// `voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]`
    /// — `specs/altair/beacon-chain.md:151`.
    pub voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    /// `sync_aggregate: SyncAggregate` — `specs/altair/beacon-chain.md:153`
    /// ([New in Altair]).
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
}

// ── BeaconBlockBodyView impl ──────────────────────────────────────────────────

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
> BeaconBlockBodyView
    for BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >
{
    type Attestation = Attestation<MAX_VALIDATORS_PER_COMMITTEE>;
    type AttesterSlashing = AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>;
    type Deposit = Deposit<DEPOSIT_PROOF_LENGTH>;

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

#[cfg(test)]
mod tests {
    use pharos_ssz::{Decode, Encode};

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(val: T) {
        let encoded = val.as_ssz_bytes();
        let decoded = T::from_ssz_bytes(&encoded).expect("SSZ decode failed");
        assert_eq!(val, decoded);
    }

    #[test]
    fn beacon_block_body_mainnet_roundtrip() {
        roundtrip(crate::altair::MainnetBeaconBlockBody::default());
    }

    #[test]
    fn beacon_block_body_minimal_roundtrip() {
        roundtrip(crate::altair::MinimalBeaconBlockBody::default());
    }
}
