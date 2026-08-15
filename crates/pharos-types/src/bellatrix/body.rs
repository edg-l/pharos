//! Bellatrix `BeaconBlockBody` container.
//!
//! Per `specs/bellatrix/beacon-chain.md:97-112` (Modified containers →
//! BeaconBlockBody). Extends altair with `execution_payload`.

use pharos_ssz::{Decode, Encode, SszList, TreeHash};
use pharos_utils::{BLSSignature, Bytes32};

use crate::altair::operations::SyncAggregate;
use crate::bellatrix::execution_payload::ExecutionPayload;
use crate::phase0::misc::Eth1Data;
use crate::phase0::operations::{
    Attestation, AttesterSlashing, Deposit, ProposerSlashing, SignedVoluntaryExit,
};
use crate::views::BeaconBlockBodyView;

// ── BeaconBlockBody ───────────────────────────────────────────────────────────

/// Bellatrix `BeaconBlockBody` per `specs/bellatrix/beacon-chain.md:100-112`.
///
/// Extends the altair body with `execution_payload: ExecutionPayload`.
///
/// Const parameters, in order:
/// 1. `MAX_PROPOSER_SLASHINGS` — `presets/*/phase0.yaml:75`
/// 2. `MAX_ATTESTER_SLASHINGS` — `presets/*/phase0.yaml:77`
/// 3. `MAX_ATTESTATIONS` — `presets/*/phase0.yaml:79`
/// 4. `MAX_DEPOSITS` — `presets/*/phase0.yaml:81`
/// 5. `MAX_VOLUNTARY_EXITS` — `presets/*/phase0.yaml:83`
/// 6. `MAX_VALIDATORS_PER_COMMITTEE` — `presets/*/phase0.yaml:10`
/// 7. `DEPOSIT_PROOF_LENGTH` — `specs/phase0/beacon-chain.md:194`
/// 8. `SYNC_COMMITTEE_SIZE` — `presets/*/altair.yaml:15`
/// 9. `MAX_BYTES_PER_TRANSACTION` — `presets/*/bellatrix.yaml`
/// 10. `MAX_TRANSACTIONS_PER_PAYLOAD` — `presets/*/bellatrix.yaml`
/// 11. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 12. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `randao_reveal: BLSSignature` — `specs/bellatrix/beacon-chain.md:101`.
    pub randao_reveal: BLSSignature,
    /// `eth1_data: Eth1Data` — `specs/bellatrix/beacon-chain.md:102`.
    pub eth1_data: Eth1Data,
    /// `graffiti: Bytes32` — `specs/bellatrix/beacon-chain.md:103`.
    pub graffiti: Bytes32,
    /// `proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]`
    /// — `specs/bellatrix/beacon-chain.md:104`.
    pub proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    /// `attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]`
    /// — `specs/bellatrix/beacon-chain.md:105`.
    pub attester_slashings:
        SszList<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTER_SLASHINGS>,
    /// `attestations: List[Attestation, MAX_ATTESTATIONS]`
    /// — `specs/bellatrix/beacon-chain.md:106`.
    pub attestations: SszList<Attestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTATIONS>,
    /// `deposits: List[Deposit, MAX_DEPOSITS]`
    /// — `specs/bellatrix/beacon-chain.md:107`.
    pub deposits: SszList<Deposit<DEPOSIT_PROOF_LENGTH>, MAX_DEPOSITS>,
    /// `voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]`
    /// — `specs/bellatrix/beacon-chain.md:108`.
    pub voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    /// `sync_aggregate: SyncAggregate` — `specs/bellatrix/beacon-chain.md:110` (from altair).
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `execution_payload: ExecutionPayload` — `specs/bellatrix/beacon-chain.md:111`
    /// ([New in Bellatrix]).
    pub execution_payload: ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
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
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
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
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
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

    fn execution_block_hash(&self) -> Option<[u8; 32]> {
        Some(self.execution_payload.block_hash.into())
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet bellatrix `BeaconBlockBody`.
pub type MainnetBeaconBlockBody = BeaconBlockBody<
    16,            // MAX_PROPOSER_SLASHINGS
    2,             // MAX_ATTESTER_SLASHINGS
    128,           // MAX_ATTESTATIONS
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    512,           // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
>;

/// Minimal bellatrix `BeaconBlockBody`.
pub type MinimalBeaconBlockBody = BeaconBlockBody<
    16,            // MAX_PROPOSER_SLASHINGS
    2,             // MAX_ATTESTER_SLASHINGS
    128,           // MAX_ATTESTATIONS
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    32,            // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
>;

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
        roundtrip(super::MainnetBeaconBlockBody::default());
    }

    #[test]
    fn beacon_block_body_minimal_roundtrip() {
        roundtrip(super::MinimalBeaconBlockBody::default());
    }
}
