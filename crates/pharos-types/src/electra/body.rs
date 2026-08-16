//! Electra `BeaconBlockBody` container.
//!
//! Per `specs/electra/beacon-chain.md` (Modified containers → BeaconBlockBody).
//!
//! ## Changes from Deneb
//! - `attester_slashings` uses `electra::AttesterSlashing` (limit `MAX_ATTESTER_SLASHINGS_ELECTRA`).
//! - `attestations` uses `electra::Attestation` (limit `MAX_ATTESTATIONS_ELECTRA`).
//! - New field `execution_requests: ExecutionRequests` (EIP-6110/7002/7251).
//! - New const params: `MAX_ATTESTER_SLASHINGS_ELECTRA`, `MAX_ATTESTATIONS_ELECTRA`,
//!   `MAX_AGGREGATION_BITS`, `MAX_COMMITTEES_PER_SLOT`, `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD`,
//!   `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD`, `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD`.

use pharos_ssz::{Decode, Encode, SszList, SszSequence as _, TreeHash};
use pharos_utils::{BLSSignature, Bytes32};

use crate::altair::operations::SyncAggregate;
use crate::capella::operations::SignedBLSToExecutionChange;
use crate::deneb::blob::KZGCommitment;
use crate::electra::attestation::{Attestation, AttesterSlashing};
use crate::electra::execution_payload::ExecutionPayload;
use crate::electra::requests::ExecutionRequests;
use crate::phase0::misc::Eth1Data;
use crate::phase0::operations::{Deposit, ProposerSlashing, SignedVoluntaryExit};
use crate::views::BeaconBlockBodyView;

// ── BeaconBlockBody ───────────────────────────────────────────────────────────

/// Electra `BeaconBlockBody` per `specs/electra/beacon-chain.md`.
///
/// Extends the Deneb body with `execution_requests` and uses modified
/// attestation/slashing types (EIP-7549).
///
/// Const parameters, in order:
/// 1.  `MAX_PROPOSER_SLASHINGS` — `presets/*/phase0.yaml:75`
/// 2.  `MAX_ATTESTER_SLASHINGS_ELECTRA` — `presets/*/electra.yaml`
/// 3.  `MAX_ATTESTATIONS_ELECTRA` — `presets/*/electra.yaml`
/// 4.  `MAX_DEPOSITS` — `presets/*/phase0.yaml:81`
/// 5.  `MAX_VOLUNTARY_EXITS` — `presets/*/phase0.yaml:83`
/// 6.  `MAX_VALIDATORS_PER_COMMITTEE` — `presets/*/phase0.yaml:10`
/// 7.  `DEPOSIT_PROOF_LENGTH` — derived: `DEPOSIT_CONTRACT_TREE_DEPTH + 1 = 33`
/// 8.  `SYNC_COMMITTEE_SIZE` — `presets/*/altair.yaml:15`
/// 9.  `MAX_BYTES_PER_TRANSACTION` — `presets/*/bellatrix.yaml`
/// 10. `MAX_TRANSACTIONS_PER_PAYLOAD` — `presets/*/bellatrix.yaml`
/// 11. `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 12. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
/// 13. `MAX_WITHDRAWALS_PER_PAYLOAD` — `presets/*/capella.yaml`
/// 14. `MAX_BLS_TO_EXECUTION_CHANGES` — `presets/*/capella.yaml`
/// 15. `MAX_BLOB_COMMITMENTS_PER_BLOCK` — `presets/*/deneb.yaml`
/// 16. `MAX_AGGREGATION_BITS` — derived: `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
/// 17. `MAX_COMMITTEES_PER_SLOT` — `presets/*/phase0.yaml:6`
/// 18. `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD` — `presets/*/electra.yaml`
/// 19. `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD` — `presets/*/electra.yaml`
/// 20. `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD` — `presets/*/electra.yaml`
#[allow(clippy::too_many_arguments)]
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BeaconBlockBody<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS_ELECTRA: u64,
    const MAX_ATTESTATIONS_ELECTRA: u64,
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
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
> {
    /// `randao_reveal: BLSSignature`.
    pub randao_reveal: BLSSignature,
    /// `eth1_data: Eth1Data`.
    pub eth1_data: Eth1Data,
    /// `graffiti: Bytes32`.
    pub graffiti: Bytes32,
    /// `proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]`.
    pub proposer_slashings: SszList<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    /// `attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS_ELECTRA]`
    /// — uses electra `AttesterSlashing` (EIP-7549 widened indices).
    pub attester_slashings:
        SszList<AttesterSlashing<MAX_AGGREGATION_BITS>, MAX_ATTESTER_SLASHINGS_ELECTRA>,
    /// `attestations: List[Attestation, MAX_ATTESTATIONS_ELECTRA]`
    /// — uses electra `Attestation` (EIP-7549 aggregation bits + committee bits).
    pub attestations: SszList<
        Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>,
        MAX_ATTESTATIONS_ELECTRA,
    >,
    /// `deposits: List[Deposit, MAX_DEPOSITS]`.
    pub deposits: SszList<Deposit<DEPOSIT_PROOF_LENGTH>, MAX_DEPOSITS>,
    /// `voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]`.
    pub voluntary_exits: SszList<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    /// `sync_aggregate: SyncAggregate` (from altair).
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    /// `execution_payload: ExecutionPayload` (identical to deneb).
    pub execution_payload: ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >,
    /// `bls_to_execution_changes: List[SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES]`
    /// (from Capella).
    pub bls_to_execution_changes: SszList<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
    /// `blob_kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]`
    /// (from Deneb).
    pub blob_kzg_commitments: SszList<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// `execution_requests: ExecutionRequests` — [New in Electra].
    pub execution_requests: ExecutionRequests<
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >,
}

// ── BeaconBlockBodyView impl ──────────────────────────────────────────────────

impl<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS_ELECTRA: u64,
    const MAX_ATTESTATIONS_ELECTRA: u64,
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
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
> BeaconBlockBodyView
    for BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_ATTESTATIONS_ELECTRA,
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
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    type Attestation = Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>;
    type AttesterSlashing = AttesterSlashing<MAX_AGGREGATION_BITS>;
    type Deposit = Deposit<DEPOSIT_PROOF_LENGTH>;

    fn randao_reveal(&self) -> &BLSSignature {
        &self.randao_reveal
    }
    fn eth1_data(&self) -> &crate::phase0::misc::Eth1Data {
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
    fn voluntary_exits(&self) -> &[crate::phase0::operations::SignedVoluntaryExit] {
        self.voluntary_exits.as_slice()
    }

    fn execution_block_hash(&self) -> Option<[u8; 32]> {
        Some(self.execution_payload.block_hash.into())
    }

    fn num_blob_kzg_commitments(&self) -> usize {
        self.blob_kzg_commitments.len()
    }

    fn blob_kzg_commitments_slice(&self) -> &[crate::deneb::KZGCommitment] {
        self.blob_kzg_commitments.as_slice()
    }
}

// ── Preset-specific type aliases ──────────────────────────────────────────────

/// Mainnet electra `BeaconBlockBody`.
///
/// Positions 2-3 use the EIP-7549 spec limits (`MAX_ATTESTER_SLASHINGS_ELECTRA=1`,
/// `MAX_ATTESTATIONS_ELECTRA=8`). These limits are mixed into `hash_tree_root`
/// (they set the List merkle-padding depth), so they MUST match the spec preset —
/// using the pre-Electra values would corrupt every BeaconBlockBody root.
pub type MainnetBeaconBlockBody = BeaconBlockBody<
    16,            // MAX_PROPOSER_SLASHINGS
    1,             // MAX_ATTESTER_SLASHINGS_ELECTRA
    8,             // MAX_ATTESTATIONS_ELECTRA
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    512,           // SYNC_COMMITTEE_SIZE
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
    16,            // MAX_WITHDRAWALS_PER_PAYLOAD (mainnet)
    16,            // MAX_BLS_TO_EXECUTION_CHANGES
    4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK
    131072,        // MAX_AGGREGATION_BITS (2048 * 64)
    64,            // MAX_COMMITTEES_PER_SLOT (mainnet)
    8192,          // MAX_DEPOSIT_REQUESTS_PER_PAYLOAD
    16,            // MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
    2,             // MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
>;

/// Minimal electra `BeaconBlockBody`.
pub type MinimalBeaconBlockBody = BeaconBlockBody<
    16,            // MAX_PROPOSER_SLASHINGS
    1,             // MAX_ATTESTER_SLASHINGS_ELECTRA
    8,             // MAX_ATTESTATIONS_ELECTRA
    16,            // MAX_DEPOSITS
    16,            // MAX_VOLUNTARY_EXITS
    2048,          // MAX_VALIDATORS_PER_COMMITTEE
    33,            // DEPOSIT_PROOF_LENGTH
    32,            // SYNC_COMMITTEE_SIZE (minimal)
    1_073_741_824, // MAX_BYTES_PER_TRANSACTION
    1_048_576,     // MAX_TRANSACTIONS_PER_PAYLOAD
    256,           // BYTES_PER_LOGS_BLOOM
    32,            // MAX_EXTRA_DATA_BYTES
    4,             // MAX_WITHDRAWALS_PER_PAYLOAD (minimal)
    16,            // MAX_BLS_TO_EXECUTION_CHANGES
    4096,          // MAX_BLOB_COMMITMENTS_PER_BLOCK
    8192,          // MAX_AGGREGATION_BITS (2048 * 4)
    4,             // MAX_COMMITTEES_PER_SLOT (minimal)
    8192,          // MAX_DEPOSIT_REQUESTS_PER_PAYLOAD
    16,            // MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
    2,             // MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
>;
