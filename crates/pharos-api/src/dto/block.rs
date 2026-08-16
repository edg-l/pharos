//! Per-fork `SignedBeaconBlock` DTOs for the Beacon API JSON wire format.
//!
//! Per `D-api-dto-serde`: DTOs in `pharos-api` own all serde; `pharos-types`
//! is serde-free. Each fork variant maps to a concrete DTO struct that mirrors
//! the beacon-APIs OpenAPI spec field names and types.
//!
//! Field encoding rules:
//! - `u64` fields → quoted decimal string (via `quoted_u64`)
//! - byte arrays / roots / pubkeys → `0x`-prefixed lowercase hex
//! - `aggregation_bits` / bitfields → SSZ-serialized bytes as `0x`-hex
//! - `base_fee_per_gas` (Uint256) → quoted decimal string

use pharos_ssz::{Encode, SszSequence};
use pharos_types::{
    phase0::{AttestationData, Eth1Data, ProposerSlashing, SignedVoluntaryExit},
    views::ForkVariant,
};
use serde::Serialize;

use crate::error::ApiError;
use crate::serde_helpers::{
    hex_bytes, quoted_u64, serialize_hex32, serialize_hex48, serialize_hex96,
};

// ── Serialize Uint256 as quoted decimal ───────────────────────────────────────

fn uint256_to_quoted_dec(v: &pharos_utils::Uint256) -> String {
    v.to_string()
}

// ── API-level SignedBlock data ────────────────────────────────────────────────

/// Block data ready for API serialization.
///
/// Built by `ChainStateApi::block_by_root_for_api` which pattern-matches on
/// the concrete enum fork variant inside the `NodeChainState` impl, where the
/// concrete const-generic parameters are known.
pub struct SignedBlockForApi {
    /// Fork variant, used to build `version` field and `Eth-Consensus-Version` header.
    pub variant: ForkVariant,
    /// JSON DTO value (the `data` field in the fork-tagged envelope).
    pub json: serde_json::Value,
    /// Canonical SSZ bytes (inner fork variant, no discriminant byte).
    pub ssz_bytes: Vec<u8>,
    /// Attestations as JSON array (for `/eth/v2/beacon/blocks/{id}/attestations`).
    pub attestations_json: Vec<serde_json::Value>,
}

// ── Common sub-DTOs ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Eth1DataDto {
    #[serde(serialize_with = "serialize_hex32")]
    pub deposit_root: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub deposit_count: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub block_hash: [u8; 32],
}

impl From<&Eth1Data> for Eth1DataDto {
    fn from(d: &Eth1Data) -> Self {
        Self {
            deposit_root: d.deposit_root.into(),
            deposit_count: d.deposit_count,
            block_hash: d.block_hash.into(),
        }
    }
}

#[derive(Serialize)]
pub struct CheckpointDto {
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub root: [u8; 32],
}

#[derive(Serialize)]
pub struct AttestationDataDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub beacon_block_root: [u8; 32],
    pub source: CheckpointDto,
    pub target: CheckpointDto,
}

impl From<&AttestationData> for AttestationDataDto {
    fn from(d: &AttestationData) -> Self {
        Self {
            slot: u64::from(d.slot),
            index: u64::from(d.index),
            beacon_block_root: d.beacon_block_root.into(),
            source: CheckpointDto {
                epoch: u64::from(d.source.epoch),
                root: d.source.root.into(),
            },
            target: CheckpointDto {
                epoch: u64::from(d.target.epoch),
                root: d.target.root.into(),
            },
        }
    }
}

/// Phase0 attestation DTO.
///
/// `aggregation_bits` is a `Bitlist[MAX_VALIDATORS_PER_COMMITTEE]` serialized
/// as SSZ bytes (with trailing sentinel bit) and encoded as `0x`-hex.
#[derive(Serialize)]
pub struct AttestationDto {
    #[serde(with = "hex_bytes")]
    pub aggregation_bits: Vec<u8>,
    pub data: AttestationDataDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

#[derive(Serialize)]
pub struct SignedBeaconBlockHeaderDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub body_root: [u8; 32],
}

#[derive(Serialize)]
pub struct SignedHeaderDto {
    pub message: SignedBeaconBlockHeaderDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

#[derive(Serialize)]
pub struct ProposerSlashingDto {
    pub signed_header_1: SignedHeaderDto,
    pub signed_header_2: SignedHeaderDto,
}

pub fn proposer_slashing_dto(ps: &ProposerSlashing) -> ProposerSlashingDto {
    let to_signed = |sh: &pharos_types::phase0::SignedBeaconBlockHeader| SignedHeaderDto {
        message: SignedBeaconBlockHeaderDto {
            slot: u64::from(sh.message.slot),
            proposer_index: u64::from(sh.message.proposer_index),
            parent_root: sh.message.parent_root.into(),
            state_root: sh.message.state_root.into(),
            body_root: sh.message.body_root.into(),
        },
        signature: sh.signature.into(),
    };
    ProposerSlashingDto {
        signed_header_1: to_signed(&ps.signed_header_1),
        signed_header_2: to_signed(&ps.signed_header_2),
    }
}

#[derive(Serialize)]
pub struct IndexedAttestationDto {
    pub attesting_indices: Vec<String>,
    pub data: AttestationDataDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

#[derive(Serialize)]
pub struct AttesterSlashingDto {
    pub attestation_1: IndexedAttestationDto,
    pub attestation_2: IndexedAttestationDto,
}

pub fn attester_slashing_dto<const N: u64>(
    a: &pharos_types::phase0::AttesterSlashing<N>,
) -> AttesterSlashingDto {
    let ia_dto = |ia: &pharos_types::phase0::IndexedAttestation<N>| IndexedAttestationDto {
        attesting_indices: ia
            .attesting_indices
            .iter()
            .map(|idx| idx.to_string())
            .collect(),
        data: (&ia.data).into(),
        signature: ia.signature.into(),
    };
    AttesterSlashingDto {
        attestation_1: ia_dto(&a.attestation_1),
        attestation_2: ia_dto(&a.attestation_2),
    }
}

#[derive(Serialize)]
pub struct DepositDataDto {
    #[serde(serialize_with = "serialize_hex48")]
    pub pubkey: [u8; 48],
    #[serde(serialize_with = "serialize_hex32")]
    pub withdrawal_credentials: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub amount: u64,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

#[derive(Serialize)]
pub struct DepositDto {
    pub proof: Vec<String>,
    pub data: DepositDataDto,
}

pub fn deposit_dto<const N: u64>(d: &pharos_types::phase0::Deposit<N>) -> DepositDto {
    DepositDto {
        proof: d
            .proof
            .iter()
            .map(|b| format!("0x{}", hex::encode(b.as_slice())))
            .collect(),
        data: DepositDataDto {
            pubkey: d.data.pubkey.into(),
            withdrawal_credentials: d.data.withdrawal_credentials.into(),
            amount: d.data.amount.into(),
            signature: d.data.signature.into(),
        },
    }
}

#[derive(Serialize)]
pub struct VoluntaryExitDto {
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
    #[serde(with = "quoted_u64")]
    pub validator_index: u64,
}

#[derive(Serialize)]
pub struct SignedVoluntaryExitDto {
    pub message: VoluntaryExitDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

impl From<&SignedVoluntaryExit> for SignedVoluntaryExitDto {
    fn from(v: &SignedVoluntaryExit) -> Self {
        Self {
            message: VoluntaryExitDto {
                epoch: u64::from(v.message.epoch),
                validator_index: u64::from(v.message.validator_index),
            },
            signature: v.signature.into(),
        }
    }
}

// ── Attestation builder ───────────────────────────────────────────────────────

pub fn attestation_dto<const N: u64>(att: &pharos_types::phase0::Attestation<N>) -> AttestationDto {
    let mut bits = Vec::new();
    att.aggregation_bits.ssz_append(&mut bits);
    AttestationDto {
        aggregation_bits: bits,
        data: (&att.data).into(),
        signature: att.signature.into(),
    }
}

// ── Phase0 body ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Phase0BlockBodyDto {
    #[serde(serialize_with = "serialize_hex96")]
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1DataDto,
    #[serde(serialize_with = "serialize_hex32")]
    pub graffiti: [u8; 32],
    pub proposer_slashings: Vec<ProposerSlashingDto>,
    pub attester_slashings: Vec<AttesterSlashingDto>,
    pub attestations: Vec<AttestationDto>,
    pub deposits: Vec<DepositDto>,
    pub voluntary_exits: Vec<SignedVoluntaryExitDto>,
}

#[derive(Serialize)]
pub struct Phase0BlockDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    pub body: Phase0BlockBodyDto,
}

#[derive(Serialize)]
pub struct Phase0SignedBlockDto {
    pub message: Phase0BlockDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

// ── Sync aggregate (Altair+) ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SyncAggregateDto {
    #[serde(with = "hex_bytes")]
    pub sync_committee_bits: Vec<u8>,
    #[serde(serialize_with = "serialize_hex96")]
    pub sync_committee_signature: [u8; 96],
}

pub fn sync_aggregate_dto<const N: u64>(
    sa: &pharos_types::altair::operations::SyncAggregate<N>,
) -> SyncAggregateDto {
    let mut bits = Vec::new();
    sa.sync_committee_bits.ssz_append(&mut bits);
    SyncAggregateDto {
        sync_committee_bits: bits,
        sync_committee_signature: sa.sync_committee_signature.into(),
    }
}

// ── Altair body ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AltairBlockBodyDto {
    #[serde(serialize_with = "serialize_hex96")]
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1DataDto,
    #[serde(serialize_with = "serialize_hex32")]
    pub graffiti: [u8; 32],
    pub proposer_slashings: Vec<ProposerSlashingDto>,
    pub attester_slashings: Vec<AttesterSlashingDto>,
    pub attestations: Vec<AttestationDto>,
    pub deposits: Vec<DepositDto>,
    pub voluntary_exits: Vec<SignedVoluntaryExitDto>,
    pub sync_aggregate: SyncAggregateDto,
}

#[derive(Serialize)]
pub struct AltairBlockDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    pub body: AltairBlockBodyDto,
}

#[derive(Serialize)]
pub struct AltairSignedBlockDto {
    pub message: AltairBlockDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

// ── Execution payload (Bellatrix) ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct ExecutionPayloadDto {
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_hash: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub fee_recipient: Vec<u8>,
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub receipts_root: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub logs_bloom: Vec<u8>,
    #[serde(serialize_with = "serialize_hex32")]
    pub prev_randao: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub block_number: u64,
    #[serde(with = "quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_bytes")]
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: String,
    #[serde(serialize_with = "serialize_hex32")]
    pub block_hash: [u8; 32],
    pub transactions: Vec<String>,
}

pub fn bellatrix_execution_payload_dto<const T: u64, const M: u64, const B: u64, const X: u64>(
    ep: &pharos_types::bellatrix::ExecutionPayload<T, M, B, X>,
) -> ExecutionPayloadDto {
    ExecutionPayloadDto {
        parent_hash: ep.parent_hash.into(),
        fee_recipient: ep.fee_recipient.as_slice().to_vec(),
        state_root: ep.state_root.into(),
        receipts_root: ep.receipts_root.into(),
        logs_bloom: ep.logs_bloom.iter().copied().collect(),
        prev_randao: ep.prev_randao.into(),
        block_number: ep.block_number,
        gas_limit: ep.gas_limit,
        gas_used: ep.gas_used,
        timestamp: ep.timestamp,
        extra_data: ep.extra_data.iter().copied().collect(),
        base_fee_per_gas: uint256_to_quoted_dec(&ep.base_fee_per_gas),
        block_hash: ep.block_hash.into(),
        transactions: ep
            .transactions
            .iter()
            .map(|tx| format!("0x{}", hex::encode(tx.iter().copied().collect::<Vec<u8>>())))
            .collect(),
    }
}

// ── Bellatrix body ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BellatrixBlockBodyDto {
    #[serde(serialize_with = "serialize_hex96")]
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1DataDto,
    #[serde(serialize_with = "serialize_hex32")]
    pub graffiti: [u8; 32],
    pub proposer_slashings: Vec<ProposerSlashingDto>,
    pub attester_slashings: Vec<AttesterSlashingDto>,
    pub attestations: Vec<AttestationDto>,
    pub deposits: Vec<DepositDto>,
    pub voluntary_exits: Vec<SignedVoluntaryExitDto>,
    pub sync_aggregate: SyncAggregateDto,
    pub execution_payload: ExecutionPayloadDto,
}

#[derive(Serialize)]
pub struct BellatrixBlockDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    pub body: BellatrixBlockBodyDto,
}

#[derive(Serialize)]
pub struct BellatrixSignedBlockDto {
    pub message: BellatrixBlockDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

// ── Capella execution payload ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct WithdrawalDto {
    #[serde(with = "quoted_u64")]
    pub index: u64,
    #[serde(with = "quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "hex_bytes")]
    pub address: Vec<u8>,
    #[serde(with = "quoted_u64")]
    pub amount: u64,
}

#[derive(Serialize)]
pub struct CapellaExecutionPayloadDto {
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_hash: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub fee_recipient: Vec<u8>,
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub receipts_root: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub logs_bloom: Vec<u8>,
    #[serde(serialize_with = "serialize_hex32")]
    pub prev_randao: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub block_number: u64,
    #[serde(with = "quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_bytes")]
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: String,
    #[serde(serialize_with = "serialize_hex32")]
    pub block_hash: [u8; 32],
    pub transactions: Vec<String>,
    pub withdrawals: Vec<WithdrawalDto>,
}

pub fn capella_execution_payload_dto<
    const T: u64,
    const M: u64,
    const B: u64,
    const X: u64,
    const W: u64,
>(
    ep: &pharos_types::capella::ExecutionPayload<T, M, B, X, W>,
) -> CapellaExecutionPayloadDto {
    CapellaExecutionPayloadDto {
        parent_hash: ep.parent_hash.into(),
        fee_recipient: ep.fee_recipient.as_slice().to_vec(),
        state_root: ep.state_root.into(),
        receipts_root: ep.receipts_root.into(),
        logs_bloom: ep.logs_bloom.iter().copied().collect(),
        prev_randao: ep.prev_randao.into(),
        block_number: ep.block_number,
        gas_limit: ep.gas_limit,
        gas_used: ep.gas_used,
        timestamp: ep.timestamp,
        extra_data: ep.extra_data.iter().copied().collect(),
        base_fee_per_gas: uint256_to_quoted_dec(&ep.base_fee_per_gas),
        block_hash: ep.block_hash.into(),
        transactions: ep
            .transactions
            .iter()
            .map(|tx| format!("0x{}", hex::encode(tx.iter().copied().collect::<Vec<u8>>())))
            .collect(),
        withdrawals: ep
            .withdrawals
            .iter()
            .map(|w| WithdrawalDto {
                index: w.index,
                validator_index: u64::from(w.validator_index),
                address: w.address.as_slice().to_vec(),
                amount: w.amount.into(),
            })
            .collect(),
    }
}

// ── Deneb execution payload ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DenebExecutionPayloadDto {
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_hash: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub fee_recipient: Vec<u8>,
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub receipts_root: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub logs_bloom: Vec<u8>,
    #[serde(serialize_with = "serialize_hex32")]
    pub prev_randao: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub block_number: u64,
    #[serde(with = "quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_bytes")]
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: String,
    #[serde(serialize_with = "serialize_hex32")]
    pub block_hash: [u8; 32],
    pub transactions: Vec<String>,
    pub withdrawals: Vec<WithdrawalDto>,
    #[serde(with = "quoted_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "quoted_u64")]
    pub excess_blob_gas: u64,
}

pub fn deneb_execution_payload_dto<
    const T: u64,
    const M: u64,
    const B: u64,
    const X: u64,
    const W: u64,
>(
    ep: &pharos_types::deneb::ExecutionPayload<T, M, B, X, W>,
) -> DenebExecutionPayloadDto {
    DenebExecutionPayloadDto {
        parent_hash: ep.parent_hash.into(),
        fee_recipient: ep.fee_recipient.as_slice().to_vec(),
        state_root: ep.state_root.into(),
        receipts_root: ep.receipts_root.into(),
        logs_bloom: ep.logs_bloom.iter().copied().collect(),
        prev_randao: ep.prev_randao.into(),
        block_number: ep.block_number,
        gas_limit: ep.gas_limit,
        gas_used: ep.gas_used,
        timestamp: ep.timestamp,
        extra_data: ep.extra_data.iter().copied().collect(),
        base_fee_per_gas: uint256_to_quoted_dec(&ep.base_fee_per_gas),
        block_hash: ep.block_hash.into(),
        transactions: ep
            .transactions
            .iter()
            .map(|tx| format!("0x{}", hex::encode(tx.iter().copied().collect::<Vec<u8>>())))
            .collect(),
        withdrawals: ep
            .withdrawals
            .iter()
            .map(|w| WithdrawalDto {
                index: w.index,
                validator_index: u64::from(w.validator_index),
                address: w.address.as_slice().to_vec(),
                amount: w.amount.into(),
            })
            .collect(),
        blob_gas_used: ep.blob_gas_used,
        excess_blob_gas: ep.excess_blob_gas,
    }
}

// ── SignedBLSToExecutionChange ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BLSToExecutionChangeDto {
    #[serde(with = "quoted_u64")]
    pub validator_index: u64,
    #[serde(serialize_with = "serialize_hex48")]
    pub from_bls_pubkey: [u8; 48],
    #[serde(with = "hex_bytes")]
    pub to_execution_address: Vec<u8>,
}

#[derive(Serialize)]
pub struct SignedBLSToExecutionChangeDto {
    pub message: BLSToExecutionChangeDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

// ── Capella body ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CapellaBlockBodyDto {
    #[serde(serialize_with = "serialize_hex96")]
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1DataDto,
    #[serde(serialize_with = "serialize_hex32")]
    pub graffiti: [u8; 32],
    pub proposer_slashings: Vec<ProposerSlashingDto>,
    pub attester_slashings: Vec<AttesterSlashingDto>,
    pub attestations: Vec<AttestationDto>,
    pub deposits: Vec<DepositDto>,
    pub voluntary_exits: Vec<SignedVoluntaryExitDto>,
    pub sync_aggregate: SyncAggregateDto,
    pub execution_payload: CapellaExecutionPayloadDto,
    pub bls_to_execution_changes: Vec<SignedBLSToExecutionChangeDto>,
}

#[derive(Serialize)]
pub struct CapellaBlockDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    pub body: CapellaBlockBodyDto,
}

#[derive(Serialize)]
pub struct CapellaSignedBlockDto {
    pub message: CapellaBlockDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

// ── Deneb body ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DenebBlockBodyDto {
    #[serde(serialize_with = "serialize_hex96")]
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1DataDto,
    #[serde(serialize_with = "serialize_hex32")]
    pub graffiti: [u8; 32],
    pub proposer_slashings: Vec<ProposerSlashingDto>,
    pub attester_slashings: Vec<AttesterSlashingDto>,
    pub attestations: Vec<AttestationDto>,
    pub deposits: Vec<DepositDto>,
    pub voluntary_exits: Vec<SignedVoluntaryExitDto>,
    pub sync_aggregate: SyncAggregateDto,
    pub execution_payload: DenebExecutionPayloadDto,
    pub bls_to_execution_changes: Vec<SignedBLSToExecutionChangeDto>,
    pub blob_kzg_commitments: Vec<String>,
}

#[derive(Serialize)]
pub struct DenebBlockDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(serialize_with = "serialize_hex32")]
    pub parent_root: [u8; 32],
    #[serde(serialize_with = "serialize_hex32")]
    pub state_root: [u8; 32],
    pub body: DenebBlockBodyDto,
}

#[derive(Serialize)]
pub struct DenebSignedBlockDto {
    pub message: DenebBlockDto,
    #[serde(serialize_with = "serialize_hex96")]
    pub signature: [u8; 96],
}

// ── BlockApiSerializer trait ──────────────────────────────────────────────────

/// A trait implemented by concrete per-fork `SignedBeaconBlock` types in `pharos-api`.
///
/// This sidesteps the Rust limitation that prevents pattern-matching on opaque
/// associated types (`E::Phase0SignedBeaconBlock`) inside a generic `impl<E: EthSpec>`
/// block. By implementing this trait for each concrete preset alias, the
/// `NodeChainState` impl can call `to_block_for_api()` on the unwrapped inner type.
pub trait BlockApiSerializer {
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError>;
}

/// Map a `serde_json` serialization error to an internal API error. Block DTO
/// serialization is infallible in practice (the DTO graph is plain derives over
/// strings/numbers), but we propagate rather than panic on a request path.
fn ser_err(e: serde_json::Error) -> ApiError {
    ApiError::Internal(format!("block DTO serialization failed: {e}"))
}

// ── Fork-specific conversion functions ───────────────────────────────────────
//
// These functions take CONCRETE fork-specific types (not the generic
// `E::SignedBeaconBlock` associated type). They are called from the
// `NodeChainState` impl where the concrete enum variant has been matched.

/// Convert a Phase0 `SignedBeaconBlock` to a JSON DTO value.
pub fn phase0_signed_block_to_api<
    const P: u64,
    const A: u64,
    const M: u64,
    const D: u64,
    const V: u64,
    const C: u64,
    const DP: u64,
>(
    b: &pharos_types::phase0::SignedBeaconBlock<P, A, M, D, V, C, DP>,
) -> Result<SignedBlockForApi, ApiError> {
    let msg = &b.message;
    let dto = Phase0SignedBlockDto {
        signature: b.signature.into(),
        message: Phase0BlockDto {
            slot: u64::from(msg.slot),
            proposer_index: u64::from(msg.proposer_index),
            parent_root: msg.parent_root.into(),
            state_root: msg.state_root.into(),
            body: Phase0BlockBodyDto {
                randao_reveal: msg.body.randao_reveal.into(),
                eth1_data: (&msg.body.eth1_data).into(),
                graffiti: msg.body.graffiti.into(),
                proposer_slashings: msg
                    .body
                    .proposer_slashings
                    .iter()
                    .map(proposer_slashing_dto)
                    .collect(),
                attester_slashings: msg
                    .body
                    .attester_slashings
                    .iter()
                    .map(attester_slashing_dto)
                    .collect(),
                attestations: msg.body.attestations.iter().map(attestation_dto).collect(),
                deposits: msg.body.deposits.iter().map(deposit_dto).collect(),
                voluntary_exits: msg.body.voluntary_exits.iter().map(|e| e.into()).collect(),
            },
        },
    };
    let attestations_json = msg
        .body
        .attestations
        .iter()
        .map(|a| serde_json::to_value(attestation_dto(a)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ser_err)?;
    let mut ssz = Vec::new();
    b.ssz_append(&mut ssz);
    Ok(SignedBlockForApi {
        variant: ForkVariant::Phase0,
        json: serde_json::to_value(dto).map_err(ser_err)?,
        ssz_bytes: ssz,
        attestations_json,
    })
}

/// Convert an Altair `SignedBeaconBlock` to a JSON DTO value.
pub fn altair_signed_block_to_api<
    const P: u64,
    const A: u64,
    const M: u64,
    const D: u64,
    const V: u64,
    const C: u64,
    const DP: u64,
    const S: u64,
>(
    b: &pharos_types::altair::SignedBeaconBlock<P, A, M, D, V, C, DP, S>,
) -> Result<SignedBlockForApi, ApiError> {
    let msg = &b.message;
    let dto = AltairSignedBlockDto {
        signature: b.signature.into(),
        message: AltairBlockDto {
            slot: u64::from(msg.slot),
            proposer_index: u64::from(msg.proposer_index),
            parent_root: msg.parent_root.into(),
            state_root: msg.state_root.into(),
            body: AltairBlockBodyDto {
                randao_reveal: msg.body.randao_reveal.into(),
                eth1_data: (&msg.body.eth1_data).into(),
                graffiti: msg.body.graffiti.into(),
                proposer_slashings: msg
                    .body
                    .proposer_slashings
                    .iter()
                    .map(proposer_slashing_dto)
                    .collect(),
                attester_slashings: msg
                    .body
                    .attester_slashings
                    .iter()
                    .map(attester_slashing_dto)
                    .collect(),
                attestations: msg.body.attestations.iter().map(attestation_dto).collect(),
                deposits: msg.body.deposits.iter().map(deposit_dto).collect(),
                voluntary_exits: msg.body.voluntary_exits.iter().map(|e| e.into()).collect(),
                sync_aggregate: sync_aggregate_dto(&msg.body.sync_aggregate),
            },
        },
    };
    let attestations_json = msg
        .body
        .attestations
        .iter()
        .map(|a| serde_json::to_value(attestation_dto(a)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ser_err)?;
    let mut ssz = Vec::new();
    b.ssz_append(&mut ssz);
    Ok(SignedBlockForApi {
        variant: ForkVariant::Altair,
        json: serde_json::to_value(dto).map_err(ser_err)?,
        ssz_bytes: ssz,
        attestations_json,
    })
}

/// Convert a Bellatrix `SignedBeaconBlock` to API data.
pub fn bellatrix_signed_block_to_api<
    const P: u64,
    const A: u64,
    const M: u64,
    const D: u64,
    const V: u64,
    const C: u64,
    const DP: u64,
    const S: u64,
    const T: u64,
    const TX: u64,
    const B: u64,
    const X: u64,
>(
    blk: &pharos_types::bellatrix::SignedBeaconBlock<P, A, M, D, V, C, DP, S, T, TX, B, X>,
) -> Result<SignedBlockForApi, ApiError> {
    let msg = &blk.message;
    let dto = BellatrixSignedBlockDto {
        signature: blk.signature.into(),
        message: BellatrixBlockDto {
            slot: u64::from(msg.slot),
            proposer_index: u64::from(msg.proposer_index),
            parent_root: msg.parent_root.into(),
            state_root: msg.state_root.into(),
            body: BellatrixBlockBodyDto {
                randao_reveal: msg.body.randao_reveal.into(),
                eth1_data: (&msg.body.eth1_data).into(),
                graffiti: msg.body.graffiti.into(),
                proposer_slashings: msg
                    .body
                    .proposer_slashings
                    .iter()
                    .map(proposer_slashing_dto)
                    .collect(),
                attester_slashings: msg
                    .body
                    .attester_slashings
                    .iter()
                    .map(attester_slashing_dto)
                    .collect(),
                attestations: msg.body.attestations.iter().map(attestation_dto).collect(),
                deposits: msg.body.deposits.iter().map(deposit_dto).collect(),
                voluntary_exits: msg.body.voluntary_exits.iter().map(|e| e.into()).collect(),
                sync_aggregate: sync_aggregate_dto(&msg.body.sync_aggregate),
                execution_payload: bellatrix_execution_payload_dto(&msg.body.execution_payload),
            },
        },
    };
    let attestations_json = msg
        .body
        .attestations
        .iter()
        .map(|a| serde_json::to_value(attestation_dto(a)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ser_err)?;
    let mut ssz = Vec::new();
    blk.ssz_append(&mut ssz);
    Ok(SignedBlockForApi {
        variant: ForkVariant::Bellatrix,
        json: serde_json::to_value(dto).map_err(ser_err)?,
        ssz_bytes: ssz,
        attestations_json,
    })
}

/// Convert a Capella `SignedBeaconBlock` to API data.
pub fn capella_signed_block_to_api<
    const P: u64,
    const A: u64,
    const M: u64,
    const D: u64,
    const V: u64,
    const C: u64,
    const DP: u64,
    const S: u64,
    const T: u64,
    const TX: u64,
    const B: u64,
    const X: u64,
    const W: u64,
    const BL: u64,
>(
    blk: &pharos_types::capella::SignedBeaconBlock<P, A, M, D, V, C, DP, S, T, TX, B, X, W, BL>,
) -> Result<SignedBlockForApi, ApiError> {
    let msg = &blk.message;
    let dto = CapellaSignedBlockDto {
        signature: blk.signature.into(),
        message: CapellaBlockDto {
            slot: u64::from(msg.slot),
            proposer_index: u64::from(msg.proposer_index),
            parent_root: msg.parent_root.into(),
            state_root: msg.state_root.into(),
            body: CapellaBlockBodyDto {
                randao_reveal: msg.body.randao_reveal.into(),
                eth1_data: (&msg.body.eth1_data).into(),
                graffiti: msg.body.graffiti.into(),
                proposer_slashings: msg
                    .body
                    .proposer_slashings
                    .iter()
                    .map(proposer_slashing_dto)
                    .collect(),
                attester_slashings: msg
                    .body
                    .attester_slashings
                    .iter()
                    .map(attester_slashing_dto)
                    .collect(),
                attestations: msg.body.attestations.iter().map(attestation_dto).collect(),
                deposits: msg.body.deposits.iter().map(deposit_dto).collect(),
                voluntary_exits: msg.body.voluntary_exits.iter().map(|e| e.into()).collect(),
                sync_aggregate: sync_aggregate_dto(&msg.body.sync_aggregate),
                execution_payload: capella_execution_payload_dto(&msg.body.execution_payload),
                bls_to_execution_changes: msg
                    .body
                    .bls_to_execution_changes
                    .iter()
                    .map(|sc| SignedBLSToExecutionChangeDto {
                        message: BLSToExecutionChangeDto {
                            validator_index: u64::from(sc.message.validator_index),
                            from_bls_pubkey: sc.message.from_bls_pubkey.into(),
                            to_execution_address: sc
                                .message
                                .to_execution_address
                                .as_slice()
                                .to_vec(),
                        },
                        signature: sc.signature.into(),
                    })
                    .collect(),
            },
        },
    };
    let attestations_json = msg
        .body
        .attestations
        .iter()
        .map(|a| serde_json::to_value(attestation_dto(a)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ser_err)?;
    let mut ssz = Vec::new();
    blk.ssz_append(&mut ssz);
    Ok(SignedBlockForApi {
        variant: ForkVariant::Capella,
        json: serde_json::to_value(dto).map_err(ser_err)?,
        ssz_bytes: ssz,
        attestations_json,
    })
}

/// Convert a Deneb `SignedBeaconBlock` to API data.
pub fn deneb_signed_block_to_api<
    const P: u64,
    const A: u64,
    const M: u64,
    const D: u64,
    const V: u64,
    const C: u64,
    const DP: u64,
    const S: u64,
    const T: u64,
    const TX: u64,
    const B: u64,
    const X: u64,
    const W: u64,
    const BL: u64,
    const KC: u64,
>(
    blk: &pharos_types::deneb::SignedBeaconBlock<P, A, M, D, V, C, DP, S, T, TX, B, X, W, BL, KC>,
) -> Result<SignedBlockForApi, ApiError> {
    let msg = &blk.message;
    let dto = DenebSignedBlockDto {
        signature: blk.signature.into(),
        message: DenebBlockDto {
            slot: u64::from(msg.slot),
            proposer_index: u64::from(msg.proposer_index),
            parent_root: msg.parent_root.into(),
            state_root: msg.state_root.into(),
            body: DenebBlockBodyDto {
                randao_reveal: msg.body.randao_reveal.into(),
                eth1_data: (&msg.body.eth1_data).into(),
                graffiti: msg.body.graffiti.into(),
                proposer_slashings: msg
                    .body
                    .proposer_slashings
                    .iter()
                    .map(proposer_slashing_dto)
                    .collect(),
                attester_slashings: msg
                    .body
                    .attester_slashings
                    .iter()
                    .map(attester_slashing_dto)
                    .collect(),
                attestations: msg.body.attestations.iter().map(attestation_dto).collect(),
                deposits: msg.body.deposits.iter().map(deposit_dto).collect(),
                voluntary_exits: msg.body.voluntary_exits.iter().map(|e| e.into()).collect(),
                sync_aggregate: sync_aggregate_dto(&msg.body.sync_aggregate),
                execution_payload: deneb_execution_payload_dto(&msg.body.execution_payload),
                bls_to_execution_changes: msg
                    .body
                    .bls_to_execution_changes
                    .iter()
                    .map(|sc| SignedBLSToExecutionChangeDto {
                        message: BLSToExecutionChangeDto {
                            validator_index: u64::from(sc.message.validator_index),
                            from_bls_pubkey: sc.message.from_bls_pubkey.into(),
                            to_execution_address: sc
                                .message
                                .to_execution_address
                                .as_slice()
                                .to_vec(),
                        },
                        signature: sc.signature.into(),
                    })
                    .collect(),
                blob_kzg_commitments: msg
                    .body
                    .blob_kzg_commitments
                    .iter()
                    .map(|c| format!("0x{}", hex::encode(c.as_slice())))
                    .collect(),
            },
        },
    };
    let attestations_json = msg
        .body
        .attestations
        .iter()
        .map(|a| serde_json::to_value(attestation_dto(a)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ser_err)?;
    let mut ssz = Vec::new();
    blk.ssz_append(&mut ssz);
    Ok(SignedBlockForApi {
        variant: ForkVariant::Deneb,
        json: serde_json::to_value(dto).map_err(ser_err)?,
        ssz_bytes: ssz,
        attestations_json,
    })
}

// ── BlockApiSerializer implementations ───────────────────────────────────────

// Phase0 — mainnet and minimal share the same const params.

impl BlockApiSerializer for pharos_types::phase0::SignedBeaconBlock<16, 2, 128, 16, 16, 2048, 33> {
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        phase0_signed_block_to_api(self)
    }
}

// Altair — distinct SYNC_COMMITTEE_SIZE (512 vs 32).

impl BlockApiSerializer
    for pharos_types::altair::SignedBeaconBlock<16, 2, 128, 16, 16, 2048, 33, 512>
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        altair_signed_block_to_api(self)
    }
}

impl BlockApiSerializer
    for pharos_types::altair::SignedBeaconBlock<16, 2, 128, 16, 16, 2048, 33, 32>
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        altair_signed_block_to_api(self)
    }
}

// Bellatrix — distinct SYNC_COMMITTEE_SIZE.

impl BlockApiSerializer
    for pharos_types::bellatrix::SignedBeaconBlock<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        256,
        32,
    >
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        bellatrix_signed_block_to_api(self)
    }
}

impl BlockApiSerializer
    for pharos_types::bellatrix::SignedBeaconBlock<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        256,
        32,
    >
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        bellatrix_signed_block_to_api(self)
    }
}

// Capella — distinct SYNC_COMMITTEE_SIZE and MAX_WITHDRAWALS_PER_PAYLOAD.

impl BlockApiSerializer
    for pharos_types::capella::SignedBeaconBlock<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        256,
        32,
        16,
        16,
    >
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        capella_signed_block_to_api(self)
    }
}

impl BlockApiSerializer
    for pharos_types::capella::SignedBeaconBlock<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        256,
        32,
        4,
        16,
    >
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        capella_signed_block_to_api(self)
    }
}

// Deneb — distinct SYNC_COMMITTEE_SIZE and MAX_WITHDRAWALS_PER_PAYLOAD.

impl BlockApiSerializer
    for pharos_types::deneb::SignedBeaconBlock<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        512,
        1_073_741_824,
        1_048_576,
        256,
        32,
        16,
        16,
        4096,
    >
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        deneb_signed_block_to_api(self)
    }
}

impl BlockApiSerializer
    for pharos_types::deneb::SignedBeaconBlock<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
        32,
        1_073_741_824,
        1_048_576,
        256,
        32,
        4,
        16,
        4096,
    >
{
    fn to_block_for_api(&self) -> Result<SignedBlockForApi, ApiError> {
        deneb_signed_block_to_api(self)
    }
}
