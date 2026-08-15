//! Light-client DTOs for the Beacon API REST endpoints.
//!
//! Per `D-api-dto-serde`: `pharos-types` is serde-free; all JSON construction
//! is done by hand-building `serde_json::Value` in this module.
//!
//! Spec references:
//! - `beacon-APIs/apis/beacon/light_client/bootstrap.yaml`
//! - `beacon-APIs/apis/beacon/light_client/updates.yaml`
//! - `beacon-APIs/apis/beacon/light_client/finality_update.yaml`
//! - `beacon-APIs/apis/beacon/light_client/optimistic_update.yaml`
//! - `specs/altair/light-client/p2p-interface.md:29-35` (MAX_REQUEST_LC_UPDATES)

use pharos_ssz::{Encode, SszSequence};
use pharos_types::{
    altair::light_client::{
        LightClientBootstrap as AltairBootstrap, LightClientFinalityUpdate as AltairFinalityUpdate,
        LightClientOptimisticUpdate as AltairOptimisticUpdate, LightClientUpdate as AltairUpdate,
    },
    capella::light_client::{
        LightClientBootstrap as CapellaBootstrap,
        LightClientFinalityUpdate as CapellaFinalityUpdate,
        LightClientOptimisticUpdate as CapellaOptimisticUpdate, LightClientUpdate as CapellaUpdate,
    },
    views::ForkVariant,
};

use crate::error::ApiError;

/// Maximum number of `LightClientUpdate` objects that can be requested in a
/// single `/eth/v1/beacon/light_client/updates` call.
///
/// Per `specs/altair/light-client/p2p-interface.md:29-35`.
pub const MAX_REQUEST_LC_UPDATES: u64 = 128;

/// A fork-tagged light-client object ready for API serialization.
///
/// Carries both the JSON DTO value (hand-built since `pharos-types` is
/// serde-free) and the raw SSZ bytes for the `application/octet-stream` path.
/// Per `D-api-lc-bridge`.
pub struct LcEnvelope {
    /// Fork variant determined by `fork_variant_at_slot(cfg, attested_slot)`.
    pub variant: ForkVariant,
    /// Hand-built JSON DTO (no `execution_optimistic` / `finalized` at this level).
    pub json: serde_json::Value,
    /// Raw SSZ bytes (unframed, no length prefix).
    /// For `get_updates` the caller length-frames each item before concatenating.
    pub ssz_bytes: Vec<u8>,
    /// Attested beacon-header slot; used to derive `variant` and framing.
    pub attested_slot: u64,
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

fn hex_bytes(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn q(v: u64) -> serde_json::Value {
    serde_json::Value::String(v.to_string())
}

fn beacon_block_header_json(h: &pharos_types::phase0::BeaconBlockHeader) -> serde_json::Value {
    serde_json::json!({
        "slot": q(h.slot.0),
        "proposer_index": q(h.proposer_index.0),
        "parent_root": hex_bytes(h.parent_root.as_slice()),
        "state_root": hex_bytes(h.state_root.as_slice()),
        "body_root": hex_bytes(h.body_root.as_slice()),
    })
}

fn altair_lc_header_json(
    h: &pharos_types::altair::light_client::LightClientHeader,
) -> serde_json::Value {
    serde_json::json!({ "beacon": beacon_block_header_json(&h.beacon) })
}

fn capella_lc_header_json<const B: u64, const X: u64>(
    h: &pharos_types::capella::light_client::LightClientHeader<B, X>,
) -> serde_json::Value {
    // Build execution payload header fields directly from the struct.
    let ep = &h.execution;
    let exec_json = serde_json::json!({
        "parent_hash": hex_bytes(ep.parent_hash.as_slice()),
        "fee_recipient": hex_bytes(ep.fee_recipient.as_slice()),
        "state_root": hex_bytes(ep.state_root.as_slice()),
        "receipts_root": hex_bytes(ep.receipts_root.as_slice()),
        "logs_bloom": hex_bytes(ep.logs_bloom.as_slice()),
        "prev_randao": hex_bytes(ep.prev_randao.as_slice()),
        "block_number": q(ep.block_number),
        "gas_limit": q(ep.gas_limit),
        "gas_used": q(ep.gas_used),
        "timestamp": q(ep.timestamp),
        "extra_data": hex_bytes(ep.extra_data.as_slice()),
        "base_fee_per_gas": serde_json::Value::String(ep.base_fee_per_gas.to_string()),
        "block_hash": hex_bytes(ep.block_hash.as_slice()),
        "transactions_root": hex_bytes(ep.transactions_root.as_slice()),
        "withdrawals_root": hex_bytes(ep.withdrawals_root.as_slice()),
    });
    let branch_json: Vec<serde_json::Value> = h
        .execution_branch
        .iter()
        .map(|b| serde_json::Value::String(hex_bytes(b.as_slice())))
        .collect();
    serde_json::json!({
        "beacon": beacon_block_header_json(&h.beacon),
        "execution": exec_json,
        "execution_branch": branch_json,
    })
}

fn sync_committee_json<const N: u64>(
    sc: &pharos_types::altair::operations::SyncCommittee<N>,
) -> serde_json::Value {
    let pubkeys: Vec<serde_json::Value> = sc
        .pubkeys
        .iter()
        .map(|pk| serde_json::Value::String(hex_bytes(pk.as_slice())))
        .collect();
    serde_json::json!({
        "pubkeys": pubkeys,
        "aggregate_pubkey": hex_bytes(sc.aggregate_pubkey.as_slice()),
    })
}

fn sync_aggregate_json<const N: u64>(
    sa: &pharos_types::altair::operations::SyncAggregate<N>,
) -> serde_json::Value {
    use pharos_ssz::Encode as _;
    serde_json::json!({
        "sync_committee_bits": hex_bytes(&sa.sync_committee_bits.as_ssz_bytes()),
        "sync_committee_signature": hex_bytes(sa.sync_committee_signature.as_slice()),
    })
}

fn branch_json<const N: u64>(
    branch: &pharos_ssz::SszVector<pharos_utils::Bytes32, N>,
) -> serde_json::Value {
    let items: Vec<serde_json::Value> = branch
        .iter()
        .map(|b| serde_json::Value::String(hex_bytes(b.as_slice())))
        .collect();
    serde_json::Value::Array(items)
}

// ── LcApiSerializer trait ─────────────────────────────────────────────────────

/// Implemented by concrete LC container types so `NodeChainState` can build a
/// `LcEnvelope` without pharos-api naming the const-generic types.
///
/// Mirrors the `BlockApiSerializer` pattern in `dto/block.rs`.
pub trait LcApiSerializer {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError>;
    fn to_ssz_bytes(&self) -> Vec<u8>;
    fn attested_slot(&self) -> u64;
}

// ── Altair impls ──────────────────────────────────────────────────────────────

impl<const N: u64> LcApiSerializer for AltairBootstrap<N> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "header": altair_lc_header_json(&self.header),
            "current_sync_committee": sync_committee_json(&self.current_sync_committee),
            "current_sync_committee_branch": branch_json(&self.current_sync_committee_branch),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.header.beacon.slot.0
    }
}

impl<const N: u64> LcApiSerializer for AltairUpdate<N> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "attested_header": altair_lc_header_json(&self.attested_header),
            "next_sync_committee": sync_committee_json(&self.next_sync_committee),
            "next_sync_committee_branch": branch_json(&self.next_sync_committee_branch),
            "finalized_header": altair_lc_header_json(&self.finalized_header),
            "finality_branch": branch_json(&self.finality_branch),
            "sync_aggregate": sync_aggregate_json(&self.sync_aggregate),
            "signature_slot": q(self.signature_slot.0),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
}

impl<const N: u64> LcApiSerializer for AltairFinalityUpdate<N> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "attested_header": altair_lc_header_json(&self.attested_header),
            "finalized_header": altair_lc_header_json(&self.finalized_header),
            "finality_branch": branch_json(&self.finality_branch),
            "sync_aggregate": sync_aggregate_json(&self.sync_aggregate),
            "signature_slot": q(self.signature_slot.0),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
}

impl<const N: u64> LcApiSerializer for AltairOptimisticUpdate<N> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "attested_header": altair_lc_header_json(&self.attested_header),
            "sync_aggregate": sync_aggregate_json(&self.sync_aggregate),
            "signature_slot": q(self.signature_slot.0),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
}

// ── Capella impls ─────────────────────────────────────────────────────────────

impl<const N: u64, const B: u64, const X: u64> LcApiSerializer for CapellaBootstrap<N, B, X> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "header": capella_lc_header_json(&self.header),
            "current_sync_committee": sync_committee_json(&self.current_sync_committee),
            "current_sync_committee_branch": branch_json(&self.current_sync_committee_branch),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.header.beacon.slot.0
    }
}

impl<const N: u64, const B: u64, const X: u64> LcApiSerializer for CapellaUpdate<N, B, X> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "attested_header": capella_lc_header_json(&self.attested_header),
            "next_sync_committee": sync_committee_json(&self.next_sync_committee),
            "next_sync_committee_branch": branch_json(&self.next_sync_committee_branch),
            "finalized_header": capella_lc_header_json(&self.finalized_header),
            "finality_branch": branch_json(&self.finality_branch),
            "sync_aggregate": sync_aggregate_json(&self.sync_aggregate),
            "signature_slot": q(self.signature_slot.0),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
}

impl<const N: u64, const B: u64, const X: u64> LcApiSerializer for CapellaFinalityUpdate<N, B, X> {
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "attested_header": capella_lc_header_json(&self.attested_header),
            "finalized_header": capella_lc_header_json(&self.finalized_header),
            "finality_branch": branch_json(&self.finality_branch),
            "sync_aggregate": sync_aggregate_json(&self.sync_aggregate),
            "signature_slot": q(self.signature_slot.0),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
}

impl<const N: u64, const B: u64, const X: u64> LcApiSerializer
    for CapellaOptimisticUpdate<N, B, X>
{
    fn to_lc_json(&self) -> Result<serde_json::Value, ApiError> {
        Ok(serde_json::json!({
            "attested_header": capella_lc_header_json(&self.attested_header),
            "sync_aggregate": sync_aggregate_json(&self.sync_aggregate),
            "signature_slot": q(self.signature_slot.0),
        }))
    }
    fn to_ssz_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
    fn attested_slot(&self) -> u64 {
        self.attested_header.beacon.slot.0
    }
}
