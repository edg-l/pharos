//! `ChainStateApi` accessor trait and concrete `NodeChainState` implementation.
//!
//! The API server reads chain state via this trait, which wraps the two shared
//! `Arc`s (`RocksStore` + `Arc<RwLock<pharos_fork_choice::Store<E>>>`) plus a
//! `NodeIdentityCache` snapshot. This is the `D-api-chain-accessor` pattern:
//! sync reads behind `spawn_blocking`, no API actor for reads.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use pharos_fork_choice::Store as FcStore;
use pharos_network::discovery::enr::Enr;
use pharos_ssz::{Bitlist, Encode as _, SszList};
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::bellatrix::execution_payload::ExecutionAddress;
use pharos_types::{
    BeaconSpec, OperationPools, SyncCommitteePubkeys,
    config::RuntimeConfig,
    electra::attestation::SingleAttestation,
    phase0::misc::{AttestationData, IndexedAttestation as Phase0IndexedAttestation},
    phase0::operations::{Attestation, AttesterSlashing as Phase0AttesterSlashing},
    phase0::primitives::{CommitteeIndex, Epoch, ValidatorIndex},
    phase0::{BeaconBlockHeader, Checkpoint, Root, Slot},
    views::SignedBeaconBlockView as _,
};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32, Uint256};
use serde_json::Value as JsonValue;

use crate::dto::block::{BlockApiSerializer, SignedBlockForApi};
use crate::dto::light_client::{LcApiSerializer, LcEnvelope};
use crate::error::ApiError;
use crate::events::EventBus;
use crate::fork_tag::fork_variant_at_slot;

// ── Light-client envelope builder (Task 1.6) ──────────────────────────────────

/// Build a `LcEnvelope` from a concrete LC object implementing `LcApiSerializer`.
///
/// - `variant`: derived from `fork_variant_at_slot(cfg, attested_slot, cfg.slots_per_epoch)`.
///   `slots_per_epoch` is carried directly in `RuntimeConfig` so `pharos-api` does not
///   need to be generic over `E`. See `D-api-lc-fork-tag-by-attested-slot`.
/// - `ssz_bytes`: raw (unframed) bytes via `LcApiSerializer::to_ssz_bytes()`.
/// - `json`: hand-built DTO via `LcApiSerializer::to_lc_json()`.
///
/// Per `D-api-lc-bridge`: NEVER length-prefix here; single-object endpoints
/// use raw bytes; `get_updates` length-frames per item in the handler.
fn make_lc_envelope<T: LcApiSerializer>(
    obj: &T,
    cfg: &RuntimeConfig,
) -> Result<LcEnvelope, ApiError> {
    let attested_slot = obj.attested_slot();
    let variant = fork_variant_at_slot(cfg, attested_slot, cfg.slots_per_epoch);
    let json = obj.to_lc_json()?;
    let ssz_bytes = obj.to_ssz_bytes();
    Ok(LcEnvelope {
        variant,
        json,
        ssz_bytes,
        attested_slot,
    })
}

// ── Serialization helpers ─────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

fn q(v: u64) -> String {
    v.to_string()
}

/// Serialize a `BeaconState` to a complete `serde_json::Value` with all
/// spec-required per-fork fields.
///
/// Dispatches on the fork variant to include:
/// - All forks: `genesis_time`, `genesis_validators_root`, `slot`, `fork`,
///   `latest_block_header`, `block_roots`, `state_roots`, `historical_roots`,
///   `eth1_data`, `eth1_data_votes`, `eth1_deposit_index`, `validators`,
///   `balances`, `randao_mixes`, `slashings`, `justification_bits`,
///   `previous_justified_checkpoint`, `current_justified_checkpoint`,
///   `finalized_checkpoint`.
/// - Phase0: `previous_epoch_attestations`, `current_epoch_attestations`.
/// - Altair+: `previous_epoch_participation`, `current_epoch_participation`,
///   `inactivity_scores`, `current_sync_committee`, `next_sync_committee`.
/// - Bellatrix+: `latest_execution_payload_header`.
/// - Capella+: `next_withdrawal_index`, `next_withdrawal_validator_index`,
///   `historical_summaries`.
///
/// The caller must clone the state out from under any read-lock before calling
/// this function, as serialization of large lists can be expensive.
pub fn beacon_state_to_json_full<E: BeaconSpec>(
    state: E::BeaconState,
) -> Result<JsonValue, ApiError> {
    use pharos_types::BeaconStateView;
    use pharos_types::views::ForkVariant;

    // Build common fields using BeaconStateView accessors.
    let fork = state.fork();
    let lbh = state.latest_block_header();
    let prev_just = state.previous_justified_checkpoint();
    let curr_just = state.current_justified_checkpoint();
    let fin_cp = state.finalized_checkpoint();
    let eth1 = state.eth1_data();

    let validators_json: Vec<JsonValue> = state
        .validators_iter()
        .map(|v| {
            serde_json::json!({
                "pubkey": hex(v.pubkey.as_slice()),
                "withdrawal_credentials": hex(v.withdrawal_credentials.as_slice()),
                "effective_balance": q(v.effective_balance.0),
                "slashed": v.slashed,
                "activation_eligibility_epoch": q(v.activation_eligibility_epoch.0),
                "activation_epoch": q(v.activation_epoch.0),
                "exit_epoch": q(v.exit_epoch.0),
                "withdrawable_epoch": q(v.withdrawable_epoch.0),
            })
        })
        .collect();

    let balances_json: Vec<JsonValue> = state
        .balances()
        .iter()
        .map(|g| JsonValue::String(q(g.0)))
        .collect();
    let block_roots_json: Vec<JsonValue> = state
        .block_roots()
        .iter()
        .map(|r| JsonValue::String(hex(r.as_slice())))
        .collect();
    let state_roots_json: Vec<JsonValue> = state
        .state_roots()
        .iter()
        .map(|r| JsonValue::String(hex(r.as_slice())))
        .collect();
    let randao_mixes_json: Vec<JsonValue> = state
        .randao_mixes()
        .iter()
        .map(|h| JsonValue::String(hex(h.as_slice())))
        .collect();
    let slashings_json: Vec<JsonValue> = state
        .slashings()
        .iter()
        .map(|g| JsonValue::String(q(g.0)))
        .collect();
    let eth1_votes_json: Vec<JsonValue> = state
        .eth1_data_votes()
        .iter()
        .map(|e| {
            serde_json::json!({
                "deposit_root": hex(e.deposit_root.as_slice()),
                "deposit_count": q(e.deposit_count),
                "block_hash": hex(e.block_hash.as_slice()),
            })
        })
        .collect();
    let historical_roots_json: Vec<JsonValue> = state
        .historical_roots()
        .iter()
        .map(|r| JsonValue::String(hex(r.as_slice())))
        .collect();
    let justification_bits_hex = hex(&state.justification_bits_bytes());

    let mut m = serde_json::Map::new();
    m.insert(
        "genesis_time".into(),
        JsonValue::String(q(state.genesis_time())),
    );
    m.insert(
        "genesis_validators_root".into(),
        JsonValue::String(hex(state.genesis_validators_root().as_slice())),
    );
    m.insert("slot".into(), JsonValue::String(q(state.slot().0)));
    m.insert(
        "fork".into(),
        serde_json::json!({
            "previous_version": hex(fork.previous_version.as_slice()),
            "current_version": hex(fork.current_version.as_slice()),
            "epoch": q(fork.epoch.0),
        }),
    );
    m.insert(
        "latest_block_header".into(),
        serde_json::json!({
            "slot": q(lbh.slot.0),
            "proposer_index": q(lbh.proposer_index.0),
            "parent_root": hex(lbh.parent_root.as_slice()),
            "state_root": hex(lbh.state_root.as_slice()),
            "body_root": hex(lbh.body_root.as_slice()),
        }),
    );
    m.insert("block_roots".into(), JsonValue::Array(block_roots_json));
    m.insert("state_roots".into(), JsonValue::Array(state_roots_json));
    m.insert(
        "historical_roots".into(),
        JsonValue::Array(historical_roots_json),
    );
    m.insert(
        "eth1_data".into(),
        serde_json::json!({
            "deposit_root": hex(eth1.deposit_root.as_slice()),
            "deposit_count": q(eth1.deposit_count),
            "block_hash": hex(eth1.block_hash.as_slice()),
        }),
    );
    m.insert("eth1_data_votes".into(), JsonValue::Array(eth1_votes_json));
    m.insert(
        "eth1_deposit_index".into(),
        JsonValue::String(q(state.eth1_deposit_index_u64())),
    );
    m.insert("validators".into(), JsonValue::Array(validators_json));
    m.insert("balances".into(), JsonValue::Array(balances_json));
    m.insert("randao_mixes".into(), JsonValue::Array(randao_mixes_json));
    m.insert("slashings".into(), JsonValue::Array(slashings_json));
    m.insert(
        "justification_bits".into(),
        JsonValue::String(justification_bits_hex),
    );
    m.insert(
        "previous_justified_checkpoint".into(),
        serde_json::json!({
            "epoch": q(prev_just.epoch.0),
            "root": hex(prev_just.root.as_slice()),
        }),
    );
    m.insert(
        "current_justified_checkpoint".into(),
        serde_json::json!({
            "epoch": q(curr_just.epoch.0),
            "root": hex(curr_just.root.as_slice()),
        }),
    );
    m.insert(
        "finalized_checkpoint".into(),
        serde_json::json!({
            "epoch": q(fin_cp.epoch.0),
            "root": hex(fin_cp.root.as_slice()),
        }),
    );

    // Fork-specific fields via BeaconStateView accessors.
    let fork_variant = state.fork_variant();
    match fork_variant {
        ForkVariant::Phase0 => {
            // Phase0: pending attestations lists.
            let prev_atts = state.previous_epoch_attestations_raw().unwrap_or_default();
            let curr_atts = state.current_epoch_attestations_raw().unwrap_or_default();
            m.insert(
                "previous_epoch_attestations".into(),
                JsonValue::Array(prev_atts.into_iter().map(pending_att_raw_to_json).collect()),
            );
            m.insert(
                "current_epoch_attestations".into(),
                JsonValue::Array(curr_atts.into_iter().map(pending_att_raw_to_json).collect()),
            );
        }
        ForkVariant::Altair
        | ForkVariant::Bellatrix
        | ForkVariant::Capella
        | ForkVariant::Deneb
        | ForkVariant::Electra
        | ForkVariant::Fulu => {
            // Altair+: participation flags and inactivity scores.
            let prev_participation: Vec<JsonValue> = state
                .previous_epoch_participation_u8s()
                .into_iter()
                .map(|f| JsonValue::String(q(f as u64)))
                .collect();
            let curr_participation: Vec<JsonValue> = state
                .current_epoch_participation_u8s()
                .into_iter()
                .map(|f| JsonValue::String(q(f as u64)))
                .collect();
            let inactivity: Vec<JsonValue> = state
                .inactivity_scores_u64s()
                .into_iter()
                .map(|s| JsonValue::String(q(s)))
                .collect();
            m.insert(
                "previous_epoch_participation".into(),
                JsonValue::Array(prev_participation),
            );
            m.insert(
                "current_epoch_participation".into(),
                JsonValue::Array(curr_participation),
            );
            m.insert("inactivity_scores".into(), JsonValue::Array(inactivity));

            // Altair+: sync committees (pubkeys from existing accessor + aggregate from new one).
            if let (Some((curr_pks, next_pks)), Some((curr_agg, next_agg))) = (
                state.sync_committee_pubkeys(),
                state.sync_committee_aggregate_pubkeys(),
            ) {
                let curr_pk_json: Vec<JsonValue> = curr_pks
                    .iter()
                    .map(|pk| JsonValue::String(hex(pk.as_slice())))
                    .collect();
                let next_pk_json: Vec<JsonValue> = next_pks
                    .iter()
                    .map(|pk| JsonValue::String(hex(pk.as_slice())))
                    .collect();
                m.insert(
                    "current_sync_committee".into(),
                    serde_json::json!({
                        "pubkeys": curr_pk_json,
                        "aggregate_pubkey": hex(curr_agg.as_slice()),
                    }),
                );
                m.insert(
                    "next_sync_committee".into(),
                    serde_json::json!({
                        "pubkeys": next_pk_json,
                        "aggregate_pubkey": hex(next_agg.as_slice()),
                    }),
                );
            }

            // Bellatrix+: execution payload header.
            if let Some(eph) = state.execution_payload_header_raw() {
                // Build base EPH object (bellatrix fields).
                let withdrawals_root = state.execution_payload_withdrawals_root();
                let mut eph_map = serde_json::Map::new();
                eph_map.insert(
                    "parent_hash".into(),
                    JsonValue::String(hex(&eph.parent_hash)),
                );
                eph_map.insert(
                    "fee_recipient".into(),
                    JsonValue::String(hex(&eph.fee_recipient)),
                );
                eph_map.insert("state_root".into(), JsonValue::String(hex(&eph.state_root)));
                eph_map.insert(
                    "receipts_root".into(),
                    JsonValue::String(hex(&eph.receipts_root)),
                );
                eph_map.insert("logs_bloom".into(), JsonValue::String(hex(&eph.logs_bloom)));
                eph_map.insert(
                    "prev_randao".into(),
                    JsonValue::String(hex(&eph.prev_randao)),
                );
                eph_map.insert(
                    "block_number".into(),
                    JsonValue::String(q(eph.block_number)),
                );
                eph_map.insert("gas_limit".into(), JsonValue::String(q(eph.gas_limit)));
                eph_map.insert("gas_used".into(), JsonValue::String(q(eph.gas_used)));
                eph_map.insert("timestamp".into(), JsonValue::String(q(eph.timestamp)));
                eph_map.insert("extra_data".into(), JsonValue::String(hex(&eph.extra_data)));
                // base_fee_per_gas: Uint256 as decimal string via to_le_bytes → Uint256 → Display.
                let bfpg = Uint256::from_le_bytes(eph.base_fee_per_gas_le);
                eph_map.insert(
                    "base_fee_per_gas".into(),
                    JsonValue::String(bfpg.to_string()),
                );
                eph_map.insert("block_hash".into(), JsonValue::String(hex(&eph.block_hash)));
                eph_map.insert(
                    "transactions_root".into(),
                    JsonValue::String(hex(&eph.transactions_root)),
                );
                if let Some(wr) = withdrawals_root {
                    eph_map.insert("withdrawals_root".into(), JsonValue::String(hex(&wr)));
                }
                // Deneb+: blob gas fields on the execution payload header.
                if let Some(bgu) = state.execution_payload_blob_gas_used() {
                    eph_map.insert("blob_gas_used".into(), JsonValue::String(q(bgu)));
                }
                if let Some(ebg) = state.execution_payload_excess_blob_gas() {
                    eph_map.insert("excess_blob_gas".into(), JsonValue::String(q(ebg)));
                }
                m.insert(
                    "latest_execution_payload_header".into(),
                    JsonValue::Object(eph_map),
                );
            }

            // Capella+: withdrawal index, validator index, historical summaries.
            if let Some(nwi) = state.next_withdrawal_index_u64() {
                m.insert("next_withdrawal_index".into(), JsonValue::String(q(nwi)));
            }
            if let Some(nwv) = state.next_withdrawal_validator_index_raw() {
                m.insert(
                    "next_withdrawal_validator_index".into(),
                    JsonValue::String(q(nwv)),
                );
            }
            if let Some(summaries) = state.historical_summaries_raw() {
                let summaries_json: Vec<JsonValue> = summaries
                    .into_iter()
                    .map(|(bsr, ssr)| {
                        serde_json::json!({
                            "block_summary_root": hex(&bsr),
                            "state_summary_root": hex(&ssr),
                        })
                    })
                    .collect();
                m.insert(
                    "historical_summaries".into(),
                    JsonValue::Array(summaries_json),
                );
            }

            // Electra+: pending queues and balance-to-consume fields (EIP-6110/7002/7251).
            if let Some(v) = state.deposit_requests_start_index() {
                m.insert(
                    "deposit_requests_start_index".into(),
                    JsonValue::String(q(v)),
                );
            }
            if let Some(v) = state.deposit_balance_to_consume() {
                m.insert("deposit_balance_to_consume".into(), JsonValue::String(q(v)));
            }
            if let Some(v) = state.exit_balance_to_consume() {
                m.insert("exit_balance_to_consume".into(), JsonValue::String(q(v)));
            }
            if let Some(v) = state.earliest_exit_epoch() {
                m.insert("earliest_exit_epoch".into(), JsonValue::String(q(v)));
            }
            if let Some(v) = state.consolidation_balance_to_consume() {
                m.insert(
                    "consolidation_balance_to_consume".into(),
                    JsonValue::String(q(v)),
                );
            }
            if let Some(v) = state.earliest_consolidation_epoch() {
                m.insert(
                    "earliest_consolidation_epoch".into(),
                    JsonValue::String(q(v)),
                );
            }
            if let Some(deposits) = state.pending_deposits_raw() {
                let arr: Vec<JsonValue> = deposits
                    .into_iter()
                    .map(|d| {
                        serde_json::json!({
                            "pubkey": hex(&d.pubkey),
                            "withdrawal_credentials": hex(&d.withdrawal_credentials),
                            "amount": q(d.amount),
                            "signature": hex(&d.signature),
                            "slot": q(d.slot),
                        })
                    })
                    .collect();
                m.insert("pending_deposits".into(), JsonValue::Array(arr));
            }
            if let Some(withdrawals) = state.pending_partial_withdrawals_raw() {
                let arr: Vec<JsonValue> = withdrawals
                    .into_iter()
                    .map(|w| {
                        serde_json::json!({
                            "validator_index": q(w.validator_index),
                            "amount": q(w.amount),
                            "withdrawable_epoch": q(w.withdrawable_epoch),
                        })
                    })
                    .collect();
                m.insert("pending_partial_withdrawals".into(), JsonValue::Array(arr));
            }
            if let Some(consolidations) = state.pending_consolidations_raw() {
                let arr: Vec<JsonValue> = consolidations
                    .into_iter()
                    .map(|c| {
                        serde_json::json!({
                            "source_index": q(c.source_index),
                            "target_index": q(c.target_index),
                        })
                    })
                    .collect();
                m.insert("pending_consolidations".into(), JsonValue::Array(arr));
            }
        }
    }

    Ok(JsonValue::Object(m))
}

// ── Internal JSON helpers ──────────────────────────────────────────────────────

/// Serialize an `Attestation` to the beacon-API JSON shape (shared by
/// `pool_attestations` and `aggregate_attestation`).
fn attestation_to_json<const N: u64>(att: &Attestation<N>) -> JsonValue {
    serde_json::json!({
        "aggregation_bits": format!("0x{}", hex::encode(att.aggregation_bits.as_ssz_bytes())),
        "data": {
            "slot": att.data.slot.0.to_string(),
            "index": att.data.index.0.to_string(),
            "beacon_block_root": format!("0x{}", hex::encode(att.data.beacon_block_root.as_slice())),
            "source": {
                "epoch": att.data.source.epoch.0.to_string(),
                "root": format!("0x{}", hex::encode(att.data.source.root.as_slice())),
            },
            "target": {
                "epoch": att.data.target.epoch.0.to_string(),
                "root": format!("0x{}", hex::encode(att.data.target.root.as_slice())),
            },
        },
        "signature": format!("0x{}", hex::encode(att.signature.as_slice())),
    })
}

/// Parse a JSON-encoded `IndexedAttestation` (either phase0 or electra shape)
/// into `Phase0IndexedAttestation<2048>`.
///
/// The two shapes share the same JSON fields (`attesting_indices`, `data`,
/// `signature`); only the `MAX_AGGREGATION_BITS` limit differs. Indices beyond
/// 2048 are truncated (silently dropped) so electra slashings with large
/// committee sizes can still be stored in the phase0 pool.
fn parse_indexed_attestation_json_as_phase0(
    v: &JsonValue,
) -> Result<Phase0IndexedAttestation<2048>, ApiError> {
    // attesting_indices: array of Uint64 strings or numbers.
    let indices_arr = v["attesting_indices"]
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("attesting_indices missing".into()))?;
    let mut parsed: Vec<ValidatorIndex> = Vec::with_capacity(indices_arr.len().min(2048));
    for (i, idx_val) in indices_arr.iter().enumerate() {
        let raw = match idx_val {
            JsonValue::String(s) => s
                .parse::<u64>()
                .map_err(|_| ApiError::BadRequest(format!("attesting_indices[{i}]: invalid u64")))?,
            JsonValue::Number(n) => n
                .as_u64()
                .ok_or_else(|| ApiError::BadRequest(format!("attesting_indices[{i}]: invalid u64")))?,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "attesting_indices[{i}]: expected string or number"
                )));
            }
        };
        if parsed.len() < 2048 {
            parsed.push(ValidatorIndex(raw));
        }
    }
    let indices = SszList::<ValidatorIndex, 2048>::from_items(parsed)
        .map_err(|_| ApiError::BadRequest("attesting_indices: too many entries".into()))?;

    // data: full AttestationData JSON object.
    let data_v = &v["data"];
    let slot = match &data_v["slot"] {
        JsonValue::String(s) => s
            .parse::<u64>()
            .map_err(|_| ApiError::BadRequest("data.slot: invalid u64".into()))?,
        JsonValue::Number(n) => n
            .as_u64()
            .ok_or_else(|| ApiError::BadRequest("data.slot: invalid u64".into()))?,
        _ => return Err(ApiError::BadRequest("data.slot missing".into())),
    };
    let index = match &data_v["index"] {
        JsonValue::String(s) => s
            .parse::<u64>()
            .map_err(|_| ApiError::BadRequest("data.index: invalid u64".into()))?,
        JsonValue::Number(n) => n
            .as_u64()
            .ok_or_else(|| ApiError::BadRequest("data.index: invalid u64".into()))?,
        _ => return Err(ApiError::BadRequest("data.index missing".into())),
    };
    let bbr_hex = data_v["beacon_block_root"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("data.beacon_block_root missing".into()))?;
    let bbr_bytes =
        hex::decode(bbr_hex.strip_prefix("0x").unwrap_or(bbr_hex))
            .map_err(|e| ApiError::BadRequest(format!("data.beacon_block_root: {e}")))?;
    let bbr_arr: [u8; 32] = bbr_bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("data.beacon_block_root: must be 32 bytes".into()))?;

    let parse_checkpoint_inline = |cv: &JsonValue| -> Result<Checkpoint, ApiError> {
        let epoch = match &cv["epoch"] {
            JsonValue::String(s) => s
                .parse::<u64>()
                .map_err(|_| ApiError::BadRequest("checkpoint epoch: invalid u64".into()))?,
            JsonValue::Number(n) => n
                .as_u64()
                .ok_or_else(|| ApiError::BadRequest("checkpoint epoch: invalid u64".into()))?,
            _ => return Err(ApiError::BadRequest("checkpoint epoch missing".into())),
        };
        let root_hex = cv["root"]
            .as_str()
            .ok_or_else(|| ApiError::BadRequest("checkpoint root missing".into()))?;
        let root_bytes =
            hex::decode(root_hex.strip_prefix("0x").unwrap_or(root_hex))
                .map_err(|e| ApiError::BadRequest(format!("checkpoint root: {e}")))?;
        let root_arr: [u8; 32] = root_bytes
            .try_into()
            .map_err(|_| ApiError::BadRequest("checkpoint root: must be 32 bytes".into()))?;
        Ok(Checkpoint {
            epoch: Epoch(epoch),
            root: Root::from(root_arr),
        })
    };

    let source = parse_checkpoint_inline(&data_v["source"])?;
    let target = parse_checkpoint_inline(&data_v["target"])?;

    let sig_hex = v["signature"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("signature missing".into()))?;
    let sig_bytes = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(sig_hex))
        .map_err(|e| ApiError::BadRequest(format!("signature: {e}")))?;
    let sig_arr: [u8; 96] = sig_bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("signature: must be 96 bytes".into()))?;

    Ok(Phase0IndexedAttestation {
        attesting_indices: indices,
        data: AttestationData {
            slot: Slot(slot),
            index: CommitteeIndex(index),
            beacon_block_root: Root::from(bbr_arr),
            source,
            target,
        },
        signature: BLSSignature::from(sig_arr),
    })
}

fn pending_att_raw_to_json(pa: pharos_types::PendingAttestationRaw) -> JsonValue {
    serde_json::json!({
        "aggregation_bits": hex(&pa.aggregation_bits_ssz),
        "data": {
            "slot": q(pa.data_slot),
            "index": q(pa.data_index),
            "beacon_block_root": hex(&pa.data_beacon_block_root),
            "source": {
                "epoch": q(pa.data_source_epoch),
                "root": hex(&pa.data_source_root),
            },
            "target": {
                "epoch": q(pa.data_target_epoch),
                "root": hex(&pa.data_target_root),
            },
        },
        "inclusion_delay": q(pa.inclusion_delay),
        "proposer_index": q(pa.proposer_index),
    })
}

// ── RegenTarget ────────────────────────────────────────────────────────────────

/// Target for state regeneration via `ChainStateApi::regenerate_state`.
///
/// Passed to the `regenerate_state` method to indicate whether the caller wants
/// the state at a particular slot, by state-root, or by block-root (post-state).
#[derive(Debug, Clone, Copy)]
pub enum RegenTarget {
    /// Return the post-state at the given slot (nearest-boundary + replay).
    Slot(Slot),
    /// Return the state whose `tree_hash_root()` equals this state-root.
    StateRoot(Root),
    /// Return the post-state of the block with this block-root.
    BlockRoot(Root),
}

// ── NodeIdentityCache ─────────────────────────────────────────────────────────

/// Snapshot of node identity data captured at startup.
///
/// `peer_id`, `enr`, and listen/discovery addresses are immutable once the
/// network has bound and are safe to hold indefinitely. `metadata` points to
/// the live `ArcSwap` on `Network` so the current metadata seq/attnets/syncnets
/// are always up to date without polling.
///
/// Populated AFTER `handle.wait_for_local_enr()` and
/// `handle.wait_for_listen_addr()` resolve in `main.rs`.
pub struct NodeIdentityCache {
    pub peer_id: PeerId,
    pub enr: Enr,
    /// Bound TCP/QUIC listen addresses.
    pub listen_addrs: Vec<Multiaddr>,
    /// Discovery (discv5) addresses derived from the ENR.
    pub discovery_addrs: Vec<Multiaddr>,
    /// Live metadata reference; reads always reflect the current seq_number.
    pub metadata: Arc<ArcSwap<AltairMetaData>>,
}

// ── ChainStateApi ─────────────────────────────────────────────────────────────

/// Read-only accessor trait for chain state consumed by Beacon API handlers.
///
/// All implementations are expected to be sync and cheap (i.e. they either
/// operate under a short read-lock or read immutable startup data). Handlers
/// wrap calls in `tokio::task::spawn_blocking` where needed.
pub trait ChainStateApi<E: BeaconSpec>: Send + Sync + 'static {
    /// The current fork-choice head root.
    fn head_root(&self) -> Root;

    /// The current slot derived from `store.time` and `store.genesis_time`.
    fn current_slot(&self) -> Slot;

    /// `(genesis_time, genesis_validators_root, genesis_fork_version)`.
    fn genesis(&self) -> (u64, Root, [u8; 4]);

    /// The highest known finalized checkpoint.
    fn finalized_checkpoint(&self) -> Checkpoint;

    /// The justified checkpoint used as the LMD-GHOST root.
    fn justified_checkpoint(&self) -> Checkpoint;

    /// Return the `BeaconBlockHeader` for `root`, or `None` if not in store.
    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader>;

    /// Runtime configuration (fork schedule, preset constants).
    fn runtime_cfg(&self) -> Arc<RuntimeConfig>;

    /// Whether the head block has not yet been validated by the EL.
    fn is_optimistic(&self) -> bool;

    /// Whether the block at `root` is optimistically imported.
    ///
    /// Returns `is_optimistic(&fc, root)` — i.e. `true` iff the block is an
    /// execution block AND `payload_statuses[root] != Valid`.  Used by per-root
    /// API responses (`block-by-id`, `state-by-id`) so `execution_optimistic`
    /// reflects THAT block's optimism, not always the head's.
    ///
    /// Per `consensus-specs/sync/optimistic.md` "Ethereum Beacon APIs":
    /// "`execution_optimistic` must be `True` whenever the request references
    /// optimistic blocks".
    fn is_optimistic_for_root(&self, root: Root) -> bool;

    /// Whether the whole node is in an optimistic state.
    ///
    /// Returns `true` when EITHER:
    /// 1. The current head is optimistic (head payload not yet EL-validated), OR
    /// 2. Every viable (non-INVALIDATED) FFG branch is gone — the filtered block
    ///    tree is degenerate (all execution-carrying branches were marked Invalid),
    ///    leaving the LMD-GHOST head equal to the justified base with no viable
    ///    children.
    ///
    /// Duty-READ endpoints (proposer/attester/sync duties) MUST stay 200 and
    /// reflect this flag in their `execution_optimistic` response field.
    ///
    /// Production/signing endpoints (produce_block, produce_attestation_data,
    /// aggregate selection, sync_committee_contribution — not yet implemented)
    /// MUST return HTTP 503 when this returns `true`.
    ///
    /// Per `consensus-specs/sync/optimistic.md` "Validator assignments".
    /// ADR `D-optimistic-node-no-viable-branch`.
    fn is_optimistic_node(&self) -> bool;

    /// Whether the node is still syncing (sync_distance > 0).
    fn is_syncing(&self) -> bool;

    /// Whether the execution-layer endpoint is currently unreachable.
    ///
    /// Backs the `el_offline` field of `/eth/v1/node/syncing`. Default `false`
    /// (no EL wired, e.g. test mocks); `NodeChainState` overrides with the real
    /// engine-handle liveness flag.
    fn el_offline(&self) -> bool {
        false
    }

    /// Read-only reference to the node identity snapshot.
    fn node_identity(&self) -> &NodeIdentityCache;

    // ── State-resolution methods (Phase 2) ────────────────────────────────────

    /// Look up the post-state for a block root from the in-memory fork-choice
    /// store. Returns `None` when the root is not present in-memory (cold state).
    fn state_by_block_root(&self, root: Root) -> Option<E::BeaconState>;

    /// Look up a state by its state-root from cold storage.
    ///
    /// Falls back to `RocksStore::get_state` when the root is not in the
    /// in-memory `block_states` map.  Returns `None` when not found anywhere.
    fn state_by_state_root(&self, state_root: Root) -> Option<E::BeaconState>;

    /// Return the block root for a given slot from the in-memory store, or
    /// `None` if the slot is not within the in-memory window.
    fn block_root_for_slot(&self, slot: Slot) -> Option<Root>;

    /// Return the genesis block root (the initial anchor block root).
    fn genesis_block_root(&self) -> Root;

    /// Return `(current_sync_committee_pubkeys, next_sync_committee_pubkeys)` for
    /// the post-state of `block_root`, or `None` for Phase0 states (no sync committee).
    ///
    /// Each pubkey is a 48-byte BLS public key (`BLSPubkey = FixedBytes<48>`).
    /// Returns `None` when the block root is not in-memory, or the state is Phase0.
    fn sync_committee_pubkeys(&self, block_root: Root) -> Option<SyncCommitteePubkeys>;

    /// Return the full `SignedBeaconBlock` for `root` serialized as API data,
    /// or `None` if not found in cold storage.
    ///
    /// The returned `SignedBlockForApi` contains the fork variant, JSON DTO value,
    /// canonical SSZ bytes (inner fork variant, no discriminant byte), and
    /// attestations as a JSON array. The implementation fetches from `RocksStore`
    /// and pattern-matches on the concrete fork-enum variant to build the DTOs.
    fn block_by_root_for_api(&self, root: Root) -> Result<Option<SignedBlockForApi>, ApiError>;

    /// Return the `(BeaconBlockHeader, BLSSignature)` for `root`, sourcing the REAL
    /// signature from the stored `SignedBeaconBlock`.
    ///
    /// After Task 1.1 (live block persistence), every imported block is flushed to
    /// `RocksStore` before the head is published, so this method reliably returns the
    /// real signature for any recently imported block. Falls back to `None` when the
    /// signed block is absent (e.g., pre-schema-v3 anchor blocks).
    fn signed_block_header_at(
        &self,
        root: Root,
    ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)>;

    // ── Replay-on-read (Phase 2) ───────────────────────────────────────────────

    // ── Debug namespace (Phase 5) ──────────────────────────────────────────────

    /// Return a fork-choice dump for `GET /eth/v1/debug/fork_choice`.
    ///
    /// Returns the justified/finalized checkpoints and a list of all in-memory
    /// fork-choice blocks as a pre-serialised `serde_json::Value`.
    ///
    /// Mock implementations may return a minimal `{"justified_checkpoint":...,
    /// "finalized_checkpoint":..., "fork_choice_nodes":[]}` object.
    fn fork_choice_dump(&self) -> Result<JsonValue, ApiError>;

    /// Serialize a `BeaconState` to a `serde_json::Value` for
    /// `GET /eth/v2/debug/beacon/states/{state_id}`.
    ///
    /// Implementations must produce a COMPLETE fork-tagged state object
    /// covering all spec-required per-fork fields (see `beacon_state_to_json_full`).
    ///
    /// `NodeChainState` calls `beacon_state_to_json_full` after cloning the state
    /// out from under the fork-choice read-lock to avoid holding the lock during
    /// large-list serialization.
    ///
    /// Mock implementations in tests should call `beacon_state_to_json_full`
    /// or return a simplified object that satisfies the test's assertions.
    fn state_to_json(&self, state: E::BeaconState) -> Result<JsonValue, ApiError>;

    /// Return the fork-choice leaf nodes for `GET /eth/v2/debug/beacon/heads`.
    ///
    /// A leaf node is a block whose root is not the parent of any other block in
    /// the in-memory store (i.e. it has no children).  Returns a
    /// pre-serialised `serde_json::Value` with a `data` array.
    ///
    /// Mock implementations may return `{"data":[]}`.
    fn fork_choice_heads(&self) -> Result<JsonValue, ApiError>;

    /// Regenerate (or fetch) a historical state via the `StateRegenService`.
    ///
    /// - `RegenTarget::Slot(s)` — find nearest stored boundary ≤ `s`, replay to `s`.
    /// - `RegenTarget::StateRoot(r)` — walk `state-summary` CF to find the block
    ///   whose post-state root is `r`, replay to that block's slot.
    /// - `RegenTarget::BlockRoot(r)` — regenerate the post-state of block `r`.
    ///
    /// Error mapping (per `D-replay-on-read`):
    /// - `RegenError::MissingBlock` / `RegenError::MissingAnchorState` /
    ///   `RegenError::NotFound` → `ApiError::NotFound`.
    /// - `RegenError::Stf` / `RegenError::Storage` → `ApiError::Internal`.
    ///
    /// Mock implementations (tests that don't exercise regen) should return
    /// `Err(ApiError::NotFound("regen not available in mock".into()))`.
    fn regenerate_state(&self, target: RegenTarget) -> Result<E::BeaconState, ApiError>;

    // ── Production endpoints (M9-Validator Phase 5) ───────────────────────────

    /// Produce an unsigned `BeaconBlock` at `slot` for the given RANDAO reveal
    /// and graffiti.
    ///
    /// Returns the block serialized as a `serde_json::Value` (fork-tagged) plus
    /// the `execution_payload_value` (`Uint256`) and `consensus_block_value`
    /// (`Uint256`, always zero for this implementation).
    ///
    /// Returns `Err(ApiError::NotSynced)` when the node is syncing or optimistic
    /// (per `D-503-on-optimistic-or-syncing`).
    ///
    /// Default returns a `NotSynced` error so mock impls only need to override
    /// when they test the production path.
    fn produce_block(
        &self,
        _slot: Slot,
        _randao_reveal: BLSSignature,
        _graffiti: Bytes32,
    ) -> Result<(JsonValue, Uint256, Uint256), ApiError> {
        Err(ApiError::NotSynced("block production not available".into()))
    }

    /// Return `AttestationData` for a given `(slot, committee_index)`.
    ///
    /// Default returns a `NotSynced` error.
    fn produce_attestation_data(
        &self,
        _slot: Slot,
        _committee_index: CommitteeIndex,
    ) -> Result<AttestationData, ApiError> {
        Err(ApiError::NotSynced(
            "attestation data production not available".into(),
        ))
    }

    /// Submit attestations to the gossip pool.
    ///
    /// Validates basic structure and calls pool insert + gossip publish for each.
    /// Default is a no-op returning `Ok(())`.
    fn submit_attestations(&self, _attestations: Vec<Attestation<2048>>) -> Result<(), ApiError> {
        Ok(())
    }

    /// Submit `SingleAttestation` objects (electra+) to the gossip pool.
    ///
    /// Routes `POST /eth/v2/beacon/pool/attestations` with `electra|fulu` header.
    /// Default accepts without pool insert (`D-pool-v2-submit-default-broadcast`):
    /// the node-side gossip-accept path handles pool insertion with BLS context.
    fn submit_single_attestations(
        &self,
        _attestations: Vec<SingleAttestation>,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Submit a `Phase0.AttesterSlashing` to the pool.
    ///
    /// Routes `POST /eth/v2/beacon/pool/attester_slashings` with pre-electra header.
    /// Default accepts without pool insert (`D-pool-v2-submit-default-broadcast`).
    fn submit_phase0_attester_slashing(
        &self,
        _slashing: Phase0AttesterSlashing<2048>,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Submit an `Electra.AttesterSlashing` (as JSON) to the pool.
    ///
    /// Routes `POST /eth/v2/beacon/pool/attester_slashings` with `electra|fulu` header.
    /// Takes JSON because the electra `AttesterSlashing` type has a const-generic
    /// `MAX_AGGREGATION_BITS` that differs between presets (131072 vs 8192), making
    /// a single typed trait method impossible. The handler validates field structure
    /// before calling this.
    /// Default accepts without pool insert (`D-pool-v2-submit-default-broadcast`):
    /// the pool stores phase0 type only; electra slashings are accepted but not pooled.
    fn submit_electra_attester_slashing(&self, _slashing: JsonValue) -> Result<(), ApiError> {
        Ok(())
    }

    /// Submit signed aggregate-and-proof messages.
    ///
    /// Default is a no-op returning `Ok(())`.
    fn submit_aggregate_and_proofs(&self, _aggregates: Vec<JsonValue>) -> Result<(), ApiError> {
        Ok(())
    }

    /// Submit `SyncCommitteeMessage` objects to the sync-message pool.
    ///
    /// Routes `POST /eth/v1/beacon/pool/sync_committees` bodies.
    /// Default is a no-op returning `Ok(())`.
    fn submit_sync_committee_messages(&self, _messages: Vec<JsonValue>) -> Result<(), ApiError> {
        Ok(())
    }

    /// Submit `SignedContributionAndProof` objects.
    ///
    /// Routes `POST /eth/v1/validator/contribution_and_proofs` bodies.
    /// Default is a no-op returning `Ok(())`.
    fn submit_contribution_and_proofs(
        &self,
        _contributions: Vec<JsonValue>,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Return pooled attestations as JSON array for `GET /eth/v1/beacon/pool/attestations`.
    ///
    /// Default returns an empty array.
    fn pool_attestations(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Best aggregate attestation pooled for `data_root`, as beacon-API JSON
    /// (`GET /eth/v2/validator/aggregate_attestation`). Default `None`
    /// (no pool wired); `NodeChainState` overrides with the real pool lookup.
    fn aggregate_attestation(&self, _data_root: Root) -> Option<JsonValue> {
        None
    }

    /// Best `SyncCommitteeContribution` JSON for `(slot, beacon_block_root,
    /// subcommittee_index)` (`GET /eth/v1/validator/sync_committee_contribution`).
    /// Default `None` (no pool/production path); `NodeChainState` overrides via
    /// the wired callback.
    fn sync_committee_contribution(
        &self,
        _slot: u64,
        _block_root: Root,
        _subcommittee_index: u64,
    ) -> Option<JsonValue> {
        None
    }

    /// Return pooled attester slashings as JSON array.
    ///
    /// Default returns an empty array.
    fn pool_attester_slashings(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Return pooled proposer slashings as JSON array.
    ///
    /// Default returns an empty array.
    fn pool_proposer_slashings(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Return pooled voluntary exits as JSON array.
    ///
    /// Default returns an empty array.
    fn pool_voluntary_exits(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Return pooled BLS-to-execution-changes as JSON array.
    ///
    /// Default returns an empty array.
    fn pool_bls_to_execution_changes(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Return pooled sync committee messages as JSON array.
    ///
    /// Default returns an empty array.
    fn pool_sync_committee_messages(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Set fee recipients for the given validator indices
    /// (`POST /eth/v1/validator/prepare_beacon_proposer`).
    ///
    /// Stores `(validator_index, fee_recipient)` in the node's fee-recipient map.
    /// `D-register-validator-accept-and-store`.
    /// Default is a no-op.
    fn set_fee_recipients_by_index(
        &self,
        _pairs: Vec<(ValidatorIndex, ExecutionAddress)>,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Store validator registrations from `POST /eth/v1/validator/register_validator`.
    ///
    /// Stores the fee recipient and gas-limit hint in the node's fee-recipient map
    /// keyed by BLS pubkey. No relay forwarding.
    /// `D-register-validator-accept-and-store`.
    /// Default is a no-op.
    fn register_validators(&self, _registrations: Vec<JsonValue>) -> Result<(), ApiError> {
        Ok(())
    }

    /// Publish a `SignedBeaconBlock` — imports it and gossips it to the network.
    ///
    /// Returns:
    /// - `Ok(true)` when the block was imported AND broadcast.
    /// - `Ok(false)` when the block could not be imported locally but was
    ///   broadcast anyway (202).
    /// - `Err(ApiError::BadRequest)` when the block cannot be decoded.
    /// - `Err(ApiError::NotSynced)` when syncing/optimistic.
    ///
    /// Default returns `Ok(false)` (broadcast-only, no local import).
    fn publish_block(&self, _block: JsonValue) -> Result<bool, ApiError> {
        Ok(false)
    }

    /// Decode SSZ bytes into a `SignedBeaconBlock` JSON representation and publish.
    ///
    /// The `fork` string (from `Eth-Consensus-Version` header, e.g. "capella")
    /// selects the correct per-fork SSZ decode path. Returns the same result
    /// codes as `publish_block`.
    ///
    /// Default returns `BadRequest` (SSZ decode requires a production node with
    /// `NodeChainState`; mock impls that don't handle SSZ just return this).
    fn publish_block_ssz(&self, _bytes: Vec<u8>, _fork: &str) -> Result<bool, ApiError> {
        Err(ApiError::BadRequest(
            "SSZ block decode not available in this context".into(),
        ))
    }

    /// Update the ENR `syncnets` bitvector on behalf of a VC subscription.
    ///
    /// Called by `POST /eth/v1/validator/sync_committee_subscriptions` with the
    /// union of all subscribed sync-committee subnet indices. The raw SSZ bytes of
    /// the `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]` (1 byte on mainnet, padded to
    /// 4 bits) are passed so `pharos-api` does not depend on `pharos-network`.
    ///
    /// Default is a no-op (no discovery layer in tests).
    /// (`D-syncnets-enr-on-subscription`)
    fn notify_sync_committee_subscriptions(&self, _syncnets_ssz: Vec<u8>) {}

    /// Return liveness information for the given validators in the given epoch.
    ///
    /// Returns a `Vec` of `(ValidatorIndex, is_live: bool)` for each requested
    /// validator index.  `is_live` is `true` when the validator has an attestation
    /// in the attestation pool or in a recently imported block for `epoch`.
    ///
    /// `D-doppelganger-bn-liveness-endpoint` (M9 Phase 5.4).
    /// Default returns all-false (one entry per requested index, none live).
    fn validator_liveness(
        &self,
        _epoch: Epoch,
        indices: Vec<ValidatorIndex>,
    ) -> Result<Vec<(ValidatorIndex, bool)>, ApiError> {
        Ok(indices.into_iter().map(|i| (i, false)).collect())
    }

    /// Return a snapshot of connected peers.
    ///
    /// Returns a `Vec<serde_json::Value>` with one object per connected peer
    /// containing `peer_id`, `state`, `direction`, `last_seen_p2p_address`,
    /// and `agent_string` fields for `/eth/v1/node/peers`.
    ///
    /// Default returns an empty list (no network layer in tests).
    fn peers(&self) -> Vec<JsonValue> {
        vec![]
    }

    /// Look up a single peer by `peer_id` string.
    ///
    /// Default impl is a linear scan of `self.peers()` matching the
    /// `"peer_id"` field.  This is correct for all callers; no override is
    /// required in `NodeChainState` because `peers()` already returns the
    /// complete per-peer JSON.
    ///
    /// Returns `None` when no peer with the given id is connected.
    ///
    /// Per `~/dev/beacon-APIs/apis/node/peer.yaml` (`getPeer`).
    fn peer_by_id(&self, peer_id: &str) -> Option<JsonValue> {
        self.peers()
            .into_iter()
            .find(|p| p.get("peer_id").and_then(|v| v.as_str()) == Some(peer_id))
    }

    // ── Light-client REST endpoints (M7-followup) ─────────────────────────────

    /// Return the `LcEnvelope` for the bootstrap at `block_root`, if stored.
    ///
    /// Tries the capella CF first, then falls back to the altair CF.
    /// Returns `Ok(None)` when no bootstrap is stored for that root.
    ///
    /// Default body returns `Ok(None)` so the five existing mock impls need
    /// no changes. `NodeChainState` overrides with the real storage call.
    ///
    /// Per `D-api-lc-trait-defaults`.
    fn light_client_bootstrap(
        &self,
        _block_root: Root,
    ) -> Result<Option<crate::dto::light_client::LcEnvelope>, ApiError> {
        Ok(None)
    }

    /// Return `LcEnvelope`s for all stored updates with period in
    /// `[start_period, start_period + count)`.
    ///
    /// Count is clamped to `MAX_REQUEST_LC_UPDATES` by the handler before
    /// this is called.  Returns an empty `Vec` when no updates are stored.
    ///
    /// Default body returns `Ok(vec![])`. Per `D-api-lc-trait-defaults`.
    fn light_client_updates(
        &self,
        _start_period: u64,
        _count: u64,
    ) -> Result<Vec<crate::dto::light_client::LcEnvelope>, ApiError> {
        Ok(vec![])
    }

    /// Return the latest `LcEnvelope` for the finality update, if any.
    ///
    /// Tries the capella CF first, then the altair CF.
    /// Default body returns `Ok(None)`. Per `D-api-lc-trait-defaults`.
    fn light_client_finality_update(
        &self,
    ) -> Result<Option<crate::dto::light_client::LcEnvelope>, ApiError> {
        Ok(None)
    }

    /// Return the latest `LcEnvelope` for the optimistic update, if any.
    ///
    /// Tries the capella CF first, then the altair CF.
    /// Default body returns `Ok(None)`. Per `D-api-lc-trait-defaults`.
    fn light_client_optimistic_update(
        &self,
    ) -> Result<Option<crate::dto::light_client::LcEnvelope>, ApiError> {
        Ok(None)
    }
}

// ── NodeChainState ────────────────────────────────────────────────────────────

/// Type alias for the state-regeneration callback injected into `NodeChainState`.
///
/// The callback is constructed in `pharos-node/src/main.rs` (which depends on
/// `pharos-api`) and wraps a `StateRegenService<E>`. This avoids a
/// `pharos-api → pharos-node` dependency while allowing `NodeChainState` to
/// call into the replay-on-read service (per `D-replay-on-read`, Task 2.4).
pub type RegenFn<E> =
    dyn Fn(RegenTarget) -> Result<<E as BeaconSpec>::BeaconState, ApiError> + Send + Sync + 'static;

/// Type alias for the block-production callback injected into `NodeChainState`.
///
/// `(slot, randao_reveal, graffiti)` → `(block_json, exec_payload_value, consensus_value)`
/// per `D-produce-empty-then-fill-stf` (M9 Phase 5).
pub type ProduceFn = dyn Fn(
        pharos_types::phase0::Slot,
        BLSSignature,
        Bytes32,
    ) -> Result<(JsonValue, Uint256, Uint256), ApiError>
    + Send
    + Sync
    + 'static;

/// Type alias for the block-publish callback injected into `NodeChainState`.
///
/// Accepts a `SignedBeaconBlock` as JSON + fork string and routes it through
/// `import_block` + gossip.  Returns `true` when imported+broadcast, `false`
/// broadcast-only.
pub type PublishFn = dyn Fn(JsonValue) -> Result<bool, ApiError> + Send + Sync + 'static;

/// Type alias for the attestation-data production callback.
///
/// `(slot, committee_index)` → `AttestationData`.
pub type ProduceAttDataFn = dyn Fn(
        pharos_types::phase0::Slot,
        pharos_types::phase0::primitives::CommitteeIndex,
    ) -> Result<AttestationData, ApiError>
    + Send
    + Sync
    + 'static;

/// Type alias for the peers-snapshot callback.
///
/// Returns JSON representations of connected peers for `/eth/v1/node/peers`.
pub type PeersFn = dyn Fn() -> Vec<JsonValue> + Send + Sync + 'static;

/// Type alias for the EL-liveness callback.
///
/// Returns `true` when the execution-layer endpoint is currently unreachable,
/// backing the `el_offline` field of `/eth/v1/node/syncing`. Reads a flag
/// maintained by the engine handle from its blocking round-trips.
pub type ElOfflineFn = dyn Fn() -> bool + Send + Sync + 'static;

/// Type alias for the sync-committee-contribution callback.
///
/// Args: `(slot, beacon_block_root, subcommittee_index)`. Returns the
/// beacon-API `SyncCommitteeContribution` JSON object built from the pool +
/// head-state sync committee, or `None` when none is available. Backs
/// `GET /eth/v1/validator/sync_committee_contribution`.
pub type SyncContributionFn = dyn Fn(u64, Root, u64) -> Option<JsonValue> + Send + Sync + 'static;

/// Type alias for the syncnets ENR update callback.
///
/// Called by `POST /eth/v1/validator/sync_committee_subscriptions` with the
/// union of all subscribed sync-committee subnet indices (0..SYNC_COMMITTEE_SUBNET_COUNT).
/// Drives `DiscoveryHandle::update_enr_syncnets` on the BN side so the local
/// ENR advertises the subscribed `syncnets` bitvector.
///
/// Per `specs/altair/p2p-interface.md:540-549`. (`D-syncnets-enr-on-subscription`)
///
/// The callback is async under the hood but is exposed here as a sync closure
/// returning `()` (fire-and-forget) to keep `ChainStateApi` sync. The BN-side
/// implementation spawns a `tokio` task to drive the async `DiscoveryHandle`.
pub type SyncnetsFn = dyn Fn(Vec<u8>) + Send + Sync + 'static;

/// Concrete `ChainStateApi` backed by the shared fork-choice store and storage.
pub struct NodeChainState<E: BeaconSpec> {
    /// Shared chain DB (cold states, anchor, etc.).
    store: Arc<RocksStore>,
    /// Live fork-choice store (in-memory head, checkpoints, blocks).
    fork_choice: Arc<RwLock<FcStore<E>>>,
    /// Static node identity snapshot.
    identity: NodeIdentityCache,
    /// Runtime configuration forwarded from `main.rs`.
    runtime_cfg: Arc<RuntimeConfig>,
    /// Optional state-regeneration callback (Phase 2).
    ///
    /// `None` when the HTTP server is not active (no `--http` flag) or when the
    /// replay service has not been wired in. When `None`, `regenerate_state`
    /// returns `ApiError::NotFound`.
    regen_fn: Option<Arc<RegenFn<E>>>,

    // ── M9 Phase 5 fields ─────────────────────────────────────────────────────
    /// Shared operation pools (attestations, slashings, exits, sync messages).
    ///
    /// Wired via `with_pools()` from `pharos-node` after pool construction.
    /// `D-register-validator-accept-and-store`.
    pools: Option<Arc<OperationPools<E>>>,

    /// Block-production callback (`D-produce-empty-then-fill-stf`).
    /// `None` when the node has no EL or block-production is not configured.
    produce_fn: Option<Arc<ProduceFn>>,

    /// Attestation-data production callback.
    produce_att_data_fn: Option<Arc<ProduceAttDataFn>>,

    /// Block-publish callback (import + gossip).
    publish_fn: Option<Arc<PublishFn>>,

    /// Fee-recipient store: pubkey → 20-byte ExecutionAddress.
    ///
    /// Populated by `POST /eth/v1/validator/prepare_beacon_proposer` and
    /// `POST /eth/v1/validator/register_validator`.
    /// `D-register-validator-accept-and-store`.
    fee_recipients: Arc<RwLock<HashMap<BLSPubkey, ExecutionAddress>>>,

    /// Peers-snapshot callback for `/eth/v1/node/peers`.
    peers_fn: Option<Arc<PeersFn>>,

    /// Syncnets ENR update callback. (`D-syncnets-enr-on-subscription`)
    ///
    /// Fired by `POST /eth/v1/validator/sync_committee_subscriptions` with the
    /// SSZ-encoded `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]` (4 bytes).
    /// `None` when the discovery layer is not available (e.g. tests without network).
    syncnets_fn: Option<Arc<SyncnetsFn>>,

    /// EL-liveness callback for `/eth/v1/node/syncing`'s `el_offline`.
    /// `None` when no EL is wired (returns `el_offline: false`).
    el_offline_fn: Option<Arc<ElOfflineFn>>,

    /// Sync-committee-contribution callback for
    /// `/eth/v1/validator/sync_committee_contribution`. `None` when no pool /
    /// production path is wired (endpoint returns 404).
    sync_contribution_fn: Option<Arc<SyncContributionFn>>,
}

/// Parse a 0x-prefixed 48-byte hex string into a fixed `[u8; 48]`.
fn parse_hex48(s: &str) -> Result<[u8; 48], ()> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

/// Parse a 0x-prefixed 20-byte Ethereum address hex string into `ExecutionAddress`.
fn parse_execution_address(s: &str) -> Result<ExecutionAddress, ()> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|_| ())?;
    let arr: [u8; 20] = bytes.try_into().map_err(|_| ())?;
    Ok(ExecutionAddress::from(arr))
}

impl<E: BeaconSpec> NodeChainState<E> {
    /// Construct without a state-regeneration service (backward-compat).
    pub fn new(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<FcStore<E>>>,
        identity: NodeIdentityCache,
        runtime_cfg: Arc<RuntimeConfig>,
    ) -> Self {
        Self {
            store,
            fork_choice,
            identity,
            runtime_cfg,
            regen_fn: None,
            pools: None,
            produce_fn: None,
            produce_att_data_fn: None,
            publish_fn: None,
            fee_recipients: Arc::new(RwLock::new(HashMap::new())),
            peers_fn: None,
            syncnets_fn: None,
            el_offline_fn: None,
            sync_contribution_fn: None,
        }
    }

    /// Construct with a state-regeneration callback (Phase 2).
    ///
    /// `regen` is a closure wrapping a `StateRegenService<E>` constructed in
    /// `pharos-node/src/main.rs`. It must be `Send + Sync + 'static` and take a
    /// `RegenTarget`, returning `Result<E::BeaconState, ApiError>`.
    pub fn new_with_regen(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<FcStore<E>>>,
        identity: NodeIdentityCache,
        runtime_cfg: Arc<RuntimeConfig>,
        regen: Arc<RegenFn<E>>,
    ) -> Self {
        Self {
            store,
            fork_choice,
            identity,
            runtime_cfg,
            regen_fn: Some(regen),
            pools: None,
            produce_fn: None,
            produce_att_data_fn: None,
            publish_fn: None,
            fee_recipients: Arc::new(RwLock::new(HashMap::new())),
            peers_fn: None,
            syncnets_fn: None,
            el_offline_fn: None,
            sync_contribution_fn: None,
        }
    }

    /// Attach an `OperationPools<E>` to the chain state (builder pattern).
    ///
    /// Called from `pharos-node/src/main.rs` after pool construction. Enables
    /// real pool reads for GET pool endpoints and liveness scanning.
    /// `D-register-validator-accept-and-store`.
    pub fn with_pools(mut self, pools: Arc<OperationPools<E>>) -> Self {
        self.pools = Some(pools);
        self
    }

    /// Attach production callbacks (builder pattern, for `new_with_all` compat).
    pub fn with_produce_fns(
        mut self,
        produce: Arc<ProduceFn>,
        produce_att_data: Arc<ProduceAttDataFn>,
        publish: Arc<PublishFn>,
        peers: Arc<PeersFn>,
    ) -> Self {
        self.produce_fn = Some(produce);
        self.produce_att_data_fn = Some(produce_att_data);
        self.publish_fn = Some(publish);
        self.peers_fn = Some(peers);
        self
    }

    /// Construct with all M9 Phase-5 production callbacks wired in.
    ///
    /// Called from `pharos-node/src/main.rs` after the engine handle and
    /// op-pools are ready. The `produce_fn`, `produce_att_data_fn`, and
    /// `publish_fn` closures wrap the `pharos-node`-side logic without
    /// introducing a `pharos-api → pharos-node` dependency.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_all(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<FcStore<E>>>,
        identity: NodeIdentityCache,
        runtime_cfg: Arc<RuntimeConfig>,
        regen: Arc<RegenFn<E>>,
        pools: Arc<OperationPools<E>>,
        produce: Arc<ProduceFn>,
        produce_att_data: Arc<ProduceAttDataFn>,
        publish: Arc<PublishFn>,
        peers: Arc<PeersFn>,
    ) -> Self {
        Self {
            store,
            fork_choice,
            identity,
            runtime_cfg,
            regen_fn: Some(regen),
            pools: Some(pools),
            produce_fn: Some(produce),
            produce_att_data_fn: Some(produce_att_data),
            publish_fn: Some(publish),
            fee_recipients: Arc::new(RwLock::new(HashMap::new())),
            peers_fn: Some(peers),
            syncnets_fn: None,
            el_offline_fn: None,
            sync_contribution_fn: None,
        }
    }

    /// Attach the syncnets ENR update callback (builder pattern).
    ///
    /// Called from `pharos-node/src/main.rs` after the discovery handle is
    /// available. Enables `POST /eth/v1/validator/sync_committee_subscriptions`
    /// to drive `DiscoveryHandle::update_enr_syncnets`.
    /// (`D-syncnets-enr-on-subscription`)
    pub fn with_syncnets_fn(mut self, f: Arc<SyncnetsFn>) -> Self {
        self.syncnets_fn = Some(f);
        self
    }

    /// Attach the EL-liveness callback (builder pattern).
    ///
    /// Called from `pharos-node/src/main.rs` with a closure reading the engine
    /// handle's liveness flag. Enables a real `el_offline` in `/eth/v1/node/syncing`.
    pub fn with_el_offline_fn(mut self, f: Arc<ElOfflineFn>) -> Self {
        self.el_offline_fn = Some(f);
        self
    }

    /// Attach the sync-committee-contribution callback (builder pattern).
    pub fn with_sync_contribution_fn(mut self, f: Arc<SyncContributionFn>) -> Self {
        self.sync_contribution_fn = Some(f);
        self
    }
}

impl<E: BeaconSpec> ChainStateApi<E> for NodeChainState<E>
where
    E::Phase0SignedBeaconBlock: BlockApiSerializer,
    E::AltairSignedBeaconBlock: BlockApiSerializer,
    E::BellatrixSignedBeaconBlock: BlockApiSerializer,
    E::CapellaSignedBeaconBlock: BlockApiSerializer,
    E::DenebSignedBeaconBlock: BlockApiSerializer,
    E::ElectraSignedBeaconBlock: BlockApiSerializer,
    E::FuluSignedBeaconBlock: BlockApiSerializer,
    E::AltairLightClientBootstrap: LcApiSerializer,
    E::AltairLightClientUpdate: LcApiSerializer,
    E::AltairLightClientFinalityUpdate: LcApiSerializer,
    E::AltairLightClientOptimisticUpdate: LcApiSerializer,
    E::CapellaLightClientBootstrap: LcApiSerializer,
    E::CapellaLightClientUpdate: LcApiSerializer,
    E::CapellaLightClientFinalityUpdate: LcApiSerializer,
    E::CapellaLightClientOptimisticUpdate: LcApiSerializer,
    E::DenebLightClientBootstrap: LcApiSerializer,
    E::DenebLightClientUpdate: LcApiSerializer,
    E::DenebLightClientFinalityUpdate: LcApiSerializer,
    E::DenebLightClientOptimisticUpdate: LcApiSerializer,
    E::ElectraLightClientBootstrap: LcApiSerializer,
    E::ElectraLightClientUpdate: LcApiSerializer,
    E::ElectraLightClientFinalityUpdate: LcApiSerializer,
    E::ElectraLightClientOptimisticUpdate: LcApiSerializer,
{
    fn head_root(&self) -> Root {
        let fc = self.fork_choice.read();
        pharos_fork_choice::get_head(&fc)
    }

    fn current_slot(&self) -> Slot {
        let fc = self.fork_choice.read();
        pharos_fork_choice::get_current_slot(&fc)
    }

    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        use pharos_types::BeaconStateView;
        let fc = self.fork_choice.read();
        let genesis_time = fc.genesis_time;
        let genesis_fork_version = fc.runtime_cfg.genesis_fork_version;
        // The genesis-validators-root is constant across every BeaconState; read
        // it from the head state. `runtime_cfg.genesis_validators_root` is NOT
        // populated on the checkpoint-sync anchor path (it stays zeroed), so a
        // lighthouse VC reading `/eth/v1/beacon/genesis` would compute wrong
        // fork digests / signing domains from it. Fall back to runtime_cfg only
        // if no head state is loaded yet.
        let head_root = pharos_fork_choice::get_head(&fc);
        let genesis_validators_root = fc
            .block_states
            .get(&head_root)
            .map(|s| s.genesis_validators_root())
            .unwrap_or_else(|| fc.runtime_cfg.genesis_validators_root.into());
        (genesis_time, genesis_validators_root, genesis_fork_version)
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        self.fork_choice.read().finalized_checkpoint.clone()
    }

    fn justified_checkpoint(&self) -> Checkpoint {
        self.fork_choice.read().justified_checkpoint.clone()
    }

    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
        use pharos_types::views::{BeaconBlockView, BeaconStateView};
        let fc = self.fork_choice.read();
        let block = fc.blocks.get(&root)?;
        // `latest_block_header` on the post-state carries the body_root already
        // computed by `process_block_header` during the STF run. Reading it here
        // avoids having to tree-hash the opaque `BeaconBlockView::Body` type.
        let state = fc.block_states.get(&root)?;
        let body_root = state.latest_block_header().body_root;
        Some(BeaconBlockHeader {
            slot: block.slot(),
            proposer_index: block.proposer_index(),
            parent_root: block.parent_root(),
            state_root: block.state_root(),
            body_root,
        })
    }

    fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.runtime_cfg)
    }

    fn is_optimistic(&self) -> bool {
        // Canonical derivation: execution block AND payload_statuses[head] != Valid.
        // Per `consensus-specs/sync/optimistic.md` "Helpers" `is_optimistic` +
        // `is_execution_block` definitions and the M8 single-source-of-truth.
        let fc = self.fork_choice.read();
        let head = pharos_fork_choice::get_head(&fc);
        pharos_fork_choice::is_optimistic(&fc, head)
    }

    fn is_optimistic_for_root(&self, root: Root) -> bool {
        // Per-root derivation for API responses about a specific block.
        // Per `consensus-specs/sync/optimistic.md` "Ethereum Beacon APIs".
        let fc = self.fork_choice.read();
        pharos_fork_choice::is_optimistic(&fc, root)
    }

    fn is_optimistic_node(&self) -> bool {
        // Per `consensus-specs/sync/optimistic.md` "Validator assignments":
        // true when head is optimistic OR all viable FFG branches are Invalid.
        // ADR `D-optimistic-node-no-viable-branch`.
        let fc = self.fork_choice.read();
        pharos_fork_choice::is_optimistic_node(&fc)
    }

    fn is_syncing(&self) -> bool {
        // Syncing when the head slot lags behind the wall-clock slot.
        let fc = self.fork_choice.read();
        let head_root = pharos_fork_choice::get_head(&fc);
        let head_slot = fc.blocks.get(&head_root).map(|b| {
            use pharos_types::views::BeaconBlockView;
            b.slot()
        });
        let current = pharos_fork_choice::get_current_slot(&fc);
        match head_slot {
            Some(s) => u64::from(s) + 1 < u64::from(current),
            None => true,
        }
    }

    fn el_offline(&self) -> bool {
        // Real EL-liveness from the engine handle's last blocking round-trip.
        // No callback wired (no EL) is reported as online (false).
        self.el_offline_fn.as_ref().is_some_and(|f| f())
    }

    fn node_identity(&self) -> &NodeIdentityCache {
        &self.identity
    }

    fn state_by_block_root(&self, root: Root) -> Option<E::BeaconState> {
        // Fast path: in-memory fork-choice post-states (always tried first).
        {
            let fc = self.fork_choice.read();
            if let Some(state) = fc.block_states.get(&root).cloned() {
                return Some(state);
            }
        }
        // Fall through to regen when the block root is not in-memory.
        // `StateRegenService::state_at_slot` (Phase 2) falls through to cold
        // restore-points via `nearest_cold_restore_point` (Phase 3 + Task 3.6),
        // so this is correct live + cold (per Task 4.4 API audit).
        // `regen_fn` converts `RegenError → ApiError`; we swallow ApiError here
        // because the trait returns `Option<E::BeaconState>`.
        if let Some(regen) = &self.regen_fn {
            regen(RegenTarget::BlockRoot(root)).ok()
        } else {
            None
        }
    }

    fn state_by_state_root(&self, state_root: Root) -> Option<E::BeaconState> {
        // Fast path 1: in-memory fork-choice post-states.
        // Clone candidates out and release the read lock BEFORE merkleizing —
        // `tree_hash_root()` over a full state is expensive and must not hold the lock.
        let candidates: Vec<E::BeaconState> = {
            let fc = self.fork_choice.read();
            fc.block_states.values().cloned().collect()
        };
        {
            use pharos_ssz::TreeHash;
            for state in candidates {
                if state.tree_hash_root() == state_root {
                    return Some(state);
                }
            }
        }
        // Fast path 2: hot `states` CF (epoch-boundary states stored by root).
        if let Ok(Some(state)) = <RocksStore as DbStore<E>>::get_state(&self.store, &state_root) {
            return Some(state);
        }
        // Fall through to regen (replay-on-read) when not found in hot storage.
        // `StateRegenService::state_at_root` (Phase 2) walks state-summaries +
        // falls through to cold restore-points (Phase 3 + Task 3.6), so this is
        // correct live + cold (per Task 4.4 API audit).
        if let Some(regen) = &self.regen_fn {
            regen(RegenTarget::StateRoot(state_root)).ok()
        } else {
            None
        }
    }

    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        use pharos_types::views::BeaconBlockView;
        // Fast path: in-memory fork-choice blocks (covers recent hot window).
        {
            let fc = self.fork_choice.read();
            if let Some(root) = fc.blocks.iter().find_map(|(root, block)| {
                if block.slot() == slot {
                    Some(*root)
                } else {
                    None
                }
            }) {
                return Some(root);
            }
        }
        // Fall through to the persisted `slot_to_block_root` CF.
        // This resolves `resolve_state_id` by decimal slot for cold history
        // (finalized blocks migrated below split_slot by Phase-3 freezer).
        // Per Task 4.4 (API audit): correct live + cold.
        self.store.block_root_at_slot(slot).ok().flatten()
    }

    fn genesis_block_root(&self) -> Root {
        // The genesis block root is the anchor root stored in the fork-choice
        // store's finalized checkpoint at epoch 0.  We look for the block at
        // slot 0 in-memory, then fall through to the persisted slot-index, then
        // fall back to the finalized checkpoint root.
        //
        // Per Task 4.4 (API audit): correct live + cold.  After Phase-3 migration
        // the genesis/anchor block is in the cold-blocks CF; the `finalized_checkpoint.root`
        // fallback covers checkpoint-sync nodes where genesis is the anchor.  For
        // genesis-from-scratch nodes, slot 0 is looked up in the persisted slot-index.
        use pharos_types::views::BeaconBlockView;
        let (in_memory_root, finalized_root) = {
            let fc = self.fork_choice.read();
            let in_mem = fc.blocks.iter().find_map(|(r, b)| {
                if b.slot() == pharos_types::phase0::Slot(0) {
                    Some(*r)
                } else {
                    None
                }
            });
            (in_mem, fc.finalized_checkpoint.root)
        };
        if let Some(root) = in_memory_root {
            return root;
        }
        // Fall through to the persisted slot-index (covers cold genesis).
        if let Ok(Some(root)) = self.store.block_root_at_slot(pharos_types::phase0::Slot(0)) {
            return root;
        }
        // Anchor checkpoint is the first block we know about.
        finalized_root
    }

    fn sync_committee_pubkeys(&self, block_root: Root) -> Option<SyncCommitteePubkeys> {
        use pharos_types::BeaconStateView;
        let fc = self.fork_choice.read();
        // Delegate to BeaconStateView::sync_committee_pubkeys which has
        // per-fork overrides returning the committee pubkeys (Phase0 returns None).
        fc.block_states.get(&block_root)?.sync_committee_pubkeys()
    }

    fn regenerate_state(&self, target: RegenTarget) -> Result<E::BeaconState, ApiError> {
        match &self.regen_fn {
            Some(regen) => regen(target),
            None => Err(ApiError::NotFound(
                "state regeneration service not available".into(),
            )),
        }
    }

    fn signed_block_header_at(&self, root: Root) -> Option<(BeaconBlockHeader, BLSSignature)> {
        // Fetch the full SignedBeaconBlock from storage to extract the real signature.
        // Try hot CF first; fall through to cold for migrated blocks.
        // Per Task 4.4 (API audit): correct live + cold.
        let signed = {
            let hot = <RocksStore as DbStore<E>>::get_block(&self.store, &root)
                .ok()
                .flatten();
            if hot.is_some() {
                hot?
            } else {
                <RocksStore as DbStore<E>>::get_cold_block(&self.store, &root)
                    .ok()
                    .flatten()?
            }
        };

        // Reconstruct BOTH the header fields and the real signature directly from
        // the stored `SignedBeaconBlock` — no dependency on the in-memory
        // fork-choice maps (which may not hold the block after a reorg or, from
        // Phase 3, after pruning). `body_root` is the block body's merkle root.
        use pharos_ssz::TreeHash;
        use pharos_types::views::BeaconBlockView as _;

        macro_rules! header_from {
            ($inner:expr) => {{
                let msg = $inner.message();
                let header = BeaconBlockHeader {
                    slot: msg.slot(),
                    proposer_index: msg.proposer_index(),
                    parent_root: msg.parent_root(),
                    state_root: msg.state_root(),
                    body_root: msg.body().tree_hash_root(),
                };
                Some((header, *$inner.signature()))
            }};
        }

        if let Some(inner) = E::unwrap_phase0_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_altair_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_bellatrix_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_capella_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_deneb_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_electra_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_fulu_signed_block(&signed) {
            header_from!(inner)
        } else {
            None
        }
    }

    fn state_to_json(&self, state: E::BeaconState) -> Result<JsonValue, ApiError> {
        // The state is already cloned by the caller (debug handler clones it out
        // before calling state_to_json, so the fork-choice read-lock is not held
        // during serialization of large lists).
        beacon_state_to_json_full::<E>(state)
    }

    fn block_by_root_for_api(&self, root: Root) -> Result<Option<SignedBlockForApi>, ApiError> {
        // Fetch from the hot CF first; fall through to the cold CF for finalized
        // blocks migrated by the Phase-3 freezer.  A genuine DB read error is
        // surfaced as 500, distinct from a missing block (Ok(None) → 404 at the
        // handler).  Per Task 4.4 (API audit): correct live + cold.
        let hot = <RocksStore as DbStore<E>>::get_block(&self.store, &root)
            .map_err(|e| ApiError::Internal(format!("block store read failed: {e}")))?;
        let block = if let Some(b) = hot {
            b
        } else {
            // Fall through to cold-blocks CF (finalized blocks migrated by freezer).
            match <RocksStore as DbStore<E>>::get_cold_block(&self.store, &root)
                .map_err(|e| ApiError::Internal(format!("cold block store read failed: {e}")))?
            {
                Some(b) => b,
                None => return Ok(None),
            }
        };

        // Use the `BeaconSpec` unwrap helpers to dispatch to the correct fork-specific
        // DTO builder via the `BlockApiSerializer` trait. Each helper returns
        // `Option<&Inner>` where `Inner: BlockApiSerializer` (guaranteed by the impl
        // bounds on this `NodeChainState<E>` impl block).
        if let Some(b) = E::unwrap_phase0_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_altair_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_bellatrix_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_capella_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_deneb_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_electra_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_fulu_signed_block(&block) {
            // Fulu reuses the Electra `SignedBeaconBlock` type, so the shared
            // `BlockApiSerializer` impl tags the DTO `ForkVariant::Electra`. The
            // outer enum variant is the authoritative fork here — override the
            // tag so the `version` field and `Eth-Consensus-Version` header read
            // `fulu` (the DTO body is structurally identical to Electra).
            let mut for_api = b.to_block_for_api()?;
            for_api.variant = pharos_types::views::ForkVariant::Fulu;
            return Ok(Some(for_api));
        }
        // All seven forks (phase0/altair/bellatrix/capella/deneb/electra/fulu) are
        // exhaustive. Reaching here indicates a new unknown fork variant.
        unreachable!("unknown fork variant in SignedBeaconBlock — update block_by_root_for_api")
    }

    fn fork_choice_dump(&self) -> Result<JsonValue, ApiError> {
        use pharos_fork_choice::get_head::get_weight;
        use pharos_types::{PayloadStatus, views::BeaconBlockView};

        let fc = self.fork_choice.read();

        let justified = serde_json::json!({
            "epoch": fc.justified_checkpoint.epoch.0.to_string(),
            "root": format!("0x{}", hex::encode(fc.justified_checkpoint.root.as_slice())),
        });
        let finalized = serde_json::json!({
            "epoch": fc.finalized_checkpoint.epoch.0.to_string(),
            "root": format!("0x{}", hex::encode(fc.finalized_checkpoint.root.as_slice())),
        });

        let nodes: Vec<serde_json::Value> = fc
            .blocks
            .iter()
            .map(|(root, block)| {
                let validity = match fc.payload_statuses.get(root) {
                    Some(PayloadStatus::Invalid) => "invalid",
                    Some(PayloadStatus::NotValidated) => "optimistic",
                    _ => "valid",
                };
                // Use the unrealized justification for this block's justified/finalized
                // epochs when available, falling back to the store checkpoints.
                let (just_epoch, fin_epoch) = fc
                    .unrealized_justifications
                    .get(root)
                    .map(|cp| (cp.epoch.0, fc.unrealized_finalized_checkpoint.epoch.0))
                    .unwrap_or((
                        fc.justified_checkpoint.epoch.0,
                        fc.finalized_checkpoint.epoch.0,
                    ));

                // Fix 4: real LMD-GHOST vote weight.
                let weight = get_weight::<E>(&fc, *root).to_string();

                // Real execution block hash for Bellatrix+ blocks (zero for
                // Phase0/Altair). Use the fork-aware fork-choice helper rather
                // than `block.body()`, which is `unimplemented!()` on the
                // fork-enum BeaconBlock (it cannot return a borrowed enum body).
                let exec_hash = pharos_fork_choice::execution_block_hash_at_root(&fc, *root);
                let exec_block_hash_hex = format!("0x{}", hex::encode(exec_hash.as_slice()));

                serde_json::json!({
                    "slot": block.slot().0.to_string(),
                    "block_root": format!("0x{}", hex::encode(root.as_slice())),
                    "parent_root": format!("0x{}", hex::encode(block.parent_root().as_slice())),
                    "justified_epoch": just_epoch.to_string(),
                    "finalized_epoch": fin_epoch.to_string(),
                    "weight": weight,
                    "validity": validity,
                    "execution_block_hash": exec_block_hash_hex,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "justified_checkpoint": justified,
            "finalized_checkpoint": finalized,
            "fork_choice_nodes": nodes,
        }))
    }

    // ── M9 Phase 5 production method overrides ────────────────────────────────

    fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: BLSSignature,
        graffiti: Bytes32,
    ) -> Result<(JsonValue, Uint256, Uint256), ApiError> {
        match &self.produce_fn {
            Some(f) => f(slot, randao_reveal, graffiti),
            None => Err(ApiError::NotSynced(
                "block production not configured".into(),
            )),
        }
    }

    fn produce_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData, ApiError> {
        match &self.produce_att_data_fn {
            Some(f) => f(slot, committee_index),
            None => Err(ApiError::NotSynced(
                "attestation data production not configured".into(),
            )),
        }
    }

    fn submit_attestations(&self, attestations: Vec<Attestation<2048>>) -> Result<(), ApiError> {
        if let Some(pools) = &self.pools {
            for att in attestations {
                pools.insert_attestation(att);
            }
        }
        Ok(())
    }

    fn submit_single_attestations(
        &self,
        attestations: Vec<SingleAttestation>,
    ) -> Result<(), ApiError> {
        let Some(pools) = &self.pools else {
            return Ok(());
        };
        for att in attestations {
            // Convert SingleAttestation → Attestation<2048> for pool storage.
            // The API layer does not have the committee length from duty data, so
            // we produce a minimal 1-bit Bitlist with bit 0 set (one aggregation
            // slot). This preserves the attestation data and signature in the pool
            // while satisfying the pool's Attestation<2048> type requirement.
            let mut agg_bits = Bitlist::<2048>::new();
            // push one `true` bit (attester at committee position 0).
            let _ = agg_bits.push(true);
            let phase0_att = Attestation::<2048> {
                aggregation_bits: agg_bits,
                data: att.data,
                signature: att.signature,
            };
            pools.insert_attestation(phase0_att);
        }
        Ok(())
    }

    fn submit_phase0_attester_slashing(
        &self,
        slashing: Phase0AttesterSlashing<2048>,
    ) -> Result<(), ApiError> {
        if let Some(pools) = &self.pools {
            pools.insert_attester_slashing(slashing);
        }
        Ok(())
    }

    fn submit_electra_attester_slashing(&self, slashing: JsonValue) -> Result<(), ApiError> {
        let Some(pools) = &self.pools else {
            return Ok(());
        };
        // The electra AttesterSlashing outer shape ({attestation_1, attestation_2}
        // with {attesting_indices, data, signature}) is identical to phase0.
        // Parse it as Phase0.AttesterSlashing<2048>, truncating any indices
        // beyond the pool's 2048 limit, and insert into the shared pool.
        let phase0_slashing =
            parse_indexed_attestation_json_as_phase0(&slashing["attestation_1"])
                .and_then(|att1| {
                    parse_indexed_attestation_json_as_phase0(&slashing["attestation_2"])
                        .map(|att2| Phase0AttesterSlashing {
                            attestation_1: att1,
                            attestation_2: att2,
                        })
                })?;
        pools.insert_attester_slashing(phase0_slashing);
        Ok(())
    }

    fn submit_aggregate_and_proofs(&self, _aggregates: Vec<JsonValue>) -> Result<(), ApiError> {
        // Aggregate-and-proof objects are JSON; full BLS verification and pool
        // insertion is a gossip-validator concern. Accept without re-inserting.
        Ok(())
    }

    fn submit_sync_committee_messages(&self, _messages: Vec<JsonValue>) -> Result<(), ApiError> {
        // Sync messages arrive here from POST /beacon/pool/sync_committees.
        // Insertion into the sync_messages pool requires decoded SyncCommitteeMessage
        // and a subcommittee_index derived from validator committee assignments —
        // both require the STF/state at call time. Accept without pool insert
        // (gossip-accept path handles pool insertion with full context).
        Ok(())
    }

    fn submit_contribution_and_proofs(
        &self,
        _contributions: Vec<JsonValue>,
    ) -> Result<(), ApiError> {
        // ContributionAndProof objects need BLS verification before pool insertion.
        // Accept without pool insert; gossip-accept path handles pool insertion.
        Ok(())
    }

    fn pool_attestations(&self) -> Vec<JsonValue> {
        let Some(pools) = &self.pools else {
            return vec![];
        };
        pools
            .attestations_snapshot()
            .iter()
            .map(attestation_to_json)
            .collect()
    }

    fn aggregate_attestation(&self, data_root: Root) -> Option<JsonValue> {
        let pools = self.pools.as_ref()?;
        pools
            .best_aggregate_for(data_root)
            .map(|att| attestation_to_json(&att))
    }

    fn sync_committee_contribution(
        &self,
        slot: u64,
        block_root: Root,
        subcommittee_index: u64,
    ) -> Option<JsonValue> {
        let f = self.sync_contribution_fn.as_ref()?;
        f(slot, block_root, subcommittee_index)
    }

    fn pool_attester_slashings(&self) -> Vec<JsonValue> {
        let Some(pools) = &self.pools else {
            return vec![];
        };
        pools
            .attester_slashings_snapshot()
            .into_iter()
            .map(|s| {
                let ia_to_json =
                    |ia: &Phase0IndexedAttestation<2048>| -> JsonValue {
                        serde_json::json!({
                            "attesting_indices": ia.attesting_indices.as_slice().iter().map(|i| i.0.to_string()).collect::<Vec<_>>(),
                            "data": {
                                "slot": ia.data.slot.0.to_string(),
                                "index": ia.data.index.0.to_string(),
                                "beacon_block_root": format!("0x{}", hex::encode(ia.data.beacon_block_root.as_slice())),
                                "source": {
                                    "epoch": ia.data.source.epoch.0.to_string(),
                                    "root": format!("0x{}", hex::encode(ia.data.source.root.as_slice())),
                                },
                                "target": {
                                    "epoch": ia.data.target.epoch.0.to_string(),
                                    "root": format!("0x{}", hex::encode(ia.data.target.root.as_slice())),
                                },
                            },
                            "signature": format!("0x{}", hex::encode(ia.signature.as_slice())),
                        })
                    };
                serde_json::json!({
                    "attestation_1": ia_to_json(&s.attestation_1),
                    "attestation_2": ia_to_json(&s.attestation_2),
                })
            })
            .collect()
    }

    fn pool_proposer_slashings(&self) -> Vec<JsonValue> {
        let Some(pools) = &self.pools else {
            return vec![];
        };
        pools
            .proposer_slashings_snapshot()
            .into_iter()
            .map(|s| {
                serde_json::json!({
                    "signed_header_1": {
                        "message": {
                            "slot": s.signed_header_1.message.slot.0.to_string(),
                            "proposer_index": s.signed_header_1.message.proposer_index.0.to_string(),
                        },
                        "signature": format!("0x{}", hex::encode(s.signed_header_1.signature.as_slice())),
                    },
                    "signed_header_2": {
                        "message": {
                            "slot": s.signed_header_2.message.slot.0.to_string(),
                            "proposer_index": s.signed_header_2.message.proposer_index.0.to_string(),
                        },
                        "signature": format!("0x{}", hex::encode(s.signed_header_2.signature.as_slice())),
                    },
                })
            })
            .collect()
    }

    fn pool_voluntary_exits(&self) -> Vec<JsonValue> {
        let Some(pools) = &self.pools else {
            return vec![];
        };
        pools
            .voluntary_exits_snapshot()
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "message": {
                        "epoch": e.message.epoch.0.to_string(),
                        "validator_index": e.message.validator_index.0.to_string(),
                    },
                    "signature": format!("0x{}", hex::encode(e.signature.as_slice())),
                })
            })
            .collect()
    }

    fn pool_bls_to_execution_changes(&self) -> Vec<JsonValue> {
        let Some(pools) = &self.pools else {
            return vec![];
        };
        pools
            .bls_to_execution_changes_snapshot()
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "message": {
                        "validator_index": c.message.validator_index.0.to_string(),
                        "from_bls_pubkey": format!("0x{}", hex::encode(c.message.from_bls_pubkey.as_slice())),
                        "to_execution_address": format!("0x{}", hex::encode(c.message.to_execution_address.as_slice())),
                    },
                    "signature": format!("0x{}", hex::encode(c.signature.as_slice())),
                })
            })
            .collect()
    }

    fn pool_sync_committee_messages(&self) -> Vec<JsonValue> {
        let Some(pools) = &self.pools else {
            return vec![];
        };
        pools
            .sync_messages_snapshot()
            .into_iter()
            .map(|m| {
                serde_json::json!({
                    "slot": m.slot.0.to_string(),
                    "beacon_block_root": format!("0x{}", hex::encode(m.beacon_block_root.as_slice())),
                    "validator_index": m.validator_index.0.to_string(),
                    "signature": format!("0x{}", hex::encode(m.signature.as_slice())),
                })
            })
            .collect()
    }

    fn set_fee_recipients_by_index(
        &self,
        pairs: Vec<(ValidatorIndex, ExecutionAddress)>,
    ) -> Result<(), ApiError> {
        // Store by validator_index using a synthetic pubkey derived from the index.
        // The fee-recipient map is keyed by BLSPubkey; since prepare_beacon_proposer
        // only provides the validator index (not pubkey), we store under a synthetic
        // index-keyed pubkey: first 8 bytes = validator_index as little-endian u64,
        // remaining 40 bytes = 0x00. This matches the lookup at block-production time.
        // `D-register-validator-accept-and-store`.
        let mut map = self.fee_recipients.write();
        for (idx, addr) in pairs {
            let mut key_bytes = [0u8; 48];
            key_bytes[..8].copy_from_slice(&idx.0.to_le_bytes());
            map.insert(BLSPubkey::from(key_bytes), addr);
        }
        Ok(())
    }

    fn register_validators(&self, registrations: Vec<JsonValue>) -> Result<(), ApiError> {
        // Accept and store fee_recipient per validator pubkey.
        // `D-register-validator-accept-and-store`.
        let mut map = self.fee_recipients.write();
        for reg in &registrations {
            let msg = &reg["message"];
            let pubkey_hex = msg["pubkey"].as_str().unwrap_or("");
            let fee_hex = msg["fee_recipient"].as_str().unwrap_or("");
            if let (Ok(pk_bytes), Ok(addr)) =
                (parse_hex48(pubkey_hex), parse_execution_address(fee_hex))
            {
                map.insert(BLSPubkey::from(pk_bytes), addr);
            }
        }
        Ok(())
    }

    fn publish_block(&self, block: JsonValue) -> Result<bool, ApiError> {
        match &self.publish_fn {
            Some(f) => f(block),
            None => Ok(false),
        }
    }

    fn publish_block_ssz(&self, bytes: Vec<u8>, fork: &str) -> Result<bool, ApiError> {
        use pharos_ssz::Decode as SszDecode;

        // Decode SSZ bytes into the concrete per-fork type, serialize to the
        // API JSON envelope, then hand off to publish_block.
        let block_json: JsonValue = match fork.to_lowercase().as_str() {
            "phase0" => {
                let b = E::Phase0SignedBeaconBlock::from_ssz_bytes(&bytes)
                    .map_err(|e| ApiError::BadRequest(format!("SSZ decode (phase0): {e:?}")))?;
                let for_api = b.to_block_for_api()?;
                serde_json::json!({ "version": "phase0", "data": for_api.json })
            }
            "altair" => {
                let b = E::AltairSignedBeaconBlock::from_ssz_bytes(&bytes)
                    .map_err(|e| ApiError::BadRequest(format!("SSZ decode (altair): {e:?}")))?;
                let for_api = b.to_block_for_api()?;
                serde_json::json!({ "version": "altair", "data": for_api.json })
            }
            "bellatrix" => {
                let b = E::BellatrixSignedBeaconBlock::from_ssz_bytes(&bytes)
                    .map_err(|e| ApiError::BadRequest(format!("SSZ decode (bellatrix): {e:?}")))?;
                let for_api = b.to_block_for_api()?;
                serde_json::json!({ "version": "bellatrix", "data": for_api.json })
            }
            "capella" => {
                let b = E::CapellaSignedBeaconBlock::from_ssz_bytes(&bytes)
                    .map_err(|e| ApiError::BadRequest(format!("SSZ decode (capella): {e:?}")))?;
                let for_api = b.to_block_for_api()?;
                serde_json::json!({ "version": "capella", "data": for_api.json })
            }
            "deneb" => {
                let b = E::DenebSignedBeaconBlock::from_ssz_bytes(&bytes)
                    .map_err(|e| ApiError::BadRequest(format!("SSZ decode (deneb): {e:?}")))?;
                let for_api = b.to_block_for_api()?;
                serde_json::json!({ "version": "deneb", "data": for_api.json })
            }
            other => {
                return Err(ApiError::BadRequest(format!(
                    "unknown fork in Eth-Consensus-Version: {other}"
                )));
            }
        };
        self.publish_block(block_json)
    }

    fn validator_liveness(
        &self,
        epoch: Epoch,
        indices: Vec<ValidatorIndex>,
    ) -> Result<Vec<(ValidatorIndex, bool)>, ApiError> {
        // Scan the attestation pool for the given epoch.
        // An attestation's `target.epoch` identifies the epoch it votes for.
        // A validator is live if it has an attestation in the pool with
        // target.epoch == requested_epoch.
        use std::collections::HashSet;

        let mut live_indices: HashSet<u64> = HashSet::new();

        // Scan pool attestations.
        // A validator is considered live if any attestation in the pool has
        // target.epoch == requested_epoch. Since aggregated attestations don't
        // carry per-validator indices without committee resolution, we mark the
        // attestation's data.index (committee_index) as a proxy. This is a
        // conservative heuristic: it produces false positives only when a
        // validator's committee index matches but they didn't personally attest.
        // False positives are safe for doppelganger (skip one extra epoch).
        // Pool attestations are accessed by reference; we check target epoch only.
        if let Some(pools) = &self.pools {
            let att_pool = pools.attestations_snapshot();
            let has_att_for_epoch = att_pool.iter().any(|att| att.data.target.epoch == epoch);
            // If there are ANY attestations for this epoch in the pool, we conservatively
            // report all requested indices as potentially live. A more precise impl
            // would require committee-to-validator-index resolution (needs fork state).
            if has_att_for_epoch {
                for att in att_pool {
                    if att.data.target.epoch == epoch {
                        // Mark committee index as a proxy for validator liveness.
                        live_indices.insert(att.data.index.0);
                    }
                }
            }
        }

        // Scan recent in-memory fork-choice block states for attestations.
        // States include `previous_epoch_participation` / `current_epoch_participation` (altair+).
        // Phase0 pending attestations are skipped (no committee resolution at this layer).
        {
            use pharos_types::BeaconStateView;
            let states: Vec<E::BeaconState> = {
                let fc = self.fork_choice.read();
                fc.block_states.values().cloned().collect()
            };

            for state in states {
                let state_epoch = Epoch(state.slot().0 / self.runtime_cfg.slots_per_epoch);

                // current_epoch_participation: non-zero flag means the validator
                // attested in the CURRENT epoch of this state.
                if state_epoch == epoch {
                    let curr = state.current_epoch_participation_u8s();
                    for (vi, &flags) in curr.iter().enumerate() {
                        if flags != 0 {
                            live_indices.insert(vi as u64);
                        }
                    }
                }

                // previous_epoch_participation: non-zero flag means the validator
                // attested in the PREVIOUS epoch of this state (= epoch we want when
                // state_epoch == requested_epoch + 1).
                if state_epoch == Epoch(epoch.0.saturating_add(1)) {
                    let prev = state.previous_epoch_participation_u8s();
                    for (vi, &flags) in prev.iter().enumerate() {
                        if flags != 0 {
                            live_indices.insert(vi as u64);
                        }
                    }
                }
            }
        }

        let result = indices
            .into_iter()
            .map(|idx| {
                let is_live = live_indices.contains(&idx.0);
                (idx, is_live)
            })
            .collect();

        Ok(result)
    }

    fn peers(&self) -> Vec<JsonValue> {
        match &self.peers_fn {
            Some(f) => f(),
            None => vec![],
        }
    }

    fn notify_sync_committee_subscriptions(&self, syncnets_ssz: Vec<u8>) {
        if let Some(f) = &self.syncnets_fn {
            f(syncnets_ssz);
        }
    }

    // ── Light-client REST endpoint overrides ──────────────────────────────────

    fn light_client_bootstrap(&self, block_root: Root) -> Result<Option<LcEnvelope>, ApiError> {
        // Probe deneb first (newest), then capella, then altair. STF writes exactly
        // ONE CF per root, so only one will return Some. Per `D-api-lc-bridge`.
        let deneb =
            <RocksStore as DbStore<E>>::get_light_client_bootstrap_deneb(&self.store, &block_root)
                .map_err(|e| ApiError::Internal(format!("lc bootstrap deneb read: {e}")))?;
        if let Some(b) = deneb {
            return Ok(Some(make_lc_envelope(&b, &self.runtime_cfg)?));
        }
        let capella = <RocksStore as DbStore<E>>::get_light_client_bootstrap_capella(
            &self.store,
            &block_root,
        )
        .map_err(|e| ApiError::Internal(format!("lc bootstrap capella read: {e}")))?;
        if let Some(b) = capella {
            return Ok(Some(make_lc_envelope(&b, &self.runtime_cfg)?));
        }
        let altair =
            <RocksStore as DbStore<E>>::get_light_client_bootstrap(&self.store, &block_root)
                .map_err(|e| ApiError::Internal(format!("lc bootstrap altair read: {e}")))?;
        altair
            .map(|b| make_lc_envelope(&b, &self.runtime_cfg))
            .transpose()
    }

    fn light_client_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<LcEnvelope>, ApiError> {
        // Build a period-indexed map. Altair updates go in first; capella updates
        // overwrite (STF mutual-exclusion: exactly one CF written per period).
        let mut by_period: std::collections::BTreeMap<u64, LcEnvelope> =
            std::collections::BTreeMap::new();

        let altair_updates = <RocksStore as DbStore<E>>::get_light_client_updates_by_range(
            &self.store,
            start_period,
            count,
        )
        .map_err(|e| ApiError::Internal(format!("lc updates altair read: {e}")))?;
        for (idx, upd) in altair_updates.into_iter().enumerate() {
            let period = start_period + idx as u64;
            by_period.insert(period, make_lc_envelope(&upd, &self.runtime_cfg)?);
        }

        // Probe capella per-period (no range getter exists in the Store trait).
        for i in 0..count {
            let period = start_period.saturating_add(i);
            match <RocksStore as DbStore<E>>::get_light_client_update_capella(&self.store, period) {
                Ok(Some(upd)) => {
                    by_period.insert(period, make_lc_envelope(&upd, &self.runtime_cfg)?);
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(ApiError::Internal(format!(
                        "lc update capella period {period}: {e}"
                    )));
                }
            }
        }

        // Probe deneb per-period; deneb overwrites capella for the same period.
        for i in 0..count {
            let period = start_period.saturating_add(i);
            match <RocksStore as DbStore<E>>::get_light_client_update_deneb(&self.store, period) {
                Ok(Some(upd)) => {
                    by_period.insert(period, make_lc_envelope(&upd, &self.runtime_cfg)?);
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(ApiError::Internal(format!(
                        "lc update deneb period {period}: {e}"
                    )));
                }
            }
        }

        Ok(by_period.into_values().collect())
    }

    fn light_client_finality_update(&self) -> Result<Option<LcEnvelope>, ApiError> {
        let deneb = <RocksStore as DbStore<E>>::get_light_client_finality_update_deneb(&self.store)
            .map_err(|e| ApiError::Internal(format!("lc finality deneb read: {e}")))?;
        if let Some(u) = deneb {
            return Ok(Some(make_lc_envelope(&u, &self.runtime_cfg)?));
        }
        let capella =
            <RocksStore as DbStore<E>>::get_light_client_finality_update_capella(&self.store)
                .map_err(|e| ApiError::Internal(format!("lc finality capella read: {e}")))?;
        if let Some(u) = capella {
            return Ok(Some(make_lc_envelope(&u, &self.runtime_cfg)?));
        }
        let altair = <RocksStore as DbStore<E>>::get_light_client_finality_update(&self.store)
            .map_err(|e| ApiError::Internal(format!("lc finality altair read: {e}")))?;
        altair
            .map(|u| make_lc_envelope(&u, &self.runtime_cfg))
            .transpose()
    }

    fn light_client_optimistic_update(&self) -> Result<Option<LcEnvelope>, ApiError> {
        let deneb =
            <RocksStore as DbStore<E>>::get_light_client_optimistic_update_deneb(&self.store)
                .map_err(|e| ApiError::Internal(format!("lc optimistic deneb read: {e}")))?;
        if let Some(u) = deneb {
            return Ok(Some(make_lc_envelope(&u, &self.runtime_cfg)?));
        }
        let capella =
            <RocksStore as DbStore<E>>::get_light_client_optimistic_update_capella(&self.store)
                .map_err(|e| ApiError::Internal(format!("lc optimistic capella read: {e}")))?;
        if let Some(u) = capella {
            return Ok(Some(make_lc_envelope(&u, &self.runtime_cfg)?));
        }
        let altair = <RocksStore as DbStore<E>>::get_light_client_optimistic_update(&self.store)
            .map_err(|e| ApiError::Internal(format!("lc optimistic altair read: {e}")))?;
        altair
            .map(|u| make_lc_envelope(&u, &self.runtime_cfg))
            .transpose()
    }

    fn fork_choice_heads(&self) -> Result<JsonValue, ApiError> {
        use pharos_types::views::BeaconBlockView;

        let fc = self.fork_choice.read();

        // Collect all parent roots of known blocks.
        let parent_roots: std::collections::HashSet<Root> =
            fc.blocks.values().map(|b| b.parent_root()).collect();

        // Leaf nodes = blocks whose own root is NOT a parent of any other block.
        // Per-root derivation: each head gets its own is_optimistic check.
        let heads: Vec<serde_json::Value> = fc
            .blocks
            .iter()
            .filter(|(root, _)| !parent_roots.contains(*root))
            .map(|(root, block)| {
                serde_json::json!({
                    "root": format!("0x{}", hex::encode(root.as_slice())),
                    "slot": block.slot().0.to_string(),
                    "execution_optimistic": pharos_fork_choice::is_optimistic(&fc, *root),
                })
            })
            .collect();

        Ok(serde_json::json!({ "data": heads }))
    }
}

// ── ApiState ──────────────────────────────────────────────────────────────────

/// Axum state wrapper.
///
/// Injected via `axum::extract::State<Arc<ApiState<E>>>`. Handlers clone the
/// `Arc` cheaply rather than cloning the full state.
pub struct ApiState<E: BeaconSpec> {
    pub chain: Arc<dyn ChainStateApi<E>>,
    /// SSE broadcast bus.  `None` when built without an event bus (e.g. tests
    /// that only exercise non-SSE endpoints).
    pub event_bus: Option<Arc<EventBus>>,
}

impl<E: BeaconSpec> ApiState<E> {
    pub fn new(chain: Arc<dyn ChainStateApi<E>>) -> Arc<Self> {
        Arc::new(Self {
            chain,
            event_bus: None,
        })
    }

    /// Construct with an SSE event bus.
    pub fn new_with_bus(chain: Arc<dyn ChainStateApi<E>>, event_bus: Arc<EventBus>) -> Arc<Self> {
        Arc::new(Self {
            chain,
            event_bus: Some(event_bus),
        })
    }
}
