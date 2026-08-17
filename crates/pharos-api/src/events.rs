//! SSE event types and broadcast bus for the Beacon API `/eth/v1/events` endpoint.
//!
//! # Event DTOs
//!
//! Each variant's JSON shape matches the `data:` example in
//! `beacon-APIs/apis/eventstream/index.yaml`.  All integer fields are quoted
//! decimal strings; all byte-array fields are `0x`-prefixed lowercase hex.
//!
//! # Topic acceptance
//!
//! `KnownTopic::parse` recognises every topic name listed in the eventstream
//! spec.  Topics that pharos does NOT emit (follow-only; no block
//! production) are nonetheless accepted as valid subscription targets so that
//! clients can subscribe with e.g. `?topics=head,payload_attributes` and receive
//! a valid stream delivering only the emitted subset.
//!
//! Topics emitted: `head`, `block`, `finalized_checkpoint`, `chain_reorg`.
//!
//! Topics accepted but never emitted (pharos is follow-only):
//!   `block_gossip`, `attestation`, `single_attestation`, `voluntary_exit`,
//!   `bls_to_execution_change`, `proposer_slashing`, `attester_slashing`,
//!   `contribution_and_proof`, `light_client_finality_update`,
//!   `light_client_optimistic_update`, `payload_attributes`,
//!   `data_column_sidecar`, `execution_payload`, `execution_payload_gossip`,
//!   `execution_payload_available`, `execution_payload_bid`,
//!   `payload_attestation_message`, `fast_confirmation`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::serde_helpers::{quoted_u64, serialize_hex32};

// ── Capacity ──────────────────────────────────────────────────────────────────

/// Broadcast channel capacity.  Slow clients drop events rather than blocking.
const BUS_CAPACITY: usize = 256;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// `data:` payload for the `head` event.
///
/// YAML example (index.yaml):
/// ```text
/// event: head
/// data: {"slot":"10", "block":"0x9a2f...", "state":"0x600e...",
///        "epoch_transition":false,
///        "previous_duty_dependent_root":"0x5e00...",
///        "current_duty_dependent_root":"0x5e00...",
///        "execution_optimistic": false}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadEventDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub block: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub state: [u8; 32],
    pub epoch_transition: bool,
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub previous_duty_dependent_root: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub current_duty_dependent_root: [u8; 32],
    pub execution_optimistic: bool,
}

/// `data:` payload for the `block` event.
///
/// YAML example (index.yaml):
/// ```text
/// event: block
/// data: {"slot":"10", "block":"0x9a2f...", "execution_optimistic": false}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEventDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub block: [u8; 32],
    pub execution_optimistic: bool,
}

/// `data:` payload for the `chain_reorg` event.
///
/// YAML example (index.yaml):
/// ```text
/// event: chain_reorg
/// data: {"slot":"200", "depth":"50",
///        "old_head_block":"0x9a2f...", "new_head_block":"0x7626...",
///        "old_head_state":"0x9a2f...", "new_head_state":"0x600e...",
///        "epoch":"2", "execution_optimistic": false}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReorgEventDto {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub depth: u64,
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub old_head_block: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub new_head_block: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub old_head_state: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub new_head_state: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
    pub execution_optimistic: bool,
}

/// `data:` payload for the `finalized_checkpoint` event.
///
/// YAML example (index.yaml):
/// ```text
/// event: finalized_checkpoint
/// data: {"block":"0x9a2f...", "state":"0x600e...",
///        "epoch":"2", "execution_optimistic": false }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedCheckpointEventDto {
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub block: [u8; 32],
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "crate::serde_helpers::deserialize_hex32"
    )]
    pub state: [u8; 32],
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
    pub execution_optimistic: bool,
}

// ── ApiEvent ──────────────────────────────────────────────────────────────────

/// An event pushed onto the broadcast bus for `/eth/v1/events` subscribers.
///
/// Each variant corresponds to a Beacon API event topic and carries its spec-
/// conformant JSON DTO.  Only the four emitted variants are listed here;
/// the full set of valid *topic names* is handled by `KnownTopic`.
#[derive(Debug, Clone)]
pub enum ApiEvent {
    Head(HeadEventDto),
    Block(BlockEventDto),
    ChainReorg(ChainReorgEventDto),
    FinalizedCheckpoint(FinalizedCheckpointEventDto),
}

impl ApiEvent {
    /// The SSE `event:` topic name for this event.
    pub fn topic(&self) -> &'static str {
        match self {
            ApiEvent::Head(_) => "head",
            ApiEvent::Block(_) => "block",
            ApiEvent::ChainReorg(_) => "chain_reorg",
            ApiEvent::FinalizedCheckpoint(_) => "finalized_checkpoint",
        }
    }

    /// Serialize the event DTO to a JSON string.
    pub fn data_json(&self) -> serde_json::Result<String> {
        match self {
            ApiEvent::Head(d) => serde_json::to_string(d),
            ApiEvent::Block(d) => serde_json::to_string(d),
            ApiEvent::ChainReorg(d) => serde_json::to_string(d),
            ApiEvent::FinalizedCheckpoint(d) => serde_json::to_string(d),
        }
    }
}

// ── KnownTopic ────────────────────────────────────────────────────────────────

/// Every topic name the spec lists in the `?topics=` parameter.
///
/// Recognising all spec topics (not just emitted ones) lets the server accept
/// any valid subscription request and simply deliver only the frames it
/// actually emits, rather than returning 400 for topics it never produces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KnownTopic {
    // ── Emitted ───────────────────────────────────────────────────────────
    Head,
    Block,
    FinalizedCheckpoint,
    ChainReorg,
    // ── Accepted but never emitted (pharos is follow-only) ────────────────
    BlockGossip,
    Attestation,
    SingleAttestation,
    VoluntaryExit,
    BlsToExecutionChange,
    ProposerSlashing,
    AttesterSlashing,
    ContributionAndProof,
    LightClientFinalityUpdate,
    LightClientOptimisticUpdate,
    PayloadAttributes,
    DataColumnSidecar,
    ExecutionPayload,
    ExecutionPayloadGossip,
    ExecutionPayloadAvailable,
    ExecutionPayloadBid,
    PayloadAttestationMessage,
    FastConfirmation,
}

impl KnownTopic {
    /// Parse a topic name string.  Returns `None` for unrecognised strings.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "head" => Some(Self::Head),
            "block" => Some(Self::Block),
            "finalized_checkpoint" => Some(Self::FinalizedCheckpoint),
            "chain_reorg" => Some(Self::ChainReorg),
            "block_gossip" => Some(Self::BlockGossip),
            "attestation" => Some(Self::Attestation),
            "single_attestation" => Some(Self::SingleAttestation),
            "voluntary_exit" => Some(Self::VoluntaryExit),
            "bls_to_execution_change" => Some(Self::BlsToExecutionChange),
            "proposer_slashing" => Some(Self::ProposerSlashing),
            "attester_slashing" => Some(Self::AttesterSlashing),
            "contribution_and_proof" => Some(Self::ContributionAndProof),
            "light_client_finality_update" => Some(Self::LightClientFinalityUpdate),
            "light_client_optimistic_update" => Some(Self::LightClientOptimisticUpdate),
            "payload_attributes" => Some(Self::PayloadAttributes),
            "data_column_sidecar" => Some(Self::DataColumnSidecar),
            "execution_payload" => Some(Self::ExecutionPayload),
            "execution_payload_gossip" => Some(Self::ExecutionPayloadGossip),
            "execution_payload_available" => Some(Self::ExecutionPayloadAvailable),
            "execution_payload_bid" => Some(Self::ExecutionPayloadBid),
            "payload_attestation_message" => Some(Self::PayloadAttestationMessage),
            "fast_confirmation" => Some(Self::FastConfirmation),
            _ => None,
        }
    }

    /// Return `true` when this topic is currently emitted by pharos.
    ///
    /// Used to filter events on the bus: a `Head` event is never sent to a
    /// subscriber that only requested `payload_attributes`.
    pub fn matches_event(&self, event: &ApiEvent) -> bool {
        matches!(
            (self, event),
            (KnownTopic::Head, ApiEvent::Head(_))
                | (KnownTopic::Block, ApiEvent::Block(_))
                | (KnownTopic::ChainReorg, ApiEvent::ChainReorg(_))
                | (
                    KnownTopic::FinalizedCheckpoint,
                    ApiEvent::FinalizedCheckpoint(_)
                )
        )
    }
}

// ── EventBus ──────────────────────────────────────────────────────────────────

/// Broadcast bus for SSE events.
///
/// Constructed once in `main.rs` when `--http` is active.  The `Arc<EventBus>`
/// is shared between `ApiState` (which hands out receivers to SSE handlers) and
/// `run_api_event_adapter` (which pushes events).
pub struct EventBus {
    tx: broadcast::Sender<ApiEvent>,
}

impl EventBus {
    /// Construct a new bus with a bounded buffer.
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Arc::new(Self { tx })
    }

    /// Clone the sender so the event adapter can push events.
    pub fn sender(&self) -> broadcast::Sender<ApiEvent> {
        self.tx.clone()
    }

    /// Subscribe to receive events.  Returns a new `Receiver` per call.
    pub fn subscribe(&self) -> broadcast::Receiver<ApiEvent> {
        self.tx.subscribe()
    }
}
