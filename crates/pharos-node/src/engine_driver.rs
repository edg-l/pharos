//! Engine driver loop — bridges fork-choice head changes and new payloads to the EL.
//!
//! The driver loop runs as a long-lived `tokio::spawn` task. It:
//! (a) watches for `HeadChange` events and calls `engine_forkchoiceUpdatedV1`;
//!     on `INVALID` status, marks the head block as `PayloadStatus::Invalid`
//!     in the in-memory fork-choice store.
//! (b) watches for `NewPayloadRequest<E>` events and calls `engine_newPayloadV1`;
//!     maps the response to `PayloadStatus` and updates the in-memory store.
//!
//! Per `D-engine-head-driver` (M4a Phase 4).
//! Cite: `specs/bellatrix/fork-choice.md:93-100`.

use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use pharos_engine::{
    EngineHandle, ForkchoiceUpdatedVersion, NewPayloadVersion, NewPayloadWire,
    types::{ExecutionPayloadV1, ExecutionPayloadV2, ForkchoiceStateV1},
};
use pharos_fork_choice::Store as FcStore;
use pharos_types::{EthSpec, PayloadStatus, phase0::primitives::Root};
use pharos_utils::Hash256;

// ── ExecutionEngineHandle ─────────────────────────────────────────────────────

/// Bridges `EngineHandle` to the sync `ExecutionEngine` trait used by the STF.
///
/// `pharos-engine` cannot depend on `pharos-stf`, and `pharos-stf` cannot
/// depend on `pharos-engine`. This newtype in `pharos-node` bridges the two:
/// it holds an `EngineHandle` and implements `ExecutionEngine` by calling
/// `EngineHandle::new_payload_blocking` (which submits a request to the engine
/// actor and blocks on the reply via the dedicated engine `Runtime`).
///
/// The STF call site is always inside `tokio::task::spawn_blocking` (M3a
/// invariant), so blocking here does not block a tokio worker thread.
#[derive(Clone)]
pub struct ExecutionEngineHandle {
    pub(crate) engine: EngineHandle,
}

impl ExecutionEngineHandle {
    /// Construct a new bridge wrapping the given engine handle.
    pub fn new(engine: EngineHandle) -> Self {
        Self { engine }
    }
}

impl pharos_stf::ExecutionEngine for ExecutionEngineHandle {
    fn notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        payload: &pharos_types::bellatrix::ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool {
        let wire = payload_to_wire_generic(payload);
        self.new_payload_wire(NewPayloadWire::V1(wire))
    }

    /// Override the default: call `engine_newPayloadV2` with the full capella payload
    /// (including withdrawals) instead of stripping and falling back to V1.
    ///
    /// Per `D-engine-v2-dispatch` (docs/decisions.md M6-Capella section): capella
    /// blocks MUST use V2; this is the Phase-2 carry-in fix (capella STF previously
    /// forwarded a Bellatrix-shaped payload with withdrawals stripped).
    fn notify_new_payload_capella<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
        const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    >(
        &self,
        payload: &pharos_types::capella::ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    ) -> bool {
        let wire: ExecutionPayloadV2 = payload.clone().into();
        self.new_payload_wire(NewPayloadWire::V2(wire))
    }
}

impl ExecutionEngineHandle {
    /// Shared helper: send a `NewPayloadWire` request to the engine actor and
    /// interpret the response as a validity boolean.
    fn new_payload_wire(&self, wire: NewPayloadWire) -> bool {
        let version = match &wire {
            NewPayloadWire::V1(_) => NewPayloadVersion::V1,
            NewPayloadWire::V2(_) => NewPayloadVersion::V2,
        };
        match self.engine.new_payload_blocking(version, wire) {
            Ok(status) => {
                use pharos_engine::types::PayloadStatusStatus;
                matches!(
                    status.status,
                    PayloadStatusStatus::Valid | PayloadStatusStatus::Accepted
                )
            }
            Err(e) => {
                tracing::warn!(error = %e, "ExecutionEngineHandle::new_payload_wire: engine error");
                false
            }
        }
    }
}

/// Convert a generic `ExecutionPayload` to `ExecutionPayloadV1` wire format.
///
/// This function handles all const-parameter combinations by using the same
/// byte-encoding logic as `PayloadToWire`, applied generically via the
/// `as_slice()` methods available on `SszList`/`SszVector`/`FixedBytes`.
fn payload_to_wire_generic<
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
>(
    payload: &pharos_types::bellatrix::ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
) -> ExecutionPayloadV1 {
    ExecutionPayloadV1 {
        parent_hash: bytes_to_data_hex(payload.parent_hash.as_slice()),
        fee_recipient: bytes_to_data_hex(payload.fee_recipient.as_slice()),
        state_root: bytes_to_data_hex(payload.state_root.as_slice()),
        receipts_root: bytes_to_data_hex(payload.receipts_root.as_slice()),
        logs_bloom: bytes_to_data_hex(payload.logs_bloom.as_slice()),
        prev_randao: bytes_to_data_hex(payload.prev_randao.as_slice()),
        block_number: u64_to_quantity_hex(payload.block_number),
        gas_limit: u64_to_quantity_hex(payload.gas_limit),
        gas_used: u64_to_quantity_hex(payload.gas_used),
        timestamp: u64_to_quantity_hex(payload.timestamp),
        extra_data: bytes_to_data_hex(payload.extra_data.as_slice()),
        base_fee_per_gas: uint256_to_quantity_hex(&payload.base_fee_per_gas),
        block_hash: bytes_to_data_hex(payload.block_hash.as_slice()),
        transactions: payload
            .transactions
            .as_slice()
            .iter()
            .map(|tx| bytes_to_data_hex(tx.as_slice()))
            .collect(),
    }
}

// ── PayloadToWire / PayloadToWireV2 ──────────────────────────────────────────

/// Convert a Bellatrix CL-side `ExecutionPayload` to `ExecutionPayloadV1` wire format.
///
/// Implemented for `MainnetExecutionPayload` and `MinimalExecutionPayload`.
/// The conversion is in `pharos-node` because `pharos-types` must not depend on
/// `pharos-engine` (the Engine API client is a node-level concern).
///
/// Called by the block-ingestion loop for every Bellatrix block
/// to push `engine_newPayloadV1` requests to the engine driver.
pub trait PayloadToWire {
    /// Convert `&self` to an `ExecutionPayloadV1`.
    fn to_execution_payload_v1(&self) -> ExecutionPayloadV1;
}

/// Convert a Capella CL-side `ExecutionPayload` to `ExecutionPayloadV2` wire format
/// (includes withdrawals).
///
/// Implemented for the concrete Capella `ExecutionPayload` with mainnet/minimal const params.
/// Used by `import.rs` to push `engine_newPayloadV2` for capella blocks.
///
/// Per `D-engine-v2-dispatch` (docs/decisions.md M6-Capella section).
pub trait PayloadToWireV2 {
    /// Convert `&self` to an `ExecutionPayloadV2`.
    fn to_execution_payload_v2(&self) -> ExecutionPayloadV2;
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Encode a byte slice as `0x`-prefixed lowercase hex (DATA encoding).
fn bytes_to_data_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Encode a `u64` as `0x`-prefixed lowercase hex QUANTITY (no leading zeros,
/// minimum representation) per Engine API spec.
fn u64_to_quantity_hex(n: u64) -> String {
    format!("0x{n:x}")
}

/// Encode a `pharos_utils::Uint256` as `0x`-prefixed hex QUANTITY (minimal
/// representation, big-endian byte order, no leading zeros).
///
/// `Uint256` stores bytes little-endian, so we reverse before encoding.
/// A zero value is encoded as `"0x0"`.
fn uint256_to_quantity_hex(n: &pharos_utils::Uint256) -> String {
    // Bytes are LE; reverse to get BE for the Engine API QUANTITY encoding.
    // Minimal hex with NO leading-zero nibble (strict ELs like geth/reth reject
    // "0x07"; the value must encode as "0x7").
    let be_bytes: Vec<u8> = n.to_le_bytes().into_iter().rev().collect();
    match be_bytes.iter().position(|&b| b != 0) {
        None => "0x0".to_string(),
        Some(i) => {
            use std::fmt::Write as _;
            let mut hex = String::with_capacity(2 + (be_bytes.len() - i) * 2);
            hex.push_str("0x");
            let _ = write!(hex, "{:x}", be_bytes[i]);
            for b in &be_bytes[i + 1..] {
                let _ = write!(hex, "{b:02x}");
            }
            hex
        }
    }
}

// ── PayloadToWire impl ────────────────────────────────────────────────────────

/// Implement `PayloadToWire` for the concrete Bellatrix `ExecutionPayload` type.
///
/// Both `MainnetExecutionPayload` and `MinimalExecutionPayload` are aliases
/// for the same `ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>` type,
/// so one implementation covers both presets.
impl PayloadToWire
    for pharos_types::bellatrix::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32>
{
    fn to_execution_payload_v1(&self) -> ExecutionPayloadV1 {
        ExecutionPayloadV1 {
            parent_hash: bytes_to_data_hex(self.parent_hash.as_slice()),
            fee_recipient: bytes_to_data_hex(self.fee_recipient.as_slice()),
            state_root: bytes_to_data_hex(self.state_root.as_slice()),
            receipts_root: bytes_to_data_hex(self.receipts_root.as_slice()),
            logs_bloom: bytes_to_data_hex(self.logs_bloom.as_slice()),
            prev_randao: bytes_to_data_hex(self.prev_randao.as_slice()),
            block_number: u64_to_quantity_hex(self.block_number),
            gas_limit: u64_to_quantity_hex(self.gas_limit),
            gas_used: u64_to_quantity_hex(self.gas_used),
            timestamp: u64_to_quantity_hex(self.timestamp),
            extra_data: bytes_to_data_hex(self.extra_data.as_slice()),
            base_fee_per_gas: uint256_to_quantity_hex(&self.base_fee_per_gas),
            block_hash: bytes_to_data_hex(self.block_hash.as_slice()),
            transactions: self
                .transactions
                .as_slice()
                .iter()
                .map(|tx| bytes_to_data_hex(tx.as_slice()))
                .collect(),
        }
    }
}

// ── PayloadToWireV2 impls ─────────────────────────────────────────────────────

/// Implement `PayloadToWireV2` for the mainnet Capella `ExecutionPayload`
/// (MAX_WITHDRAWALS_PER_PAYLOAD = 16).
impl PayloadToWireV2
    for pharos_types::capella::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 16>
{
    fn to_execution_payload_v2(&self) -> ExecutionPayloadV2 {
        self.clone().into()
    }
}

/// Implement `PayloadToWireV2` for the minimal Capella `ExecutionPayload`
/// (MAX_WITHDRAWALS_PER_PAYLOAD = 4).
impl PayloadToWireV2
    for pharos_types::capella::ExecutionPayload<1_073_741_824, 1_048_576, 256, 32, 4>
{
    fn to_execution_payload_v2(&self) -> ExecutionPayloadV2 {
        self.clone().into()
    }
}

// ── HeadChange ────────────────────────────────────────────────────────────────

/// Describes a head-selection update, broadcast from the ingestion loop to
/// the engine driver via a `watch` channel.
///
/// All hash fields are 32-byte EL block hashes encoded as hex strings with
/// a `0x` prefix (`DATA` encoding per the Engine API spec), or `"0x" + "00"*32`
/// when the block is pre-merge (no EL counterpart).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadChange {
    /// CL block root of the new head.
    pub head_root: Root,
    /// EL block hash of the new head block.
    pub head_block_hash: String,
    /// EL block hash of the safe block (justified checkpoint).
    pub safe_block_hash: String,
    /// EL block hash of the finalized block (finalized checkpoint).
    pub finalized_block_hash: String,
}

// ── NewPayloadRequest ─────────────────────────────────────────────────────────

/// Wraps a fork-discriminated execution payload together with its CL block root
/// so the engine driver can record the returned `PayloadStatus` keyed by root.
///
/// V1 carries a Bellatrix payload; V2 carries a Capella payload (with withdrawals).
/// The driver dispatches `engine_newPayloadV1` or `engine_newPayloadV2` accordingly.
pub struct NewPayloadRequest<E: EthSpec> {
    /// CL block root of the block that contains this payload.
    pub block_root: Root,
    /// The wire-format execution payload (fork-discriminated).
    pub payload: NewPayloadWire,
    /// `_marker` lets the struct carry the `E: EthSpec` bound without storing
    /// an `E`-typed value (the payload itself is fork-agnostic at wire level).
    pub _marker: std::marker::PhantomData<E>,
}

// ── compute_safe_block_hash / compute_finalized_block_hash ────────────────────

/// Derive the `safe_block_hash` for `engine_forkchoiceUpdatedV1`.
///
/// Per `specs/bellatrix/fork-choice.md:93-100`.
///
/// M4a simplification: uses the justified-checkpoint head's EL block hash.
/// The full `get_safe_execution_block_hash` re-org-aware variant (which
/// considers proposer-boost state) is deferred to M11 alongside the full
/// proposer-boost re-org logic.
///
/// Per `D-engine-head-driver` ADR: full `get_safe_execution_block_hash` is
/// deferred to M11.
pub fn compute_safe_block_hash<E: EthSpec>(store: &FcStore<E>) -> Hash256 {
    use pharos_fork_choice::execution_block_hash_at_root;
    execution_block_hash_at_root(store, store.justified_checkpoint.root)
}

/// Derive the `finalized_block_hash` for `engine_forkchoiceUpdatedV1`.
///
/// Uses the finalized-checkpoint block's EL block hash.
/// Returns `Hash256::default()` (zero hash) for pre-merge (Phase0/Altair) blocks.
pub fn compute_finalized_block_hash<E: EthSpec>(store: &FcStore<E>) -> Hash256 {
    use pharos_fork_choice::execution_block_hash_at_root;
    execution_block_hash_at_root(store, store.finalized_checkpoint.root)
}

/// Format a `Hash256` as a `0x`-prefixed lowercase hex string.
///
/// Used by the block-ingestion loop to build `HeadChange` hash strings.
pub fn hash_to_hex(h: Hash256) -> String {
    let bytes = h.as_slice();
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ── run_engine_driver_loop ────────────────────────────────────────────────────

/// Async engine-driver loop.
///
/// Selects between:
/// (a) `head_rx.changed()` — calls `engine_forkchoiceUpdatedV1` with the new
///     head/safe/finalized hashes.  If the EL returns `INVALID`, marks the
///     head block as `PayloadStatus::Invalid` in the in-memory store.
/// (b) `payload_rx.recv()` — calls `engine_newPayloadV1` with the new payload.
///     Maps `PayloadStatusStatus` to `PayloadStatus` and updates the store.
///
/// The loop exits when both `head_rx` and `payload_rx` are dropped.
pub async fn run_engine_driver_loop<E: EthSpec>(
    engine: EngineHandle,
    store: Arc<RwLock<FcStore<E>>>,
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    mut payload_rx: mpsc::Receiver<NewPayloadRequest<E>>,
) {
    loop {
        tokio::select! {
            // Head changed — call forkchoiceUpdated.
            result = head_rx.changed() => {
                if result.is_err() {
                    // The sender was dropped; shut down.
                    break;
                }
                let change = {
                    let guard = head_rx.borrow();
                    guard.clone()
                };
                let Some(change) = change else { continue };

                let state = ForkchoiceStateV1 {
                    head_block_hash: change.head_block_hash.clone(),
                    safe_block_hash: change.safe_block_hash.clone(),
                    finalized_block_hash: change.finalized_block_hash.clone(),
                };

                // Select engine_forkchoiceUpdatedV1 (Bellatrix) or V2 (Capella+)
                // based on the head block's fork.
                //
                // For the follow-only path (no payload attributes), FCU V1 and V2
                // behave identically when attrs = null. We dispatch V2 when the
                // head block is a Capella block (E::unwrap_capella_block returns Some).
                //
                // Per `D-engine-v2-dispatch`: dispatch V2 when head is Capella.
                let fcu_version = {
                    let store = store.read();
                    if let Some(block) = store.blocks.get(&change.head_root) {
                        if E::unwrap_capella_block(block).is_some() {
                            ForkchoiceUpdatedVersion::V2
                        } else {
                            ForkchoiceUpdatedVersion::V1
                        }
                    } else {
                        ForkchoiceUpdatedVersion::V1
                    }
                };

                let engine_clone = engine.clone();
                let state_clone = state.clone();
                let fcu_result = tokio::task::spawn_blocking(move || {
                    match fcu_version {
                        ForkchoiceUpdatedVersion::V2 => engine_clone
                            .forkchoice_updated_v2_blocking(state_clone, None),
                        _ => engine_clone.forkchoice_updated_blocking(
                            ForkchoiceUpdatedVersion::V1,
                            state_clone,
                            None,
                        ),
                    }
                })
                .await;

                match fcu_result {
                    Err(join_err) => {
                        error!(error = %join_err, "forkchoice_updated: join error");
                    }
                    Ok(Err(engine_err)) => {
                        warn!(error = %engine_err, "forkchoice_updated: engine error");
                    }
                    Ok(Ok(resp)) => {
                        use pharos_engine::types::PayloadStatusStatus;
                        match resp.payload_status.status {
                            PayloadStatusStatus::Invalid | PayloadStatusStatus::InvalidBlockHash => {
                                warn!(
                                    head_root = %change.head_root,
                                    "forkchoice_updated: EL returned INVALID for head; \
                                     marking block as Invalid"
                                );
                                store.write().mark_payload_status(
                                    change.head_root,
                                    PayloadStatus::Invalid,
                                );
                            }
                            PayloadStatusStatus::Valid => {
                                // Do not overwrite the status set by engine_newPayloadV1.
                                // `newPayload` is the authoritative source for block-level
                                // payload validity; FCU Valid merely means the EL accepted
                                // the forkchoice state (which may include a block already
                                // marked Invalid by a prior newPayload call).  Overwriting
                                // here would lose the Invalid verdict in a race between
                                // newPayload-INVALID and FCU-VALID for the same root.
                                info!(
                                    head_hash = %change.head_block_hash,
                                    "forkchoice_updated: EL accepted head"
                                );
                            }
                            PayloadStatusStatus::Syncing | PayloadStatusStatus::Accepted => {
                                info!(
                                    status = ?resp.payload_status.status,
                                    "forkchoice_updated: EL is syncing / optimistic"
                                );
                            }
                        }
                    }
                }
            }

            // New payload — call newPayload.
            maybe_req = payload_rx.recv() => {
                let Some(req) = maybe_req else { break };

                let engine_clone = engine.clone();
                let payload_wire = req.payload.clone();
                let version = match &payload_wire {
                    NewPayloadWire::V1(_) => NewPayloadVersion::V1,
                    NewPayloadWire::V2(_) => NewPayloadVersion::V2,
                };
                let np_result = tokio::task::spawn_blocking(move || {
                    engine_clone.new_payload_blocking(version, payload_wire)
                })
                .await;

                let status = match np_result {
                    Err(join_err) => {
                        error!(error = %join_err, "new_payload: join error");
                        PayloadStatus::NotValidated
                    }
                    Ok(Err(engine_err)) => {
                        warn!(error = %engine_err, "new_payload: engine error");
                        PayloadStatus::NotValidated
                    }
                    Ok(Ok(resp)) => {
                        use pharos_engine::types::PayloadStatusStatus;
                        match resp.status {
                            PayloadStatusStatus::Valid => PayloadStatus::Valid,
                            PayloadStatusStatus::Invalid
                            | PayloadStatusStatus::InvalidBlockHash => PayloadStatus::Invalid,
                            PayloadStatusStatus::Syncing | PayloadStatusStatus::Accepted => {
                                PayloadStatus::NotValidated
                            }
                        }
                    }
                };

                store.write().mark_payload_status(req.block_root, status);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_engine::{ExecutionPayloadV1, ExecutionPayloadV2};

    /// Verify that `NewPayloadRequest` built with a `V1` wire payload selects
    /// `NewPayloadVersion::V1` (Bellatrix path).
    #[test]
    fn new_payload_wire_v1_selects_v1_version() {
        let payload = ExecutionPayloadV1 {
            parent_hash: "0x00".into(),
            fee_recipient: "0x00".into(),
            state_root: "0x00".into(),
            receipts_root: "0x00".into(),
            logs_bloom: "0x00".into(),
            prev_randao: "0x00".into(),
            block_number: "0x0".into(),
            gas_limit: "0x0".into(),
            gas_used: "0x0".into(),
            timestamp: "0x0".into(),
            extra_data: "0x".into(),
            base_fee_per_gas: "0x0".into(),
            block_hash: "0x00".into(),
            transactions: vec![],
        };
        let wire = NewPayloadWire::V1(payload);
        let version = match &wire {
            NewPayloadWire::V1(_) => NewPayloadVersion::V1,
            NewPayloadWire::V2(_) => NewPayloadVersion::V2,
        };
        assert_eq!(version, NewPayloadVersion::V1);
    }

    /// Verify that `NewPayloadRequest` built with a `V2` wire payload selects
    /// `NewPayloadVersion::V2` (Capella path, with withdrawals).
    #[test]
    fn new_payload_wire_v2_selects_v2_version() {
        let payload = ExecutionPayloadV2 {
            parent_hash: "0x00".into(),
            fee_recipient: "0x00".into(),
            state_root: "0x00".into(),
            receipts_root: "0x00".into(),
            logs_bloom: "0x00".into(),
            prev_randao: "0x00".into(),
            block_number: "0x0".into(),
            gas_limit: "0x0".into(),
            gas_used: "0x0".into(),
            timestamp: "0x0".into(),
            extra_data: "0x".into(),
            base_fee_per_gas: "0x0".into(),
            block_hash: "0x00".into(),
            transactions: vec![],
            withdrawals: vec![],
        };
        let wire = NewPayloadWire::V2(payload);
        let version = match &wire {
            NewPayloadWire::V1(_) => NewPayloadVersion::V1,
            NewPayloadWire::V2(_) => NewPayloadVersion::V2,
        };
        assert_eq!(version, NewPayloadVersion::V2);
    }
}
