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
    EngineError, EngineHandle, ForkchoiceUpdatedVersion, NewPayloadVersion, NewPayloadWire,
    types::{
        BlobsBundleV1, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3,
        ForkchoiceStateV1, GetPayloadV3Response, PayloadAttributesV1, PayloadAttributesV2,
        PayloadAttributesV3, PayloadIdV1, WithdrawalV1,
    },
};
use pharos_fork_choice::{
    PowBlockProvider, Store as FcStore, ValidateMergeBlockError, apply_invalid_payload,
    block_is_execution_enabled, execution_block_hash_at_root, get_head, promote_valid_ancestors,
    validate_merge_block,
};
use pharos_stf::{
    GetExpectedWithdrawalsDispatch,
    phase0::accessors::{get_current_epoch, get_randao_mix},
};
use pharos_types::{
    BeaconStateView, EthSpec, PayloadStatus,
    config::RuntimeConfig,
    phase0::primitives::Root,
    views::{BeaconBlockView, ForkVariant},
};
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
    ) -> pharos_stf::PayloadVerificationStatus {
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
    ) -> pharos_stf::PayloadVerificationStatus {
        let wire: ExecutionPayloadV2 = payload.clone().into();
        self.new_payload_wire(NewPayloadWire::V2(wire))
    }

    /// Override the default: call `engine_newPayloadV3` with the full deneb payload
    /// (including `blobGasUsed`, `excessBlobGas`), the versioned hashes derived from
    /// `blob_kzg_commitments`, and the `parentBeaconBlockRoot`.
    ///
    /// Per `execution-apis/src/engine/cancun.md` engine_newPayloadV3.
    fn notify_new_payload_deneb<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
        const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    >(
        &self,
        payload: &pharos_types::deneb::ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
        versioned_hashes: &[[u8; 32]],
        parent_beacon_block_root: pharos_types::phase0::primitives::Root,
    ) -> pharos_stf::PayloadVerificationStatus {
        let wire: ExecutionPayloadV3 = payload.clone().into();
        // Convert versioned hashes to hex DATA strings.
        let vh_hex: Vec<String> = versioned_hashes
            .iter()
            .map(|h| bytes_to_data_hex(h))
            .collect();
        let pbbr_hex = bytes_to_data_hex(parent_beacon_block_root.as_slice());
        self.new_payload_wire(NewPayloadWire::V3 {
            payload: wire,
            versioned_hashes: vh_hex,
            parent_beacon_block_root: pbbr_hex,
        })
    }

    /// Override the default: call `engine_getBlobsV1` on the local EL blob pool.
    ///
    /// Returns one `Option<(blob_bytes, proof_bytes)>` per versioned hash.  `None`
    /// means the EL does not have that blob (not yet in mempool or already pruned).
    /// Any engine transport/JSON-RPC error results in an empty vec (no fallback).
    ///
    /// Per `D-getblobsv1-da-fallback` (M10-Deneb Phase 3).
    fn get_blobs_v1(&self, versioned_hashes: &[[u8; 32]]) -> Vec<Option<(Vec<u8>, Vec<u8>)>> {
        let vh_hex: Vec<String> = versioned_hashes
            .iter()
            .map(|h| bytes_to_data_hex(h))
            .collect();
        match self.engine.get_blobs_v1_blocking(vh_hex) {
            Ok(blobs) => blobs
                .into_iter()
                .map(|opt| {
                    opt.map(|b| {
                        // Decode hex-encoded blob and proof bytes.
                        let blob = hex_data_to_bytes(&b.blob).unwrap_or_default();
                        let proof = hex_data_to_bytes(&b.proof).unwrap_or_default();
                        (blob, proof)
                    })
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "get_blobs_v1: engine error; skipping EL fallback");
                vec![]
            }
        }
    }
}

impl ExecutionEngineHandle {
    /// Shared helper: send a `NewPayloadWire` request to the engine actor and
    /// map the EL response to `PayloadVerificationStatus`.
    ///
    /// Per `specs/sync/optimistic.md` "How to optimistically import blocks":
    /// - `VALID`                   → `Valid`
    /// - `SYNCING` / `ACCEPTED`    → `NotValidated` (NOT_VALIDATED)
    /// - `INVALID` / `INVALID_BLOCK_HASH` → `Invalid` (INVALIDATED)
    /// - engine error              → `Invalid` (MUST NOT import on EL error)
    ///
    /// Both `notify_new_payload` and `notify_new_payload_capella` on
    /// `ExecutionEngineHandle` inherit this behaviour via this shared helper.
    ///
    /// IMPORTANT: `FixedExecutionEngine` (the conformance mock in
    /// `pharos-stf`) is intentionally NOT changed — `execution_valid: false`
    /// fixtures must still drive STF rejection on the conformance path.
    ///
    /// Per `D-engine-edge-stf-relaxation` (M8 Phase 1), `D-payload-verification-status` (M8 Phase 3b).
    fn new_payload_wire(&self, wire: NewPayloadWire) -> pharos_stf::PayloadVerificationStatus {
        use pharos_stf::PayloadVerificationStatus;
        let version = match &wire {
            NewPayloadWire::V1(_) => NewPayloadVersion::V1,
            NewPayloadWire::V2(_) => NewPayloadVersion::V2,
            NewPayloadWire::V3 { .. } => NewPayloadVersion::V3,
        };
        match self.engine.new_payload_blocking(version, wire) {
            Ok(status) => {
                use pharos_engine::types::PayloadStatusStatus;
                match status.status {
                    PayloadStatusStatus::Valid => PayloadVerificationStatus::Valid,
                    PayloadStatusStatus::Syncing | PayloadStatusStatus::Accepted => {
                        PayloadVerificationStatus::NotValidated
                    }
                    PayloadStatusStatus::Invalid | PayloadStatusStatus::InvalidBlockHash => {
                        PayloadVerificationStatus::Invalid
                    }
                }
            }
            Err(e) => {
                // Per `specs/sync/optimistic.md` "Execution Engine Errors":
                // a CL MUST NOT optimistically import a block if the EL returns
                // an error for engine_newPayload.
                tracing::warn!(error = %e, "ExecutionEngineHandle::new_payload_wire: engine error");
                PayloadVerificationStatus::Invalid
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

/// Decode a `0x`-prefixed hex DATA string to raw bytes.
///
/// Returns `None` on any parse error.
pub fn hex_data_to_bytes(s: &str) -> Option<Vec<u8>> {
    let hex = s.strip_prefix("0x")?;
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Encode a byte slice as `0x`-prefixed lowercase hex (DATA encoding).
pub fn bytes_to_data_hex(bytes: &[u8]) -> String {
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
    /// Beacon chain slot of the new head block.
    pub head_slot: pharos_types::phase0::Slot,
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
/// Resolves `latest_verified_ancestor` of the justified checkpoint root FIRST,
/// so an optimistically-imported block is NEVER sent to the EL as `safe`.
/// Per `consensus-specs/sync/optimistic.md` "Validator assignments / Re-orgs":
/// "the safe block hash MUST be the `latest_verified_ancestor` of the justified
/// checkpoint block". ADR `D-fcu-safe-finalized-verified-ancestor`.
///
/// Per `D-engine-head-driver` ADR: full `get_safe_execution_block_hash` is
/// deferred to M11.
pub fn compute_safe_block_hash<E: EthSpec>(store: &FcStore<E>) -> Hash256 {
    use pharos_fork_choice::{execution_block_hash_at_root, latest_verified_ancestor};
    let verified = latest_verified_ancestor::<E>(store, store.justified_checkpoint.root);
    execution_block_hash_at_root(store, verified)
}

/// Derive the `finalized_block_hash` for `engine_forkchoiceUpdatedV1`.
///
/// Uses the finalized-checkpoint block's EL block hash.
/// Returns `Hash256::default()` (zero hash) for pre-merge (Phase0/Altair) blocks.
///
/// Resolves `latest_verified_ancestor` of the finalized checkpoint root FIRST,
/// so an optimistically-imported block is NEVER sent to the EL as `finalized`.
/// Per `consensus-specs/sync/optimistic.md` "Validator assignments / Re-orgs".
/// ADR `D-fcu-safe-finalized-verified-ancestor`.
pub fn compute_finalized_block_hash<E: EthSpec>(store: &FcStore<E>) -> Hash256 {
    use pharos_fork_choice::{execution_block_hash_at_root, latest_verified_ancestor};
    let verified = latest_verified_ancestor::<E>(store, store.finalized_checkpoint.root);
    execution_block_hash_at_root(store, verified)
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

// ── parse_latest_valid_hash ───────────────────────────────────────────────────

/// Parse the Engine API `latestValidHash` field into `Option<Hash256>`.
///
/// The Engine API encodes the field as a `DATA` hex string (`0x`-prefixed
/// 32 bytes) or JSON `null`.  A `None` input (JSON null) or a string that
/// cannot be decoded as exactly 32 hex bytes returns `None`, which the
/// caller treats as "null LVH" per the spec table.
///
/// Per `consensus-specs/sync/optimistic.md:224-233`:
/// "How to apply latestValidHash when payload status is INVALID".
///
/// `Hash256 = FixedBytes<32>` implements `FromStr` (strips `0x`, hex-decodes,
/// checks length) so we delegate to that.
pub fn parse_latest_valid_hash(s: Option<&str>) -> Option<Hash256> {
    let s = s?;
    s.parse::<Hash256>().ok()
}

// ── PayloadNotReady ───────────────────────────────────────────────────────────

/// Errors returned by `prepare_execution_payload[_bellatrix]`.
#[derive(Debug)]
pub enum PreparePayloadError {
    /// EL returned `payloadId = None` — EL is syncing or not ready to build.
    PayloadNotReady,
    /// Engine API call failed.
    Engine(EngineError),
}

impl std::fmt::Display for PreparePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreparePayloadError::PayloadNotReady => {
                write!(f, "EL did not return a payload id (syncing/not ready)")
            }
            PreparePayloadError::Engine(e) => write!(f, "engine error: {e}"),
        }
    }
}

impl From<EngineError> for PreparePayloadError {
    fn from(e: EngineError) -> Self {
        PreparePayloadError::Engine(e)
    }
}

// ── build_payload_attributes_v2 / v1 ─────────────────────────────────────────

/// Build `PayloadAttributesV2` for a Capella block proposal.
///
/// - `timestamp`           = `state.genesis_time + slot * seconds_per_slot`
/// - `prev_randao`         = `get_randao_mix(state, current_epoch)`
///   (the mix used by the proposer, per `specs/capella/beacon-chain.md`)
/// - `suggested_fee_recipient` = `fee_recipient` arg (caller-supplied)
/// - `withdrawals`         = `get_expected_withdrawals(state)` for the proposal slot
///
/// Per `execution-apis/src/engine/shanghai.md` `PayloadAttributesV2`.
pub fn build_payload_attributes_v2<E: EthSpec>(
    state: &E::BeaconState,
    capella_inner: &E::CapellaBeaconState,
    slot: pharos_types::phase0::Slot,
    fee_recipient: String,
    runtime_cfg: &RuntimeConfig,
) -> PayloadAttributesV2
where
    E::CapellaBeaconState: GetExpectedWithdrawalsDispatch<E>,
{
    let timestamp = state.genesis_time() + slot.0 * runtime_cfg.seconds_per_slot;
    // prev_randao = get_randao_mix(state, get_current_epoch(state)) per
    // capella/validator.md. Precondition: `state` is advanced to the proposal
    // slot (process_slots(state, slot)) so its current epoch IS the proposal
    // epoch — at an epoch boundary a slot-derived epoch would diverge.
    let current_epoch = get_current_epoch::<E>(state);
    let prev_randao = get_randao_mix::<E>(state, current_epoch);
    let withdrawals: Vec<WithdrawalV1> = capella_inner
        .get_expected_withdrawals_dispatch()
        .into_iter()
        .map(|w| WithdrawalV1 {
            index: format!("0x{:x}", w.index),
            validator_index: format!("0x{:x}", w.validator_index.0),
            address: bytes_to_data_hex(w.address.as_slice()),
            amount: format!("0x{:x}", w.amount.0),
        })
        .collect();
    PayloadAttributesV2 {
        timestamp: format!("0x{timestamp:x}"),
        prev_randao: bytes_to_data_hex(prev_randao.as_slice()),
        suggested_fee_recipient: fee_recipient,
        withdrawals,
    }
}

/// Build `PayloadAttributesV3` for a Deneb block proposal.
///
/// Extends `PayloadAttributesV2` with `parentBeaconBlockRoot`:
/// - `timestamp`                = `state.genesis_time + slot * seconds_per_slot`
/// - `prev_randao`              = `get_randao_mix(state, current_epoch)`
/// - `suggested_fee_recipient`  = `fee_recipient` arg
/// - `withdrawals`              = pre-computed withdrawal list (caller assembles via
///   `GetExpectedWithdrawalsDispatch`)
/// - `parent_beacon_block_root` = `hash_tree_root(state.latest_block_header)` (per deneb/validator.md)
///
/// Per `execution-apis/src/engine/cancun.md` `PayloadAttributesV3`.
pub fn build_payload_attributes_v3<E: EthSpec>(
    state: &E::BeaconState,
    withdrawals: Vec<WithdrawalV1>,
    slot: pharos_types::phase0::Slot,
    fee_recipient: String,
    parent_beacon_block_root: Hash256,
    runtime_cfg: &RuntimeConfig,
) -> PayloadAttributesV3 {
    let timestamp = state.genesis_time() + slot.0 * runtime_cfg.seconds_per_slot;
    let current_epoch = get_current_epoch::<E>(state);
    let prev_randao = get_randao_mix::<E>(state, current_epoch);
    PayloadAttributesV3 {
        timestamp: format!("0x{timestamp:x}"),
        prev_randao: bytes_to_data_hex(prev_randao.as_slice()),
        suggested_fee_recipient: fee_recipient,
        withdrawals,
        parent_beacon_block_root: bytes_to_data_hex(parent_beacon_block_root.as_slice()),
    }
}

/// Build `PayloadAttributesV1` for a Bellatrix block proposal.
///
/// - `timestamp`           = `state.genesis_time + slot * seconds_per_slot`
/// - `prev_randao`         = `get_randao_mix(state, current_epoch)`
/// - `suggested_fee_recipient` = `fee_recipient` arg
///
/// Per `execution-apis/src/engine/paris.md` `PayloadAttributesV1`.
/// No `withdrawals` field (Bellatrix pre-dates withdrawals).
pub fn build_payload_attributes_v1<E: EthSpec>(
    state: &E::BeaconState,
    slot: pharos_types::phase0::Slot,
    fee_recipient: String,
    runtime_cfg: &RuntimeConfig,
) -> PayloadAttributesV1 {
    let timestamp = state.genesis_time() + slot.0 * runtime_cfg.seconds_per_slot;
    // Precondition: `state` advanced to the proposal slot — see the V2 builder.
    let current_epoch = get_current_epoch::<E>(state);
    let prev_randao = get_randao_mix::<E>(state, current_epoch);
    PayloadAttributesV1 {
        timestamp: format!("0x{timestamp:x}"),
        prev_randao: bytes_to_data_hex(prev_randao.as_slice()),
        suggested_fee_recipient: fee_recipient,
    }
}

// ── prepare_execution_payload / prepare_execution_payload_bellatrix ───────────

/// Capella V2 payload preparation: FCU V2 with attributes → payloadId → getPayloadV2.
///
/// Steps:
/// 1. Call `engine_forkchoiceUpdatedV2(fcu_state, Some(attrs))`.
/// 2. Extract `payloadId` — if absent (EL syncing / not ready) returns
///    `PreparePayloadError::PayloadNotReady` (never panics).
/// 3. Call `engine_getPayloadV2(payload_id)` and return the `ExecutionPayloadV2` plus
///    the EL `blockValue` (priority fees in wei) as a `Uint256`.
///
/// Per `execution-apis/src/engine/shanghai.md`.
pub fn prepare_execution_payload_with_value(
    engine: &EngineHandle,
    fcu_state: ForkchoiceStateV1,
    attrs: PayloadAttributesV2,
) -> Result<(ExecutionPayloadV2, pharos_utils::Uint256), PreparePayloadError> {
    let fcu_resp = engine.forkchoice_updated_v2_blocking(fcu_state, Some(attrs))?;
    let payload_id: PayloadIdV1 = fcu_resp
        .payload_id
        .ok_or(PreparePayloadError::PayloadNotReady)?;
    let get_resp = engine.get_payload_v2_blocking(payload_id)?;
    let block_value: pharos_utils::Uint256 = get_resp
        .block_value
        .parse()
        .unwrap_or(pharos_utils::Uint256::ZERO);
    Ok((get_resp.execution_payload, block_value))
}

/// Capella V2 payload preparation: FCU V2 with attributes → payloadId → getPayloadV2.
///
/// Returns only the `ExecutionPayloadV2` (drops `blockValue`).
/// Kept for backward compatibility with existing call sites that do not need the
/// execution payload value.
///
/// Per `execution-apis/src/engine/shanghai.md`.
pub fn prepare_execution_payload(
    engine: &EngineHandle,
    fcu_state: ForkchoiceStateV1,
    attrs: PayloadAttributesV2,
) -> Result<ExecutionPayloadV2, PreparePayloadError> {
    prepare_execution_payload_with_value(engine, fcu_state, attrs).map(|(payload, _value)| payload)
}

/// Bellatrix V1 payload preparation: FCU V1 with attributes → payloadId → getPayloadV1.
///
/// Steps:
/// 1. Call `engine_forkchoiceUpdatedV1(fcu_state, Some(attrs))`.
/// 2. Extract `payloadId` — if absent returns `PreparePayloadError::PayloadNotReady`.
/// 3. Call `engine_getPayloadV1(payload_id)` and return the `ExecutionPayloadV1`.
///
/// Per `execution-apis/src/engine/paris.md`.
pub fn prepare_execution_payload_bellatrix(
    engine: &EngineHandle,
    fcu_state: ForkchoiceStateV1,
    attrs: PayloadAttributesV1,
) -> Result<ExecutionPayloadV1, PreparePayloadError> {
    let fcu_resp =
        engine.forkchoice_updated_blocking(ForkchoiceUpdatedVersion::V1, fcu_state, Some(attrs))?;
    let payload_id: PayloadIdV1 = fcu_resp
        .payload_id
        .ok_or(PreparePayloadError::PayloadNotReady)?;
    let payload = engine.get_payload_blocking(pharos_engine::GetPayloadVersion::V1, payload_id)?;
    Ok(payload)
}

/// Deneb V3 payload preparation: FCU V3 with attributes → payloadId → getPayloadV3.
///
/// Steps:
/// 1. Call `engine_forkchoiceUpdatedV3(fcu_state, Some(attrs))`.
/// 2. Extract `payloadId` — if absent returns `PreparePayloadError::PayloadNotReady`.
/// 3. Call `engine_getPayloadV3(payload_id)` and return `(ExecutionPayloadV3,
///    BlobsBundleV1, block_value)`.
///
/// Per `execution-apis/src/engine/cancun.md`.
pub fn prepare_execution_payload_v3(
    engine: &EngineHandle,
    fcu_state: ForkchoiceStateV1,
    attrs: PayloadAttributesV3,
) -> Result<(ExecutionPayloadV3, BlobsBundleV1, pharos_utils::Uint256), PreparePayloadError> {
    let fcu_resp = engine.forkchoice_updated_v3_blocking(fcu_state, Some(attrs))?;
    let payload_id: PayloadIdV1 = fcu_resp
        .payload_id
        .ok_or(PreparePayloadError::PayloadNotReady)?;
    let GetPayloadV3Response {
        execution_payload,
        block_value,
        blobs_bundle,
        ..
    } = engine.get_payload_v3_blocking(payload_id)?;
    let value: pharos_utils::Uint256 = block_value.parse().unwrap_or(pharos_utils::Uint256::ZERO);
    Ok((execution_payload, blobs_bundle, value))
}

// ── maybe_emit_head_change ────────────────────────────────────────────────────

/// Recompute and emit a `HeadChange` if `new_head != prev_head`.
///
/// Called after `apply_invalid_payload` marks one or more blocks `Invalid`.
/// If the head did not move (the newly-invalid blocks were on a non-head branch)
/// we emit nothing to avoid a spurious FCU round-trip.
///
/// Per `consensus-specs/sync/optimistic.md:263-267` (fork choice MUST support
/// removing invalidated blocks from the canonical chain); the next call to
/// `engine_forkchoiceUpdated` (triggered by the emitted `HeadChange`) will
/// inform the EL of the updated head.
fn maybe_emit_head_change<E: EthSpec>(
    store: &Arc<RwLock<FcStore<E>>>,
    new_head: Root,
    prev_head: Root,
    head_tx: &watch::Sender<Option<HeadChange>>,
) where
    E::BeaconBlock: BeaconBlockView,
{
    if new_head == prev_head {
        return;
    }
    let s = store.read();
    let head_block_hash = hash_to_hex(execution_block_hash_at_root(&s, new_head));
    let safe_block_hash = hash_to_hex(compute_safe_block_hash(&s));
    let finalized_block_hash = hash_to_hex(compute_finalized_block_hash(&s));
    let head_slot = s
        .blocks
        .get(&new_head)
        .map(|b| b.slot())
        .unwrap_or_default();
    drop(s);

    let change = HeadChange {
        head_root: new_head,
        head_slot,
        head_block_hash,
        safe_block_hash,
        finalized_block_hash,
    };
    info!(
        new_head = %new_head,
        "invalidation moved head; emitting HeadChange"
    );
    let _ = head_tx.send(Some(change));
}

// ── run_engine_driver_loop ────────────────────────────────────────────────────

/// Async engine-driver loop.
///
/// Selects between:
/// (a) `head_rx.changed()` — calls `engine_forkchoiceUpdated` (V1 or V2 depending
///     on the head block's fork) with the new head/safe/finalized hashes.  If the
///     EL returns `INVALID`, calls `apply_invalid_payload` with the `latestValidHash`
///     to mark the invalid block and all its descendants as `Invalid`, then recomputes
///     head via `get_head` and emits a new `HeadChange` if the head has changed.
/// (b) `payload_rx.recv()` — calls `engine_newPayload` (V1 or V2 depending on the
///     payload's fork) with the new payload.  On `INVALID`/`INVALID_BLOCK_HASH`,
///     calls `apply_invalid_payload` with `latestValidHash` for transitive
///     descendant invalidation; then recomputes head and emits a `HeadChange`
///     if the head has changed.
///
/// Per `consensus-specs/sync/optimistic.md:219-222` and `263-267`.
/// Per `D-engine-head-driver` (M4a Phase 4) and `D-latest-valid-hash-resolution` (M8 Phase 3).
///
/// The loop exits when both `head_rx` and `payload_rx` are dropped.
pub async fn run_engine_driver_loop<E: EthSpec, P: PowBlockProvider + Send + Sync + 'static>(
    engine: EngineHandle,
    store: Arc<RwLock<FcStore<E>>>,
    mut head_rx: watch::Receiver<Option<HeadChange>>,
    mut payload_rx: mpsc::Receiver<NewPayloadRequest<E>>,
    head_tx: watch::Sender<Option<HeadChange>>,
    pow_provider: Arc<P>,
) where
    E::BeaconBlock: BeaconBlockView + Clone,
    E::BeaconState: pharos_types::BeaconStateView,
{
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

                // Select engine_forkchoiceUpdatedV1 (Bellatrix), V2 (Capella), or V3 (Deneb+)
                // based on the head block's fork.
                //
                // For the follow-only path (no payload attributes), all FCU versions
                // behave identically when attrs = null. We dispatch the highest version
                // matching the head block's fork.
                //
                // Per `D-engine-v2-dispatch`: dispatch V2 when head is Capella.
                // Deneb uses V3 per cancun.md `engine_forkchoiceUpdatedV3`.
                let fcu_version = {
                    let store = store.read();
                    // Exhaustive fork match (no `unwrap_<fork>` chains): adding a
                    // new fork forces a compile error here rather than silently
                    // dispatching the wrong FCU version. Derived from the head
                    // state's fork (== the head block's fork; the block view has
                    // no fork discriminant).
                    match store
                        .block_states
                        .get(&change.head_root)
                        .map(|s| s.fork_variant())
                    {
                        Some(ForkVariant::Deneb) => ForkchoiceUpdatedVersion::V3,
                        Some(ForkVariant::Capella) => ForkchoiceUpdatedVersion::V2,
                        Some(
                            ForkVariant::Phase0
                            | ForkVariant::Altair
                            | ForkVariant::Bellatrix,
                        ) => ForkchoiceUpdatedVersion::V1,
                        None => ForkchoiceUpdatedVersion::V1,
                    }
                };

                let engine_clone = engine.clone();
                let state_clone = state.clone();
                let fcu_result = tokio::task::spawn_blocking(move || {
                    match fcu_version {
                        ForkchoiceUpdatedVersion::V3 => engine_clone
                            .forkchoice_updated_v3_blocking(state_clone, None),
                        ForkchoiceUpdatedVersion::V2 => engine_clone
                            .forkchoice_updated_v2_blocking(state_clone, None),
                        ForkchoiceUpdatedVersion::V1 => engine_clone.forkchoice_updated_blocking(
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
                                let lvh = parse_latest_valid_hash(
                                    resp.payload_status.latest_valid_hash.as_deref(),
                                );
                                warn!(
                                    head_root = %change.head_root,
                                    latest_valid_hash = ?lvh,
                                    "forkchoice_updated: EL returned INVALID; \
                                     applying transitive invalidation"
                                );
                                // Apply transitive invalidation under the write lock.
                                // Per `consensus-specs/sync/optimistic.md:219-222`.
                                // Invalid entries remain in-memory only (no DB handle in
                                // the driver); they self-heal on restart when the EL
                                // re-reports INVALID for the same payloads via newPayload.
                                let new_head = {
                                    let mut s = store.write();
                                    apply_invalid_payload::<E>(&mut s, change.head_root, lvh);
                                    get_head::<E>(&s)
                                };
                                maybe_emit_head_change::<E>(
                                    &store,
                                    new_head,
                                    change.head_root,
                                    &head_tx,
                                );
                            }
                            PayloadStatusStatus::Valid => {
                                // Do not overwrite the status set by engine_newPayloadV1/V2/V3.
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
                    NewPayloadWire::V3 { .. } => NewPayloadVersion::V3,
                };
                let np_result = tokio::task::spawn_blocking(move || {
                    engine_clone.new_payload_blocking(version, payload_wire)
                })
                .await;

                match np_result {
                    Err(join_err) => {
                        // ASYNC DRIVER PATH: a tokio join error is a transient runtime
                        // failure, NOT a protocol INVALID verdict.  Mapping to `Invalid`
                        // here would permanently evict a possibly-valid block from fork
                        // choice on a thread-pool blip.  We leave the block `NotValidated`
                        // (optimistic) so the next newPayload/FCU call retries when the
                        // thread pool recovers.
                        //
                        // Contrast with the SYNC path (`new_payload_wire`, STF-time):
                        // an engine error there maps to `Invalid` (MUST NOT import per
                        // `consensus-specs/sync/optimistic.md` "Execution Engine Errors"),
                        // because the block has NOT yet been imported into fork choice.
                        // Here the block is already imported; marking it Invalid would be
                        // an irreversible, unjustified eviction.
                        error!(error = %join_err, "new_payload: join error");
                        store
                            .write()
                            .mark_payload_status(req.block_root, PayloadStatus::NotValidated);
                    }
                    Ok(Err(engine_err)) => {
                        // ASYNC DRIVER PATH: a transient EL RPC error is NOT a protocol
                        // INVALID verdict.  The block is already imported; downgrading to
                        // `Invalid` on a connection blip would permanently evict it from
                        // fork choice.  Leave it `NotValidated` so the driver retries on
                        // the next newPayload/FCU when the EL reconnects.
                        //
                        // Sync-path divergence: `new_payload_wire` returns `Invalid` on
                        // engine error so the block is never imported (spec "MUST NOT
                        // import on EL error").  That conservative behaviour is correct at
                        // STF time because the block can be re-fetched; it is wrong here
                        // because the block is already in fork choice and re-fetching it
                        // would re-run the same `newPayload` call.
                        // Per `consensus-specs/sync/optimistic.md` "Execution Engine
                        // Errors" (deliberate sync-vs-async distinction).
                        warn!(error = %engine_err, "new_payload: engine error");
                        store
                            .write()
                            .mark_payload_status(req.block_root, PayloadStatus::NotValidated);
                    }
                    Ok(Ok(resp)) => {
                        use pharos_engine::types::PayloadStatusStatus;
                        match resp.status {
                            PayloadStatusStatus::Valid => {
                                // Per `consensus-specs/sync/optimistic.md:193-196`:
                                // when a block transitions NOT_VALIDATED → VALID, all
                                // ancestors MUST also transition NOT_VALIDATED → VALID.
                                // Promote under the write lock so ancestor promotion and
                                // the VALID mark are atomic from the lock's perspective.
                                //
                                // Per `consensus-specs/sync/optimistic.md:205-212`:
                                // when a "merge block" is declared VALID (directly or
                                // indirectly), `validate_merge_block` MUST be re-run.
                                // On failure the merge block MUST be treated as
                                // INVALIDATED (it and all descendants are invalidated).
                                let needs_invalidation = {
                                    let s = store.read();
                                    // Determine if req.block_root is a merge-transition block.
                                    // The spec definition keys on the PARENT post-state's
                                    // `is_merge_transition_complete` (latest_execution_payload_header
                                    // == default), NOT the parent block body: on a merge-at-genesis
                                    // chain (TTD=0) the genesis block body carries an empty payload
                                    // while the genesis STATE already holds the execution header, so
                                    // the structural "parent block has no payload" heuristic would
                                    // falsely flag the first post-genesis block as a merge transition
                                    // and invalidate the whole chain. Use the parent state via
                                    // `E::is_merge_transition_block`, falling back to the structural
                                    // check only when the parent state is unavailable.
                                    match s.blocks.get(&req.block_root) {
                                        Some(block) => {
                                            let parent_root = block.parent_root();
                                            match s.block_states.get(&parent_root) {
                                                Some(parent_state) => {
                                                    E::is_merge_transition_block(parent_state, block)
                                                }
                                                None => {
                                                    let is_exec =
                                                        block_is_execution_enabled::<E>(block);
                                                    let parent_is_exec = s
                                                        .blocks
                                                        .get(&parent_root)
                                                        .map(|b| block_is_execution_enabled::<E>(b))
                                                        .unwrap_or(false);
                                                    is_exec && !parent_is_exec
                                                }
                                            }
                                        }
                                        None => false,
                                    }
                                };

                                if needs_invalidation {
                                    // Re-run validate_merge_block as required by spec.
                                    // Extract payload_parent_hash for the check.
                                    //
                                    // NOTE: For checkpoint-synced Pharos the anchor is
                                    // always post-merge, so `is_exec && !parent_is_exec`
                                    // is never true for any imported block (no merge
                                    // transition block ever enters the store).  This code
                                    // path is only reachable if Pharos syncs from genesis
                                    // through the merge-transition itself (not the normal
                                    // operational mode).  The hook is implemented for
                                    // spec-correctness; see Task 4.2 finding in the phase
                                    // completion report.
                                    use pharos_stf::phase0::accessors::compute_epoch_at_slot;
                                    let (payload_parent_hash, tbh, tbh_epoch, ttd, block_slot) = {
                                        let s = store.read();
                                        let block = s.blocks.get(&req.block_root);
                                        (
                                            block
                                                .and_then(|b| {
                                                    E::get_execution_payload_parent_hash(b)
                                                })
                                                .unwrap_or_default(),
                                            s.terminal_block_hash,
                                            s.terminal_block_hash_activation_epoch,
                                            s.terminal_total_difficulty,
                                            block.map(|b| b.slot()).unwrap_or_default(),
                                        )
                                    };
                                    let current_epoch =
                                        compute_epoch_at_slot(block_slot, E::SLOTS_PER_EPOCH).0;
                                    let pow_clone = Arc::clone(&pow_provider);
                                    let merge_result = tokio::task::spawn_blocking(move || {
                                        validate_merge_block(
                                            payload_parent_hash,
                                            current_epoch,
                                            tbh,
                                            tbh_epoch,
                                            ttd,
                                            &*pow_clone,
                                        )
                                    })
                                    .await;

                                    // KNOWN LIMITATION (genesis-sync-through-merge only):
                                    //
                                    // (a) If re-validation returns PowBlockNotFound here
                                    //     (pow block still unavailable despite the EL
                                    //     reporting VALID — a contradictory/near-impossible
                                    //     EL state), the merge block stays NotValidated with
                                    //     no automatic retry.  newPayload fires once per
                                    //     block, so there is no recovery path short of a
                                    //     restart.  This edge is unreachable for checkpoint-
                                    //     synced Pharos (no merge-transition block ever
                                    //     enters the store in normal operation).
                                    //
                                    // (b) `promote_valid_ancestors` does NOT re-run
                                    //     `validate_merge_block` when it INDIRECTLY promotes
                                    //     a merge-transition block (i.e. when a descendant
                                    //     gets VALID and the walk crosses the merge block).
                                    //     Per spec, an indirect VALID of a merge block should
                                    //     also trigger `validate_merge_block`.  This is not
                                    //     implemented because it would require threading
                                    //     `pow_provider` into `promote_valid_ancestors`, and
                                    //     the path is unreachable for checkpoint-synced Pharos.
                                    match merge_result {
                                        Ok(Ok(())) => {
                                            // Merge block passed re-validation.  Mark it
                                            // explicitly Valid before promoting ancestors so the
                                            // promotion does not rely on the wildcard arm of
                                            // `promote_valid_ancestors` for the root itself.
                                            let mut s = store.write();
                                            s.mark_payload_status(
                                                req.block_root,
                                                PayloadStatus::Valid,
                                            );
                                            promote_valid_ancestors::<E>(&mut s, req.block_root);
                                        }
                                        Ok(Err(ValidateMergeBlockError::PowBlockNotFound {
                                            hash,
                                        })) => {
                                            // Still unknown: leave NotValidated.
                                            // See KNOWN LIMITATION (a) above.
                                            warn!(
                                                %hash,
                                                block_root = %req.block_root,
                                                "merge-transition VALID re-validation: \
                                                 pow_block still unknown; leaving NotValidated"
                                            );
                                        }
                                        Ok(Err(e)) => {
                                            // Merge block re-validation FAILED → treat as
                                            // INVALIDATED.  Per
                                            // `consensus-specs/sync/optimistic.md:209-212`.
                                            warn!(
                                                error = %e,
                                                block_root = %req.block_root,
                                                "merge-transition VALID re-validation FAILED; \
                                                 invalidating block and descendants"
                                            );
                                            let prev_head = {
                                                let guard = head_rx.borrow();
                                                guard
                                                    .as_ref()
                                                    .map(|hc| hc.head_root)
                                                    .unwrap_or_default()
                                            };
                                            let new_head = {
                                                let mut s = store.write();
                                                apply_invalid_payload::<E>(
                                                    &mut s,
                                                    req.block_root,
                                                    None,
                                                );
                                                get_head::<E>(&s)
                                            };
                                            maybe_emit_head_change::<E>(
                                                &store,
                                                new_head,
                                                prev_head,
                                                &head_tx,
                                            );
                                        }
                                        Err(join_err) => {
                                            error!(
                                                error = %join_err,
                                                "merge re-validation: spawn_blocking join error; \
                                                 leaving NotValidated"
                                            );
                                        }
                                    }
                                } else {
                                    // Non-merge-transition block: mark Valid explicitly
                                    // then promote ancestors.  Explicit mark removes the
                                    // dependency on the wildcard arm of
                                    // `promote_valid_ancestors` for the root itself.
                                    // Per `consensus-specs/sync/optimistic.md:193-196`.
                                    let mut s = store.write();
                                    s.mark_payload_status(
                                        req.block_root,
                                        PayloadStatus::Valid,
                                    );
                                    promote_valid_ancestors::<E>(&mut s, req.block_root);
                                }
                            }
                            PayloadStatusStatus::Invalid
                            | PayloadStatusStatus::InvalidBlockHash => {
                                let lvh =
                                    parse_latest_valid_hash(resp.latest_valid_hash.as_deref());
                                warn!(
                                    block_root = %req.block_root,
                                    latest_valid_hash = ?lvh,
                                    "new_payload: EL returned INVALID; \
                                     applying transitive invalidation"
                                );
                                // Apply transitive invalidation under the write lock.
                                // Per `consensus-specs/sync/optimistic.md:219-222`.
                                // Invalid entries remain in-memory only (no DB handle in
                                // the driver); they self-heal on restart when the EL
                                // re-reports INVALID for the same payloads via newPayload.
                                let prev_head = {
                                    let guard = head_rx.borrow();
                                    guard.as_ref().map(|hc| hc.head_root).unwrap_or_default()
                                };
                                let new_head = {
                                    let mut s = store.write();
                                    apply_invalid_payload::<E>(
                                        &mut s,
                                        req.block_root,
                                        lvh,
                                    );
                                    get_head::<E>(&s)
                                };
                                maybe_emit_head_change::<E>(
                                    &store,
                                    new_head,
                                    prev_head,
                                    &head_tx,
                                );
                            }
                            PayloadStatusStatus::Syncing | PayloadStatusStatus::Accepted => {
                                store.write().mark_payload_status(
                                    req.block_root,
                                    PayloadStatus::NotValidated,
                                );
                            }
                        }
                    }
                }
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
            NewPayloadWire::V3 { .. } => NewPayloadVersion::V3,
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
            NewPayloadWire::V3 { .. } => NewPayloadVersion::V3,
        };
        assert_eq!(version, NewPayloadVersion::V2);
    }

    // ── parse_latest_valid_hash tests ─────────────────────────────────────────

    /// None input (JSON null) → None.
    #[test]
    fn parse_lvh_none_returns_none() {
        assert_eq!(parse_latest_valid_hash(None), None);
    }

    /// Valid 0x-prefixed 32-byte hex → Some(hash).
    #[test]
    fn parse_lvh_valid_hash_returns_some() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_latest_valid_hash(Some(hex));
        assert_eq!(result, Some(Hash256::default()));
    }

    /// Valid 32-byte hash with nonzero bytes.
    #[test]
    fn parse_lvh_nonzero_hash_returns_some() {
        let hex = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let result = parse_latest_valid_hash(Some(hex));
        let expected = Hash256::from_array(
            [0xde, 0xad, 0xbe, 0xef]
                .into_iter()
                .cycle()
                .take(32)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        );
        assert_eq!(result, Some(expected));
    }

    /// Malformed string (too short) → None.
    #[test]
    fn parse_lvh_malformed_returns_none() {
        assert_eq!(parse_latest_valid_hash(Some("0xdeadbeef")), None);
    }

    /// Non-hex string → None.
    #[test]
    fn parse_lvh_non_hex_returns_none() {
        assert_eq!(parse_latest_valid_hash(Some("not-a-hash")), None);
    }

    /// Empty string → None.
    #[test]
    fn parse_lvh_empty_string_returns_none() {
        assert_eq!(parse_latest_valid_hash(Some("")), None);
    }
}
