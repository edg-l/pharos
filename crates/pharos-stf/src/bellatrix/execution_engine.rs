//! `ExecutionEngine` trait for Bellatrix STF.
//!
//! Per `specs/bellatrix/beacon-chain.md:288-358`.
//!
//! The trait is sync-callable. The real impl (`ExecutionEngineHandle`, Phase 3)
//! wraps the async `EngineClient` by submitting the request onto the engine
//! actor's dedicated `Arc<tokio::runtime::Runtime>` via
//! `runtime.block_on(oneshot_rx)` on the caller thread. The STF caller MUST
//! itself run inside `tokio::task::spawn_blocking` (M3a invariant) so the call
//! thread is not a tokio worker.

use pharos_types::bellatrix::ExecutionPayload;

// ── NewPayloadRequest ─────────────────────────────────────────────────────────

/// `NewPayloadRequest` per `specs/bellatrix/beacon-chain.md:293-296`.
///
/// Wraps the execution payload to be validated by the EL.
pub struct NewPayloadRequest<
    'a,
    const MAX_BYTES_PER_TRANSACTION: u64,
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
> {
    /// `execution_payload` — the payload to verify and import.
    pub execution_payload: &'a ExecutionPayload<
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
}

// ── ExecutionEngine trait ─────────────────────────────────────────────────────

/// Sync-callable EL interface used by the Bellatrix STF.
///
/// Per `specs/bellatrix/beacon-chain.md:303-357`. The interface is sync because
/// the STF runs on a blocking thread (`spawn_blocking`); the real Phase-3 impl
/// bridges to async via a held `Arc<tokio::runtime::Runtime>` and
/// `runtime.block_on(reply_rx)` — NOT `block_in_place`.
pub trait ExecutionEngine: Send + Sync + 'static {
    /// `notify_new_payload` per `specs/bellatrix/beacon-chain.md:319-324`.
    ///
    /// Returns `true` iff the payload is valid with respect to the EL's
    /// execution state.
    fn notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        payload: &ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool;

    /// `verify_and_notify_new_payload` per `specs/bellatrix/beacon-chain.md:337-357`.
    ///
    /// Default implementation mirrors the Python spec:
    /// 1. Reject if any transaction in the payload is empty (`b""`).
    ///    spec line 348: `if b"" in execution_payload.transactions: return False`
    /// 2. Block-hash validation is delegated to the EL via `engine_newPayloadV1`.
    ///    The EL returns `INVALID_BLOCK_HASH` (Paris spec) when the block hash
    ///    is wrong; the CL does NOT independently recompute it.
    ///    spec line 351: `if not self.is_valid_block_hash(execution_payload): return False`
    /// 3. Call `notify_new_payload`; return its result.
    ///    spec line 354: `if not self.notify_new_payload(execution_payload): return False`
    fn verify_and_notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        req: NewPayloadRequest<
            '_,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool {
        // spec line 348: reject if any transaction is empty.
        for tx in req.execution_payload.transactions.as_slice() {
            if tx.as_slice().is_empty() {
                return false;
            }
        }

        // spec lines 351, 354: block-hash validation and payload import are both
        // delegated to the EL via engine_newPayloadV1. `notify_new_payload` covers
        // both checks (the EL returns INVALID_BLOCK_HASH when the hash is wrong).
        self.notify_new_payload(req.execution_payload)
    }
}

// ── FixedExecutionEngine ──────────────────────────────────────────────────────

/// `FixedExecutionEngine` — returns a fixed validity for all payload calls.
///
/// Used in conformance tests that supply an `execution_valid` flag via fixture
/// metadata (`execution.yaml`). Construct with `FixedExecutionEngine(true)` or
/// `FixedExecutionEngine(false)`.
pub struct FixedExecutionEngine(pub bool);

impl ExecutionEngine for FixedExecutionEngine {
    fn notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        _payload: &ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool {
        self.0
    }

    fn verify_and_notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        _req: NewPayloadRequest<
            '_,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool {
        self.0
    }
}

// ── NullExecutionEngine ───────────────────────────────────────────────────────

/// `NullExecutionEngine` — always returns `true`.
///
/// Used for spec-test conformance runs that have no EL counterpart.
pub struct NullExecutionEngine;

impl ExecutionEngine for NullExecutionEngine {
    fn notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        _payload: &ExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool {
        true
    }

    /// Override default: spec-test paths have no EL; short-circuit to `true`.
    fn verify_and_notify_new_payload<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
    >(
        &self,
        _req: NewPayloadRequest<
            '_,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> bool {
        true
    }
}
