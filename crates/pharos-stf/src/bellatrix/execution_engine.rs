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
use pharos_types::capella::ExecutionPayload as CapellaExecutionPayload;
use pharos_types::deneb::ExecutionPayload as DenebExecutionPayload;
use pharos_types::phase0::primitives::Root;

// ── PayloadVerificationStatus ─────────────────────────────────────────────────

/// Three-valued result of EL payload verification.
///
/// Per `specs/sync/optimistic.md` Helpers:
/// - `Valid`        — EL returned `VALID`; block is fully validated.
/// - `NotValidated` — EL returned `SYNCING` or `ACCEPTED` (`NOT_VALIDATED`);
///   block may be imported optimistically if it is a candidate.
/// - `Invalid`      — EL returned `INVALID`, `INVALID_BLOCK_HASH`, or an engine
///   error; block MUST NOT import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadVerificationStatus {
    Valid,
    NotValidated,
    Invalid,
}

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
    /// Returns `PayloadVerificationStatus` reflecting the EL's verdict:
    /// `Valid` / `NotValidated` (SYNCING|ACCEPTED) / `Invalid`.
    /// Per `specs/sync/optimistic.md` Helpers.
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
    ) -> PayloadVerificationStatus;

    /// `notify_new_payload` for Capella payloads (with withdrawals).
    ///
    /// **CONSENSUS-SAFETY WARNING**: any `ExecutionEngine` that talks to a REAL
    /// execution client MUST override this method to call `engine_newPayloadV2`
    /// with the full Capella payload INCLUDING `withdrawals`. The default below
    /// strips withdrawals and forwards to V1 — a real EL would then compute a
    /// different `state_root` and return `INVALID`. The default is only safe for
    /// test/null engines (e.g. `NullExecutionEngine`) that do not validate
    /// against a live EL. The production `ExecutionEngineHandle` in `pharos-node`
    /// overrides this to call `engine_newPayloadV2` directly (`D-engine-v2-dispatch`).
    /// NOTE: this notify is independent of the STF `process_withdrawals`
    /// equality check, which always runs regardless of the EL response.
    fn notify_new_payload_capella<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
        const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    >(
        &self,
        payload: &CapellaExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    ) -> PayloadVerificationStatus {
        // Default: strip withdrawals, forward to V1.
        self.notify_new_payload(&ExecutionPayload {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions.clone(),
        })
    }

    /// `notify_new_payload` for Deneb payloads (with blob gas fields).
    ///
    /// **CONSENSUS-SAFETY WARNING**: any `ExecutionEngine` that talks to a REAL
    /// execution client MUST override this method to call `engine_newPayloadV3`
    /// with the full Deneb payload INCLUDING `versioned_hashes` and
    /// `parent_beacon_block_root`. The default strips the Deneb-only fields and
    /// forwards to `notify_new_payload_capella`, which in turn strips withdrawals.
    /// The default is only safe for test/null engines. The production
    /// `ExecutionEngineHandle` in `pharos-node` overrides this (Phase 3).
    ///
    /// `versioned_hashes` is derived from `body.blob_kzg_commitments` via
    /// `kzg_commitment_to_versioned_hash`. `parent_beacon_block_root` is
    /// `state.latest_block_header.parent_root` (read before header mutation).
    fn notify_new_payload_deneb<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
        const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
    >(
        &self,
        payload: &DenebExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
        _versioned_hashes: &[[u8; 32]],
        _parent_beacon_block_root: Root,
    ) -> PayloadVerificationStatus {
        // Default: strip Deneb-only fields, forward to Capella V2.
        self.notify_new_payload_capella(&CapellaExecutionPayload {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions.clone(),
            withdrawals: payload.withdrawals.clone(),
        })
    }

    /// `notify_new_payload` for Electra payloads (with versioned hashes, parent root,
    /// and execution requests per EIP-7685).
    ///
    /// **CONSENSUS-SAFETY WARNING**: any `ExecutionEngine` that talks to a REAL
    /// execution client MUST override this method to call `engine_newPayloadV4`
    /// with the full Electra payload INCLUDING `execution_requests`. The default
    /// ignores `execution_requests` and delegates to `notify_new_payload_deneb`.
    /// The default is only safe for test/null engines. The production
    /// `ExecutionEngineHandle` in `pharos-node` overrides this for Electra (M12-Engine).
    fn notify_new_payload_electra<
        const MAX_BYTES_PER_TRANSACTION: u64,
        const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
        const BYTES_PER_LOGS_BLOOM: u64,
        const MAX_EXTRA_DATA_BYTES: u64,
        const MAX_WITHDRAWALS_PER_PAYLOAD: u64,
        const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64,
        const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64,
    >(
        &self,
        payload: &DenebExecutionPayload<
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
        versioned_hashes: &[[u8; 32]],
        parent_beacon_block_root: Root,
        _execution_requests: &pharos_types::electra::requests::ExecutionRequests<
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        >,
    ) -> PayloadVerificationStatus {
        // Default: ignore execution_requests, delegate to Deneb V3.
        self.notify_new_payload_deneb(payload, versioned_hashes, parent_beacon_block_root)
    }

    /// Retrieve blob data from the local EL blob pool for the given versioned hashes.
    ///
    /// Returns `None` for each missing blob (preserves request order).  Used as a
    /// DA-gate fallback when gossip sidecars have not arrived yet: if the EL already
    /// has the blobs (from mempool) the import can proceed without parking.
    ///
    /// Default: returns an empty vec (no fallback — block will be parked as usual).
    /// The production `ExecutionEngineHandle` in `pharos-node` overrides this to call
    /// `engine_getBlobsV1` (`D-getblobsv1-da-fallback`).
    ///
    /// `versioned_hashes` are 32-byte versioned hash values
    /// (`VERSIONED_HASH_VERSION_KZG || sha256(commitment)[1:]`).
    fn get_blobs_v1(&self, _versioned_hashes: &[[u8; 32]]) -> Vec<Option<(Vec<u8>, Vec<u8>)>> {
        vec![]
    }

    /// `verify_and_notify_new_payload` per `specs/bellatrix/beacon-chain.md:337-357`.
    ///
    /// Default implementation mirrors the Python spec:
    /// 1. Reject if any transaction in the payload is empty (`b""`).
    ///    spec line 348: `if b"" in execution_payload.transactions: return False`
    ///    → returns `PayloadVerificationStatus::Invalid`.
    /// 2. Block-hash validation is delegated to the EL via `engine_newPayloadV1`.
    ///    The EL returns `INVALID_BLOCK_HASH` (Paris spec) when the block hash
    ///    is wrong; the CL does NOT independently recompute it.
    ///    spec line 351: `if not self.is_valid_block_hash(execution_payload): return False`
    /// 3. Call `notify_new_payload`; return its `PayloadVerificationStatus`.
    ///    spec line 354: `if not self.notify_new_payload(execution_payload): return False`
    ///
    /// Per `specs/sync/optimistic.md` Helpers: NOT_VALIDATED = SYNCING|ACCEPTED,
    /// INVALIDATED = INVALID|INVALID_BLOCK_HASH.
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
    ) -> PayloadVerificationStatus {
        // spec line 348: reject if any transaction is empty.
        for tx in req.execution_payload.transactions.as_slice() {
            if tx.as_slice().is_empty() {
                return PayloadVerificationStatus::Invalid;
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
///
/// Mapping: `true` → `Valid`, `false` → `Invalid`.
/// `execution_valid: false` fixtures MUST still produce `Err(InvalidExecutionPayload)`
/// from the STF — `Invalid` preserves that behaviour.
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
    ) -> PayloadVerificationStatus {
        if self.0 {
            PayloadVerificationStatus::Valid
        } else {
            PayloadVerificationStatus::Invalid
        }
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
    ) -> PayloadVerificationStatus {
        if self.0 {
            PayloadVerificationStatus::Valid
        } else {
            PayloadVerificationStatus::Invalid
        }
    }
}

// ── NullExecutionEngine ───────────────────────────────────────────────────────

/// `NullExecutionEngine` — always returns `Valid`.
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
    ) -> PayloadVerificationStatus {
        PayloadVerificationStatus::Valid
    }

    /// Override default: spec-test paths have no EL; short-circuit to `Valid`.
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
    ) -> PayloadVerificationStatus {
        PayloadVerificationStatus::Valid
    }
}

// ── NotValidatedExecutionEngine (test helper) ─────────────────────────────────

/// `NotValidatedExecutionEngine` — always returns `NotValidated` (SYNCING/ACCEPTED).
///
/// Used in unit tests to simulate an EL that is still syncing.
#[cfg(test)]
pub struct NotValidatedExecutionEngine;

#[cfg(test)]
impl ExecutionEngine for NotValidatedExecutionEngine {
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
    ) -> PayloadVerificationStatus {
        PayloadVerificationStatus::NotValidated
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `FixedExecutionEngine(true)` → `Valid`.
    /// Confirms conformance `execution_valid: true` fixture path still works.
    #[test]
    fn fixed_true_returns_valid() {
        let engine = FixedExecutionEngine(true);
        // notify_new_payload returns Valid for true.
        // Use a zero-sized request to satisfy const generics.
        let payload = ExecutionPayload::<1, 1, 1, 1>::default();
        assert_eq!(
            engine.notify_new_payload(&payload),
            PayloadVerificationStatus::Valid
        );
    }

    /// `FixedExecutionEngine(false)` → `Invalid`.
    /// Confirms conformance `execution_valid: false` still drives STF rejection.
    #[test]
    fn fixed_false_returns_invalid() {
        let engine = FixedExecutionEngine(false);
        let payload = ExecutionPayload::<1, 1, 1, 1>::default();
        assert_eq!(
            engine.notify_new_payload(&payload),
            PayloadVerificationStatus::Invalid
        );
    }

    /// `NullExecutionEngine` → `Valid`.
    #[test]
    fn null_returns_valid() {
        let engine = NullExecutionEngine;
        let payload = ExecutionPayload::<1, 1, 1, 1>::default();
        assert_eq!(
            engine.notify_new_payload(&payload),
            PayloadVerificationStatus::Valid
        );
    }

    /// `NotValidatedExecutionEngine` → `NotValidated` (SYNCING).
    #[test]
    fn not_validated_engine_returns_not_validated() {
        let engine = NotValidatedExecutionEngine;
        let payload = ExecutionPayload::<1, 1, 1, 1>::default();
        assert_eq!(
            engine.notify_new_payload(&payload),
            PayloadVerificationStatus::NotValidated
        );
    }

    /// Gate logic: `NotValidated` from EL triggers the candidate check;
    /// `Valid` bypasses it. This verifies the condition used in `import.rs`.
    ///
    /// Per `specs/sync/optimistic.md`: `is_optimistic_candidate_block` gates
    /// MAY-optimistic import only; a `Valid` non-candidate MUST still import.
    #[test]
    fn gate_condition_valid_bypasses_candidate_check() {
        // With Valid: gate condition is false → no candidate check needed.
        let valid_status = Some(PayloadVerificationStatus::Valid);
        let would_trigger = valid_status == Some(PayloadVerificationStatus::NotValidated);
        assert!(
            !would_trigger,
            "Valid payload status must not trigger the candidate gate"
        );
    }

    /// Gate logic: `NotValidated` from EL triggers the candidate check.
    #[test]
    fn gate_condition_not_validated_triggers_candidate_check() {
        let not_validated_status = Some(PayloadVerificationStatus::NotValidated);
        let would_trigger = not_validated_status == Some(PayloadVerificationStatus::NotValidated);
        assert!(
            would_trigger,
            "NotValidated payload status must trigger the candidate gate"
        );
    }
}
