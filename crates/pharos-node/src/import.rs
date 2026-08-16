//! Shared block-import core: pre-state fetch → STF → on_block → payload push → HeadChange.
//!
//! `import_block` is the canonical per-block import sequence used by both the
//! gossip ingestion loop (`block_ingestion.rs`) and the forward backfill driver
//! (`backfill.rs`).  It deliberately carries NO light-client dispatch or LC
//! gossip publish — those stay in the ingestion loop after this function returns,
//! so the AltairDispatchBounds / BellatrixDispatchBounds bounds do NOT appear here.
//!
//! Design note: `D-import-block-core-only` in `docs/m5-lookup-plan.md`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use thiserror::Error;
use tracing::warn;

use pharos_fork_choice::Store as FcStore;
use pharos_fork_choice::{
    PowBlockProvider, get_current_slot, get_head, is_optimistic_candidate_block, on_block,
    on_tick_per_slot,
};
use pharos_stf::{
    ExecutionEngine, PayloadVerificationStatus, StateTransitionError, state_transition,
};
use pharos_storage::{BlockTransition, RocksStore, StateSummary, StorageError, Store as DbStore};
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::KZGCommitment;
use pharos_types::views::{BeaconBlockView as _, BeaconStateView as _, ForkVariant};
use pharos_types::{EthSpec, PayloadStatus, phase0::primitives::Root};

use crate::data_availability::{DataAvailabilityChecker, DataAvailabilityVerdict};

use crate::engine_driver::{
    HeadChange, NewPayloadRequest, PayloadToWire, PayloadToWireV2, compute_finalized_block_hash,
    compute_safe_block_hash, hash_to_hex,
};

// ── ImportError ───────────────────────────────────────────────────────────────

/// Errors that can occur during the core block-import sequence.
///
/// Mirrors the corresponding variants from `IngestionError`; the ingestion
/// loop converts via `From<ImportError>`.
#[derive(Error, Debug)]
pub enum ImportError {
    /// Parent state not found in the fork-choice store.
    #[error("missing parent state for block")]
    MissingParentState,

    /// State transition failed.
    #[error("state transition failed: {0}")]
    StateTransition(#[from] StateTransitionError),

    /// Fork-choice `on_block` rejected the block.
    #[error("fork-choice on_block failed: {0}")]
    ForkChoice(#[from] pharos_fork_choice::ForkChoiceError),

    /// RocksDB / storage error.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// `spawn_blocking` join error (tokio thread pool failure).
    #[error("spawn_blocking join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// `get_head` returned a root not present in the block store — a fork-choice
    /// invariant violation. Surfaced as an error (block dropped / retried by the
    /// caller) rather than panicking the whole node on the hot import path.
    #[error("fork-choice head {root} not in block store (invariant violation)")]
    HeadMissing { root: Root },

    /// One or more blob sidecars required by a Deneb block are not yet available
    /// in the local store.  The block must be parked in `BlobAwaitingBlocks`
    /// until all sidecars arrive (per `D-da-block-not-in-forkchoice-until-available`).
    ///
    /// The block is NOT inserted into fork-choice when this error is returned
    /// (the gate fires before `state_transition` and `on_block`).
    #[error("blob sidecars not yet available for block (data not available)")]
    DataNotAvailable,

    /// Execution block rejected: not yet an optimistic-import candidate and EL
    /// validation is unavailable (SYNCING).  Caller should retry or defer.
    ///
    /// Per `D-optimistic-candidate-gates-import` and
    /// `consensus-specs/sync/optimistic.md` `is_optimistic_candidate_block`:
    /// a non-candidate execution block MUST NOT be imported optimistically;
    /// without a VALID verdict it must be rejected outright.
    #[error(
        "block slot {block_slot} not an optimistic candidate (current_slot={current_slot}); \
         parent execution status unknown — rejecting non-VALID execution block"
    )]
    NotOptimisticCandidate { block_slot: u64, current_slot: u64 },

    /// Block is already present in the fork-choice store (duplicate from
    /// lookup-sync or backfill re-fetch).  The caller should drop this block.
    #[error("block already imported: {root}")]
    AlreadyImported { root: Root },
}

// ── ImportOutcome ─────────────────────────────────────────────────────────────

/// Result of a successful `import_block` call.
#[allow(dead_code)]
pub struct ImportOutcome<E: EthSpec> {
    /// The new head after this block was applied to the fork-choice store.
    pub head_change: HeadChange,
    /// The block root (hash_tree_root of the message).
    pub block_root: Root,
    /// Fork variant of the post-state; used by the ingestion loop to gate
    /// light-client snapshot dispatch and LC gossip publishing.
    pub fork_variant: ForkVariant,
    /// Post-state after the STF.  Returned to the ingestion loop so it can
    /// perform light-client snapshot dispatch (which needs AltairDispatchBounds
    /// / BellatrixDispatchBounds — bounds the ingestion loop carries but
    /// import_block deliberately does not).
    pub post_state: E::BeaconState,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract `blob_kzg_commitments` from a fork-enum `SignedBeaconBlock`.
///
/// Called ONCE at the call site (per W6) before the DA gate so the
/// `DataAvailabilityChecker` impl receives a plain `&[KZGCommitment]` and does
/// no fork-dispatch.  Pre-Deneb blocks return an empty `Vec` (DA is Irrelevant).
///
/// Uses `BeaconBlockBodyView::blob_kzg_commitments_slice()` — a default-empty
/// method on the trait; the Deneb body overrides it to return the real slice.
pub(crate) fn extract_blob_kzg_commitments<E: EthSpec>(
    signed_block: &E::SignedBeaconBlock,
) -> Vec<KZGCommitment>
where
    E::DenebSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::DenebBeaconBlock: pharos_types::views::BeaconBlockView,
    <E::DenebBeaconBlock as pharos_types::views::BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView,
{
    use pharos_types::views::{
        BeaconBlockBodyView as _, BeaconBlockView as _, SignedBeaconBlockView as _,
    };
    if let Some(inner) = E::unwrap_deneb_signed_block(signed_block) {
        inner.message().body().blob_kzg_commitments_slice().to_vec()
    } else {
        Vec::new()
    }
}

/// Returns `true` if the signed block carries an active execution payload
/// (non-zero `block_hash`), matching the semantics of `block_is_execution_enabled`.
///
/// Uses per-fork borrowing accessors (`unwrap_bellatrix_signed_block` /
/// `unwrap_capella_signed_block`) so the entire inner block is never cloned —
/// only the 32-byte `block_hash` field is read. Bellatrix and Capella blocks
/// with a zeroed `block_hash` are pre-merge and return `false`.
fn signed_block_is_execution_enabled<E: EthSpec>(b: &E::SignedBeaconBlock) -> bool {
    use pharos_types::views::{
        BeaconBlockBodyView as _, BeaconBlockView as _, SignedBeaconBlockView as _,
    };
    if let Some(inner) = E::unwrap_bellatrix_signed_block(b) {
        inner
            .message()
            .body()
            .execution_block_hash()
            .is_some_and(|h| h != [0u8; 32])
    } else if let Some(inner) = E::unwrap_capella_signed_block(b) {
        inner
            .message()
            .body()
            .execution_block_hash()
            .is_some_and(|h| h != [0u8; 32])
    } else if let Some(inner) = E::unwrap_deneb_signed_block(b) {
        inner
            .message()
            .body()
            .execution_block_hash()
            .is_some_and(|h| h != [0u8; 32])
    } else {
        false
    }
}

/// Return the `slot` field of any fork variant of `SignedBeaconBlock`.
///
/// Covers phase0 / altair / bellatrix / capella / deneb in one place so
/// callers do not duplicate the five-arm match.
pub fn signed_block_slot<E: EthSpec>(
    b: &E::SignedBeaconBlock,
) -> pharos_types::phase0::primitives::Slot {
    use pharos_types::views::{BeaconBlockView as _, SignedBeaconBlockView as _};
    if let Some(inner) = E::unwrap_phase0_signed_block(b) {
        inner.message().slot()
    } else if let Some(inner) = E::unwrap_altair_signed_block(b) {
        inner.message().slot()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(b) {
        inner.message().slot()
    } else if let Some(inner) = E::unwrap_capella_signed_block(b) {
        inner.message().slot()
    } else if let Some(inner) = E::unwrap_deneb_signed_block(b) {
        inner.message().slot()
    } else {
        unreachable!("unknown fork variant in SignedBeaconBlock")
    }
}

/// STF-verified `state_root` of a fork-enum `SignedBeaconBlock`.
///
/// Mirrors [`signed_block_slot`]: no single trait-dispatch accessor covers all
/// variants, so each fork is unwrapped here in ONE place. Adding a new fork
/// requires extending this arm — keeping the per-fork unwrap out of `import_block`
/// so a call site can never silently miss a variant.
pub fn signed_block_state_root<E: EthSpec>(
    b: &E::SignedBeaconBlock,
) -> pharos_types::phase0::primitives::Root {
    use pharos_types::views::{BeaconBlockView as _, SignedBeaconBlockView as _};
    if let Some(inner) = E::unwrap_phase0_signed_block(b) {
        inner.message().state_root()
    } else if let Some(inner) = E::unwrap_altair_signed_block(b) {
        inner.message().state_root()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(b) {
        inner.message().state_root()
    } else if let Some(inner) = E::unwrap_capella_signed_block(b) {
        inner.message().state_root()
    } else if let Some(inner) = E::unwrap_deneb_signed_block(b) {
        inner.message().state_root()
    } else {
        unreachable!("unknown fork variant in SignedBeaconBlock")
    }
}

// ── import_block ──────────────────────────────────────────────────────────────

/// Core block-import sequence.
///
/// Executes: pre-state fetch → DA gate (spawn_blocking, RI-1) → STF
/// (same spawn_blocking) → on_block (spawn_blocking) → payload_tx push
/// (try_send, drop-on-full) → head computation → persist worker
/// (spawn_blocking, after write lock released).
///
/// **DA gate ordering (RI-1)**: `da_checker.is_data_available` runs INSIDE
/// the STF `spawn_blocking`, BEFORE `state_transition`.  This satisfies the
/// `fork-choice.md on_block` requirement that `is_data_available` precedes
/// `state_transition`.  A `DataNotAvailable` result causes an early return;
/// no fork-choice write has occurred (per `D-da-block-not-in-forkchoice-until-available`).
///
/// **Does NOT** perform light-client snapshot dispatch or LC gossip publish.
/// Those steps require `AltairDispatchBounds` / `BellatrixDispatchBounds` and
/// must remain in the callers that carry those bounds.
///
/// `validate_result` is forwarded to `state_transition`. Set `false` in tests
/// where blocks are produced without valid BLS signatures.
///
/// `store` is a concrete `&Arc<RocksStore>` (not a generic `S: Store<E>`) so no
/// new where-bound explodes across call sites; `RocksStore` is the only `Store`
/// impl wired in the binary (per `D-persist-in-import-core`).
///
/// `da_checker` is the DA gate; pass `&NoopDataAvailabilityChecker` in backfill
/// (historical blocks do not carry sidecars) and in pre-Deneb contexts.
#[allow(clippy::too_many_arguments)]
pub async fn import_block<E, EE, PP, DA>(
    signed_block: &E::SignedBeaconBlock,
    fc_store: &Arc<RwLock<FcStore<E>>>,
    execution_engine: &Arc<EE>,
    pow_provider: &Arc<PP>,
    payload_tx: &tokio::sync::mpsc::Sender<NewPayloadRequest<E>>,
    validate_result: bool,
    cfg: &RuntimeConfig,
    store: &Arc<RocksStore>,
    da_checker: &Arc<DA>,
) -> Result<ImportOutcome<E>, ImportError>
where
    DA: DataAvailabilityChecker<E> + 'static,
    E: EthSpec,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::Phase0BeaconBlock:
        pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, EE>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, EE>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, EE>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
    E::DenebExecutionPayload: Into<pharos_engine::ExecutionPayloadV3>,
    E::DenebSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    <E::DenebSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <<E::DenebSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message as pharos_types::views::BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView,
    EE: ExecutionEngine + 'static,
    PP: PowBlockProvider + Send + Sync + 'static,
{
    use crate::block_ingestion::{extract_block_root, extract_parent_root};

    // (a) Fetch pre_state from the fork-choice store.
    let parent_root = extract_parent_root::<E>(signed_block);
    let pre_state = {
        let store_read = fc_store.read();
        match store_read.block_states.get(&parent_root).cloned() {
            Some(s) => s,
            None => return Err(ImportError::MissingParentState),
        }
    };

    // (a.5) Extract blob KZG commitments from the block body ONCE (per W6).
    //
    // Pre-Deneb blocks return an empty Vec (DA is Irrelevant for them).
    // Deneb blocks return the commitments from `blob_kzg_commitments`.
    // This extraction happens at the call site so `da_checker` receives a plain
    // `&[KZGCommitment]` and does no fork-dispatch (Fulu PeerDAS seam).
    //
    // `kzg_commitments_for_closure` is moved into the spawn_blocking closure (DA gate +
    // EL fallback).  `kzg_commitments` (re-bound below) is kept outside for the
    // payload push that follows the closure.
    let kzg_commitments = extract_blob_kzg_commitments::<E>(signed_block);
    let kzg_commitments_for_closure = kzg_commitments.clone();

    // (b) Run DA gate + state transition in spawn_blocking (both CPU/IO-bound; RI-1 + W7).
    //
    // DA gate is MERGED INTO the STF spawn_blocking: RocksDB reads and KZG verification
    // are blocking operations; running them in the same worker as the STF avoids an
    // extra `await` and keeps the critical path tight (W7).
    //
    // Gate ordering (RI-1): DA check fires BEFORE `state_transition`.  If the check
    // returns `NotAvailable`, this spawn returns `Err(ImportError::DataNotAvailable)`
    // without touching fork-choice (no `on_block` call, no state write).  The block
    // is NOT in fork-choice until DA is satisfied
    // (per `D-da-block-not-in-forkchoice-until-available`).
    let signed_block_clone = signed_block.clone();
    let ee = Arc::clone(execution_engine);
    let cfg_clone = cfg.clone();
    let da_checker_clone = Arc::clone(da_checker);
    let block_root_for_da = extract_block_root::<E>(signed_block);
    let store_for_da = Arc::clone(store);
    // (a.6) Duplicate import guard: if the block root is already in the
    // fork-choice store, reject immediately without touching the STF.
    // This prevents re-processing blocks that lookup-sync or backfill may
    // re-fetch after they've already been imported via gossip.
    {
        let store_read = fc_store.read();
        if store_read.blocks.contains_key(&block_root_for_da) {
            return Err(ImportError::AlreadyImported {
                root: block_root_for_da,
            });
        }
    }
    let stf_result: Result<_, ImportError> = tokio::task::spawn_blocking(move || {
        let kzg_commitments = kzg_commitments_for_closure;
        // Step (a.5) inner: DA gate — BEFORE state_transition (RI-1).
        let verdict = da_checker_clone.is_data_available(block_root_for_da, &kzg_commitments);
        match verdict {
            DataAvailabilityVerdict::Available | DataAvailabilityVerdict::Irrelevant => {}
            DataAvailabilityVerdict::NotAvailable => {
                // DA-gate fallback (D-getblobsv1-da-fallback): if the local EL
                // already has the blobs in its blob pool (e.g. from mempool), fetch
                // them via engine_getBlobsV1, persist to the store, and proceed
                // without parking the block.  This allows blocks from self-produced
                // or recently-broadcast transactions to import immediately without
                // waiting on gossip sidecars.
                //
                // Versioned hashes are computed from `kzg_commitments`.
                use pharos_kzg::kzg_commitment_to_versioned_hash;
                use pharos_ssz::SszVector;
                use pharos_types::deneb::BlobSidecar;
                use pharos_utils::FixedBytes;
                let versioned_hashes: Vec<[u8; 32]> = kzg_commitments
                    .iter()
                    .map(|c| kzg_commitment_to_versioned_hash(&c.into_inner()))
                    .collect();
                let el_blobs = ee.get_blobs_v1(&versioned_hashes);
                // Only proceed if the EL returned a non-empty answer with ALL blobs present.
                let el_satisfied = !el_blobs.is_empty()
                    && el_blobs.len() == kzg_commitments.len()
                    && el_blobs.iter().all(Option::is_some);
                if el_satisfied {
                    // Persist the EL-supplied blobs so the DA checker will find
                    // them and the re-imported block can pass.  We persist with
                    // index = position in the versioned-hash list.
                    for (index, (blob_and_proof, commitment)) in
                        el_blobs.into_iter().zip(kzg_commitments.iter()).enumerate()
                    {
                        if let Some((blob_bytes, proof_bytes)) = blob_and_proof {
                            // Build a minimal BlobSidecar sufficient for storage.
                            // signed_block_header and inclusion proof left as zero-defaults;
                            // the store key is block_root + index, not the header.
                            let blob_vec: Vec<u8> = if blob_bytes.len() == 131072 {
                                blob_bytes
                            } else {
                                continue;
                            };
                            let Ok(blob) = SszVector::from_vec(blob_vec) else {
                                continue;
                            };
                            let proof_arr: [u8; 48] = if proof_bytes.len() == 48 {
                                let mut arr = [0u8; 48];
                                arr.copy_from_slice(&proof_bytes);
                                arr
                            } else {
                                continue;
                            };
                            let sidecar = BlobSidecar {
                                index: index as u64,
                                blob,
                                kzg_commitment: *commitment,
                                kzg_proof: FixedBytes::from_array(proof_arr),
                                ..BlobSidecar::default()
                            };
                            let _ = <RocksStore as DbStore<E>>::put_blob_sidecar(
                                &store_for_da,
                                block_root_for_da,
                                index as u64,
                                &sidecar,
                            );
                        }
                    }
                    // Re-check DA after persisting. If all blobs are now present and
                    // KZG-verified, proceed; otherwise fall through to NotAvailable.
                    let verdict2 =
                        da_checker_clone.is_data_available(block_root_for_da, &kzg_commitments);
                    if verdict2 == DataAvailabilityVerdict::NotAvailable {
                        return Err(ImportError::DataNotAvailable);
                    }
                    // DA satisfied via EL fallback — proceed to STF below.
                } else {
                    return Err(ImportError::DataNotAvailable);
                }
            }
        }

        // DA gate passed (or Irrelevant for pre-Deneb). Run the STF.
        state_transition::<E, EE>(
            pre_state,
            &signed_block_clone,
            &ee,
            validate_result,
            &cfg_clone,
        )
        .map_err(ImportError::StateTransition)
    })
    .await?;

    let (post_state, payload_status) = stf_result?;

    // (c) Optimistic-candidate gate — AFTER the STF so the real EL verdict is known.
    //
    // Per `specs/sync/optimistic.md` `is_optimistic_candidate_block`: the gate
    // permits MAY-optimistic import only. A block with EL verdict `Valid` MUST
    // still import regardless of candidacy. Only a `NotValidated` (SYNCING/ACCEPTED)
    // non-candidate block is rejected here.
    //
    // Sequence:
    // - `Valid`         → always import (no gate needed).
    // - `None` (pre-merge) → always import.
    // - `NotValidated` + candidate → import optimistically.
    // - `NotValidated` + NOT candidate + block_slot <= current_slot → REJECT.
    // - `NotValidated` + block_slot > current_slot → bypass (future-block hold path).
    // - `Invalid` → already rejected by the STF (InvalidExecutionPayload).
    //
    // Per `D-optimistic-candidate-gates-import` (M8 Phase 3b).
    if payload_status == Some(PayloadVerificationStatus::NotValidated) {
        let block_slot: u64 = signed_block_slot::<E>(signed_block).0;

        let (current_slot, candidate) = {
            let store_read = fc_store.read();
            let cs = get_current_slot::<E>(&store_read).0;
            let cand = is_optimistic_candidate_block::<E>(&store_read, cs, parent_root, block_slot);
            (cs, cand)
        };

        // Future blocks (block_slot > current_slot) bypass this gate: they have
        // not yet reached their slot so candidacy is meaningless. on_block handles
        // them via the future-slot hold path.
        if block_slot <= current_slot && !candidate {
            return Err(ImportError::NotOptimisticCandidate {
                block_slot,
                current_slot,
            });
        }
    }

    // Capture fork variant now that we have the post-state.
    let fork_variant = post_state.fork_variant();

    // Clone post_state for return to the caller (ingestion loop uses it for
    // light-client snapshot dispatch, which needs AltairDispatchBounds /
    // BellatrixDispatchBounds that import_block deliberately does not carry).
    // Also used by the persist worker below (after on_block has moved post_state).
    let post_state_for_return = post_state.clone();

    // (d) block_root was already computed above for the DA gate; reuse it.
    let block_root: Root = block_root_for_da;

    // (e) Call on_block in spawn_blocking (may do blocking PoW lookup; M3a invariant).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let fc_clone = Arc::clone(fc_store);
    let block_for_on_block = signed_block.clone();
    let pow_clone = Arc::clone(pow_provider);

    let on_block_result = tokio::task::spawn_blocking(move || {
        let mut store = fc_clone.write();
        // Advance the fork-choice clock to wall-now before on_block's future-slot
        // guard runs. The background 1s on_tick driver fires at an arbitrary
        // sub-second phase and floors to whole seconds, so right after a slot
        // boundary `store.time` can still report the previous slot — which would
        // spuriously reject a just-proposed block as FutureSlot.
        //
        // Advance-only and single-step, deliberately NOT the catch-up `on_tick`:
        //  - never regress the cursor (a caller or the background ticker may have
        //    set `store.time` further ahead; on_tick_per_slot's `store.time =
        //    time` would otherwise move it backwards),
        //  - O(1): `on_tick`'s slot-by-slot catch-up loop would iterate once per
        //    elapsed slot, which explodes against a mock `genesis_time = 0`.
        // The background `on_tick` remains the primary clock driver; this is only
        // a sub-slot freshness nudge. on_block's `get_current_slot >= block.slot`
        // assert is untouched.
        if now > store.time {
            on_tick_per_slot::<E>(&mut store, now);
        }
        on_block::<E, PP>(&mut store, &block_for_on_block, post_state, now, &pow_clone)
    })
    .await?;

    on_block_result.map_err(ImportError::ForkChoice)?;
    // The fork-choice WRITE guard is now dropped (on_block_result consumed it).

    // (f) For execution-layer blocks, push the execution payload to the engine driver.
    // Deneb blocks use engine_newPayloadV3 (with blob gas + versioned hashes);
    // Capella blocks use engine_newPayloadV2 (with withdrawals); Bellatrix uses V1.
    // Per `D-engine-v2-dispatch` (docs/decisions.md M6-Capella section).
    if let Some(deneb_payload) = E::get_deneb_execution_payload(signed_block) {
        // Deneb block: V3 wire format (includes blobGasUsed, excessBlobGas).
        // Derive versioned hashes from the blob KZG commitments (already extracted for DA gate).
        use pharos_engine::{ExecutionPayloadV3, NewPayloadWire};
        use pharos_kzg::kzg_commitment_to_versioned_hash;
        let vh_hex: Vec<String> = kzg_commitments
            .iter()
            .map(|c| {
                let h = kzg_commitment_to_versioned_hash(&c.into_inner());
                crate::engine_driver::hash_to_hex(pharos_utils::Hash256::from_array(h))
            })
            .collect();
        // parent_beacon_block_root = block.parent_root (the CL parent, NOT the EL parent).
        let pbbr_hex = crate::engine_driver::hash_to_hex(parent_root);
        let wire: ExecutionPayloadV3 = deneb_payload.into();
        let req = NewPayloadRequest {
            block_root,
            payload: NewPayloadWire::V3 {
                payload: wire,
                versioned_hashes: vh_hex,
                parent_beacon_block_root: pbbr_hex,
            },
            _marker: std::marker::PhantomData,
        };
        if payload_tx.try_send(req).is_err() {
            warn!(%block_root, "import_block: payload_tx full or closed; dropping newPayloadV3");
        }
    } else if let Some(capella_payload) = E::get_capella_execution_payload(signed_block) {
        // Capella block: V2 wire format (includes withdrawals).
        use pharos_engine::NewPayloadWire;
        let req = NewPayloadRequest {
            block_root,
            payload: NewPayloadWire::V2(capella_payload.to_execution_payload_v2()),
            _marker: std::marker::PhantomData,
        };
        if payload_tx.try_send(req).is_err() {
            warn!(%block_root, "import_block: payload_tx full or closed; dropping newPayloadV2");
        }
    } else if let Some(payload) = E::get_execution_payload(signed_block) {
        // Bellatrix block: V1 wire format.
        use pharos_engine::NewPayloadWire;
        let req = NewPayloadRequest {
            block_root,
            payload: NewPayloadWire::V1(payload.to_execution_payload_v1()),
            _marker: std::marker::PhantomData,
        };
        if payload_tx.try_send(req).is_err() {
            warn!(%block_root, "import_block: payload_tx full or closed; dropping newPayload");
        }
    }

    // (g) Compute new head and build HeadChange under a SINGLE read guard so
    // the head-root selection and its block-hash lookup are consistent (avoids
    // a TOCTOU window where a concurrent write could change head between reads).
    let head_change = {
        use pharos_types::views::BeaconBlockView as _;
        let store = fc_store.read();
        let head_root = get_head::<E>(&store);
        let safe_hash = compute_safe_block_hash::<E>(&store);
        let finalized_hash = compute_finalized_block_hash::<E>(&store);
        let head_block = match store.blocks.get(&head_root) {
            Some(b) => b,
            None => return Err(ImportError::HeadMissing { root: head_root }),
        };
        let head_slot = head_block.slot();
        let head_block_hash =
            hash_to_hex(E::get_execution_block_hash(head_block).unwrap_or_default());
        HeadChange {
            head_root,
            head_slot,
            head_block_hash,
            safe_block_hash: hash_to_hex(safe_hash),
            finalized_block_hash: hash_to_hex(finalized_hash),
        }
    };

    // (h) Persist worker — runs AFTER on_block has dropped the WRITE guard.
    //
    // Per `D-persist-in-import-core`: the DB write is in a SEPARATE
    // `spawn_blocking` worker that takes only `fc.read()` (write guard is already
    // dropped). This means the disk write never blocks fork-choice readers
    // (get_head / gossip validators / API / SSE). The worker is `.await`-ed to
    // completion before `import_block` returns its `ImportOutcome`, so no head
    // is ever published referencing an unpersisted block.
    //
    // The batch ALWAYS carries `forkchoice = Some(snapshot)` so a restart after
    // live imports rehydrates from a fresh cursor, not the stale checkpoint-sync
    // snapshot (WARNING-5 fix from the plan).
    {
        let fc_snap = Arc::clone(fc_store);
        let store_persist = Arc::clone(store);
        let signed_block_persist = signed_block.clone();
        let post_state_persist = post_state_for_return.clone();
        let head_root_for_persist = head_change.head_root;

        // Determine whether this block carries a live execution payload so the
        // persist worker can pre-seed `payload_statuses[block_root] = NotValidated`.
        // Per `D-preseed-notvalidated-on-import` (M8 Phase 1): every execution-
        // carrying block must have an entry from import time; the async engine
        // driver later overwrites with Valid / Invalid.
        //
        // Uses borrowing accessors rather than `E::signed_block_message` (which
        // clones the entire inner block) to avoid a ~dozen-KB clone on every import.
        let is_execution_block = signed_block_is_execution_enabled::<E>(signed_block);

        // Capture the fields needed from the block before moving into the closure.
        // `E::SignedBeaconBlock` is a fork-enum: use per-fork helpers rather than
        // the trait-dispatch `.message()` which panics for the enum variant.
        let block_parent_root = parent_root; // already computed above via extract_parent_root
        // Derive slot and state_root from the block.  `state_root` is the
        // STF-verified field (cheaper than re-merkleizing the post-state).
        // Both go through fork-exhaustive helpers so a call site can never miss
        // a variant (no single trait-dispatch accessor covers all forks).
        let block_slot = signed_block_slot::<E>(signed_block);
        let block_state_root = signed_block_state_root::<E>(signed_block);

        let persist_result = tokio::task::spawn_blocking(move || {
            // Pre-seed `payload_statuses[block_root] = NotValidated` for execution
            // blocks BEFORE the read-lock snapshot, using a brief write lock.
            //
            // Invariant: every execution-carrying block has a `payload_statuses`
            // entry from import time. The async engine driver later overwrites with
            // Valid / Invalid. `mark_payload_status_if_absent` uses
            // `entry().or_insert()` semantics so it NEVER overwrites a Valid /
            // Invalid verdict the driver may have already set (the driver can race
            // ahead of this worker on a fast EL).
            //
            // The write lock is acquired and released BEFORE all I/O so it is never
            // held across a disk write. Per `D-preseed-notvalidated-on-import` (M8).
            if is_execution_block {
                fc_snap
                    .write()
                    .mark_payload_status_if_absent(block_root, PayloadStatus::NotValidated);
            }

            // Take only a READ guard for the snapshot and batch build (write guard
            // dropped after on_block, and the brief pre-seed write lock above is
            // also already dropped).
            let fc = fc_snap.read();

            // Snapshot fork-choice cursors so a restart rehydrates from the
            // freshest state (not the stale checkpoint-sync snapshot).
            let head_slot_for_snap = fc
                .blocks
                .get(&head_root_for_persist)
                .map(|b| b.slot())
                .unwrap_or(block_slot);
            let snapshot = pharos_storage::ForkChoiceSnapshot {
                justified_checkpoint: fc.justified_checkpoint.clone(),
                finalized_checkpoint: fc.finalized_checkpoint.clone(),
                unrealized_justified_checkpoint: fc.unrealized_justified_checkpoint.clone(),
                unrealized_finalized_checkpoint: fc.unrealized_finalized_checkpoint.clone(),
                proposer_boost_root: fc.proposer_boost_root,
                last_known_time: fc.time,
                genesis_time: fc.genesis_time,
                head_root: head_root_for_persist,
                head_slot: head_slot_for_snap,
            };

            let mut batch = BlockTransition::<E>::new();
            batch.block = Some((block_root, signed_block_persist));
            batch.slot_index = Some((block_slot, block_root));
            batch.forkchoice = Some(snapshot);
            batch.state_summary = Some((
                block_root,
                StateSummary {
                    slot: block_slot,
                    state_root: block_state_root,
                    parent_root: block_parent_root,
                },
            ));

            // Persist the pre-seeded NotValidated status to the `payload-status` CF
            // so a restart rehydrates NotValidated for blocks whose EL verdict has
            // not yet been received. Per `D-preseed-notvalidated-on-import` (M8 Phase 1).
            //
            // Guarded: skip the write if the engine driver has already persisted a
            // Valid or Invalid verdict in the in-memory map. The driver can race
            // ahead of this persist worker on a fast EL; overwriting Valid/Invalid
            // with NotValidated on disk would corrupt the restart verdict. Using the
            // read guard `fc` already held above avoids a second lock acquisition.
            if is_execution_block {
                let already_decided = fc
                    .payload_statuses
                    .get(&block_root)
                    .is_some_and(|s| matches!(s, PayloadStatus::Valid | PayloadStatus::Invalid));
                if !already_decided {
                    batch.payload_status = Some((block_root, PayloadStatus::NotValidated));
                }
            }

            // Write epoch-boundary full state only when slot % SLOTS_PER_EPOCH == 0.
            // This bounds the per-epoch state-write cost to one full-state encode
            // per `D-epoch-boundary-state-cadence`.
            if block_slot.0 % E::SLOTS_PER_EPOCH == 0 {
                batch.state = Some((block_state_root, post_state_persist));
            }

            // Write `head_state_root` metadata ONLY when the imported block became
            // the new head. On a non-head (competing-fork) import, `head_root` still
            // points at the prior head, so writing this block's state-root here would
            // desync the pointer from `forkchoice.head_root` and corrupt warm-restart.
            if head_root_for_persist == block_root {
                batch
                    .metadata
                    .push((b"head_state_root", block_state_root.as_slice().to_vec()));
            }

            <RocksStore as DbStore<E>>::write_block_transition(&*store_persist, batch)
        })
        .await?;

        if let Err(e) = persist_result {
            warn!(
                %block_root,
                error = %e,
                "import_block: persist worker failed; block is in fork-choice RAM but not on disk"
            );
            return Err(ImportError::Storage(e));
        }
    }

    Ok(ImportOutcome {
        head_change,
        block_root,
        fork_variant,
        post_state: post_state_for_return,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Gate integration tests for `import_block`.
    //!
    //! These tests exercise the optimistic-candidate gate at the `import_block`
    //! seam — the lowest synchronous decision point where a real
    //! `PayloadVerificationStatus` from the EE flows into the gate logic.
    //!
    //! Scenario: Bellatrix genesis anchor (zeroed `block_hash`, NOT execution-
    //! enabled) + a Bellatrix block at slot 1 with a non-zero `block_hash`
    //! (execution-enabled).  With `fc_store.time = 6` (6-second minimal-preset
    //! slots, `genesis_time = 0`) the store's `current_slot = 1`, so:
    //!   - Branch 1 of `is_optimistic_candidate_block`: parent block_hash == 0 →
    //!     NOT execution-enabled → false
    //!   - Branch 2: `block_slot + 128 = 129 > current_slot = 1` → false
    //!
    //! So the block is NOT an optimistic candidate.
    //!
    //! Test (a): EE returns `NotValidated` (SYNCING) → gate fires →
    //!   `Err(ImportError::NotOptimisticCandidate)`.
    //! Test (b): EE returns `Valid` → gate does not fire (status ≠ NotValidated) →
    //!   import succeeds with `Ok(ImportOutcome)`.
    //!
    //! Per `D-optimistic-candidate-gates-import` (M8 Phase 3b).

    use std::sync::Arc;

    use parking_lot::RwLock;
    use pharos_fork_choice::get_forkchoice_store;
    use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
    use pharos_stf::bellatrix::execution_engine::NewPayloadRequest;
    use pharos_stf::{ExecutionEngine, NullExecutionEngine, PayloadVerificationStatus};
    use pharos_storage::{RocksStore, RocksStoreConfig};
    use pharos_types::altair::MinimalSyncCommittee;
    use pharos_types::bellatrix::{
        MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
        execution_payload::MinimalExecutionPayload,
    };
    use pharos_types::phase0::misc::{Fork, Validator};
    use pharos_types::phase0::operations::BeaconBlockHeader;
    use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
    use pharos_types::state::{
        MinimalBeaconState as ForkMinimalBeaconState, SignedBeaconBlock as ForkSignedBeaconBlock,
    };
    use pharos_types::{EthSpec, MinimalEthSpec};
    use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
    use tokio::sync::mpsc;

    use super::*;
    use crate::data_availability::NoopDataAvailabilityChecker;
    use crate::engine_driver::NewPayloadRequest as EngineNewPayloadRequest;

    // ── Terminal hash used in both tests ──────────────────────────────────────

    const TERMINAL_HASH: [u8; 32] = [0xAA_u8; 32];

    // ── Mock EEs ──────────────────────────────────────────────────────────────

    /// Always returns `NotValidated` (SYNCING/ACCEPTED).
    struct SyncingEE;

    impl ExecutionEngine for SyncingEE {
        fn notify_new_payload<
            const MAX_BYTES_PER_TRANSACTION: u64,
            const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
            const BYTES_PER_LOGS_BLOOM: u64,
            const MAX_EXTRA_DATA_BYTES: u64,
        >(
            &self,
            _payload: &pharos_types::bellatrix::ExecutionPayload<
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        ) -> PayloadVerificationStatus {
            PayloadVerificationStatus::NotValidated
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
            PayloadVerificationStatus::NotValidated
        }
    }

    /// Always returns `Valid`.
    struct ValidEE;

    impl ExecutionEngine for ValidEE {
        fn notify_new_payload<
            const MAX_BYTES_PER_TRANSACTION: u64,
            const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
            const BYTES_PER_LOGS_BLOOM: u64,
            const MAX_EXTRA_DATA_BYTES: u64,
        >(
            &self,
            _payload: &pharos_types::bellatrix::ExecutionPayload<
                MAX_BYTES_PER_TRANSACTION,
                MAX_TRANSACTIONS_PER_PAYLOAD,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
        ) -> PayloadVerificationStatus {
            PayloadVerificationStatus::Valid
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
            PayloadVerificationStatus::Valid
        }
    }

    // ── Fixture builder ───────────────────────────────────────────────────────

    /// Minimal BLS pubkey: deterministically derived but non-zero.
    fn test_pubkey() -> BLSPubkey {
        use blst::min_pk::SecretKey;
        BLSPubkey::from_array(
            SecretKey::key_gen(&[1u8; 32], &[])
                .unwrap()
                .sk_to_pk()
                .compress(),
        )
    }

    /// Build a Bellatrix anchor state at slot 0 (`genesis_time = 0`) with a
    /// zeroed `block_hash` (NOT execution-enabled), plus the matching signed
    /// anchor block.
    fn build_anchor() -> (
        ForkMinimalBeaconState,
        ForkSignedBeaconBlock<
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
            8192,
            4,
            8192,
            16,
            2,
        >,
    ) {
        let anchor_body = MinimalBeaconBlockBody::default();
        let anchor_body_root: Root = anchor_body.tree_hash_root();

        let validator = Validator {
            pubkey: test_pubkey(),
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            slashed: false,
            ..Validator::default()
        };

        let sync_committee = MinimalSyncCommittee {
            pubkeys: SszVector::from_vec(vec![
                test_pubkey();
                MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize
            ])
            .unwrap(),
            aggregate_pubkey: test_pubkey(),
        };

        let state_inner = MinimalBeaconState {
            genesis_time: 0,
            slot: Slot(0),
            fork: Fork {
                previous_version: Version::from_array([0x01, 0x00, 0x00, 0x01]),
                current_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
                epoch: Epoch(0),
            },
            latest_block_header: BeaconBlockHeader {
                slot: Slot(0),
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: anchor_body_root,
            },
            validators: SszList::empty_tree().with_push(validator).unwrap(),
            balances: SszList::with_push(
                &SszList::default(),
                Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            )
            .unwrap(),
            previous_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
            current_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
            inactivity_scores: SszList::with_push(&SszList::default(), 0u64).unwrap(),
            current_sync_committee: sync_committee.clone(),
            next_sync_committee: sync_committee,
            ..MinimalBeaconState::default()
        };

        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let state_root: Root = fork_state.tree_hash_root();

        let anchor_block_inner = MinimalBeaconBlock {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: anchor_body,
        };
        // Anchor block root (tree_hash_root of the inner block).
        let signed_anchor: ForkSignedBeaconBlock<
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
            8192,
            4,
            8192,
            16,
            2,
        > = ForkSignedBeaconBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: anchor_block_inner,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        (fork_state, signed_anchor)
    }

    /// Build a Bellatrix execution block at `slot = 1` whose parent is the
    /// anchor (zeroed block_hash, NOT execution-enabled).
    ///
    /// The block carries a non-zero `block_hash` so it IS execution-enabled.
    /// Its `payload.parent_hash = TERMINAL_HASH` so the fork-choice merge-
    /// transition guard (TERMINAL_BLOCK_HASH override mode) passes.
    ///
    /// Returns `(signed_block, anchor_root)`.
    fn build_execution_block<EE: ExecutionEngine + 'static>(
        genesis_state: ForkMinimalBeaconState,
        anchor_root: Root,
        ee: &EE,
    ) -> ForkSignedBeaconBlock<
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
        8192,
        4,
        8192,
        16,
        2,
    > {
        use pharos_stf::state_transition;

        let runtime_cfg = pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: 0, // Bellatrix from genesis
            altair_fork_epoch: 0,    // Altair from genesis
            ..Default::default()
        };

        // `timestamp` must equal `genesis_time + slot * seconds_per_slot` per spec line 394.
        // With genesis_time = 0, slot = 1, seconds_per_slot = 6: timestamp = 6.
        // `prev_randao` must equal `randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR]`.
        // The default anchor state has all-zero randao_mixes, so prev_randao = default.
        let payload = MinimalExecutionPayload {
            parent_hash: Hash256::from_array(TERMINAL_HASH),
            block_number: 1,
            gas_limit: 0x1c9c380,
            timestamp: 6, // genesis_time=0 + slot=1 * seconds_per_slot=6
            block_hash: Hash256::from_array([0x01u8; 32]),
            ..Default::default()
        };

        // Step 1: draft pass (state_root = default) to get post-state.
        let draft = MinimalBeaconBlock {
            slot: Slot(1),
            proposer_index: ValidatorIndex(0),
            parent_root: anchor_root,
            state_root: Root::default(),
            body: MinimalBeaconBlockBody {
                execution_payload: payload.clone(),
                ..Default::default()
            },
        };
        let draft_signed: ForkSignedBeaconBlock<
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
            8192,
            4,
            8192,
            16,
            2,
        > = ForkSignedBeaconBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: draft,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        let (post_state, _) = state_transition::<MinimalEthSpec, EE>(
            genesis_state,
            &draft_signed,
            ee,
            false,
            &runtime_cfg,
        )
        .expect("draft STF must succeed");

        let state_root: Root = post_state.tree_hash_root();

        // Step 2: final block with correct state_root.
        let final_block = MinimalBeaconBlock {
            slot: Slot(1),
            proposer_index: ValidatorIndex(0),
            parent_root: anchor_root,
            state_root,
            body: MinimalBeaconBlockBody {
                execution_payload: payload,
                ..Default::default()
            },
        };
        ForkSignedBeaconBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: final_block,
            signature: BLSSignature::from_array([0u8; 96]),
        })
    }

    // ── Shared test scaffolding ───────────────────────────────────────────────

    /// Scaffold shared by both gate tests:
    /// - RocksStore at a tempdir
    /// - fc_store with Bellatrix anchor (zeroed block_hash, NOT execution-enabled)
    /// - `fc_store.time = 6` → `current_slot = 1` (MinimalEthSpec: 6-second slots)
    /// - Terminal-block-hash override so the merge-transition guard passes
    fn build_scaffold(
        tmpdir: &tempfile::TempDir,
    ) -> (
        Arc<RwLock<pharos_fork_choice::Store<MinimalEthSpec>>>,
        Root,
        Arc<RocksStore>,
    ) {
        let store = Arc::new(
            RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
                path: tmpdir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("RocksStore::open"),
        );

        let (genesis_state, signed_anchor) = build_anchor();
        let anchor_root: Root = match &signed_anchor {
            ForkSignedBeaconBlock::Bellatrix(inner) => inner.message.tree_hash_root(),
            _ => unreachable!("anchor is always Bellatrix"),
        };
        let anchor_block = match signed_anchor {
            ForkSignedBeaconBlock::Bellatrix(inner) => {
                pharos_types::state::MinimalBeaconBlock::Bellatrix(inner.message)
            }
            _ => unreachable!("anchor is always Bellatrix"),
        };

        let mut fc = get_forkchoice_store::<MinimalEthSpec>(genesis_state, anchor_block);

        // Set time so current_slot = 1 (MinimalEthSpec SLOT_DURATION_MS = 6000):
        // slot = (time - genesis_time) * 1000 / SLOT_DURATION_MS = 6 * 1000 / 6000 = 1.
        // The candidate gate at import_block step (c) reads this BEFORE on_block
        // advances the clock to wall-now, so the gate sees current_slot = 1.
        fc.time = 6;

        // Terminal-block-hash override: validate_merge_block checks
        // payload.parent_hash == fc.terminal_block_hash.
        fc.set_terminal_config(
            pharos_utils::Uint256::default(),
            Hash256::from_array(TERMINAL_HASH),
            0,
        );

        (Arc::new(RwLock::new(fc)), anchor_root, store)
    }

    // ── Test (a) ──────────────────────────────────────────────────────────────

    /// Non-candidate execution block + EL returns SYNCING → gate fires →
    /// `Err(ImportError::NotOptimisticCandidate)`.
    ///
    /// Verifies: when `payload_status == NotValidated` and the block is NOT an
    /// optimistic candidate (parent not execution-enabled + block within 128
    /// slots of current), `import_block` rejects it without importing.
    ///
    /// Per `D-optimistic-candidate-gates-import` (M8 Phase 3b).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_candidate_syncing_el_rejects_with_not_optimistic_candidate() {
        let tmpdir = tempfile::tempdir().unwrap();

        let (fc_store, anchor_root, rocks_store) = build_scaffold(&tmpdir);

        let (genesis_state, _) = build_anchor();
        // The STF uses NullExecutionEngine so the block's state_root is computed correctly.
        // The gate verdict comes from SyncingEE passed to import_block.
        let block = build_execution_block(genesis_state, anchor_root, &NullExecutionEngine);

        let runtime_cfg = pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: 0,
            altair_fork_epoch: 0,
            ..Default::default()
        };

        let (payload_tx, _payload_rx) =
            mpsc::channel::<EngineNewPayloadRequest<MinimalEthSpec>>(16);
        let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

        let result = import_block::<
            MinimalEthSpec,
            SyncingEE,
            pharos_fork_choice::NoopPowBlockProvider,
            NoopDataAvailabilityChecker,
        >(
            &block,
            &fc_store,
            &Arc::new(SyncingEE),
            &pow_provider,
            &payload_tx,
            false, // validate_result: false — no BLS in test blocks
            &runtime_cfg,
            &rocks_store,
            &Arc::new(NoopDataAvailabilityChecker),
        )
        .await;

        match result {
            Err(ImportError::NotOptimisticCandidate {
                block_slot,
                current_slot,
            }) => {
                assert_eq!(block_slot, 1, "block_slot must be 1");
                assert_eq!(current_slot, 1, "current_slot must be 1 at gate check time");
            }
            Err(e) => panic!("expected NotOptimisticCandidate error, got different Err: {e}"),
            Ok(_) => panic!("expected Err(NotOptimisticCandidate), got Ok (import succeeded)"),
        }
    }

    // ── Test (b) ──────────────────────────────────────────────────────────────

    /// Non-candidate execution block + EL returns VALID → gate not entered →
    /// import succeeds.
    ///
    /// Verifies: `import_block` gate only fires when `payload_status ==
    /// NotValidated`.  A `Valid` verdict from the EL bypasses the candidate
    /// check entirely, so even a non-candidate block imports successfully.
    ///
    /// Per `D-optimistic-candidate-gates-import` (M8 Phase 3b).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_candidate_valid_el_imports_successfully() {
        let tmpdir = tempfile::tempdir().unwrap();

        let (fc_store, anchor_root, rocks_store) = build_scaffold(&tmpdir);

        let (genesis_state, _) = build_anchor();
        let block = build_execution_block(genesis_state, anchor_root, &NullExecutionEngine);

        let runtime_cfg = pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: 0,
            altair_fork_epoch: 0,
            ..Default::default()
        };

        let (payload_tx, _payload_rx) =
            mpsc::channel::<EngineNewPayloadRequest<MinimalEthSpec>>(16);
        let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

        let result = import_block::<
            MinimalEthSpec,
            ValidEE,
            pharos_fork_choice::NoopPowBlockProvider,
            NoopDataAvailabilityChecker,
        >(
            &block,
            &fc_store,
            &Arc::new(ValidEE),
            &pow_provider,
            &payload_tx,
            false, // validate_result: false
            &runtime_cfg,
            &rocks_store,
            &Arc::new(NoopDataAvailabilityChecker),
        )
        .await;

        assert!(
            result.is_ok(),
            "non-candidate block with EL=VALID must import successfully; got Err: {}",
            result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );
        let outcome = result.unwrap();
        assert_eq!(outcome.block_root, {
            match &block {
                ForkSignedBeaconBlock::Bellatrix(inner) => inner.message.tree_hash_root(),
                _ => unreachable!(),
            }
        });
    }

    // ── Candidate scaffold (fc.time = 774 → current_slot = 129) ─────────────

    /// Identical to `build_scaffold` except `fc.time = 774` so that
    /// `current_slot = 129` at the candidate gate.
    ///
    /// With `block_slot = 1` and `SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY = 128`:
    ///   Branch 2: `1 + 128 = 129 <= 129` → IS a candidate.
    ///
    /// This is the minimum configuration for Tests 1 and 2 (optimistic import
    /// path runs to completion because the candidate gate passes).
    fn build_candidate_scaffold(
        tmpdir: &tempfile::TempDir,
    ) -> (
        Arc<RwLock<pharos_fork_choice::Store<MinimalEthSpec>>>,
        Root,
        Arc<RocksStore>,
    ) {
        let store = Arc::new(
            RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
                path: tmpdir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("RocksStore::open"),
        );

        let (genesis_state, signed_anchor) = build_anchor();
        let anchor_root: Root = match &signed_anchor {
            ForkSignedBeaconBlock::Bellatrix(inner) => inner.message.tree_hash_root(),
            _ => unreachable!("anchor is always Bellatrix"),
        };
        let anchor_block = match signed_anchor {
            ForkSignedBeaconBlock::Bellatrix(inner) => {
                pharos_types::state::MinimalBeaconBlock::Bellatrix(inner.message)
            }
            _ => unreachable!("anchor is always Bellatrix"),
        };

        let mut fc = get_forkchoice_store::<MinimalEthSpec>(genesis_state, anchor_block);

        // time = 129 * 6 = 774  →  current_slot = (774 - 0) * 1000 / 6000 = 129.
        // With block_slot = 1: `1 + 128 = 129 <= 129` → candidate via Branch 2.
        fc.time = 774;

        // Terminal-block-hash override so the merge-transition guard passes
        // (same as build_scaffold).
        fc.set_terminal_config(
            pharos_utils::Uint256::default(),
            Hash256::from_array(TERMINAL_HASH),
            0,
        );

        (Arc::new(RwLock::new(fc)), anchor_root, store)
    }

    // ── Test 1 — pre-seed survives a full payload_tx channel ─────────────────

    /// Pre-seed `payload_statuses[block_root] = NotValidated` survives even when
    /// `payload_tx` is full and the `try_send` of the newPayload request is
    /// dropped.
    ///
    /// The pre-seed happens in the persist worker (step h of `import_block`),
    /// AFTER the `try_send` at step (f).  They are independent: the dropped send
    /// does NOT prevent the pre-seed write from reaching `fc_store.payload_statuses`.
    ///
    /// Scenario:
    /// - CANDIDATE execution block (Branch 2: slot 1 + 128 <= current_slot 129).
    /// - `SyncingEE` returns `NotValidated`.
    /// - Channel capacity 1, pre-filled → the `try_send` at step (f) fails.
    ///
    /// Assertions:
    /// (a) `import_block` returns `Ok` (optimistic import succeeded).
    /// (b) `fc_store.read().payload_statuses[block_root] == NotValidated`.
    ///
    /// Per `D-preseed-notvalidated-on-import` (M8 Phase 1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn preseed_not_validated_survives_full_payload_channel() {
        let tmpdir = tempfile::tempdir().unwrap();
        let (fc_store, anchor_root, rocks_store) = build_candidate_scaffold(&tmpdir);

        let (genesis_state, _) = build_anchor();
        let block = build_execution_block(genesis_state, anchor_root, &NullExecutionEngine);

        let block_root: Root = match &block {
            ForkSignedBeaconBlock::Bellatrix(inner) => inner.message.tree_hash_root(),
            _ => unreachable!(),
        };

        let runtime_cfg = pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: 0,
            altair_fork_epoch: 0,
            ..Default::default()
        };

        // Capacity 1; pre-fill with a dummy request so the next try_send fails
        // (exercises the drop-on-full path in import_block step (f)).
        let (payload_tx, _payload_rx) = mpsc::channel::<EngineNewPayloadRequest<MinimalEthSpec>>(1);
        let dummy = EngineNewPayloadRequest::<MinimalEthSpec> {
            block_root: Root::default(),
            payload: pharos_engine::NewPayloadWire::V1(pharos_engine::ExecutionPayloadV1 {
                parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                fee_recipient: "0x0000000000000000000000000000000000000000".into(),
                state_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                receipts_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                logs_bloom: "0x00".into(),
                prev_randao: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                block_number: "0x0".into(),
                gas_limit: "0x0".into(),
                gas_used: "0x0".into(),
                timestamp: "0x0".into(),
                extra_data: "0x".into(),
                base_fee_per_gas: "0x0".into(),
                block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                transactions: vec![],
            }),
            _marker: std::marker::PhantomData,
        };
        // Fill the channel: this succeeds (capacity = 1, was empty).
        payload_tx
            .try_send(dummy)
            .expect("should fill channel (was empty)");
        // Confirm channel is now full so import_block's try_send will drop.
        assert!(
            payload_tx.capacity() == 0,
            "channel must be full before import so try_send is exercised as a drop"
        );

        let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);
        let result = import_block::<
            MinimalEthSpec,
            SyncingEE,
            pharos_fork_choice::NoopPowBlockProvider,
            NoopDataAvailabilityChecker,
        >(
            &block,
            &fc_store,
            &Arc::new(SyncingEE),
            &pow_provider,
            &payload_tx,
            false,
            &runtime_cfg,
            &rocks_store,
            &Arc::new(NoopDataAvailabilityChecker),
        )
        .await;

        // (a) Import must succeed despite the dropped send.
        assert!(
            result.is_ok(),
            "import must succeed even when payload_tx is full; got Err: {}",
            result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );

        // (b) Pre-seed must have written NotValidated regardless of the dropped send.
        let status = fc_store.read().payload_statuses.get(&block_root).copied();
        assert_eq!(
            status,
            Some(PayloadStatus::NotValidated),
            "payload_statuses[block_root] must be NotValidated after import \
             even when the payload_tx send was dropped"
        );
    }

    // ── Test 2 — optimistic import then VALID promotion ───────────────────────

    /// Optimistic-sync happy path at the import/fork-choice level:
    /// - A CANDIDATE execution block imported while EL is SYNCING enters
    ///   fork choice optimistically (head advances, status NotValidated).
    /// - A later VALID verdict from the engine driver promotes the block
    ///   (and all `NotValidated` ancestors) to `Valid`.
    ///
    /// Assertions after import:
    /// (a) `import_block` returns `Ok`.
    /// (b) `is_optimistic(&store, B_root) == true`.
    /// (c) `payload_statuses[B_root] == NotValidated`.
    /// (d) Anchor remains `Valid` (promotion stops at it).
    ///
    /// Assertions after promotion via `promote_valid_ancestors(B_root)`:
    /// (e) `is_optimistic(&store, B_root) == false`.
    /// (f) `payload_statuses[B_root] == Valid`.
    /// (g) Anchor still `Valid` (walk stops at the first already-Valid entry).
    ///
    /// Per `D-optimistic-candidate-gates-import` (M8 Phase 3b) and
    /// `D-preseed-notvalidated-on-import` (M8 Phase 1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn optimistic_import_then_valid_promotion() {
        use pharos_fork_choice::{is_optimistic, promote_valid_ancestors};

        let tmpdir = tempfile::tempdir().unwrap();
        let (fc_store, anchor_root, rocks_store) = build_candidate_scaffold(&tmpdir);

        let (genesis_state, _) = build_anchor();
        let block = build_execution_block(genesis_state, anchor_root, &NullExecutionEngine);

        let block_root: Root = match &block {
            ForkSignedBeaconBlock::Bellatrix(inner) => inner.message.tree_hash_root(),
            _ => unreachable!(),
        };

        let runtime_cfg = pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
            bellatrix_fork_epoch: 0,
            altair_fork_epoch: 0,
            ..Default::default()
        };

        let (payload_tx, _payload_rx) =
            mpsc::channel::<EngineNewPayloadRequest<MinimalEthSpec>>(16);
        let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

        // ── Phase A: import with SYNCING EL ──────────────────────────────────

        let result = import_block::<
            MinimalEthSpec,
            SyncingEE,
            pharos_fork_choice::NoopPowBlockProvider,
            NoopDataAvailabilityChecker,
        >(
            &block,
            &fc_store,
            &Arc::new(SyncingEE),
            &pow_provider,
            &payload_tx,
            false,
            &runtime_cfg,
            &rocks_store,
            &Arc::new(NoopDataAvailabilityChecker),
        )
        .await;

        // (a) Import must succeed.
        assert!(
            result.is_ok(),
            "optimistic import with SYNCING EL must succeed; got Err: {}",
            result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );

        let outcome = result.unwrap();
        assert_eq!(
            outcome.block_root, block_root,
            "outcome.block_root must equal the computed block root"
        );

        {
            let store = fc_store.read();

            // (b) Block must be optimistic (execution-enabled + not Valid).
            assert!(
                is_optimistic::<MinimalEthSpec>(&store, block_root),
                "block must be optimistic after import with SYNCING EL"
            );

            // (c) Status must be NotValidated (pre-seeded by persist worker).
            assert_eq!(
                store.payload_statuses.get(&block_root).copied(),
                Some(PayloadStatus::NotValidated),
                "payload_statuses[B_root] must be NotValidated after optimistic import"
            );

            // (d) Anchor must still be Valid (get_forkchoice_store seeds it Valid).
            assert_eq!(
                store.payload_statuses.get(&anchor_root).copied(),
                Some(PayloadStatus::Valid),
                "anchor must remain Valid after optimistic import of child block"
            );
        }

        // ── Phase B: simulate engine-driver VALID verdict ─────────────────────
        //
        // Mirrors what `run_engine_driver_loop` does on a VALID newPayload
        // response: mark the block Valid then call `promote_valid_ancestors`.
        {
            let mut store = fc_store.write();
            store.mark_payload_status(block_root, PayloadStatus::Valid);
            promote_valid_ancestors::<MinimalEthSpec>(&mut store, block_root);
        }

        {
            let store = fc_store.read();

            // (e) Block must no longer be optimistic.
            assert!(
                !is_optimistic::<MinimalEthSpec>(&store, block_root),
                "block must NOT be optimistic after VALID promotion"
            );

            // (f) Status must be Valid.
            assert_eq!(
                store.payload_statuses.get(&block_root).copied(),
                Some(PayloadStatus::Valid),
                "payload_statuses[B_root] must be Valid after promotion"
            );

            // (g) Anchor must still be Valid (promotion walk stops at first Valid).
            assert_eq!(
                store.payload_statuses.get(&anchor_root).copied(),
                Some(PayloadStatus::Valid),
                "anchor must remain Valid after promotion walk stops at it"
            );
        }
    }
}
