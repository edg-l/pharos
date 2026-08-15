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
use pharos_fork_choice::{PowBlockProvider, get_head, on_block, on_tick_per_slot};
use pharos_stf::{ExecutionEngine, StateTransitionError, state_transition};
use pharos_storage::{BlockTransition, RocksStore, StateSummary, StorageError, Store as DbStore};
use pharos_types::config::RuntimeConfig;
use pharos_types::views::{BeaconBlockView as _, BeaconStateView as _, ForkVariant};
use pharos_types::{EthSpec, phase0::primitives::Root};

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
}

// ── ImportOutcome ─────────────────────────────────────────────────────────────

/// Result of a successful `import_block` call.
#[allow(dead_code)]
pub(crate) struct ImportOutcome<E: EthSpec> {
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

// ── import_block ──────────────────────────────────────────────────────────────

/// Core block-import sequence.
///
/// Executes: pre-state fetch → STF (spawn_blocking) → on_block (spawn_blocking)
/// → payload_tx push (try_send, drop-on-full) → head computation
/// → persist worker (spawn_blocking, after write lock released).
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn import_block<E, EE, PP>(
    signed_block: &E::SignedBeaconBlock,
    fc_store: &Arc<RwLock<FcStore<E>>>,
    execution_engine: &Arc<EE>,
    pow_provider: &Arc<PP>,
    payload_tx: &tokio::sync::mpsc::Sender<NewPayloadRequest<E>>,
    validate_result: bool,
    cfg: &RuntimeConfig,
    store: &Arc<RocksStore>,
) -> Result<ImportOutcome<E>, ImportError>
where
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
        + pharos_stf::CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
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

    // (b) Capture fork variant of the post-state BEFORE consuming pre_state.
    // We need the post-state fork variant for the caller (LC gating), but
    // we can derive it from the pre-state since single-block transitions never
    // change fork variant in normal operation (upgrades are at epoch boundaries,
    // not mid-chain). However, to be accurate we compute it after STF below.

    // (c) Run state transition in spawn_blocking (CPU-bound; M3a invariant).
    let signed_block_clone = signed_block.clone();
    let ee = Arc::clone(execution_engine);
    let cfg_clone = cfg.clone();
    let post_result = tokio::task::spawn_blocking(move || {
        state_transition::<E, EE>(
            pre_state,
            &signed_block_clone,
            &ee,
            validate_result,
            &cfg_clone,
        )
    })
    .await?;

    let post_state = post_result.map_err(ImportError::StateTransition)?;

    // Capture fork variant now that we have the post-state.
    let fork_variant = post_state.fork_variant();

    // Clone post_state for return to the caller (ingestion loop uses it for
    // light-client snapshot dispatch, which needs AltairDispatchBounds /
    // BellatrixDispatchBounds that import_block deliberately does not carry).
    // Also used by the persist worker below (after on_block has moved post_state).
    let post_state_for_return = post_state.clone();

    // (d) Compute block_root before moving signed_block into the spawn.
    let block_root: Root = extract_block_root::<E>(signed_block);

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
    // Capella blocks use engine_newPayloadV2 (with withdrawals); Bellatrix uses V1.
    // Per `D-engine-v2-dispatch` (docs/decisions.md M6-Capella section).
    if let Some(capella_payload) = E::get_capella_execution_payload(signed_block) {
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

        // Capture the fields needed from the block before moving into the closure.
        // `E::SignedBeaconBlock` is a fork-enum: use per-fork helpers rather than
        // the trait-dispatch `.message()` which panics for the enum variant.
        let block_parent_root = parent_root; // already computed above via extract_parent_root
        // Derive slot and state_root by unwrapping to the concrete fork variant.
        // `state_root` is the STF-verified field from the block (cheaper than
        // re-merkleizing the post-state).
        let (block_slot, block_state_root) = {
            use pharos_types::views::{BeaconBlockView as _, SignedBeaconBlockView as _};
            if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
                let msg = inner.message();
                (msg.slot(), msg.state_root())
            } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
                let msg = inner.message();
                (msg.slot(), msg.state_root())
            } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
                let msg = inner.message();
                (msg.slot(), msg.state_root())
            } else if let Some(inner) = E::unwrap_capella_signed_block(signed_block) {
                let msg = inner.message();
                (msg.slot(), msg.state_root())
            } else {
                unreachable!("unknown fork variant in SignedBeaconBlock")
            }
        };

        let persist_result = tokio::task::spawn_blocking(move || {
            // Take only a READ guard (write guard dropped after on_block).
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
