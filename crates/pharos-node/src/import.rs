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
use pharos_fork_choice::{PowBlockProvider, get_head, on_block};
use pharos_stf::{ExecutionEngine, StateTransitionError, state_transition};
use pharos_storage::StorageError;
use pharos_types::config::RuntimeConfig;
use pharos_types::views::{BeaconStateView as _, ForkVariant};
use pharos_types::{EthSpec, phase0::primitives::Root};

use crate::engine_driver::{
    HeadChange, NewPayloadRequest, PayloadToWire, compute_finalized_block_hash,
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
/// → payload_tx push (try_send, drop-on-full) → head computation.
///
/// **Does NOT** perform light-client snapshot dispatch or LC gossip publish.
/// Those steps require `AltairDispatchBounds` / `BellatrixDispatchBounds` and
/// must remain in the callers that carry those bounds.
///
/// `validate_result` is forwarded to `state_transition`. Set `false` in tests
/// where blocks are produced without valid BLS signatures.
pub(crate) async fn import_block<E, EE, PP>(
    signed_block: &E::SignedBeaconBlock,
    fc_store: &Arc<RwLock<FcStore<E>>>,
    execution_engine: &Arc<EE>,
    pow_provider: &Arc<PP>,
    payload_tx: &tokio::sync::mpsc::Sender<NewPayloadRequest<E>>,
    validate_result: bool,
    cfg: &RuntimeConfig,
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
        + pharos_stf::AltairProcessSlotsDispatch<E>,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    EE: ExecutionEngine + 'static,
    PP: PowBlockProvider + Send + Sync + 'static,
{
    use crate::block_ingestion::{extract_block_root, extract_parent_root};

    // (a) Fetch pre_state from the fork-choice store.
    let parent_root = extract_parent_root::<E>(signed_block);
    let pre_state = {
        let store = fc_store.read();
        match store.block_states.get(&parent_root).cloned() {
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
        on_block::<E, PP>(&mut store, &block_for_on_block, post_state, now, &pow_clone)
    })
    .await?;

    on_block_result.map_err(ImportError::ForkChoice)?;

    // (f) For Bellatrix blocks, push the execution payload to the engine driver.
    if let Some(payload) = E::get_execution_payload(signed_block) {
        let req = NewPayloadRequest {
            block_root,
            payload: payload.to_execution_payload_v1(),
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
        let store = fc_store.read();
        let head_root = get_head::<E>(&store);
        let safe_hash = compute_safe_block_hash::<E>(&store);
        let finalized_hash = compute_finalized_block_hash::<E>(&store);
        let head_block_hash = hash_to_hex(
            E::get_execution_block_hash(
                store.blocks.get(&head_root).expect("head must be in store"),
            )
            .unwrap_or_default(),
        );
        HeadChange {
            head_root,
            head_block_hash,
            safe_block_hash: hash_to_hex(safe_hash),
            finalized_block_hash: hash_to_hex(finalized_hash),
        }
    };

    Ok(ImportOutcome {
        head_change,
        block_root,
        fork_variant,
        post_state: post_state_for_return,
    })
}
