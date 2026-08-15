//! Block ingestion loop — decodes gossip blocks, runs STF, calls fork-choice.
//!
//! The loop receives `NetworkEvent::GossipMessage { topic, data }` events,
//! decodes the SSZ-snappy payload into a `SignedBeaconBlock<E>`, runs
//! `state_transition` in a `spawn_blocking` worker, then calls
//! `pharos_fork_choice::on_block`, extracts the new head, and publishes a
//! `HeadChange` to the engine driver.
//!
//! Per M4a Phase 4 plan (Task 4.8b). Design note: `spawn_blocking` is required
//! because `state_transition` is sync and CPU-bound (M3a invariant).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_fork_choice::{get_head, on_block};
use pharos_network::network::NetworkEvent;
use pharos_network::topics::GossipTopicKind;
use pharos_ssz::Decode;
use pharos_stf::{ExecutionEngine, StateTransitionError, state_transition};
use pharos_storage::StorageError;
use pharos_types::views::{BeaconBlockView as _, SignedBeaconBlockView as _};
use pharos_types::{EthSpec, phase0::primitives::Root};

use crate::engine_driver::{
    HeadChange, NewPayloadRequest, PayloadToWire, compute_finalized_block_hash,
    compute_safe_block_hash, hash_to_hex,
};
use crate::host_impl::HostImpl;
use crate::pow_block::EnginePowBlockProvider;

// ── IngestionError ────────────────────────────────────────────────────────────

/// Errors that can occur during block ingestion.
///
/// Most variants are non-fatal for the loop (logged at warn then continue);
/// `Join` errors are fatal if the tokio thread pool is broken.
#[derive(Error, Debug)]
pub enum IngestionError {
    /// SSZ / snappy decode failure.
    #[error("decode error: {0}")]
    Decode(String),

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

// ── run_block_ingestion_loop ──────────────────────────────────────────────────

/// Async block-ingestion loop.
///
/// Receives `NetworkEvent::GossipMessage` for beacon-block topics, decodes the
/// SSZ payload, runs state transition in a `spawn_blocking` worker, calls
/// `on_block` to update the fork-choice store, and publishes a `HeadChange`
/// to the engine driver via `head_tx`.
///
/// Bellatrix blocks additionally push the execution payload onto `payload_tx`
/// so the engine driver calls `engine_newPayloadV1`.
///
/// `validate_result` is passed directly to `state_transition`. Set to `false`
/// in test contexts where blocks are constructed without valid BLS signatures
/// or state roots (mirrors the conformance-test `bls_setting: 2` pattern).
///
/// The loop exits when `event_rx` is closed (i.e. the network task shut down).
#[allow(clippy::too_many_arguments)]
pub async fn run_block_ingestion_loop<E, EE>(
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    host: Arc<HostImpl<E>>,
    fc_store: Arc<RwLock<FcStore<E>>>,
    execution_engine: Arc<EE>,
    pow_provider: Arc<EnginePowBlockProvider>,
    head_tx: watch::Sender<Option<HeadChange>>,
    payload_tx: mpsc::Sender<NewPayloadRequest<E>>,
    validate_result: bool,
) -> Result<(), IngestionError>
where
    E: EthSpec,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconBlock:
        pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
    E::Phase0SignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    EE: ExecutionEngine + 'static,
{
    let cfg = pharos_types::config::RuntimeConfig::default();

    while let Some(event) = event_rx.recv().await {
        let (topic, data) = match event {
            NetworkEvent::GossipMessage { topic, data, .. }
                if topic.kind == GossipTopicKind::BeaconBlock =>
            {
                (topic, data)
            }
            _ => continue,
        };
        debug!(?topic, "block_ingestion: received gossip block");

        // (b) Decode SSZ bytes. Phase 4: no snappy framing assumed at this layer
        // (the network task already decompress when emitting GossipMessage).
        let signed_block: E::SignedBeaconBlock = match E::SignedBeaconBlock::from_ssz_bytes(&data) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = ?e, "block_ingestion: SSZ decode failed; dropping");
                continue;
            }
        };

        // (c) Fetch pre_state from the fork-choice store.
        let pre_state = {
            // The fork-enum SignedBeaconBlock doesn't have a working message() —
            // extract parent_root via the inner variant.
            let parent_root = extract_parent_root::<E>(&signed_block);
            let store = fc_store.read();
            match store.block_states.get(&parent_root).cloned() {
                Some(s) => s,
                None => {
                    warn!(%parent_root, "block_ingestion: missing parent state; dropping block");
                    continue;
                }
            }
        };

        // (d) Run state transition in spawn_blocking (M3a invariant).
        let signed_block_clone = signed_block.clone();
        let ee = Arc::clone(&execution_engine);
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
        .await;

        let post_state = match post_result {
            Err(join_err) => {
                warn!(error = %join_err, "block_ingestion: spawn_blocking join error");
                continue;
            }
            Ok(Err(stf_err)) => {
                warn!(error = %stf_err, "block_ingestion: state_transition failed; dropping block");
                continue;
            }
            Ok(Ok(ps)) => ps,
        };

        // (e) Call on_block in spawn_blocking so any blocking HTTP inside
        // validate_merge_block (PoW-block lookup) does not stall the tokio
        // worker while holding fc_store.write() (M3a spawn_blocking invariant).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let block_root: Root = extract_block_root::<E>(&signed_block);

        let fc_clone = Arc::clone(&fc_store);
        let block_for_on_block = signed_block.clone();
        let pow_clone = Arc::clone(&pow_provider);
        let on_block_result = tokio::task::spawn_blocking(move || {
            let mut store = fc_clone.write();
            on_block::<E, EnginePowBlockProvider>(
                &mut store,
                &block_for_on_block,
                post_state,
                now,
                &pow_clone,
            )
        })
        .await;

        let on_block_outcome = match on_block_result {
            Err(join_err) => {
                warn!(error = %join_err, "block_ingestion: on_block spawn_blocking join error");
                continue;
            }
            Ok(outcome) => outcome,
        };

        if let Err(e) = on_block_outcome {
            warn!(error = %e, "block_ingestion: on_block failed; dropping block");
            continue;
        }

        // (f) For Bellatrix blocks, push the execution payload to the engine driver.
        if let Some(payload) = E::get_execution_payload(&signed_block) {
            let req = NewPayloadRequest {
                block_root,
                payload: payload.to_execution_payload_v1(),
                _marker: std::marker::PhantomData,
            };
            if payload_tx.try_send(req).is_err() {
                warn!(%block_root, "block_ingestion: payload_tx full or closed; dropping newPayload");
            }
        }

        // (g) Get the new head and release the lock.
        let (head_root, safe_hash, finalized_hash) = {
            let store = fc_store.read();
            let head_root = get_head::<E>(&store);
            let safe = compute_safe_block_hash::<E>(&store);
            let finalized = compute_finalized_block_hash::<E>(&store);
            (head_root, safe, finalized)
        };

        // (h) Build HeadChange and publish.
        let head_block_hash = {
            let store = fc_store.read();
            hash_to_hex(
                E::get_execution_block_hash(
                    store.blocks.get(&head_root).expect("head must be in store"),
                )
                .unwrap_or_default(),
            )
        };

        let change = HeadChange {
            head_root,
            head_block_hash,
            safe_block_hash: hash_to_hex(safe_hash),
            finalized_block_hash: hash_to_hex(finalized_hash),
        };

        // Also notify HostImpl for any subscribers.
        host.on_head_change(change.clone());
        let _ = head_tx.send(Some(change));
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the parent_root from a fork-enum `SignedBeaconBlock<E>`.
///
/// The fork-enum `SignedBeaconBlock` cannot return a trait-object reference
/// from `message()`, so we unwrap to each concrete inner type.
pub(crate) fn extract_parent_root<E: EthSpec>(signed_block: &E::SignedBeaconBlock) -> Root
where
    E::Phase0SignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::AltairSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::BellatrixSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    <E::Phase0SignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::AltairSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::BellatrixSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
{
    if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
        inner.message().parent_root()
    } else {
        Root::default()
    }
}

/// Extract the block_root (hash_tree_root) from a fork-enum `SignedBeaconBlock<E>`.
pub(crate) fn extract_block_root<E: EthSpec>(signed_block: &E::SignedBeaconBlock) -> Root
where
    E::BeaconBlock: pharos_ssz::TreeHash,
    E::Phase0SignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::AltairSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::BellatrixSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    <E::Phase0SignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::AltairSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::BellatrixSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
{
    use pharos_ssz::TreeHash as _;
    if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else {
        Root::default()
    }
}
