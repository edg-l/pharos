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

use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::{Notify, mpsc, watch};
use tracing::{debug, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_network::NetworkCommandSender;
use pharos_network::host::{ForkContext as _, LightClientProvider as _};
use pharos_network::network::NetworkEvent;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_ssz::Decode;
use pharos_stf::{
    AltairDispatchBounds, BellatrixDispatchBounds, ExecutionEngine, StateTransitionError,
};
use pharos_storage::StorageError;
use pharos_types::views::{BeaconBlockView as _, ForkVariant, SignedBeaconBlockView as _};
use pharos_types::{EthSpec, phase0::primitives::Root};

use crate::engine_driver::{HeadChange, NewPayloadRequest, PayloadToWire};
use crate::host_impl::HostImpl;
use crate::lookup::LookupRequest;
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

    /// Delegated import error (from the shared import core).
    #[error(transparent)]
    Import(#[from] crate::import::ImportError),
}

// ── IngestionEgress ───────────────────────────────────────────────────────────

/// Output channels from the block-ingestion loop.
///
/// Bundles the head-change watch sender, new-payload mpsc sender, and the
/// clonable network command sender so the ingestion loop can publish LC gossip
/// updates without holding a non-`Clone` `NetworkHandle<E>`.
///
/// `notify_backfill` is fired via `notify_one()` whenever ingestion defers an
/// orphan block (missing parent state), waking the backfill loop so it can
/// heal the tip gap via range re-convergence.
pub struct IngestionEgress<E: EthSpec> {
    pub head_tx: watch::Sender<Option<HeadChange>>,
    pub payload_tx: mpsc::Sender<NewPayloadRequest<E>>,
    /// Clonable command sender for publishing gossip messages.
    pub network: NetworkCommandSender<E>,
    /// Wakes the backfill loop when an orphan block is deferred.
    pub notify_backfill: std::sync::Arc<Notify>,
    /// Forwards unknown-parent orphans and parent-imported signals to the
    /// lookup loop.  Not generic over `E` — `LookupRequest` carries raw bytes.
    pub lookup_tx: mpsc::Sender<LookupRequest>,
}

// ── run_block_ingestion_loop ──────────────────────────────────────────────────

/// Async block-ingestion loop.
///
/// Receives `NetworkEvent::GossipMessage` for beacon-block topics, decodes the
/// SSZ payload, runs state transition in a `spawn_blocking` worker, calls
/// `on_block` to update the fork-choice store, and publishes a `HeadChange`
/// to the engine driver via `egress.head_tx`.
///
/// Bellatrix blocks additionally push the execution payload onto
/// `egress.payload_tx` so the engine driver calls `engine_newPayloadV1`.
///
/// After each head change, if the block is post-Altair, publishes the latest
/// `LightClientFinalityUpdate` and `LightClientOptimisticUpdate` via
/// `egress.network`.
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
    egress: IngestionEgress<E>,
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
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + AltairDispatchBounds<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash
        + BellatrixDispatchBounds<E>,
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
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    EE: ExecutionEngine + 'static,
{
    let cfg = pharos_types::config::RuntimeConfig::default();

    while let Some(event) = event_rx.recv().await {
        // Forward unknown-parent gossip blocks to the lookup loop.
        if let NetworkEvent::UnknownParentBlock { topic, peer, data } = event {
            let _ = egress
                .lookup_tx
                .try_send(LookupRequest::UnknownParent { topic, peer, data });
            continue;
        }

        let (topic, data) = match event {
            NetworkEvent::GossipMessage { topic, data, .. }
                if topic.kind == GossipTopicKind::BeaconBlock =>
            {
                (topic, data)
            }
            _ => continue,
        };
        debug!(?topic, "block_ingestion: received gossip block");

        // (b) Decode SSZ bytes by the topic's fork-digest. Gossip beacon_block
        // carries raw per-fork SSZ with no discriminant prefix — the fork is
        // determined by the topic's fork-digest, not a leading byte.
        let signed_block: E::SignedBeaconBlock =
            match decode_block_by_topic::<E, _>(&*host, &topic, &data) {
                Some(b) => b,
                None => continue,
            };

        // (c)-(h) Core import: pre-state fetch → STF → on_block → payload push → HeadChange.
        let parent_root = extract_parent_root::<E>(&signed_block);
        let outcome = match crate::import::import_block::<E, EE, EnginePowBlockProvider>(
            &signed_block,
            &fc_store,
            &execution_engine,
            &pow_provider,
            &egress.payload_tx,
            validate_result,
            &cfg,
        )
        .await
        {
            Ok(o) => o,
            Err(crate::import::ImportError::MissingParentState) => {
                debug!(%parent_root, "block_ingestion: missing parent; deferring to backfill");
                egress.notify_backfill.notify_one();
                continue;
            }
            Err(e) => {
                warn!(error = %e, "block_ingestion: import_block failed; dropping block");
                continue;
            }
        };

        // Signal the lookup loop so it can drain any queued descendants of
        // this just-imported block.
        let _ = egress.lookup_tx.try_send(LookupRequest::ParentImported {
            root: outcome.block_root,
        });

        // (e2) Write LC snapshots before publishing (Task 2.2).
        // spawn_blocking per M3a invariant (R8); .await to ensure write completes
        // before the publish step below reads from the snapshot CF.
        {
            let post_state_snap = outcome.post_state.clone();
            let signed_block_snap = signed_block.clone();
            let fc_snap = Arc::clone(&fc_store);
            let store_snap = Arc::clone(&host.store_arc());
            let snap_result = tokio::task::spawn_blocking(move || {
                let fc = fc_snap.read();
                dispatch_update_light_client_snapshots::<E, _>(
                    &post_state_snap,
                    &signed_block_snap,
                    &fc,
                    &*store_snap,
                );
            })
            .await;
            if let Err(e) = snap_result {
                warn!(error = %e, "lc snapshot dispatch task failed");
            }
        }

        // Also notify HostImpl for any subscribers.
        host.on_head_change(outcome.head_change.clone());
        let _ = egress.head_tx.send(Some(outcome.head_change));

        // (i) Publish LC finality + optimistic updates (Tasks 2.4 + 2.5).
        // Gate: only when the head block is post-Altair.
        let has_lc_snapshots = outcome.fork_variant != ForkVariant::Phase0;
        if has_lc_snapshots {
            if let Some(fu) = host.light_client_finality_update() {
                let topic = GossipTopic {
                    fork_digest: host.current_fork_digest(),
                    kind: GossipTopicKind::LightClientFinalityUpdate,
                };
                if let Err(e) = egress.network.publish(topic, &fu).await {
                    warn!(error = %e, "lc finality update publish failed");
                }
            }
            if let Some(ou) = host.light_client_optimistic_update() {
                let topic = GossipTopic {
                    fork_digest: host.current_fork_digest(),
                    kind: GossipTopicKind::LightClientOptimisticUpdate,
                };
                if let Err(e) = egress.network.publish(topic, &ou).await {
                    warn!(error = %e, "lc optimistic update publish failed");
                }
            }
        }
    }

    Ok(())
}

// ── dispatch_update_light_client_snapshots ────────────────────────────────────

/// Fork-aware dispatcher: build and persist LC snapshots after each block.
///
/// Lives in `pharos-node` (rather than `pharos-stf`) because it needs
/// `pharos_fork_choice::Store<E>` — and `pharos-fork-choice` already depends
/// on `pharos-stf`, so `pharos-stf` cannot depend on `pharos-fork-choice`.
///
/// The actual const-generic LC snapshot writes are delegated to
/// `AltairDispatchBounds::call_update_lc_snapshots` and
/// `BellatrixDispatchBounds::call_update_lc_snapshots_bellatrix`, both of
/// which live in `pharos-stf` and carry the fifteen const-generic bounds.
pub(crate) fn dispatch_update_light_client_snapshots<E, S>(
    post_state: &E::BeaconState,
    signed_block: &E::SignedBeaconBlock,
    fc_store: &FcStore<E>,
    store: &S,
) where
    E: EthSpec,
    E::AltairBeaconState: AltairDispatchBounds<E>,
    E::BellatrixBeaconState: BellatrixDispatchBounds<E>,
    S: pharos_storage::Store<E>,
    E::AltairSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView,
    E::BellatrixSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::BellatrixBeaconBlock: pharos_types::views::BeaconBlockView,
    E::BeaconState: pharos_types::views::BeaconStateView,
{
    use pharos_types::views::{BeaconBlockView as _, BeaconStateView as _};
    match post_state.fork_variant() {
        ForkVariant::Phase0 => {
            // No LC snapshots before Altair.
        }
        ForkVariant::Altair => {
            let Some(altair_signed) = E::unwrap_altair_signed_block(signed_block) else {
                return;
            };
            // Access the unsigned block via SignedBeaconBlockView::message().
            let altair_block = altair_signed.message();
            let Some(post_state_altair) = E::unwrap_altair_state(post_state) else {
                return;
            };

            let attested_root = altair_block.parent_root();
            let finalized_root = post_state.finalized_checkpoint().root;

            let attested_block_opt = fc_store
                .blocks
                .get(&attested_root)
                .and_then(|b| E::unwrap_altair_block(b));
            let attested_state_opt = fc_store
                .block_states
                .get(&attested_root)
                .and_then(|s| E::unwrap_altair_state(s));
            let finalized_block_opt = fc_store
                .blocks
                .get(&finalized_root)
                .and_then(|b| E::unwrap_altair_block(b));

            post_state_altair.call_update_lc_snapshots::<S>(
                altair_block,
                attested_state_opt,
                attested_block_opt,
                finalized_block_opt,
                store,
            );
        }
        ForkVariant::Bellatrix => {
            let Some(bellatrix_signed) = E::unwrap_bellatrix_signed_block(signed_block) else {
                return;
            };
            let bellatrix_block = bellatrix_signed.message();
            let Some(post_state_bellatrix) = E::unwrap_bellatrix_state(post_state) else {
                return;
            };

            let attested_root = bellatrix_block.parent_root();
            let finalized_root = post_state.finalized_checkpoint().root;

            let attested_block_opt = fc_store
                .blocks
                .get(&attested_root)
                .and_then(|b| E::unwrap_bellatrix_block(b));
            let attested_state_opt = fc_store
                .block_states
                .get(&attested_root)
                .and_then(|s| E::unwrap_bellatrix_state(s));
            let finalized_block_opt = fc_store
                .blocks
                .get(&finalized_root)
                .and_then(|b| E::unwrap_bellatrix_block(b));

            post_state_bellatrix.call_update_lc_snapshots_bellatrix::<S>(
                bellatrix_block,
                attested_state_opt,
                attested_block_opt,
                finalized_block_opt,
                store,
            );
        }
    }
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

/// Decode a gossip beacon-block payload into a fork-enum `SignedBeaconBlock<E>`.
///
/// The topic's fork-digest identifies which per-fork SSZ layout to use.
/// Returns `None` (logging a warning) on decode failure or an unrecognised
/// fork digest.
///
/// Extracted from the inline match in `run_block_ingestion_loop` so it can be
/// reused by the lookup loop (Phase 4).
pub(crate) fn decode_block_by_topic<E, H>(
    host: &H,
    topic: &GossipTopic,
    data: &[u8],
) -> Option<E::SignedBeaconBlock>
where
    E: EthSpec,
    H: pharos_network::host::ForkContext,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
{
    match host.fork_from_context(&topic.fork_digest.into_inner()) {
        Some(pharos_network::types::Fork::Bellatrix) => {
            match E::BellatrixSignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::bellatrix_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: bellatrix SSZ decode failed; dropping");
                    None
                }
            }
        }
        Some(pharos_network::types::Fork::Altair) => {
            match E::AltairSignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::altair_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: altair SSZ decode failed; dropping");
                    None
                }
            }
        }
        Some(pharos_network::types::Fork::Phase0) | None => {
            match E::Phase0SignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::phase0_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: phase0 SSZ decode failed; dropping");
                    None
                }
            }
        }
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

/// Encode a fork-enum `SignedBeaconBlock<E>` as raw per-fork SSZ bytes (no
/// discriminant), matching the wire format used by gossip and stored in
/// `PendingBlocks`.
///
/// The fork-enum `Encode` impl prepends a 1-byte discriminant; this helper
/// encodes the inner variant directly so the bytes are compatible with
/// `decode_block_by_topic`.
pub(crate) fn encode_signed_block_as_gossip_bytes<E: EthSpec>(
    signed_block: &E::SignedBeaconBlock,
) -> Vec<u8>
where
    E::Phase0SignedBeaconBlock: pharos_ssz::Encode,
    E::AltairSignedBeaconBlock: pharos_ssz::Encode,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Encode,
{
    use pharos_ssz::Encode as _;
    if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else {
        // Unreachable for any valid EthSpec implementation.
        Vec::new()
    }
}
