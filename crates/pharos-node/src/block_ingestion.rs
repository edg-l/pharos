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
use tracing::{Instrument as _, debug, info_span, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_network::NetworkCommandSender;
use pharos_network::host::{ForkContext as _, LightClientProvider as _};
use pharos_network::network::NetworkEvent;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_ssz::Decode;
use pharos_stf::{
    AltairDispatchBounds, BellatrixDispatchBounds, CapellaDispatchBounds, DenebDispatchBounds,
    ElectraDispatchBounds, ExecutionEngine, FuluDispatchBounds, StateTransitionError,
};
use pharos_storage::StorageError;
use pharos_types::views::{
    BeaconBlockView as _, ForkVariant, LightClientFinalityUpdateView as _,
    LightClientOptimisticUpdateView as _, SignedBeaconBlockView as _,
};
use pharos_types::{BeaconSpec, phase0::primitives::Root};

use crate::data_availability::{BlobAwaitingBlocks, DataAvailabilityChecker};
use crate::engine_driver::{HeadChange, NewPayloadRequest, PayloadToWire, PayloadToWireV2};
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
pub struct IngestionEgress<E: BeaconSpec> {
    pub head_tx: watch::Sender<Option<HeadChange>>,
    pub payload_tx: mpsc::Sender<NewPayloadRequest<E>>,
    /// Clonable command sender for publishing gossip messages.
    pub network: NetworkCommandSender<E>,
    /// Wakes the backfill loop when an orphan block is deferred.
    pub notify_backfill: std::sync::Arc<Notify>,
    /// Forwards unknown-parent orphans and parent-imported signals to the
    /// lookup loop.  Not generic over `E` — `LookupRequest` carries raw bytes.
    pub lookup_tx: mpsc::Sender<LookupRequest>,
    /// Re-injects a gossip block `(topic, data)` back into the ingestion loop
    /// after a delay.  Used to honour the fork-choice "delay future blocks
    /// until they are in the past" rule: a block that arrived a hair before its
    /// slot (clock skew within `MAXIMUM_GOSSIP_CLOCK_DISPARITY`) is held and
    /// replayed at slot start instead of being dropped. Cloned into the lookup
    /// loop so its direct-import path can defer future blocks the same way.
    pub reinject_tx: mpsc::Sender<ReinjectBlock>,
}

/// A gossip block re-queued for a later import attempt: `(topic, raw SSZ)`.
pub type ReinjectBlock = (GossipTopic, Vec<u8>);

/// Sanity cap on how far ahead a re-injected future block may be held. The
/// gossip validator already IGNOREs blocks more than
/// `MAXIMUM_GOSSIP_CLOCK_DISPARITY` into the future, so a legitimately
/// importable block is at most a slot away; anything beyond this is dropped
/// (and logged) rather than parked indefinitely.
const MAX_FUTURE_BLOCK_HOLD: std::time::Duration = std::time::Duration::from_secs(24);

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
pub async fn run_block_ingestion_loop<E, EE, DA>(
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    mut reinject_rx: mpsc::Receiver<ReinjectBlock>,
    host: Arc<HostImpl<E>>,
    fc_store: Arc<RwLock<FcStore<E>>>,
    execution_engine: Arc<EE>,
    pow_provider: Arc<EnginePowBlockProvider>,
    egress: IngestionEgress<E>,
    validate_result: bool,
    da_checker: Arc<DA>,
    blob_awaiting: Arc<BlobAwaitingBlocks>,
    // Registry for DA-pending fulu blocks awaiting data-column sidecars
    // (EIP-7594 PeerDAS). `None` in pre-Fulu configurations; fulu blocks fall
    // back to `blob_awaiting` parking when absent.
    column_awaiting: Option<Arc<crate::column_ingestion::ColumnAwaitingBlocks>>,
    // Forward channel for `GossipBlobSidecar` events to the blob ingestion loop.
    // `None` in pre-Deneb configurations; blob events are silently dropped.
    blob_event_tx: Option<mpsc::Sender<NetworkEvent>>,
    // Forward channel for `GossipDataColumnSidecar` events to the column ingestion
    // loop (EIP-7594 PeerDAS). `None` in pre-Fulu configurations; column events
    // are silently dropped.
    column_event_tx: Option<mpsc::Sender<NetworkEvent>>,
) -> Result<(), IngestionError>
where
    DA: DataAvailabilityChecker<E> + 'static,
    E: BeaconSpec,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>
        + AltairDispatchBounds<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + BellatrixDispatchBounds<E>,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, EE>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>
        + CapellaDispatchBounds<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, EE>
        + pharos_stf::DenebJaFDispatch<E>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + DenebDispatchBounds<E>,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, EE>
        + pharos_stf::ElectraJaFDispatch<E>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_stf::ElectraUpgradeDispatch<E>
        + pharos_ssz::TreeHash
        + ElectraDispatchBounds<E>,
    E::FuluBeaconState: pharos_stf::FuluDispatch<E, EE>
        + pharos_stf::FuluJaFDispatch<E>
        + pharos_stf::FuluProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash
        + FuluDispatchBounds<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
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
    E::DenebBeaconBlock: pharos_types::views::BeaconBlockView,
    E::DenebSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
    E::DenebExecutionPayload: Into<pharos_engine::ExecutionPayloadV3>,
    EE: ExecutionEngine + 'static,
{
    // Use the node's loaded runtime config (carries the real fork epochs) so
    // `state_transition` -> `process_slots_fork` can trigger live fork upgrades
    // (e.g. bellatrix -> capella). A hardcoded default has CAPELLA_FORK_EPOCH =
    // u64::MAX, which silently suppresses the upgrade and freezes the node at
    // the fork boundary with `UnsupportedFork`.
    let cfg = fc_store.read().runtime_cfg.clone();

    loop {
        // Pull the next block to import from either the network (fresh gossip)
        // or the re-inject channel (a future block whose slot has now opened).
        let (topic, data) = tokio::select! {
            ev = event_rx.recv() => {
                let Some(event) = ev else { break }; // network task closed → exit
                // Forward blob sidecar events to the blob ingestion loop.
                if let NetworkEvent::GossipBlobSidecar { .. } = &event {
                    if let Some(ref tx) = blob_event_tx {
                        if tx.try_send(event).is_err() {
                            warn!("blob_ingestion: blob_event channel full; dropping GossipBlobSidecar (awaiting block may be parked until timeout)");
                        }
                    }
                    continue;
                }
                // Forward data-column sidecar events to the column ingestion loop.
                if let NetworkEvent::GossipDataColumnSidecar { .. } = &event {
                    if let Some(ref tx) = column_event_tx {
                        if tx.try_send(event).is_err() {
                            warn!("column_ingestion: column_event channel full; dropping GossipDataColumnSidecar (awaiting block may be parked until timeout)");
                        }
                    }
                    continue;
                }
                // Forward unknown-parent gossip blocks to the lookup loop.
                if let NetworkEvent::UnknownParentBlock { topic, peer, data } = event {
                    let _ = egress
                        .lookup_tx
                        .try_send(LookupRequest::UnknownParent { topic, peer, data });
                    continue;
                }
                match event {
                    NetworkEvent::GossipMessage { topic, data, .. }
                        if topic.kind == GossipTopicKind::BeaconBlock =>
                    {
                        (topic, data)
                    }
                    _ => continue,
                }
            }
            Some(reinjected) = reinject_rx.recv() => reinjected,
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

        // Per-slot root span and per-block child span.
        // Both are created with an explicit parent relationship so tracing's span
        // hierarchy is correct without holding `EnteredSpan` guards across `.await`
        // points (which would make the future `!Send` and break `tokio::spawn`).
        let block_slot = crate::import::signed_block_slot::<E>(&signed_block).0;
        let block_root = extract_block_root::<E>(&signed_block);
        let slot_span = info_span!("process_slot", slot = block_slot);
        // `import_block` span is explicitly parented to the slot span.
        let block_span = info_span!(
            parent: &slot_span,
            "import_block",
            block_root = %block_root,
            slot = block_slot,
        );

        // (c)-(h) Core import: pre-state fetch → DA gate → STF → on_block → payload push → HeadChange.
        let parent_root = extract_parent_root::<E>(&signed_block);
        let outcome = match crate::import::import_block::<E, EE, EnginePowBlockProvider, DA>(
            &signed_block,
            &fc_store,
            &execution_engine,
            &pow_provider,
            &egress.payload_tx,
            validate_result,
            &cfg,
            &host.store_arc(),
            &da_checker,
        )
        .instrument(block_span)
        .await
        {
            Ok(o) => o,
            Err(crate::import::ImportError::MissingParentState) => {
                debug!(%parent_root, "block_ingestion: missing parent; deferring to backfill");
                egress.notify_backfill.notify_one();
                continue;
            }
            // DA not yet satisfied: park awaiting the missing sidecars. When they
            // arrive (blob / column ingestion loop) and complete the set, the
            // block is re-injected via reinject_tx. Fulu blocks await data-column
            // sidecars (ColumnAwaitingBlocks); pre-Fulu blocks await blob sidecars
            // (BlobAwaitingBlocks). Route by the topic's fork digest so a single
            // block is parked in exactly one registry (no double re-inject).
            Err(crate::import::ImportError::DataNotAvailable) => {
                let block_root = crate::block_ingestion::extract_block_root::<E>(&signed_block);
                let is_fulu = matches!(
                    host.fork_from_context(&topic.fork_digest.into_inner()),
                    Some(pharos_network::types::Fork::Fulu)
                );
                match (is_fulu, &column_awaiting) {
                    (true, Some(registry)) => {
                        registry.park(block_root, (topic, data), egress.reinject_tx.clone());
                    }
                    _ => {
                        blob_awaiting.park(block_root, (topic, data), egress.reinject_tx.clone());
                    }
                }
                continue;
            }
            // Future block: per fork-choice.md its consideration "must be delayed
            // until they are in the past" — re-inject at slot start rather than
            // drop. Reachable only for blocks that arrived within
            // MAXIMUM_GOSSIP_CLOCK_DISPARITY before their slot (the gossip
            // validator already IGNOREs anything further ahead).
            Err(crate::import::ImportError::ForkChoice(
                pharos_fork_choice::ForkChoiceError::FutureSlot { block_slot, .. },
            )) => {
                let wait = host.wait_until_slot_start(block_slot.0);
                hold_future_block(&egress.reinject_tx, wait, block_slot.0, topic, data);
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
        //
        // For each fork, read from the fork-specific LC CFs and publish under
        // the current fork-digest. Electra uses electra LC CFs; Deneb uses deneb
        // LC CFs; Capella uses capella CFs; Altair/Bellatrix use altair CFs.
        //
        // The broadcast is *delayed* to the spec's gossip window so it is not
        // rejected as TooEarly by peers (D-lc-publish-due-time).
        let has_lc_snapshots = matches!(
            outcome.fork_variant,
            ForkVariant::Altair
                | ForkVariant::Bellatrix
                | ForkVariant::Capella
                | ForkVariant::Deneb
                | ForkVariant::Electra
                | ForkVariant::Fulu
        );
        if has_lc_snapshots {
            let digest = host.current_fork_digest();
            if outcome.fork_variant == ForkVariant::Fulu {
                // Fulu LC types ARE the electra LC types and are written to the
                // electra LC CFs by `call_update_lc_snapshots_fulu`; read them via
                // the electra LC provider methods and publish under the FULU
                // fork-digest (the BPO-aware `current_fork_digest`).
                use pharos_network::host::LightClientProvider as _;
                if let Some(fu) = host.light_client_finality_update_electra() {
                    let wait = host.lc_publish_wait(fu.finality_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientFinalityUpdate,
                        };
                        if let Err(e) = net.publish(topic, &fu).await {
                            warn!(error = %e, "fulu lc finality update publish failed");
                        }
                    });
                }
                if let Some(ou) = host.light_client_optimistic_update_electra() {
                    let wait = host.lc_publish_wait(ou.optimistic_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientOptimisticUpdate,
                        };
                        if let Err(e) = net.publish(topic, &ou).await {
                            warn!(error = %e, "fulu lc optimistic update publish failed");
                        }
                    });
                }
            } else if outcome.fork_variant == ForkVariant::Electra {
                // Electra LC: read from electra CFs and publish with electra digest.
                use pharos_network::host::LightClientProvider as _;
                if let Some(fu) = host.light_client_finality_update_electra() {
                    let wait = host.lc_publish_wait(fu.finality_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientFinalityUpdate,
                        };
                        if let Err(e) = net.publish(topic, &fu).await {
                            warn!(error = %e, "electra lc finality update publish failed");
                        }
                    });
                }
                if let Some(ou) = host.light_client_optimistic_update_electra() {
                    let wait = host.lc_publish_wait(ou.optimistic_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientOptimisticUpdate,
                        };
                        if let Err(e) = net.publish(topic, &ou).await {
                            warn!(error = %e, "electra lc optimistic update publish failed");
                        }
                    });
                }
            } else if outcome.fork_variant == ForkVariant::Deneb {
                // Deneb LC: read from deneb CFs and publish with deneb digest.
                use pharos_network::host::LightClientProvider as _;
                if let Some(fu) = host.light_client_finality_update_deneb() {
                    let wait = host.lc_publish_wait(fu.finality_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientFinalityUpdate,
                        };
                        if let Err(e) = net.publish(topic, &fu).await {
                            warn!(error = %e, "deneb lc finality update publish failed");
                        }
                    });
                }
                if let Some(ou) = host.light_client_optimistic_update_deneb() {
                    let wait = host.lc_publish_wait(ou.optimistic_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientOptimisticUpdate,
                        };
                        if let Err(e) = net.publish(topic, &ou).await {
                            warn!(error = %e, "deneb lc optimistic update publish failed");
                        }
                    });
                }
            } else if outcome.fork_variant == ForkVariant::Capella {
                // Capella LC: read from capella CFs and publish with capella digest.
                use pharos_network::host::LightClientProvider as _;
                if let Some(fu) = host.light_client_finality_update_capella() {
                    let wait = host.lc_publish_wait(fu.finality_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientFinalityUpdate,
                        };
                        if let Err(e) = net.publish(topic, &fu).await {
                            warn!(error = %e, "capella lc finality update publish failed");
                        }
                    });
                }
                if let Some(ou) = host.light_client_optimistic_update_capella() {
                    let wait = host.lc_publish_wait(ou.optimistic_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientOptimisticUpdate,
                        };
                        if let Err(e) = net.publish(topic, &ou).await {
                            warn!(error = %e, "capella lc optimistic update publish failed");
                        }
                    });
                }
            } else {
                // Altair / Bellatrix: use the altair LC CFs.
                if let Some(fu) = host.light_client_finality_update() {
                    let wait = host.lc_publish_wait(fu.finality_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientFinalityUpdate,
                        };
                        if let Err(e) = net.publish(topic, &fu).await {
                            warn!(error = %e, "lc finality update publish failed");
                        }
                    });
                }
                if let Some(ou) = host.light_client_optimistic_update() {
                    let wait = host.lc_publish_wait(ou.optimistic_signature_slot());
                    let net = egress.network.clone();
                    tokio::spawn(async move {
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                        let topic = GossipTopic {
                            fork_digest: digest,
                            kind: GossipTopicKind::LightClientOptimisticUpdate,
                        };
                        if let Err(e) = net.publish(topic, &ou).await {
                            warn!(error = %e, "lc optimistic update publish failed");
                        }
                    });
                }
            }
        }
    }

    Ok(())
}

// ── hold_future_block ──────────────────────────────────────────────────────────

/// Re-inject a future gossip block once its slot starts, instead of dropping it.
///
/// Implements the fork-choice rule that a future block's "consideration must be
/// delayed until they are in the past" (`fork-choice.md` on_block). Spawns a
/// task that sleeps `wait` (the time until the block's slot opens, from
/// `HostImpl::wait_until_slot_start`), then re-sends `(topic, data)` on the
/// ingestion re-inject channel for another import attempt. If the block is
/// implausibly far ahead (`wait > MAX_FUTURE_BLOCK_HOLD` — the gossip validator
/// should already have IGNOREd it) it is dropped with a warning rather than
/// parked, so the holding mechanism can't be abused to pin memory.
///
/// `wait` is passed in (not computed here) so this stays host-free and unit-
/// testable; the caller computes it via `HostImpl::wait_until_slot_start`.
///
/// `pub(crate)` so the lookup-sync loop can reuse the same hold-and-replay
/// mechanism for future blocks it imports directly (see `lookup.rs`).
pub(crate) fn hold_future_block(
    reinject_tx: &mpsc::Sender<ReinjectBlock>,
    wait: std::time::Duration,
    block_slot: u64,
    topic: GossipTopic,
    data: Vec<u8>,
) {
    if wait > MAX_FUTURE_BLOCK_HOLD {
        warn!(
            block_slot,
            ?wait,
            "block_ingestion: future block too far ahead; dropping"
        );
        return;
    }
    debug!(
        block_slot,
        ?wait,
        "block_ingestion: holding future block; replay at slot start"
    );
    let tx = reinject_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(wait).await;
        let _ = tx.send((topic, data)).await;
    });
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
    E: BeaconSpec,
    E::AltairBeaconState: AltairDispatchBounds<E>,
    E::BellatrixBeaconState: BellatrixDispatchBounds<E>,
    E::CapellaBeaconState: CapellaDispatchBounds<E>,
    E::DenebBeaconState: DenebDispatchBounds<E>,
    E::ElectraBeaconState: ElectraDispatchBounds<E>,
    E::FuluBeaconState: FuluDispatchBounds<E>,
    S: pharos_storage::Store<E>,
    E::AltairSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView,
    E::BellatrixSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::BellatrixBeaconBlock: pharos_types::views::BeaconBlockView,
    E::CapellaSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::CapellaBeaconBlock: pharos_types::views::BeaconBlockView,
    E::DenebSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::DenebBeaconBlock: pharos_types::views::BeaconBlockView,
    E::ElectraSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::ElectraBeaconBlock>,
    E::ElectraBeaconBlock: pharos_types::views::BeaconBlockView,
    E::FuluSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::FuluBeaconBlock>,
    E::FuluBeaconBlock: pharos_types::views::BeaconBlockView,
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
        ForkVariant::Capella => {
            let Some(capella_signed) = E::unwrap_capella_signed_block(signed_block) else {
                return;
            };
            let capella_block = capella_signed.message();
            let Some(post_state_capella) = E::unwrap_capella_state(post_state) else {
                return;
            };

            let attested_root = capella_block.parent_root();
            let finalized_root = post_state.finalized_checkpoint().root;

            let attested_block_opt = fc_store
                .blocks
                .get(&attested_root)
                .and_then(|b| E::unwrap_capella_block(b));
            let attested_state_opt = fc_store
                .block_states
                .get(&attested_root)
                .and_then(|s| E::unwrap_capella_state(s));
            let finalized_block_opt = fc_store
                .blocks
                .get(&finalized_root)
                .and_then(|b| E::unwrap_capella_block(b));

            post_state_capella.call_update_lc_snapshots_capella::<S>(
                capella_block,
                attested_state_opt,
                attested_block_opt,
                finalized_block_opt,
                store,
            );
        }
        ForkVariant::Deneb => {
            let Some(deneb_signed) = E::unwrap_deneb_signed_block(signed_block) else {
                return;
            };
            let deneb_block = deneb_signed.message();
            let Some(post_state_deneb) = E::unwrap_deneb_state(post_state) else {
                return;
            };

            let attested_root = deneb_block.parent_root();
            let finalized_root = post_state.finalized_checkpoint().root;

            let attested_block_opt = fc_store
                .blocks
                .get(&attested_root)
                .and_then(|b| E::unwrap_deneb_block(b));
            let attested_state_opt = fc_store
                .block_states
                .get(&attested_root)
                .and_then(|s| E::unwrap_deneb_state(s));
            let finalized_block_opt = fc_store
                .blocks
                .get(&finalized_root)
                .and_then(|b| E::unwrap_deneb_block(b));

            post_state_deneb.call_update_lc_snapshots_deneb::<S>(
                deneb_block,
                attested_state_opt,
                attested_block_opt,
                finalized_block_opt,
                store,
            );
        }
        ForkVariant::Electra => {
            let Some(electra_signed) = E::unwrap_electra_signed_block(signed_block) else {
                return;
            };
            let electra_block = electra_signed.message();
            let Some(post_state_electra) = E::unwrap_electra_state(post_state) else {
                return;
            };

            let attested_root = electra_block.parent_root();
            let finalized_root = post_state.finalized_checkpoint().root;

            let attested_block_opt = fc_store
                .blocks
                .get(&attested_root)
                .and_then(|b| E::unwrap_electra_block(b));
            let attested_state_opt = fc_store
                .block_states
                .get(&attested_root)
                .and_then(|s| E::unwrap_electra_state(s));
            let finalized_block_opt = fc_store
                .blocks
                .get(&finalized_root)
                .and_then(|b| E::unwrap_electra_block(b));

            post_state_electra.call_update_lc_snapshots_electra::<S>(
                electra_block,
                attested_state_opt,
                attested_block_opt,
                finalized_block_opt,
                store,
            );
        }
        ForkVariant::Fulu => {
            let Some(fulu_signed) = E::unwrap_fulu_signed_block(signed_block) else {
                return;
            };
            let fulu_block = fulu_signed.message();
            let Some(post_state_fulu) = E::unwrap_fulu_state(post_state) else {
                return;
            };

            let attested_root = fulu_block.parent_root();
            let finalized_root = post_state.finalized_checkpoint().root;

            let attested_block_opt = fc_store
                .blocks
                .get(&attested_root)
                .and_then(|b| E::unwrap_fulu_block(b));
            let attested_state_opt = fc_store
                .block_states
                .get(&attested_root)
                .and_then(|s| E::unwrap_fulu_state(s));
            let finalized_block_opt = fc_store
                .blocks
                .get(&finalized_root)
                .and_then(|b| E::unwrap_fulu_block(b));

            post_state_fulu.call_update_lc_snapshots_fulu::<S>(
                fulu_block,
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
pub(crate) fn extract_parent_root<E: BeaconSpec>(signed_block: &E::SignedBeaconBlock) -> Root
where
    E::Phase0SignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::AltairSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::BellatrixSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::CapellaSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::DenebSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::ElectraSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    <E::Phase0SignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::AltairSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::BellatrixSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::CapellaSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::DenebSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
    <E::ElectraSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_types::views::BeaconBlockView,
{
    if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_capella_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_deneb_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_electra_signed_block(signed_block) {
        inner.message().parent_root()
    } else if let Some(inner) = E::unwrap_fulu_signed_block(signed_block) {
        inner.message().parent_root()
    } else {
        unreachable!("unknown fork variant in SignedBeaconBlock")
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
    E: BeaconSpec,
    H: pharos_network::host::ForkContext,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::DenebSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    E::ElectraSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::ElectraBeaconBlock>,
    E::FuluSignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::FuluBeaconBlock>,
{
    match host.fork_from_context(&topic.fork_digest.into_inner()) {
        Some(pharos_network::types::Fork::Fulu) => {
            // Fulu beacon blocks share the Electra block shape; the topic's
            // fork-digest context selects the Fulu SSZ type (RI-2).
            match E::FuluSignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::fulu_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: fulu SSZ decode failed; dropping");
                    None
                }
            }
        }
        Some(pharos_network::types::Fork::Electra) => {
            match E::ElectraSignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::electra_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: electra SSZ decode failed; dropping");
                    None
                }
            }
        }
        Some(pharos_network::types::Fork::Deneb) => {
            match E::DenebSignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::deneb_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: deneb SSZ decode failed; dropping");
                    None
                }
            }
        }
        Some(pharos_network::types::Fork::Capella) => {
            match E::CapellaSignedBeaconBlock::from_ssz_bytes(data) {
                Ok(inner) => Some(E::capella_into_signed_block(inner)),
                Err(e) => {
                    warn!(error = ?e, "block_ingestion: capella SSZ decode failed; dropping");
                    None
                }
            }
        }
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
pub(crate) fn extract_block_root<E: BeaconSpec>(signed_block: &E::SignedBeaconBlock) -> Root
where
    E::BeaconBlock: pharos_ssz::TreeHash,
    E::Phase0SignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::AltairSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::BellatrixSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::CapellaSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::DenebSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::ElectraSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    E::FuluSignedBeaconBlock: pharos_types::views::SignedBeaconBlockView,
    <E::Phase0SignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::AltairSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::BellatrixSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::CapellaSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::DenebSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::ElectraSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
    <E::FuluSignedBeaconBlock as pharos_types::views::SignedBeaconBlockView>::Message:
        pharos_ssz::TreeHash,
{
    use pharos_ssz::TreeHash as _;
    if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_capella_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_deneb_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_electra_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else if let Some(inner) = E::unwrap_fulu_signed_block(signed_block) {
        inner.message().tree_hash_root()
    } else {
        unreachable!("unknown fork variant in SignedBeaconBlock")
    }
}

/// Encode a fork-enum `SignedBeaconBlock<E>` as raw per-fork SSZ bytes (no
/// discriminant), matching the wire format used by gossip and stored in
/// `PendingBlocks`.
///
/// The fork-enum `Encode` impl prepends a 1-byte discriminant; this helper
/// encodes the inner variant directly so the bytes are compatible with
/// `decode_block_by_topic`.
pub(crate) fn encode_signed_block_as_gossip_bytes<E: BeaconSpec>(
    signed_block: &E::SignedBeaconBlock,
) -> Vec<u8>
where
    E::Phase0SignedBeaconBlock: pharos_ssz::Encode,
    E::AltairSignedBeaconBlock: pharos_ssz::Encode,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Encode,
    E::CapellaSignedBeaconBlock: pharos_ssz::Encode,
    E::DenebSignedBeaconBlock: pharos_ssz::Encode,
    E::ElectraSignedBeaconBlock: pharos_ssz::Encode,
{
    use pharos_ssz::Encode as _;
    if let Some(inner) = E::unwrap_phase0_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_altair_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_capella_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_deneb_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else if let Some(inner) = E::unwrap_electra_signed_block(signed_block) {
        inner.as_ssz_bytes()
    } else {
        unreachable!("unknown fork variant in SignedBeaconBlock")
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{MAX_FUTURE_BLOCK_HOLD, ReinjectBlock, hold_future_block};
    use pharos_network::topics::{GossipTopic, GossipTopicKind};
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn beacon_block_topic() -> GossipTopic {
        GossipTopic {
            fork_digest: Default::default(),
            kind: GossipTopicKind::BeaconBlock,
        }
    }

    /// A future block due soon is re-injected (not dropped) once its wait elapses.
    #[tokio::test]
    async fn hold_future_block_replays_when_due() {
        let (tx, mut rx) = mpsc::channel::<ReinjectBlock>(4);
        let data = vec![1u8, 2, 3, 4];
        hold_future_block(
            &tx,
            Duration::from_millis(50),
            7,
            beacon_block_topic(),
            data.clone(),
        );

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("reinject should fire before timeout")
            .expect("reinject channel should yield the held block");
        assert_eq!(got.0.kind, GossipTopicKind::BeaconBlock);
        assert_eq!(got.1, data, "replayed bytes must be the original block");
    }

    /// A block implausibly far in the future is dropped, never re-injected.
    #[tokio::test]
    async fn hold_future_block_drops_when_too_far() {
        let (tx, mut rx) = mpsc::channel::<ReinjectBlock>(4);
        let wait = MAX_FUTURE_BLOCK_HOLD + Duration::from_secs(5);
        hold_future_block(&tx, wait, 999_999, beacon_block_topic(), vec![9u8]);

        // Nothing should arrive — the block was dropped, not parked.
        let r = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        assert!(
            r.is_err(),
            "no block should be re-injected for a far-future hold"
        );
    }
}
