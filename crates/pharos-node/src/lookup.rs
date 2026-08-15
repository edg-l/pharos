//! Lookup-sync loop — fetches missing ancestor chain via `BeaconBlocksByRoot`.
//!
//! When the ingestion loop receives a gossip block whose parent is not in the
//! fork-choice store, it queues the orphan in `PendingBlocks` and sends a
//! `LookupRequest::UnknownParent` here.  The lookup loop walks backwards at
//! most `MAX_LOOKUP_DEPTH` hops via `BlocksByRoot`, importing each fetched
//! ancestor and replaying queued descendants once a parent lands.
//!
//! On depth exhaustion (gap too large for lookup), `notify_backfill` is fired
//! so the range-backfill driver heals the tip gap.
//!
//! # W1 — no Mutex guard across `.await`
//!
//! All `PendingBlocks` methods (`insert`, `drain_children`, `total`) acquire
//! and release their internal `parking_lot::Mutex` guard within that single
//! synchronous call — they never return a guard.  This module never holds a
//! guard across an `.await` point.

use std::sync::Arc;
use std::time::Duration;

use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::sync::{Notify, mpsc, watch};
use tracing::{debug, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_network::host::ForkContext as _;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_types::{
    EthSpec,
    phase0::primitives::{ForkDigest, Root},
};

use crate::block_ingestion::{
    ReinjectBlock, decode_block_by_topic, encode_signed_block_as_gossip_bytes, extract_block_root,
    extract_parent_root, hold_future_block,
};
use crate::engine_driver::{HeadChange, NewPayloadRequest, PayloadToWire, PayloadToWireV2};
use crate::host_impl::HostImpl;
use crate::import::ImportError;
use crate::pending_blocks::{PendingBlocks, PendingEntry};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of hops the lookup loop will walk backward before deferring
/// to range-backfill.
pub const MAX_LOOKUP_DEPTH: usize = 32;

/// Per-request timeout for `BeaconBlocksByRoot`.
pub const LOOKUP_REQ_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of a single `try_import` attempt.
///
/// Distinguishes the missing-parent case (walk further back) from a hard
/// rejection (a bad block — STF/fork-choice failure). A hard rejection must
/// NOT trigger a backward walk: re-fetching ancestors of a deterministically
/// invalid block wastes network/CPU and pollutes the pending store.
enum ImportAttempt {
    /// Block imported into the fork-choice store.
    Imported,
    /// Parent state absent — the gap continues; walk further back.
    MissingParent,
    /// Block is valid but its slot is ahead of the store clock (`FutureSlot`).
    /// Per `fork-choice.md`, consideration "must be delayed until they are in
    /// the past": the caller holds it and re-injects at slot start (mirroring
    /// the gossip path) instead of dropping it. Carries the block's slot so the
    /// caller can compute the hold duration via `HostImpl::wait_until_slot_start`.
    FutureSlot { block_slot: u64 },
    /// STF / fork-choice rejected the block (or a join error). Do not walk back.
    Rejected,
}

// ── LookupRequest ─────────────────────────────────────────────────────────────

/// A command sent to `run_lookup_loop`.
///
/// Not generic over `E` — raw `Vec<u8>` bytes are decoded inside the loop
/// which is the generic context.  This keeps the channel type simple.
pub enum LookupRequest {
    /// Received a gossip block whose parent root is not in the fork-choice
    /// store.  The lookup loop should fetch the missing ancestors and import
    /// them, then replay `data` once the gap is closed.
    UnknownParent {
        topic: GossipTopic,
        peer: PeerId,
        data: Vec<u8>,
    },
    /// A previously-missing parent block has just been imported.  The lookup
    /// loop should drain and replay any children queued under `root`.
    ParentImported { root: Root },
}

// ── LookupError ───────────────────────────────────────────────────────────────

/// Errors returned by the lookup loop or provider.
#[derive(thiserror::Error, Debug)]
pub enum LookupError {
    /// No connected peers with a known head status.
    #[error("no usable peers")]
    NoUsablePeers,

    /// The underlying network provider returned an error.
    #[error("provider error: {0}")]
    Provider(String),

    /// The requested root list exceeds `MAX_LOOKUP_DEPTH`.
    #[error("too many roots requested")]
    TooManyRoots,

    /// Block import failed.
    #[error("import error: {0}")]
    Import(String),
}

impl From<ImportError> for LookupError {
    fn from(e: ImportError) -> Self {
        LookupError::Import(e.to_string())
    }
}

// ── LookupBlockProvider ───────────────────────────────────────────────────────

/// Provides blocks for the lookup loop via a `BeaconBlocksByRoot` request.
///
/// Native `async fn` in trait (Rust 1.85 stable).  This trait is only used as
/// a monomorphised generic `P: LookupBlockProvider<E>` on `run_lookup_loop`;
/// it is never invoked through `dyn`.  No `async-trait` dependency is needed.
pub trait LookupBlockProvider<E: EthSpec>: Send + Sync + 'static {
    fn blocks_by_root(
        &self,
        roots: Vec<Root>,
    ) -> impl std::future::Future<Output = Result<Vec<E::SignedBeaconBlock>, LookupError>> + Send;
}

// ── run_lookup_loop ───────────────────────────────────────────────────────────

/// Async lookup-sync loop.
///
/// Receives `LookupRequest` messages from the ingestion loop:
/// - `UnknownParent`: decode the orphan block, queue it in `pending`, then
///   call `fetch_and_walk` to fetch missing ancestors via `BlocksByRoot`.
/// - `ParentImported`: drain children of `root` from `pending` and replay them.
///
/// On depth exhaustion or peer failure, fires `notify_backfill` so the
/// range-backfill driver heals the gap.
///
/// Returns `Ok(())` on clean shutdown, never on error from a single block.
#[allow(clippy::too_many_arguments)]
pub async fn run_lookup_loop<E, P, EE, PP>(
    mut lookup_rx: mpsc::Receiver<LookupRequest>,
    provider: P,
    host: Arc<HostImpl<E>>,
    fc_store: Arc<RwLock<FcStore<E>>>,
    execution_engine: Arc<EE>,
    pow_provider: Arc<PP>,
    head_tx: watch::Sender<Option<HeadChange>>,
    payload_tx: mpsc::Sender<NewPayloadRequest<E>>,
    pending: Arc<PendingBlocks>,
    notify_backfill: Arc<Notify>,
    reinject_tx: mpsc::Sender<ReinjectBlock>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), LookupError>
where
    E: EthSpec,
    P: LookupBlockProvider<E>,
    EE: pharos_stf::ExecutionEngine + 'static,
    PP: pharos_fork_choice::PowBlockProvider + Send + Sync + 'static,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, EE>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock:
        pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
{
    // Loaded runtime config from the store: carries the real fork epochs so the
    // STF can trigger live fork upgrades across a boundary (see block_ingestion).
    let cfg = fc_store.read().runtime_cfg.clone();

    loop {
        tokio::select! {
            Some(req) = lookup_rx.recv() => {
                match req {
                    LookupRequest::UnknownParent { topic, peer, data } => {
                        // Decode the orphan block using the topic's fork digest.
                        let signed_block = match decode_block_by_topic::<E, _>(&*host, &topic, &data) {
                            Some(b) => b,
                            None => {
                                warn!(?topic, "lookup: failed to decode orphan block; dropping");
                                continue;
                            }
                        };

                        let parent_root = extract_parent_root::<E>(&signed_block);
                        let block_root = extract_block_root::<E>(&signed_block);

                        // If parent is already in the store, import directly and replay children.
                        let parent_known = {
                            let store = fc_store.read();
                            store.blocks.contains_key(&parent_root)
                        };
                        // Guard dropped here — before any await.

                        if parent_known {
                            debug!(%block_root, "lookup: parent known; importing directly");
                            match try_import(
                                &signed_block,
                                &fc_store,
                                &execution_engine,
                                &pow_provider,
                                &payload_tx,
                                &cfg,
                                &host,
                                &head_tx,
                            )
                            .await
                            {
                                ImportAttempt::Imported => {
                                    drain_and_replay(
                                        block_root,
                                        &pending,
                                        &host,
                                        &fc_store,
                                        &execution_engine,
                                        &pow_provider,
                                        &payload_tx,
                                        &cfg,
                                        &head_tx,
                                        &reinject_tx,
                                    )
                                    .await;
                                }
                                ImportAttempt::FutureSlot { block_slot } => {
                                    // Block is valid but ahead of the store clock. Hold and
                                    // re-inject the original gossip `(topic, data)` at slot
                                    // start via the ingestion re-inject channel, exactly as
                                    // the gossip path does — rather than dropping it and
                                    // relying on the next block's re-lookup to self-heal.
                                    let wait = host.wait_until_slot_start(block_slot);
                                    hold_future_block(&reinject_tx, wait, block_slot, topic, data);
                                }
                                ImportAttempt::MissingParent | ImportAttempt::Rejected => {}
                            }
                        } else {
                            // Queue the orphan, then walk backward to fetch its missing parent.
                            pending.insert(
                                parent_root,
                                block_root,
                                peer,
                                data,
                                topic.fork_digest,
                            );
                            fetch_and_walk(
                                parent_root,
                                &provider,
                                &pending,
                                &host,
                                &fc_store,
                                &execution_engine,
                                &pow_provider,
                                &payload_tx,
                                &cfg,
                                &head_tx,
                                &notify_backfill,
                                &reinject_tx,
                            )
                            .await;
                        }
                    }

                    LookupRequest::ParentImported { root } => {
                        drain_and_replay(
                            root,
                            &pending,
                            &host,
                            &fc_store,
                            &execution_engine,
                            &pow_provider,
                            &payload_tx,
                            &cfg,
                            &head_tx,
                            &reinject_tx,
                        )
                        .await;
                    }
                }
            }

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

// ── try_import ────────────────────────────────────────────────────────────────

/// Attempt to import a single block.
///
/// Returns `ImportAttempt::Imported` on success, `MissingParent` if the parent
/// state was absent (the caller should walk further back), or `Rejected` for a
/// hard STF/fork-choice failure (the caller must NOT walk back). Non-fatal in
/// all cases (errors are logged at warn). Lookup does not publish LC updates —
/// that is ingestion-only (catch-up path).
#[allow(clippy::too_many_arguments)]
async fn try_import<E, EE, PP>(
    signed_block: &E::SignedBeaconBlock,
    fc_store: &Arc<RwLock<FcStore<E>>>,
    execution_engine: &Arc<EE>,
    pow_provider: &Arc<PP>,
    payload_tx: &mpsc::Sender<NewPayloadRequest<E>>,
    cfg: &pharos_types::config::RuntimeConfig,
    host: &Arc<HostImpl<E>>,
    head_tx: &watch::Sender<Option<HeadChange>>,
) -> ImportAttempt
where
    E: EthSpec,
    EE: pharos_stf::ExecutionEngine + 'static,
    PP: pharos_fork_choice::PowBlockProvider + Send + Sync + 'static,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, EE>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>,
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
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
{
    match crate::import::import_block::<E, EE, PP>(
        signed_block,
        fc_store,
        execution_engine,
        pow_provider,
        payload_tx,
        true,
        cfg,
        &host.store_arc(),
    )
    .await
    {
        Ok(outcome) => {
            host.on_head_change(outcome.head_change.clone());
            let _ = head_tx.send(Some(outcome.head_change));
            ImportAttempt::Imported
        }
        Err(ImportError::MissingParentState) => ImportAttempt::MissingParent,
        Err(ImportError::ForkChoice(pharos_fork_choice::ForkChoiceError::FutureSlot {
            block_slot,
            ..
        })) => ImportAttempt::FutureSlot {
            block_slot: block_slot.0,
        },
        Err(e) => {
            warn!(error = %e, "lookup: import_block rejected block; not walking back");
            ImportAttempt::Rejected
        }
    }
}

/// Fork digest for a block's OWN fork, derived from its fork-enum variant.
///
/// Used when queuing a fetched (non-gossip) block for later replay so that
/// `drain_and_replay`'s `decode_block_by_topic` decodes it with the correct
/// fork digest even when the lookup walk crosses a fork boundary — using the
/// wall-clock `current_fork_digest()` would mis-decode ancestors from an
/// earlier fork.
fn fork_digest_of_block<E>(host: &Arc<HostImpl<E>>, signed: &E::SignedBeaconBlock) -> ForkDigest
where
    E: EthSpec,
{
    use pharos_network::types::Fork as NetworkFork;
    if E::unwrap_phase0_signed_block(signed).is_some() {
        host.fork_digest_for(NetworkFork::Phase0)
    } else if E::unwrap_altair_signed_block(signed).is_some() {
        host.fork_digest_for(NetworkFork::Altair)
    } else if E::unwrap_capella_signed_block(signed).is_some() {
        // Must precede the Bellatrix fallback: a Capella block tagged with the
        // Bellatrix digest would be decoded with the wrong schema by peers and
        // earn an instant InvalidByteLength ban (cf. M5 `D-blocksbyroot-bare-list`).
        host.fork_digest_for(NetworkFork::Capella)
    } else {
        host.fork_digest_for(NetworkFork::Bellatrix)
    }
}

// ── fetch_and_walk ────────────────────────────────────────────────────────────

/// Walk backward from `target_root`, fetching and importing one block at a time.
///
/// On success (gap closed): the fetched parent block is imported and
/// `drain_and_replay` is called for its block root so queued children are
/// replayed.  On failure or depth exhaustion: `notify_backfill` is fired so
/// the range-backfill driver heals the gap.
///
/// # W1
/// No `PendingBlocks` mutex guard is held across any `.await` inside this
/// function.  `pending.insert(...)` is a synchronous call that acquires and
/// releases the guard before returning.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_walk<E, P, EE, PP>(
    target_root: Root,
    provider: &P,
    pending: &Arc<PendingBlocks>,
    host: &Arc<HostImpl<E>>,
    fc_store: &Arc<RwLock<FcStore<E>>>,
    execution_engine: &Arc<EE>,
    pow_provider: &Arc<PP>,
    payload_tx: &mpsc::Sender<NewPayloadRequest<E>>,
    cfg: &pharos_types::config::RuntimeConfig,
    head_tx: &watch::Sender<Option<HeadChange>>,
    notify_backfill: &Arc<Notify>,
    reinject_tx: &mpsc::Sender<ReinjectBlock>,
) where
    E: EthSpec,
    P: LookupBlockProvider<E>,
    EE: pharos_stf::ExecutionEngine + 'static,
    PP: pharos_fork_choice::PowBlockProvider + Send + Sync + 'static,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, EE>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlock:
        pharos_types::views::BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
    E::Phase0SignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::Phase0BeaconBlockBody: pharos_ssz::TreeHash
        + pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::AltairBeaconBlock: pharos_types::views::BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: pharos_ssz::Decode
        + pharos_ssz::Encode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
{
    let mut current_target = target_root;
    let mut depth = MAX_LOOKUP_DEPTH;

    loop {
        // Fetch the single block identified by current_target.
        // No PendingBlocks guard is held here — .await is safe.
        let blocks = match provider.blocks_by_root(vec![current_target]).await {
            Ok(b) => b,
            Err(LookupError::NoUsablePeers) => {
                debug!(%current_target, "lookup: no usable peers; deferring to backfill");
                notify_backfill.notify_one();
                return;
            }
            Err(e) => {
                warn!(error = %e, %current_target, "lookup: provider error; deferring to backfill");
                notify_backfill.notify_one();
                return;
            }
        };

        if blocks.is_empty() {
            debug!(%current_target, "lookup: peer returned no blocks; deferring to backfill");
            notify_backfill.notify_one();
            return;
        }

        // Use the first (and expected only) returned block.
        let fetched = &blocks[0];
        let fetched_block_root = extract_block_root::<E>(fetched);
        let fetched_parent_root = extract_parent_root::<E>(fetched);

        // Try to import the fetched block.
        match try_import(
            fetched,
            fc_store,
            execution_engine,
            pow_provider,
            payload_tx,
            cfg,
            host,
            head_tx,
        )
        .await
        {
            ImportAttempt::Imported => {
                // Gap closed up to this point.  Replay any queued children.
                debug!(%fetched_block_root, "lookup: fetched block imported; replaying children");
                drain_and_replay(
                    fetched_block_root,
                    pending,
                    host,
                    fc_store,
                    execution_engine,
                    pow_provider,
                    payload_tx,
                    cfg,
                    head_tx,
                    reinject_tx,
                )
                .await;
                return;
            }
            ImportAttempt::FutureSlot { block_slot } => {
                // A fetched block ahead of the store clock. Ancestors walked
                // backward are normally in the past, so this is only reachable
                // at the very tip; hold and re-inject at slot start (mirroring
                // the gossip path) rather than walk back or drop. Reconstruct
                // the gossip `(topic, data)` from the block's OWN fork digest —
                // the re-inject channel feeds the ingestion loop's import path.
                debug!(%fetched_block_root, "lookup: fetched block in future; holding for slot start");
                let topic = GossipTopic {
                    fork_digest: fork_digest_of_block::<E>(host, fetched),
                    kind: GossipTopicKind::BeaconBlock,
                };
                let data = encode_signed_block_as_gossip_bytes::<E>(fetched);
                let wait = host.wait_until_slot_start(block_slot);
                hold_future_block(reinject_tx, wait, block_slot, topic, data);
                return;
            }
            ImportAttempt::Rejected => {
                // Hard STF/fork-choice rejection: do NOT walk back (re-fetching
                // ancestors of a deterministically invalid block is wasted work
                // and pollutes the pending store). Hand off to range-backfill.
                debug!(%fetched_block_root, "lookup: fetched block rejected; deferring to backfill");
                notify_backfill.notify_one();
                return;
            }
            ImportAttempt::MissingParent => { /* fall through to walk further back */ }
        }

        // The fetched block's own parent is missing; need to walk further back.
        if depth == 0 {
            debug!(%fetched_block_root, "lookup: depth exhausted; deferring to backfill");
            notify_backfill.notify_one();
            return;
        }

        depth -= 1;

        // Queue this fetched block under its own parent so we can replay it
        // later when its parent is eventually imported. Derive the fork-digest
        // from the fetched block's OWN fork variant (not wall-clock) so a walk
        // across a fork boundary stores the correct digest for replay decode.
        let fd = fork_digest_of_block::<E>(host, fetched);
        // Encode the fetched block as raw per-fork SSZ (no fork-enum discriminant)
        // so that drain_and_replay's decode_block_by_topic call can decode it.
        // The fork-enum Encode prepends a 1-byte discriminant; the helper
        // encode_signed_block_as_gossip_bytes encodes the inner variant directly.
        let fetched_data = encode_signed_block_as_gossip_bytes::<E>(fetched);
        // Use PeerId::random() as a placeholder — the peer is not tracked for
        // fetched (non-gossip) blocks; it does not affect replay logic.
        pending.insert(
            fetched_parent_root,
            fetched_block_root,
            PeerId::random(),
            fetched_data,
            fd,
        );

        current_target = fetched_parent_root;
    }
}

// ── drain_and_replay ──────────────────────────────────────────────────────────

/// Iteratively drain and import all blocks queued under `root`, then their
/// children, and so on until no more queued descendants remain.
///
/// Uses an explicit work-stack (`Vec<Root>`) to avoid async recursion (which
/// would require `Box::pin` and is harder to reason about re: W1).
///
/// # W1
/// `pending.drain_children(r)` acquires and releases the mutex in one
/// synchronous call.  No guard is held across any `.await` below.
#[allow(clippy::too_many_arguments)]
async fn drain_and_replay<E, EE, PP>(
    root: Root,
    pending: &Arc<PendingBlocks>,
    host: &Arc<HostImpl<E>>,
    fc_store: &Arc<RwLock<FcStore<E>>>,
    execution_engine: &Arc<EE>,
    pow_provider: &Arc<PP>,
    payload_tx: &mpsc::Sender<NewPayloadRequest<E>>,
    cfg: &pharos_types::config::RuntimeConfig,
    head_tx: &watch::Sender<Option<HeadChange>>,
    reinject_tx: &mpsc::Sender<ReinjectBlock>,
) where
    E: EthSpec,
    EE: pharos_stf::ExecutionEngine + 'static,
    PP: pharos_fork_choice::PowBlockProvider + Send + Sync + 'static,
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + Clone,
    E::BeaconBlock: pharos_types::views::BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock: pharos_ssz::Decode
        + pharos_types::views::SignedBeaconBlockView<Message = E::BeaconBlock>
        + Clone,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, EE>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, EE>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>,
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
    E::ExecutionPayload: PayloadToWire,
    E::CapellaExecutionPayload: PayloadToWireV2,
{
    let mut stack: Vec<Root> = vec![root];

    while let Some(r) = stack.pop() {
        // drain_children acquires and releases the mutex synchronously — no
        // guard is live when we hit any .await below.
        let children: Vec<PendingEntry> = pending.drain_children(r);

        for entry in children {
            // Reconstruct the GossipTopic from the stored fork_digest.  This is
            // reliable because the fork_digest was captured at insertion time
            // from the original gossip topic, not from the host's current state.
            let topic = GossipTopic {
                fork_digest: entry.fork_digest,
                kind: GossipTopicKind::BeaconBlock,
            };

            let signed_block = match decode_block_by_topic::<E, _>(host, &topic, &entry.data) {
                Some(b) => b,
                None => {
                    warn!(
                        block_root = ?entry.block_root,
                        "lookup: drain_and_replay: decode failed; dropping pending entry"
                    );
                    continue;
                }
            };

            // Import.  No guard held here — try_import is .await-able.
            match try_import(
                &signed_block,
                fc_store,
                execution_engine,
                pow_provider,
                payload_tx,
                cfg,
                host,
                head_tx,
            )
            .await
            {
                ImportAttempt::Imported => {
                    // Enqueue this block's root so its children are also replayed.
                    stack.push(entry.block_root);
                }
                ImportAttempt::FutureSlot { block_slot } => {
                    // A replayed descendant whose slot is still ahead of the
                    // store clock: hold and re-inject at slot start rather than
                    // drop. We already hold the original gossip `(topic, data)`
                    // for this entry, so re-inject it verbatim.
                    let wait = host.wait_until_slot_start(block_slot);
                    hold_future_block(reinject_tx, wait, block_slot, topic, entry.data);
                }
                ImportAttempt::MissingParent | ImportAttempt::Rejected => {}
            }
        }
    }
}
