//! Forward backfill driver.
//!
//! `run_backfill_loop` issues `BeaconBlocksByRange` req-resp requests to peers,
//! runs the STF on each returned block, and calls `on_block` to advance the
//! fork-choice store toward the wall-clock head.
//!
//! The loop heals the chain to `wall_slot - 1` (tolerating the in-progress
//! slot), then parks on a hybrid `tokio::select!` waiting for either a
//! `tokio::sync::Notify` wake (fired by the ingestion loop when it defers an
//! orphan) or a `BACKFILL_FOLLOW_FALLBACK` backstop timer.  The loop never
//! exits while caught up — only when `shutdown_rx` fires.
//!
//! Design note: `BackfillBlockProvider` uses native `async fn` in trait (Rust
//! 1.85 stable, no `async-trait` needed) because it is always used as a
//! monomorphised generic `P: BackfillBlockProvider<E>`, never as `dyn`.
//! `PeerPicker` uses `#[async_trait::async_trait]` because it IS used as
//! `Arc<dyn PeerPicker>` (dyn-safety is the genuine reason).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tokio::sync::{Notify, mpsc, watch};
use tracing::{debug, info, warn};

use pharos_fork_choice::Store as FcStore;
use pharos_stf::StateTransitionError;
use pharos_types::views::BeaconBlockView as _;
use pharos_types::{BeaconSpec, phase0::primitives::Slot};

use crate::block_ingestion::{extract_block_root, extract_parent_root};
use crate::data_availability::NoopDataAvailabilityChecker;
use crate::engine_driver::{HeadChange, NewPayloadRequest, PayloadToWire, PayloadToWireV2};
use crate::host_impl::HostImpl;
use crate::lookup::LookupRequest;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of blocks to request in a single `BeaconBlocksByRange` call.
pub const BACKFILL_CHUNK_SIZE: u64 = 64;

/// Per-request timeout for `BeaconBlocksByRange`.
pub const BACKFILL_REQ_TIMEOUT: Duration = Duration::from_secs(15);

/// Wait between retries when no peers are available or the provider fails.
pub const BACKFILL_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Backstop wake interval (~4 mainnet slots); the Notify is the primary wake.
///
/// When the ingestion loop defers an orphan it fires the `Notify` immediately,
/// so normal tip-following wakes in under one gossip round-trip.  The fallback
/// ensures the loop periodically re-checks even if no orphan arrives (e.g.
/// when the node is behind and no gossip blocks are visible yet).
pub const BACKFILL_FOLLOW_FALLBACK: Duration = Duration::from_secs(48);

/// If backfill imports a chunk whose start is within this many slots of the wall
/// clock, the node is at the tip and live gossip — not backfill — should be
/// delivering those blocks. Used to detect a silent gossip-follow failure that
/// the backfill fallback would otherwise mask (the head keeps advancing, so the
/// node looks healthy). ~2 fallback intervals' worth of slots.
const NEAR_TIP_BACKFILL_SLOTS: u64 = 8;

/// Throttle for the "advancing via backfill near the tip" warning so a genuine
/// follow-lag is surfaced without flooding the log every chunk.
const FOLLOWLAG_WARN_INTERVAL: Duration = Duration::from_secs(120);

// ── BackfillError ─────────────────────────────────────────────────────────────

/// Errors returned by the backfill driver.
#[derive(thiserror::Error, Debug)]
pub enum BackfillError {
    #[error("no usable peers")]
    NoUsablePeers,
    #[error("provider error: {0}")]
    Provider(String),
    #[error("storage: {0}")]
    Storage(#[from] pharos_storage::StorageError),
    #[error("state transition: {0}")]
    Stf(#[from] StateTransitionError),
    #[error("fork choice: {0}")]
    ForkChoice(#[from] pharos_fork_choice::ForkChoiceError),
    #[error("join: {0}")]
    Join(#[from] tokio::task::JoinError),
}

// ── BackfillBlockProvider ─────────────────────────────────────────────────────

/// Provides blocks for the backfill loop via a range request.
///
/// Native `async fn` in trait (Rust 1.85 stable).  This trait is only used as
/// a monomorphised generic `P: BackfillBlockProvider<E>` on `run_backfill_loop`;
/// it is never invoked through `dyn`.  No `async-trait` dependency is needed.
pub trait BackfillBlockProvider<E: BeaconSpec>: Send + Sync + 'static {
    fn blocks_by_range(
        &self,
        start_slot: Slot,
        count: u64,
    ) -> impl std::future::Future<Output = Result<Vec<E::SignedBeaconBlock>, BackfillError>> + Send;
}

// ── run_backfill_loop ─────────────────────────────────────────────────────────

/// Async forward-backfill loop.
///
/// Repeatedly fetches chunks of blocks from `provider`, runs the STF, and
/// calls `on_block` on each.  Heals the chain up to `wall_slot - 1`, then
/// parks on a hybrid `select!` that wakes on `notify` (fired by the ingestion
/// loop when it defers an orphan block) or on `BACKFILL_FOLLOW_FALLBACK` as a
/// backstop.  The loop never exits while caught up — only when `shutdown_rx`
/// fires.
///
/// Per Task 3.3 design (D-backfill-driver):
/// - Head slot computed via `get_head` + `store.blocks` lookup (no `head_slot()`
///   method on `Store<E>`).
/// - `on_block` is idempotent on re-insertion (HashMap::insert semantics,
///   verified by `on_block_is_idempotent_on_reapplication`); no BlockKnown
///   variant in `ForkChoiceError`.
///
/// `lookup_tx`: optional channel to the lookup loop.  When `Some`, a
/// `LookupRequest::ParentImported` is sent after each successful import so the
/// lookup loop can drain any queued descendants of the imported block.  Pass
/// `None` in test contexts that do not instantiate a lookup loop.
///
/// `lowest_block_tx`: progress signal (Phase 2, Task 2.1).  Publishes the
/// **lowest imported block slot** the node holds after each chunk.  Forward
/// backfill walks UP from the anchor toward the wall clock and exits at
/// `BACKFILL_TAIL_LAG_SLOTS` from wall on the tip side; it does NOT walk below
/// the anchor, so the lowest-block slot it observes is the anchor (or genesis
/// once reached).  The backward state-backfill loop
/// (`run_backward_backfill_loop`) subscribes to the matching
/// `watch::Receiver<Slot>` and gates each restore-point regeneration on this
/// value (it only regenerates a restore point whose source blocks are present,
/// i.e. `lowest_block_slot <= target_slot`).
#[allow(clippy::too_many_arguments)]
pub async fn run_backfill_loop<E, P, EE, PP>(
    provider: P,
    host: Arc<HostImpl<E>>,
    fc_store: Arc<RwLock<FcStore<E>>>,
    execution_engine: Arc<EE>,
    pow_provider: Arc<PP>,
    head_tx: watch::Sender<Option<HeadChange>>,
    payload_tx: mpsc::Sender<NewPayloadRequest<E>>,
    genesis_time_secs: u64,
    mut shutdown_rx: watch::Receiver<bool>,
    notify: std::sync::Arc<Notify>,
    lookup_tx: Option<mpsc::Sender<LookupRequest>>,
    lowest_block_tx: watch::Sender<Slot>,
) -> Result<(), BackfillError>
where
    E: BeaconSpec,
    P: BackfillBlockProvider<E>,
    EE: pharos_stf::ExecutionEngine,
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
        + pharos_stf::ElectraUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::FuluBeaconState: pharos_stf::FuluDispatch<E, EE>
        + pharos_stf::FuluJaFDispatch<E>
        + pharos_stf::FuluProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
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
    E::CapellaExecutionPayload: PayloadToWireV2,
    E::DenebExecutionPayload: Into<pharos_engine::ExecutionPayloadV3>,
{
    // Loaded runtime config from the store: carries the real fork epochs so the
    // STF can trigger live fork upgrades across a boundary (see block_ingestion).
    let cfg = fc_store.read().runtime_cfg.clone();
    let seconds_per_slot = cfg.seconds_per_slot;

    // Throttle for the gossip-follow-lag warning (see NEAR_TIP_BACKFILL_SLOTS).
    let mut last_followlag_warn: Option<tokio::time::Instant> = None;

    // Phase 2 (Task 2.1): publish the lowest imported block slot. Computed from
    // the fork-choice `blocks` map (the slot of the lowest-slot block we hold).
    // Forward backfill only adds blocks at-or-above the anchor, so this stays at
    // the anchor; the backward state-backfill loop reads it to gate its
    // restore-point regeneration on block availability. Helper closure so the
    // publish site is a single source of truth.
    let publish_lowest_block_slot = |store: &FcStore<E>| {
        let lowest = store.blocks.values().map(|b| b.slot()).min();
        if let Some(slot) = lowest {
            // Only forward the watch value; never error on a dropped receiver
            // (the backward loop may not be spawned, e.g. without --backward-backfill).
            let _ = lowest_block_tx.send(slot);
        }
    };

    // Publish the initial lowest-block slot before the loop body so a backward
    // loop that subscribes immediately sees the anchor without waiting a chunk.
    publish_lowest_block_slot(&fc_store.read());

    loop {
        // Check for shutdown before doing any work.
        if *shutdown_rx.borrow() {
            info!("backfill: shutdown signal received; exiting");
            return Ok(());
        }

        // Task 3.2(b): no Store::head_slot() method; compute inline via get_head.
        let (_head_root, head_slot) = {
            let s = fc_store.read();
            let root = pharos_fork_choice::get_head::<E>(&s);
            let slot = s.blocks.get(&root).map(|b| b.slot()).ok_or_else(|| {
                BackfillError::Provider(format!("head root {root:?} missing from store.blocks"))
            })?;
            (root, slot)
        };

        let wall_slot = current_slot(genesis_time_secs, seconds_per_slot);

        // Tolerate the in-progress slot: heal up to but not including the
        // currently-building slot.
        let fetch_target = wall_slot.saturating_sub(1);

        // Caught-up: park until notified (orphan deferred by ingestion),
        // a fallback timer fires, or shutdown is requested.
        if head_slot.0 >= fetch_target {
            debug!(
                head = %head_slot,
                wall = %wall_slot,
                "backfill: caught up; parking until notified"
            );
            tokio::select! {
                _ = notify.notified() => {}
                _ = tokio::time::sleep(BACKFILL_FOLLOW_FALLBACK) => {}
                _ = shutdown_rx.changed() => {}
            }
            if *shutdown_rx.borrow() {
                info!("backfill: shutdown; exiting");
                return Ok(());
            }
            continue;
        }

        let start = Slot(head_slot.0 + 1);
        let remaining = fetch_target.saturating_sub(start.0) + 1;
        let count = remaining.min(BACKFILL_CHUNK_SIZE);

        let blocks = match provider.blocks_by_range(start, count).await {
            Ok(b) => b,
            Err(BackfillError::NoUsablePeers) => {
                warn!("backfill: no peers available; retrying after delay");
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
                tokio::time::sleep(BACKFILL_RETRY_DELAY).await;
                continue;
            }
            Err(e) => {
                // A provider error (peer timeout, disconnect, malformed/mismatched
                // response) must NOT permanently kill the backfill loop — that would
                // strand the node with a stale head until restart. Log and retry after
                // a delay (same recovery path as NoUsablePeers); honor shutdown first.
                warn!(error = %e, "backfill: provider failed; retrying after delay");
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
                tokio::time::sleep(BACKFILL_RETRY_DELAY).await;
                continue;
            }
        };

        if blocks.is_empty() {
            // Peer returned no blocks; back off before retrying. Honor shutdown
            // first so a node teardown isn't stalled for BACKFILL_RETRY_DELAY
            // (mirrors the NoUsablePeers path above).
            if *shutdown_rx.borrow() {
                return Ok(());
            }
            tokio::time::sleep(BACKFILL_RETRY_DELAY).await;
            continue;
        }

        // Observability: if backfill is importing blocks this close to the wall
        // clock, the node is at the tip and live gossip — not the backfill
        // fallback — should be delivering them. A persistent occurrence means
        // gossip following is broken (e.g. wrong fork-digest, unformed mesh) and
        // the backfill fallback is silently masking the lag. Surface it (throttled)
        // so the failure isn't invisible behind a still-advancing head.
        if start.0 + NEAR_TIP_BACKFILL_SLOTS >= wall_slot {
            let now = tokio::time::Instant::now();
            let due = last_followlag_warn
                .map(|t| now.duration_since(t) >= FOLLOWLAG_WARN_INTERVAL)
                .unwrap_or(true);
            if due {
                warn!(
                    head = %head_slot,
                    wall = %wall_slot,
                    start = %start,
                    "backfill is advancing the head near the tip — live gossip is not following \
                     (check beacon_block gossip: fork-digest / mesh / peer fork). The backfill \
                     fallback is masking the lag."
                );
                last_followlag_warn = Some(now);
            }
        }

        // Allocate once per chunk, not per block: historical blocks are finalized
        // and we do not retrieve their sidecars, so DA is always irrelevant for backfill.
        let noop_da = Arc::new(NoopDataAvailabilityChecker);

        for signed in blocks {
            // Check shutdown inside the per-block loop so we don't hold the
            // lock for many blocks before yielding.
            if *shutdown_rx.borrow() {
                info!("backfill: shutdown during chunk; exiting");
                return Ok(());
            }

            let parent_root = extract_parent_root::<E>(&signed);

            // Core import: pre-state fetch → STF → on_block → payload push → HeadChange.
            let outcome =
                match crate::import::import_block::<E, EE, PP, NoopDataAvailabilityChecker>(
                    &signed,
                    &fc_store,
                    &execution_engine,
                    &pow_provider,
                    &payload_tx,
                    true,
                    &cfg,
                    &host.store_arc(),
                    &noop_da,
                )
                .await
                {
                    Ok(o) => o,
                    Err(crate::import::ImportError::MissingParentState) => {
                        debug!(
                            %parent_root,
                            "backfill: missing parent state; aborting chunk"
                        );
                        break;
                    }
                    Err(crate::import::ImportError::Join(e)) => {
                        return Err(BackfillError::Join(e));
                    }
                    Err(crate::import::ImportError::StateTransition(e)) => {
                        let block_root = extract_block_root::<E>(&signed);
                        warn!(%block_root, error = %e, "backfill: state_transition failed; backing off and retrying");
                        if *shutdown_rx.borrow() {
                            return Ok(());
                        }
                        tokio::time::sleep(BACKFILL_RETRY_DELAY).await;
                        break;
                    }
                    Err(crate::import::ImportError::ForkChoice(e)) => {
                        let block_root = extract_block_root::<E>(&signed);
                        warn!(%block_root, error = %e, "backfill: on_block rejected; backing off and retrying");
                        if *shutdown_rx.borrow() {
                            return Ok(());
                        }
                        tokio::time::sleep(BACKFILL_RETRY_DELAY).await;
                        break;
                    }
                    Err(crate::import::ImportError::Storage(e)) => {
                        return Err(BackfillError::Storage(e));
                    }
                    Err(crate::import::ImportError::HeadMissing { root }) => {
                        warn!(%root, "backfill: fork-choice head not in store; backing off and retrying");
                        if *shutdown_rx.borrow() {
                            return Ok(());
                        }
                        tokio::time::sleep(BACKFILL_RETRY_DELAY).await;
                        break;
                    }
                    Err(crate::import::ImportError::NotOptimisticCandidate {
                        block_slot,
                        current_slot,
                    }) => {
                        // An execution block near the tip whose parent is not yet an
                        // execution block.  Wait proportionally to how many slots remain
                        // until the block ages past SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
                        // so we do not busy-loop (5 s retries for ~26 min) on a
                        // merge-transition block within SAFE_SLOTS of the wall clock.
                        let slots_until_safe = (block_slot
                            + pharos_fork_choice::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY)
                            .saturating_sub(current_slot);
                        let wait = std::cmp::max(
                            BACKFILL_RETRY_DELAY,
                            Duration::from_secs(slots_until_safe.saturating_mul(seconds_per_slot)),
                        );
                        warn!(
                            block_slot,
                            current_slot,
                            wait_secs = wait.as_secs(),
                            "backfill: not an optimistic candidate; waiting for clock to advance past SAFE_SLOTS"
                        );
                        if *shutdown_rx.borrow() {
                            return Ok(());
                        }
                        tokio::time::sleep(wait).await;
                        break;
                    }
                    // NoopDataAvailabilityChecker always returns Irrelevant, so
                    // DataNotAvailable is unreachable on the backfill path.
                    Err(crate::import::ImportError::DataNotAvailable) => {
                        unreachable!(
                            "backfill uses NoopDataAvailabilityChecker: DataNotAvailable is impossible"
                        )
                    }
                    // Duplicate block — already present in fork-choice from a
                    // prior backfill iteration or lookup-sync.  Benign: move to
                    // the next block in the chunk.
                    Err(crate::import::ImportError::AlreadyImported { root }) => {
                        debug!(%root, "backfill: block already imported; skipping");
                        continue;
                    }
                };

            host.on_head_change(outcome.head_change.clone());
            let _ = head_tx.send(Some(outcome.head_change));

            // Signal the lookup loop so it can drain any queued descendants of
            // this just-imported block.
            if let Some(tx) = &lookup_tx {
                let _ = tx.try_send(LookupRequest::ParentImported {
                    root: outcome.block_root,
                });
            }
        }

        // Phase 2 (Task 2.1): republish the lowest-block slot after each chunk so
        // the backward state-backfill loop is woken when block coverage extends.
        publish_lowest_block_slot(&fc_store.read());
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute the current slot from the wall-clock time and genesis parameters.
///
/// Returns `(wall_secs - genesis_time_secs) / seconds_per_slot`.
/// Saturates to 0 when `wall_secs < genesis_time_secs` (pre-genesis).
pub(crate) fn current_slot(genesis_time_secs: u64, seconds_per_slot: u64) -> u64 {
    let wall_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    wall_secs
        .saturating_sub(genesis_time_secs)
        .checked_div(seconds_per_slot)
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use blst::min_pk::SecretKey;
    use parking_lot::RwLock;
    use pharos_fork_choice::{get_forkchoice_store, get_head};
    use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
    use pharos_stf::phase0::accessors::{compute_signing_root, get_current_epoch, get_domain};
    use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
    use pharos_stf::{NullExecutionEngine, state_transition};
    use pharos_types::{
        BeaconSpec, MinimalBeaconSpec,
        altair::{MinimalSyncAggregate, MinimalSyncCommittee},
        bellatrix::{
            MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState,
            MinimalSignedBeaconBlock,
        },
        phase0::{Epoch, Gwei, Root, Slot, Validator, ValidatorIndex, Version},
        state::{
            BeaconBlock as ForkBeaconBlock, MinimalBeaconState as ForkMinState,
            SignedBeaconBlock as ForkSignedBeaconBlock,
        },
        views::BeaconBlockView as _,
    };
    use pharos_utils::bls::BLS_DST;
    use pharos_utils::{BLSPubkey, BLSSignature, Hash256};
    use tokio::sync::{Notify, mpsc, watch};

    use crate::engine_driver::{HeadChange, NewPayloadRequest};
    use crate::host_impl::HostImpl;
    use pharos_types::fork::ForkSchedule;

    use super::{BackfillBlockProvider, BackfillError, run_backfill_loop};

    // ── Type aliases for the minimal-preset fork-enum types ───────────────────

    type MinForkSignedBlock = ForkSignedBeaconBlock<
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
    >;
    type MinForkState = ForkMinState;

    // ── Test constants ────────────────────────────────────────────────────────

    /// A far-past genesis time (unix seconds) so that the computed `wall_slot`
    /// is much larger than any test chain length, ensuring the backfill loop
    /// requests blocks from the provider rather than exiting immediately.
    const BACKFILL_GENESIS_TIME_SECS: u64 = 1_000_000;

    // ── BLS test keypair helpers ──────────────────────────────────────────────

    /// Deterministic secret key derived from a fixed 32-byte seed.
    fn test_sk() -> SecretKey {
        SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM")
    }

    /// Compressed pubkey bytes for `test_sk()`.
    fn test_pubkey() -> BLSPubkey {
        BLSPubkey::from_array(test_sk().sk_to_pk().compress())
    }

    /// Sign `msg` with `test_sk()` using the Ethereum BLS DST.
    fn test_sign(msg: &[u8]) -> BLSSignature {
        BLSSignature::from_array(test_sk().sign(msg, BLS_DST, &[]).compress())
    }

    // ── Fixture chain builder ─────────────────────────────────────────────────

    const TERMINAL_BLOCK_HASH_BYTES: [u8; 32] = [0xAA_u8; 32];

    fn build_genesis_for_test() -> (
        MinForkState,
        ForkBeaconBlock<
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
        use pharos_types::phase0::{Fork, operations::BeaconBlockHeader};

        let anchor_body = MinimalBeaconBlockBody::default();
        let anchor_body_root: Root = anchor_body.tree_hash_root();
        let validator = Validator {
            pubkey: test_pubkey(),
            effective_balance: Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            slashed: false,
            ..Validator::default()
        };
        // Build sync committees where every slot uses test_pubkey(), so
        // process_sync_aggregate can always resolve pubkey -> validator index.
        let sync_committee = MinimalSyncCommittee {
            pubkeys: SszVector::from_vec(vec![
                test_pubkey();
                MinimalBeaconSpec::SYNC_COMMITTEE_SIZE as usize
            ])
            .unwrap(),
            aggregate_pubkey: test_pubkey(),
        };

        let genesis_bellatrix = MinimalBeaconState {
            genesis_time: 0,
            slot: Slot(0),
            fork: Fork {
                previous_version: Version::from_array([0x01, 0x00, 0x00, 0x01]),
                current_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
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
                Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
            )
            .unwrap(),
            previous_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
            current_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
            inactivity_scores: SszList::with_push(&SszList::default(), 0u64).unwrap(),
            current_sync_committee: sync_committee.clone(),
            next_sync_committee: sync_committee,
            ..MinimalBeaconState::default()
        };

        let genesis_state = ForkMinState::Bellatrix(genesis_bellatrix);
        let state_root: Root = genesis_state.tree_hash_root();

        let anchor_block = ForkBeaconBlock::Bellatrix(MinimalBeaconBlock {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: anchor_body,
        });

        (genesis_state, anchor_block)
    }

    fn build_chain(
        genesis_state: MinForkState,
        anchor_root: Root,
        n: u64,
    ) -> (Vec<MinForkSignedBlock>, Vec<Root>, MinForkState) {
        use pharos_stf::process_slots_fork;
        use pharos_types::bellatrix::execution_payload::MinimalExecutionPayload;

        let runtime_cfg = pharos_types::config::RuntimeConfig {
            seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
            bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
            ..Default::default()
        };
        let null_engine = NullExecutionEngine;

        let mut state = genesis_state;
        let mut signed_blocks = Vec::new();
        let mut block_roots = Vec::new();
        let mut prev_block_root = anchor_root;

        for i in 1..=n {
            let slot = Slot(i);

            let mut pre_state_advanced = state.clone();
            process_slots_fork::<MinimalBeaconSpec>(
                &mut pre_state_advanced,
                slot,
                pharos_stf::ForkEpochs::never(),
                &runtime_cfg,
            )
            .unwrap_or_else(|e| panic!("process_slots failed at slot {i}: {e}"));

            let (prev_randao, expected_timestamp) = {
                let s = match &pre_state_advanced {
                    ForkMinState::Bellatrix(s) => s,
                    _ => panic!("expected Bellatrix state"),
                };
                let epoch = slot.0 / MinimalBeaconSpec::SLOTS_PER_EPOCH;
                let idx = (epoch % MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
                let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
                let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
                (randao, ts)
            };

            let payload_parent_hash = if i == 1 {
                Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES)
            } else {
                let mut h = [0u8; 32];
                h[0] = (i - 1) as u8;
                Hash256::from_array(h)
            };
            let mut bh = [0u8; 32];
            bh[0] = i as u8;
            let block_hash = Hash256::from_array(bh);

            let payload = MinimalExecutionPayload {
                parent_hash: payload_parent_hash,
                prev_randao,
                block_number: i,
                gas_limit: 0x1c9c380,
                timestamp: expected_timestamp,
                block_hash,
                ..Default::default()
            };

            // Produce a valid RANDAO reveal so process_randao with
            // verify_signatures=true passes in run_backfill_loop.
            let randao_epoch = get_current_epoch::<MinimalBeaconSpec>(&pre_state_advanced);
            let randao_domain = get_domain::<MinimalBeaconSpec>(
                &pre_state_advanced,
                DOMAIN_RANDAO,
                Some(randao_epoch),
            );
            let randao_signing_root = compute_signing_root(&randao_epoch, randao_domain);
            let randao_reveal = test_sign(randao_signing_root.as_slice());

            // Empty sync aggregate must use G2_POINT_AT_INFINITY as the
            // signature per eth_fast_aggregate_verify semantics.
            const G2_INFINITY: [u8; 96] = {
                let mut b = [0u8; 96];
                b[0] = 0xc0;
                b
            };
            let sync_aggregate = MinimalSyncAggregate {
                sync_committee_signature: BLSSignature::from_array(G2_INFINITY),
                ..Default::default()
            };

            let body = MinimalBeaconBlockBody {
                execution_payload: payload,
                randao_reveal,
                sync_aggregate,
                ..Default::default()
            };
            let draft = MinimalBeaconBlock {
                slot,
                proposer_index: ValidatorIndex(0),
                parent_root: prev_block_root,
                state_root: Root::default(),
                body: body.clone(),
            };
            let draft_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
                message: draft,
                signature: BLSSignature::from_array([0u8; 96]),
            });
            let (post_draft, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
                state.clone(),
                &draft_signed,
                &null_engine,
                false,
                &runtime_cfg,
            )
            .unwrap_or_else(|e| panic!("draft STF failed at slot {i}: {e}"));

            let state_root: Root = post_draft.tree_hash_root();
            let final_block = MinimalBeaconBlock {
                slot,
                proposer_index: ValidatorIndex(0),
                parent_root: prev_block_root,
                state_root,
                body,
            };
            let block_root: Root = final_block.tree_hash_root();

            // Produce a valid BLS signature so state_transition with
            // validate_result=true accepts the block in run_backfill_loop.
            let domain =
                get_domain::<MinimalBeaconSpec>(&pre_state_advanced, DOMAIN_BEACON_PROPOSER, None);
            let signing_root = compute_signing_root(&final_block, domain);
            let real_sig = test_sign(signing_root.as_slice());

            let fork_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
                message: final_block,
                signature: real_sig,
            });
            let (post_final, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
                state.clone(),
                &fork_signed,
                &null_engine,
                false,
                &runtime_cfg,
            )
            .unwrap_or_else(|e| panic!("final STF failed at slot {i}: {e}"));

            state = post_final;
            prev_block_root = block_root;
            signed_blocks.push(fork_signed);
            block_roots.push(block_root);
        }

        (signed_blocks, block_roots, state)
    }

    // ── FixtureBlockProvider ──────────────────────────────────────────────────

    /// Test-only `BackfillBlockProvider` that returns a pre-built list of blocks
    /// on the first call and an empty `Vec` on subsequent calls.
    #[derive(Clone)]
    struct FixtureBlockProvider {
        blocks: Arc<parking_lot::Mutex<Option<Vec<MinForkSignedBlock>>>>,
    }

    impl FixtureBlockProvider {
        fn new(blocks: Vec<MinForkSignedBlock>) -> Self {
            Self {
                blocks: Arc::new(parking_lot::Mutex::new(Some(blocks))),
            }
        }

        fn empty() -> Self {
            Self {
                blocks: Arc::new(parking_lot::Mutex::new(Some(vec![]))),
            }
        }
    }

    impl BackfillBlockProvider<MinimalBeaconSpec> for FixtureBlockProvider {
        async fn blocks_by_range(
            &self,
            _start_slot: Slot,
            _count: u64,
        ) -> Result<Vec<MinForkSignedBlock>, BackfillError> {
            // Return the stored blocks once, then return empty on subsequent calls.
            let mut guard = self.blocks.lock();
            Ok(guard.take().unwrap_or_default())
        }
    }

    // ── Helper: build test components ─────────────────────────────────────────

    type TestBackfillHarness = (
        Arc<RwLock<pharos_fork_choice::Store<MinimalBeaconSpec>>>,
        Arc<HostImpl<MinimalBeaconSpec>>,
        Arc<NullExecutionEngine>,
        Arc<pharos_fork_choice::NoopPowBlockProvider>,
        watch::Sender<Option<HeadChange>>,
        watch::Receiver<Option<HeadChange>>,
        mpsc::Sender<NewPayloadRequest<MinimalBeaconSpec>>,
        mpsc::Receiver<NewPayloadRequest<MinimalBeaconSpec>>,
    );

    /// Build the fork-choice store, host, pow_provider, and channels for tests.
    ///
    /// Uses `NullExecutionEngine` directly (since `run_backfill_loop` is now
    /// generic over `EE: ExecutionEngine`).  No engine actor or axum mock is
    /// needed; tests avoid the runtime-drop-in-async-context problem entirely.
    fn build_test_components(
        genesis_state: MinForkState,
        anchor_block: ForkBeaconBlock<
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
    ) -> TestBackfillHarness {
        let anchor_root: Root = anchor_block.tree_hash_root();
        let mut fc = get_forkchoice_store::<MinimalBeaconSpec>(genesis_state, anchor_block);
        // Populate the store's runtime_cfg with the minimal-preset config, exactly
        // as `main.rs` does from the loaded `--config-dir` in production. The
        // backfill loop reads `fc_store.runtime_cfg` (seconds_per_slot, fork epochs);
        // `get_forkchoice_store` defaults it to the mainnet `RuntimeConfig::default()`,
        // which would give the wrong (12s) slot timing for these minimal-spec tests.
        fc.runtime_cfg = MinimalBeaconSpec::default_runtime_config();
        // Advance store time past genesis so on_block future-slot guard passes.
        fc.time = 10_000_000;
        // Set terminal_block_hash override so the merge-transition guard passes.
        fc.set_terminal_config(
            pharos_utils::Uint256::default(),
            Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES),
            0,
        );
        let _ = anchor_root;

        let fc = Arc::new(RwLock::new(fc));

        let tmpdir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            pharos_storage::RocksStore::open::<MinimalBeaconSpec>(
                pharos_storage::RocksStoreConfig {
                    path: tmpdir.path().join("chain_db"),
                    create_if_missing: true,
                },
            )
            .unwrap(),
        );
        let genesis_validators_root = Root::default();
        // Bellatrix-at-genesis schedule: all three epochs = 0.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array(MinimalBeaconSpec::GENESIS_FORK_VERSION),
            altair_fork_version: Version::from_array(MinimalBeaconSpec::ALTAIR_FORK_VERSION),
            altair_fork_epoch: Epoch(0),
            bellatrix_fork_version: Version::from_array(MinimalBeaconSpec::BELLATRIX_FORK_VERSION),
            bellatrix_fork_epoch: Epoch(0),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
            deneb_fork_epoch: Epoch(u64::MAX),
            electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
            electra_fork_epoch: Epoch(u64::MAX),
            fulu_fork_version: Version::from_array([0x06, 0x00, 0x00, 0x00]),
            fulu_fork_epoch: Epoch(u64::MAX),
            blob_schedule: Vec::new(),
            genesis_validators_root,
        };
        let host = Arc::new(HostImpl::<MinimalBeaconSpec>::new(
            store,
            Arc::clone(&fc),
            genesis_validators_root,
            fork_schedule,
            0,
            Arc::new(pharos_types::config::RuntimeConfig::default()),
        ));

        // Use NullExecutionEngine directly; run_backfill_loop is generic over EE.
        let exec_engine = Arc::new(NullExecutionEngine);
        // NoopPowBlockProvider satisfies the on_block merge-transition guard for
        // the Bellatrix terminal block (terminal_block_hash override is set above).
        let pow_provider = Arc::new(pharos_fork_choice::NoopPowBlockProvider);

        let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
        let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalBeaconSpec>>(64);

        (
            fc,
            host,
            exec_engine,
            pow_provider,
            head_tx,
            head_rx,
            payload_tx,
            payload_rx,
        )
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Verify the backfill loop parks (does NOT exit) when `head_slot` is
    /// already caught up with `wall_slot - 1`.
    ///
    /// Setup: `genesis_time_secs` = wall-clock → `wall_slot = 0` →
    /// `fetch_target = 0`.  The anchor is at slot 0, so `head_slot(0) >=
    /// fetch_target(0)` is true on the first iteration.  The loop must
    /// park (not return) because only a shutdown signal exits it.
    ///
    /// Assertion: a `timeout(800 ms)` does NOT complete (the future is still
    /// pending, meaning the loop is parked).  Then we send `shutdown_tx.send(true)`
    /// and assert the handle yields `Ok(())` promptly.
    #[tokio::test]
    async fn backfill_idles_when_caught_up() {
        let _ = tracing_subscriber::fmt::try_init();

        let (genesis_state, anchor_block) = build_genesis_for_test();
        let (fc, host, exec_engine, pow_provider, head_tx, _head_rx, payload_tx, _payload_rx) =
            build_test_components(genesis_state, anchor_block);

        // genesis_time_secs = current wall clock → wall_slot = 0 → fetch_target = 0.
        let genesis_time_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let provider = FixtureBlockProvider::empty();

        let notify = Arc::new(Notify::new());
        let fc_for_assert = Arc::clone(&fc);

        let mut handle = tokio::spawn(async move {
            run_backfill_loop::<
                MinimalBeaconSpec,
                _,
                NullExecutionEngine,
                pharos_fork_choice::NoopPowBlockProvider,
            >(
                provider,
                host,
                fc,
                exec_engine,
                pow_provider,
                head_tx,
                payload_tx,
                genesis_time_secs,
                shutdown_rx,
                notify,
                None,
                watch::channel(Slot(0)).0,
            )
            .await
        });

        // The loop must NOT complete within 800 ms — it should be parked.
        let timed_out = tokio::time::timeout(Duration::from_millis(800), &mut handle)
            .await
            .is_err();
        assert!(timed_out, "backfill loop must be parked (idle), not exited");

        // Head must be unchanged (still at slot 0).
        let head_slot = {
            let s = fc_for_assert.read();
            let root = get_head::<MinimalBeaconSpec>(&s);
            s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
        };
        assert_eq!(
            head_slot,
            Slot(0),
            "head must remain at slot 0 while parked"
        );

        // Send shutdown — loop must exit promptly.
        let _ = shutdown_tx.send(true);
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("loop must exit after shutdown signal");
        assert!(result.is_ok(), "task must not panic: {result:?}");
        assert!(
            result.unwrap().is_ok(),
            "loop must return Ok(()) on shutdown"
        );
    }

    /// Verify the backfill loop processes a chunk of blocks and advances the
    /// fork-choice head.
    ///
    /// Builds 8 minimal Bellatrix blocks.  `FixtureBlockProvider` returns all
    /// 8 on the first call, then returns empty on the second (triggering the
    /// `BACKFILL_RETRY_DELAY` path which we skip with shutdown).  Assert
    /// head advances to slot 8.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_advances_head_through_chunk() {
        let _ = tracing_subscriber::fmt::try_init();

        let (genesis_state, anchor_block) = build_genesis_for_test();
        let anchor_root: Root = anchor_block.tree_hash_root();

        let (fc, host, exec_engine, pow_provider, head_tx, _head_rx, payload_tx, _payload_rx) =
            build_test_components(genesis_state.clone(), anchor_block);

        let n_blocks: u64 = 8;
        let (signed_blocks, _block_roots, _final_state) =
            build_chain(genesis_state, anchor_root, n_blocks);

        // genesis_time_secs far in the past so wall_slot > n_blocks (backfill
        // will request blocks).  After processing all 8 blocks the second
        // provider call returns empty, which causes BACKFILL_RETRY_DELAY.
        // Send shutdown before the delay expires.
        let genesis_time_secs = BACKFILL_GENESIS_TIME_SECS;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let provider = FixtureBlockProvider::new(signed_blocks);

        let fc_for_assert = Arc::clone(&fc);

        let handle = tokio::spawn(async move {
            run_backfill_loop::<
                MinimalBeaconSpec,
                _,
                NullExecutionEngine,
                pharos_fork_choice::NoopPowBlockProvider,
            >(
                provider,
                host,
                fc,
                exec_engine,
                pow_provider,
                head_tx,
                payload_tx,
                genesis_time_secs,
                shutdown_rx,
                Arc::new(Notify::new()),
                None,
                watch::channel(Slot(0)).0,
            )
            .await
        });

        // Wait for the blocks to be processed (allow up to 10 s).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let head_slot = {
                let s = fc_for_assert.read();
                let root = get_head::<MinimalBeaconSpec>(&s);
                s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
            };
            if head_slot.0 >= n_blocks {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "timeout: head_slot={} expected >= {}",
                    head_slot.0, n_blocks
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Trigger shutdown so the loop exits.
        let _ = shutdown_tx.send(true);
        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("loop should exit after shutdown");
        assert!(result.is_ok(), "task must not panic");

        let head_slot = {
            let s = fc_for_assert.read();
            let root = get_head::<MinimalBeaconSpec>(&s);
            s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
        };
        assert_eq!(
            head_slot,
            Slot(n_blocks),
            "head must advance to slot {n_blocks} after processing chain, got {head_slot:?}"
        );
    }

    /// Verify the backfill loop is idempotent when the provider returns a block
    /// that is already in the fork-choice store.
    ///
    /// Pre-applies block A (slot 1) directly via `on_block`, then supplies
    /// `FixtureBlockProvider` with [A, B].  Assert the loop does not return an
    /// error and the head ends at B (slot 2).
    ///
    /// This exercises the `on_block_is_idempotent_on_reapplication` property in
    /// an async integration setting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backfill_idempotent_on_already_known() {
        let _ = tracing_subscriber::fmt::try_init();

        let (genesis_state, anchor_block) = build_genesis_for_test();
        let anchor_root: Root = anchor_block.tree_hash_root();

        let (fc, host, exec_engine, pow_provider, head_tx, _head_rx, payload_tx, _payload_rx) =
            build_test_components(genesis_state.clone(), anchor_block);

        let n_blocks: u64 = 2;
        let (signed_blocks, block_roots, _) =
            build_chain(genesis_state.clone(), anchor_root, n_blocks);

        // Pre-apply block A (slot 1) to fc_store before starting the loop.
        {
            use pharos_types::config::RuntimeConfig;

            let cfg = RuntimeConfig {
                seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
                bellatrix_fork_version: MinimalBeaconSpec::BELLATRIX_FORK_VERSION,
                ..Default::default()
            };
            let signed_a = signed_blocks[0].clone();
            let pre_state = {
                let s = fc.read();
                s.block_states.get(&anchor_root).cloned().unwrap()
            };
            let (post_a, _) = state_transition::<MinimalBeaconSpec, NullExecutionEngine>(
                pre_state,
                &signed_a,
                &NullExecutionEngine,
                false,
                &cfg,
            )
            .expect("pre-apply STF for block A");

            let mut store = fc.write();
            pharos_fork_choice::on_block::<
                MinimalBeaconSpec,
                pharos_fork_choice::NoopPowBlockProvider,
            >(
                &mut store,
                &signed_a,
                post_a,
                10_000_000,
                &pharos_fork_choice::NoopPowBlockProvider,
            )
            .expect("pre-apply on_block for block A");
        }

        let genesis_time_secs = BACKFILL_GENESIS_TIME_SECS;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let provider = FixtureBlockProvider::new(signed_blocks);

        let fc_for_assert = Arc::clone(&fc);

        let handle = tokio::spawn(async move {
            run_backfill_loop::<
                MinimalBeaconSpec,
                _,
                NullExecutionEngine,
                pharos_fork_choice::NoopPowBlockProvider,
            >(
                provider,
                host,
                fc,
                exec_engine,
                pow_provider,
                head_tx,
                payload_tx,
                genesis_time_secs,
                shutdown_rx,
                Arc::new(Notify::new()),
                None,
                watch::channel(Slot(0)).0,
            )
            .await
        });

        // Wait for head to advance to slot 2.
        let expected_root = block_roots[1];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let head_root = {
                let s = fc_for_assert.read();
                get_head::<MinimalBeaconSpec>(&s)
            };
            if head_root == expected_root {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                let slot = {
                    let s = fc_for_assert.read();
                    s.blocks
                        .get(&head_root)
                        .map(|b| b.slot())
                        .unwrap_or(Slot(0))
                };
                panic!("timeout: head_slot={} expected slot 2", slot.0);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = shutdown_tx.send(true);
        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("loop should exit");
        assert!(result.is_ok(), "task must not panic: {result:?}");

        let head_slot = {
            let s = fc_for_assert.read();
            let root = get_head::<MinimalBeaconSpec>(&s);
            s.blocks.get(&root).map(|b| b.slot()).unwrap_or(Slot(0))
        };
        assert_eq!(
            head_slot,
            Slot(n_blocks),
            "head must be at slot {n_blocks} after idempotent replay, got {head_slot:?}"
        );
    }
}
