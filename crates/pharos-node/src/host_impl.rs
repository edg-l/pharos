//! Real `Host<E>` implementation for `pharos-node`.
//!
//! This module replaces the M2 stubs (`BlockStoreStub`, `ForkContextStub`,
//! `GossipValidatorStub`, non-generic `HostImpl`) with a single generic
//! `HostImpl<E: EthSpec>` backed by a real `RocksStore` and the in-memory
//! `pharos_fork_choice::Store<E>`.
//!
//! # GossipValidator note
//!
//! `GossipValidator<E>` methods on `HostImpl<E>` return `GossipVerdict::Accept`
//! stubs except for the two light-client gossip topics, which implement full
//! validation per `specs/altair/light-client/p2p-interface.md` (M4c Phase 1).
//! See `D-lc-gossip-validation-full-node-arm` in `docs/decisions.md`.
//!
//! # record_attnets_change
//!
//! `record_attnets_change` is the public hook for the M3b subnet-rotation
//! driver. At startup (M3a) it is called once from `main.rs` to set the
//! initial attestation subnet bitfield and bump `seq_number` from 0 to 1.
//! The M3b epoch driver will call it every `EPOCHS_PER_SUBNET_SUBSCRIPTION`
//! epochs when the persistent subnet assignment rotates.

use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lru::LruCache;

use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};
use tracing::warn;

use pharos_network::host::{
    BlockProvider, ForkContext, GOSSIP_REASON_PARENT_UNSEEN, GossipValidator, GossipVerdict,
    LightClientProvider,
};
use pharos_network::types::{Fork, SubnetId};
use pharos_ssz::{Bitvector, TreeHash};
use pharos_storage::{RocksStore, Store as StoreTrait};
use pharos_types::EthSpec;
use pharos_types::RuntimeConfig;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::fork::{ForkSchedule, compute_fork_digest};
use pharos_types::phase0::primitives::{
    ATTESTATION_SUBNET_COUNT, ForkDigest, INTERVALS_PER_SLOT, MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
    Root, Version,
};
use pharos_types::phase0::{
    Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
    SignedAggregateAndProof, SignedVoluntaryExit, Slot,
};
use pharos_types::views::{LightClientFinalityUpdateView, LightClientOptimisticUpdateView};
use pharos_utils::Epoch;

use crate::engine_driver::{HeadChange, NewPayloadRequest};
use crate::op_pools::OperationPools;

// ── ForkContextInner ──────────────────────────────────────────────────────────

/// Private fork-context state stored inside `HostImpl`.
///
/// `current_fork_digest()` is computed dynamically from `fork_schedule` +
/// wall-clock epoch derived from `genesis_time_secs`; there is no frozen
/// digest field. This means Status / ENR / message-id stay correct as the
/// epoch advances without any mutation path. (ADR `D-epoch-driven-fork-digest`.)
struct ForkContextInner {
    genesis_validators_root: Root,
    fork_schedule: ForkSchedule,
    /// Unix timestamp of genesis slot 0 (seconds).
    ///
    /// `0` is treated as "epoch 0 forever" (suitable for tests where no real
    /// wall-clock alignment is needed).
    genesis_time_secs: u64,
}

// ── HostImpl ──────────────────────────────────────────────────────────────────

/// Combined node host implementation.
///
/// Implements `ForkContext + BlockProvider<E> + GossipValidator<E>` so it
/// satisfies the `Host<E>` blanket bound required by `NetworkBuilder`.
///
/// Fields:
/// - `store`: RocksDB-backed persistent block/state storage.
/// - `fork_choice`: In-memory LMD-GHOST + FFG fork-choice state, shared with
///   any future STF executor via `Arc<RwLock<...>>`.
/// - `fork_context`: Precomputed fork-digest + schedule (read-only after
///   construction).
/// - `metadata`: Local `MetaData` cell; read-mostly (Ping/MetaData responses),
///   written on subnet changes.
pub struct HostImpl<E: EthSpec> {
    store: Arc<RocksStore>,
    fork_choice: Arc<RwLock<pharos_fork_choice::Store<E>>>,
    fork_context: ForkContextInner,
    metadata: RwLock<AltairMetaData>,
    /// Runtime configuration (seconds_per_slot, etc.) for gossip validation timing.
    runtime_cfg: Arc<RuntimeConfig>,
    /// In-memory operation pools fed by the gossip-accept path (Task 2.4).
    ///
    /// Accepted attestations, slashings, exits, and credential changes are
    /// inserted here for later `drain_for_block` at block-production time.
    /// Shared as `Arc` so the same pool can be read by block-production without
    /// holding any `HostImpl` lock.
    pub op_pools: Arc<OperationPools<E>>,
    /// Highest `finalized_header.beacon.slot` of any forwarded altair finality update.
    ///
    /// Backs the per-topic monotonic forwarded-slot IGNORE rule per
    /// `specs/altair/light-client/p2p-interface.md`.
    last_forwarded_finality_slot: AtomicU64,
    /// Highest `attested_header.beacon.slot` of any forwarded altair optimistic update.
    last_forwarded_optimistic_slot: AtomicU64,
    /// Highest `finalized_header.beacon.slot` of any forwarded capella finality update.
    last_forwarded_finality_slot_capella: AtomicU64,
    /// Highest `attested_header.beacon.slot` of any forwarded capella optimistic update.
    last_forwarded_optimistic_slot_capella: AtomicU64,
    /// Broadcast channel for head-change events.  `None` before the engine
    /// driver is wired in (cold start before Task 4.8 spawns the loop).
    pub(crate) head_tx: Option<watch::Sender<Option<HeadChange>>>,
    /// Channel for new-payload requests to the engine driver.
    pub(crate) payload_tx: Option<mpsc::Sender<NewPayloadRequest<E>>>,
    /// Tracks (slot, proposer_index) pairs seen so far; gates the RB3 duplicate-
    /// proposer IGNORE rule per `specs/phase0/p2p-interface.md:575`.
    /// Capacity: 4096 entries (D-seen-cache-after-accept).
    seen_block_proposers: RwLock<LruCache<(Slot, u64), ()>>,
    /// Caches `(slot, parent_root) → expected_proposer_index` to avoid
    /// re-running `process_slots` + `get_beacon_proposer_index` on repeated
    /// calls with the same key.
    /// Capacity: 1024 entries.
    proposer_cache: RwLock<LruCache<(Slot, Root), u64>>,
    /// Set of block roots that have been explicitly REJECTed; used to
    /// short-circuit children of bad blocks per `D-invalid-roots-cache`.
    /// Capacity: 256 entries.
    invalid_block_roots: RwLock<LruCache<Root, ()>>,
    /// Tracks `(validator_index, target_epoch)` pairs that have already produced
    /// an accepted unaggregated attestation; gates the RAT7 duplicate-validator
    /// IGNORE rule per `specs/phase0/p2p-interface.md:979`.
    /// Capacity: 131072 entries (D-seen-cache-after-accept).
    seen_attestation_validators: RwLock<LruCache<(u64, Epoch), ()>>,
    /// Caches `(slot, committee_index, head_root) → Vec<validator_index>` to
    /// avoid re-running `get_beacon_committee` for repeated attestation-validator
    /// lookups against the same head. Key includes `head_root` for reorg safety
    /// (D-cache-key-on-head).
    /// Capacity: 4096 entries.
    committee_cache: RwLock<LruCache<(Slot, u64, Root), Vec<u64>>>,
    /// Tracks `(aggregator_index, target_epoch)` pairs that have already produced
    /// an accepted aggregate; gates the RAG7 duplicate-aggregator IGNORE rule per
    /// `specs/phase0/p2p-interface.md:679`.
    /// Capacity: 8192 entries (D-seen-cache-after-accept).
    seen_aggregators: RwLock<LruCache<(u64, Epoch), ()>>,
    /// Per data_root, stores the OR of all previously-seen aggregation bitlists.
    /// Used to implement the RAG6 weakened-superset IGNORE rule: IGNORE iff every
    /// set bit in the incoming bitlist is already set in the stored bitlist.
    /// Capacity: 2048 entries.
    seen_aggregate_data: RwLock<LruCache<Root, pharos_ssz::Bitlist<2048>>>,
    /// Tracks validator indices for which a `voluntary_exit` has been accepted.
    /// Gates the duplicate-exit IGNORE rule per `specs/phase0/p2p-interface.md`.
    /// Capacity: 4096 entries (D-seen-cache-shape).
    seen_voluntary_exit_indices: RwLock<LruCache<u64, ()>>,
    /// Tracks validator indices for which a `proposer_slashing` has been accepted.
    /// Gates the duplicate-slashing IGNORE rule per `specs/phase0/p2p-interface.md`.
    /// Capacity: 4096 entries.
    seen_proposer_slashing_indices: RwLock<LruCache<u64, ()>>,
    /// Tracks validator indices present in attester slashings that have been accepted.
    /// Gates the duplicate-attester-slashing IGNORE rule per `specs/phase0/p2p-interface.md`.
    /// Capacity: 4096 entries.
    seen_attester_slashing_indices: RwLock<LruCache<u64, ()>>,
    /// Tracks validator indices for which a `bls_to_execution_change` has been accepted.
    /// Gates the duplicate-change IGNORE rule per `specs/capella/p2p-interface.md`
    /// (ADR `D-bls-to-exec-seen-cache`).
    /// Capacity: 4096 entries.
    seen_bls_to_execution_change_indices: RwLock<LruCache<u64, ()>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> HostImpl<E> {
    /// Construct a new `HostImpl<E>`.
    ///
    /// `fork_choice` should already be hydrated (either from
    /// `pharos_fork_choice::get_forkchoice_store` on cold start, or from
    /// `rehydrate_fork_choice_store` on warm restart). This constructor does
    /// not own rehydration; that is the binary startup path's responsibility
    /// (Task 2.7).
    pub fn new(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<pharos_fork_choice::Store<E>>>,
        genesis_validators_root: Root,
        fork_schedule: ForkSchedule,
        genesis_time_secs: u64,
        runtime_cfg: Arc<RuntimeConfig>,
    ) -> Self {
        let fork_context = ForkContextInner {
            genesis_validators_root,
            fork_schedule,
            genesis_time_secs,
        };

        Self {
            store,
            fork_choice,
            fork_context,
            metadata: RwLock::new(AltairMetaData {
                seq_number: 0,
                attnets: Bitvector::default(),
                syncnets: Bitvector::default(),
            }),
            runtime_cfg,
            last_forwarded_finality_slot: AtomicU64::new(0),
            last_forwarded_optimistic_slot: AtomicU64::new(0),
            last_forwarded_finality_slot_capella: AtomicU64::new(0),
            last_forwarded_optimistic_slot_capella: AtomicU64::new(0),
            head_tx: None,
            payload_tx: None,
            seen_block_proposers: RwLock::new(LruCache::new(NonZeroUsize::new(4096).unwrap())),
            proposer_cache: RwLock::new(LruCache::new(NonZeroUsize::new(1024).unwrap())),
            invalid_block_roots: RwLock::new(LruCache::new(NonZeroUsize::new(256).unwrap())),
            seen_attestation_validators: RwLock::new(LruCache::new(
                NonZeroUsize::new(131072).unwrap(),
            )),
            committee_cache: RwLock::new(LruCache::new(NonZeroUsize::new(4096).unwrap())),
            seen_aggregators: RwLock::new(LruCache::new(NonZeroUsize::new(8192).unwrap())),
            seen_aggregate_data: RwLock::new(LruCache::new(NonZeroUsize::new(2048).unwrap())),
            seen_voluntary_exit_indices: RwLock::new(LruCache::new(
                NonZeroUsize::new(4096).unwrap(),
            )),
            seen_proposer_slashing_indices: RwLock::new(LruCache::new(
                NonZeroUsize::new(4096).unwrap(),
            )),
            seen_attester_slashing_indices: RwLock::new(LruCache::new(
                NonZeroUsize::new(4096).unwrap(),
            )),
            seen_bls_to_execution_change_indices: RwLock::new(LruCache::new(
                NonZeroUsize::new(4096).unwrap(),
            )),
            op_pools: OperationPools::new(),
            _phantom: PhantomData,
        }
    }

    /// Wire the engine-driver channels into `HostImpl`.
    ///
    /// Must be called before `Arc::new(self)` so that `on_head_change` and
    /// `on_new_block` are live for the M4b/M4c gossip-validator path.
    ///
    /// Both senders must be clones of the same channels passed to
    /// `run_engine_driver_loop` / `run_block_ingestion_loop` in `main.rs`.
    pub fn wire_engine(
        &mut self,
        head_tx: watch::Sender<Option<HeadChange>>,
        payload_tx: mpsc::Sender<NewPayloadRequest<E>>,
    ) {
        self.head_tx = Some(head_tx);
        self.payload_tx = Some(payload_tx);
    }

    /// Send a new execution payload to the engine driver for validation.
    ///
    /// Called by the gossip-block ingestion path (Task 4.8b) once a Bellatrix
    /// block has been accepted by `on_block`. The engine driver calls
    /// `engine_newPayloadV1` and records the returned `PayloadStatus`.
    pub fn on_new_block(
        &self,
        block_root: Root,
        payload: pharos_engine::types::ExecutionPayloadV1,
    ) {
        if let Some(ref tx) = self.payload_tx {
            let req = NewPayloadRequest {
                block_root,
                payload: pharos_engine::NewPayloadWire::V1(payload),
                _marker: PhantomData,
            };
            // Best-effort: if the channel is full the ingestion loop has fallen
            // behind; log a warning and drop.
            if tx.try_send(req).is_err() {
                warn!(%block_root, "on_new_block: payload channel full or closed; dropping payload");
            }
        }
    }

    /// Publish a head-change event to the engine driver watch channel.
    ///
    /// Called by the block-ingestion loop (Task 4.8b) after each successful
    /// `get_head` computation.
    pub fn on_head_change(&self, change: HeadChange) {
        if let Some(ref tx) = self.head_tx {
            let _ = tx.send(Some(change));
        }
    }

    /// The fork schedule for this node.
    #[allow(dead_code)]
    pub fn fork_schedule(&self) -> &ForkSchedule {
        &self.fork_context.fork_schedule
    }

    // ── Private epoch/fork helpers ────────────────────────────────────────────

    /// Wall-clock epoch derived from `genesis_time_secs`.
    ///
    /// Uses the same ms-based arithmetic as `fork_migration.rs:77-85` so that
    /// sub-second slot durations (used in tests) don't round to zero:
    ///
    /// ```text
    /// elapsed_ms   = (now_secs - genesis_time_secs) * 1000
    /// elapsed_slots = elapsed_ms / SLOT_DURATION_MS
    /// epoch        = elapsed_slots / SLOTS_PER_EPOCH
    /// ```
    ///
    /// When `genesis_time_secs == 0` the epoch is always 0 (suitable for
    /// tests where no real genesis-time alignment is needed).
    fn current_epoch(&self) -> Epoch {
        let genesis_time_secs = self.fork_context.genesis_time_secs;
        if genesis_time_secs == 0 {
            return Epoch(0);
        }
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_secs < genesis_time_secs {
            return Epoch(0);
        }
        let elapsed_ms = (now_secs - genesis_time_secs).saturating_mul(1000);
        let slot_ms = E::SLOT_DURATION_MS.max(1);
        let elapsed_slots = elapsed_ms / slot_ms;
        Epoch(elapsed_slots / E::SLOTS_PER_EPOCH)
    }

    /// The fork version active at the current wall-clock epoch.
    fn current_fork_version_now(&self) -> Version {
        self.fork_context
            .fork_schedule
            .current_fork_version(self.current_epoch())
    }

    /// Return a clone of the `Arc<RocksStore>` backing this host.
    ///
    /// Used by the block-ingestion loop to pass the store into a
    /// `spawn_blocking` closure for LC snapshot writes (Task 2.2).
    pub fn store_arc(&self) -> Arc<RocksStore> {
        Arc::clone(&self.store)
    }

    /// Wall-clock delay the LC-gossip *publisher* must wait before broadcasting
    /// an update whose `signature_slot` is given, so the broadcast lands inside
    /// the spec's gossip window and is not rejected as `TooEarly`.
    ///
    /// Per `specs/altair/light-client/p2p-interface.md`, a compliant node only
    /// forwards a finality/optimistic update received after
    /// `get_sync_message_due_ms()` (one `INTERVALS_PER_SLOT` fraction into the
    /// slot) has transpired since the start of `signature_slot`. Broadcasting
    /// earlier earns a `light_client_gossip_error` peer penalty.
    ///
    /// This is the publish-side counterpart to the `due_ms` gate in
    /// `validate_light_client_{finality,optimistic}_update`. We wait until the
    /// full `due_ms` (no clock-disparity shaving) so the message stays inside
    /// the receiver's window even under modest clock skew. Returns
    /// `Duration::ZERO` when the window has already opened.
    /// Wall-clock delay until `slot` begins (its slot-start time). Returns
    /// `Duration::ZERO` if that slot has already started.
    ///
    /// Used by the block-import path to honour the fork-choice rule that a
    /// future block's "consideration must be delayed until they are in the
    /// past" (`fork-choice.md` on_block): instead of dropping a block that
    /// arrived a hair before its slot (clock skew within
    /// `MAXIMUM_GOSSIP_CLOCK_DISPARITY`), we re-inject it once its slot opens.
    pub fn wait_until_slot_start(&self, slot: u64) -> Duration {
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => return Duration::ZERO,
        };
        let genesis_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let slot_ms = u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let slot_start_ms = genesis_ms + u128::from(slot) * slot_ms;
        if now_ms >= slot_start_ms {
            Duration::ZERO
        } else {
            Duration::from_millis((slot_start_ms - now_ms) as u64)
        }
    }

    pub fn lc_publish_wait(&self, signature_slot: u64) -> Duration {
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => return Duration::ZERO,
        };
        let genesis_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let slot_ms = u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let slot_start_ms = genesis_ms + u128::from(signature_slot) * slot_ms;
        let due_ms = slot_start_ms + slot_ms / u128::from(INTERVALS_PER_SLOT);
        if now_ms >= due_ms {
            Duration::ZERO
        } else {
            Duration::from_millis((due_ms - now_ms) as u64)
        }
    }

    /// Update the local `attnets` field and bump `seq_number` if attnets changed.
    ///
    /// Spec: `p2p-interface.md:391-393`.
    /// Only bumps `seq_number` on a genuine change (idempotent on same value).
    /// Increment is wrapping per spec.
    pub fn record_attnets_change(&self, new_attnets: Bitvector<ATTESTATION_SUBNET_COUNT>) {
        let mut md = self.metadata.write();
        if md.attnets != new_attnets {
            md.attnets = new_attnets;
            md.seq_number = md.seq_number.wrapping_add(1);
        }
    }

    /// Return a clone of the head state advanced to `slot`.
    ///
    /// Mirrors `crates/pharos-fork-choice/src/handlers.rs:194-199`. Used by
    /// `validate_attestation` (step 1) and `validate_aggregate_and_proof`
    /// (Phase 3 step 1). Returns `None` when the head state is unavailable
    /// (e.g., during the checkpoint-sync window before the first block).
    fn head_state_at_slot(&self, slot: pharos_types::phase0::Slot) -> Option<E::BeaconState>
    where
        E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash,
        E::AltairBeaconState:
            pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
        E::BellatrixBeaconState:
            pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
        E::CapellaBeaconState: pharos_stf::CapellaProcessSlotsDispatch<E>,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
            >,
    {
        use pharos_stf::process_slots_fork;
        use pharos_types::BeaconStateView as _;

        let (head_root, fork_epochs) = {
            let fc = self.fork_choice.read();
            (pharos_fork_choice::get_head(&*fc), fc.fork_epochs())
        };
        let mut state = self
            .fork_choice
            .read()
            .block_states
            .get(&head_root)?
            .clone();
        if state.slot() < slot {
            process_slots_fork::<E>(&mut state, slot, fork_epochs, &self.runtime_cfg).ok()?;
        }
        Some(state)
    }

    /// Look up the committee for `(slot, index)` from cache, or compute it by
    /// advancing the head state.
    ///
    /// Cache key is `(slot, index, head_root)` per D-cache-key-on-head so that
    /// a reorg transparently invalidates stale entries.
    ///
    /// Returns `None` when the head state is unavailable or committee computation
    /// fails (caller should IGNORE).
    fn lookup_or_compute_committee(
        &self,
        slot: pharos_types::phase0::Slot,
        index: u64,
    ) -> Option<Vec<u64>>
    where
        E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash,
        E::AltairBeaconState:
            pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
        E::BellatrixBeaconState:
            pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
        E::CapellaBeaconState: pharos_stf::CapellaProcessSlotsDispatch<E>,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
            >,
    {
        use pharos_stf::phase0::accessors::get_beacon_committee;
        use pharos_stf::process_slots_fork;
        use pharos_types::BeaconStateView as _;

        let (head_root, fork_epochs) = {
            let fc = self.fork_choice.read();
            (pharos_fork_choice::get_head(&*fc), fc.fork_epochs())
        };

        let cache_key = (slot, index, head_root);

        // Fast path: peek cache (preserves LRU order on read path).
        if let Some(committee) = self.committee_cache.read().peek(&cache_key) {
            return Some(committee.clone());
        }

        // Slow path: advance head state to `slot` and compute committee.
        let mut state = self
            .fork_choice
            .read()
            .block_states
            .get(&head_root)?
            .clone();
        if state.slot() < slot {
            process_slots_fork::<E>(&mut state, slot, fork_epochs, &self.runtime_cfg).ok()?;
        }
        let committee: Vec<u64> = get_beacon_committee::<E>(&state, slot, index)
            .iter()
            .map(|vi| vi.0)
            .collect();
        self.committee_cache
            .write()
            .put(cache_key, committee.clone());
        Some(committee)
    }

    /// Look up the expected proposer for `(slot, parent_root)` from the cache,
    /// or compute it by advancing the parent state to `slot`.
    ///
    /// Returns `Some((expected_proposer_index, state_at_slot))` on success.
    /// Returns `None` when the parent state is not in the fork-choice store
    /// (caller should IGNORE in that case).
    ///
    /// The cache is keyed on `(slot, parent_root) → u64`; the state clone is
    /// returned on both cache-hit and cache-miss so the signature-verify step
    /// (step 11) can reuse it without re-acquiring the fork-choice lock.
    fn lookup_or_compute_expected_proposer(
        &self,
        slot: pharos_types::phase0::Slot,
        parent_root: Root,
    ) -> Option<(u64, E::BeaconState)>
    where
        E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash,
        E::AltairBeaconState:
            pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
        E::BellatrixBeaconState:
            pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
        E::CapellaBeaconState: pharos_stf::CapellaProcessSlotsDispatch<E>,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
            >,
    {
        use pharos_stf::phase0::accessors::get_beacon_proposer_index;
        use pharos_stf::process_slots_fork;
        use pharos_types::BeaconStateView as _;

        let fork_epochs = self.fork_choice.read().fork_epochs();

        // Fast path: check cache (peek preserves LRU order on the read path).
        if let Some(&idx) = self.proposer_cache.read().peek(&(slot, parent_root)) {
            // Re-fetch parent state to advance to slot for signature verification.
            let mut parent_state = self
                .fork_choice
                .read()
                .block_states
                .get(&parent_root)?
                .clone();
            if parent_state.slot() < slot {
                process_slots_fork::<E>(&mut parent_state, slot, fork_epochs, &self.runtime_cfg)
                    .ok()?;
            }
            return Some((idx, parent_state));
        }

        // Slow path: advance parent state to `slot` and compute proposer.
        let mut parent_state = self
            .fork_choice
            .read()
            .block_states
            .get(&parent_root)?
            .clone();
        if parent_state.slot() < slot {
            process_slots_fork::<E>(&mut parent_state, slot, fork_epochs, &self.runtime_cfg)
                .ok()?;
        }
        let idx = get_beacon_proposer_index::<E>(&parent_state).0;
        self.proposer_cache.write().put((slot, parent_root), idx);
        Some((idx, parent_state))
    }
}

// ── ForkContext ───────────────────────────────────────────────────────────────

impl<E: EthSpec> ForkContext for HostImpl<E> {
    /// Compute the current fork digest from the wall-clock epoch.
    ///
    /// Computed on every call from `fork_schedule.current_fork_version(current_epoch())`
    /// combined with `genesis_validators_root`. No frozen field; the value tracks the
    /// epoch boundary automatically. (ADR `D-epoch-driven-fork-digest`.)
    fn current_fork_digest(&self) -> ForkDigest {
        let gvr = &self.fork_context.genesis_validators_root;
        compute_fork_digest(self.current_fork_version_now(), gvr)
    }

    /// Returns the ENR fork ID for the current epoch.
    ///
    /// `fork_digest` reflects the active fork; `next_fork_version` and
    /// `next_fork_epoch` are taken from the fork schedule so that ENR
    /// announcements remain correct across fork boundaries.
    fn enr_fork_id(&self) -> ENRForkID {
        let epoch = self.current_epoch();
        ENRForkID {
            fork_digest: self.current_fork_digest(),
            next_fork_version: self.fork_context.fork_schedule.next_fork_version(epoch),
            next_fork_epoch: self.fork_context.fork_schedule.next_fork_epoch(epoch),
        }
    }

    fn genesis_validators_root(&self) -> Root {
        self.fork_context.genesis_validators_root
    }

    /// Returns the fork digest for the given network `Fork`.
    ///
    /// Each fork maps to its own version field in `fork_schedule`, so all
    /// three digests are distinct (Phase0 ≠ Altair ≠ Bellatrix) whenever the
    /// schedule has distinct version bytes.
    fn fork_digest_for(&self, fork: Fork) -> ForkDigest {
        let sched = &self.fork_context.fork_schedule;
        let version = match fork {
            Fork::Phase0 => sched.genesis_fork_version,
            Fork::Altair => sched.altair_fork_version,
            Fork::Bellatrix => sched.bellatrix_fork_version,
            Fork::Capella => sched.capella_fork_version,
        };
        compute_fork_digest(version, &self.fork_context.genesis_validators_root)
    }

    /// Reverse-maps a raw 4-byte context to a `Fork`.
    ///
    /// Computes the four known fork digests on the fly and compares against
    /// `ctx`. Returns `None` for any unrecognised context bytes.
    fn fork_from_context(&self, ctx: &[u8; 4]) -> Option<Fork> {
        let gvr = &self.fork_context.genesis_validators_root;
        let sched = &self.fork_context.fork_schedule;
        let phase0_digest = compute_fork_digest(sched.genesis_fork_version, gvr);
        if *ctx == phase0_digest.into_inner() {
            return Some(Fork::Phase0);
        }
        let altair_digest = compute_fork_digest(sched.altair_fork_version, gvr);
        if *ctx == altair_digest.into_inner() {
            return Some(Fork::Altair);
        }
        let bellatrix_digest = compute_fork_digest(sched.bellatrix_fork_version, gvr);
        if *ctx == bellatrix_digest.into_inner() {
            return Some(Fork::Bellatrix);
        }
        let capella_digest = compute_fork_digest(sched.capella_fork_version, gvr);
        if *ctx == capella_digest.into_inner() {
            return Some(Fork::Capella);
        }
        None
    }

    fn local_metadata(&self) -> AltairMetaData {
        self.metadata.read().clone()
    }
}

// ── BlockProvider ─────────────────────────────────────────────────────────────

impl<E: EthSpec> BlockProvider<E> for HostImpl<E> {
    /// Look up a block by root.
    ///
    /// Returns `None` on storage error (logged at `warn`) or missing block.
    fn block_by_root(&self, root: Root) -> Option<E::SignedBeaconBlock> {
        match <RocksStore as StoreTrait<E>>::get_block(&self.store, &root) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(%e, %root, "block_by_root: storage error");
                None
            }
        }
    }

    /// Retrieve a range of blocks starting at `start_slot`.
    ///
    /// Returns an empty vec on storage error.
    fn blocks_by_range(&self, start_slot: Slot, count: u64) -> Vec<E::SignedBeaconBlock> {
        match <RocksStore as StoreTrait<E>>::get_blocks_by_range(&self.store, start_slot, count) {
            Ok(blocks) => blocks,
            Err(e) => {
                warn!(%e, %start_slot, count, "blocks_by_range: storage error");
                vec![]
            }
        }
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        self.fork_choice.read().finalized_checkpoint.clone()
    }

    /// The current chain head `(block_root, slot)`.
    ///
    /// Calls `get_head` for the LMD-GHOST head root; looks up the slot from
    /// `fork_choice.blocks`. Falls back to `(finalized_checkpoint.root,
    /// finalized_block.slot())` when the head block root is not found in the
    /// block map (e.g. during abnormal state) so this method does not panic.
    fn head(&self) -> (Root, Slot) {
        use pharos_types::views::BeaconBlockView;
        let fc = self.fork_choice.read();
        let head_root = pharos_fork_choice::get_head(&*fc);
        if let Some(block) = fc.blocks.get(&head_root) {
            (head_root, block.slot())
        } else {
            warn!(%head_root, "head block not found in fork-choice store; falling back to finalized");
            let fin = &fc.finalized_checkpoint;
            let fin_slot = fc
                .blocks
                .get(&fin.root)
                .map(|b| b.slot())
                .unwrap_or(Slot(0));
            (fin.root, fin_slot)
        }
    }
}

// ── GossipValidator ───────────────────────────────────────────────────────────

impl<E: EthSpec> GossipValidator<E> for HostImpl<E>
where
    E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash,
    E::AltairBeaconState:
        pharos_stf::AltairProcessSlotsDispatch<E> + pharos_stf::AltairUpgradeDispatch<E>,
    E::BellatrixBeaconState:
        pharos_stf::BellatrixProcessSlotsDispatch<E> + pharos_stf::BellatrixUpgradeDispatch<E>,
    E::CapellaBeaconState: pharos_stf::CapellaProcessSlotsDispatch<E>,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = pharos_types::phase0::Attestation<2048>,
        >,
    E::Phase0SignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock:
        pharos_types::views::SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
{
    /// Validate a gossip `beacon_block` message per `specs/phase0/p2p-interface.md:540-620`.
    ///
    /// Implements the 12-step pipeline:
    ///   1. RB7 — parent in invalid-roots cache (REJECT).
    ///   2. RB1 — future slot (IGNORE).
    ///   3. RB2 — at or below finalized slot (IGNORE).
    ///   4. RB3 — duplicate proposer/slot (IGNORE).
    ///   5. RB4 — proposer index out of range (REJECT).
    ///   6. RB6 — parent unseen (IGNORE).
    ///   7. Defensive parent-state-missing guard (REJECT).
    ///   8. RB8 — block not higher than parent slot (REJECT).
    ///   9. RB9 — finalized not ancestor (REJECT).
    ///  10. RB10 — proposer mismatch (REJECT) or shuffling unavailable (IGNORE).
    ///  11. RB5 — invalid proposer signature (REJECT).
    ///  12. Insert into seen-proposers cache; return Accept.
    ///
    /// See `D-bls-on-hot-path`, `D-invalid-roots-cache`, `D-seen-cache-after-accept`.
    fn validate_beacon_block(&self, block: &E::SignedBeaconBlock) -> GossipVerdict {
        use pharos_ssz::TreeHash;
        use pharos_stf::phase0::accessors::{
            compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch, get_domain,
        };
        use pharos_stf::phase0::helpers::DOMAIN_BEACON_PROPOSER;
        use pharos_types::BeaconStateView as _;
        use pharos_types::views::{BeaconBlockView, SignedBeaconBlockView};

        // Extract the fork-enum `E::BeaconBlock` from the signed block via the
        // exhaustive-match dispatch on `EthSpec`. This cannot miss a fork variant
        // (a new fork is a compile error in `signed_block_message`), unlike the
        // old per-fork `if let` chain that silently rejected capella blocks.
        let block_msg: E::BeaconBlock = E::signed_block_message(block);

        // Compute block_root once; reused by steps 8/9/10/11 cache inserts.
        let block_root: Root = block_msg.tree_hash_root();

        // Step 1 — RB7: parent block is in the invalid-roots set (REJECT).
        if self
            .invalid_block_roots
            .read()
            .peek(&block_msg.parent_root())
            .is_some()
        {
            return GossipVerdict::Reject("block: parent in invalid set".into());
        }

        // Step 2 — RB1: block is from a future slot (IGNORE).
        let genesis_time_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let slot_time_ms = genesis_time_ms
            + u128::from(block_msg.slot().0) * u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => {
                return GossipVerdict::Ignore("block: clock unavailable".into());
            }
        };
        if now_ms + u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS) < slot_time_ms {
            return GossipVerdict::Ignore("block: from future slot".into());
        }

        // Step 3 — RB2: block is not from a slot greater than the latest finalized slot (IGNORE).
        {
            let fc = self.fork_choice.read();
            let finalized_slot =
                compute_start_slot_at_epoch(fc.finalized_checkpoint.epoch, E::SLOTS_PER_EPOCH);
            if block_msg.slot() <= finalized_slot {
                return GossipVerdict::Ignore("block: not greater than finalized slot".into());
            }
        }

        // Step 4 — RB3: first block for this proposer for the slot (IGNORE duplicate).
        if self
            .seen_block_proposers
            .read()
            .peek(&(block_msg.slot(), block_msg.proposer_index().0))
            .is_some()
        {
            return GossipVerdict::Ignore("block: duplicate proposer/slot".into());
        }

        // Steps 5–7 and 8 require the fork-choice lock; acquire once and hold
        // through step 9, then drop before calling lookup_or_compute_expected_proposer.
        let (parent_slot, finalized_checkpoint) = {
            let fc = self.fork_choice.read();

            // Step 5 — RB4: proposer index out of range (REJECT).
            if let Some(state) = fc.block_states.get(&block_msg.parent_root()) {
                if block_msg.proposer_index().0 as usize >= state.num_validators() {
                    return GossipVerdict::Reject("block: proposer index out of range".into());
                }
            }
            // (If state is None, fall through — RB6 below handles missing parent.)

            // Step 6 — RB6: block's parent has been seen (IGNORE if unseen).
            if !fc.blocks.contains_key(&block_msg.parent_root()) {
                return GossipVerdict::Ignore(GOSSIP_REASON_PARENT_UNSEEN.into());
            }

            // Step 7 — defensive: parent is in blocks but state is missing (REJECT).
            if !fc.block_states.contains_key(&block_msg.parent_root()) {
                return GossipVerdict::Reject("block: parent invalid".into());
            }

            // Step 8 — RB8: block is from a higher slot than its parent (REJECT).
            let parent_slot = fc.blocks.get(&block_msg.parent_root()).unwrap().slot();
            if block_msg.slot() <= parent_slot {
                self.invalid_block_roots.write().put(block_root, ());
                return GossipVerdict::Reject("block: not higher than parent slot".into());
            }

            (parent_slot, fc.finalized_checkpoint.clone())
        };
        let _ = parent_slot; // consumed above

        // Step 9 — RB9: current finalized checkpoint is an ancestor of the block (REJECT).
        {
            let fc = self.fork_choice.read();
            let cp = pharos_fork_choice::get_checkpoint_block::<E>(
                &*fc,
                block_msg.parent_root(),
                finalized_checkpoint.epoch,
            );
            if cp != finalized_checkpoint.root {
                self.invalid_block_roots.write().put(block_root, ());
                return GossipVerdict::Reject("block: finalized not ancestor".into());
            }
        }

        // Step 10 — RB10: block is proposed by the expected proposer (REJECT/IGNORE).
        // Drop the fc read guard before calling the helper (it re-acquires).
        let (expected_idx, parent_state_at_slot) = match self
            .lookup_or_compute_expected_proposer(block_msg.slot(), block_msg.parent_root())
        {
            None => {
                return GossipVerdict::Ignore("block: shuffling unavailable".into());
            }
            Some(pair) => pair,
        };
        if expected_idx != block_msg.proposer_index().0 {
            self.invalid_block_roots.write().put(block_root, ());
            return GossipVerdict::Reject("block: proposer mismatch".into());
        }

        // Step 11 — RB5: proposer signature is valid (REJECT).
        {
            let block_epoch = compute_epoch_at_slot(block_msg.slot(), E::SLOTS_PER_EPOCH);
            let domain = get_domain::<E>(
                &parent_state_at_slot,
                DOMAIN_BEACON_PROPOSER,
                Some(block_epoch),
            );
            let signing_root = compute_signing_root(&block_msg, domain);
            let pubkey = match parent_state_at_slot.validator(block_msg.proposer_index().0 as usize)
            {
                Some(v) => v.pubkey,
                None => {
                    self.invalid_block_roots.write().put(block_root, ());
                    return GossipVerdict::Reject("block: proposer index out of range".into());
                }
            };
            match pharos_utils::bls::verify(&pubkey, signing_root.as_ref(), block.signature()) {
                Ok(true) => {}
                Ok(false) => {
                    self.invalid_block_roots.write().put(block_root, ());
                    return GossipVerdict::Reject("block: invalid proposer signature".into());
                }
                Err(_) => {
                    self.invalid_block_roots.write().put(block_root, ());
                    return GossipVerdict::Reject("block: invalid proposer signature".into());
                }
            }
        }

        // Step 12 — insert into seen-proposers cache and accept.
        self.seen_block_proposers
            .write()
            .put((block_msg.slot(), block_msg.proposer_index().0), ());
        GossipVerdict::Accept
    }

    /// Validate a gossip unaggregated attestation per
    /// `specs/phase0/p2p-interface.md:929-1013` (rules RAT1-RAT12).
    ///
    /// Step order:
    ///   1.  Defensive — head state unavailable (IGNORE, covers checkpoint-sync window).
    ///   2.  RAT1  — committee index out of range (REJECT).
    ///   3.  RAT2  — attestation is for the correct subnet (REJECT).
    ///   4.  RAT3  — attestation slot within propagation range (IGNORE).
    ///   5.  RAT4  — attestation's epoch matches its target (REJECT).
    ///   6.  RAT5  — attestation is unaggregated (exactly one bit set) (REJECT).
    ///   7.  RAT6  — aggregation bits length matches committee size (REJECT).
    ///   8.  RAT7  — no other valid attestation seen for this validator/epoch (IGNORE).
    ///   9.  RAT8  — attestation signature is valid (REJECT).
    ///  10.  RAT9  — block being voted for has been seen (IGNORE).
    ///  11.  RAT10 — block being voted for passes validation (REJECT).
    ///  12.  RAT11 — target block is ancestor of LMD vote block (REJECT).
    ///  13.  RAT12 — finalized checkpoint is an ancestor of the block (IGNORE).
    ///  14.  Insert into seen cache; return Accept.
    ///
    /// See `D-seen-cache-after-accept`, `D-cache-key-on-head`,
    /// `D-bls-on-hot-path` in `docs/decisions.md`.
    fn validate_attestation(&self, subnet: SubnetId, att: &Attestation<2048>) -> GossipVerdict {
        use pharos_stf::phase0::accessors::{
            compute_epoch_at_slot, compute_subnet_for_attestation, get_committee_count_per_slot,
            get_indexed_attestation,
        };
        use pharos_stf::phase0::predicates::is_valid_indexed_attestation;
        use pharos_types::phase0::primitives::{
            ATTESTATION_PROPAGATION_SLOT_RANGE, MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
        };

        // Step 1 — Defensive: head state must be available.
        let head_state = match self.head_state_at_slot(att.data.slot) {
            Some(s) => s,
            None => return GossipVerdict::Ignore("att: head state unavailable".into()),
        };

        // Step 2 — RAT1: committee index must be within range.
        // Compute committee count for the attestation's slot-epoch, not its
        // target epoch: RAT4 below enforces equality, but RAT1 runs first.
        let att_epoch = compute_epoch_at_slot(att.data.slot, E::SLOTS_PER_EPOCH);
        let committee_count = get_committee_count_per_slot::<E>(&head_state, att_epoch);
        if att.data.index.0 >= committee_count {
            return GossipVerdict::Reject("att: committee index out of range".into());
        }

        // Step 3 — RAT2: attestation must be for the correct subnet.
        let expected_subnet =
            compute_subnet_for_attestation::<E>(committee_count, att.data.slot, att.data.index.0);
        if expected_subnet != subnet {
            return GossipVerdict::Reject("att: wrong subnet".into());
        }

        // Step 4 — RAT3: attestation slot must be within propagation range.
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => return GossipVerdict::Ignore("att: clock unavailable".into()),
        };
        let genesis_time_s = self.fork_choice.read().genesis_time;
        let seconds_per_slot = self.runtime_cfg.seconds_per_slot;
        let att_slot = att.data.slot.0;
        let range = ATTESTATION_PROPAGATION_SLOT_RANGE;
        let start_time_ms = genesis_time_s * 1000 + att_slot * seconds_per_slot * 1000;
        let end_time_ms = genesis_time_s * 1000 + (att_slot + range + 1) * seconds_per_slot * 1000;
        if now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < start_time_ms
            || end_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < now_ms
        {
            return GossipVerdict::Ignore("att: slot not in propagation range".into());
        }

        // Step 5 — RAT4: attestation's epoch must match its target.
        if att.data.target.epoch != compute_epoch_at_slot(att.data.slot, E::SLOTS_PER_EPOCH) {
            return GossipVerdict::Reject("att: target epoch mismatch".into());
        }

        // Step 6 — RAT5: attestation must be unaggregated (exactly one bit set).
        let num_bits_set = att.aggregation_bits.iter().filter(|b| *b).count();
        if num_bits_set != 1 {
            return GossipVerdict::Reject("att: not unaggregated".into());
        }

        // Step 7 — RAT6: aggregation bits length must match committee size.
        let committee = match self.lookup_or_compute_committee(att.data.slot, att.data.index.0) {
            Some(c) => c,
            None => return GossipVerdict::Ignore("att: committee unavailable".into()),
        };
        if att.aggregation_bits.len() != committee.len() {
            return GossipVerdict::Reject("att: agg bits length mismatch".into());
        }

        // Step 8 — RAT7: no other valid attestation seen for this validator/epoch.
        // Safe: step 6 confirmed exactly one bit is set.
        let bit_idx = att.aggregation_bits.iter().position(|b| b).unwrap();
        let participant = committee[bit_idx];
        if self
            .seen_attestation_validators
            .read()
            .peek(&(participant, att.data.target.epoch))
            .is_some()
        {
            return GossipVerdict::Ignore("att: duplicate validator/epoch".into());
        }

        // Step 9 — RAT8: attestation signature must be valid.
        let indexed = get_indexed_attestation::<E>(&head_state, att);
        if !is_valid_indexed_attestation::<E>(&head_state, &indexed, true) {
            return GossipVerdict::Reject("att: invalid signature".into());
        }

        // Steps 10-12 require the fork-choice lock; acquire once.
        {
            let fc = self.fork_choice.read();

            // Step 10 — RAT9: block being voted for must have been seen.
            if !fc.blocks.contains_key(&att.data.beacon_block_root) {
                return GossipVerdict::Ignore("att: voted block unseen".into());
            }

            // Step 11 — RAT10: block being voted for must pass validation.
            if !fc.block_states.contains_key(&att.data.beacon_block_root) {
                return GossipVerdict::Reject("att: voted block invalid".into());
            }

            // Step 12 — RAT11: target block must be an ancestor of the LMD vote block.
            let target_cp = pharos_fork_choice::get_checkpoint_block::<E>(
                &*fc,
                att.data.beacon_block_root,
                att.data.target.epoch,
            );
            if target_cp != att.data.target.root {
                return GossipVerdict::Reject("att: target not ancestor".into());
            }

            // Step 13 — RAT12: finalized checkpoint must be an ancestor of the block.
            let final_cp = pharos_fork_choice::get_checkpoint_block::<E>(
                &*fc,
                att.data.beacon_block_root,
                fc.finalized_checkpoint.epoch,
            );
            if final_cp != fc.finalized_checkpoint.root {
                return GossipVerdict::Ignore("att: finalized not ancestor".into());
            }
        }

        // Step 14 — Insert into seen-validators cache and accept.
        self.seen_attestation_validators
            .write()
            .put((participant, att.data.target.epoch), ());
        // Feed the operation pool: insert the accepted unaggregated attestation
        // so block-production can aggregate it (Task 2.4).
        self.op_pools.insert_attestation(att.clone());
        GossipVerdict::Accept
    }

    /// Validate a gossip `beacon_aggregate_and_proof` per
    /// `specs/phase0/p2p-interface.md:629-737` (rules RAG1-RAG16).
    ///
    /// Step order:
    ///   1.  RAG1  — committee index within range (REJECT).
    ///   2.  RAG2  — aggregate slot within propagation range (IGNORE).
    ///   3.  RAG3  — target epoch matches slot epoch (REJECT).
    ///   4.  RAG4  — aggregation bits length matches committee size (REJECT).
    ///   5.  RAG5  — aggregate has at least one participant (REJECT).
    ///   6.  RAG6  — weakened superset check: bits not fully covered (IGNORE).
    ///   7.  RAG7  — first valid aggregate from this aggregator this epoch (IGNORE).
    ///   8.  RAG8  — selection proof selects validator as aggregator (REJECT).
    ///   9.  RAG9  — aggregator index is within committee (REJECT).
    ///  10.  RAG10 — selection-proof signature is valid (REJECT).
    ///  11.  RAG11 — aggregator signature over AggregateAndProof is valid (REJECT).
    ///  12.  RAG12 — aggregate signature valid (via indexed attestation) (REJECT).
    ///  13.  RAG13 — voted block has been seen (IGNORE).
    ///  14.  RAG14 — voted block passes validation (REJECT).
    ///  15.  RAG15 — target block is an ancestor of the LMD vote block (REJECT).
    ///  16.  RAG16 — finalized checkpoint is an ancestor of the block (IGNORE).
    ///  17.  Insert into seen caches; return Accept.
    fn validate_aggregate_and_proof(&self, saap: &SignedAggregateAndProof<2048>) -> GossipVerdict
    where
        E::BeaconState: pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash,
        E::AltairBeaconState: pharos_stf::AltairProcessSlotsDispatch<E>,
        E::BellatrixBeaconState: pharos_stf::BellatrixProcessSlotsDispatch<E>,
        E::CapellaBeaconState: pharos_stf::CapellaProcessSlotsDispatch<E>,
        E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
                Attestation = pharos_types::phase0::Attestation<2048>,
            >,
    {
        use pharos_ssz::TreeHash as _;
        use pharos_stf::phase0::accessors::{
            compute_epoch_at_slot, compute_signing_root, get_attesting_indices,
            get_committee_count_per_slot, get_domain, get_indexed_attestation,
        };
        use pharos_stf::phase0::helpers::{DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF};
        use pharos_stf::phase0::predicates::{is_aggregator, is_valid_indexed_attestation};
        use pharos_types::BeaconStateView as _;
        use pharos_types::phase0::primitives::{
            ATTESTATION_PROPAGATION_SLOT_RANGE, MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
        };

        let agg = &saap.message.aggregate;

        // Step 1 — RAG1: committee index must be within range.
        // Use compute_epoch_at_slot on agg.data.slot (not target epoch) per Phase 2 follow-up.
        let head_state = match self.head_state_at_slot(agg.data.slot) {
            Some(s) => s,
            None => return GossipVerdict::Ignore("agg: head state unavailable".into()),
        };
        let att_epoch = compute_epoch_at_slot(agg.data.slot, E::SLOTS_PER_EPOCH);
        let committee_count = get_committee_count_per_slot::<E>(&head_state, att_epoch);
        if agg.data.index.0 >= committee_count {
            return GossipVerdict::Reject("agg: committee index out of range".into());
        }

        // Step 2 — RAG2: aggregate slot must be within propagation range.
        let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => return GossipVerdict::Ignore("agg: clock unavailable".into()),
        };
        let genesis_time_s = self.fork_choice.read().genesis_time;
        let seconds_per_slot = self.runtime_cfg.seconds_per_slot;
        let agg_slot = agg.data.slot.0;
        let range = ATTESTATION_PROPAGATION_SLOT_RANGE;
        let start_time_ms = genesis_time_s * 1000 + agg_slot * seconds_per_slot * 1000;
        let end_time_ms = genesis_time_s * 1000 + (agg_slot + range + 1) * seconds_per_slot * 1000;
        if now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < start_time_ms
            || end_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < now_ms
        {
            return GossipVerdict::Ignore("agg: slot not in propagation range".into());
        }

        // Step 3 — RAG3: target epoch must match slot epoch.
        if agg.data.target.epoch != compute_epoch_at_slot(agg.data.slot, E::SLOTS_PER_EPOCH) {
            return GossipVerdict::Reject("agg: target epoch mismatch".into());
        }

        // Step 4 — RAG4: aggregation bits length must match committee size.
        let committee = match self.lookup_or_compute_committee(agg.data.slot, agg.data.index.0) {
            Some(c) => c,
            None => return GossipVerdict::Ignore("agg: committee unavailable".into()),
        };
        if agg.aggregation_bits.len() != committee.len() {
            return GossipVerdict::Reject("agg: agg bits length mismatch".into());
        }

        // Step 5 — RAG5: aggregate must have at least one participant.
        let attesting_indices =
            get_attesting_indices::<E>(&head_state, &agg.data, &agg.aggregation_bits);
        if attesting_indices.is_empty() {
            return GossipVerdict::Reject("agg: no participants".into());
        }

        // Step 6 — RAG6: weakened-superset check.
        // IGNORE iff every set bit in incoming is already set in the stored OR-bitlist.
        let data_root = agg.data.tree_hash_root();
        {
            let read = self.seen_aggregate_data.read();
            if let Some(stored) = read.peek(&data_root) {
                let mut covered = true;
                for (i, b) in agg.aggregation_bits.iter().enumerate() {
                    if b && !stored.get(i).unwrap_or(false) {
                        covered = false;
                        break;
                    }
                }
                if covered {
                    return GossipVerdict::Ignore("agg: superset seen".into());
                }
            }
        }

        // Step 7 — RAG7: first valid aggregate from this aggregator this epoch.
        let aggregator_index = saap.message.aggregator_index.0;
        let target_epoch = agg.data.target.epoch;
        if self
            .seen_aggregators
            .read()
            .peek(&(aggregator_index, target_epoch))
            .is_some()
        {
            return GossipVerdict::Ignore("agg: duplicate aggregator/epoch".into());
        }

        // Step 8 — RAG8: selection proof must select validator as aggregator.
        if !is_aggregator(committee.len(), &saap.message.selection_proof) {
            return GossipVerdict::Reject("agg: not selected as aggregator".into());
        }

        // Step 9 — RAG9: aggregator index must be within committee.
        if !committee.contains(&aggregator_index) {
            return GossipVerdict::Reject("agg: aggregator not in committee".into());
        }

        // Step 10 — RAG10: selection-proof signature must be valid.
        let aggregator_pubkey = match head_state.validator(aggregator_index as usize) {
            Some(v) => v.pubkey,
            None => return GossipVerdict::Reject("agg: aggregator index out of range".into()),
        };
        let domain_sel = get_domain::<E>(&head_state, DOMAIN_SELECTION_PROOF, Some(target_epoch));
        let signing_root_sel = compute_signing_root(&agg.data.slot, domain_sel);
        match pharos_utils::bls::verify(
            &aggregator_pubkey,
            signing_root_sel.as_ref(),
            &saap.message.selection_proof,
        ) {
            Ok(true) => {}
            _ => return GossipVerdict::Reject("agg: invalid selection proof signature".into()),
        }

        // Step 11 — RAG11: aggregator signature over AggregateAndProof must be valid.
        let domain_aap =
            get_domain::<E>(&head_state, DOMAIN_AGGREGATE_AND_PROOF, Some(target_epoch));
        let signing_root_aap = compute_signing_root(&saap.message, domain_aap);
        match pharos_utils::bls::verify(
            &aggregator_pubkey,
            signing_root_aap.as_ref(),
            &saap.signature,
        ) {
            Ok(true) => {}
            _ => return GossipVerdict::Reject("agg: invalid aggregator signature".into()),
        }

        // Step 12 — RAG12: aggregate signature must be valid.
        let indexed = get_indexed_attestation::<E>(&head_state, agg);
        if !is_valid_indexed_attestation::<E>(&head_state, &indexed, true) {
            return GossipVerdict::Reject("agg: invalid aggregate signature".into());
        }

        // Steps 13-16 require the fork-choice lock; acquire once.
        {
            let fc = self.fork_choice.read();

            // Step 13 — RAG13: voted block must have been seen.
            if !fc.blocks.contains_key(&agg.data.beacon_block_root) {
                return GossipVerdict::Ignore("agg: voted block unseen".into());
            }

            // Step 14 — RAG14: voted block must pass validation.
            if !fc.block_states.contains_key(&agg.data.beacon_block_root) {
                return GossipVerdict::Reject("agg: voted block invalid".into());
            }

            // Step 15 — RAG15: target block must be an ancestor of the LMD vote block.
            let target_cp = pharos_fork_choice::get_checkpoint_block::<E>(
                &*fc,
                agg.data.beacon_block_root,
                target_epoch,
            );
            if target_cp != agg.data.target.root {
                return GossipVerdict::Reject("agg: target not ancestor".into());
            }

            // Step 16 — RAG16: finalized checkpoint must be an ancestor of the block.
            let final_cp = pharos_fork_choice::get_checkpoint_block::<E>(
                &*fc,
                agg.data.beacon_block_root,
                fc.finalized_checkpoint.epoch,
            );
            if final_cp != fc.finalized_checkpoint.root {
                return GossipVerdict::Ignore("agg: finalized not ancestor".into());
            }
        }

        // Step 17 — Insert into seen caches and accept.
        self.seen_aggregators
            .write()
            .put((aggregator_index, target_epoch), ());
        {
            let mut write = self.seen_aggregate_data.write();
            let stored = write.get_or_insert_mut(data_root, || {
                let mut bl = pharos_ssz::Bitlist::<2048>::with_capacity(committee.len());
                for _ in 0..committee.len() {
                    // push(false) initialises bit_len to committee.len()
                    let _ = bl.push(false);
                }
                bl
            });
            for (i, b) in agg.aggregation_bits.iter().enumerate() {
                if b {
                    stored.set(i, true);
                }
            }
        }
        // Feed the operation pool: insert the accepted aggregate attestation
        // (Task 2.4). The aggregate is extracted from the `AggregateAndProof`.
        self.op_pools
            .insert_attestation(saap.message.aggregate.clone());
        GossipVerdict::Accept
    }

    /// Validate a `voluntary_exit` message per `specs/phase0/p2p-interface.md:740-793`.
    ///
    /// 1 IGNORE + 6 REJECT rules (per spec), + mark-seen on accept.
    /// Per `D-folded-phase0-validators` in `docs/decisions.md`.
    fn validate_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> GossipVerdict {
        use pharos_stf::phase0::accessors::{
            compute_epoch_at_slot, compute_signing_root, get_domain,
        };
        use pharos_stf::phase0::helpers::DOMAIN_VOLUNTARY_EXIT;
        use pharos_stf::phase0::predicates::is_active_validator;
        use pharos_types::BeaconStateView as _;

        let voluntary_exit = &exit.message;
        let validator_index = voluntary_exit.validator_index.0;

        // [IGNORE] First valid voluntary exit for this validator.
        if self
            .seen_voluntary_exit_indices
            .read()
            .peek(&validator_index)
            .is_some()
        {
            return GossipVerdict::Ignore("exit: already seen for this validator".into());
        }

        // Get the head state for subsequent checks (two-step to avoid double-lock).
        let head_root = pharos_fork_choice::get_head(&*self.fork_choice.read());
        let head_state = match self
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
        {
            Some(s) => s,
            None => return GossipVerdict::Ignore("exit: head state unavailable".into()),
        };

        let num_validators = head_state.num_validators();
        let current_epoch = compute_epoch_at_slot(head_state.slot(), E::SLOTS_PER_EPOCH);

        // [REJECT] Validator index must be in range.
        if validator_index as usize >= num_validators {
            return GossipVerdict::Reject("exit: validator index out of range".into());
        }

        let validator = match head_state.validator(validator_index as usize) {
            Some(v) => v,
            None => return GossipVerdict::Reject("exit: validator index out of range".into()),
        };

        // [REJECT] Validator must be active.
        if !is_active_validator(validator, current_epoch.0) {
            return GossipVerdict::Reject("exit: validator not active".into());
        }

        // [REJECT] Validator must not have already initiated exit.
        if validator.exit_epoch.0 != u64::MAX {
            return GossipVerdict::Reject("exit: validator already exiting".into());
        }

        // [REJECT] Exit epoch must not be in the future (current_epoch >= voluntary_exit.epoch).
        if current_epoch < voluntary_exit.epoch {
            return GossipVerdict::Reject("exit: exit epoch in the future".into());
        }

        // [REJECT] Validator must have been active long enough (SHARD_COMMITTEE_PERIOD).
        if current_epoch.0 < validator.activation_epoch.0 + E::SHARD_COMMITTEE_PERIOD {
            return GossipVerdict::Reject("exit: validator not active long enough".into());
        }

        // [REJECT] BLS signature must be valid.
        let domain = get_domain::<E>(
            &head_state,
            DOMAIN_VOLUNTARY_EXIT,
            Some(voluntary_exit.epoch),
        );
        let signing_root = compute_signing_root(voluntary_exit, domain);
        match pharos_utils::bls::verify(&validator.pubkey, signing_root.as_ref(), &exit.signature) {
            Ok(true) => {}
            _ => return GossipVerdict::Reject("exit: invalid signature".into()),
        }

        // Mark as seen and accept.
        self.seen_voluntary_exit_indices
            .write()
            .put(validator_index, ());
        // Feed the operation pool (Task 2.4).
        self.op_pools.insert_voluntary_exit(exit.clone());
        GossipVerdict::Accept
    }

    /// Validate a `proposer_slashing` message per `specs/phase0/p2p-interface.md:796-851`.
    ///
    /// 1 IGNORE + 6 REJECT rules (per spec), + mark-seen on accept.
    /// Per `D-folded-phase0-validators` in `docs/decisions.md`.
    fn validate_proposer_slashing(&self, slashing: &ProposerSlashing) -> GossipVerdict {
        use pharos_stf::phase0::accessors::{
            compute_epoch_at_slot, compute_signing_root, get_domain,
        };
        use pharos_stf::phase0::helpers::DOMAIN_BEACON_PROPOSER;
        use pharos_stf::phase0::predicates::is_slashable_validator;
        use pharos_types::BeaconStateView as _;

        let header_1 = &slashing.signed_header_1.message;
        let header_2 = &slashing.signed_header_2.message;
        let proposer_index = header_1.proposer_index.0;

        // [IGNORE] First valid proposer slashing for this proposer.
        if self
            .seen_proposer_slashing_indices
            .read()
            .peek(&proposer_index)
            .is_some()
        {
            return GossipVerdict::Ignore(
                "proposer_slashing: already seen for this proposer".into(),
            );
        }

        // [REJECT] Header slots must match.
        if header_1.slot != header_2.slot {
            return GossipVerdict::Reject("proposer_slashing: header slots do not match".into());
        }

        // [REJECT] Header proposer indices must match.
        if header_1.proposer_index != header_2.proposer_index {
            return GossipVerdict::Reject(
                "proposer_slashing: header proposer indices do not match".into(),
            );
        }

        // [REJECT] Headers must be different.
        if header_1 == header_2 {
            return GossipVerdict::Reject("proposer_slashing: headers are not different".into());
        }

        // Get the head state (two-step to avoid double-lock).
        let head_root = pharos_fork_choice::get_head(&*self.fork_choice.read());
        let head_state = match self
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
        {
            Some(s) => s,
            None => {
                return GossipVerdict::Ignore("proposer_slashing: head state unavailable".into());
            }
        };

        let num_validators = head_state.num_validators();
        let current_epoch = compute_epoch_at_slot(head_state.slot(), E::SLOTS_PER_EPOCH);

        // [REJECT] Proposer index must be in range.
        if proposer_index as usize >= num_validators {
            return GossipVerdict::Reject("proposer_slashing: proposer index out of range".into());
        }

        let proposer = match head_state.validator(proposer_index as usize) {
            Some(v) => v,
            None => {
                return GossipVerdict::Reject(
                    "proposer_slashing: proposer index out of range".into(),
                );
            }
        };

        // [REJECT] Proposer must be slashable.
        if !is_slashable_validator(proposer, current_epoch.0) {
            return GossipVerdict::Reject("proposer_slashing: proposer not slashable".into());
        }

        // [REJECT] Both signatures must be valid.
        for signed_header in [&slashing.signed_header_1, &slashing.signed_header_2] {
            let epoch = compute_epoch_at_slot(signed_header.message.slot, E::SLOTS_PER_EPOCH);
            let domain = get_domain::<E>(&head_state, DOMAIN_BEACON_PROPOSER, Some(epoch));
            let signing_root = compute_signing_root(&signed_header.message, domain);
            match pharos_utils::bls::verify(
                &proposer.pubkey,
                signing_root.as_ref(),
                &signed_header.signature,
            ) {
                Ok(true) => {}
                _ => {
                    return GossipVerdict::Reject("proposer_slashing: invalid signature".into());
                }
            }
        }

        // Mark as seen and accept.
        self.seen_proposer_slashing_indices
            .write()
            .put(proposer_index, ());
        // Feed the operation pool (Task 2.4).
        self.op_pools.insert_proposer_slashing(slashing.clone());
        GossipVerdict::Accept
    }

    /// Validate an `attester_slashing` message per `specs/phase0/p2p-interface.md:854-913`.
    ///
    /// 1 IGNORE + 6 REJECT rules (per spec), + mark-seen on accept.
    /// Per `D-folded-phase0-validators` in `docs/decisions.md`.
    fn validate_attester_slashing(&self, slashing: &AttesterSlashing<2048>) -> GossipVerdict {
        use pharos_stf::phase0::predicates::{
            is_slashable_attestation_data, is_slashable_validator, is_valid_indexed_attestation,
        };
        use pharos_types::BeaconStateView as _;

        let att_1 = &slashing.attestation_1;
        let att_2 = &slashing.attestation_2;

        use pharos_stf::phase0::accessors::compute_epoch_at_slot;

        // Compute the intersection of attesting indices using as_slice() on SszList.
        let indices_1: std::collections::HashSet<u64> = att_1
            .attesting_indices
            .as_slice()
            .iter()
            .map(|v| v.0)
            .collect();
        let indices_2: std::collections::HashSet<u64> = att_2
            .attesting_indices
            .as_slice()
            .iter()
            .map(|v| v.0)
            .collect();
        let slashable_indices: std::collections::HashSet<u64> =
            indices_1.intersection(&indices_2).copied().collect();

        // [IGNORE] At least one index in the intersection must be new (not yet seen).
        let has_new = {
            let cache = self.seen_attester_slashing_indices.read();
            slashable_indices
                .iter()
                .any(|idx| cache.peek(idx).is_none())
        };
        if !has_new {
            return GossipVerdict::Ignore("attester_slashing: all indices already seen".into());
        }

        // [REJECT] Attestation data must be slashable (double vote or surround).
        if !is_slashable_attestation_data(&att_1.data, &att_2.data) {
            return GossipVerdict::Reject(
                "attester_slashing: attestation data not slashable".into(),
            );
        }

        // Get head state for index-range checks and signature verification (two-step).
        let head_root = pharos_fork_choice::get_head(&*self.fork_choice.read());
        let head_state = match self
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
        {
            Some(s) => s,
            None => {
                return GossipVerdict::Ignore("attester_slashing: head state unavailable".into());
            }
        };

        let num_validators = head_state.num_validators();

        // [REJECT] All indices in attestation_1 must be in range.
        if att_1
            .attesting_indices
            .as_slice()
            .iter()
            .any(|v| v.0 as usize >= num_validators)
        {
            return GossipVerdict::Reject(
                "attester_slashing: index out of range in attestation_1".into(),
            );
        }

        // [REJECT] attestation_1 must be valid (signature check included).
        if !is_valid_indexed_attestation::<E>(&head_state, att_1, true) {
            return GossipVerdict::Reject(
                "attester_slashing: invalid indexed attestation_1".into(),
            );
        }

        // [REJECT] All indices in attestation_2 must be in range.
        if att_2
            .attesting_indices
            .as_slice()
            .iter()
            .any(|v| v.0 as usize >= num_validators)
        {
            return GossipVerdict::Reject(
                "attester_slashing: index out of range in attestation_2".into(),
            );
        }

        // [REJECT] attestation_2 must be valid (signature check included).
        if !is_valid_indexed_attestation::<E>(&head_state, att_2, true) {
            return GossipVerdict::Reject(
                "attester_slashing: invalid indexed attestation_2".into(),
            );
        }

        // Compute current epoch for slashability check.
        let current_epoch = compute_epoch_at_slot(head_state.slot(), E::SLOTS_PER_EPOCH);

        // [REJECT] At least one validator in the intersection must be slashable.
        let any_slashable = slashable_indices.iter().any(|idx| {
            head_state
                .validator(*idx as usize)
                .map(|v| is_slashable_validator(v, current_epoch.0))
                .unwrap_or(false)
        });
        if !any_slashable {
            return GossipVerdict::Reject(
                "attester_slashing: no slashable validators in intersection".into(),
            );
        }

        // Mark new indices as seen and accept.
        {
            let mut cache = self.seen_attester_slashing_indices.write();
            for idx in &slashable_indices {
                cache.put(*idx, ());
            }
        }
        // Feed the operation pool (Task 2.4).
        self.op_pools.insert_attester_slashing(slashing.clone());
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate sync committee message slot, validator index, signature.
    fn validate_sync_committee_message(
        &self,
        subnet: SubnetId,
        msg: &pharos_types::altair::SyncCommitteeMessage,
    ) -> GossipVerdict {
        // Feed accepted sync messages into the pool so drain_sync_aggregate can
        // use them at block-production time (Task 2.4).
        // `subnet` is the sync committee subcommittee index (0..SYNC_COMMITTEE_SUBNET_COUNT).
        self.op_pools.insert_sync_message(msg.clone(), subnet);
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate sync committee contribution: aggregator index, proof, signature.
    fn validate_sync_committee_contribution_and_proof(
        &self,
        _msg: &<E as EthSpec>::AltairSignedContributionAndProof,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// Validate a gossip `LightClientFinalityUpdate` per the full-node arm of
    /// `specs/altair/light-client/p2p-interface.md` (gossip topic
    /// `light_client_finality_update`). Spec-ordered IGNORE conditions:
    ///
    /// 1. No snapshot yet (LC snapshot store not yet populated).
    /// 2. `msg.finalized_header.beacon.slot` is not strictly greater than the
    ///    highest slot previously forwarded on this topic (monotonic guard).
    /// 3. Clock-window: `now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < due_ms`
    ///    where `due_ms = slot_start_ms + slot_ms / INTERVALS_PER_SLOT`.
    /// 4. `tree_hash_root(msg) != tree_hash_root(local_snapshot)` — different
    ///    finality update for this slot (full-node arm).
    ///
    /// All conditions map to `[IGNORE]` (not `[REJECT]`) per the spec.
    ///
    /// Known deviation: the spec's monotonic rule allows forwarding a
    /// same-slot update IF its `sync_aggregate` shows supermajority participation
    /// and the previously forwarded one did not. We currently apply the strict
    /// `incoming > prev` rule and drop the supermajority-upgrade case;
    /// TODO(M4c-phase2): track previous update's supermajority bit. See
    /// `p2p-interface.md:60-65`.
    ///
    /// See also `D-lc-gossip-validation-full-node-arm` (docs/decisions.md).
    fn validate_light_client_finality_update(
        &self,
        msg: &<E as EthSpec>::AltairLightClientFinalityUpdate,
    ) -> GossipVerdict {
        // Note (Phase 5 / D-capella-lc-header): The M4c IGNORE rules are
        // unchanged for Capella. The header equality check at step 4 uses
        // `tree_hash_root()`, which works correctly for any LightClientHeader
        // shape (altair: beacon-only; capella: beacon + execution + branch).
        // Phase 6 will update the method parameter from
        // `E::AltairLightClientFinalityUpdate` to `E::CapellaLightClientFinalityUpdate`
        // when the network fork-digest migration for capella is implemented.

        // Step 1 — snapshot lookup.
        let local = match self.light_client_finality_update() {
            Some(u) => u,
            None => {
                return GossipVerdict::Ignore("lc_finality: no local snapshot".into());
            }
        };

        // Step 2 — monotonic forwarded-slot guard (load current high-water mark).
        let incoming = msg.finalized_header_slot();
        let mut prev = self.last_forwarded_finality_slot.load(Ordering::Relaxed);
        if incoming <= prev {
            return GossipVerdict::Ignore("lc_finality: non-monotonic slot".into());
        }

        // Step 3 — clock window (per spec, common condition before full-node arm).
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => return GossipVerdict::Ignore("lc_finality: clock unavailable".into()),
        };
        let genesis_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let signature_slot = msg.finality_signature_slot();
        let slot_ms = u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let slot_start_ms = genesis_ms + u128::from(signature_slot) * slot_ms;
        let due_ms = slot_start_ms + slot_ms / u128::from(INTERVALS_PER_SLOT);
        if now_ms + u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS) < due_ms {
            return GossipVerdict::Ignore("lc_finality: clock window not elapsed".into());
        }

        // Step 4 — snapshot equality (full-node arm).
        if local.tree_hash_root() != msg.tree_hash_root() {
            return GossipVerdict::Ignore("lc_finality: snapshot mismatch".into());
        }

        // Step 5 — commit CAS; retry loop if a concurrent thread advanced the slot.
        loop {
            match self.last_forwarded_finality_slot.compare_exchange(
                prev,
                incoming,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return GossipVerdict::Accept,
                Err(current) => {
                    if incoming <= current {
                        return GossipVerdict::Ignore(
                            "lc_finality: lost CAS race to higher slot".into(),
                        );
                    }
                    prev = current;
                }
            }
        }
    }

    /// Validate a gossip `LightClientOptimisticUpdate` per the full-node arm of
    /// `specs/altair/light-client/p2p-interface.md` (gossip topic
    /// `light_client_optimistic_update`). Three IGNORE conditions apply:
    ///
    /// 1. No snapshot yet.
    /// 2. `msg.attested_header.beacon.slot` is not strictly greater than the
    ///    highest slot previously forwarded on this topic.
    /// 3. Clock-window: `now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < due_ms`.
    /// 4. `tree_hash_root(msg) != tree_hash_root(local_snapshot)` (full-node arm).
    ///
    /// All conditions map to `[IGNORE]` per the spec.
    ///
    /// See also `D-lc-gossip-validation-full-node-arm` (docs/decisions.md).
    fn validate_light_client_optimistic_update(
        &self,
        msg: &<E as EthSpec>::AltairLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        // Note (Phase 5 / D-capella-lc-header): Same as finality update — the
        // IGNORE rules are unchanged for Capella; Phase 6 will change the type
        // parameter to `E::CapellaLightClientOptimisticUpdate`.

        // Step 1 — snapshot lookup.
        let local = match self.light_client_optimistic_update() {
            Some(u) => u,
            None => return GossipVerdict::Ignore("lc_optimistic: no local snapshot".into()),
        };

        // Step 2 — monotonic forwarded-slot guard.
        let incoming = msg.optimistic_attested_slot();
        let mut prev = self.last_forwarded_optimistic_slot.load(Ordering::Relaxed);
        if incoming <= prev {
            return GossipVerdict::Ignore("lc_optimistic: non-monotonic slot".into());
        }

        // Step 3 — clock window (per spec, common condition before full-node arm).
        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => return GossipVerdict::Ignore("lc_optimistic: clock unavailable".into()),
        };
        let genesis_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let signature_slot = msg.optimistic_signature_slot();
        let slot_ms = u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let slot_start_ms = genesis_ms + u128::from(signature_slot) * slot_ms;
        let due_ms = slot_start_ms + slot_ms / u128::from(INTERVALS_PER_SLOT);
        if now_ms + u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS) < due_ms {
            return GossipVerdict::Ignore("lc_optimistic: clock window not elapsed".into());
        }

        // Step 4 — snapshot equality (full-node arm).
        if local.tree_hash_root() != msg.tree_hash_root() {
            return GossipVerdict::Ignore("lc_optimistic: snapshot mismatch".into());
        }

        // Step 5 — commit CAS; retry loop if a concurrent thread advanced the slot.
        loop {
            match self.last_forwarded_optimistic_slot.compare_exchange(
                prev,
                incoming,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return GossipVerdict::Accept,
                Err(current) => {
                    if incoming <= current {
                        return GossipVerdict::Ignore(
                            "lc_optimistic: lost CAS race to higher slot".into(),
                        );
                    }
                    prev = current;
                }
            }
        }
    }

    /// Validate a capella-fork `light_client_finality_update` per
    /// `specs/capella/light-client/p2p-interface.md`.
    ///
    /// Same IGNORE rules as the altair path; only the storage CF differs.
    /// Per `D-lc-gossip-validation-full-node-arm`, full-node arm:
    /// snapshot equality short-circuit via `tree_hash_root`.
    fn validate_capella_light_client_finality_update(
        &self,
        msg: &<E as EthSpec>::CapellaLightClientFinalityUpdate,
    ) -> GossipVerdict {
        use pharos_ssz::TreeHash;
        use pharos_types::views::LightClientFinalityUpdateView as _;

        let local = match <RocksStore as StoreTrait<E>>::get_light_client_finality_update_capella(
            &self.store,
        ) {
            Ok(Some(u)) => u,
            Ok(None) => {
                return GossipVerdict::Ignore("capella_lc_finality: no local snapshot".into());
            }
            Err(e) => {
                warn!(%e, "capella_lc_finality: storage error");
                return GossipVerdict::Ignore("capella_lc_finality: no local snapshot".into());
            }
        };

        let incoming = msg.finalized_header_slot();
        let mut prev = self
            .last_forwarded_finality_slot_capella
            .load(Ordering::Relaxed);
        if incoming <= prev {
            return GossipVerdict::Ignore("capella_lc_finality: non-monotonic slot".into());
        }

        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => {
                return GossipVerdict::Ignore("capella_lc_finality: clock unavailable".into());
            }
        };
        let genesis_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let signature_slot = msg.finality_signature_slot();
        let slot_ms = u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let slot_start_ms = genesis_ms + u128::from(signature_slot) * slot_ms;
        let due_ms = slot_start_ms + slot_ms / u128::from(INTERVALS_PER_SLOT);
        if now_ms + u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS) < due_ms {
            return GossipVerdict::Ignore("capella_lc_finality: clock window not elapsed".into());
        }

        if local.tree_hash_root() != msg.tree_hash_root() {
            return GossipVerdict::Ignore("capella_lc_finality: snapshot mismatch".into());
        }

        loop {
            match self.last_forwarded_finality_slot_capella.compare_exchange(
                prev,
                incoming,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return GossipVerdict::Accept,
                Err(current) => {
                    if incoming <= current {
                        return GossipVerdict::Ignore(
                            "capella_lc_finality: lost CAS race to higher slot".into(),
                        );
                    }
                    prev = current;
                }
            }
        }
    }

    /// Validate a capella-fork `light_client_optimistic_update` per
    /// `specs/capella/light-client/p2p-interface.md`.
    ///
    /// Same IGNORE rules as the altair path; only the storage CF differs.
    fn validate_capella_light_client_optimistic_update(
        &self,
        msg: &<E as EthSpec>::CapellaLightClientOptimisticUpdate,
    ) -> GossipVerdict {
        use pharos_ssz::TreeHash;
        use pharos_types::views::LightClientOptimisticUpdateView as _;

        let local = match <RocksStore as StoreTrait<E>>::get_light_client_optimistic_update_capella(
            &self.store,
        ) {
            Ok(Some(u)) => u,
            Ok(None) => {
                return GossipVerdict::Ignore("capella_lc_optimistic: no local snapshot".into());
            }
            Err(e) => {
                warn!(%e, "capella_lc_optimistic: storage error");
                return GossipVerdict::Ignore("capella_lc_optimistic: no local snapshot".into());
            }
        };

        let incoming = msg.optimistic_attested_slot();
        let mut prev = self
            .last_forwarded_optimistic_slot_capella
            .load(Ordering::Relaxed);
        if incoming <= prev {
            return GossipVerdict::Ignore("capella_lc_optimistic: non-monotonic slot".into());
        }

        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis(),
            Err(_) => {
                return GossipVerdict::Ignore("capella_lc_optimistic: clock unavailable".into());
            }
        };
        let genesis_ms = u128::from(self.fork_choice.read().genesis_time) * 1000;
        let signature_slot = msg.optimistic_signature_slot();
        let slot_ms = u128::from(self.runtime_cfg.seconds_per_slot) * 1000;
        let slot_start_ms = genesis_ms + u128::from(signature_slot) * slot_ms;
        let due_ms = slot_start_ms + slot_ms / u128::from(INTERVALS_PER_SLOT);
        if now_ms + u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS) < due_ms {
            return GossipVerdict::Ignore("capella_lc_optimistic: clock window not elapsed".into());
        }

        if local.tree_hash_root() != msg.tree_hash_root() {
            return GossipVerdict::Ignore("capella_lc_optimistic: snapshot mismatch".into());
        }

        loop {
            match self
                .last_forwarded_optimistic_slot_capella
                .compare_exchange(prev, incoming, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return GossipVerdict::Accept,
                Err(current) => {
                    if incoming <= current {
                        return GossipVerdict::Ignore(
                            "capella_lc_optimistic: lost CAS race to higher slot".into(),
                        );
                    }
                    prev = current;
                }
            }
        }
    }

    /// Validate a `bls_to_execution_change` message per
    /// `specs/capella/p2p-interface.md:207-259`.
    ///
    /// Spec rules (2 IGNORE + 4 REJECT + mark-seen on accept):
    ///  1. [IGNORE] Current epoch must be at or after CAPELLA_FORK_EPOCH.
    ///  2. [IGNORE] First valid change for this validator (seen-cache).
    ///  3. [REJECT] Validator index must be in range.
    ///  4. [REJECT] Validator must have BLS withdrawal credentials (prefix 0x00).
    ///  5. [REJECT] `from_bls_pubkey` hash must match the stored credential.
    ///  6. [REJECT] BLS signature over the fork-agnostic domain must be valid.
    ///
    /// Domain is fork-agnostic per `D-bls-to-exec-change-domain`:
    /// `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_FORK_VERSION, genesis_validators_root)`.
    fn validate_bls_to_execution_change(
        &self,
        signed_msg: &pharos_types::capella::operations::SignedBLSToExecutionChange,
    ) -> GossipVerdict {
        use pharos_stf::phase0::accessors::{compute_domain, compute_signing_root};
        use pharos_types::BeaconStateView as _;
        use pharos_types::fork::DOMAIN_BLS_TO_EXECUTION_CHANGE;

        let msg = &signed_msg.message;
        let validator_index = msg.validator_index.0;

        // [IGNORE] Current epoch must be at or after CAPELLA_FORK_EPOCH.
        // Use wall-clock epoch from fork_context (same computation as current_epoch()).
        {
            let current_ep = self.current_epoch();
            let capella_fork_epoch = self.fork_context.fork_schedule.capella_fork_epoch;
            if current_ep < capella_fork_epoch {
                return GossipVerdict::Ignore("bls_to_exec: current epoch is pre-capella".into());
            }
        }

        // [IGNORE] First valid change for this validator.
        if self
            .seen_bls_to_execution_change_indices
            .read()
            .peek(&validator_index)
            .is_some()
        {
            return GossipVerdict::Ignore("bls_to_exec: already seen for this validator".into());
        }

        // Get head state for remaining checks (two-step to avoid double-lock).
        let head_root = pharos_fork_choice::get_head(&*self.fork_choice.read());
        let head_state = match self
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
        {
            Some(s) => s,
            None => return GossipVerdict::Ignore("bls_to_exec: head state unavailable".into()),
        };

        // [REJECT] Validator index must be in range.
        if validator_index as usize >= head_state.num_validators() {
            return GossipVerdict::Reject("bls_to_exec: validator index out of range".into());
        }

        let validator = match head_state.validator(validator_index as usize) {
            Some(v) => v,
            None => {
                return GossipVerdict::Reject("bls_to_exec: validator index out of range".into());
            }
        };

        // [REJECT] Validator must have BLS withdrawal credentials (prefix 0x00).
        let creds = validator.withdrawal_credentials;
        if creds.as_slice()[0] != 0x00u8 {
            return GossipVerdict::Reject("bls_to_exec: not BLS withdrawal credentials".into());
        }

        // [REJECT] `from_bls_pubkey` must hash-match the stored credential.
        let pubkey_hash = pharos_utils::hash::hash(msg.from_bls_pubkey.as_slice());
        if creds.as_slice()[1..] != pubkey_hash.as_slice()[1..] {
            return GossipVerdict::Reject("bls_to_exec: pubkey hash mismatch".into());
        }

        // [REJECT] BLS signature must be valid (fork-agnostic domain).
        let gvr = &self.fork_context.genesis_validators_root;
        let domain = compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, E::GENESIS_FORK_VERSION, gvr);
        let signing_root = compute_signing_root(msg, domain);
        match pharos_utils::bls::verify(
            &msg.from_bls_pubkey,
            signing_root.as_ref(),
            &signed_msg.signature,
        ) {
            Ok(true) => {}
            _ => return GossipVerdict::Reject("bls_to_exec: invalid signature".into()),
        }

        // Mark as seen and accept.
        self.seen_bls_to_execution_change_indices
            .write()
            .put(validator_index, ());
        // Feed the operation pool (Task 2.4).
        self.op_pools
            .insert_bls_to_execution_change(signed_msg.clone());
        GossipVerdict::Accept
    }
}

// ── LightClientProvider ───────────────────────────────────────────────────────

/// Light-client provider for `HostImpl<E>`.
///
/// Per `D-light-client-server-only`: serves the four LC req-resp methods.
/// Reads LC snapshots from the dedicated storage column families defined in
/// Task 6.9. Snapshots are written by the STF hook in `pharos-stf`
/// (`create_light_client_*`) on each finality advance or optimistic head update.
impl<E: EthSpec> LightClientProvider<E> for HostImpl<E> {
    /// Look up a pre-computed `LightClientBootstrap` for the given block root.
    ///
    /// Reads from the `light-client-bootstrap` column family (Task 6.9(b)).
    /// Returns `None` on storage error (logged at `warn`) or missing entry.
    fn light_client_bootstrap(&self, block_root: Root) -> Option<E::AltairLightClientBootstrap> {
        match <RocksStore as StoreTrait<E>>::get_light_client_bootstrap(&self.store, &block_root) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(%e, %block_root, "light_client_bootstrap: storage error");
                None
            }
        }
    }

    /// Retrieve a range of stored `LightClientUpdate` objects.
    ///
    /// Reads from the `light-client-update` column family (Task 6.9(b)).
    /// Returns an empty vec on storage error.
    fn light_client_updates_by_range(
        &self,
        start_period: u64,
        count: u64,
    ) -> Vec<E::AltairLightClientUpdate> {
        match <RocksStore as StoreTrait<E>>::get_light_client_updates_by_range(
            &self.store,
            start_period,
            count,
        ) {
            Ok(updates) => updates,
            Err(e) => {
                warn!(%e, start_period, count, "light_client_updates_by_range: storage error");
                vec![]
            }
        }
    }

    /// Return the latest stored `LightClientFinalityUpdate`, if any.
    ///
    /// Reads from the `latest-finality-update` column family (Task 6.9(b)).
    fn light_client_finality_update(&self) -> Option<E::AltairLightClientFinalityUpdate> {
        match <RocksStore as StoreTrait<E>>::get_light_client_finality_update(&self.store) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(%e, "light_client_finality_update: storage error");
                None
            }
        }
    }

    /// Return the latest stored `LightClientOptimisticUpdate`, if any.
    ///
    /// Reads from the `latest-optimistic-update` column family (Task 6.9(b)).
    fn light_client_optimistic_update(&self) -> Option<E::AltairLightClientOptimisticUpdate> {
        match <RocksStore as StoreTrait<E>>::get_light_client_optimistic_update(&self.store) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(%e, "light_client_optimistic_update: storage error");
                None
            }
        }
    }

    /// Return the latest stored Capella `LightClientFinalityUpdate`, if any.
    fn light_client_finality_update_capella(&self) -> Option<E::CapellaLightClientFinalityUpdate> {
        match <RocksStore as StoreTrait<E>>::get_light_client_finality_update_capella(&self.store) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(%e, "light_client_finality_update_capella: storage error");
                None
            }
        }
    }

    /// Return the latest stored Capella `LightClientOptimisticUpdate`, if any.
    fn light_client_optimistic_update_capella(
        &self,
    ) -> Option<E::CapellaLightClientOptimisticUpdate> {
        match <RocksStore as StoreTrait<E>>::get_light_client_optimistic_update_capella(&self.store)
        {
            Ok(opt) => opt,
            Err(e) => {
                warn!(%e, "light_client_optimistic_update_capella: storage error");
                None
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
// Several validator tests reach into `block_states.get_mut` then match the
// fork-enum variant; the nested `if let` form is clearer than the collapsed
// `if let Some(Variant(..))` here, so allow it in test code only.
#[allow(clippy::collapsible_match)]
mod tests {
    use super::*;
    use pharos_ssz::Bitvector;
    use pharos_storage::{RocksStore, RocksStoreConfig, Store as StoreTrait};
    use pharos_types::MainnetEthSpec;
    use pharos_types::altair::light_client::{
        LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate,
    };
    use pharos_types::altair::{
        MainnetLightClientFinalityUpdate, MainnetLightClientOptimisticUpdate,
    };
    use pharos_types::phase0::operations::BeaconBlockHeader;

    fn make_host(dir: &tempfile::TempDir) -> HostImpl<MainnetEthSpec> {
        use pharos_ssz::TreeHash;
        use pharos_types::state::BeaconBlock as ForkBeaconBlock;
        let store = Arc::new(
            RocksStore::open::<MainnetEthSpec>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );
        let genesis_state = <MainnetEthSpec as EthSpec>::BeaconState::default();
        let state_root = genesis_state.tree_hash_root();
        // Satisfy get_forkchoice_store's assertion: anchor_block.state_root == hash_tree_root(anchor_state).
        let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
            state_root,
            ..pharos_types::phase0::MainnetBeaconBlock::default()
        });
        let fc_store =
            pharos_fork_choice::get_forkchoice_store::<MainnetEthSpec>(genesis_state, anchor_block);
        let fork_choice = Arc::new(RwLock::new(fc_store));
        let gvr = Root::default();
        // Phase0-only schedule: altair/bellatrix epochs = FAR_FUTURE, versions = mainnet defaults.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(u64::MAX),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(u64::MAX),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            genesis_validators_root: gvr,
        };
        let runtime_cfg = Arc::new(RuntimeConfig::default());
        HostImpl::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg)
    }

    /// Build a `HostImpl` with a bellatrix-at-genesis schedule:
    /// `altair_fork_epoch == bellatrix_fork_epoch == 0`.
    /// `genesis_time_secs = 0` causes `current_epoch()` to always return 0,
    /// which resolves to the bellatrix fork version.
    fn make_bellatrix_genesis_host(dir: &tempfile::TempDir) -> HostImpl<MainnetEthSpec> {
        use pharos_ssz::TreeHash;
        use pharos_types::state::BeaconBlock as ForkBeaconBlock;
        let store = Arc::new(
            RocksStore::open::<MainnetEthSpec>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );
        let genesis_state = <MainnetEthSpec as EthSpec>::BeaconState::default();
        let state_root = genesis_state.tree_hash_root();
        let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
            state_root,
            ..pharos_types::phase0::MainnetBeaconBlock::default()
        });
        let fc_store =
            pharos_fork_choice::get_forkchoice_store::<MainnetEthSpec>(genesis_state, anchor_block);
        let fork_choice = Arc::new(RwLock::new(fc_store));
        let gvr = Root::default();
        // Bellatrix-at-genesis: both altair and bellatrix activate at epoch 0.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(0),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(0),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            genesis_validators_root: gvr,
        };
        let runtime_cfg = Arc::new(RuntimeConfig::default());
        HostImpl::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg)
    }

    // ── lc_publish_wait: spec gossip-window delay for LC broadcasts (M5) ────────

    /// An LC update whose `signature_slot` window already opened (slot far in
    /// the past relative to wall clock) needs no publish delay.
    #[test]
    fn lc_publish_wait_past_slot_is_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        // genesis_time = 0 (default): slot 0's due time is epoch 0 + 4s, decades
        // in the past, so the broadcast window is open.
        assert_eq!(host.lc_publish_wait(0), Duration::ZERO);
    }

    /// An LC update for a slot whose due time is still ahead returns a positive
    /// wait of ~(signature_slot * SECONDS_PER_SLOT + SECONDS_PER_SLOT /
    /// INTERVALS_PER_SLOT) past genesis — the spec `get_sync_message_due_ms`
    /// point. Publishing earlier is what lighthouse rejected as `TooEarly`.
    #[test]
    fn lc_publish_wait_future_slot_delays_to_due_time() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Anchor genesis at "now" so future slots are genuinely ahead.
        host.fork_choice.write().genesis_time = now_secs;
        // seconds_per_slot = 12, INTERVALS_PER_SLOT = 3 → due = slot*12 + 4 s.
        let sig_slot = 100u64;
        let expected = sig_slot * 12 + 4; // 1204 s
        let secs = host.lc_publish_wait(sig_slot).as_secs();
        // A few seconds of slack between the genesis stamp and the clock read.
        assert!(
            secs >= expected - 3 && secs <= expected,
            "wait {secs}s not within [{}, {expected}]s",
            expected - 3
        );
    }

    /// A slot already started → no wait. A slot still ahead → wait ≈
    /// `slot * SECONDS_PER_SLOT` past genesis (the slot-start time, with no
    /// `get_sync_message_due_ms` fraction added — unlike `lc_publish_wait`).
    #[test]
    fn wait_until_slot_start_past_and_future() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        // genesis_time = 0 (default): slot 0 began decades ago → no wait.
        assert_eq!(host.wait_until_slot_start(0), Duration::ZERO);

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        host.fork_choice.write().genesis_time = now_secs;
        // seconds_per_slot = 12 → slot 50 starts 600 s out (no due fraction).
        let slot = 50u64;
        let expected = slot * 12; // 600 s
        let secs = host.wait_until_slot_start(slot).as_secs();
        assert!(
            secs >= expected - 3 && secs <= expected,
            "wait {secs}s not within [{}, {expected}]s",
            expected - 3
        );
    }

    // ── Task 5.2: current_fork_digest / enr_fork_id on bellatrix-genesis host ──

    /// A `HostImpl` with bellatrix-at-genesis schedule and `genesis_time_secs=0`
    /// must report the bellatrix fork digest from `current_fork_digest()` and
    /// the same digest from `enr_fork_id().fork_digest`.
    #[test]
    fn bellatrix_genesis_host_reports_bellatrix_digest() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_bellatrix_genesis_host(&dir);
        let gvr = Root::default();
        let bellatrix_version = Version::from_array([0x02, 0x00, 0x00, 0x00]);
        let expected_digest = compute_fork_digest(bellatrix_version, &gvr);

        let got = host.current_fork_digest();
        assert_eq!(
            got, expected_digest,
            "bellatrix-genesis HostImpl must report bellatrix fork digest"
        );
        let enr_id = host.enr_fork_id();
        assert_eq!(
            enr_id.fork_digest, expected_digest,
            "enr_fork_id().fork_digest must match bellatrix digest"
        );
    }

    /// A phase0-only `HostImpl` (altair/bellatrix at FAR_FUTURE) must report
    /// the phase0 fork digest. Regression guard: confirms the dynamic lookup
    /// does not accidentally return a non-phase0 digest on a phase0-only schedule.
    #[test]
    fn phase0_only_host_reports_phase0_digest() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        let gvr = Root::default();
        let phase0_version = Version::from_array([0x00, 0x00, 0x00, 0x00]);
        let bellatrix_version = Version::from_array([0x02, 0x00, 0x00, 0x00]);
        let expected_phase0_digest = compute_fork_digest(phase0_version, &gvr);
        let bellatrix_digest = compute_fork_digest(bellatrix_version, &gvr);

        let got = host.current_fork_digest();
        assert_eq!(
            got, expected_phase0_digest,
            "phase0-only HostImpl must report phase0 fork digest"
        );
        // `fork_digest_for(Fork::Phase0)` must not equal the bellatrix digest.
        let phase0_fd = host.fork_digest_for(pharos_network::types::Fork::Phase0);
        assert_ne!(
            phase0_fd, bellatrix_digest,
            "fork_digest_for(Phase0) must differ from bellatrix digest"
        );
    }

    // ── Task 5.3: fork_from_context round-trips ───────────────────────────────

    /// `fork_from_context` correctly reverse-maps each of the three fork digests
    /// and returns `None` for an unknown 4-byte value.
    #[test]
    fn fork_from_context_round_trips() {
        use pharos_network::types::Fork;
        let dir = tempfile::TempDir::new().unwrap();
        // Use a three-fork schedule so all three digests are distinct.
        let host = make_bellatrix_genesis_host(&dir);
        let gvr = Root::default();
        let phase0_version = Version::from_array([0x00, 0x00, 0x00, 0x00]);
        let altair_version = Version::from_array([0x01, 0x00, 0x00, 0x00]);
        let bellatrix_version = Version::from_array([0x02, 0x00, 0x00, 0x00]);

        let phase0_bytes = compute_fork_digest(phase0_version, &gvr).into_inner();
        let altair_bytes = compute_fork_digest(altair_version, &gvr).into_inner();
        let bellatrix_bytes = compute_fork_digest(bellatrix_version, &gvr).into_inner();
        let unknown_bytes = [0xde, 0xad, 0xbe, 0xef];

        assert_eq!(
            host.fork_from_context(&bellatrix_bytes),
            Some(Fork::Bellatrix),
            "bellatrix digest must round-trip to Fork::Bellatrix"
        );
        assert_eq!(
            host.fork_from_context(&altair_bytes),
            Some(Fork::Altair),
            "altair digest must round-trip to Fork::Altair"
        );
        assert_eq!(
            host.fork_from_context(&phase0_bytes),
            Some(Fork::Phase0),
            "phase0 digest must round-trip to Fork::Phase0"
        );
        assert_eq!(
            host.fork_from_context(&unknown_bytes),
            None,
            "unknown 4-byte context must return None"
        );
    }

    #[test]
    fn record_attnets_change_idempotent_no_bump() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);

        assert_eq!(host.local_metadata().seq_number, 0);

        // Calling with the same (default, all-zero) attnets must not bump.
        let same_attnets: Bitvector<ATTESTATION_SUBNET_COUNT> = Bitvector::default();
        host.record_attnets_change(same_attnets.clone());
        assert_eq!(
            host.local_metadata().seq_number,
            0,
            "idempotent call must not increment seq_number"
        );
    }

    #[test]
    fn record_attnets_change_diff_bumps() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);

        assert_eq!(host.local_metadata().seq_number, 0);

        // Set bit 0 — this is a real change.
        let mut new_attnets: Bitvector<ATTESTATION_SUBNET_COUNT> = Bitvector::default();
        new_attnets.set(0, true);
        host.record_attnets_change(new_attnets.clone());
        assert_eq!(
            host.local_metadata().seq_number,
            1,
            "different attnets must bump seq_number"
        );

        // Same value again — must not bump.
        host.record_attnets_change(new_attnets);
        assert_eq!(
            host.local_metadata().seq_number,
            1,
            "second idempotent call must not bump"
        );

        // Different value — must bump again.
        let mut newer_attnets: Bitvector<ATTESTATION_SUBNET_COUNT> = Bitvector::default();
        newer_attnets.set(1, true);
        host.record_attnets_change(newer_attnets);
        assert_eq!(
            host.local_metadata().seq_number,
            2,
            "second distinct change must bump to 2"
        );
    }

    // ── Helper: build a finality update with a given finalized slot + signature slot ──

    fn make_finality_update(
        finalized_slot: u64,
        signature_slot: u64,
    ) -> MainnetLightClientFinalityUpdate {
        LightClientFinalityUpdate {
            finalized_header: LightClientHeader {
                beacon: BeaconBlockHeader {
                    slot: Slot(finalized_slot),
                    ..BeaconBlockHeader::default()
                },
            },
            attested_header: LightClientHeader {
                beacon: BeaconBlockHeader {
                    slot: Slot(finalized_slot),
                    ..BeaconBlockHeader::default()
                },
            },
            signature_slot: Slot(signature_slot),
            ..Default::default()
        }
    }

    fn make_optimistic_update(
        attested_slot: u64,
        signature_slot: u64,
    ) -> MainnetLightClientOptimisticUpdate {
        LightClientOptimisticUpdate {
            attested_header: LightClientHeader {
                beacon: BeaconBlockHeader {
                    slot: Slot(attested_slot),
                    ..BeaconBlockHeader::default()
                },
            },
            signature_slot: Slot(signature_slot),
            ..Default::default()
        }
    }

    // ── Task 1.5(a): validator_accepts_exact_match_finality ───────────────────

    #[test]
    fn validator_accepts_exact_match_finality() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        // signature_slot = 0 → due_ms = 4000 ms, always in the past.
        let upd = make_finality_update(1, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_finality_update(
            &host.store,
            &upd,
        )
        .expect("put finality update");
        assert_eq!(
            host.validate_light_client_finality_update(&upd),
            GossipVerdict::Accept,
        );
    }

    // ── Task 1.5(b): validator_ignores_when_snapshot_absent_finality ──────────

    #[test]
    fn validator_ignores_when_snapshot_absent_finality() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        let upd = make_finality_update(1, 0);
        // No snapshot written — must Ignore.
        assert!(matches!(
            host.validate_light_client_finality_update(&upd),
            GossipVerdict::Ignore(_),
        ));
    }

    // ── Task 1.5(c): validator_clock_window_just_past_finality ───────────────

    #[test]
    fn validator_clock_window_just_past_finality() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);

        // Accept case: signature_slot = 0 → due_ms = 4000 ms (far in the past).
        let upd_accept = make_finality_update(1, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_finality_update(
            &host.store,
            &upd_accept,
        )
        .expect("put");
        assert_eq!(
            host.validate_light_client_finality_update(&upd_accept),
            GossipVerdict::Accept,
            "past slot should Accept",
        );

        // Ignore case: signature_slot in the future.
        // due_ms = sig_slot * 12000 + 4000 must be > now_ms + 500.
        // now_ms is ~unix epoch. A slot far in the future: now_ms / 12000 + 1000.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let future_sig_slot = (now_ms / 12000) as u64 + 1000;
        // Use a finalized_slot strictly greater than the previous Accept so monotonic check passes.
        let upd_ignore = make_finality_update(future_sig_slot + 1, future_sig_slot);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_finality_update(
            &host.store,
            &upd_ignore,
        )
        .expect("put");
        assert!(
            matches!(
                host.validate_light_client_finality_update(&upd_ignore),
                GossipVerdict::Ignore(_),
            ),
            "future slot should Ignore",
        );
    }

    // ── Task 1.5(d): validator_accepts_exact_match_optimistic ────────────────

    #[test]
    fn validator_accepts_exact_match_optimistic() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);
        let upd = make_optimistic_update(1, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_optimistic_update(
            &host.store,
            &upd,
        )
        .expect("put optimistic update");
        assert_eq!(
            host.validate_light_client_optimistic_update(&upd),
            GossipVerdict::Accept,
        );
    }

    // ── Task 1.5(e): validator_clock_window_just_past_optimistic ─────────────

    #[test]
    fn validator_clock_window_just_past_optimistic() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);

        // Accept case.
        let upd_accept = make_optimistic_update(1, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_optimistic_update(
            &host.store,
            &upd_accept,
        )
        .expect("put");
        assert_eq!(
            host.validate_light_client_optimistic_update(&upd_accept),
            GossipVerdict::Accept,
            "past slot should Accept",
        );

        // Ignore case.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let future_sig_slot = (now_ms / 12000) as u64 + 1000;
        let upd_ignore = make_optimistic_update(future_sig_slot + 1, future_sig_slot);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_optimistic_update(
            &host.store,
            &upd_ignore,
        )
        .expect("put");
        assert!(
            matches!(
                host.validate_light_client_optimistic_update(&upd_ignore),
                GossipVerdict::Ignore(_),
            ),
            "future slot should Ignore",
        );
    }

    // ── Task 1.5(f): validator_ignores_non_monotonic_finality ────────────────

    #[test]
    fn validator_ignores_non_monotonic_finality() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);

        let upd = make_finality_update(5, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_finality_update(
            &host.store,
            &upd,
        )
        .expect("put");

        // First call: finalized_slot = 5, signature_slot = 0 → Accept.
        assert_eq!(
            host.validate_light_client_finality_update(&upd),
            GossipVerdict::Accept,
            "first call must Accept",
        );

        // Second call with same slot: high-water mark is 5, incoming is 5 → Ignore.
        assert!(
            matches!(
                host.validate_light_client_finality_update(&upd),
                GossipVerdict::Ignore(_),
            ),
            "second call with same slot must Ignore",
        );

        // Third call with strictly greater slot → Accept.
        let upd2 = make_finality_update(6, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_finality_update(
            &host.store,
            &upd2,
        )
        .expect("put");
        assert_eq!(
            host.validate_light_client_finality_update(&upd2),
            GossipVerdict::Accept,
            "strictly greater slot must Accept",
        );
    }

    // ── Task 1.5(g): validator_ignores_non_monotonic_optimistic ──────────────

    #[test]
    fn validator_ignores_non_monotonic_optimistic() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_host(&dir);

        let upd = make_optimistic_update(5, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_optimistic_update(
            &host.store,
            &upd,
        )
        .expect("put");

        // First call: attested_slot = 5, signature_slot = 0 → Accept.
        assert_eq!(
            host.validate_light_client_optimistic_update(&upd),
            GossipVerdict::Accept,
            "first call must Accept",
        );

        // Second call with same slot → Ignore.
        assert!(
            matches!(
                host.validate_light_client_optimistic_update(&upd),
                GossipVerdict::Ignore(_),
            ),
            "second call with same slot must Ignore",
        );

        // Third call with strictly greater attested_slot → Accept.
        let upd2 = make_optimistic_update(6, 0);
        <RocksStore as StoreTrait<MainnetEthSpec>>::put_light_client_optimistic_update(
            &host.store,
            &upd2,
        )
        .expect("put");
        assert_eq!(
            host.validate_light_client_optimistic_update(&upd2),
            GossipVerdict::Accept,
            "strictly greater slot must Accept",
        );
    }

    // ── beacon_block validation tests (Tasks 1.5 a–n) ────────────────────────

    use blst::min_pk::SecretKey as BlstSecretKey;
    use pharos_ssz::{SszList, SszSequence as _, TreeHash};
    use pharos_stf::phase0::accessors::{compute_signing_root, get_domain};
    use pharos_stf::phase0::helpers::DOMAIN_BEACON_PROPOSER;
    use pharos_types::MinimalEthSpec;
    use pharos_types::phase0::{
        MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    };
    use pharos_types::state::{
        MinimalBeaconState as ForkMinimalState, SignedBeaconBlock as ForkSignedBeaconBlock,
    };
    use pharos_utils::bls::BLS_DST;
    use pharos_utils::{BLSPubkey, BLSSignature, Gwei};

    /// Type alias for the fork-enum `SignedBeaconBlock` over minimal Phase0 params.
    type MinForkSigned = ForkSignedBeaconBlock<
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
    >;

    fn block_test_sk() -> BlstSecretKey {
        BlstSecretKey::key_gen(&[42u8; 32], &[]).expect("valid IKM")
    }

    fn block_test_pubkey() -> BLSPubkey {
        BLSPubkey::from_array(block_test_sk().sk_to_pk().compress())
    }

    fn block_test_sign(msg: &[u8]) -> BLSSignature {
        BLSSignature::from_array(block_test_sk().sign(msg, BLS_DST, &[]).compress())
    }

    /// Build a `HostImpl<MinimalEthSpec>` with a genesis Phase0 state+block
    /// pre-inserted into the fork-choice store.
    ///
    /// Returns `(host, genesis_root, genesis_slot)` where `genesis_root` is
    /// the hash_tree_root of the genesis block (usable as `parent_root` for
    /// the next block).
    fn make_block_test_host(dir: &tempfile::TempDir) -> (HostImpl<MinimalEthSpec>, Root, Slot) {
        use pharos_types::phase0::misc::Fork;
        use pharos_types::phase0::operations::BeaconBlockHeader;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};

        let store = Arc::new(
            RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );

        let genesis_slot = Slot(0);

        let validator = pharos_types::phase0::misc::Validator {
            pubkey: block_test_pubkey(),
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            slashed: false,
            ..Default::default()
        };

        let genesis_body_root = MinimalBeaconBlockBody::default().tree_hash_root();
        let genesis_state_inner = MinimalBeaconState {
            genesis_time: 0,
            slot: genesis_slot,
            fork: Fork {
                previous_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                current_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                epoch: Epoch(0),
            },
            latest_block_header: BeaconBlockHeader {
                slot: genesis_slot,
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: genesis_body_root,
            },
            validators: SszList::with_push(&SszList::default(), validator).unwrap(),
            balances: SszList::with_push(
                &SszList::default(),
                Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            )
            .unwrap(),
            ..Default::default()
        };

        let fork_genesis_state = ForkMinimalState::Phase0(genesis_state_inner.clone());
        let state_root = fork_genesis_state.tree_hash_root();

        let genesis_block = MinimalBeaconBlock {
            slot: genesis_slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: MinimalBeaconBlockBody::default(),
        };
        let genesis_root: Root = genesis_block.tree_hash_root();

        let fork_genesis_block = pharos_types::state::BeaconBlock::Phase0(genesis_block.clone());

        // Build an anchor signed block (signature unused for anchor).
        let anchor_signed = MinimalSignedBeaconBlock {
            message: genesis_block,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        let _fork_anchor = MinForkSigned::Phase0(anchor_signed);

        let fc_store = pharos_fork_choice::get_forkchoice_store::<MinimalEthSpec>(
            fork_genesis_state.clone(),
            fork_genesis_block,
        );
        let fork_choice = Arc::new(RwLock::new(fc_store));

        // Insert genesis state into block_states so validate_beacon_block
        // can find it as the parent state.  The store already has the anchor
        // block; we additionally insert genesis_root → genesis_state so that
        // lookup_or_compute_expected_proposer resolves the parent state.
        {
            let mut fc = fork_choice.write();
            fc.block_states
                .insert(genesis_root, fork_genesis_state.clone());
            // Insert the fork-enum block so `fc.blocks.contains_key` succeeds.
            fc.blocks.insert(genesis_root, {
                let b = MinimalBeaconBlock {
                    slot: genesis_slot,
                    proposer_index: pharos_types::phase0::primitives::ValidatorIndex(0),
                    parent_root: Root::default(),
                    state_root: fork_genesis_state.tree_hash_root(),
                    body: MinimalBeaconBlockBody::default(),
                };
                pharos_types::state::BeaconBlock::Phase0(b)
            });
        }

        let gvr = Root::default();
        // Phase0-only schedule: altair/bellatrix epochs = FAR_FUTURE, versions = mainnet defaults.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(u64::MAX),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(u64::MAX),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            genesis_validators_root: gvr,
        };
        let runtime_cfg = Arc::new(RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            ..Default::default()
        });
        let host =
            HostImpl::<MinimalEthSpec>::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg);
        (host, genesis_root, genesis_slot)
    }

    /// Build a signed Phase0 block at `slot` with `parent_root` and sign
    /// it with `block_test_sk()` against the given pre-state (advanced to slot).
    ///
    /// `proposer_idx` lets tests override the declared proposer index.
    fn make_signed_block(
        slot: Slot,
        parent_root: Root,
        parent_state: &ForkMinimalState,
        proposer_idx: u64,
        flip_sig: bool,
    ) -> MinForkSigned {
        use pharos_types::phase0::primitives::ValidatorIndex;

        let block = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(proposer_idx),
            parent_root,
            state_root: Root::default(),
            body: MinimalBeaconBlockBody::default(),
        };

        let domain = get_domain::<MinimalEthSpec>(
            parent_state,
            DOMAIN_BEACON_PROPOSER,
            Some(pharos_stf::phase0::accessors::compute_epoch_at_slot(
                slot,
                MinimalEthSpec::SLOTS_PER_EPOCH,
            )),
        );
        let signing_root = compute_signing_root(&block, domain);
        let mut sig_bytes: [u8; 96] = block_test_sign(signing_root.as_ref()).into();
        if flip_sig {
            sig_bytes[0] ^= 0xff;
        }
        let sig = BLSSignature::from_array(sig_bytes);

        MinForkSigned::Phase0(MinimalSignedBeaconBlock {
            message: block,
            signature: sig,
        })
    }

    // ── (a) RB1: block_ignores_future_slot ───────────────────────────────────

    #[test]
    fn block_ignores_future_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        // A slot 1000 epochs in the future (genesis_time=0, seconds_per_slot=6).
        let future_slot = Slot((now_ms / 6000) as u64 + 1000 * 8);
        let block = make_signed_block(
            future_slot,
            parent_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Ignore("block: from future slot".into()),
        );
    }

    // ── (b) RB2: block_ignores_at_or_below_finalized ─────────────────────────

    #[test]
    fn block_ignores_at_or_below_finalized() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // Finalized slot from genesis fork-choice is 0.  A block at slot 0 should Ignore.
        let block = make_signed_block(
            Slot(0),
            parent_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Ignore("block: not greater than finalized slot".into()),
        );
    }

    // ── (c) RB3: block_ignores_duplicate_proposer_slot ───────────────────────

    #[test]
    fn block_ignores_duplicate_proposer_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // Pre-insert (slot=1, proposer=0) into the seen cache.
        host.seen_block_proposers.write().put((Slot(1), 0), ());

        let block = make_signed_block(
            Slot(1),
            parent_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Ignore("block: duplicate proposer/slot".into()),
        );
    }

    // ── (d) RB4: block_rejects_proposer_index_out_of_range ───────────────────

    #[test]
    fn block_rejects_proposer_index_out_of_range() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // The genesis state has 1 validator (index 0). Index 1 is out of range.
        let block = make_signed_block(
            Slot(1),
            parent_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            1,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Reject("block: proposer index out of range".into()),
        );
    }

    // ── (e) RB6: block_ignores_unknown_parent ────────────────────────────────

    #[test]
    fn block_ignores_unknown_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _, _) = make_block_test_host(&dir);

        // Use a parent root that is not in fc.blocks.
        let unknown_parent = Root::from_array([0xff; 32]);
        let block = make_signed_block(
            Slot(1),
            unknown_parent,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Ignore(GOSSIP_REASON_PARENT_UNSEEN.into()),
        );
    }

    // ── (f) RB7: block_rejects_parent_in_invalid_set ─────────────────────────

    #[test]
    fn block_rejects_parent_in_invalid_set() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // Pre-populate the invalid-roots cache with the parent root.
        host.invalid_block_roots.write().put(parent_root, ());

        let block = make_signed_block(
            Slot(1),
            parent_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Reject("block: parent in invalid set".into()),
        );
    }

    // ── (g) defensive: block_rejects_parent_state_missing ────────────────────

    #[test]
    fn block_rejects_parent_state_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _, _) = make_block_test_host(&dir);

        // Insert a parent block but NOT its state into fork-choice.
        let orphan_root = Root::from_array([0xaa; 32]);
        {
            let mut fc = host.fork_choice.write();
            fc.blocks.insert(orphan_root, {
                use pharos_types::phase0::primitives::ValidatorIndex;
                pharos_types::state::BeaconBlock::Phase0(MinimalBeaconBlock {
                    slot: Slot(0),
                    proposer_index: ValidatorIndex(0),
                    parent_root: Root::default(),
                    state_root: Root::default(),
                    body: MinimalBeaconBlockBody::default(),
                })
            });
            // Deliberately do NOT insert fc.block_states[orphan_root].
        }

        let block = make_signed_block(
            Slot(1),
            orphan_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Reject("block: parent invalid".into()),
        );
    }

    // ── (h) RB8: block_rejects_lower_or_equal_slot_than_parent ───────────────

    #[test]
    fn block_rejects_lower_or_equal_slot_than_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, parent_slot) = make_block_test_host(&dir);

        // Block at same slot as parent (parent_slot == 0).
        let block = make_signed_block(
            parent_slot,
            parent_root,
            &ForkMinimalState::Phase0(MinimalBeaconState::default()),
            0,
            false,
        );
        let result = host.validate_beacon_block(&block);
        // Because block.slot == 0 == finalized_slot (step 3 fires first), this
        // would Ignore at RB2. Use slot 1 with parent slot 1 to hit RB8.
        // Reset: insert a parent block at slot 2 (same as the test block slot).
        let parent2 = Root::from_array([0x55; 32]);
        // Re-use genesis state (has 1 validator so RB4 passes).
        let genesis_state = host.fork_choice.read().block_states[&parent_root].clone();
        {
            use pharos_types::phase0::primitives::ValidatorIndex;
            let mut fc = host.fork_choice.write();
            fc.blocks.insert(
                parent2,
                pharos_types::state::BeaconBlock::Phase0(MinimalBeaconBlock {
                    slot: Slot(2),
                    proposer_index: ValidatorIndex(0),
                    parent_root: Root::default(),
                    state_root: Root::default(),
                    body: MinimalBeaconBlockBody::default(),
                }),
            );
            fc.block_states.insert(parent2, genesis_state.clone());
        }
        // Block at slot 2 with parent also at slot 2 → RB8.
        let block2 = make_signed_block(Slot(2), parent2, &genesis_state, 0, false);
        assert_eq!(
            host.validate_beacon_block(&block2),
            GossipVerdict::Reject("block: not higher than parent slot".into()),
        );
        // Ensure the block_root was cached in invalid_block_roots (side effect).
        let block2_root: Root = {
            use pharos_ssz::TreeHash;
            use pharos_types::phase0::primitives::ValidatorIndex;
            MinimalBeaconBlock {
                slot: Slot(2),
                proposer_index: ValidatorIndex(0),
                parent_root: parent2,
                state_root: Root::default(),
                body: MinimalBeaconBlockBody::default(),
            }
            .tree_hash_root()
        };
        assert!(host.invalid_block_roots.read().peek(&block2_root).is_some());
        let _ = result; // suppress unused warning for the first check (expected Ignore)
    }

    // ── (i) RB9: block_rejects_finalized_not_ancestor ────────────────────────

    #[test]
    fn block_rejects_finalized_not_ancestor() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // The fork-choice has a finalized checkpoint at root=0x00..00.
        // Insert a "parent" block whose ancestry does NOT include that root.
        // We do this by inserting a parent with parent_root == [0xcc;32] (not in blocks).
        let fake_parent = Root::from_array([0xbb; 32]);
        // Re-use genesis state (has 1 validator so RB4 passes before RB9 can fire).
        let genesis_state = host.fork_choice.read().block_states[&parent_root].clone();
        {
            use pharos_types::phase0::primitives::ValidatorIndex;
            let mut fc = host.fork_choice.write();
            fc.blocks.insert(
                fake_parent,
                pharos_types::state::BeaconBlock::Phase0(MinimalBeaconBlock {
                    slot: Slot(1),
                    proposer_index: ValidatorIndex(0),
                    parent_root: Root::from_array([0xcc; 32]), // not in blocks → walk terminates
                    state_root: Root::default(),
                    body: MinimalBeaconBlockBody::default(),
                }),
            );
            fc.block_states.insert(fake_parent, genesis_state.clone());
        }

        // Block at slot 2 with this fake parent → finalized not ancestor.
        let block = make_signed_block(Slot(2), fake_parent, &genesis_state, 0, false);
        // get_checkpoint_block walks from fake_parent and finds nothing matching
        // the finalized root (0x00..00) → returns genesis root (walk terminates at
        // slot <= epoch_start).  If the returned root != finalized_checkpoint.root,
        // we REJECT.  The genesis root IS the finalized root in our test setup,
        // so this test forces a mismatch by using a parent not on the canonical chain.
        // Because the walk from fake_parent will return [0xcc;32]'s walk result
        // (which is get_ancestor of a missing root, returning [0xcc;32] itself —
        // actually get_ancestor walks until slot <= epoch_0_start = 0).
        // With epoch=0 and block_slot=1, get_checkpoint_block returns fake_parent
        // itself (its slot 1 > 0 so get_ancestor recurses to its parent=[0xcc;32]
        // which is not in blocks, so get_ancestor returns [0xcc;32]).
        // [0xcc;32] != finalized_checkpoint.root (0x00..00) → REJECT.
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Reject("block: finalized not ancestor".into()),
        );
    }

    // ── (j) RB10: block_rejects_proposer_mismatch ────────────────────────────

    #[test]
    fn block_rejects_proposer_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // The genesis state has 1 validator; expected proposer is 0.
        // Use proposer_index=0 but correct expected is also 0, so we need to
        // actually use index 0 but set the expected to something else.
        // Since there's only 1 validator, proposer_index=0 is always expected.
        // To trigger a mismatch, we'd need a state with ≥2 validators and
        // a shuffling that picks index ≠ the one we declare.
        // Simpler: add a second validator and declare proposer_index=1 when
        // the shuffling will select 0 (or vice versa).
        // Since shuffling with 1 validator always picks 0, we need 2+ validators.
        // Insert an extra validator into the parent state.
        {
            use pharos_types::phase0::misc::Validator;
            use pharos_types::phase0::primitives::Epoch;
            let extra_validator = Validator {
                pubkey: BLSPubkey::from_array([0x99u8; 48]),
                effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
                activation_epoch: Epoch(0),
                exit_epoch: Epoch(u64::MAX),
                withdrawable_epoch: Epoch(u64::MAX),
                slashed: false,
                ..Default::default()
            };
            let mut fc = host.fork_choice.write();
            let state = fc.block_states.get_mut(&parent_root).unwrap();
            if let ForkMinimalState::Phase0(inner) = state {
                inner.validators = SszList::with_push(&inner.validators, extra_validator).unwrap();
                inner.balances = SszList::with_push(
                    &inner.balances,
                    Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
                )
                .unwrap();
            }
        }

        // Get the actual expected proposer so we can declare a different one.
        let expected = host
            .lookup_or_compute_expected_proposer(Slot(1), parent_root)
            .map(|(idx, _)| idx)
            .unwrap();
        // Use the other index (0 → 1, or 1 → 0).
        let wrong_idx = if expected == 0 { 1 } else { 0 };

        let parent_state = host.fork_choice.read().block_states[&parent_root].clone();
        let block = make_signed_block(Slot(1), parent_root, &parent_state, wrong_idx, false);
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Reject("block: proposer mismatch".into()),
        );
    }

    // ── (k) RB5: block_rejects_invalid_signature ─────────────────────────────

    #[test]
    fn block_rejects_invalid_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        let parent_state = host.fork_choice.read().block_states[&parent_root].clone();
        // Flip a byte in the signature to make it invalid.
        let block = make_signed_block(Slot(1), parent_root, &parent_state, 0, true);
        assert_eq!(
            host.validate_beacon_block(&block),
            GossipVerdict::Reject("block: invalid proposer signature".into()),
        );
    }

    // ── (l) cache-mechanic: block_accepts_happy_path ─────────────────────────

    #[test]
    fn block_accepts_happy_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        let parent_state = host.fork_choice.read().block_states[&parent_root].clone();
        let expected = host
            .lookup_or_compute_expected_proposer(Slot(1), parent_root)
            .map(|(idx, _)| idx)
            .unwrap();
        let block = make_signed_block(Slot(1), parent_root, &parent_state, expected, false);
        assert_eq!(host.validate_beacon_block(&block), GossipVerdict::Accept);

        // Accept must insert into seen_block_proposers.
        assert!(
            host.seen_block_proposers
                .read()
                .peek(&(Slot(1), expected))
                .is_some(),
            "seen cache must be populated after accept"
        );
    }

    // ── per-fork dispatch coverage ───────────────────────────────────────────
    //
    // Regression guard for the M7 capella gossip-follow bug: `validate_beacon_block`
    // had no capella arm in its fork-unwrap chain, so every capella `beacon_block`
    // was Reject("unrecognised fork variant"). The unwrap is now the exhaustive
    // `EthSpec::signed_block_message`; this asserts EVERY active fork variant is
    // dispatched (reaches the validation pipeline) rather than rejected as an
    // unknown fork. Each default block is at slot 0 so it is IGNOREd at the
    // finalized-slot step — the point is that the fork-unwrap itself succeeds.
    #[test]
    fn block_validator_dispatches_every_fork_variant() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _parent_root, _) = make_block_test_host(&dir);

        // Build a default signed block of each fork variant via the EthSpec
        // associated inner types so the params match the fork enum exactly.
        let cases: [(&str, MinForkSigned); 4] = [
            (
                "phase0",
                MinForkSigned::Phase0(
                    <MinimalEthSpec as pharos_types::EthSpec>::Phase0SignedBeaconBlock::default(),
                ),
            ),
            (
                "altair",
                MinForkSigned::Altair(
                    <MinimalEthSpec as pharos_types::EthSpec>::AltairSignedBeaconBlock::default(),
                ),
            ),
            (
                "bellatrix",
                MinForkSigned::Bellatrix(
                    <MinimalEthSpec as pharos_types::EthSpec>::BellatrixSignedBeaconBlock::default(
                    ),
                ),
            ),
            (
                "capella",
                MinForkSigned::Capella(
                    <MinimalEthSpec as pharos_types::EthSpec>::CapellaSignedBeaconBlock::default(),
                ),
            ),
        ];

        for (name, block) in cases {
            let verdict = host.validate_beacon_block(&block);
            assert!(
                !matches!(&verdict, GossipVerdict::Reject(r) if r.contains("unrecognised fork variant")),
                "{name} beacon_block wrongly rejected as unrecognised fork variant: {verdict:?}"
            );
        }
    }

    // ── (m) cache-mechanic: block_proposer_cache_avoids_redo ─────────────────

    #[test]
    fn block_proposer_cache_avoids_redo() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        // First call: populates the proposer cache.
        let (expected, _) = host
            .lookup_or_compute_expected_proposer(Slot(1), parent_root)
            .unwrap();

        // Second call with same (slot, parent_root) must return the same index.
        let (expected2, _) = host
            .lookup_or_compute_expected_proposer(Slot(1), parent_root)
            .unwrap();
        assert_eq!(expected, expected2, "cache must return same proposer index");

        // Verify cache is populated.
        assert!(
            host.proposer_cache
                .read()
                .peek(&(Slot(1), parent_root))
                .is_some(),
            "proposer_cache must be populated after first call"
        );

        // Verify that the proposer cache has the entry from the first call.
        // A second call for the same (slot, parent_root) must return the cached
        // value rather than re-acquiring the fork-choice lock.
        // (With 1 validator in test state, any wrong_idx would hit RB4 first,
        // but the cache population — the mechanic under test — is verified above.)
        assert!(
            host.proposer_cache
                .read()
                .peek(&(Slot(1), parent_root))
                .is_some()
        );
    }

    // ── (n) cache-mechanic: block_invalid_roots_cache_persists ───────────────

    #[test]
    fn block_invalid_roots_cache_persists() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, parent_root, _) = make_block_test_host(&dir);

        let parent_state = host.fork_choice.read().block_states[&parent_root].clone();
        let expected = host
            .lookup_or_compute_expected_proposer(Slot(1), parent_root)
            .map(|(idx, _)| idx)
            .unwrap();

        // First call: invalid signature → REJECT; must also insert into invalid_block_roots.
        let bad_block = make_signed_block(Slot(1), parent_root, &parent_state, expected, true);
        let bad_block_root: Root = {
            use pharos_types::phase0::primitives::ValidatorIndex;
            MinimalBeaconBlock {
                slot: Slot(1),
                proposer_index: ValidatorIndex(expected),
                parent_root,
                state_root: Root::default(),
                body: MinimalBeaconBlockBody::default(),
            }
            .tree_hash_root()
        };
        assert_eq!(
            host.validate_beacon_block(&bad_block),
            GossipVerdict::Reject("block: invalid proposer signature".into()),
        );
        assert!(
            host.invalid_block_roots
                .read()
                .peek(&bad_block_root)
                .is_some(),
            "bad block root must be in invalid_block_roots"
        );

        // Second call: a child block whose parent_root == bad_block_root.
        // This must trigger the step-1 short-circuit (RB7).
        let child_block =
            make_signed_block(Slot(2), bad_block_root, &parent_state, expected, false);
        assert_eq!(
            host.validate_beacon_block(&child_block),
            GossipVerdict::Reject("block: parent in invalid set".into()),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attestation validation tests (Tasks 2.5 a–m, RAT1–RAT12 + happy path)
    // ─────────────────────────────────────────────────────────────────────────

    use pharos_stf::phase0::accessors::{
        compute_signing_root as att_signing_root, get_domain as att_get_domain,
    };
    use pharos_stf::phase0::helpers::DOMAIN_BEACON_ATTESTER;
    use pharos_types::phase0::misc::{AttestationData, Checkpoint};
    use pharos_types::phase0::primitives::CommitteeIndex;

    /// Attestation-test runtime config with `seconds_per_slot` for MinimalEthSpec.
    fn att_runtime_cfg(_att_slot: u64) -> Arc<RuntimeConfig> {
        let seconds_per_slot = MinimalEthSpec::SLOT_DURATION_MS / 1000; // 6 s
        Arc::new(RuntimeConfig {
            seconds_per_slot,
            ..Default::default()
        })
    }

    /// Build a `HostImpl<MinimalEthSpec>` wired for attestation testing.
    ///
    /// - One validator at index 0 (pubkey = `att_test_pubkey()`).
    /// - Fork-choice has genesis block+state at root `genesis_root`.
    /// - genesis_time set so `att_slot` is within the propagation window.
    ///
    /// Returns `(host, genesis_root, genesis_state)`.
    fn make_att_test_host(
        dir: &tempfile::TempDir,
        att_slot: u64,
    ) -> (HostImpl<MinimalEthSpec>, Root, ForkMinimalState) {
        use pharos_types::phase0::misc::Fork;
        use pharos_types::phase0::operations::BeaconBlockHeader;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};

        let store = Arc::new(
            RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );

        let genesis_slot = Slot(0);

        // Use 8 validators (all with att_test_pubkey) so that slot=0 / index=0
        // committee is non-empty (size=1 with 8 validators and SLOTS_PER_EPOCH=8).
        let validator = pharos_types::phase0::misc::Validator {
            pubkey: att_test_pubkey(),
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            slashed: false,
            ..Default::default()
        };
        let validators_vec = vec![validator.clone(); 8];
        let balances_vec = vec![Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE); 8];
        let validators_list =
            pharos_ssz::SszList::from_vec(validators_vec).expect("8 validators within limit");
        let balances_list =
            pharos_ssz::SszList::from_vec(balances_vec).expect("8 balances within limit");

        let genesis_body_root = MinimalBeaconBlockBody::default().tree_hash_root();
        let genesis_state_inner = MinimalBeaconState {
            genesis_time: 0,
            slot: genesis_slot,
            fork: Fork {
                previous_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                current_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                epoch: Epoch(0),
            },
            latest_block_header: BeaconBlockHeader {
                slot: genesis_slot,
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: genesis_body_root,
            },
            validators: validators_list,
            balances: balances_list,
            ..Default::default()
        };

        let fork_genesis_state = ForkMinimalState::Phase0(genesis_state_inner.clone());
        let state_root = fork_genesis_state.tree_hash_root();

        let genesis_block = MinimalBeaconBlock {
            slot: genesis_slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root,
            body: MinimalBeaconBlockBody::default(),
        };
        let genesis_root: Root = genesis_block.tree_hash_root();

        let fork_genesis_block = pharos_types::state::BeaconBlock::Phase0(genesis_block);

        let fc_store = pharos_fork_choice::get_forkchoice_store::<MinimalEthSpec>(
            fork_genesis_state.clone(),
            fork_genesis_block,
        );
        let fork_choice = Arc::new(RwLock::new(fc_store));

        {
            let mut fc = fork_choice.write();
            fc.block_states
                .insert(genesis_root, fork_genesis_state.clone());
            fc.blocks.insert(genesis_root, {
                let b = MinimalBeaconBlock {
                    slot: genesis_slot,
                    proposer_index: ValidatorIndex(0),
                    parent_root: Root::default(),
                    state_root: fork_genesis_state.tree_hash_root(),
                    body: MinimalBeaconBlockBody::default(),
                };
                pharos_types::state::BeaconBlock::Phase0(b)
            });
            // Set genesis_time in the fork_choice store to match att_runtime_cfg.
            let seconds_per_slot = MinimalEthSpec::SLOT_DURATION_MS / 1000;
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            fc.genesis_time = now_sec.saturating_sub(att_slot * seconds_per_slot + 1);
        }

        let gvr = Root::default();
        // Phase0-only schedule: altair/bellatrix epochs = FAR_FUTURE, versions = mainnet defaults.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(u64::MAX),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(u64::MAX),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            genesis_validators_root: gvr,
        };
        let runtime_cfg = att_runtime_cfg(att_slot);
        let host =
            HostImpl::<MinimalEthSpec>::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg);
        (host, genesis_root, fork_genesis_state)
    }

    fn att_test_sk() -> BlstSecretKey {
        BlstSecretKey::key_gen(&[99u8; 32], &[]).expect("valid IKM")
    }

    fn att_test_pubkey() -> BLSPubkey {
        BLSPubkey::from_array(att_test_sk().sk_to_pk().compress())
    }

    fn att_test_sign(msg: &[u8]) -> BLSSignature {
        BLSSignature::from_array(att_test_sk().sign(msg, BLS_DST, &[]).compress())
    }

    /// Build a valid-looking attestation data for slot=0, committee_index=0,
    /// targeting `beacon_block_root` as both the voted block and target root.
    fn make_att_data(beacon_block_root: Root) -> AttestationData {
        AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: beacon_block_root,
            },
        }
    }

    /// Build a properly-signed unaggregated attestation for validator 0 in a
    /// single-validator committee at slot 0 / committee_index 0.
    fn make_signed_att(
        beacon_block_root: Root,
        head_state: &ForkMinimalState,
        flip_sig: bool,
    ) -> pharos_types::phase0::Attestation<2048> {
        use pharos_ssz::Bitlist;
        let data = make_att_data(beacon_block_root);
        let domain =
            att_get_domain::<MinimalEthSpec>(head_state, DOMAIN_BEACON_ATTESTER, Some(Epoch(0)));
        let signing_root = att_signing_root(&data, domain);
        let mut sig_bytes: [u8; 96] = att_test_sign(signing_root.as_ref()).into();
        if flip_sig {
            sig_bytes[0] ^= 0xff;
        }
        let sig = BLSSignature::from_array(sig_bytes);
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap(); // validator 0 attests
        pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: sig,
        }
    }

    /// Compute the expected subnet for slot=0, index=0, committees_per_slot=1,
    /// MinimalEthSpec: 0 % 64 = 0.
    fn att_expected_subnet() -> u64 {
        0
    }

    // ── (a) RAT1: att_rejects_committee_index_out_of_range ──────────────────

    #[test]
    fn att_rejects_committee_index_out_of_range() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(9999), // way out of range
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: genesis_root,
            },
        };
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Reject("att: committee index out of range".into()),
        );
    }

    // ── (b) RAT2: att_rejects_wrong_subnet ──────────────────────────────────

    #[test]
    fn att_rejects_wrong_subnet() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        let data = make_att_data(genesis_root);
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };

        // Pass subnet=1 but expected is 0.
        assert_eq!(
            host.validate_attestation(1, &att),
            GossipVerdict::Reject("att: wrong subnet".into()),
        );
    }

    // ── (c) RAT3: att_ignores_slot_out_of_range ──────────────────────────────

    #[test]
    fn att_ignores_slot_out_of_range() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        // Override genesis_time to 0 so all slots are "too old" for the propagation window.
        host.fork_choice.write().genesis_time = 0;

        let data = make_att_data(genesis_root);
        let mut bits = pharos_ssz::Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Ignore("att: slot not in propagation range".into()),
        );
    }

    // ── (d) RAT4: att_rejects_target_epoch_mismatch ─────────────────────────

    #[test]
    fn att_rejects_target_epoch_mismatch() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        // slot=0 → epoch=0, but target.epoch=1 → mismatch.
        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(1),
                root: genesis_root,
            }, // wrong epoch
        };
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Reject("att: target epoch mismatch".into()),
        );
    }

    // ── (e) RAT5: att_rejects_aggregated_bits ───────────────────────────────

    #[test]
    fn att_rejects_aggregated_bits() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        let data = make_att_data(genesis_root);
        // Zero bits set → not unaggregated.
        let bits = Bitlist::<2048>::new();
        let att_zero = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data: data.clone(),
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att_zero),
            GossipVerdict::Reject("att: not unaggregated".into()),
        );

        // Two bits set → aggregated.
        let mut bits2 = Bitlist::<2048>::new();
        bits2.push(true).unwrap();
        bits2.push(true).unwrap();
        let att_two = pharos_types::phase0::Attestation {
            aggregation_bits: bits2,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att_two),
            GossipVerdict::Reject("att: not unaggregated".into()),
        );
    }

    // ── (f) RAT6: att_rejects_agg_bits_length_mismatch ──────────────────────

    #[test]
    fn att_rejects_agg_bits_length_mismatch() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        let data = make_att_data(genesis_root);
        // Committee has 1 member but we send a bitlist with bit 5 set (length > committee).
        let mut bits = Bitlist::<2048>::new();
        bits.push(false).unwrap();
        bits.push(false).unwrap();
        bits.push(false).unwrap();
        bits.push(false).unwrap();
        bits.push(false).unwrap();
        bits.push(true).unwrap(); // bit 5 set, length=6 > committee size=1
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Reject("att: agg bits length mismatch".into()),
        );
    }

    // ── (g) RAT7: att_ignores_duplicate_validator_epoch ─────────────────────

    #[test]
    fn att_ignores_duplicate_validator_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        let att = make_signed_att(genesis_root, &genesis_state, false);

        // Determine the actual participant by computing the committee directly.
        let participant = {
            use pharos_stf::phase0::accessors::get_beacon_committee;
            let committee = get_beacon_committee::<MinimalEthSpec>(&genesis_state, Slot(0), 0);
            let bit_idx = att.aggregation_bits.iter().position(|b| b).unwrap();
            committee[bit_idx].0
        };
        // Pre-populate the seen cache with the actual participant's (index, epoch).
        host.seen_attestation_validators
            .write()
            .put((participant, Epoch(0)), ());

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Ignore("att: duplicate validator/epoch".into()),
        );
    }

    // ── (h) RAT8: att_rejects_invalid_signature ──────────────────────────────

    #[test]
    fn att_rejects_invalid_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        // flip_sig=true → bad signature.
        let att = make_signed_att(genesis_root, &genesis_state, true);

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Reject("att: invalid signature".into()),
        );
    }

    // ── (i) RAT9: att_ignores_unseen_voted_block ─────────────────────────────

    #[test]
    fn att_ignores_unseen_voted_block() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        // Use a beacon_block_root that is NOT in the fork-choice store.
        let unknown_root = Root::from_array([0xab; 32]);
        // Build an attestation with the correct target root for the unknown block root.
        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: unknown_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: unknown_root,
            },
        };
        let domain = att_get_domain::<MinimalEthSpec>(
            &genesis_state,
            DOMAIN_BEACON_ATTESTER,
            Some(Epoch(0)),
        );
        let signing_root = att_signing_root(&data, domain);
        let sig = att_test_sign(signing_root.as_ref());
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att2 = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: sig,
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att2),
            GossipVerdict::Ignore("att: voted block unseen".into()),
        );
    }

    // ── (j) RAT10: att_rejects_invalid_voted_block ───────────────────────────

    #[test]
    fn att_rejects_invalid_voted_block() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        // Insert a block root into `fc.blocks` but NOT into `fc.block_states`.
        // This simulates a block that has been seen but failed validation.
        let orphan_root = Root::from_array([0xcd; 32]);
        {
            let mut fc = host.fork_choice.write();
            fc.blocks.insert(orphan_root, {
                pharos_types::state::BeaconBlock::Phase0(MinimalBeaconBlock {
                    slot: Slot(0),
                    ..Default::default()
                })
            });
            // Do NOT insert into block_states.
        }

        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: orphan_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: orphan_root,
            },
        };
        let domain = att_get_domain::<MinimalEthSpec>(
            &genesis_state,
            DOMAIN_BEACON_ATTESTER,
            Some(Epoch(0)),
        );
        let signing_root = att_signing_root(&data, domain);
        let sig = att_test_sign(signing_root.as_ref());
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: sig,
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Reject("att: voted block invalid".into()),
        );
    }

    // ── (k) RAT11: att_rejects_target_not_ancestor ──────────────────────────

    #[test]
    fn att_rejects_target_not_ancestor() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        // target.root points somewhere that is NOT an ancestor of genesis_root.
        let wrong_target = Root::from_array([0xef; 32]);
        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: wrong_target,
            },
        };
        let domain = att_get_domain::<MinimalEthSpec>(
            &genesis_state,
            DOMAIN_BEACON_ATTESTER,
            Some(Epoch(0)),
        );
        let signing_root = att_signing_root(&data, domain);
        let sig = att_test_sign(signing_root.as_ref());
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let att = pharos_types::phase0::Attestation {
            aggregation_bits: bits,
            data,
            signature: sig,
        };

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Reject("att: target not ancestor".into()),
        );
    }

    // ── (l) RAT12: att_ignores_finalized_not_ancestor ───────────────────────

    #[test]
    fn att_ignores_finalized_not_ancestor() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        // Override the finalized checkpoint to point at a root that is NOT
        // an ancestor of genesis_root.
        let fake_finalized = Root::from_array([0x77; 32]);
        {
            let mut fc = host.fork_choice.write();
            fc.finalized_checkpoint = Checkpoint {
                epoch: Epoch(0),
                root: fake_finalized,
            };
        }

        let att = make_signed_att(genesis_root, &genesis_state, false);

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Ignore("att: finalized not ancestor".into()),
        );
    }

    // ── (m) happy path: att_accepts_happy_path ───────────────────────────────

    #[test]
    fn att_accepts_happy_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        let att = make_signed_att(genesis_root, &genesis_state, false);

        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Accept,
        );

        // Second call with same validator/epoch must be deduplicated (RAT7).
        assert_eq!(
            host.validate_attestation(att_expected_subnet(), &att),
            GossipVerdict::Ignore("att: duplicate validator/epoch".into()),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Aggregate-and-proof validation tests (Task 3.5 a–q, RAG1–RAG16 + happy)
    // ─────────────────────────────────────────────────────────────────────────

    use pharos_stf::phase0::accessors::get_beacon_committee;
    use pharos_stf::phase0::helpers::{DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF};
    use pharos_types::phase0::primitives::ValidatorIndex;
    use pharos_types::phase0::{AggregateAndProof, SignedAggregateAndProof};

    /// Build the slot-based signing root for the selection proof.
    fn sel_signing_root(state: &ForkMinimalState, slot: Slot) -> Root {
        let domain =
            att_get_domain::<MinimalEthSpec>(state, DOMAIN_SELECTION_PROOF, Some(Epoch(0)));
        att_signing_root(&slot, domain)
    }

    /// Build the signing root for the aggregator signature over AggregateAndProof.
    fn aap_signing_root(state: &ForkMinimalState, aap: &AggregateAndProof<2048>) -> Root {
        let domain =
            att_get_domain::<MinimalEthSpec>(state, DOMAIN_AGGREGATE_AND_PROOF, Some(Epoch(0)));
        att_signing_root(aap, domain)
    }

    /// Build a valid SignedAggregateAndProof for the given parameters.
    ///
    /// - `beacon_block_root`: root that goes into the attestation data.
    /// - `head_state`: state used for domain computation.
    /// - `aggregator_index`: index of the aggregating validator (all use `att_test_sk`).
    /// - `flip_sel`: if true, corrupt the selection proof.
    /// - `flip_agg_sig`: if true, corrupt the aggregator signature.
    /// - `flip_agg_att_sig`: if true, corrupt the aggregate attestation signature.
    fn make_signed_aap(
        beacon_block_root: Root,
        head_state: &ForkMinimalState,
        aggregator_index: u64,
        flip_sel: bool,
        flip_agg_sig: bool,
        flip_agg_att_sig: bool,
    ) -> SignedAggregateAndProof<2048> {
        use pharos_ssz::Bitlist;

        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: beacon_block_root,
            },
        };

        // Build aggregation bits with all committee members attesting.
        // Committee at slot=0,index=0 has 1 member for our 8-validator state.
        let committee_len = {
            let c = get_beacon_committee::<MinimalEthSpec>(head_state, Slot(0), 0);
            c.len()
        };
        let mut bits = Bitlist::<2048>::new();
        for _ in 0..committee_len {
            bits.push(true).unwrap();
        }

        // Sign the aggregate over attestation data (DOMAIN_BEACON_ATTESTER).
        let att_domain =
            att_get_domain::<MinimalEthSpec>(head_state, DOMAIN_BEACON_ATTESTER, Some(Epoch(0)));
        let att_signing = att_signing_root(&data, att_domain);
        let mut att_sig_bytes: [u8; 96] = att_test_sign(att_signing.as_ref()).into();
        if flip_agg_att_sig {
            att_sig_bytes[0] ^= 0xff;
        }

        let agg_and_proof = AggregateAndProof {
            aggregator_index: ValidatorIndex(aggregator_index),
            aggregate: pharos_types::phase0::Attestation {
                aggregation_bits: bits,
                data,
                signature: BLSSignature::from_array(att_sig_bytes),
            },
            selection_proof: {
                // Selection proof: sign(slot=0) with DOMAIN_SELECTION_PROOF.
                let sr = sel_signing_root(head_state, Slot(0));
                let mut bytes: [u8; 96] = att_test_sign(sr.as_ref()).into();
                if flip_sel {
                    bytes[0] ^= 0xff;
                }
                BLSSignature::from_array(bytes)
            },
        };

        // Aggregator signature: sign(AggregateAndProof) with DOMAIN_AGGREGATE_AND_PROOF.
        let aap_sr = aap_signing_root(head_state, &agg_and_proof);
        let mut aap_sig_bytes: [u8; 96] = att_test_sign(aap_sr.as_ref()).into();
        if flip_agg_sig {
            aap_sig_bytes[0] ^= 0xff;
        }

        SignedAggregateAndProof {
            message: agg_and_proof,
            signature: BLSSignature::from_array(aap_sig_bytes),
        }
    }

    /// Compute the actual aggregator index for slot=0, committee=0 in a
    /// 8-validator state (first member of the committee).
    fn agg_test_aggregator_index(head_state: &ForkMinimalState) -> u64 {
        let c = get_beacon_committee::<MinimalEthSpec>(head_state, Slot(0), 0);
        c[0].0
    }

    // ── (a) RAG1: agg_rejects_committee_index_out_of_range ──────────────────

    #[test]
    fn agg_rejects_committee_index_out_of_range() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        // committee_index=9999 is way out of range.
        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(9999),
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: genesis_root,
            },
        };
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let agg_and_proof = AggregateAndProof {
            aggregator_index: ValidatorIndex(0),
            aggregate: pharos_types::phase0::Attestation {
                aggregation_bits: bits,
                data,
                signature: BLSSignature::from_array([0u8; 96]),
            },
            selection_proof: BLSSignature::from_array([0u8; 96]),
        };
        let saap = SignedAggregateAndProof {
            message: agg_and_proof,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        let _ = genesis_state;
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: committee index out of range".into()),
        );
    }

    // ── (b) RAG2: agg_ignores_slot_out_of_range ─────────────────────────────

    #[test]
    fn agg_ignores_slot_out_of_range() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        // Override genesis_time to 0 so slot=0 is out of propagation window.
        host.fork_choice.write().genesis_time = 0;

        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: genesis_root,
            },
        };
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let saap = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: ValidatorIndex(0),
                aggregate: pharos_types::phase0::Attestation {
                    aggregation_bits: bits,
                    data,
                    signature: BLSSignature::from_array([0u8; 96]),
                },
                selection_proof: BLSSignature::from_array([0u8; 96]),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Ignore("agg: slot not in propagation range".into()),
        );
    }

    // ── (c) RAG3: agg_rejects_target_epoch_mismatch ─────────────────────────

    #[test]
    fn agg_rejects_target_epoch_mismatch() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        // slot=0 → epoch=0, but target.epoch=1 → mismatch.
        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(1),
                root: genesis_root,
            },
        };
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        let saap = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: ValidatorIndex(0),
                aggregate: pharos_types::phase0::Attestation {
                    aggregation_bits: bits,
                    data,
                    signature: BLSSignature::from_array([0u8; 96]),
                },
                selection_proof: BLSSignature::from_array([0u8; 96]),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: target epoch mismatch".into()),
        );
    }

    // ── (d) RAG4: agg_rejects_agg_bits_length_mismatch ──────────────────────

    #[test]
    fn agg_rejects_agg_bits_length_mismatch() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        // Committee size = 1 for our test setup, but we push 6 bits.
        let data = make_att_data(genesis_root);
        let mut bits = Bitlist::<2048>::new();
        for _ in 0..6 {
            bits.push(false).unwrap();
        }
        bits.set(5, true);
        let saap = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: ValidatorIndex(0),
                aggregate: pharos_types::phase0::Attestation {
                    aggregation_bits: bits,
                    data,
                    signature: BLSSignature::from_array([0u8; 96]),
                },
                selection_proof: BLSSignature::from_array([0u8; 96]),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: agg bits length mismatch".into()),
        );
    }

    // ── (e) RAG5: agg_rejects_no_participants ───────────────────────────────

    #[test]
    fn agg_rejects_no_participants() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, _) = make_att_test_host(&dir, 0);

        // Zero bits set → no participants.
        let data = make_att_data(genesis_root);
        let mut bits = Bitlist::<2048>::new();
        bits.push(false).unwrap(); // committee size=1, bit=false → no participants
        let saap = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: ValidatorIndex(0),
                aggregate: pharos_types::phase0::Attestation {
                    aggregation_bits: bits,
                    data,
                    signature: BLSSignature::from_array([0u8; 96]),
                },
                selection_proof: BLSSignature::from_array([0u8; 96]),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: no participants".into()),
        );
    }

    // ── (f) RAG6: agg_ignores_seen_superset ─────────────────────────────────

    #[test]
    fn agg_ignores_seen_superset() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // First call: accept to populate seen_aggregate_data.
        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Accept,
        );

        // Second call: same aggregate data but different aggregator_index.
        // RAG6 fires before RAG7 in the pipeline, so this hits RAG6 (superset seen)
        // because bit[0]=true is already stored for this data_root.
        let saap_same = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index + 1,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap_same),
            GossipVerdict::Ignore("agg: superset seen".into()),
        );
    }

    // ── (g) RAG7: agg_ignores_duplicate_aggregator_epoch ────────────────────

    #[test]
    fn agg_ignores_duplicate_aggregator_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // Pre-populate the seen_aggregators cache.
        host.seen_aggregators
            .write()
            .put((aggregator_index, Epoch(0)), ());

        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Ignore("agg: duplicate aggregator/epoch".into()),
        );
    }

    // ── (h) RAG8: agg_rejects_not_aggregator ────────────────────────────────

    #[test]
    fn agg_rejects_not_aggregator() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // Use a selection proof that sha256-hashes to n%1 != 0.
        // With committee_len=1, modulo=1, so n%1==0 always → can never reject RAG8.
        // We need committee_len > 16 to get modulo > 1.
        // Our test state has 1-member committee, so RAG8 cannot fire with our setup.
        // Instead: build a custom attestation with mismatched committee index that
        // has a larger committee... but that requires restructuring the state.
        //
        // Workaround: use a selection proof with [0x01]*96 bytes.
        // sha256([0x01]*96)[0..8] LE = 15010667366611956363, %2 = 1 → not aggregator for clen=32.
        // We can't easily get clen=32 in test. Instead, since clen=1 → modulo=1 → always aggregator,
        // we patch the committee in the cache to fake clen=32 by pre-populating with a larger vec.
        //
        // Pre-populate committee_cache with 32 members so modulo=max(1,32/16)=2.
        let fake_committee: Vec<u64> = (0u64..32).collect();
        let head_root = {
            let fc = host.fork_choice.read();
            pharos_fork_choice::get_head(&*fc)
        };
        host.committee_cache
            .write()
            .put((Slot(0), 0, head_root), fake_committee.clone());

        let data = make_att_data(genesis_root);
        // Build bitlist of length 32 with first bit set.
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        for _ in 1..32 {
            bits.push(false).unwrap();
        }

        // selection_proof = [0x01]*96 → sha256 n%2=1 → not aggregator.
        let agg_and_proof = AggregateAndProof {
            aggregator_index: ValidatorIndex(aggregator_index),
            aggregate: pharos_types::phase0::Attestation {
                aggregation_bits: bits,
                data,
                signature: BLSSignature::from_array([0u8; 96]),
            },
            selection_proof: BLSSignature::from_array([0x01u8; 96]),
        };
        let saap = SignedAggregateAndProof {
            message: agg_and_proof,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: not selected as aggregator".into()),
        );
    }

    // ── (i) RAG9: agg_rejects_aggregator_not_in_committee ───────────────────

    #[test]
    fn agg_rejects_aggregator_not_in_committee() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);

        let data = make_att_data(genesis_root);
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        // Use aggregator_index=99 which is NOT in the committee (and not in state validators).
        let saap = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: ValidatorIndex(99),
                aggregate: pharos_types::phase0::Attestation {
                    aggregation_bits: bits,
                    data,
                    signature: BLSSignature::from_array([0u8; 96]),
                },
                // selection_proof with [0x00]*96 → n%1=0 → is_aggregator=true (clen=1, modulo=1).
                selection_proof: BLSSignature::from_array([0x00u8; 96]),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        let _ = genesis_state;
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: aggregator not in committee".into()),
        );
    }

    // ── (j) RAG10: agg_rejects_invalid_selection_proof ──────────────────────

    #[test]
    fn agg_rejects_invalid_selection_proof() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // flip_sel=true → bad selection proof.
        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            true,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: invalid selection proof signature".into()),
        );
    }

    // ── (k) RAG11: agg_rejects_invalid_aggregator_signature ─────────────────

    #[test]
    fn agg_rejects_invalid_aggregator_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // flip_agg_sig=true → bad outer signature.
        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            false,
            true,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: invalid aggregator signature".into()),
        );
    }

    // ── (l) RAG12: agg_rejects_invalid_aggregate_signature ──────────────────

    #[test]
    fn agg_rejects_invalid_aggregate_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // flip_agg_att_sig=true → bad inner aggregate attestation signature.
        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            true,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: invalid aggregate signature".into()),
        );
    }

    // ── (m) RAG13: agg_ignores_unseen_voted_block ────────────────────────────

    #[test]
    fn agg_ignores_unseen_voted_block() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // Use a beacon_block_root not in the fork-choice store.
        let unknown_root = Root::from_array([0xab; 32]);
        let saap = make_signed_aap(
            unknown_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Ignore("agg: voted block unseen".into()),
        );
    }

    // ── (n) RAG14: agg_rejects_voted_block_invalid ───────────────────────────

    #[test]
    fn agg_rejects_voted_block_invalid() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, _genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // Insert a block into fc.blocks but NOT into fc.block_states (failed validation).
        let orphan_root = Root::from_array([0xcd; 32]);
        {
            let mut fc = host.fork_choice.write();
            fc.blocks.insert(
                orphan_root,
                pharos_types::state::BeaconBlock::Phase0(MinimalBeaconBlock {
                    slot: Slot(0),
                    ..Default::default()
                }),
            );
        }

        let saap = make_signed_aap(
            orphan_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: voted block invalid".into()),
        );
    }

    // ── (o) RAG15: agg_rejects_target_not_ancestor ───────────────────────────

    #[test]
    fn agg_rejects_target_not_ancestor() {
        use pharos_ssz::Bitlist;
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // Build an attestation with target.root != get_checkpoint_block result.
        let wrong_target = Root::from_array([0xef; 32]);
        let data = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: genesis_root,
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: wrong_target,
            },
        };
        let mut bits = Bitlist::<2048>::new();
        bits.push(true).unwrap();
        // Build a valid selection proof and aggregator sig for this data.
        let domain_sel = att_get_domain::<MinimalEthSpec>(
            &genesis_state,
            DOMAIN_SELECTION_PROOF,
            Some(Epoch(0)),
        );
        let sr_sel = att_signing_root(&Slot(0u64), domain_sel);
        let sel_proof = att_test_sign(sr_sel.as_ref());
        let att_domain = att_get_domain::<MinimalEthSpec>(
            &genesis_state,
            DOMAIN_BEACON_ATTESTER,
            Some(Epoch(0)),
        );
        let att_sr = att_signing_root(&data, att_domain);
        let att_sig = att_test_sign(att_sr.as_ref());
        let agg_and_proof = AggregateAndProof {
            aggregator_index: ValidatorIndex(aggregator_index),
            aggregate: pharos_types::phase0::Attestation {
                aggregation_bits: bits,
                data,
                signature: att_sig,
            },
            selection_proof: sel_proof,
        };
        let domain_aap = att_get_domain::<MinimalEthSpec>(
            &genesis_state,
            DOMAIN_AGGREGATE_AND_PROOF,
            Some(Epoch(0)),
        );
        let aap_sr = att_signing_root(&agg_and_proof, domain_aap);
        let aap_sig = att_test_sign(aap_sr.as_ref());
        let saap = SignedAggregateAndProof {
            message: agg_and_proof,
            signature: aap_sig,
        };
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Reject("agg: target not ancestor".into()),
        );
    }

    // ── (p) RAG16: agg_ignores_finalized_not_ancestor ────────────────────────

    #[test]
    fn agg_ignores_finalized_not_ancestor() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        // Override finalized checkpoint to a root not on genesis's chain.
        let fake_finalized = Root::from_array([0x77; 32]);
        {
            let mut fc = host.fork_choice.write();
            fc.finalized_checkpoint = Checkpoint {
                epoch: Epoch(0),
                root: fake_finalized,
            };
        }

        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Ignore("agg: finalized not ancestor".into()),
        );
    }

    // ── (q) happy path: agg_accepts_happy_path ───────────────────────────────

    #[test]
    fn agg_accepts_happy_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let (host, genesis_root, genesis_state) = make_att_test_host(&dir, 0);
        let aggregator_index = agg_test_aggregator_index(&genesis_state);

        let saap = make_signed_aap(
            genesis_root,
            &genesis_state,
            aggregator_index,
            false,
            false,
            false,
        );
        assert_eq!(
            host.validate_aggregate_and_proof(&saap),
            GossipVerdict::Accept,
        );

        // Verify seen_aggregators was populated.
        assert!(
            host.seen_aggregators
                .read()
                .peek(&(aggregator_index, Epoch(0)))
                .is_some(),
            "seen_aggregators must be populated after Accept"
        );

        // Second call with same data/bits must deduplicate (RAG6 or RAG7).
        // RAG6 (superset-seen) fires before RAG7 because seen_aggregate_data
        // is populated on Accept; either Ignore is correct deduplication.
        let second = host.validate_aggregate_and_proof(&saap);
        assert!(
            matches!(second, GossipVerdict::Ignore(_)),
            "second call must Ignore (either RAG6 or RAG7 dedup), got {:?}",
            second,
        );
    }

    // ── voluntary_exit validation tests ──────────────────────────────────────

    // Helpers for exit/slashing tests.
    fn exit_test_sk() -> BlstSecretKey {
        BlstSecretKey::key_gen(&[77u8; 32], &[]).expect("valid IKM")
    }

    fn exit_test_pubkey() -> BLSPubkey {
        BLSPubkey::from_array(exit_test_sk().sk_to_pk().compress())
    }

    /// Build a host with the validator set up for exit tests. The validator has:
    /// - pubkey from exit_test_sk
    /// - activation_epoch = 0
    /// - exit_epoch = FAR_FUTURE (not yet exiting)
    fn make_exit_test_host(dir: &tempfile::TempDir) -> HostImpl<MinimalEthSpec> {
        use pharos_types::phase0::misc::Fork;
        use pharos_types::phase0::operations::BeaconBlockHeader;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};

        let store = Arc::new(
            RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );

        let genesis_slot = Slot(0);
        let validator = pharos_types::phase0::misc::Validator {
            pubkey: exit_test_pubkey(),
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            slashed: false,
            ..Default::default()
        };

        let genesis_body_root = MinimalBeaconBlockBody::default().tree_hash_root();
        let genesis_state_inner = MinimalBeaconState {
            genesis_time: 0,
            slot: genesis_slot,
            fork: Fork {
                previous_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                current_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                epoch: Epoch(0),
            },
            latest_block_header: BeaconBlockHeader {
                slot: genesis_slot,
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: genesis_body_root,
            },
            validators: SszList::with_push(&SszList::default(), validator).unwrap(),
            balances: SszList::with_push(
                &SszList::default(),
                Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            )
            .unwrap(),
            ..Default::default()
        };

        let fork_genesis_state = ForkMinimalState::Phase0(genesis_state_inner.clone());

        let genesis_inner_block = MinimalBeaconBlock {
            slot: genesis_slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: fork_genesis_state.tree_hash_root(),
            body: MinimalBeaconBlockBody::default(),
        };
        let genesis_root: Root = genesis_inner_block.tree_hash_root();
        let genesis_block = pharos_types::state::BeaconBlock::Phase0(genesis_inner_block);

        let fc_store = pharos_fork_choice::get_forkchoice_store::<MinimalEthSpec>(
            fork_genesis_state.clone(),
            genesis_block.clone(),
        );
        let fork_choice = Arc::new(RwLock::new(fc_store));
        {
            let mut fc = fork_choice.write();
            fc.block_states
                .insert(genesis_root, fork_genesis_state.clone());
            fc.blocks.insert(genesis_root, genesis_block);
        }

        let gvr = Root::default();
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(u64::MAX),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(u64::MAX),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            genesis_validators_root: gvr,
        };
        let runtime_cfg = Arc::new(RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            ..Default::default()
        });
        HostImpl::<MinimalEthSpec>::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg)
    }

    fn make_valid_exit(host: &HostImpl<MinimalEthSpec>) -> SignedVoluntaryExit {
        use pharos_stf::phase0::helpers::DOMAIN_VOLUNTARY_EXIT;
        use pharos_types::BeaconStateView as _;
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::ValidatorIndex;

        let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
        let state = host
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
            .unwrap();
        let current_epoch = pharos_stf::phase0::accessors::compute_epoch_at_slot(
            state.slot(),
            MinimalEthSpec::SLOTS_PER_EPOCH,
        );

        let exit = VoluntaryExit {
            epoch: current_epoch,
            validator_index: ValidatorIndex(0),
        };
        let domain = pharos_stf::phase0::accessors::get_domain::<MinimalEthSpec>(
            &state,
            DOMAIN_VOLUNTARY_EXIT,
            Some(current_epoch),
        );
        let signing_root = pharos_stf::phase0::accessors::compute_signing_root(&exit, domain);
        let sig = BLSSignature::from_array(
            exit_test_sk()
                .sign(signing_root.as_ref(), BLS_DST, &[])
                .compress(),
        );
        SignedVoluntaryExit {
            message: exit,
            signature: sig,
        }
    }

    #[test]
    fn exit_ignore_already_seen() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        let exit = make_valid_exit(&host);
        // Pre-populate seen cache.
        host.seen_voluntary_exit_indices.write().put(0u64, ());
        assert_eq!(
            host.validate_voluntary_exit(&exit),
            GossipVerdict::Ignore("exit: already seen for this validator".into()),
        );
    }

    #[test]
    fn exit_reject_out_of_range() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::ValidatorIndex;
        let bad_exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: pharos_utils::Epoch(0),
                validator_index: ValidatorIndex(999),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_voluntary_exit(&bad_exit),
            GossipVerdict::Reject("exit: validator index out of range".into()),
        );
    }

    #[test]
    fn exit_reject_not_active() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};
        // Set validator exit_epoch to a past epoch to make it inactive.
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(state) = fc.block_states.get_mut(&head_root) {
                if let ForkMinimalState::Phase0(s) = state {
                    let mut v = s.validators.get(0).unwrap().clone();
                    v.exit_epoch = Epoch(0); // exited already
                    s.validators = SszList::with_push(&SszList::default(), v).unwrap();
                }
            }
        }
        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: pharos_utils::Epoch(0),
                validator_index: ValidatorIndex(0),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_voluntary_exit(&exit),
            GossipVerdict::Reject("exit: validator not active".into()),
        );
    }

    #[test]
    fn exit_reject_already_exiting() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};
        // Set validator exit_epoch to a future (but non-max) epoch.
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(state) = fc.block_states.get_mut(&head_root) {
                if let ForkMinimalState::Phase0(s) = state {
                    let mut v = s.validators.get(0).unwrap().clone();
                    v.exit_epoch = Epoch(100); // future exit planned
                    s.validators = SszList::with_push(&SszList::default(), v).unwrap();
                }
            }
        }
        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: pharos_utils::Epoch(0),
                validator_index: ValidatorIndex(0),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_voluntary_exit(&exit),
            GossipVerdict::Reject("exit: validator already exiting".into()),
        );
    }

    #[test]
    fn exit_reject_future_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};
        // epoch=1 is in the future (current_epoch=0)
        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(1),
                validator_index: ValidatorIndex(0),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_voluntary_exit(&exit),
            GossipVerdict::Reject("exit: exit epoch in the future".into()),
        );
    }

    #[test]
    fn exit_reject_not_active_long_enough() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};
        // Set activation_epoch to require more time than has passed.
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(state) = fc.block_states.get_mut(&head_root) {
                if let ForkMinimalState::Phase0(s) = state {
                    let mut v = s.validators.get(0).unwrap().clone();
                    // SHARD_COMMITTEE_PERIOD=64 for minimal; current_epoch=0 < 0+64
                    v.activation_epoch = Epoch(0);
                    s.validators = SszList::with_push(&SszList::default(), v).unwrap();
                    // Advance slot to epoch 1 so exit_epoch=0 isn't "future"
                    s.slot = Slot(MinimalEthSpec::SLOTS_PER_EPOCH); // epoch 1
                }
            }
        }
        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(0),
                validator_index: ValidatorIndex(0),
            },
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_voluntary_exit(&exit),
            GossipVerdict::Reject("exit: validator not active long enough".into()),
        );
    }

    #[test]
    fn exit_reject_invalid_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::VoluntaryExit;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};

        // Advance the state slot to epoch 64 so the SHARD_COMMITTEE_PERIOD check passes.
        // SHARD_COMMITTEE_PERIOD=64 for MinimalEthSpec; activation_epoch=0.
        // Need: current_epoch(64) >= 0 + 64 → true.
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(ForkMinimalState::Phase0(s)) = fc.block_states.get_mut(&head_root) {
                s.slot =
                    Slot(MinimalEthSpec::SHARD_COMMITTEE_PERIOD * MinimalEthSpec::SLOTS_PER_EPOCH);
            }
        }

        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(MinimalEthSpec::SHARD_COMMITTEE_PERIOD), // current_epoch >= this
                validator_index: ValidatorIndex(0),
            },
            signature: BLSSignature::from_array([0u8; 96]), // zero sig = invalid
        };
        assert_eq!(
            host.validate_voluntary_exit(&exit),
            GossipVerdict::Reject("exit: invalid signature".into()),
        );
    }

    // ── proposer_slashing validation tests ────────────────────────────────────

    fn make_ps_headers(
        host: &HostImpl<MinimalEthSpec>,
        slot: Slot,
        proposer: u64,
        different: bool,
        flip_sig1: bool,
        flip_sig2: bool,
    ) -> ProposerSlashing {
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
        use pharos_types::phase0::primitives::ValidatorIndex;

        let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
        let state = host
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
            .unwrap();
        let epoch = pharos_stf::phase0::accessors::compute_epoch_at_slot(
            slot,
            MinimalEthSpec::SLOTS_PER_EPOCH,
        );
        let domain = pharos_stf::phase0::accessors::get_domain::<MinimalEthSpec>(
            &state,
            pharos_stf::phase0::helpers::DOMAIN_BEACON_PROPOSER,
            Some(epoch),
        );

        let h1 = BeaconBlockHeader {
            slot,
            proposer_index: ValidatorIndex(proposer),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root: Root::default(),
        };
        let h2 = if different {
            BeaconBlockHeader {
                slot,
                proposer_index: ValidatorIndex(proposer),
                parent_root: Root::from_array([1u8; 32]),
                state_root: Root::default(),
                body_root: Root::default(),
            }
        } else {
            h1.clone()
        };

        let sign = |header: &BeaconBlockHeader, flip: bool| {
            let sr = pharos_stf::phase0::accessors::compute_signing_root(header, domain);
            let mut bytes: [u8; 96] = exit_test_sk().sign(sr.as_ref(), BLS_DST, &[]).compress();
            if flip {
                bytes[0] ^= 0xff;
            }
            BLSSignature::from_array(bytes)
        };

        ProposerSlashing {
            signed_header_1: SignedBeaconBlockHeader {
                message: h1.clone(),
                signature: sign(&h1, flip_sig1),
            },
            signed_header_2: SignedBeaconBlockHeader {
                message: h2.clone(),
                signature: sign(&h2, flip_sig2),
            },
        }
    }

    #[test]
    fn ps_ignore_already_seen() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        host.seen_proposer_slashing_indices.write().put(0u64, ());
        let ps = make_ps_headers(&host, Slot(1), 0, true, false, false);
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Ignore("proposer_slashing: already seen for this proposer".into()),
        );
    }

    #[test]
    fn ps_reject_slots_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
        use pharos_types::phase0::primitives::ValidatorIndex;
        let h1 = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: ValidatorIndex(0),
            ..Default::default()
        };
        let h2 = BeaconBlockHeader {
            slot: Slot(2),
            proposer_index: ValidatorIndex(0),
            ..Default::default()
        };
        let ps = ProposerSlashing {
            signed_header_1: SignedBeaconBlockHeader {
                message: h1,
                signature: BLSSignature::from_array([0u8; 96]),
            },
            signed_header_2: SignedBeaconBlockHeader {
                message: h2,
                signature: BLSSignature::from_array([0u8; 96]),
            },
        };
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Reject("proposer_slashing: header slots do not match".into()),
        );
    }

    #[test]
    fn ps_reject_proposer_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
        use pharos_types::phase0::primitives::ValidatorIndex;
        let h1 = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: ValidatorIndex(0),
            ..Default::default()
        };
        let h2 = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: ValidatorIndex(1),
            ..Default::default()
        };
        let ps = ProposerSlashing {
            signed_header_1: SignedBeaconBlockHeader {
                message: h1,
                signature: BLSSignature::from_array([0u8; 96]),
            },
            signed_header_2: SignedBeaconBlockHeader {
                message: h2,
                signature: BLSSignature::from_array([0u8; 96]),
            },
        };
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Reject("proposer_slashing: header proposer indices do not match".into()),
        );
    }

    #[test]
    fn ps_reject_same_headers() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
        use pharos_types::phase0::primitives::ValidatorIndex;
        let h = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: ValidatorIndex(0),
            ..Default::default()
        };
        let ps = ProposerSlashing {
            signed_header_1: SignedBeaconBlockHeader {
                message: h.clone(),
                signature: BLSSignature::from_array([0u8; 96]),
            },
            signed_header_2: SignedBeaconBlockHeader {
                message: h,
                signature: BLSSignature::from_array([0u8; 96]),
            },
        };
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Reject("proposer_slashing: headers are not different".into()),
        );
    }

    #[test]
    fn ps_reject_out_of_range() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::operations::{BeaconBlockHeader, SignedBeaconBlockHeader};
        use pharos_types::phase0::primitives::ValidatorIndex;
        let h1 = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: ValidatorIndex(999),
            parent_root: Root::default(),
            ..Default::default()
        };
        let h2 = BeaconBlockHeader {
            slot: Slot(1),
            proposer_index: ValidatorIndex(999),
            parent_root: Root::from_array([1u8; 32]),
            ..Default::default()
        };
        let ps = ProposerSlashing {
            signed_header_1: SignedBeaconBlockHeader {
                message: h1,
                signature: BLSSignature::from_array([0u8; 96]),
            },
            signed_header_2: SignedBeaconBlockHeader {
                message: h2,
                signature: BLSSignature::from_array([0u8; 96]),
            },
        };
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Reject("proposer_slashing: proposer index out of range".into()),
        );
    }

    #[test]
    fn ps_reject_not_slashable() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        // Mark the validator as already slashed.
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(state) = fc.block_states.get_mut(&head_root) {
                if let ForkMinimalState::Phase0(s) = state {
                    let mut v = s.validators.get(0).unwrap().clone();
                    v.slashed = true;
                    s.validators = SszList::with_push(&SszList::default(), v).unwrap();
                }
            }
        }
        let ps = make_ps_headers(&host, Slot(1), 0, true, false, false);
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Reject("proposer_slashing: proposer not slashable".into()),
        );
    }

    #[test]
    fn ps_reject_invalid_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        // Build valid headers but with zero sigs.
        let ps = make_ps_headers(&host, Slot(1), 0, true, true, false); // flip sig1
        assert_eq!(
            host.validate_proposer_slashing(&ps),
            GossipVerdict::Reject("proposer_slashing: invalid signature".into()),
        );
    }

    // ── attester_slashing validation tests ────────────────────────────────────

    fn make_indexed_att(
        host: &HostImpl<MinimalEthSpec>,
        indices: &[u64],
        slot: Slot,
        target_epoch: pharos_utils::Epoch,
        source_epoch: pharos_utils::Epoch,
        flip_sig: bool,
    ) -> pharos_types::phase0::IndexedAttestation<2048> {
        use pharos_ssz::SszList;
        use pharos_types::phase0::primitives::ValidatorIndex;
        use pharos_types::phase0::{AttestationData, Checkpoint, IndexedAttestation};

        let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
        let state = host
            .fork_choice
            .read()
            .block_states
            .get(&head_root)
            .cloned()
            .unwrap();

        let data = AttestationData {
            slot,
            index: pharos_types::phase0::primitives::CommitteeIndex(0),
            beacon_block_root: head_root,
            source: Checkpoint {
                epoch: source_epoch,
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: target_epoch,
                root: Root::default(),
            },
        };
        let domain = pharos_stf::phase0::accessors::get_domain::<MinimalEthSpec>(
            &state,
            pharos_stf::phase0::helpers::DOMAIN_BEACON_ATTESTER,
            Some(target_epoch),
        );
        let sr = pharos_stf::phase0::accessors::compute_signing_root(&data, domain);
        let mut sig: [u8; 96] = exit_test_sk().sign(sr.as_ref(), BLS_DST, &[]).compress();
        if flip_sig {
            sig[0] ^= 0xff;
        }

        let vi: Vec<ValidatorIndex> = indices.iter().map(|&i| ValidatorIndex(i)).collect();
        let attesting_indices = {
            let mut l = SszList::<ValidatorIndex, 2048>::default();
            for v in &vi {
                l = SszList::with_push(&l, *v).unwrap();
            }
            l
        };
        IndexedAttestation {
            attesting_indices,
            data,
            signature: BLSSignature::from_array(sig),
        }
    }

    #[test]
    fn as_ignore_all_seen() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        host.seen_attester_slashing_indices.write().put(0u64, ());
        use pharos_types::phase0::AttesterSlashing;
        let att1 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let att2 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(2),
            pharos_utils::Epoch(0),
            false,
        );
        let slashing = AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        assert_eq!(
            host.validate_attester_slashing(&slashing),
            GossipVerdict::Ignore("attester_slashing: all indices already seen".into()),
        );
    }

    #[test]
    fn as_reject_not_slashable() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::AttesterSlashing;
        // Same target epoch → not slashable (no double vote, no surround)
        let att1 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let att2 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let slashing = AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        // Both same data → is_slashable_attestation_data returns false (not slashable)
        let verdict = host.validate_attester_slashing(&slashing);
        assert_eq!(
            verdict,
            GossipVerdict::Reject("attester_slashing: attestation data not slashable".into()),
        );
    }

    #[test]
    fn as_reject_index_out_of_range_att1() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::AttesterSlashing;
        // Double vote (same target_epoch, different slot) → slashable data.
        // Then att1 has index=999 which is out of range.
        let att1 = make_indexed_att(
            &host,
            &[999],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let att2 = make_indexed_att(
            &host,
            &[999],
            Slot(1),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let slashing = AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        assert_eq!(
            host.validate_attester_slashing(&slashing),
            GossipVerdict::Reject("attester_slashing: index out of range in attestation_1".into()),
        );
    }

    #[test]
    fn as_reject_invalid_att1() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::AttesterSlashing;
        // Double vote (same target_epoch, different slot) → slashable data.
        // att1 has flipped sig → invalid indexed attestation.
        let att1 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            true,
        );
        let att2 = make_indexed_att(
            &host,
            &[0],
            Slot(1),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let slashing = AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        assert_eq!(
            host.validate_attester_slashing(&slashing),
            GossipVerdict::Reject("attester_slashing: invalid indexed attestation_1".into()),
        );
    }

    #[test]
    fn as_reject_index_out_of_range_att2() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        // att1: valid index 0; att2: invalid index 999 (but they must share an index for IGNORE to pass)
        // We need att1 and att2 to have a shared index first, so we use index 0 in both.
        // But att2 has index 999 not in att1. Actually for att2 out-of-range we need intersection nonempty too.
        // Easiest: use index 0 in att1 (valid), indices [0, 999] in att2 (one valid, one invalid range check)
        // Actually the spec check is: any index in att2 >= len(validators). With our att2 having [999],
        // the intersection with att1's [0] is empty → IGNORE fires first. We need to have index 0 in both
        // so intersection is nonempty, and also have 999 in att2 to trigger the range check.
        use pharos_ssz::SszList;
        use pharos_types::phase0::primitives::ValidatorIndex;
        // att1: valid index 0; att2: indices [0, 999] (shared + out-of-range).
        // Double vote: both have target_epoch=0, different slot → slashable.
        let att1 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        // Build att2 with indices [0, 999] — intersection with att1 = [0] (not all seen).
        // att2 has 999 which is out of range. Use slot=1 so data != att1's data (double vote).
        let vi: Vec<ValidatorIndex> = [0u64, 999].iter().map(|&i| ValidatorIndex(i)).collect();
        let mut idx_list = SszList::<ValidatorIndex, 2048>::default();
        for v in &vi {
            idx_list = SszList::with_push(&idx_list, *v).unwrap();
        }
        use pharos_types::phase0::{AttestationData, Checkpoint, IndexedAttestation};
        let data = AttestationData {
            slot: Slot(1), // different slot → double vote (same target_epoch=0)
            index: pharos_types::phase0::primitives::CommitteeIndex(0),
            beacon_block_root: Root::default(),
            source: Checkpoint {
                epoch: pharos_utils::Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: pharos_utils::Epoch(0),
                root: Root::default(),
            },
        };
        let att2 = IndexedAttestation {
            attesting_indices: idx_list,
            data,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        let slashing = pharos_types::phase0::AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        assert_eq!(
            host.validate_attester_slashing(&slashing),
            GossipVerdict::Reject("attester_slashing: index out of range in attestation_2".into()),
        );
    }

    #[test]
    fn as_reject_invalid_att2() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::AttesterSlashing;
        // Double vote (same target_epoch=0, different slot) → slashable data.
        // att1 valid; att2 has flipped sig → invalid indexed attestation_2.
        let att1 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let att2 = make_indexed_att(
            &host,
            &[0],
            Slot(1),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            true,
        );
        let slashing = AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        assert_eq!(
            host.validate_attester_slashing(&slashing),
            GossipVerdict::Reject("attester_slashing: invalid indexed attestation_2".into()),
        );
    }

    #[test]
    fn as_reject_no_slashable_validators() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_exit_test_host(&dir);
        // Mark the validator as already slashed (not slashable).
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(state) = fc.block_states.get_mut(&head_root) {
                if let ForkMinimalState::Phase0(s) = state {
                    let mut v = s.validators.get(0).unwrap().clone();
                    v.slashed = true;
                    s.validators = SszList::with_push(&SszList::default(), v).unwrap();
                }
            }
        }
        use pharos_types::phase0::AttesterSlashing;
        // Double vote (same target_epoch=0, different slot) → slashable data.
        // Validator is slashed → no slashable validators in intersection.
        let att1 = make_indexed_att(
            &host,
            &[0],
            Slot(0),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let att2 = make_indexed_att(
            &host,
            &[0],
            Slot(1),
            pharos_utils::Epoch(0),
            pharos_utils::Epoch(0),
            false,
        );
        let slashing = AttesterSlashing {
            attestation_1: att1,
            attestation_2: att2,
        };
        assert_eq!(
            host.validate_attester_slashing(&slashing),
            GossipVerdict::Reject(
                "attester_slashing: no slashable validators in intersection".into()
            ),
        );
    }

    // ── bls_to_execution_change validation tests ─────────────────────────────

    use pharos_types::bellatrix::execution_payload::ExecutionAddress;
    use pharos_types::capella::operations::{BLSToExecutionChange, SignedBLSToExecutionChange};

    fn bls_test_sk() -> BlstSecretKey {
        BlstSecretKey::key_gen(&[88u8; 32], &[]).expect("valid IKM")
    }

    fn bls_test_pubkey() -> BLSPubkey {
        BLSPubkey::from_array(bls_test_sk().sk_to_pk().compress())
    }

    /// Build a host where the single validator has BLS withdrawal credentials
    /// matching `bls_test_pubkey()`, and capella_fork_epoch = 0 (active now).
    fn make_bls_to_exec_host(dir: &tempfile::TempDir) -> HostImpl<MinimalEthSpec> {
        use pharos_types::phase0::misc::Fork;
        use pharos_types::phase0::operations::BeaconBlockHeader;
        use pharos_types::phase0::primitives::{Epoch, ValidatorIndex};

        // Build withdrawal_credentials = 0x00 || hash(pubkey)[1..]
        let pubkey_hash = pharos_utils::hash::hash(bls_test_pubkey().as_slice());
        let mut creds = [0u8; 32];
        creds[0] = 0x00;
        creds[1..].copy_from_slice(&pubkey_hash.as_slice()[1..]);

        let store = Arc::new(
            RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );

        let genesis_slot = Slot(0);
        let validator = pharos_types::phase0::misc::Validator {
            pubkey: exit_test_pubkey(), // validator signing key (different from BLS withdrawal key)
            effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            slashed: false,
            withdrawal_credentials: pharos_utils::Hash256::from_array(creds),
            ..Default::default()
        };

        let genesis_body_root = MinimalBeaconBlockBody::default().tree_hash_root();
        let genesis_state_inner = MinimalBeaconState {
            genesis_time: 0,
            slot: genesis_slot,
            fork: Fork {
                previous_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                current_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
                epoch: Epoch(0),
            },
            latest_block_header: BeaconBlockHeader {
                slot: genesis_slot,
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: genesis_body_root,
            },
            validators: SszList::with_push(&SszList::default(), validator).unwrap(),
            balances: SszList::with_push(
                &SszList::default(),
                Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
            )
            .unwrap(),
            ..Default::default()
        };

        let fork_genesis_state = ForkMinimalState::Phase0(genesis_state_inner.clone());
        let genesis_inner_block = MinimalBeaconBlock {
            slot: genesis_slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: fork_genesis_state.tree_hash_root(),
            body: MinimalBeaconBlockBody::default(),
        };
        let genesis_root: Root = genesis_inner_block.tree_hash_root();
        let genesis_block = pharos_types::state::BeaconBlock::Phase0(genesis_inner_block);

        let fc_store = pharos_fork_choice::get_forkchoice_store::<MinimalEthSpec>(
            fork_genesis_state.clone(),
            genesis_block.clone(),
        );
        let fork_choice = Arc::new(RwLock::new(fc_store));
        {
            let mut fc = fork_choice.write();
            fc.block_states
                .insert(genesis_root, fork_genesis_state.clone());
            fc.blocks.insert(genesis_root, genesis_block);
        }

        let gvr = Root::default();
        // capella_fork_epoch = 0 so current epoch (0) >= capella epoch → IGNORE check passes.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(u64::MAX),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(u64::MAX),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(0), // active at genesis
            genesis_validators_root: gvr,
        };
        let runtime_cfg = Arc::new(RuntimeConfig {
            seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
            ..Default::default()
        });
        HostImpl::<MinimalEthSpec>::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg)
    }

    fn make_valid_bls_to_exec(_host: &HostImpl<MinimalEthSpec>) -> SignedBLSToExecutionChange {
        use pharos_types::fork::DOMAIN_BLS_TO_EXECUTION_CHANGE;
        use pharos_types::phase0::primitives::ValidatorIndex;

        let msg = BLSToExecutionChange {
            validator_index: ValidatorIndex(0),
            from_bls_pubkey: bls_test_pubkey(),
            to_execution_address: ExecutionAddress::default(),
        };
        let gvr = Root::default();
        let domain = pharos_stf::phase0::accessors::compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            MinimalEthSpec::GENESIS_FORK_VERSION,
            &gvr,
        );
        let sr = pharos_stf::phase0::accessors::compute_signing_root(&msg, domain);
        let sig =
            BLSSignature::from_array(bls_test_sk().sign(sr.as_ref(), BLS_DST, &[]).compress());
        SignedBLSToExecutionChange {
            message: msg,
            signature: sig,
        }
    }

    #[test]
    fn bls_to_exec_ignore_pre_capella() {
        let dir = tempfile::TempDir::new().unwrap();
        // Use the exit_test_host which has capella_fork_epoch = FAR_FUTURE.
        let host = make_exit_test_host(&dir);
        use pharos_types::phase0::primitives::ValidatorIndex;
        let msg = BLSToExecutionChange {
            validator_index: ValidatorIndex(0),
            from_bls_pubkey: bls_test_pubkey(),
            to_execution_address: ExecutionAddress::default(),
        };
        let signed = SignedBLSToExecutionChange {
            message: msg,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_bls_to_execution_change(&signed),
            GossipVerdict::Ignore("bls_to_exec: current epoch is pre-capella".into()),
        );
    }

    #[test]
    fn bls_to_exec_ignore_already_seen() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_bls_to_exec_host(&dir);
        host.seen_bls_to_execution_change_indices
            .write()
            .put(0u64, ());
        let signed = make_valid_bls_to_exec(&host);
        assert_eq!(
            host.validate_bls_to_execution_change(&signed),
            GossipVerdict::Ignore("bls_to_exec: already seen for this validator".into()),
        );
    }

    #[test]
    fn bls_to_exec_reject_out_of_range() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_bls_to_exec_host(&dir);
        use pharos_types::phase0::primitives::ValidatorIndex;
        let msg = BLSToExecutionChange {
            validator_index: ValidatorIndex(999),
            from_bls_pubkey: bls_test_pubkey(),
            to_execution_address: ExecutionAddress::default(),
        };
        let signed = SignedBLSToExecutionChange {
            message: msg,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_bls_to_execution_change(&signed),
            GossipVerdict::Reject("bls_to_exec: validator index out of range".into()),
        );
    }

    #[test]
    fn bls_to_exec_reject_not_bls_credentials() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_bls_to_exec_host(&dir);
        // Overwrite the validator's withdrawal_credentials to use prefix 0x01 (not BLS).
        {
            let head_root = pharos_fork_choice::get_head(&*host.fork_choice.read());
            let mut fc = host.fork_choice.write();
            if let Some(state) = fc.block_states.get_mut(&head_root) {
                if let ForkMinimalState::Phase0(s) = state {
                    let mut v = s.validators.get(0).unwrap().clone();
                    let mut creds: [u8; 32] = v.withdrawal_credentials.into();
                    creds[0] = 0x01; // ETH1 prefix
                    v.withdrawal_credentials = pharos_utils::Hash256::from_array(creds);
                    s.validators = SszList::with_push(&SszList::default(), v).unwrap();
                }
            }
        }
        let signed = make_valid_bls_to_exec(&host);
        assert_eq!(
            host.validate_bls_to_execution_change(&signed),
            GossipVerdict::Reject("bls_to_exec: not BLS withdrawal credentials".into()),
        );
    }

    #[test]
    fn bls_to_exec_reject_pubkey_hash_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_bls_to_exec_host(&dir);
        use pharos_types::phase0::primitives::ValidatorIndex;
        // Use a different pubkey than what was stored in withdrawal_credentials.
        let other_pubkey = block_test_pubkey(); // different from bls_test_pubkey
        let msg = BLSToExecutionChange {
            validator_index: ValidatorIndex(0),
            from_bls_pubkey: other_pubkey,
            to_execution_address: ExecutionAddress::default(),
        };
        let signed = SignedBLSToExecutionChange {
            message: msg,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_bls_to_execution_change(&signed),
            GossipVerdict::Reject("bls_to_exec: pubkey hash mismatch".into()),
        );
    }

    #[test]
    fn bls_to_exec_reject_invalid_signature() {
        let dir = tempfile::TempDir::new().unwrap();
        let host = make_bls_to_exec_host(&dir);
        // Valid msg but zero signature.
        use pharos_types::phase0::primitives::ValidatorIndex;
        let msg = BLSToExecutionChange {
            validator_index: ValidatorIndex(0),
            from_bls_pubkey: bls_test_pubkey(),
            to_execution_address: ExecutionAddress::default(),
        };
        let signed = SignedBLSToExecutionChange {
            message: msg,
            signature: BLSSignature::from_array([0u8; 96]),
        };
        assert_eq!(
            host.validate_bls_to_execution_change(&signed),
            GossipVerdict::Reject("bls_to_exec: invalid signature".into()),
        );
    }
}
