//! `ChainStateApi` accessor trait and concrete `NodeChainState` implementation.
//!
//! The API server reads chain state via this trait, which wraps the two shared
//! `Arc`s (`RocksStore` + `Arc<RwLock<pharos_fork_choice::Store<E>>>`) plus a
//! `NodeIdentityCache` snapshot. This is the `D-api-chain-accessor` pattern:
//! sync reads behind `spawn_blocking`, no API actor for reads.

use std::sync::Arc;

use arc_swap::ArcSwap;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use pharos_fork_choice::Store as FcStore;
use pharos_network::discovery::enr::Enr;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::{
    EthSpec, SyncCommitteePubkeys,
    config::RuntimeConfig,
    phase0::{BeaconBlockHeader, Checkpoint, Root, Slot},
    views::SignedBeaconBlockView as _,
};
use pharos_utils::BLSSignature;

use crate::dto::block::{BlockApiSerializer, SignedBlockForApi};
use crate::error::ApiError;

// ── RegenTarget ────────────────────────────────────────────────────────────────

/// Target for state regeneration via `ChainStateApi::regenerate_state`.
///
/// Passed to the `regenerate_state` method to indicate whether the caller wants
/// the state at a particular slot, by state-root, or by block-root (post-state).
#[derive(Debug, Clone, Copy)]
pub enum RegenTarget {
    /// Return the post-state at the given slot (nearest-boundary + replay).
    Slot(Slot),
    /// Return the state whose `tree_hash_root()` equals this state-root.
    StateRoot(Root),
    /// Return the post-state of the block with this block-root.
    BlockRoot(Root),
}

// ── NodeIdentityCache ─────────────────────────────────────────────────────────

/// Snapshot of node identity data captured at startup.
///
/// `peer_id`, `enr`, and listen/discovery addresses are immutable once the
/// network has bound and are safe to hold indefinitely. `metadata` points to
/// the live `ArcSwap` on `Network` so the current metadata seq/attnets/syncnets
/// are always up to date without polling.
///
/// Populated AFTER `handle.wait_for_local_enr()` and
/// `handle.wait_for_listen_addr()` resolve in `main.rs`.
pub struct NodeIdentityCache {
    pub peer_id: PeerId,
    pub enr: Enr,
    /// Bound TCP/QUIC listen addresses.
    pub listen_addrs: Vec<Multiaddr>,
    /// Discovery (discv5) addresses derived from the ENR.
    pub discovery_addrs: Vec<Multiaddr>,
    /// Live metadata reference; reads always reflect the current seq_number.
    pub metadata: Arc<ArcSwap<AltairMetaData>>,
}

// ── ChainStateApi ─────────────────────────────────────────────────────────────

/// Read-only accessor trait for chain state consumed by Beacon API handlers.
///
/// All implementations are expected to be sync and cheap (i.e. they either
/// operate under a short read-lock or read immutable startup data). Handlers
/// wrap calls in `tokio::task::spawn_blocking` where needed.
pub trait ChainStateApi<E: EthSpec>: Send + Sync + 'static {
    /// The current fork-choice head root.
    fn head_root(&self) -> Root;

    /// The current slot derived from `store.time` and `store.genesis_time`.
    fn current_slot(&self) -> Slot;

    /// `(genesis_time, genesis_validators_root, genesis_fork_version)`.
    fn genesis(&self) -> (u64, Root, [u8; 4]);

    /// The highest known finalized checkpoint.
    fn finalized_checkpoint(&self) -> Checkpoint;

    /// The justified checkpoint used as the LMD-GHOST root.
    fn justified_checkpoint(&self) -> Checkpoint;

    /// Return the `BeaconBlockHeader` for `root`, or `None` if not in store.
    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader>;

    /// Runtime configuration (fork schedule, preset constants).
    fn runtime_cfg(&self) -> Arc<RuntimeConfig>;

    /// Whether the head block has not yet been validated by the EL.
    fn is_optimistic(&self) -> bool;

    /// Whether the node is still syncing (sync_distance > 0).
    fn is_syncing(&self) -> bool;

    /// Read-only reference to the node identity snapshot.
    fn node_identity(&self) -> &NodeIdentityCache;

    // ── State-resolution methods (Phase 2) ────────────────────────────────────

    /// Look up the post-state for a block root from the in-memory fork-choice
    /// store. Returns `None` when the root is not present in-memory (cold state).
    fn state_by_block_root(&self, root: Root) -> Option<E::BeaconState>;

    /// Look up a state by its state-root from cold storage.
    ///
    /// Falls back to `RocksStore::get_state` when the root is not in the
    /// in-memory `block_states` map.  Returns `None` when not found anywhere.
    fn state_by_state_root(&self, state_root: Root) -> Option<E::BeaconState>;

    /// Return the block root for a given slot from the in-memory store, or
    /// `None` if the slot is not within the in-memory window.
    fn block_root_for_slot(&self, slot: Slot) -> Option<Root>;

    /// Return the genesis block root (the initial anchor block root).
    fn genesis_block_root(&self) -> Root;

    /// Return `(current_sync_committee_pubkeys, next_sync_committee_pubkeys)` for
    /// the post-state of `block_root`, or `None` for Phase0 states (no sync committee).
    ///
    /// Each pubkey is a 48-byte BLS public key (`BLSPubkey = FixedBytes<48>`).
    /// Returns `None` when the block root is not in-memory, or the state is Phase0.
    fn sync_committee_pubkeys(&self, block_root: Root) -> Option<SyncCommitteePubkeys>;

    /// Return the full `SignedBeaconBlock` for `root` serialized as API data,
    /// or `None` if not found in cold storage.
    ///
    /// The returned `SignedBlockForApi` contains the fork variant, JSON DTO value,
    /// canonical SSZ bytes (inner fork variant, no discriminant byte), and
    /// attestations as a JSON array. The implementation fetches from `RocksStore`
    /// and pattern-matches on the concrete fork-enum variant to build the DTOs.
    fn block_by_root_for_api(&self, root: Root) -> Result<Option<SignedBlockForApi>, ApiError>;

    /// Return the `(BeaconBlockHeader, BLSSignature)` for `root`, sourcing the REAL
    /// signature from the stored `SignedBeaconBlock`.
    ///
    /// After Task 1.1 (live block persistence), every imported block is flushed to
    /// `RocksStore` before the head is published, so this method reliably returns the
    /// real signature for any recently imported block. Falls back to `None` when the
    /// signed block is absent (e.g., pre-schema-v3 anchor blocks).
    fn signed_block_header_at(
        &self,
        root: Root,
    ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)>;

    // ── Replay-on-read (Phase 2) ───────────────────────────────────────────────

    /// Regenerate (or fetch) a historical state via the `StateRegenService`.
    ///
    /// - `RegenTarget::Slot(s)` — find nearest stored boundary ≤ `s`, replay to `s`.
    /// - `RegenTarget::StateRoot(r)` — walk `state-summary` CF to find the block
    ///   whose post-state root is `r`, replay to that block's slot.
    /// - `RegenTarget::BlockRoot(r)` — regenerate the post-state of block `r`.
    ///
    /// Error mapping (per `D-replay-on-read`):
    /// - `RegenError::MissingBlock` / `RegenError::MissingAnchorState` /
    ///   `RegenError::NotFound` → `ApiError::NotFound`.
    /// - `RegenError::Stf` / `RegenError::Storage` → `ApiError::Internal`.
    ///
    /// Mock implementations (tests that don't exercise regen) should return
    /// `Err(ApiError::NotFound("regen not available in mock".into()))`.
    fn regenerate_state(&self, target: RegenTarget) -> Result<E::BeaconState, ApiError>;
}

// ── NodeChainState ────────────────────────────────────────────────────────────

/// Type alias for the state-regeneration callback injected into `NodeChainState`.
///
/// The callback is constructed in `pharos-node/src/main.rs` (which depends on
/// `pharos-api`) and wraps a `StateRegenService<E>`. This avoids a
/// `pharos-api → pharos-node` dependency while allowing `NodeChainState` to
/// call into the replay-on-read service (per `D-replay-on-read`, Task 2.4).
pub type RegenFn<E> =
    dyn Fn(RegenTarget) -> Result<<E as EthSpec>::BeaconState, ApiError> + Send + Sync + 'static;

/// Concrete `ChainStateApi` backed by the shared fork-choice store and storage.
pub struct NodeChainState<E: EthSpec> {
    /// Shared chain DB (cold states, anchor, etc.).
    store: Arc<RocksStore>,
    /// Live fork-choice store (in-memory head, checkpoints, blocks).
    fork_choice: Arc<RwLock<FcStore<E>>>,
    /// Static node identity snapshot.
    identity: NodeIdentityCache,
    /// Runtime configuration forwarded from `main.rs`.
    runtime_cfg: Arc<RuntimeConfig>,
    /// Optional state-regeneration callback (Phase 2).
    ///
    /// `None` when the HTTP server is not active (no `--http` flag) or when the
    /// replay service has not been wired in. When `None`, `regenerate_state`
    /// returns `ApiError::NotFound`.
    regen_fn: Option<Arc<RegenFn<E>>>,
}

impl<E: EthSpec> NodeChainState<E> {
    /// Construct without a state-regeneration service (backward-compat).
    pub fn new(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<FcStore<E>>>,
        identity: NodeIdentityCache,
        runtime_cfg: Arc<RuntimeConfig>,
    ) -> Self {
        Self {
            store,
            fork_choice,
            identity,
            runtime_cfg,
            regen_fn: None,
        }
    }

    /// Construct with a state-regeneration callback (Phase 2).
    ///
    /// `regen` is a closure wrapping a `StateRegenService<E>` constructed in
    /// `pharos-node/src/main.rs`. It must be `Send + Sync + 'static` and take a
    /// `RegenTarget`, returning `Result<E::BeaconState, ApiError>`.
    pub fn new_with_regen(
        store: Arc<RocksStore>,
        fork_choice: Arc<RwLock<FcStore<E>>>,
        identity: NodeIdentityCache,
        runtime_cfg: Arc<RuntimeConfig>,
        regen: Arc<RegenFn<E>>,
    ) -> Self {
        Self {
            store,
            fork_choice,
            identity,
            runtime_cfg,
            regen_fn: Some(regen),
        }
    }
}

impl<E: EthSpec> ChainStateApi<E> for NodeChainState<E>
where
    E::Phase0SignedBeaconBlock: BlockApiSerializer,
    E::AltairSignedBeaconBlock: BlockApiSerializer,
    E::BellatrixSignedBeaconBlock: BlockApiSerializer,
    E::CapellaSignedBeaconBlock: BlockApiSerializer,
{
    fn head_root(&self) -> Root {
        let fc = self.fork_choice.read();
        pharos_fork_choice::get_head(&fc)
    }

    fn current_slot(&self) -> Slot {
        let fc = self.fork_choice.read();
        pharos_fork_choice::get_current_slot(&fc)
    }

    fn genesis(&self) -> (u64, Root, [u8; 4]) {
        let fc = self.fork_choice.read();
        let genesis_time = fc.genesis_time;
        let genesis_validators_root = fc.runtime_cfg.genesis_validators_root.into();
        let genesis_fork_version = fc.runtime_cfg.genesis_fork_version;
        (genesis_time, genesis_validators_root, genesis_fork_version)
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        self.fork_choice.read().finalized_checkpoint.clone()
    }

    fn justified_checkpoint(&self) -> Checkpoint {
        self.fork_choice.read().justified_checkpoint.clone()
    }

    fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
        use pharos_types::views::{BeaconBlockView, BeaconStateView};
        let fc = self.fork_choice.read();
        let block = fc.blocks.get(&root)?;
        // `latest_block_header` on the post-state carries the body_root already
        // computed by `process_block_header` during the STF run. Reading it here
        // avoids having to tree-hash the opaque `BeaconBlockView::Body` type.
        let state = fc.block_states.get(&root)?;
        let body_root = state.latest_block_header().body_root;
        Some(BeaconBlockHeader {
            slot: block.slot(),
            proposer_index: block.proposer_index(),
            parent_root: block.parent_root(),
            state_root: block.state_root(),
            body_root,
        })
    }

    fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.runtime_cfg)
    }

    fn is_optimistic(&self) -> bool {
        // A block is optimistic when its payload status is NotValidated.
        use pharos_types::PayloadStatus;
        let fc = self.fork_choice.read();
        let head = pharos_fork_choice::get_head(&fc);
        matches!(
            fc.payload_statuses.get(&head),
            Some(PayloadStatus::NotValidated)
        )
    }

    fn is_syncing(&self) -> bool {
        // Syncing when the head slot lags behind the wall-clock slot.
        let fc = self.fork_choice.read();
        let head_root = pharos_fork_choice::get_head(&fc);
        let head_slot = fc.blocks.get(&head_root).map(|b| {
            use pharos_types::views::BeaconBlockView;
            b.slot()
        });
        let current = pharos_fork_choice::get_current_slot(&fc);
        match head_slot {
            Some(s) => u64::from(s) + 1 < u64::from(current),
            None => true,
        }
    }

    fn node_identity(&self) -> &NodeIdentityCache {
        &self.identity
    }

    fn state_by_block_root(&self, root: Root) -> Option<E::BeaconState> {
        // Fast path: in-memory fork-choice post-states (always tried first).
        {
            let fc = self.fork_choice.read();
            if let Some(state) = fc.block_states.get(&root).cloned() {
                return Some(state);
            }
        }
        // Fall through to regen when the block root is not in-memory.
        // `StateRegenService::state_at_slot` (Phase 2) falls through to cold
        // restore-points via `nearest_cold_restore_point` (Phase 3 + Task 3.6),
        // so this is correct live + cold (per Task 4.4 API audit).
        // `regen_fn` converts `RegenError → ApiError`; we swallow ApiError here
        // because the trait returns `Option<E::BeaconState>`.
        if let Some(regen) = &self.regen_fn {
            regen(RegenTarget::BlockRoot(root)).ok()
        } else {
            None
        }
    }

    fn state_by_state_root(&self, state_root: Root) -> Option<E::BeaconState> {
        // Fast path 1: in-memory fork-choice post-states.
        // Clone candidates out and release the read lock BEFORE merkleizing —
        // `tree_hash_root()` over a full state is expensive and must not hold the lock.
        let candidates: Vec<E::BeaconState> = {
            let fc = self.fork_choice.read();
            fc.block_states.values().cloned().collect()
        };
        {
            use pharos_ssz::TreeHash;
            for state in candidates {
                if state.tree_hash_root() == state_root {
                    return Some(state);
                }
            }
        }
        // Fast path 2: hot `states` CF (epoch-boundary states stored by root).
        if let Ok(Some(state)) = <RocksStore as DbStore<E>>::get_state(&self.store, &state_root) {
            return Some(state);
        }
        // Fall through to regen (replay-on-read) when not found in hot storage.
        // `StateRegenService::state_at_root` (Phase 2) walks state-summaries +
        // falls through to cold restore-points (Phase 3 + Task 3.6), so this is
        // correct live + cold (per Task 4.4 API audit).
        if let Some(regen) = &self.regen_fn {
            regen(RegenTarget::StateRoot(state_root)).ok()
        } else {
            None
        }
    }

    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        use pharos_types::views::BeaconBlockView;
        // Fast path: in-memory fork-choice blocks (covers recent hot window).
        {
            let fc = self.fork_choice.read();
            if let Some(root) = fc.blocks.iter().find_map(|(root, block)| {
                if block.slot() == slot {
                    Some(*root)
                } else {
                    None
                }
            }) {
                return Some(root);
            }
        }
        // Fall through to the persisted `slot_to_block_root` CF.
        // This resolves `resolve_state_id` by decimal slot for cold history
        // (finalized blocks migrated below split_slot by Phase-3 freezer).
        // Per Task 4.4 (API audit): correct live + cold.
        self.store.block_root_at_slot(slot).ok().flatten()
    }

    fn genesis_block_root(&self) -> Root {
        // The genesis block root is the anchor root stored in the fork-choice
        // store's finalized checkpoint at epoch 0.  We look for the block at
        // slot 0 in-memory, then fall through to the persisted slot-index, then
        // fall back to the finalized checkpoint root.
        //
        // Per Task 4.4 (API audit): correct live + cold.  After Phase-3 migration
        // the genesis/anchor block is in the cold-blocks CF; the `finalized_checkpoint.root`
        // fallback covers checkpoint-sync nodes where genesis is the anchor.  For
        // genesis-from-scratch nodes, slot 0 is looked up in the persisted slot-index.
        use pharos_types::views::BeaconBlockView;
        let (in_memory_root, finalized_root) = {
            let fc = self.fork_choice.read();
            let in_mem = fc.blocks.iter().find_map(|(r, b)| {
                if b.slot() == pharos_types::phase0::Slot(0) {
                    Some(*r)
                } else {
                    None
                }
            });
            (in_mem, fc.finalized_checkpoint.root)
        };
        if let Some(root) = in_memory_root {
            return root;
        }
        // Fall through to the persisted slot-index (covers cold genesis).
        if let Ok(Some(root)) = self.store.block_root_at_slot(pharos_types::phase0::Slot(0)) {
            return root;
        }
        // Anchor checkpoint is the first block we know about.
        finalized_root
    }

    fn sync_committee_pubkeys(&self, block_root: Root) -> Option<SyncCommitteePubkeys> {
        use pharos_types::BeaconStateView;
        let fc = self.fork_choice.read();
        // Delegate to BeaconStateView::sync_committee_pubkeys which has
        // per-fork overrides returning the committee pubkeys (Phase0 returns None).
        fc.block_states.get(&block_root)?.sync_committee_pubkeys()
    }

    fn regenerate_state(&self, target: RegenTarget) -> Result<E::BeaconState, ApiError> {
        match &self.regen_fn {
            Some(regen) => regen(target),
            None => Err(ApiError::NotFound(
                "state regeneration service not available".into(),
            )),
        }
    }

    fn signed_block_header_at(&self, root: Root) -> Option<(BeaconBlockHeader, BLSSignature)> {
        // Fetch the full SignedBeaconBlock from storage to extract the real signature.
        // Try hot CF first; fall through to cold for migrated blocks.
        // Per Task 4.4 (API audit): correct live + cold.
        let signed = {
            let hot = <RocksStore as DbStore<E>>::get_block(&self.store, &root)
                .ok()
                .flatten();
            if hot.is_some() {
                hot?
            } else {
                <RocksStore as DbStore<E>>::get_cold_block(&self.store, &root)
                    .ok()
                    .flatten()?
            }
        };

        // Reconstruct BOTH the header fields and the real signature directly from
        // the stored `SignedBeaconBlock` — no dependency on the in-memory
        // fork-choice maps (which may not hold the block after a reorg or, from
        // Phase 3, after pruning). `body_root` is the block body's merkle root.
        use pharos_ssz::TreeHash;
        use pharos_types::views::BeaconBlockView as _;

        macro_rules! header_from {
            ($inner:expr) => {{
                let msg = $inner.message();
                let header = BeaconBlockHeader {
                    slot: msg.slot(),
                    proposer_index: msg.proposer_index(),
                    parent_root: msg.parent_root(),
                    state_root: msg.state_root(),
                    body_root: msg.body().tree_hash_root(),
                };
                Some((header, *$inner.signature()))
            }};
        }

        if let Some(inner) = E::unwrap_phase0_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_altair_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_bellatrix_signed_block(&signed) {
            header_from!(inner)
        } else if let Some(inner) = E::unwrap_capella_signed_block(&signed) {
            header_from!(inner)
        } else {
            None
        }
    }

    fn block_by_root_for_api(&self, root: Root) -> Result<Option<SignedBlockForApi>, ApiError> {
        // Fetch from the hot CF first; fall through to the cold CF for finalized
        // blocks migrated by the Phase-3 freezer.  A genuine DB read error is
        // surfaced as 500, distinct from a missing block (Ok(None) → 404 at the
        // handler).  Per Task 4.4 (API audit): correct live + cold.
        let hot = <RocksStore as DbStore<E>>::get_block(&self.store, &root)
            .map_err(|e| ApiError::Internal(format!("block store read failed: {e}")))?;
        let block = if let Some(b) = hot {
            b
        } else {
            // Fall through to cold-blocks CF (finalized blocks migrated by freezer).
            match <RocksStore as DbStore<E>>::get_cold_block(&self.store, &root)
                .map_err(|e| ApiError::Internal(format!("cold block store read failed: {e}")))?
            {
                Some(b) => b,
                None => return Ok(None),
            }
        };

        // Use the `EthSpec` unwrap helpers to dispatch to the correct fork-specific
        // DTO builder via the `BlockApiSerializer` trait. Each helper returns
        // `Option<&Inner>` where `Inner: BlockApiSerializer` (guaranteed by the impl
        // bounds on this `NodeChainState<E>` impl block).
        if let Some(b) = E::unwrap_phase0_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_altair_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_bellatrix_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        if let Some(b) = E::unwrap_capella_signed_block(&block) {
            return Ok(Some(b.to_block_for_api()?));
        }
        // All four forks are exhaustive — reaching here indicates a new unknown fork.
        unreachable!("unknown fork variant in SignedBeaconBlock — update block_by_root_for_api")
    }
}

// ── ApiState ──────────────────────────────────────────────────────────────────

/// Axum state wrapper.
///
/// Injected via `axum::extract::State<Arc<ApiState<E>>>`. Handlers clone the
/// `Arc` cheaply rather than cloning the full state.
pub struct ApiState<E: EthSpec> {
    pub chain: Arc<dyn ChainStateApi<E>>,
}

impl<E: EthSpec> ApiState<E> {
    pub fn new(chain: Arc<dyn ChainStateApi<E>>) -> Arc<Self> {
        Arc::new(Self { chain })
    }
}
