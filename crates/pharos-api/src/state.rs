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
};

use crate::dto::block::{BlockApiSerializer, SignedBlockForApi};
use crate::error::ApiError;

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
}

// ── NodeChainState ────────────────────────────────────────────────────────────

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
}

impl<E: EthSpec> NodeChainState<E> {
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
        let fc = self.fork_choice.read();
        fc.block_states.get(&root).cloned()
    }

    fn state_by_state_root(&self, state_root: Root) -> Option<E::BeaconState> {
        // First check in-memory fork-choice post-states (keyed by block root,
        // but each has a .state_root). Clone the candidates out and release the
        // read lock BEFORE merkleizing — `tree_hash_root()` over a full state is
        // expensive and must not block concurrent fork-choice writers.
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
        // Fall back to cold storage.
        <RocksStore as DbStore<E>>::get_state(&self.store, &state_root)
            .ok()
            .flatten()
    }

    fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
        use pharos_types::views::BeaconBlockView;
        let fc = self.fork_choice.read();
        fc.blocks.iter().find_map(|(root, block)| {
            if block.slot() == slot {
                Some(*root)
            } else {
                None
            }
        })
    }

    fn genesis_block_root(&self) -> Root {
        // The genesis block root is the anchor root stored in the fork-choice
        // store's finalized checkpoint at epoch 0.  We look for the block at
        // slot 0 in-memory, then fall back to the finalized checkpoint root.
        use pharos_types::views::BeaconBlockView;
        let fc = self.fork_choice.read();
        if let Some(root) = fc.blocks.iter().find_map(|(r, b)| {
            if b.slot() == pharos_types::phase0::Slot(0) {
                Some(*r)
            } else {
                None
            }
        }) {
            return root;
        }
        // Anchor checkpoint is the first block we know about.
        fc.finalized_checkpoint.root
    }

    fn sync_committee_pubkeys(&self, block_root: Root) -> Option<SyncCommitteePubkeys> {
        use pharos_types::BeaconStateView;
        let fc = self.fork_choice.read();
        // Delegate to BeaconStateView::sync_committee_pubkeys which has
        // per-fork overrides returning the committee pubkeys (Phase0 returns None).
        fc.block_states.get(&block_root)?.sync_committee_pubkeys()
    }

    fn block_by_root_for_api(&self, root: Root) -> Result<Option<SignedBlockForApi>, ApiError> {
        // Fetch from cold storage (the only place full signed blocks are kept).
        // A genuine DB read error is surfaced as 500, distinct from a missing
        // block (Ok(None) → 404 at the handler).
        let block = match <RocksStore as DbStore<E>>::get_block(&self.store, &root)
            .map_err(|e| ApiError::Internal(format!("block store read failed: {e}")))?
        {
            Some(b) => b,
            None => return Ok(None),
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
