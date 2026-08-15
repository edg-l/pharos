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
use pharos_storage::RocksStore;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::{
    EthSpec,
    config::RuntimeConfig,
    phase0::{BeaconBlockHeader, Checkpoint, Root, Slot},
};

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
}

// ── NodeChainState ────────────────────────────────────────────────────────────

/// Concrete `ChainStateApi` backed by the shared fork-choice store and storage.
pub struct NodeChainState<E: EthSpec> {
    /// Shared chain DB (cold states, anchor, etc.).
    _store: Arc<RocksStore>,
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
            _store: store,
            fork_choice,
            identity,
            runtime_cfg,
        }
    }
}

impl<E: EthSpec> ChainStateApi<E> for NodeChainState<E> {
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
