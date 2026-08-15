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
use pharos_utils::{BLSSignature, Uint256};
use serde_json::Value as JsonValue;

use crate::dto::block::{BlockApiSerializer, SignedBlockForApi};
use crate::error::ApiError;
use crate::events::EventBus;

// ── Serialization helpers ─────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

fn q(v: u64) -> String {
    v.to_string()
}

/// Serialize a `BeaconState` to a complete `serde_json::Value` with all
/// spec-required per-fork fields.
///
/// Dispatches on the fork variant to include:
/// - All forks: `genesis_time`, `genesis_validators_root`, `slot`, `fork`,
///   `latest_block_header`, `block_roots`, `state_roots`, `historical_roots`,
///   `eth1_data`, `eth1_data_votes`, `eth1_deposit_index`, `validators`,
///   `balances`, `randao_mixes`, `slashings`, `justification_bits`,
///   `previous_justified_checkpoint`, `current_justified_checkpoint`,
///   `finalized_checkpoint`.
/// - Phase0: `previous_epoch_attestations`, `current_epoch_attestations`.
/// - Altair+: `previous_epoch_participation`, `current_epoch_participation`,
///   `inactivity_scores`, `current_sync_committee`, `next_sync_committee`.
/// - Bellatrix+: `latest_execution_payload_header`.
/// - Capella+: `next_withdrawal_index`, `next_withdrawal_validator_index`,
///   `historical_summaries`.
///
/// The caller must clone the state out from under any read-lock before calling
/// this function, as serialization of large lists can be expensive.
pub fn beacon_state_to_json_full<E: EthSpec>(state: E::BeaconState) -> Result<JsonValue, ApiError> {
    use pharos_types::BeaconStateView;
    use pharos_types::views::ForkVariant;

    // Build common fields using BeaconStateView accessors.
    let fork = state.fork();
    let lbh = state.latest_block_header();
    let prev_just = state.previous_justified_checkpoint();
    let curr_just = state.current_justified_checkpoint();
    let fin_cp = state.finalized_checkpoint();
    let eth1 = state.eth1_data();

    let validators_json: Vec<JsonValue> = state
        .validators_iter()
        .map(|v| {
            serde_json::json!({
                "pubkey": hex(v.pubkey.as_slice()),
                "withdrawal_credentials": hex(v.withdrawal_credentials.as_slice()),
                "effective_balance": q(v.effective_balance.0),
                "slashed": v.slashed,
                "activation_eligibility_epoch": q(v.activation_eligibility_epoch.0),
                "activation_epoch": q(v.activation_epoch.0),
                "exit_epoch": q(v.exit_epoch.0),
                "withdrawable_epoch": q(v.withdrawable_epoch.0),
            })
        })
        .collect();

    let balances_json: Vec<JsonValue> = state
        .balances()
        .iter()
        .map(|g| JsonValue::String(q(g.0)))
        .collect();
    let block_roots_json: Vec<JsonValue> = state
        .block_roots()
        .iter()
        .map(|r| JsonValue::String(hex(r.as_slice())))
        .collect();
    let state_roots_json: Vec<JsonValue> = state
        .state_roots()
        .iter()
        .map(|r| JsonValue::String(hex(r.as_slice())))
        .collect();
    let randao_mixes_json: Vec<JsonValue> = state
        .randao_mixes()
        .iter()
        .map(|h| JsonValue::String(hex(h.as_slice())))
        .collect();
    let slashings_json: Vec<JsonValue> = state
        .slashings()
        .iter()
        .map(|g| JsonValue::String(q(g.0)))
        .collect();
    let eth1_votes_json: Vec<JsonValue> = state
        .eth1_data_votes()
        .iter()
        .map(|e| {
            serde_json::json!({
                "deposit_root": hex(e.deposit_root.as_slice()),
                "deposit_count": q(e.deposit_count),
                "block_hash": hex(e.block_hash.as_slice()),
            })
        })
        .collect();
    let historical_roots_json: Vec<JsonValue> = state
        .historical_roots()
        .iter()
        .map(|r| JsonValue::String(hex(r.as_slice())))
        .collect();
    let justification_bits_hex = hex(&state.justification_bits_bytes());

    let mut m = serde_json::Map::new();
    m.insert(
        "genesis_time".into(),
        JsonValue::String(q(state.genesis_time())),
    );
    m.insert(
        "genesis_validators_root".into(),
        JsonValue::String(hex(state.genesis_validators_root().as_slice())),
    );
    m.insert("slot".into(), JsonValue::String(q(state.slot().0)));
    m.insert(
        "fork".into(),
        serde_json::json!({
            "previous_version": hex(fork.previous_version.as_slice()),
            "current_version": hex(fork.current_version.as_slice()),
            "epoch": q(fork.epoch.0),
        }),
    );
    m.insert(
        "latest_block_header".into(),
        serde_json::json!({
            "slot": q(lbh.slot.0),
            "proposer_index": q(lbh.proposer_index.0),
            "parent_root": hex(lbh.parent_root.as_slice()),
            "state_root": hex(lbh.state_root.as_slice()),
            "body_root": hex(lbh.body_root.as_slice()),
        }),
    );
    m.insert("block_roots".into(), JsonValue::Array(block_roots_json));
    m.insert("state_roots".into(), JsonValue::Array(state_roots_json));
    m.insert(
        "historical_roots".into(),
        JsonValue::Array(historical_roots_json),
    );
    m.insert(
        "eth1_data".into(),
        serde_json::json!({
            "deposit_root": hex(eth1.deposit_root.as_slice()),
            "deposit_count": q(eth1.deposit_count),
            "block_hash": hex(eth1.block_hash.as_slice()),
        }),
    );
    m.insert("eth1_data_votes".into(), JsonValue::Array(eth1_votes_json));
    m.insert(
        "eth1_deposit_index".into(),
        JsonValue::String(q(state.eth1_deposit_index_u64())),
    );
    m.insert("validators".into(), JsonValue::Array(validators_json));
    m.insert("balances".into(), JsonValue::Array(balances_json));
    m.insert("randao_mixes".into(), JsonValue::Array(randao_mixes_json));
    m.insert("slashings".into(), JsonValue::Array(slashings_json));
    m.insert(
        "justification_bits".into(),
        JsonValue::String(justification_bits_hex),
    );
    m.insert(
        "previous_justified_checkpoint".into(),
        serde_json::json!({
            "epoch": q(prev_just.epoch.0),
            "root": hex(prev_just.root.as_slice()),
        }),
    );
    m.insert(
        "current_justified_checkpoint".into(),
        serde_json::json!({
            "epoch": q(curr_just.epoch.0),
            "root": hex(curr_just.root.as_slice()),
        }),
    );
    m.insert(
        "finalized_checkpoint".into(),
        serde_json::json!({
            "epoch": q(fin_cp.epoch.0),
            "root": hex(fin_cp.root.as_slice()),
        }),
    );

    // Fork-specific fields via BeaconStateView accessors.
    let fork_variant = state.fork_variant();
    match fork_variant {
        ForkVariant::Phase0 => {
            // Phase0: pending attestations lists.
            let prev_atts = state.previous_epoch_attestations_raw().unwrap_or_default();
            let curr_atts = state.current_epoch_attestations_raw().unwrap_or_default();
            m.insert(
                "previous_epoch_attestations".into(),
                JsonValue::Array(prev_atts.into_iter().map(pending_att_raw_to_json).collect()),
            );
            m.insert(
                "current_epoch_attestations".into(),
                JsonValue::Array(curr_atts.into_iter().map(pending_att_raw_to_json).collect()),
            );
        }
        ForkVariant::Altair | ForkVariant::Bellatrix | ForkVariant::Capella => {
            // Altair+: participation flags and inactivity scores.
            let prev_participation: Vec<JsonValue> = state
                .previous_epoch_participation_u8s()
                .into_iter()
                .map(|f| JsonValue::String(q(f as u64)))
                .collect();
            let curr_participation: Vec<JsonValue> = state
                .current_epoch_participation_u8s()
                .into_iter()
                .map(|f| JsonValue::String(q(f as u64)))
                .collect();
            let inactivity: Vec<JsonValue> = state
                .inactivity_scores_u64s()
                .into_iter()
                .map(|s| JsonValue::String(q(s)))
                .collect();
            m.insert(
                "previous_epoch_participation".into(),
                JsonValue::Array(prev_participation),
            );
            m.insert(
                "current_epoch_participation".into(),
                JsonValue::Array(curr_participation),
            );
            m.insert("inactivity_scores".into(), JsonValue::Array(inactivity));

            // Altair+: sync committees (pubkeys from existing accessor + aggregate from new one).
            if let (Some((curr_pks, next_pks)), Some((curr_agg, next_agg))) = (
                state.sync_committee_pubkeys(),
                state.sync_committee_aggregate_pubkeys(),
            ) {
                let curr_pk_json: Vec<JsonValue> = curr_pks
                    .iter()
                    .map(|pk| JsonValue::String(hex(pk.as_slice())))
                    .collect();
                let next_pk_json: Vec<JsonValue> = next_pks
                    .iter()
                    .map(|pk| JsonValue::String(hex(pk.as_slice())))
                    .collect();
                m.insert(
                    "current_sync_committee".into(),
                    serde_json::json!({
                        "pubkeys": curr_pk_json,
                        "aggregate_pubkey": hex(curr_agg.as_slice()),
                    }),
                );
                m.insert(
                    "next_sync_committee".into(),
                    serde_json::json!({
                        "pubkeys": next_pk_json,
                        "aggregate_pubkey": hex(next_agg.as_slice()),
                    }),
                );
            }

            // Bellatrix+: execution payload header.
            if let Some(eph) = state.execution_payload_header_raw() {
                // Build base EPH object (bellatrix fields).
                let withdrawals_root = state.execution_payload_withdrawals_root();
                let mut eph_map = serde_json::Map::new();
                eph_map.insert(
                    "parent_hash".into(),
                    JsonValue::String(hex(&eph.parent_hash)),
                );
                eph_map.insert(
                    "fee_recipient".into(),
                    JsonValue::String(hex(&eph.fee_recipient)),
                );
                eph_map.insert("state_root".into(), JsonValue::String(hex(&eph.state_root)));
                eph_map.insert(
                    "receipts_root".into(),
                    JsonValue::String(hex(&eph.receipts_root)),
                );
                eph_map.insert("logs_bloom".into(), JsonValue::String(hex(&eph.logs_bloom)));
                eph_map.insert(
                    "prev_randao".into(),
                    JsonValue::String(hex(&eph.prev_randao)),
                );
                eph_map.insert(
                    "block_number".into(),
                    JsonValue::String(q(eph.block_number)),
                );
                eph_map.insert("gas_limit".into(), JsonValue::String(q(eph.gas_limit)));
                eph_map.insert("gas_used".into(), JsonValue::String(q(eph.gas_used)));
                eph_map.insert("timestamp".into(), JsonValue::String(q(eph.timestamp)));
                eph_map.insert("extra_data".into(), JsonValue::String(hex(&eph.extra_data)));
                // base_fee_per_gas: Uint256 as decimal string via to_le_bytes → Uint256 → Display.
                let bfpg = Uint256::from_le_bytes(eph.base_fee_per_gas_le);
                eph_map.insert(
                    "base_fee_per_gas".into(),
                    JsonValue::String(bfpg.to_string()),
                );
                eph_map.insert("block_hash".into(), JsonValue::String(hex(&eph.block_hash)));
                eph_map.insert(
                    "transactions_root".into(),
                    JsonValue::String(hex(&eph.transactions_root)),
                );
                if let Some(wr) = withdrawals_root {
                    eph_map.insert("withdrawals_root".into(), JsonValue::String(hex(&wr)));
                }
                m.insert(
                    "latest_execution_payload_header".into(),
                    JsonValue::Object(eph_map),
                );
            }

            // Capella+: withdrawal index, validator index, historical summaries.
            if let Some(nwi) = state.next_withdrawal_index_u64() {
                m.insert("next_withdrawal_index".into(), JsonValue::String(q(nwi)));
            }
            if let Some(nwv) = state.next_withdrawal_validator_index_raw() {
                m.insert(
                    "next_withdrawal_validator_index".into(),
                    JsonValue::String(q(nwv)),
                );
            }
            if let Some(summaries) = state.historical_summaries_raw() {
                let summaries_json: Vec<JsonValue> = summaries
                    .into_iter()
                    .map(|(bsr, ssr)| {
                        serde_json::json!({
                            "block_summary_root": hex(&bsr),
                            "state_summary_root": hex(&ssr),
                        })
                    })
                    .collect();
                m.insert(
                    "historical_summaries".into(),
                    JsonValue::Array(summaries_json),
                );
            }
        }
    }

    Ok(JsonValue::Object(m))
}

// ── Internal JSON helpers ──────────────────────────────────────────────────────

fn pending_att_raw_to_json(pa: pharos_types::PendingAttestationRaw) -> JsonValue {
    serde_json::json!({
        "aggregation_bits": hex(&pa.aggregation_bits_ssz),
        "data": {
            "slot": q(pa.data_slot),
            "index": q(pa.data_index),
            "beacon_block_root": hex(&pa.data_beacon_block_root),
            "source": {
                "epoch": q(pa.data_source_epoch),
                "root": hex(&pa.data_source_root),
            },
            "target": {
                "epoch": q(pa.data_target_epoch),
                "root": hex(&pa.data_target_root),
            },
        },
        "inclusion_delay": q(pa.inclusion_delay),
        "proposer_index": q(pa.proposer_index),
    })
}

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

    // ── Debug namespace (Phase 5) ──────────────────────────────────────────────

    /// Return a fork-choice dump for `GET /eth/v1/debug/fork_choice`.
    ///
    /// Returns the justified/finalized checkpoints and a list of all in-memory
    /// fork-choice blocks as a pre-serialised `serde_json::Value`.
    ///
    /// Mock implementations may return a minimal `{"justified_checkpoint":...,
    /// "finalized_checkpoint":..., "fork_choice_nodes":[]}` object.
    fn fork_choice_dump(&self) -> Result<JsonValue, ApiError>;

    /// Serialize a `BeaconState` to a `serde_json::Value` for
    /// `GET /eth/v2/debug/beacon/states/{state_id}`.
    ///
    /// Implementations must produce a COMPLETE fork-tagged state object
    /// covering all spec-required per-fork fields (see `beacon_state_to_json_full`).
    ///
    /// `NodeChainState` calls `beacon_state_to_json_full` after cloning the state
    /// out from under the fork-choice read-lock to avoid holding the lock during
    /// large-list serialization.
    ///
    /// Mock implementations in tests should call `beacon_state_to_json_full`
    /// or return a simplified object that satisfies the test's assertions.
    fn state_to_json(&self, state: E::BeaconState) -> Result<JsonValue, ApiError>;

    /// Return the fork-choice leaf nodes for `GET /eth/v2/debug/beacon/heads`.
    ///
    /// A leaf node is a block whose root is not the parent of any other block in
    /// the in-memory store (i.e. it has no children).  Returns a
    /// pre-serialised `serde_json::Value` with a `data` array.
    ///
    /// Mock implementations may return `{"data":[]}`.
    fn fork_choice_heads(&self) -> Result<JsonValue, ApiError>;

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

    fn state_to_json(&self, state: E::BeaconState) -> Result<JsonValue, ApiError> {
        // The state is already cloned by the caller (debug handler clones it out
        // before calling state_to_json, so the fork-choice read-lock is not held
        // during serialization of large lists).
        beacon_state_to_json_full::<E>(state)
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

    fn fork_choice_dump(&self) -> Result<JsonValue, ApiError> {
        use pharos_fork_choice::get_head::get_weight;
        use pharos_types::{PayloadStatus, views::BeaconBlockView};

        let fc = self.fork_choice.read();

        let justified = serde_json::json!({
            "epoch": fc.justified_checkpoint.epoch.0.to_string(),
            "root": format!("0x{}", hex::encode(fc.justified_checkpoint.root.as_slice())),
        });
        let finalized = serde_json::json!({
            "epoch": fc.finalized_checkpoint.epoch.0.to_string(),
            "root": format!("0x{}", hex::encode(fc.finalized_checkpoint.root.as_slice())),
        });

        let nodes: Vec<serde_json::Value> = fc
            .blocks
            .iter()
            .map(|(root, block)| {
                let validity = match fc.payload_statuses.get(root) {
                    Some(PayloadStatus::Invalid) => "invalid",
                    Some(PayloadStatus::NotValidated) => "optimistic",
                    _ => "valid",
                };
                // Use the unrealized justification for this block's justified/finalized
                // epochs when available, falling back to the store checkpoints.
                let (just_epoch, fin_epoch) = fc
                    .unrealized_justifications
                    .get(root)
                    .map(|cp| (cp.epoch.0, fc.unrealized_finalized_checkpoint.epoch.0))
                    .unwrap_or((
                        fc.justified_checkpoint.epoch.0,
                        fc.finalized_checkpoint.epoch.0,
                    ));

                // Fix 4: real LMD-GHOST vote weight.
                let weight = get_weight::<E>(&fc, *root).to_string();

                // Fix 5: real execution block hash for Bellatrix+ blocks;
                // Phase0/Altair stay zero.
                use pharos_types::views::BeaconBlockBodyView as _;
                let exec_block_hash_hex = block
                    .body()
                    .execution_block_hash()
                    .map(|h| format!("0x{}", hex::encode(h)))
                    .unwrap_or_else(|| format!("0x{}", "0".repeat(64)));

                serde_json::json!({
                    "slot": block.slot().0.to_string(),
                    "block_root": format!("0x{}", hex::encode(root.as_slice())),
                    "parent_root": format!("0x{}", hex::encode(block.parent_root().as_slice())),
                    "justified_epoch": just_epoch.to_string(),
                    "finalized_epoch": fin_epoch.to_string(),
                    "weight": weight,
                    "validity": validity,
                    "execution_block_hash": exec_block_hash_hex,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "justified_checkpoint": justified,
            "finalized_checkpoint": finalized,
            "fork_choice_nodes": nodes,
        }))
    }

    fn fork_choice_heads(&self) -> Result<JsonValue, ApiError> {
        use pharos_types::{PayloadStatus, views::BeaconBlockView};

        let fc = self.fork_choice.read();

        // Collect all parent roots of known blocks.
        let parent_roots: std::collections::HashSet<Root> =
            fc.blocks.values().map(|b| b.parent_root()).collect();

        // Leaf nodes = blocks whose own root is NOT a parent of any other block.
        let is_optimistic_head = |root: &Root| {
            matches!(
                fc.payload_statuses.get(root),
                Some(PayloadStatus::NotValidated)
            )
        };

        let heads: Vec<serde_json::Value> = fc
            .blocks
            .iter()
            .filter(|(root, _)| !parent_roots.contains(*root))
            .map(|(root, block)| {
                serde_json::json!({
                    "root": format!("0x{}", hex::encode(root.as_slice())),
                    "slot": block.slot().0.to_string(),
                    "execution_optimistic": is_optimistic_head(root),
                })
            })
            .collect();

        Ok(serde_json::json!({ "data": heads }))
    }
}

// ── ApiState ──────────────────────────────────────────────────────────────────

/// Axum state wrapper.
///
/// Injected via `axum::extract::State<Arc<ApiState<E>>>`. Handlers clone the
/// `Arc` cheaply rather than cloning the full state.
pub struct ApiState<E: EthSpec> {
    pub chain: Arc<dyn ChainStateApi<E>>,
    /// SSE broadcast bus.  `None` when built without an event bus (e.g. tests
    /// that only exercise non-SSE endpoints).
    pub event_bus: Option<Arc<EventBus>>,
}

impl<E: EthSpec> ApiState<E> {
    pub fn new(chain: Arc<dyn ChainStateApi<E>>) -> Arc<Self> {
        Arc::new(Self {
            chain,
            event_bus: None,
        })
    }

    /// Construct with an SSE event bus.
    pub fn new_with_bus(chain: Arc<dyn ChainStateApi<E>>, event_bus: Arc<EventBus>) -> Arc<Self> {
        Arc::new(Self {
            chain,
            event_bus: Some(event_bus),
        })
    }
}
