//! Real `Host<E>` implementation for `pharos-node`.
//!
//! This module replaces the M2 stubs (`BlockStoreStub`, `ForkContextStub`,
//! `GossipValidatorStub`, non-generic `HostImpl`) with a single generic
//! `HostImpl<E: EthSpec>` backed by a real `RocksStore` and the in-memory
//! `pharos_fork_choice::Store<E>`.
//!
//! # GossipValidator note
//!
//! Every `GossipValidator<E>` method on `HostImpl<E>` returns
//! `GossipVerdict::Accept` for M3a. The trait *holder* is now the real
//! `HostImpl`; M4 fills the validation bodies once STF wiring lands.
//! See each method's `TODO(M4)` comment.
//!
//! # record_attnets_change
//!
//! `record_attnets_change` is the public hook for the M3b subnet-rotation
//! driver. At startup (M3a) it is called once from `main.rs` to set the
//! initial attestation subnet bitfield and bump `seq_number` from 0 to 1.
//! The M3b epoch driver will call it every `EPOCHS_PER_SUBNET_SUBSCRIPTION`
//! epochs when the persistent subnet assignment rotates.

use std::marker::PhantomData;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::warn;

use pharos_network::host::{
    BlockProvider, ForkContext, GossipValidator, GossipVerdict, LightClientProvider,
};
use pharos_network::types::{Fork, SubnetId};
use pharos_ssz::Bitvector;
use pharos_storage::{RocksStore, Store as StoreTrait};
use pharos_types::EthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::fork::{ForkSchedule, compute_fork_digest};
use pharos_types::phase0::primitives::{ATTESTATION_SUBNET_COUNT, ForkDigest, Root, Version};
use pharos_types::phase0::{
    AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
    SignedVoluntaryExit, Slot,
};
use pharos_utils::Epoch;

// ── ForkContextInner ──────────────────────────────────────────────────────────

/// Private fork-context state stored inside `HostImpl`.
struct ForkContextInner {
    genesis_validators_root: Root,
    current_fork_version: Version,
    /// Precomputed at construction so `current_fork_digest` has no runtime cost.
    current_fork_digest: ForkDigest,
    // Accessed via HostImpl::fork_schedule(); the field itself is not read
    // within this module but is part of the public API surface for Phase 3+.
    #[allow(dead_code)]
    fork_schedule: ForkSchedule,
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
        current_fork_version: Version,
    ) -> Self {
        let current_fork_digest =
            compute_fork_digest(current_fork_version, &genesis_validators_root);

        let fork_schedule = ForkSchedule {
            genesis_fork_version: current_fork_version,
            altair_fork_version: current_fork_version,
            altair_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH; overridden by RuntimeConfig
            bellatrix_fork_version: current_fork_version,
            bellatrix_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
            genesis_validators_root,
        };

        let fork_context = ForkContextInner {
            genesis_validators_root,
            current_fork_version,
            current_fork_digest,
            fork_schedule,
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
            _phantom: PhantomData,
        }
    }

    /// The fork schedule for this node.
    ///
    /// At M3a, `altair_fork_epoch = FAR_FUTURE_EPOCH`; `fork_at_epoch` returns
    /// Phase 0 for all epochs. M3b's YAML loader overwrites `altair_fork_epoch`
    /// with the real value without changing this struct shape.
    #[allow(dead_code)]
    pub fn fork_schedule(&self) -> &ForkSchedule {
        &self.fork_context.fork_schedule
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
}

// ── ForkContext ───────────────────────────────────────────────────────────────

impl<E: EthSpec> ForkContext for HostImpl<E> {
    fn current_fork_digest(&self) -> ForkDigest {
        self.fork_context.current_fork_digest
    }

    /// Returns the Phase-0-only ENR fork ID.
    ///
    /// `next_fork_version` and `next_fork_epoch` use `FAR_FUTURE_EPOCH`
    /// (Phase 0 only). M3b extends to real Altair values.
    fn enr_fork_id(&self) -> ENRForkID {
        ENRForkID {
            fork_digest: self.fork_context.current_fork_digest,
            next_fork_version: self.fork_context.current_fork_version,
            next_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH
        }
    }

    fn genesis_validators_root(&self) -> Root {
        self.fork_context.genesis_validators_root
    }

    /// Returns the fork digest for the given network `Fork`.
    ///
    /// Phase 0: `compute_fork_digest(genesis_fork_version, gvr)`.
    /// Altair:  `compute_fork_digest(altair_fork_version,  gvr)`.
    fn fork_digest_for(&self, fork: Fork) -> ForkDigest {
        let version = match fork {
            Fork::Phase0 => self.fork_context.fork_schedule.genesis_fork_version,
            Fork::Altair => self.fork_context.fork_schedule.altair_fork_version,
        };
        compute_fork_digest(version, &self.fork_context.genesis_validators_root)
    }

    /// Reverse-maps a raw 4-byte context to a `Fork`.
    ///
    /// Computes the known fork digests on the fly (two calls to
    /// `compute_fork_digest`; result is tiny and computed once per chunk).
    /// Returns `None` for any unknown context bytes.
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

impl<E: EthSpec> GossipValidator<E> for HostImpl<E> {
    /// TODO(M4): Validate proposer signature, known parent, slot bounds.
    fn validate_beacon_block(&self, _block: &E::SignedBeaconBlock) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate attestation target epoch, aggregation bits, signature.
    fn validate_attestation(&self, _subnet: SubnetId, _att: &Attestation<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate aggregate proof, selection proof, signature.
    fn validate_aggregate_and_proof(&self, _msg: &AggregateAndProof<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate voluntary exit epoch, validator status, signature.
    fn validate_voluntary_exit(&self, _exit: &SignedVoluntaryExit) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate proposer slashing headers, signature.
    fn validate_proposer_slashing(&self, _slashing: &ProposerSlashing) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate attester slashing indices, signature.
    fn validate_attester_slashing(&self, _slashing: &AttesterSlashing<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate sync committee message slot, validator index, signature.
    fn validate_sync_committee_message(
        &self,
        _subnet: SubnetId,
        _msg: &pharos_types::altair::SyncCommitteeMessage,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate sync committee contribution: aggregator index, proof, signature.
    fn validate_sync_committee_contribution_and_proof(
        &self,
        _msg: &<E as EthSpec>::AltairSignedContributionAndProof,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate light client finality update: better finalized header than latest.
    fn validate_light_client_finality_update(
        &self,
        _msg: &<E as EthSpec>::AltairLightClientFinalityUpdate,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    /// TODO(M4): Validate light client optimistic update: attested header slot.
    fn validate_light_client_optimistic_update(
        &self,
        _msg: &<E as EthSpec>::AltairLightClientOptimisticUpdate,
    ) -> GossipVerdict {
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
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_ssz::Bitvector;
    use pharos_storage::{RocksStore, RocksStoreConfig};
    use pharos_types::MainnetEthSpec;

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
        let fv = Version::from_array([0x00, 0x00, 0x00, 0x00]);
        HostImpl::new(store, fork_choice, gvr, fv)
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
}
