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

use pharos_network::host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict};
use pharos_network::types::SubnetId;
use pharos_ssz::Bitvector;
use pharos_storage::{RocksStore, Store as StoreTrait};
use pharos_types::EthSpec;
use pharos_types::fork::{ForkSchedule, compute_fork_digest};
use pharos_types::phase0::primitives::{ATTESTATION_SUBNET_COUNT, ForkDigest, Root, Version};
use pharos_types::phase0::{
    AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, MetaData,
    ProposerSlashing, SignedVoluntaryExit, Slot,
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
    metadata: RwLock<MetaData>,
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

        // M3a: altair_fork_epoch = FAR_FUTURE_EPOCH; Phase 0 for all epochs.
        let fork_schedule = ForkSchedule {
            genesis_fork_version: current_fork_version,
            altair_fork_version: current_fork_version, // placeholder; M3b sets real value
            altair_fork_epoch: Epoch(u64::MAX),        // FAR_FUTURE_EPOCH
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
            metadata: RwLock::new(MetaData {
                seq_number: 0,
                attnets: Bitvector::default(),
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

    fn local_metadata(&self) -> MetaData {
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
        use pharos_types::phase0::MainnetBeaconBlock;
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
        let anchor_block = MainnetBeaconBlock {
            state_root,
            ..MainnetBeaconBlock::default()
        };
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
