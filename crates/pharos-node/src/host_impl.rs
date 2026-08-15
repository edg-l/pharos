//! Stub host implementations for `pharos-node`.
//!
//! These stubs satisfy the `Host<E>` trait bounds required by `NetworkBuilder`
//! without real storage or consensus logic.  Real implementations replace them
//! in later milestones.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pharos_network::host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict};
use pharos_network::types::SubnetId;
use pharos_types::MainnetEthSpec;
use pharos_types::phase0::primitives::ForkDigest;
use pharos_types::phase0::{
    AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, MetaData,
    ProposerSlashing, Root, SignedVoluntaryExit, Slot,
};
use pharos_utils::{Bytes4, Epoch};

/// Mainnet phase0 fork digest for a zeroed `genesis_validators_root`.
///
/// Formula: `compute_fork_digest(current_version, gvr) = compute_fork_data_root(current_version, gvr)[..4]`
/// where `compute_fork_data_root = hash_tree_root(ForkData { current_version, genesis_validators_root })`.
///
/// SSZ Merkleization of `ForkData`: each field's `hash_tree_root` is padded to 32 bytes, then
/// the pair is hashed: `sha256([0u8; 64])[..4]`.
///
/// Spec: `specs/phase0/beacon-chain.md:935-948` (`compute_fork_data_root`),
///       `specs/phase0/p2p-interface.md:269-285` (`compute_fork_digest`).
///
/// Verification: `python3 -c "import hashlib; print(hashlib.sha256(bytes(64)).hexdigest()[:8])"` → `f5a5fd42`.
const PHASE0_ZERO_FORK_DIGEST: [u8; 4] = [0xf5, 0xa5, 0xfd, 0x42];

// ── BlockStoreStub ────────────────────────────────────────────────────────────

/// In-memory block store stub.
///
/// Holds `MainnetSignedBeaconBlock` values keyed by `Root`.
/// TODO(M4): replace with real storage-backed implementation.
pub struct BlockStoreStub {
    pub inner:
        Arc<Mutex<HashMap<Root, <MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock>>>,
}

impl BlockStoreStub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for BlockStoreStub {
    fn default() -> Self {
        Self::new()
    }
}

// ── ForkContextStub ───────────────────────────────────────────────────────────

/// Stub fork context for M2 node startup.
///
/// Uses a zeroed `genesis_validators_root` and the corresponding hardcoded
/// mainnet phase0 fork digest.
/// TODO(M3): replace with a real implementation derived from BeaconState.
pub struct ForkContextStub {
    /// Zeroed genesis validators root (placeholder until genesis state is loaded).
    pub genesis_validators_root: Root,
    /// Hardcoded mainnet phase0 fork digest for the zeroed genesis root.
    pub current_fork_digest: ForkDigest,
}

impl ForkContextStub {
    pub fn new() -> Self {
        Self {
            genesis_validators_root: Root::default(),
            current_fork_digest: ForkDigest::from_array(PHASE0_ZERO_FORK_DIGEST),
        }
    }
}

impl Default for ForkContextStub {
    fn default() -> Self {
        Self::new()
    }
}

// ── GossipValidatorStub ───────────────────────────────────────────────────────

/// Stub gossip validator that accepts all messages.
///
/// TODO(M3): replace with real state-aware validation logic.
pub struct GossipValidatorStub;

// ── HostImpl ──────────────────────────────────────────────────────────────────

/// Combined node host implementation for M2.
///
/// Bundles `BlockStoreStub`, `ForkContextStub`, and `GossipValidatorStub`.
pub struct HostImpl {
    block_store: BlockStoreStub,
    fork_context: ForkContextStub,
    _gossip_validator: GossipValidatorStub,
}

impl HostImpl {
    pub fn new() -> Self {
        Self {
            block_store: BlockStoreStub::new(),
            fork_context: ForkContextStub::new(),
            _gossip_validator: GossipValidatorStub,
        }
    }
}

impl Default for HostImpl {
    fn default() -> Self {
        Self::new()
    }
}

// ── Trait implementations ─────────────────────────────────────────────────────

impl ForkContext for HostImpl {
    fn current_fork_digest(&self) -> ForkDigest {
        self.fork_context.current_fork_digest
    }

    fn enr_fork_id(&self) -> ENRForkID {
        ENRForkID {
            fork_digest: Bytes4::from_array(PHASE0_ZERO_FORK_DIGEST),
            next_fork_version: Bytes4::from_array([0u8; 4]),
            next_fork_epoch: Epoch(u64::MAX),
        }
    }

    fn genesis_validators_root(&self) -> Root {
        self.fork_context.genesis_validators_root
    }

    fn local_metadata(&self) -> MetaData {
        MetaData::default()
    }
}

impl BlockProvider<MainnetEthSpec> for HostImpl {
    fn block_by_root(
        &self,
        root: Root,
    ) -> Option<<MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock> {
        self.block_store
            .inner
            .lock()
            .expect("block store lock poisoned")
            .get(&root)
            .cloned()
    }

    fn blocks_by_range(
        &self,
        _start_slot: Slot,
        _count: u64,
    ) -> Vec<<MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock> {
        Vec::new()
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            root: Root::default(),
            epoch: Epoch(0),
        }
    }

    fn head(&self) -> (Root, Slot) {
        (Root::default(), Slot(0))
    }
}

impl GossipValidator<MainnetEthSpec> for HostImpl {
    fn validate_beacon_block(
        &self,
        _block: &<MainnetEthSpec as pharos_types::EthSpec>::SignedBeaconBlock,
    ) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_attestation(&self, _subnet: SubnetId, _att: &Attestation<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_aggregate_and_proof(&self, _msg: &AggregateAndProof<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_voluntary_exit(&self, _exit: &SignedVoluntaryExit) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_proposer_slashing(&self, _slashing: &ProposerSlashing) -> GossipVerdict {
        GossipVerdict::Accept
    }

    fn validate_attester_slashing(&self, _slashing: &AttesterSlashing<2048>) -> GossipVerdict {
        GossipVerdict::Accept
    }
}
