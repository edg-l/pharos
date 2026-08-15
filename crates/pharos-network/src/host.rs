//! Host trait boundaries: `ForkContext`, `BlockProvider`, `GossipValidator`.
//!
//! These traits decouple the network layer from the node implementation.
//! The node binary (`pharos-node`) provides concrete implementations over
//! `pharos-storage` + `pharos-fork-choice`. The network crate must not depend
//! on either of those crates.
//!
//! Plan reference: D-trait boundaries in `docs/m2-plan.md`.

use pharos_types::EthSpec;
use pharos_types::phase0::primitives::ForkDigest;
use pharos_types::phase0::{
    AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, MetaData,
    ProposerSlashing, Root, SignedVoluntaryExit, Slot,
};

use crate::types::SubnetId;

// ── GossipVerdict ─────────────────────────────────────────────────────────────

/// The verdict returned by a `GossipValidator` method.
///
/// Used to drive libp2p gossipsub message acceptance; maps directly onto
/// gossipsub's `MessageAcceptance`.
#[derive(Debug, Clone)]
pub enum GossipVerdict {
    /// The message is valid; propagate it to other peers.
    Accept,
    /// The message is invalid; penalise the sender and discard.
    Reject(String),
    /// The message is not relevant right now; discard without penalising.
    Ignore(String),
}

// ── ForkContext ───────────────────────────────────────────────────────────────

/// Provides fork-digest and genesis-root information to the network layer.
///
/// Implemented by the node binary over the current `BeaconState` + clock.
pub trait ForkContext: Send + Sync + 'static {
    /// The 4-byte fork digest for the current fork.
    fn current_fork_digest(&self) -> ForkDigest;

    /// The ENR fork identifier (fork_digest + next_fork_version + next_fork_epoch).
    fn enr_fork_id(&self) -> ENRForkID;

    /// The genesis validators root used in fork-digest computation.
    fn genesis_validators_root(&self) -> Root;

    /// The local node's current `MetaData`.
    ///
    /// Used by `Ping` and `MetaData` req-resp handlers to return the node's
    /// sequence number and attestation subnet bitfield. The default
    /// implementation returns a zeroed `MetaData`; production nodes should
    /// override this.
    fn local_metadata(&self) -> MetaData {
        MetaData::default()
    }
}

// ── BlockProvider ─────────────────────────────────────────────────────────────

/// Provides block-lookup and chain-head information to the network layer.
///
/// Used by req-resp handlers to serve `BeaconBlocksByRange` and
/// `BeaconBlocksByRoot` responses without the network crate touching storage
/// directly.
pub trait BlockProvider<E: EthSpec>: Send + Sync + 'static {
    /// Retrieve a single block by its beacon block root.
    ///
    /// Returns `None` if the block is not in the local store.
    fn block_by_root(&self, root: Root) -> Option<E::SignedBeaconBlock>;

    /// Retrieve a range of blocks starting from `start_slot`.
    ///
    /// Returns up to `count` consecutive blocks. May return fewer if slots are
    /// empty or `start_slot + count` exceeds the current head.
    fn blocks_by_range(&self, start_slot: Slot, count: u64) -> Vec<E::SignedBeaconBlock>;

    /// The latest finalized checkpoint.
    fn finalized_checkpoint(&self) -> Checkpoint;

    /// The current chain head: `(block_root, slot)`.
    fn head(&self) -> (Root, Slot);
}

// ── GossipValidator ───────────────────────────────────────────────────────────

/// Validates gossip messages that require state-aware checks.
///
/// The network crate performs only protocol-level checks (topic validity,
/// SSZ decode, snappy decode, message-id). State-aware checks (proposer
/// signature, known parent, etc.) are delegated here.
///
/// Each method corresponds to one of the six Phase-0 gossip topics defined in
/// `specs/phase0/p2p-interface.md`.
///
/// The const generics (`MAX_VALIDATORS_PER_COMMITTEE`) match those used by the
/// concrete operation containers in `pharos-types`. Both mainnet and minimal
/// presets share `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
pub trait GossipValidator<E: EthSpec>: Send + Sync + 'static {
    /// Validate a `beacon_block` message.
    fn validate_beacon_block(&self, block: &E::SignedBeaconBlock) -> GossipVerdict;

    /// Validate a `beacon_attestation_{subnet_id}` message.
    ///
    /// `subnet` is the subnet id extracted from the topic string.
    /// `MAX_VALIDATORS_PER_COMMITTEE = 2048` for both mainnet and minimal.
    fn validate_attestation(&self, subnet: SubnetId, att: &Attestation<2048>) -> GossipVerdict;

    /// Validate a `beacon_aggregate_and_proof` message.
    ///
    /// `MAX_VALIDATORS_PER_COMMITTEE = 2048` for both mainnet and minimal.
    fn validate_aggregate_and_proof(&self, msg: &AggregateAndProof<2048>) -> GossipVerdict;

    /// Validate a `voluntary_exit` message.
    fn validate_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> GossipVerdict;

    /// Validate a `proposer_slashing` message.
    fn validate_proposer_slashing(&self, slashing: &ProposerSlashing) -> GossipVerdict;

    /// Validate an `attester_slashing` message.
    ///
    /// `MAX_VALIDATORS_PER_COMMITTEE = 2048` for both mainnet and minimal.
    fn validate_attester_slashing(&self, slashing: &AttesterSlashing<2048>) -> GossipVerdict;
}

// ── Host ──────────────────────────────────────────────────────────────────────

/// Combined host trait: a single bound for `ForkContext + BlockProvider<E> + GossipValidator<E>`.
///
/// `Network<E, H, S>` takes a single `Arc<H>` rather than three separate arcs.
/// The blanket impl monomorphises once per concrete `(T, E)` pair (in practice
/// `(HostImpl, MainnetEthSpec)` plus the test mock); no dynamic dispatch is
/// introduced.
pub trait Host<E: EthSpec>: ForkContext + BlockProvider<E> + GossipValidator<E> {}

impl<T, E> Host<E> for T
where
    T: ForkContext + BlockProvider<E> + GossipValidator<E>,
    E: EthSpec,
{
}
