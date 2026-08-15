//! PoW block provider trait and merge-transition validation helpers.
//!
//! Per `specs/bellatrix/fork-choice.md:170-260` (`is_valid_terminal_pow_block`,
//! `validate_merge_block`) and `specs/bellatrix/fork-choice.md:303-304`
//! (the `on_block` merge-transition guard).

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_types::phase0::Root;
use pharos_utils::{Hash256, Uint256};
use thiserror::Error;

use crate::store::Store;
use pharos_types::EthSpec;

// ── PowBlock ──────────────────────────────────────────────────────────────────

/// A PoW-chain block summary needed to verify the terminal PoW block condition.
///
/// Per `specs/bellatrix/fork-choice.md` `PowBlock` container.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct PowBlock {
    /// The block's own hash.
    pub block_hash: Hash256,
    /// The parent block's hash.
    pub parent_hash: Hash256,
    /// Cumulative difficulty up to and including this block.
    pub total_difficulty: Uint256,
}

// ── PowBlockError ─────────────────────────────────────────────────────────────

/// Errors returned by `PowBlockProvider`.
#[derive(Error, Debug)]
pub enum PowBlockError {
    /// The EL returned an error while looking up the block.
    #[error("execution-layer error looking up PoW block: {0}")]
    ExecutionLayer(String),
}

// ── PowBlockProvider ──────────────────────────────────────────────────────────

/// Provider for PoW-chain block data needed by `validate_merge_block`.
///
/// The production impl (`EnginePowBlockProvider` in `pharos-node`) calls
/// `eth_getBlockByHash` via `EngineHandle`. In conformance tests, an in-memory
/// `HashMap<Hash256, PowBlock>` is used.
///
/// Per `specs/bellatrix/fork-choice.md:231-237` (`get_pow_block` description).
pub trait PowBlockProvider {
    /// Fetch the PoW block identified by `hash`.
    ///
    /// Returns `Ok(None)` when the block is not yet available.
    fn get_pow_block(&self, hash: Hash256) -> Result<Option<PowBlock>, PowBlockError>;
}

// ── NoopPowBlockProvider ──────────────────────────────────────────────────────

/// A no-op `PowBlockProvider` that always returns `Ok(None)`.
///
/// Used in conformance runners for non-merge-transition fixtures (Phase0 /
/// Altair fork-choice cases) where no PoW block lookup is ever performed.
pub struct NoopPowBlockProvider;

impl PowBlockProvider for NoopPowBlockProvider {
    fn get_pow_block(&self, _hash: Hash256) -> Result<Option<PowBlock>, PowBlockError> {
        Ok(None)
    }
}

// ── HashMapPowBlockProvider ───────────────────────────────────────────────────

/// In-memory `PowBlockProvider` backed by a `HashMap<Hash256, PowBlock>`.
///
/// Used by conformance runners for Bellatrix `on_merge_block` test fixtures
/// (Phase 5 Task 5.5b), where the fixture YAML lists `pow_block` steps that
/// pre-populate this map.
pub struct HashMapPowBlockProvider {
    pub blocks: std::collections::HashMap<Hash256, PowBlock>,
}

impl PowBlockProvider for HashMapPowBlockProvider {
    fn get_pow_block(&self, hash: Hash256) -> Result<Option<PowBlock>, PowBlockError> {
        Ok(self.blocks.get(&hash).cloned())
    }
}

// ── is_valid_terminal_pow_block ───────────────────────────────────────────────

/// `is_valid_terminal_pow_block` per `specs/bellatrix/fork-choice.md:170-190`.
///
/// Returns `true` iff `block.total_difficulty >= TTD` and
/// `parent.total_difficulty < TTD`.
pub fn is_valid_terminal_pow_block(block: &PowBlock, parent: &PowBlock, ttd: Uint256) -> bool {
    let is_total_difficulty_reached = block.total_difficulty >= ttd;
    let is_parent_total_difficulty_valid = parent.total_difficulty < ttd;
    is_total_difficulty_reached && is_parent_total_difficulty_valid
}

// ── ValidateMergeBlockError ───────────────────────────────────────────────────

/// Reasons `validate_merge_block` can fail.
#[derive(Error, Debug)]
pub enum ValidateMergeBlockError {
    /// The activation epoch for `TERMINAL_BLOCK_HASH` has not been reached.
    #[error("terminal block hash activation epoch not reached")]
    ActivationEpochNotReached,

    /// The execution payload's `parent_hash` does not equal `TERMINAL_BLOCK_HASH`.
    #[error("payload parent_hash does not match TERMINAL_BLOCK_HASH")]
    ParentHashMismatch,

    /// The PoW block (parent of the merge block) was not found.
    #[error("PoW block not found: {hash:?}")]
    PowBlockNotFound { hash: Hash256 },

    /// The PoW parent block was not found.
    #[error("PoW parent block not found: {hash:?}")]
    PowParentNotFound { hash: Hash256 },

    /// The terminal PoW block validity check failed.
    #[error("invalid terminal PoW block")]
    InvalidTerminalPowBlock,

    /// `PowBlockProvider` returned an error.
    #[error("PoW block provider error: {0}")]
    Provider(#[from] PowBlockError),
}

// ── validate_merge_block ──────────────────────────────────────────────────────

/// `validate_merge_block` per `specs/bellatrix/fork-choice.md:200-260`.
///
/// Validates that the execution payload's parent is a valid terminal PoW block.
/// Two modes:
///
/// 1. `TERMINAL_BLOCK_HASH != Hash32()` (override mode):
///    - asserts `current_epoch >= TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH`
///    - asserts `payload.parent_hash == TERMINAL_BLOCK_HASH`
///
/// 2. TTD-based mode:
///    - fetches `pow_block = get_pow_block(payload.parent_hash)`
///    - fetches `pow_parent = get_pow_block(pow_block.parent_hash)`
///    - asserts `is_valid_terminal_pow_block(pow_block, pow_parent)`
pub fn validate_merge_block<P: PowBlockProvider>(
    payload_parent_hash: Hash256,
    current_epoch: u64,
    terminal_block_hash: Hash256,
    terminal_block_hash_activation_epoch: u64,
    terminal_total_difficulty: Uint256,
    pow_provider: &P,
) -> Result<(), ValidateMergeBlockError> {
    let zero_hash = Hash256::default();

    if terminal_block_hash != zero_hash {
        // `specs/bellatrix/fork-choice.md:218-222` — TERMINAL_BLOCK_HASH override.
        if current_epoch < terminal_block_hash_activation_epoch {
            return Err(ValidateMergeBlockError::ActivationEpochNotReached);
        }
        if payload_parent_hash != terminal_block_hash {
            return Err(ValidateMergeBlockError::ParentHashMismatch);
        }
        return Ok(());
    }

    // `specs/bellatrix/fork-choice.md:224-260` — TTD-based terminal block check.
    let pow_block = pow_provider.get_pow_block(payload_parent_hash)?.ok_or(
        ValidateMergeBlockError::PowBlockNotFound {
            hash: payload_parent_hash,
        },
    )?;

    let pow_parent = pow_provider.get_pow_block(pow_block.parent_hash)?.ok_or(
        ValidateMergeBlockError::PowParentNotFound {
            hash: pow_block.parent_hash,
        },
    )?;

    if !is_valid_terminal_pow_block(&pow_block, &pow_parent, terminal_total_difficulty) {
        return Err(ValidateMergeBlockError::InvalidTerminalPowBlock);
    }

    Ok(())
}

// ── execution_block_hash_at_root ──────────────────────────────────────────────

/// Return the EL `block_hash` for the block at `root`, if it is a Bellatrix block.
///
/// Returns `Hash256::default()` (zeroed) for Phase0 and Altair blocks (pre-merge,
/// no EL block).
///
/// Used by the engine driver to compute `safe_block_hash` and
/// `finalized_block_hash` per `specs/bellatrix/fork-choice.md:93-100`.
pub fn execution_block_hash_at_root<E: EthSpec>(store: &Store<E>, root: Root) -> Hash256
where
    E::BeaconBlock: pharos_types::views::BeaconBlockView,
{
    store
        .blocks
        .get(&root)
        .and_then(|b| E::get_execution_block_hash(b))
        .unwrap_or_default()
}
