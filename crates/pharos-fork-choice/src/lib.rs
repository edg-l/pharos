//! LMD-GHOST + FFG Casper fork choice.
//!
//! Conformance: `consensus-specs/tests/formats/fork_choice`.

pub mod error;
pub mod get_head;
pub mod handlers;
pub mod optimistic;
pub mod pow_block;
pub mod store;

pub use error::ForkChoiceError;
pub use get_head::{get_checkpoint_block, get_current_slot, get_head};
pub use handlers::{
    compute_pulled_up_tip, on_attestation, on_attestation_electra, on_attester_slashing, on_block,
    on_tick, on_tick_per_slot, should_override_forkchoice_update, update_checkpoints,
    update_unrealized_checkpoints,
};
pub use optimistic::{
    SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY, apply_invalid_payload, is_optimistic,
    is_optimistic_candidate_block, is_optimistic_node, latest_verified_ancestor,
    promote_valid_ancestors, resolve_invalid_block,
};
pub use pharos_types::PayloadStatus;
pub use pow_block::{
    HashMapPowBlockProvider, NoopPowBlockProvider, PowBlock, PowBlockError, PowBlockProvider,
    ValidateMergeBlockError, block_is_execution_enabled, execution_block_hash_at_root,
    is_valid_terminal_pow_block, validate_merge_block,
};
pub use store::{LatestMessage, Store, get_forkchoice_store};
