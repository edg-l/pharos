//! LMD-GHOST + FFG Casper fork choice.
//!
//! Conformance: `consensus-specs/tests/formats/fork_choice`.

pub mod error;
pub mod get_head;
pub mod handlers;
pub mod pow_block;
pub mod store;

pub use error::ForkChoiceError;
pub use get_head::{get_checkpoint_block, get_current_slot, get_head};
pub use handlers::{
    compute_pulled_up_tip, on_attestation, on_attester_slashing, on_block, on_tick,
    on_tick_per_slot, should_override_forkchoice_update, update_checkpoints,
    update_unrealized_checkpoints,
};
pub use pharos_types::PayloadStatus;
pub use pow_block::{
    HashMapPowBlockProvider, NoopPowBlockProvider, PowBlock, PowBlockError, PowBlockProvider,
    ValidateMergeBlockError, block_is_execution_enabled, execution_block_hash_at_root,
    is_valid_terminal_pow_block, validate_merge_block,
};
pub use store::{LatestMessage, Store, get_forkchoice_store};
