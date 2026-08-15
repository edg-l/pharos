//! LMD-GHOST + FFG Casper fork choice.
//!
//! Conformance: `consensus-specs/tests/formats/fork_choice`.

pub mod error;
pub mod get_head;
pub mod handlers;
pub mod store;

pub use error::ForkChoiceError;
pub use get_head::get_head;
pub use handlers::{
    compute_pulled_up_tip, on_attestation, on_attester_slashing, on_block, on_tick,
    update_checkpoints, update_unrealized_checkpoints,
};
pub use store::{LatestMessage, Store, get_forkchoice_store};
