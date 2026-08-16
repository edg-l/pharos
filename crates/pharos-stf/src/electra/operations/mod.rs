//! Electra block-processing operations.
//!
//! Per `specs/electra/beacon-chain.md` Block processing.

pub mod attestation;
pub mod block_header;
pub mod deposit;
pub mod proposer_slashing;
pub mod sync_aggregate;
pub mod voluntary_exit;

pub use attestation::{process_attestation_electra, process_attester_slashing_electra};
pub use block_header::process_block_header_electra;
pub use deposit::process_deposit_electra;
pub use proposer_slashing::process_proposer_slashing_electra;
pub use sync_aggregate::process_sync_aggregate_electra;
pub use voluntary_exit::process_voluntary_exit_electra;
