//! Electra block-processing operations.
//!
//! Per `specs/electra/beacon-chain.md` Block processing.

pub mod attestation;
pub mod block_header;
pub mod consolidation_request;
pub mod deposit;
pub mod deposit_request;
pub mod proposer_slashing;
pub mod sync_aggregate;
pub mod voluntary_exit;
pub mod withdrawal_request;
pub mod withdrawals;

pub use attestation::{process_attestation_electra, process_attester_slashing_electra};
pub use block_header::process_block_header_electra;
pub use consolidation_request::{
    is_valid_switch_to_compounding_request, process_consolidation_request,
};
pub use deposit::process_deposit_electra;
pub use deposit_request::process_deposit_request;
pub use proposer_slashing::process_proposer_slashing_electra;
pub use sync_aggregate::process_sync_aggregate_electra;
pub use voluntary_exit::process_voluntary_exit_electra;
pub use withdrawal_request::process_withdrawal_request;
pub use withdrawals::process_withdrawals_electra;
