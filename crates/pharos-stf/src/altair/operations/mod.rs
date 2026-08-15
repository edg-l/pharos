pub mod attestation;
pub mod attester_slashing;
pub mod deposit;
pub mod proposer_slashing;
pub mod sync_aggregate;
pub mod voluntary_exit;

pub use attestation::process_attestation;
pub use attester_slashing::process_attester_slashing;
pub use deposit::process_deposit;
pub use proposer_slashing::process_proposer_slashing;
pub use sync_aggregate::process_sync_aggregate;
pub use voluntary_exit::process_voluntary_exit;
