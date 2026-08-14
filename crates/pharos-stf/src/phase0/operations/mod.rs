pub mod attestation;
pub mod attester_slashing;
pub mod block_header;
pub mod deposit;
pub mod eth1_data;
pub mod proposer_slashing;
pub mod randao;
pub mod voluntary_exit;

pub use attestation::process_attestation;
pub use attester_slashing::process_attester_slashing;
pub use block_header::process_block_header;
pub use deposit::process_deposit;
pub use eth1_data::process_eth1_data;
pub use proposer_slashing::process_proposer_slashing;
pub use randao::process_randao;
pub use voluntary_exit::process_voluntary_exit;
