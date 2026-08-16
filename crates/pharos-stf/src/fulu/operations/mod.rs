//! Fulu block-processing operations.
//!
//! Per `specs/fulu/beacon-chain.md` Block processing. The only fulu-specific
//! operation delta is `process_execution_payload` (EIP-7892 epoch-dependent blob
//! limit). `process_operations` and `process_deposit_request` are verified
//! unchanged from electra (consensus-specs v1.7.0-alpha.8) and re-exported.

pub mod deposit_request;
pub mod execution_payload;
pub mod process_operations;

pub use deposit_request::process_deposit_request;
pub use execution_payload::process_execution_payload as process_execution_payload_fulu;
pub use process_operations::process_operations_fulu;
