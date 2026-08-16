//! `process_deposit_request` for Fulu.
//!
//! Verified against `specs/fulu/beacon-chain.md` (consensus-specs
//! v1.7.0-alpha.8): fulu does NOT override `process_deposit_request`. The fulu
//! spec's only "Modified" functions are `process_execution_payload`,
//! `compute_fork_digest`, `get_beacon_proposer_index`, `process_epoch`; the only
//! "New" functions are `BlobParameters`, `get_blob_parameters`,
//! `compute_proposer_indices`, `get_beacon_proposer_indices`,
//! `process_proposer_lookahead`. `process_deposit_request` is unchanged from
//! electra (EIP-6110: enqueue a `PendingDeposit` with `slot = state.slot`).
//!
//! Therefore the fulu `process_deposit_request` IS the electra impl; it is
//! re-exported rather than reimplemented (no fabricated delta).

pub use crate::electra::operations::deposit_request::{
    UNSET_DEPOSIT_REQUESTS_START_INDEX, process_deposit_request,
};
