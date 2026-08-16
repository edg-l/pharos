//! Electra fork types.
//!
//! Per `specs/electra/beacon-chain.md` and related EIPs:
//! - EIP-6110: execution-layer deposit requests
//! - EIP-7002: execution-layer withdrawal requests
//! - EIP-7251: maxEB + consolidations
//! - EIP-7549: attestation restructuring (committee_bits)
//! - EIP-7685: general execution-layer requests container

pub mod attestation;
pub mod block;
pub mod body;
pub mod execution_payload;
pub mod light_client;
pub mod requests;
pub mod state;

pub use attestation::{
    Attestation, AttesterSlashing, IndexedAttestation, MainnetAggregateAndProof,
    MainnetAttestation, MainnetAttesterSlashing, MainnetIndexedAttestation,
    MainnetSignedAggregateAndProof, MinimalAggregateAndProof, MinimalAttestation,
    MinimalAttesterSlashing, MinimalIndexedAttestation, MinimalSignedAggregateAndProof,
    SingleAttestation,
};
pub use block::{
    BeaconBlock, MainnetBeaconBlock, MainnetSignedBeaconBlock, MinimalBeaconBlock,
    MinimalSignedBeaconBlock, SignedBeaconBlock,
};
pub use body::{BeaconBlockBody, MainnetBeaconBlockBody, MinimalBeaconBlockBody};
pub use execution_payload::{ExecutionPayload, ExecutionPayloadHeader};
pub use requests::{
    ConsolidationRequest, DepositRequest, ExecutionRequests, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, WithdrawalRequest,
};
pub use state::{BeaconState, MainnetBeaconState, MinimalBeaconState};
