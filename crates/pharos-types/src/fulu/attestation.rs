//! Fulu attestation containers.
//!
//! Per `specs/fulu/beacon-chain.md`. Fulu does NOT reshape the attestation
//! containers (the only reshaped container is `BeaconState` + the new DAS
//! containers), so we re-export the electra types.

pub use crate::electra::attestation::{
    Attestation, AttesterSlashing, IndexedAttestation, MainnetAggregateAndProof,
    MainnetAttestation, MainnetAttesterSlashing, MainnetIndexedAttestation,
    MainnetSignedAggregateAndProof, MinimalAggregateAndProof, MinimalAttestation,
    MinimalAttesterSlashing, MinimalIndexedAttestation, MinimalSignedAggregateAndProof,
    SingleAttestation,
};
