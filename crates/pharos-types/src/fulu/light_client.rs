//! Fulu light-client containers.
//!
//! Per `specs/fulu/light-client/sync-protocol.md`. Fulu appends
//! `proposer_lookahead` to `BeaconState`, which deepens the generalized
//! indices of the light-client merkle branches. The LC header / bootstrap /
//! update / finality / optimistic containers are structurally identical to
//! the electra LC types (EIP-7251 already deepened the branches in electra;
//! fulu does NOT further reshape the LC containers), so we re-export the
//! electra LC types.

pub use crate::electra::light_client::{
    CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientHeader, LightClientOptimisticUpdate, LightClientUpdate, MainnetLightClientBootstrap,
    MainnetLightClientFinalityUpdate, MainnetLightClientHeader, MainnetLightClientOptimisticUpdate,
    MainnetLightClientUpdate, MinimalLightClientBootstrap, MinimalLightClientFinalityUpdate,
    MinimalLightClientHeader, MinimalLightClientOptimisticUpdate, MinimalLightClientUpdate,
    NEXT_SYNC_COMMITTEE_BRANCH_DEPTH_ELECTRA,
};
