//! Electra light-client containers.
//!
//! Per `specs/electra/light-client/sync-protocol.md`.
//!
//! ## Changes from Deneb
//!
//! The `LightClientHeader.execution` field type is unchanged (electra execution
//! payload header is identical to deneb). All light-client containers are
//! structurally identical to their deneb counterparts; we re-export them to
//! avoid duplication.

pub use crate::deneb::light_client::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate, MainnetLightClientBootstrap,
    MainnetLightClientFinalityUpdate, MainnetLightClientHeader, MainnetLightClientOptimisticUpdate,
    MainnetLightClientUpdate, MinimalLightClientBootstrap, MinimalLightClientFinalityUpdate,
    MinimalLightClientHeader, MinimalLightClientOptimisticUpdate, MinimalLightClientUpdate,
};
