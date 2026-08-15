//! Beacon API data-transfer objects (DTOs).
//!
//! DTOs own ALL serde (`pharos-types` is serde-free per `D-api-dto-serde`).
//! The canonical types are only referenced for field extraction; no serde
//! derives are added to `pharos-types` structs.

pub mod block;
pub mod light_client;
