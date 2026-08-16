//! Fulu light-client helpers.
//!
//! Per `specs/fulu/light-client/sync-protocol.md` and `full-node.md`.
//!
//! Fulu does NOT reshape the light-client containers: the fulu `LightClientHeader`
//! / bootstrap / update / finality / optimistic types ARE the electra LC types
//! (re-exported in `pharos_types::fulu::light_client`), and the fulu block IS the
//! electra block. Therefore the fulu LC helpers are the electra LC helpers:
//! `fulu_block_to_light_client_header` re-exports
//! `electra_block_to_light_client_header`, which builds the header from the
//! STF-verified `block.state_root` (the M4c `D-bellatrix-lc-header-uses-state-root`
//! invariant — never a recomputed `state.tree_hash_root()` on a projected state).
//!
//! `get_lc_execution_root` and `is_valid_light_client_header` are likewise the
//! electra implementations (gindex 25, depth 4; EIP-7251 already deepened the
//! branches in electra and fulu does not further reshape them).

pub use crate::electra::light_client::{
    electra_block_to_light_client_header as fulu_block_to_light_client_header,
    get_lc_execution_root, is_valid_light_client_header,
};
