//! State-id and block-id resolution.
//!
//! Per `D-api-id-resolution`: maps the string identifiers accepted by
//! `/eth/v1/beacon/states/{state_id}` and `/eth/v1/beacon/blocks/{block_id}`
//! to a `ResolvedId` containing the concrete block root, slot,
//! `execution_optimistic` flag, and `finalized` flag.
//!
//! ID forms supported:
//! - `"head"` — the current fork-choice head.
//! - `"genesis"` — the genesis block (slot 0).
//! - `"finalized"` — the highest finalized checkpoint block.
//! - `"justified"` — the highest justified checkpoint block.
//! - `"<decimal>"` — a slot number; looks up the canonical block at that slot.
//! - `"0x<hex32>"` — a block root (32-byte hex with `0x` prefix).
//!
//! Errors:
//! - `ApiError::BadRequest` — malformed id (e.g. non-hex 0x string).
//! - `ApiError::NotFound` — id is valid but not in any store (pruned or never seen).

use pharos_types::{
    EthSpec,
    phase0::{Root, Slot},
};

use crate::error::ApiError;
use crate::state::ChainStateApi;

// ── ResolvedId ────────────────────────────────────────────────────────────────

/// Resolved state or block identifier.
#[derive(Debug, Clone)]
pub struct ResolvedId {
    /// The block root (block whose post-state is the target).
    pub block_root: Root,
    /// The slot of that block.
    pub slot: Slot,
    /// Whether the head block's payload has not yet been EL-validated.
    pub execution_optimistic: bool,
    /// Whether this block is at or behind the finalized checkpoint.
    pub finalized: bool,
}

// ── resolve_state_id ──────────────────────────────────────────────────────────

/// Resolve a `state_id` path segment into a `ResolvedId`.
///
/// `state_id` may be `"head"`, `"genesis"`, `"finalized"`, `"justified"`,
/// a decimal slot number, or a `0x`-prefixed 32-byte hex block root.
///
/// # Errors
/// - `ApiError::BadRequest` for malformed ids.
/// - `ApiError::NotFound` for valid but unknown ids.
pub fn resolve_state_id<E: EthSpec>(
    chain: &dyn ChainStateApi<E>,
    state_id: &str,
) -> Result<ResolvedId, ApiError> {
    let finalized_cp = chain.finalized_checkpoint();
    let spe = E::SLOTS_PER_EPOCH;

    match state_id {
        "head" => {
            // Head-level optimism is correct: the response IS about the head.
            let block_root = chain.head_root();
            let slot = chain.current_slot();
            let finalized = is_finalized(slot, &finalized_cp, spe);
            Ok(ResolvedId {
                block_root,
                slot,
                execution_optimistic: chain.is_optimistic_for_root(block_root),
                finalized,
            })
        }
        "genesis" => {
            // Genesis is always finalized and non-optimistic; no EL payload.
            let genesis_root = chain.genesis_block_root();
            Ok(ResolvedId {
                block_root: genesis_root,
                slot: Slot(0),
                execution_optimistic: false,
                finalized: true,
            })
        }
        "finalized" => {
            // Finalized blocks are by definition non-optimistic: the EL must
            // have confirmed them Valid before finalization. The derivation
            // `is_optimistic` returns false naturally for them (Valid != NotValidated),
            // but hardcoding false is an explicit invariant assertion.
            let cp = chain.finalized_checkpoint();
            Ok(ResolvedId {
                block_root: cp.root,
                slot: cp.epoch.start_slot(spe),
                execution_optimistic: false,
                finalized: true,
            })
        }
        "justified" => {
            // Use per-root derivation: response is about the justified checkpoint block.
            let cp = chain.justified_checkpoint();
            let slot = cp.epoch.start_slot(spe);
            let fin = is_finalized(slot, &finalized_cp, spe);
            Ok(ResolvedId {
                block_root: cp.root,
                slot,
                execution_optimistic: chain.is_optimistic_for_root(cp.root),
                finalized: fin,
            })
        }
        id if id.starts_with("0x") => {
            // Root form: 0x + 64 hex chars = 66 total.
            if id.len() != 66 {
                return Err(ApiError::BadRequest(format!(
                    "0x-prefixed state_id must be exactly 32 bytes (66 chars), got {}",
                    id.len()
                )));
            }
            let bytes = hex::decode(&id[2..])
                .map_err(|e| ApiError::BadRequest(format!("invalid hex in state_id: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ApiError::BadRequest("state_id root is not 32 bytes".to_string()))?;
            let block_root = Root::from(arr);
            // Find the slot from the in-memory store.
            let header = chain
                .block_header_at(block_root)
                .ok_or_else(|| ApiError::NotFound(format!("state not found for root {id}")))?;
            let slot = header.slot;
            let fin = is_finalized(slot, &finalized_cp, spe);
            // Per-root derivation: response is about THIS specific block.
            Ok(ResolvedId {
                block_root,
                slot,
                execution_optimistic: chain.is_optimistic_for_root(block_root),
                finalized: fin,
            })
        }
        slot_str => {
            // Decimal slot number.
            let slot_num: u64 = slot_str
                .parse()
                .map_err(|_| ApiError::BadRequest(format!("invalid state_id: '{slot_str}'")))?;
            let slot = Slot(slot_num);
            // Look up canonical block root at this slot from fork-choice store.
            let block_root = chain
                .block_root_for_slot(slot)
                .ok_or_else(|| ApiError::NotFound(format!("no block at slot {slot_num}")))?;
            let fin = is_finalized(slot, &finalized_cp, spe);
            // Per-root derivation: response is about THIS specific block.
            Ok(ResolvedId {
                block_root,
                slot,
                execution_optimistic: chain.is_optimistic_for_root(block_root),
                finalized: fin,
            })
        }
    }
}

// ── resolve_block_id ──────────────────────────────────────────────────────────

/// Resolve a `block_id` path segment.
///
/// Same forms as `resolve_state_id`; both IDs use identical resolution logic
/// (a block root identifies both the block and its post-state).
pub fn resolve_block_id<E: EthSpec>(
    chain: &dyn ChainStateApi<E>,
    block_id: &str,
) -> Result<ResolvedId, ApiError> {
    // Block-id uses the same resolution table as state-id.
    resolve_state_id(chain, block_id)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// A block is finalized when its epoch is at or behind the finalized checkpoint epoch.
fn is_finalized(
    slot: Slot,
    finalized_cp: &pharos_types::phase0::Checkpoint,
    slots_per_epoch: u64,
) -> bool {
    let slot_epoch = slot.epoch(slots_per_epoch);
    slot_epoch <= finalized_cp.epoch
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pharos_types::config::RuntimeConfig;
    use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
    use pharos_types::phase0::{BeaconBlockHeader, Checkpoint};
    use pharos_types::{EthSpec, MainnetEthSpec};

    use super::*;
    use crate::state::{ChainStateApi, NodeIdentityCache, RegenTarget};

    // ── Minimal mock ──────────────────────────────────────────────────────────

    struct Mock {
        head_root: Root,
        head_slot: Slot,
        finalized_root: Root,
        finalized_epoch: Epoch,
        justified_root: Root,
        justified_epoch: Epoch,
        genesis_root: Root,
    }

    impl Mock {
        fn new() -> Self {
            Self {
                head_root: Root::from([0xab; 32]),
                head_slot: Slot(100),
                finalized_root: Root::from([0xf1; 32]),
                finalized_epoch: Epoch(3),
                justified_root: Root::from([0xf2; 32]),
                justified_epoch: Epoch(4),
                genesis_root: Root::from([0x00; 32]),
            }
        }
    }

    impl ChainStateApi<MainnetEthSpec> for Mock {
        fn head_root(&self) -> Root {
            self.head_root
        }
        fn current_slot(&self) -> Slot {
            self.head_slot
        }
        fn genesis(&self) -> (u64, Root, [u8; 4]) {
            (0, Root::default(), [0u8; 4])
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            Checkpoint {
                epoch: self.finalized_epoch,
                root: self.finalized_root,
            }
        }
        fn justified_checkpoint(&self) -> Checkpoint {
            Checkpoint {
                epoch: self.justified_epoch,
                root: self.justified_root,
            }
        }
        fn block_header_at(&self, root: Root) -> Option<BeaconBlockHeader> {
            if root == self.head_root {
                Some(BeaconBlockHeader {
                    slot: self.head_slot,
                    proposer_index: ValidatorIndex(0),
                    parent_root: Root::default(),
                    state_root: Root::default(),
                    body_root: Root::default(),
                })
            } else {
                None
            }
        }
        fn runtime_cfg(&self) -> Arc<RuntimeConfig> {
            Arc::new(RuntimeConfig::default())
        }
        fn is_optimistic(&self) -> bool {
            false
        }
        fn is_optimistic_for_root(&self, _root: pharos_types::phase0::Root) -> bool {
            false
        }
        fn is_optimistic_node(&self) -> bool {
            false
        }
        fn is_syncing(&self) -> bool {
            false
        }
        fn node_identity(&self) -> &NodeIdentityCache {
            unimplemented!()
        }
        fn state_by_block_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::BeaconState> {
            None
        }
        fn state_by_state_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::BeaconState> {
            None
        }
        fn block_root_for_slot(&self, slot: Slot) -> Option<Root> {
            if slot == self.head_slot {
                Some(self.head_root)
            } else {
                None
            }
        }
        fn genesis_block_root(&self) -> Root {
            self.genesis_root
        }

        fn sync_committee_pubkeys(&self, _root: Root) -> Option<(Vec<[u8; 48]>, Vec<[u8; 48]>)> {
            None
        }

        fn block_by_root_for_api(
            &self,
            _root: Root,
        ) -> Result<Option<crate::dto::block::SignedBlockForApi>, ApiError> {
            Ok(None)
        }

        fn signed_block_header_at(
            &self,
            _root: Root,
        ) -> Option<(BeaconBlockHeader, pharos_utils::BLSSignature)> {
            None
        }

        fn regenerate_state(
            &self,
            _target: RegenTarget,
        ) -> Result<<MainnetEthSpec as EthSpec>::BeaconState, ApiError> {
            Err(ApiError::NotFound("regen not available in mock".into()))
        }

        fn fork_choice_dump(&self) -> Result<serde_json::Value, ApiError> {
            Ok(serde_json::json!({
                "justified_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                "finalized_checkpoint": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                "fork_choice_nodes": [],
            }))
        }

        fn fork_choice_heads(&self) -> Result<serde_json::Value, ApiError> {
            Ok(serde_json::json!({ "data": [] }))
        }

        fn state_to_json(
            &self,
            state: <MainnetEthSpec as EthSpec>::BeaconState,
        ) -> Result<serde_json::Value, ApiError> {
            crate::state::beacon_state_to_json_full::<MainnetEthSpec>(state)
        }
    }

    #[test]
    fn resolve_head() {
        let m = Mock::new();
        let r = resolve_state_id(&m, "head").unwrap();
        assert_eq!(r.block_root, m.head_root);
        assert_eq!(r.slot, m.head_slot);
        assert!(!r.execution_optimistic);
    }

    #[test]
    fn resolve_genesis() {
        let m = Mock::new();
        let r = resolve_state_id(&m, "genesis").unwrap();
        assert_eq!(r.block_root, m.genesis_root);
        assert_eq!(r.slot, Slot(0));
        assert!(r.finalized);
    }

    #[test]
    fn resolve_finalized() {
        let m = Mock::new();
        let r = resolve_state_id(&m, "finalized").unwrap();
        assert_eq!(r.block_root, m.finalized_root);
        assert!(r.finalized);
    }

    #[test]
    fn resolve_justified() {
        let m = Mock::new();
        let r = resolve_state_id(&m, "justified").unwrap();
        assert_eq!(r.block_root, m.justified_root);
    }

    #[test]
    fn resolve_slot() {
        let m = Mock::new();
        let r = resolve_state_id(&m, "100").unwrap();
        assert_eq!(r.block_root, m.head_root);
        assert_eq!(r.slot, Slot(100));
    }

    #[test]
    fn resolve_slot_not_found() {
        let m = Mock::new();
        let err = resolve_state_id(&m, "999").unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[test]
    fn resolve_root_hex() {
        let m = Mock::new();
        let hex = format!("0x{}", hex::encode(m.head_root.as_slice()));
        let r = resolve_state_id(&m, &hex).unwrap();
        assert_eq!(r.block_root, m.head_root);
    }

    #[test]
    fn resolve_root_hex_not_found() {
        let m = Mock::new();
        let hex = format!("0x{}", hex::encode([0xcc; 32]));
        let err = resolve_state_id(&m, &hex).unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[test]
    fn resolve_bad_hex() {
        let m = Mock::new();
        let err = resolve_state_id(&m, "0xdeadbeef").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn resolve_garbage() {
        let m = Mock::new();
        let err = resolve_state_id(&m, "notavalidid").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
