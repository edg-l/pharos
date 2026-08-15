//! Capella operation containers.
//!
//! Per `specs/capella/beacon-chain.md` (Containers section).
//!
//! New containers in Capella:
//! - `BLSToExecutionChange` — credential change request.
//! - `SignedBLSToExecutionChange` — signed wrapper.
//! - `HistoricalSummary` — replaces `historical_roots` append in Capella epochs.

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};

use crate::bellatrix::execution_payload::ExecutionAddress;
use crate::phase0::primitives::ValidatorIndex;

// ── BLSToExecutionChange ──────────────────────────────────────────────────────

/// Capella `BLSToExecutionChange` per `specs/capella/beacon-chain.md`.
///
/// Requests a change of a validator's withdrawal credential from BLS (0x00)
/// to an execution address (0x01).
///
/// The signing domain for this operation is fork-agnostic:
/// `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_FORK_VERSION, genesis_validators_root)`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BLSToExecutionChange {
    /// `validator_index: ValidatorIndex` — which validator is changing.
    pub validator_index: ValidatorIndex,
    /// `from_bls_pubkey: BLSPubkey` — the current BLS withdrawal pubkey (0x00 credential).
    pub from_bls_pubkey: BLSPubkey,
    /// `to_execution_address: ExecutionAddress` — target execution address (0x01 credential).
    pub to_execution_address: ExecutionAddress,
}

// ── SignedBLSToExecutionChange ────────────────────────────────────────────────

/// Capella `SignedBLSToExecutionChange` per `specs/capella/beacon-chain.md`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SignedBLSToExecutionChange {
    /// `message: BLSToExecutionChange`.
    pub message: BLSToExecutionChange,
    /// `signature: BLSSignature`.
    pub signature: BLSSignature,
}

// ── HistoricalSummary ─────────────────────────────────────────────────────────

/// Capella `HistoricalSummary` per `specs/capella/beacon-chain.md`.
///
/// Accumulates per-period block and state summary roots. Appended once per
/// `SLOTS_PER_HISTORICAL_ROOT` slots by `process_historical_summaries_update`,
/// which replaces the Phase 0 `process_historical_roots_update` in Capella.
/// `historical_roots` is retained but frozen (never appended) after the
/// Capella upgrade.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct HistoricalSummary {
    /// `block_summary_root: Root` — `hash_tree_root(state.block_roots)`.
    pub block_summary_root: Hash256,
    /// `state_summary_root: Root` — `hash_tree_root(state.state_roots)`.
    pub state_summary_root: Hash256,
}

#[cfg(test)]
mod tests {
    use pharos_ssz::{Decode, Encode};

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(val: T) {
        let encoded = val.as_ssz_bytes();
        let decoded = T::from_ssz_bytes(&encoded).expect("SSZ decode failed");
        assert_eq!(val, decoded);
    }

    #[test]
    fn bls_to_execution_change_roundtrip() {
        roundtrip(super::BLSToExecutionChange::default());
    }

    #[test]
    fn signed_bls_to_execution_change_roundtrip() {
        roundtrip(super::SignedBLSToExecutionChange::default());
    }

    #[test]
    fn historical_summary_roundtrip() {
        roundtrip(super::HistoricalSummary::default());
    }
}
