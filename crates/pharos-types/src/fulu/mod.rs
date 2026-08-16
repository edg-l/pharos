//! Fulu fork types.
//!
//! Per `specs/fulu/beacon-chain.md`, `specs/fulu/das-core.md`,
//! `specs/fulu/p2p-interface.md`, and `specs/fulu/partial-columns/p2p-interface.md`.
//!
//! Fulu (EIP-7594 PeerDAS + EIP-7917 deterministic proposer lookahead +
//! EIP-7892 blob-parameter-only forks) reshapes only `BeaconState` (adds
//! `proposer_lookahead`) and introduces new DAS containers. All other
//! containers (block, body, execution payload, light-client, requests,
//! attestation) are structurally identical to electra and re-exported.
//!
//! ## `BlobParameters` + `get_blob_parameters` (EIP-7892)
//!
//! Fulu's max-blobs-per-block is entirely epoch-driven via `get_blob_parameters`
//! walking `BLOB_SCHEDULE`. There is NO `MAX_BLOBS_PER_BLOCK_FULU` const; the
//! fallback is `MAX_BLOBS_PER_BLOCK_ELECTRA = 9` (from M12). The SSZ list bound
//! for `blob_kzg_commitments` remains `MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096`.

pub mod attestation;
pub mod block;
pub mod body;
pub mod das_identifier;
pub mod data_column_sidecar;
pub mod execution_payload;
pub mod light_client;
pub mod matrix;
pub mod partial_column;
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
pub use das_identifier::{
    DataColumnsByRootIdentifier, MainnetDataColumnsByRootIdentifier,
    MinimalDataColumnsByRootIdentifier,
};
pub use data_column_sidecar::{
    BYTES_PER_CELL, Cell, ColumnIndex, CustodyIndex, DataColumnSidecar, DataColumnSidecarView,
    MainnetDataColumnSidecar, MinimalDataColumnSidecar, RowIndex,
};
pub use execution_payload::{
    ExecutionPayload, ExecutionPayloadHeader, MainnetExecutionPayload,
    MainnetExecutionPayloadHeader, MinimalExecutionPayload, MinimalExecutionPayloadHeader,
    Transaction, Withdrawal,
};
pub use light_client::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate, MainnetLightClientBootstrap,
    MainnetLightClientFinalityUpdate, MainnetLightClientHeader, MainnetLightClientOptimisticUpdate,
    MainnetLightClientUpdate, MinimalLightClientBootstrap, MinimalLightClientFinalityUpdate,
    MinimalLightClientHeader, MinimalLightClientOptimisticUpdate, MinimalLightClientUpdate,
};
pub use matrix::MatrixEntry;
pub use partial_column::{
    MainnetPartialDataColumnHeader, MainnetPartialDataColumnPartsMetadata,
    MainnetPartialDataColumnSidecar, MinimalPartialDataColumnHeader,
    MinimalPartialDataColumnPartsMetadata, MinimalPartialDataColumnSidecar,
    PartialDataColumnHeader, PartialDataColumnPartsMetadata, PartialDataColumnSidecar,
};
pub use requests::{
    ConsolidationRequest, DepositRequest, ExecutionRequests, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, WithdrawalRequest,
};
pub use state::{BeaconState, MainnetBeaconState, MinimalBeaconState};

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_utils::Epoch;

// ── BlobScheduleEntry ─────────────────────────────────────────────────────────

/// One entry in the EIP-7892 `BLOB_SCHEDULE` config list.
///
/// Per `specs/fulu/beacon-chain.md` (Configuration → Blob schedule). The
/// schedule defines the maximum blobs per block limit for a given epoch.
/// There MUST NOT exist multiple entries with the same epoch value. The epoch
/// value in each entry MUST be greater than or equal to `FULU_FORK_EPOCH`. The
/// maximum blobs per block limit in each entry MUST be less than or equal to
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK`. The schedule MAY be empty.
///
/// Stored in `RuntimeConfig::blob_schedule` and walked by `get_blob_parameters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobScheduleEntry {
    /// `EPOCH` — the epoch at which this entry activates.
    pub epoch: u64,
    /// `MAX_BLOBS_PER_BLOCK` — the max blobs per block at and after `epoch`.
    pub max_blobs_per_block: u64,
}

// ── BlobParameters ────────────────────────────────────────────────────────────

/// `BlobParameters` per `specs/fulu/beacon-chain.md` (New `BlobParameters`).
///
/// SSZ container with two scalar fields. Used by `get_blob_parameters` to
/// return the blob parameters at a given epoch. The SSZ derive is for the
/// `ssz_static` conformance runner ONLY; the fork-digest computation uses
/// `hash()` of the concatenated little-endian u64 bytes, NOT the SSZ
/// `hash_tree_root()` (the two produce different bytes; see
/// `compute_fork_digest_fulu` in `crate::fork`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BlobParameters {
    /// `epoch: Epoch`.
    pub epoch: Epoch,
    /// `max_blobs_per_block: uint64`.
    pub max_blobs_per_block: u64,
}

// ── get_blob_parameters ───────────────────────────────────────────────────────

/// `get_blob_parameters(epoch, blob_schedule, electra_fork_epoch,
/// max_blobs_per_block_electra)` per `specs/fulu/beacon-chain.md`.
///
/// Walks `blob_schedule` reverse-sorted by epoch and returns the first entry
/// with `epoch <= given_epoch`. Falls back to
/// `(ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK_ELECTRA)` if no entry matches.
///
/// This is the runtime-driven source of truth for the max-blobs-per-block
/// limit in Fulu (EIP-7892). There is NO `MAX_BLOBS_PER_BLOCK_FULU` const.
pub fn get_blob_parameters(
    epoch: Epoch,
    blob_schedule: &[BlobScheduleEntry],
    electra_fork_epoch: Epoch,
    max_blobs_per_block_electra: u64,
) -> BlobParameters {
    // Spec sorts BLOB_SCHEDULE by epoch (reverse) and takes the first entry with
    // entry.EPOCH <= epoch. We do not assume the input is ordered: select the
    // entry with the largest epoch that is still <= the given epoch. Falls back
    // to (ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK_ELECTRA) when none matches.
    blob_schedule
        .iter()
        .filter(|entry| epoch.0 >= entry.epoch)
        .max_by_key(|entry| entry.epoch)
        .map(|entry| BlobParameters {
            epoch: Epoch(entry.epoch),
            max_blobs_per_block: entry.max_blobs_per_block,
        })
        .unwrap_or(BlobParameters {
            epoch: electra_fork_epoch,
            max_blobs_per_block: max_blobs_per_block_electra,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_blob_parameters_fallback_when_schedule_empty() {
        let electra_epoch = Epoch(364_032);
        let params = get_blob_parameters(Epoch(500_000), &[], electra_epoch, 9);
        assert_eq!(params.epoch, electra_epoch);
        assert_eq!(params.max_blobs_per_block, 9);
    }

    #[test]
    fn get_blob_parameters_hits_schedule_entry() {
        let electra_epoch = Epoch(364_032);
        // Ascending schedule (SHOULD order per spec).
        let schedule = [
            BlobScheduleEntry {
                epoch: 412_672,
                max_blobs_per_block: 15,
            },
            BlobScheduleEntry {
                epoch: 419_072,
                max_blobs_per_block: 21,
            },
        ];
        // Before the first entry → fallback.
        let p0 = get_blob_parameters(Epoch(411_392), &schedule, electra_epoch, 9);
        assert_eq!(p0.epoch, electra_epoch);
        assert_eq!(p0.max_blobs_per_block, 9);
        // At/after the first entry, before the second → first entry.
        let p1 = get_blob_parameters(Epoch(412_672), &schedule, electra_epoch, 9);
        assert_eq!(p1.epoch, Epoch(412_672));
        assert_eq!(p1.max_blobs_per_block, 15);
        let p1b = get_blob_parameters(Epoch(415_000), &schedule, electra_epoch, 9);
        assert_eq!(p1b.epoch, Epoch(412_672));
        assert_eq!(p1b.max_blobs_per_block, 15);
        // At/after the second entry → second entry.
        let p2 = get_blob_parameters(Epoch(419_072), &schedule, electra_epoch, 9);
        assert_eq!(p2.epoch, Epoch(419_072));
        assert_eq!(p2.max_blobs_per_block, 21);
        let p2b = get_blob_parameters(Epoch(1_000_000), &schedule, electra_epoch, 9);
        assert_eq!(p2b.epoch, Epoch(419_072));
        assert_eq!(p2b.max_blobs_per_block, 21);
    }
}
