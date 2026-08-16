//! Slasher Phase B — proposer double-block detection.
//!
//! `ProposerSlasher` indexes one `SignedBeaconBlockHeader` per
//! `(slot, proposer_index, header_root)` in the on-disk `slasher-proposers`
//! column family. On each observation it prefix-scans the
//! `(slot, proposer_index)` bucket: if a previously stored header has a
//! DIFFERENT `message` root, the proposer signed two distinct blocks at the
//! same slot, which is the `ProposerSlashing` condition
//! (`specs/phase0/beacon-chain.md` `process_proposer_slashing`: two distinct
//! signed headers with the same `slot` and `proposer_index`).
//!
//! On detection a `ProposerSlashing` is constructed from the two headers,
//! inserted into `op_pools` so the next produced block includes it, and the
//! `pharos_slasher_detections_total{kind="proposer_double_block"}` counter is
//! incremented.
//!
//! Unlike the Phase A in-memory attestation slasher, the proposer index is
//! persisted: it is keyed in a RocksDB CF (`D-slasher-proposer-index-cf`) so it
//! survives across the whole replayed history without an unbounded in-memory
//! map. The CF is rebuilt from scratch on each `--slasher` replay.

use std::sync::Arc;

use pharos_ssz::TreeHash;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::BeaconSpec;
use pharos_types::phase0::operations::{ProposerSlashing, SignedBeaconBlockHeader};
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::pools::OperationPools;

use pharos_utils::metrics::METRIC_SLASHER_DETECTIONS_TOTAL;

/// Persistent proposer double-block slasher (Phase B).
///
/// `E` bounds `OperationPools<E>` and the `Store<E>` methods; the detection
/// logic itself is fork-agnostic (a `SignedBeaconBlockHeader` is identical
/// across forks).
pub struct ProposerSlasher<E: BeaconSpec> {
    /// Persistent block-header index (the `slasher-proposers` CF).
    store: Arc<RocksStore>,
    /// Shared operation pools so a detected `ProposerSlashing` is block-includable.
    op_pools: Arc<OperationPools<E>>,
}

impl<E: BeaconSpec> ProposerSlasher<E> {
    /// Create a new `ProposerSlasher` backed by `store` and `op_pools`.
    pub fn new(store: Arc<RocksStore>, op_pools: Arc<OperationPools<E>>) -> Self {
        Self { store, op_pools }
    }

    /// Observe one block header from the replayed history.
    ///
    /// Looks up every previously stored header for `(slot, proposer_index)`. If
    /// one has a different `message` root than `header`, the pair is a slashable
    /// proposer double-block: a `ProposerSlashing` is inserted into `op_pools`
    /// and the detection metric is incremented. Then `header` is recorded so a
    /// later sibling can be matched against it.
    ///
    /// Idempotent for an identical header: re-observing the same `(slot,
    /// proposer, header_root)` overwrites its own row and never self-matches
    /// (the equal-root entry is skipped in the scan).
    pub fn observe(&self, header: &SignedBeaconBlockHeader) -> Result<(), ProposerSlasherError> {
        let slot = header.message.slot;
        let proposer = header.message.proposer_index.0;
        let header_root: Root = header.message.tree_hash_root();

        // Scan existing headers for this (slot, proposer). A stored header with a
        // different message root is a double-block.
        let existing =
            <RocksStore as DbStore<E>>::slasher_proposer_headers_at(&self.store, slot, proposer)?;

        let mut detected: Option<SignedBeaconBlockHeader> = None;
        for prior in &existing {
            let prior_root: Root = prior.message.tree_hash_root();
            if prior_root != header_root {
                detected = Some(prior.clone());
                break;
            }
        }

        if let Some(prior) = detected {
            let slashing = ProposerSlashing {
                signed_header_1: prior,
                signed_header_2: header.clone(),
            };
            self.op_pools.insert_proposer_slashing(slashing);
            metrics::counter!(METRIC_SLASHER_DETECTIONS_TOTAL, "kind" => "proposer_double_block")
                .increment(1);
        }

        // Record this header so future observations can match against it.
        <RocksStore as DbStore<E>>::put_slasher_proposer_header(
            &self.store,
            slot,
            proposer,
            header_root,
            header,
        )?;

        Ok(())
    }
}

/// Build a `SignedBeaconBlockHeader` from a block's header fields.
///
/// Mirrors `signed_block_header` in `block_production.rs`: the `body_root` is
/// the `tree_hash_root()` of the block body. The replay scanner uses this to
/// turn each stored signed block into the header the proposer index needs.
pub fn header_from_parts(
    slot: Slot,
    proposer_index: u64,
    parent_root: Root,
    state_root: Root,
    body_root: Root,
    signature: pharos_utils::BLSSignature,
) -> SignedBeaconBlockHeader {
    use pharos_types::phase0::operations::BeaconBlockHeader;
    use pharos_types::phase0::primitives::ValidatorIndex;
    SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot,
            proposer_index: ValidatorIndex(proposer_index),
            parent_root,
            state_root,
            body_root,
        },
        signature,
    }
}

/// Errors from the proposer slasher.
#[derive(Debug, thiserror::Error)]
pub enum ProposerSlasherError {
    /// A storage read/write of the proposer index failed.
    #[error("slasher proposer-index storage error: {0}")]
    Storage(#[from] pharos_storage::StorageError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use pharos_storage::{RocksStore, RocksStoreConfig};
    use pharos_types::MinimalBeaconSpec;
    use pharos_types::phase0::operations::BeaconBlockHeader;
    use pharos_types::phase0::primitives::ValidatorIndex;
    use pharos_utils::BLSSignature;

    type E = MinimalBeaconSpec;

    fn temp_store() -> Arc<RocksStore> {
        let dir = std::env::temp_dir().join(format!(
            "pharos-proposer-slasher-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        Arc::new(
            RocksStore::open::<E>(RocksStoreConfig {
                path: dir,
                create_if_missing: true,
            })
            .expect("open temp store"),
        )
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn header(slot: u64, proposer: u64, body_byte: u8) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: Slot(slot),
                proposer_index: ValidatorIndex(proposer),
                parent_root: Root::default(),
                state_root: Root::default(),
                body_root: Root::from_array([body_byte; 32]),
            },
            signature: BLSSignature::default(),
        }
    }

    /// Two distinct headers (same slot + proposer, different body root) → exactly
    /// one proposer slashing in op_pools.
    #[test]
    fn proposer_double_block_detected() {
        let store = temp_store();
        let pools = OperationPools::<E>::new();
        let slasher = ProposerSlasher::<E>::new(store, Arc::clone(&pools));

        slasher.observe(&header(10, 3, 0xAA)).unwrap();
        slasher.observe(&header(10, 3, 0xBB)).unwrap();

        let slashings = pools.proposer_slashings_snapshot();
        assert_eq!(slashings.len(), 1, "expected one proposer double-block");
        assert_eq!(slashings[0].signed_header_1.message.slot, Slot(10));
        assert_eq!(slashings[0].signed_header_2.message.slot, Slot(10));
    }

    /// Re-observing the identical header is idempotent: no self-slashing.
    #[test]
    fn identical_header_not_slashed() {
        let store = temp_store();
        let pools = OperationPools::<E>::new();
        let slasher = ProposerSlasher::<E>::new(store, Arc::clone(&pools));

        let h = header(7, 1, 0x11);
        slasher.observe(&h).unwrap();
        slasher.observe(&h).unwrap();

        assert_eq!(
            pools.proposer_slashings_snapshot().len(),
            0,
            "identical header must not self-slash"
        );
    }

    /// Distinct slots or proposers never collide.
    #[test]
    fn distinct_slot_or_proposer_not_slashed() {
        let store = temp_store();
        let pools = OperationPools::<E>::new();
        let slasher = ProposerSlasher::<E>::new(store, Arc::clone(&pools));

        slasher.observe(&header(1, 0, 0x01)).unwrap();
        slasher.observe(&header(2, 0, 0x02)).unwrap(); // different slot
        slasher.observe(&header(1, 1, 0x03)).unwrap(); // different proposer

        assert_eq!(pools.proposer_slashings_snapshot().len(), 0);
    }
}
