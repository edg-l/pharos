//! Slasher Phase A — in-memory attestation double-vote and surround-vote
//! detector.
//!
//! `AttestationSlasher` is fed every gossip-accepted `IndexedAttestation` (from
//! both the unaggregated and aggregate attestation accept paths).  It stores a
//! bounded per-validator window of `AttestRecord`s, one per target epoch, and
//! on each new observation checks for:
//!
//! - **Double vote**: a prior record with the SAME target epoch but a DIFFERENT
//!   `data_root` (`is_slashable_attestation_data` double-vote arm,
//!   `specs/phase0/beacon-chain.md:749-759`).
//! - **Surround vote**: a stored attestation that surrounds or is surrounded by
//!   the new one (`is_slashable_attestation_data` surround arm).
//!
//! On detection an `AttesterSlashing` is constructed and inserted into
//! `op_pools` so it will be included in the next produced block.  The
//! `pharos_slasher_detections_total` counter is also incremented (label `kind`
//! = `double_vote` | `surround_vote`).
//!
//! Memory is bounded by evicting records with
//! `target_epoch < current_epoch - HISTORY_EPOCHS`.
//!
//! # Crate-vs-module rationale
//!
//! Phase A is purely in-memory and has no external consumers outside
//! `pharos-node`; a separate crate would add a dependency edge for
//! node-internal functionality.  Phase B (chain-history replay, `--slasher`
//! flag) may be promoted to `crates/pharos-slasher` if it grows storage-heavy.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use pharos_ssz::SszList;
use pharos_types::EthSpec;
use pharos_types::phase0::misc::IndexedAttestation;
use pharos_types::phase0::operations::AttesterSlashing;
use pharos_types::phase0::primitives::ValidatorIndex;
use pharos_types::pools::OperationPools;

use pharos_utils::metrics::METRIC_SLASHER_DETECTIONS_TOTAL;

// ── constants ──────────────────────────────────────────────────────────────────

/// Number of epochs of attestation history retained per validator.
///
/// Records with `target_epoch < current_epoch - HISTORY_EPOCHS` are evicted on
/// each observation.  Small default (54 epochs ≈ ~6 hours on mainnet) keeps
/// the per-validator footprint bounded; Phase B stores the full history on disk.
pub const HISTORY_EPOCHS: u64 = 54;

// ── per-validator record ───────────────────────────────────────────────────────

/// One attestation record stored per `(validator_index, target_epoch)`.
///
/// Both fields are taken from `IndexedAttestation.data`.
#[derive(Clone, Debug)]
struct AttestRecord {
    source_epoch: u64,
    target_epoch: u64,
    /// `tree_hash_root()` of the full `AttestationData` — distinguishes double
    /// votes that share the same target epoch but differ in any other field.
    data_root: [u8; 32],
    /// The full `IndexedAttestation` is retained so we can construct a valid
    /// `AttesterSlashing` on detection.
    indexed: IndexedAttestation<2048>,
}

// ── AttestationSlasher ─────────────────────────────────────────────────────────

/// In-memory attestation slasher (Phase A).
///
/// `E` is needed only to bound `OperationPools<E>` so the pool insert call
/// compiles; the detection logic itself is fork-agnostic.
pub struct AttestationSlasher<E: EthSpec> {
    /// Per-validator attestation records: `validator_index → Vec<AttestRecord>`.
    ///
    /// Protected by a single `Mutex` (the detection path is not on the hot
    /// gossip-receive latency path; it runs after the gossip validator accepts).
    records: Mutex<HashMap<u64, Vec<AttestRecord>>>,
    /// Shared reference to the node's operation pools so detected slashings can
    /// be surfaced immediately for block inclusion.
    op_pools: Arc<OperationPools<E>>,
}

impl<E: EthSpec> AttestationSlasher<E> {
    /// Create a new `AttestationSlasher` backed by `op_pools`.
    pub fn new(op_pools: Arc<OperationPools<E>>) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            op_pools,
        }
    }

    /// Observe a gossip-accepted `IndexedAttestation`.
    ///
    /// Runs double-vote and surround-vote checks for each validator index in the
    /// attestation.  Detected slashings are inserted into `op_pools` and
    /// counted via the `pharos_slasher_detections_total` metric.
    ///
    /// `current_epoch` is the wall-clock epoch at observation time; it drives
    /// the eviction window.
    pub fn observe<const MAX: u64>(&self, indexed: &IndexedAttestation<MAX>, current_epoch: u64) {
        use pharos_ssz::TreeHash;

        let new_data = &indexed.data;
        let new_source = new_data.source.epoch.0;
        let new_target = new_data.target.epoch.0;
        let new_root: [u8; 32] = new_data.tree_hash_root().into_inner();

        // Repack into the canonical 2048-bound type used by AttesterSlashing.
        let new_indexed = repack_indexed(indexed);

        // Collect detections while holding the records lock, then release the
        // lock before calling op_pools (avoids lock-ordering issues).
        let detections: Vec<(IndexedAttestation<2048>, SlashKind)> = {
            let mut lock = self.records.lock();

            let mut found_list = Vec::new();

            for vi in indexed.attesting_indices.as_slice() {
                let validator = vi.0;
                let history = lock.entry(validator).or_default();

                // Evict records older than the window.
                let cutoff = current_epoch.saturating_sub(HISTORY_EPOCHS);
                history.retain(|r| r.target_epoch >= cutoff);

                // Scan existing records for slashable pairs.
                let mut detection: Option<(AttestRecord, SlashKind)> = None;
                for existing in history.iter() {
                    let kind = is_slashable_pair(existing, new_source, new_target, new_root);
                    if kind != SlashKind::None {
                        detection = Some((existing.clone(), kind));
                        break;
                    }
                }

                if let Some((prior, kind)) = detection {
                    found_list.push((prior.indexed.clone(), kind));
                }

                // Record this attestation if there is not already an identical entry.
                let already_stored = history
                    .iter()
                    .any(|r| r.target_epoch == new_target && r.data_root == new_root);
                if !already_stored {
                    history.push(AttestRecord {
                        source_epoch: new_source,
                        target_epoch: new_target,
                        data_root: new_root,
                        indexed: new_indexed.clone(),
                    });
                }
            }

            found_list
        }; // lock released here

        // Surface detections into op_pools outside the records lock.
        for (prior_indexed, kind) in detections {
            let slashing = AttesterSlashing {
                attestation_1: prior_indexed,
                attestation_2: new_indexed.clone(),
            };
            self.op_pools.insert_attester_slashing(slashing);
            emit_detection_metric(kind);
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

/// Detection outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlashKind {
    None,
    DoubleVote,
    SurroundVote,
}

/// Check whether an existing record and a new attestation form a slashable pair.
///
/// Mirrors `is_slashable_attestation_data` from
/// `specs/phase0/beacon-chain.md:749-759`:
///
/// ```text
/// (d1 != d2 && d1.target.epoch == d2.target.epoch)      // double vote
/// || (d1.source.epoch < d2.source.epoch                  // surround vote
///     && d2.target.epoch < d1.target.epoch)
/// ```
///
/// `d1` is the stored record; `d2` is the incoming attestation.
fn is_slashable_pair(
    existing: &AttestRecord,
    new_source: u64,
    new_target: u64,
    new_root: [u8; 32],
) -> SlashKind {
    // Double vote: same target epoch, different data.
    if existing.target_epoch == new_target && existing.data_root != new_root {
        return SlashKind::DoubleVote;
    }
    // Surround vote: existing surrounds new (e1.source < e2.source && e2.target < e1.target).
    if existing.source_epoch < new_source && new_target < existing.target_epoch {
        return SlashKind::SurroundVote;
    }
    // Surround vote: new surrounds existing (e2.source < e1.source && e1.target < e2.target).
    if new_source < existing.source_epoch && existing.target_epoch < new_target {
        return SlashKind::SurroundVote;
    }
    SlashKind::None
}

/// Repack a `IndexedAttestation<MAX>` into the canonical `IndexedAttestation<2048>`
/// used by `AttesterSlashing`.  Both presets use `MAX_VALIDATORS_PER_COMMITTEE =
/// 2048`, so this is a lossless re-encoding.
fn repack_indexed<const MAX: u64>(src: &IndexedAttestation<MAX>) -> IndexedAttestation<2048> {
    let items: Vec<ValidatorIndex> = src.attesting_indices.as_slice().to_vec();
    let list: SszList<ValidatorIndex, 2048> = SszList::from_items(items)
        .expect("attesting_indices length <= MAX_VALIDATORS_PER_COMMITTEE = 2048");
    IndexedAttestation {
        attesting_indices: list,
        data: src.data.clone(),
        signature: src.signature,
    }
}

/// Increment the `pharos_slasher_detections_total` counter.
fn emit_detection_metric(kind: SlashKind) {
    let kind_str = match kind {
        SlashKind::DoubleVote => "double_vote",
        SlashKind::SurroundVote => "surround_vote",
        SlashKind::None => return,
    };
    metrics::counter!(METRIC_SLASHER_DETECTIONS_TOTAL, "kind" => kind_str).increment(1);
}

// ── unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use pharos_ssz::SszList;
    use pharos_types::MinimalEthSpec;
    use pharos_types::phase0::misc::{AttestationData, Checkpoint, IndexedAttestation};
    use pharos_types::phase0::primitives::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};
    use pharos_utils::BLSSignature;

    type E = MinimalEthSpec;

    fn zero_sig() -> BLSSignature {
        BLSSignature::default()
    }

    fn make_att_data(source: u64, target: u64) -> AttestationData {
        AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(0),
            beacon_block_root: Root::default(),
            source: Checkpoint {
                epoch: Epoch(source),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(target),
                root: Root::default(),
            },
        }
    }

    fn make_att_data_distinct(source: u64, target: u64, block_root_byte: u8) -> AttestationData {
        AttestationData {
            slot: Slot(target * 8),
            index: CommitteeIndex(0),
            beacon_block_root: Root::from_array([block_root_byte; 32]),
            source: Checkpoint {
                epoch: Epoch(source),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(target),
                root: Root::default(),
            },
        }
    }

    fn make_indexed(data: AttestationData, validator: u64) -> IndexedAttestation<2048> {
        let list: SszList<ValidatorIndex, 2048> =
            SszList::from_items(vec![ValidatorIndex(validator)]).unwrap();
        IndexedAttestation {
            attesting_indices: list,
            data,
            signature: zero_sig(),
        }
    }

    fn new_slasher() -> AttestationSlasher<E> {
        AttestationSlasher::new(OperationPools::<E>::new())
    }

    // ── tests ──────────────────────────────────────────────────────────────────

    /// Two attestations by the same validator for the SAME target epoch but
    /// DIFFERENT data → exactly one double-vote slashing inserted into op_pools.
    #[test]
    fn double_vote_detected() {
        let slasher = new_slasher();

        let data_a = make_att_data_distinct(0, 5, 0xAA);
        let data_b = make_att_data_distinct(0, 5, 0xBB); // same target, different block root

        let idx_a = make_indexed(data_a, 42);
        let idx_b = make_indexed(data_b, 42); // same validator

        slasher.observe(&idx_a, 5);
        slasher.observe(&idx_b, 5);

        let slashings = slasher.op_pools.attester_slashings_snapshot();
        assert_eq!(
            slashings.len(),
            1,
            "expected exactly one double-vote slashing"
        );
    }

    /// An outer attestation [s1=1, t1=10] and an inner [s2=3, t2=7] by the
    /// same validator → exactly one surround-vote slashing in op_pools.
    #[test]
    fn surround_vote_detected() {
        let slasher = new_slasher();

        // Outer attestation: source=1, target=10
        let outer = make_indexed(make_att_data(1, 10), 7);
        // Inner attestation: source=3, target=7  (outer surrounds inner)
        let inner = make_indexed(make_att_data(3, 7), 7);

        slasher.observe(&outer, 10);
        slasher.observe(&inner, 10);

        let slashings = slasher.op_pools.attester_slashings_snapshot();
        assert_eq!(
            slashings.len(),
            1,
            "expected exactly one surround-vote slashing"
        );
    }

    /// Two attestations for DISTINCT target epochs with no surround relationship
    /// → no slashing.
    #[test]
    fn non_slashable_pair_ignored() {
        let slasher = new_slasher();

        let att1 = make_indexed(make_att_data(0, 3), 99);
        let att2 = make_indexed(make_att_data(4, 8), 99);

        slasher.observe(&att1, 8);
        slasher.observe(&att2, 8);

        let slashings = slasher.op_pools.attester_slashings_snapshot();
        assert_eq!(
            slashings.len(),
            0,
            "no slashing expected for non-slashable pair"
        );
    }

    /// Records with `target_epoch < current_epoch - HISTORY_EPOCHS` are evicted
    /// and do not trigger detection against future observations.
    #[test]
    fn eviction_drops_old_epochs() {
        let slasher = new_slasher();

        // Observe at epoch 0.
        let old_data = make_att_data_distinct(0, 1, 0x01);
        let old_idx = make_indexed(old_data, 55);
        slasher.observe(&old_idx, 0);

        // Advance current_epoch far enough to evict the old record.
        let far_epoch = HISTORY_EPOCHS + 2;

        // Now observe a double-vote candidate for the old target epoch.
        // The record should have been evicted, so no slashing.
        let new_data = make_att_data_distinct(0, 1, 0x02);
        let new_idx = make_indexed(new_data, 55);
        slasher.observe(&new_idx, far_epoch);

        let slashings = slasher.op_pools.attester_slashings_snapshot();
        assert_eq!(
            slashings.len(),
            0,
            "evicted record must not trigger detection"
        );
    }

    /// Verify the surround check in the reverse direction: new surrounds old.
    #[test]
    fn surround_vote_detected_reverse() {
        let slasher = new_slasher();

        // Inner (observed first): source=3, target=7
        let inner = make_indexed(make_att_data(3, 7), 7);
        // Outer (observed second): source=1, target=10  (new surrounds old)
        let outer = make_indexed(make_att_data(1, 10), 7);

        slasher.observe(&inner, 10);
        slasher.observe(&outer, 10);

        let slashings = slasher.op_pools.attester_slashings_snapshot();
        assert_eq!(
            slashings.len(),
            1,
            "expected exactly one surround-vote slashing (new surrounds old)"
        );
    }
}
