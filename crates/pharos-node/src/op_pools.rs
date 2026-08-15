//! In-memory operation pools for the beacon node.
//!
//! `OperationPools<E>` collects gossip-validated operations before they are
//! drained into a produced `BeaconBlock`. Each map is independently locked via
//! `parking_lot::RwLock` so different operation types can be inserted
//! concurrently without contending on a single pool-level lock.
//!
//! # Attestation aggregation
//!
//! On `insert_attestation` the pool attempts to merge the incoming attestation
//! with any existing pooled attestation for the same `AttestationData`. Merging
//! is only performed when the bits are disjoint; overlapping attestations are
//! stored under a distinct subkey so correctness is preserved (an aggregate
//! with overlapping bits has an invalid BLS signature).
//!
//! # Sync messages
//!
//! `insert_sync_message` stores `SyncCommitteeMessage` values keyed by
//! `(slot, subcommittee_index, beacon_block_root)`.
//! `drain_sync_aggregate` merges participation bits across all stored messages
//! and aggregates their BLS signatures into a `SyncAggregate`.
//!
//! # Eviction
//!
//! Every map is capped at `MAX_POOL_ENTRIES`. When the cap is reached the
//! oldest-inserted entry is evicted (via `lru::LruCache`).
//!
//! # D-no-deposit-source
//!
//! Deposits are NOT pooled. The produced block's `deposits` list is derived
//! from `eth1_data.deposit_count - eth1_deposit_index` at block-production
//! time, but Pharos has no eth1 deposit-following subsystem (genesis-funded
//! devnet validators). Until M11 adds deposit-following, `BlockOperations`
//! always carries an empty deposits list.

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::RwLock;

use pharos_ssz::Bitvector;
use pharos_types::EthSpec;
use pharos_types::altair::{SyncAggregate, SyncCommitteeMessage};
use pharos_types::capella::operations::SignedBLSToExecutionChange;
use pharos_types::phase0::operations::{
    Attestation, AttesterSlashing, ProposerSlashing, SignedVoluntaryExit,
};
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_utils::BLSSignature;
use pharos_utils::bls::aggregate;

// ── constants ──────────────────────────────────────────────────────────────────

/// Maximum number of entries in each individual pool map before the oldest
/// entry is evicted.
pub const MAX_POOL_ENTRIES: usize = 16384;

// Mainnet and minimal both use 2048 for MAX_VALIDATORS_PER_COMMITTEE.
// Using the concrete literal avoids the stable-Rust limitation that prevents
// `E::ASSOCIATED_CONST` in const-generic positions.
const VALIDATORS_PER_COMMITTEE: u64 = 2048;

// ── attestation pool key ───────────────────────────────────────────────────────

/// Primary key for the attestation pool.
///
/// `att_data_root` is `AttestationData::tree_hash_root()`, encoding
/// slot, committee index, beacon_block_root, source, and target.
/// `subkey` is a monotone counter that differentiates multiple attestations
/// sharing the same `AttestationData` but with overlapping aggregation bits
/// (which cannot be safely merged). Disjoint-bit attestations are merged
/// in-place and kept at `subkey == 0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AttKey {
    att_data_root: Root,
    subkey: u32,
}

impl AttKey {
    fn primary(root: Root) -> Self {
        Self {
            att_data_root: root,
            subkey: 0,
        }
    }

    fn with_subkey(root: Root, subkey: u32) -> Self {
        Self {
            att_data_root: root,
            subkey,
        }
    }
}

/// Lowest unused subkey (≥ 1) for `data_root` in the attestation cache.
///
/// Scoped to a single data root, unlike `cache.len()` which counts entries
/// across all data roots and can therefore collide with an existing subkey.
fn next_free_subkey(
    cache: &LruCache<AttKey, Attestation<VALIDATORS_PER_COMMITTEE>>,
    data_root: Root,
) -> u32 {
    (1u32..)
        .find(|sk| !cache.contains(&AttKey::with_subkey(data_root, *sk)))
        .expect("u32 subkey space exhausted before pool cap (16384)")
}

// ── sync message pool key ──────────────────────────────────────────────────────

/// Key for the `sync_messages` map.
///
/// One entry per `(slot, subcommittee_index, beacon_block_root)` triple holds
/// the list of individual sync committee messages for that combination.
/// A single slot typically produces 4 subcommittee buckets (mainnet).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyncMessageKey {
    pub slot: Slot,
    pub subcommittee_index: u64,
    pub beacon_block_root: Root,
}

// ── BlockOperations ────────────────────────────────────────────────────────────

/// Assembled operations ready to be placed into a produced `BeaconBlock`.
///
/// Each list is capped at the corresponding `EthSpec` `MAX_*` constant by
/// `drain_for_block`. Deposits are always empty — see `D-no-deposit-source`.
///
/// The concrete literal `VALIDATORS_PER_COMMITTEE = 2048` is used for the
/// generic const parameters on `Attestation` and `AttesterSlashing` because
/// stable Rust does not allow `E::MAX_VALIDATORS_PER_COMMITTEE` in a
/// const-generic position. Both mainnet and minimal define this constant as 2048.
#[derive(Default)]
pub struct BlockOperations {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub attester_slashings: Vec<AttesterSlashing<VALIDATORS_PER_COMMITTEE>>,
    pub attestations: Vec<Attestation<VALIDATORS_PER_COMMITTEE>>,
    /// Always empty. Pharos has no eth1 deposit-following subsystem
    /// (`D-no-deposit-source`). The deposit count is available as
    /// `eth1_data.deposit_count - eth1_deposit_index` but without a deposit
    /// source the actual deposit objects cannot be produced here.
    pub deposits: Vec<()>,
    pub voluntary_exits: Vec<SignedVoluntaryExit>,
    pub bls_to_execution_changes: Vec<SignedBLSToExecutionChange>,
}

// ── OperationPools ─────────────────────────────────────────────────────────────

/// Shared in-memory operation pool for a running beacon node.
///
/// Each map is independently locked so concurrent inserts across different
/// operation types do not block one another.
///
/// Shared as `Arc<OperationPools>` by all consumers (gossip-validator path,
/// block-production) so the pool lives for the node lifetime.
///
/// The struct is generic over `E: EthSpec` so that `drain_for_block` can
/// read the spec-level `MAX_*` caps from the preset. The concrete per-entry
/// types use the literal `2048` (which equals `MAX_VALIDATORS_PER_COMMITTEE`
/// for all presets) to avoid stable Rust const-generic expression limits.
pub struct OperationPools<E: EthSpec> {
    /// Aggregated attestations.
    ///
    /// Key: `AttKey { att_data_root, subkey }`.
    /// Value: `Attestation<2048>`.
    ///
    /// Disjoint-bit attestations sharing `AttestationData` are merged at
    /// `subkey = 0`. Overlapping attestations are stored with a distinct
    /// `subkey` to preserve correctness.
    attestations: RwLock<LruCache<AttKey, Attestation<VALIDATORS_PER_COMMITTEE>>>,

    /// Attester slashings.
    ///
    /// Keyed by a compact u128 derived from the intersection of the two
    /// attesting-indices sets (see `attester_slashing_key`).
    attester_slashings: RwLock<LruCache<u128, AttesterSlashing<VALIDATORS_PER_COMMITTEE>>>,

    /// Proposer slashings, keyed by proposer index.
    proposer_slashings: RwLock<LruCache<u64, ProposerSlashing>>,

    /// Voluntary exits, keyed by validator index.
    voluntary_exits: RwLock<LruCache<u64, SignedVoluntaryExit>>,

    /// BLS-to-execution-credential changes, keyed by validator index.
    bls_to_execution_changes: RwLock<LruCache<u64, SignedBLSToExecutionChange>>,

    /// Sync committee messages.
    ///
    /// Keyed by `(slot, subcommittee_index, beacon_block_root)`.
    /// Value: a `Vec` of `SyncCommitteeMessage`.
    ///
    /// An `LruCache` of `Vec`s is used because multiple validators contribute
    /// per slot; each `Vec` entry is one validator's contribution.
    sync_messages: RwLock<LruCache<SyncMessageKey, Vec<SyncCommitteeMessage>>>,

    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> OperationPools<E> {
    /// Construct a new empty pool with `MAX_POOL_ENTRIES` capacity per map.
    pub fn new() -> Arc<Self> {
        let cap = NonZeroUsize::new(MAX_POOL_ENTRIES).unwrap();
        Arc::new(Self {
            attestations: RwLock::new(LruCache::new(cap)),
            attester_slashings: RwLock::new(LruCache::new(cap)),
            proposer_slashings: RwLock::new(LruCache::new(cap)),
            voluntary_exits: RwLock::new(LruCache::new(cap)),
            bls_to_execution_changes: RwLock::new(LruCache::new(cap)),
            sync_messages: RwLock::new(LruCache::new(cap)),
            _phantom: std::marker::PhantomData,
        })
    }

    // ── insert helpers ────────────────────────────────────────────────────────

    /// Insert an attestation into the pool.
    ///
    /// If a pooled attestation exists for the same `AttestationData` AND
    /// the aggregation bits are disjoint, the bits are merged and signatures
    /// are aggregated via `pharos_utils::bls::aggregate`. Otherwise, the
    /// incoming attestation is stored under a new subkey.
    ///
    /// Capacity is `MAX_POOL_ENTRIES`; once reached, the LRU entry is evicted.
    pub fn insert_attestation(&self, att: Attestation<VALIDATORS_PER_COMMITTEE>) {
        use pharos_ssz::TreeHash;

        let data_root = att.data.tree_hash_root();
        let primary_key = AttKey::primary(data_root);

        let mut cache = self.attestations.write();

        // Attempt merge with the existing entry at the primary subkey.
        if let Some(existing) = cache.peek(&primary_key) {
            let bits_disjoint = existing
                .aggregation_bits
                .iter()
                .zip(att.aggregation_bits.iter())
                .all(|(a, b)| !(a && b));

            if bits_disjoint {
                // Merge: combine bits and aggregate BLS signatures.
                let mut merged = existing.clone();
                for (i, bit) in att.aggregation_bits.iter().enumerate() {
                    if bit {
                        merged.aggregation_bits.set(i, true);
                    }
                }
                match aggregate(&[existing.signature, att.signature]) {
                    Ok(agg_sig) => merged.signature = agg_sig,
                    Err(_) => {
                        // Aggregation failed; store separately rather than discard.
                        // Use the per-data-root subkey scan, NOT cache.len() (which
                        // counts every data root's entries and can collide).
                        let subkey = next_free_subkey(&cache, data_root);
                        cache.put(AttKey::with_subkey(data_root, subkey), att);
                        return;
                    }
                }
                cache.put(primary_key, merged);
                return;
            }
        }

        // No existing entry or bits overlap: store separately.
        if cache.peek(&primary_key).is_none() {
            cache.put(primary_key, att);
        } else {
            let subkey = next_free_subkey(&cache, data_root);
            cache.put(AttKey::with_subkey(data_root, subkey), att);
        }
    }

    /// Insert an attester slashing into the pool.
    ///
    /// Duplicate (already-pooled) entries are silently ignored.
    pub fn insert_attester_slashing(&self, slashing: AttesterSlashing<VALIDATORS_PER_COMMITTEE>) {
        let key = attester_slashing_key(&slashing);
        let mut cache = self.attester_slashings.write();
        if cache.peek(&key).is_none() {
            cache.put(key, slashing);
        }
    }

    /// Insert a proposer slashing into the pool, keyed by proposer index.
    pub fn insert_proposer_slashing(&self, slashing: ProposerSlashing) {
        let proposer = slashing.signed_header_1.message.proposer_index.0;
        let mut cache = self.proposer_slashings.write();
        if cache.peek(&proposer).is_none() {
            cache.put(proposer, slashing);
        }
    }

    /// Insert a voluntary exit into the pool, keyed by validator index.
    pub fn insert_voluntary_exit(&self, exit: SignedVoluntaryExit) {
        let idx = exit.message.validator_index.0;
        let mut cache = self.voluntary_exits.write();
        if cache.peek(&idx).is_none() {
            cache.put(idx, exit);
        }
    }

    /// Insert a BLS-to-execution change into the pool, keyed by validator index.
    pub fn insert_bls_to_execution_change(&self, change: SignedBLSToExecutionChange) {
        let idx = change.message.validator_index.0;
        let mut cache = self.bls_to_execution_changes.write();
        if cache.peek(&idx).is_none() {
            cache.put(idx, change);
        }
    }

    /// Insert a sync committee message into the pool.
    ///
    /// The message is grouped by `(slot, subcommittee_index, beacon_block_root)`.
    /// Each validator's message is stored once; duplicates (same
    /// `validator_index`) are overwritten with the latest message.
    ///
    /// `subcommittee_index` is the subcommittee (0..SYNC_COMMITTEE_SUBNET_COUNT)
    /// the validator belongs to for this slot.
    pub fn insert_sync_message(&self, msg: SyncCommitteeMessage, subcommittee_index: u64) {
        let key = SyncMessageKey {
            slot: msg.slot,
            subcommittee_index,
            beacon_block_root: msg.beacon_block_root,
        };
        let mut cache = self.sync_messages.write();
        let entry = cache.get_or_insert_mut(key, Vec::new);
        let val_idx = msg.validator_index;
        if let Some(existing) = entry.iter_mut().find(|m| m.validator_index == val_idx) {
            *existing = msg;
        } else {
            entry.push(msg);
        }
    }

    // ── drain helpers ─────────────────────────────────────────────────────────

    /// Drain all pooled operations, returning them capped at their respective
    /// `EthSpec` `MAX_*` constants.
    ///
    /// `deposits` is always empty — see `D-no-deposit-source`.
    pub fn drain_for_block(&self, _slot: u64) -> BlockOperations {
        let max_proposer = E::MAX_PROPOSER_SLASHINGS as usize;
        let max_attester = E::MAX_ATTESTER_SLASHINGS as usize;
        let max_att = E::MAX_ATTESTATIONS as usize;
        let max_exits = E::MAX_VOLUNTARY_EXITS as usize;
        let max_bls = E::MAX_BLS_TO_EXECUTION_CHANGES as usize;

        let proposer_slashings: Vec<_> = {
            let mut cache = self.proposer_slashings.write();
            let keys: Vec<_> = cache.iter().take(max_proposer).map(|(k, _)| *k).collect();
            keys.into_iter().filter_map(|k| cache.pop(&k)).collect()
        };

        let attester_slashings: Vec<_> = {
            let mut cache = self.attester_slashings.write();
            let keys: Vec<_> = cache.iter().take(max_attester).map(|(k, _)| *k).collect();
            keys.into_iter().filter_map(|k| cache.pop(&k)).collect()
        };

        let attestations: Vec<_> = {
            let mut cache = self.attestations.write();
            let keys: Vec<_> = cache.iter().take(max_att).map(|(k, _)| k.clone()).collect();
            keys.into_iter().filter_map(|k| cache.pop(&k)).collect()
        };

        let voluntary_exits: Vec<_> = {
            let mut cache = self.voluntary_exits.write();
            let keys: Vec<_> = cache.iter().take(max_exits).map(|(k, _)| *k).collect();
            keys.into_iter().filter_map(|k| cache.pop(&k)).collect()
        };

        let bls_to_execution_changes: Vec<_> = {
            let mut cache = self.bls_to_execution_changes.write();
            let keys: Vec<_> = cache.iter().take(max_bls).map(|(k, _)| *k).collect();
            keys.into_iter().filter_map(|k| cache.pop(&k)).collect()
        };

        BlockOperations {
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits: Vec::new(),
            voluntary_exits,
            bls_to_execution_changes,
        }
    }

    /// Build a `SyncAggregate` for the given `(slot, beacon_block_root)` from
    /// pooled sync committee messages.
    ///
    /// Merges participation bits across all subcommittees and aggregates their
    /// BLS signatures. When no messages are pooled for this slot+block_root,
    /// returns an empty (zero-participation) `SyncAggregate` — this is
    /// spec-valid (a block with no sync committee participation).
    ///
    /// The flat index in `sync_committee_bits` is:
    ///   `global = subcommittee_index * SYNC_SUBCOMMITTEE_SIZE + position`
    ///
    /// KNOWN-INCOMPLETE (M9 Phase 2): `position` is currently the pool
    /// *insertion order* within the subcommittee, NOT the validator's true
    /// offset in `state.current_sync_committee.pubkeys`. The two coincide only
    /// when every committee member contributes in committee order, so a block
    /// built from this aggregate will generally FAIL `process_sync_aggregate`
    /// verification. The correct position must be derived from the ordered
    /// committee pubkeys, which are only available at block-assembly time.
    /// Phase 4 (`produce_block`) MUST pass the committee in and compute real
    /// positions before this is wired into live production. Until then callers
    /// get a structurally-valid but semantically-placeholder aggregate.
    pub fn drain_sync_aggregate<const SYNC_COMMITTEE_SIZE: u64>(
        &self,
        slot: Slot,
        block_root: Root,
    ) -> SyncAggregate<SYNC_COMMITTEE_SIZE> {
        let subcommittee_size = E::SYNC_SUBCOMMITTEE_SIZE as usize;
        let mut bits: Bitvector<SYNC_COMMITTEE_SIZE> = Bitvector::default();
        let mut sigs: Vec<BLSSignature> = Vec::new();

        let mut cache = self.sync_messages.write();

        for subc_idx in 0..E::SYNC_COMMITTEE_SUBNET_COUNT {
            let key = SyncMessageKey {
                slot,
                subcommittee_index: subc_idx,
                beacon_block_root: block_root,
            };
            if let Some(msgs) = cache.pop(&key) {
                // FIXME(M9 Phase 4): `pos` is insertion order, not committee
                // offset — see the doc comment. Wrong bits on mainnet.
                for (pos, msg) in msgs.iter().enumerate() {
                    let global = subc_idx as usize * subcommittee_size + pos;
                    if (global as u64) < SYNC_COMMITTEE_SIZE {
                        bits.set(global, true);
                        sigs.push(msg.signature);
                    }
                }
            }
        }

        let sync_committee_signature = if sigs.is_empty() {
            BLSSignature::default()
        } else {
            aggregate(&sigs).unwrap_or_default()
        };

        SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature,
        }
    }
}

impl<E: EthSpec> Default for OperationPools<E> {
    fn default() -> Self {
        let cap = NonZeroUsize::new(MAX_POOL_ENTRIES).unwrap();
        Self {
            attestations: RwLock::new(LruCache::new(cap)),
            attester_slashings: RwLock::new(LruCache::new(cap)),
            proposer_slashings: RwLock::new(LruCache::new(cap)),
            voluntary_exits: RwLock::new(LruCache::new(cap)),
            bls_to_execution_changes: RwLock::new(LruCache::new(cap)),
            sync_messages: RwLock::new(LruCache::new(cap)),
            _phantom: std::marker::PhantomData,
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

/// Compute a stable dedup key for an attester slashing from the intersection
/// of the two attesting-indices sets.
///
/// Encodes the two smallest intersecting indices as a `u128`:
///   `low as u128 | (high as u128 << 64)`
///
/// With fewer than two intersecting indices, falls back to XOR-encoding the
/// full index sets to still produce a stable key.
fn attester_slashing_key(slashing: &AttesterSlashing<VALIDATORS_PER_COMMITTEE>) -> u128 {
    use std::collections::BTreeSet;

    let set1: BTreeSet<u64> = slashing
        .attestation_1
        .attesting_indices
        .as_slice()
        .iter()
        .map(|v| v.0)
        .collect();
    let set2: BTreeSet<u64> = slashing
        .attestation_2
        .attesting_indices
        .as_slice()
        .iter()
        .map(|v| v.0)
        .collect();

    let mut intersection: Vec<u64> = set1.intersection(&set2).copied().collect();
    intersection.sort_unstable();

    match intersection.as_slice() {
        [] => {
            let xor_a: u64 = set1.iter().copied().fold(0, |a, b| a ^ b);
            let xor_b: u64 = set2.iter().copied().fold(0, |a, b| a ^ b);
            (xor_a as u128) | ((xor_b as u128) << 64)
        }
        [a] => *a as u128,
        [a, b, ..] => (*a as u128) | ((*b as u128) << 64),
    }
}

// ── unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use std::num::NonZeroUsize;

    use pharos_ssz::Bitlist;
    use pharos_types::phase0::misc::{AttestationData, Checkpoint};
    use pharos_types::phase0::operations::VoluntaryExit;
    use pharos_types::phase0::primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex};
    use pharos_types::{EthSpec, MinimalEthSpec};
    use pharos_utils::BLSSignature;
    use pharos_utils::bls::{BLSSecretKey, aggregate as bls_aggregate};

    type E = MinimalEthSpec;
    type Att = Attestation<VALIDATORS_PER_COMMITTEE>;

    fn make_att_data(slot: u64, index: u64) -> AttestationData {
        AttestationData {
            slot: Slot(slot),
            index: CommitteeIndex(index),
            beacon_block_root: Root::default(),
            source: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
            target: Checkpoint {
                epoch: Epoch(0),
                root: Root::default(),
            },
        }
    }

    fn make_att_one_bit(slot: u64, index: u64, bit: usize, sig: BLSSignature) -> Att {
        let mut bits = Bitlist::<VALIDATORS_PER_COMMITTEE>::with_capacity(8);
        for i in 0..8 {
            bits.push(i == bit).unwrap();
        }
        Att {
            aggregation_bits: bits,
            data: make_att_data(slot, index),
            signature: sig,
        }
    }

    fn zero_sig() -> BLSSignature {
        BLSSignature::default()
    }

    fn real_sig(ikm: &[u8; 32], msg: &[u8]) -> BLSSignature {
        BLSSecretKey::key_gen(ikm).unwrap().sign(msg)
    }

    // ── 2.6 tests ─────────────────────────────────────────────────────────────

    /// Task 2.6: `insert_and_drain_attestation`
    #[test]
    fn insert_and_drain_attestation() {
        let pools = OperationPools::<E>::new();
        let att = make_att_one_bit(1, 0, 0, zero_sig());
        pools.insert_attestation(att.clone());
        let ops = pools.drain_for_block(1);
        assert_eq!(ops.attestations.len(), 1);
        assert_eq!(ops.attestations[0].data.slot.0, 1);
        // After drain the pool is empty.
        let ops2 = pools.drain_for_block(1);
        assert_eq!(ops2.attestations.len(), 0);
    }

    /// Task 2.6: `disjoint_bits_aggregate`
    #[test]
    fn disjoint_bits_aggregate() {
        let ikm_a = [0xAAu8; 32];
        let ikm_b = [0xBBu8; 32];
        let msg = b"test";
        let sig_a = real_sig(&ikm_a, msg);
        let sig_b = real_sig(&ikm_b, msg);

        let att_a = make_att_one_bit(2, 0, 0, sig_a);
        let att_b = make_att_one_bit(2, 0, 1, sig_b);

        let pools = OperationPools::<E>::new();
        pools.insert_attestation(att_a);
        pools.insert_attestation(att_b);

        let ops = pools.drain_for_block(2);
        // Merged into a single attestation.
        assert_eq!(ops.attestations.len(), 1);
        let merged = &ops.attestations[0];
        // Bits 0 and 1 are both set.
        assert_eq!(merged.aggregation_bits.get(0), Some(true));
        assert_eq!(merged.aggregation_bits.get(1), Some(true));
        // Signature is the aggregation of sig_a and sig_b.
        let expected_agg = bls_aggregate(&[sig_a, sig_b]).unwrap();
        assert_eq!(merged.signature, expected_agg);
    }

    /// Task 2.6: `overlapping_bits_kept_separate`
    #[test]
    fn overlapping_bits_kept_separate() {
        let att_a = make_att_one_bit(3, 0, 0, zero_sig());
        let att_b = make_att_one_bit(3, 0, 0, zero_sig()); // same bit = overlap

        let pools = OperationPools::<E>::new();
        pools.insert_attestation(att_a);
        pools.insert_attestation(att_b);

        let ops = pools.drain_for_block(3);
        // Must not be merged — two separate entries.
        assert_eq!(ops.attestations.len(), 2);
    }

    /// Task 2.6: `exit_dedup_by_index`
    #[test]
    fn exit_dedup_by_index() {
        let exit1 = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(1),
                validator_index: ValidatorIndex(7),
            },
            signature: zero_sig(),
        };
        let exit2 = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(2),
                validator_index: ValidatorIndex(7), // same index — duplicate
            },
            signature: zero_sig(),
        };

        let pools = OperationPools::<E>::new();
        pools.insert_voluntary_exit(exit1.clone());
        pools.insert_voluntary_exit(exit2.clone()); // ignored

        let ops = pools.drain_for_block(1);
        assert_eq!(ops.voluntary_exits.len(), 1);
        assert_eq!(ops.voluntary_exits[0].message.epoch.0, 1); // first wins
    }

    /// Task 2.6: `eviction_at_cap`
    #[test]
    fn eviction_at_cap() {
        // Test the LruCache eviction behaviour that underpins our pool cap.
        let cap = NonZeroUsize::new(3).unwrap();
        let mut cache: LruCache<u64, u64> = LruCache::new(cap);
        cache.put(1, 1);
        cache.put(2, 2);
        cache.put(3, 3);
        cache.put(4, 4); // evicts 1 (oldest)
        assert!(cache.peek(&1).is_none(), "oldest entry should be evicted");
        assert!(cache.peek(&4).is_some(), "newest entry should be present");
    }

    /// Task 2.6: `drain_caps_at_max`
    #[test]
    fn drain_caps_at_max() {
        let pools = OperationPools::<E>::new();
        let max_att = E::MAX_ATTESTATIONS as usize;
        for i in 0..(max_att + 10) {
            // Different committee indices prevent merging.
            let att = make_att_one_bit(4, i as u64, 0, zero_sig());
            pools.insert_attestation(att);
        }
        let ops = pools.drain_for_block(4);
        assert!(
            ops.attestations.len() <= max_att,
            "drain must cap at MAX_ATTESTATIONS"
        );
    }

    /// Task 2.6: `sync_aggregate_empty_when_no_messages`
    #[test]
    fn sync_aggregate_empty_when_no_messages() {
        let pools = OperationPools::<E>::new();
        // MinimalEthSpec: SYNC_COMMITTEE_SIZE = 32
        let agg = pools.drain_sync_aggregate::<{ MinimalEthSpec::SYNC_COMMITTEE_SIZE }>(
            Slot(10),
            Root::default(),
        );
        for i in 0..(MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize) {
            assert_eq!(agg.sync_committee_bits.get(i), Some(false));
        }
        assert_eq!(agg.sync_committee_signature, BLSSignature::default());
    }
}
