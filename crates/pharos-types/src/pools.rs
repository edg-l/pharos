//! In-memory operation pools for the beacon node.
//!
//! `OperationPools<E>` collects gossip-validated operations before they are
//! drained into a produced `BeaconBlock`. Each map is independently locked via
//! `parking_lot::RwLock` so different operation types can be inserted
//! concurrently without contending on a single pool-level lock.
//!
//! This module is in `pharos-types` so both `pharos-node` and `pharos-api`
//! can reference the concrete `OperationPools<E>` type without introducing a
//! `pharos-api → pharos-node` dependency.
//!
//! # Attestation aggregation
//!
//! On `insert_attestation` the pool attempts to merge the incoming attestation
//! with any existing pooled attestation for the same `AttestationData`. Merging
//! is only performed when the bits are disjoint; overlapping attestations are
//! stored under a distinct subkey so correctness is preserved.
//!
//! # Sync messages
//!
//! `insert_sync_message` stores `SyncCommitteeMessage` values keyed by
//! `(slot, subcommittee_index, beacon_block_root)`.
//! `drain_sync_aggregate_raw` merges participation bits across all stored messages.
//!
//! # Eviction
//!
//! Every map is capped at `MAX_POOL_ENTRIES`. When the cap is reached the
//! oldest-inserted entry is evicted (via `lru::LruCache`).

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::RwLock;

use crate::EthSpec;
use crate::altair::{SyncAggregate, SyncCommitteeMessage};
use crate::capella::operations::SignedBLSToExecutionChange;
use crate::phase0::operations::{
    Attestation, AttesterSlashing, ProposerSlashing, SignedVoluntaryExit,
};
use crate::phase0::primitives::{Root, Slot};
use pharos_ssz::Bitvector;
use pharos_utils::BLSSignature;
use pharos_utils::bls::aggregate;

// ── constants ──────────────────────────────────────────────────────────────────

/// Maximum number of entries in each individual pool map before the oldest
/// entry is evicted.
pub const MAX_POOL_ENTRIES: usize = 16384;

/// Compressed G2 point at infinity (`b'\xc0' + b'\x00' * 95`), per
/// `specs/altair/bls.md`. This is the canonical signature for an **empty** sync
/// aggregate: `eth_fast_aggregate_verify` accepts empty pubkeys only when paired
/// with this exact value. A produced block with no sync participants must carry
/// it (NOT the all-zero `BLSSignature::default()`), or its own
/// `verify_signatures=true` re-import would fail `process_sync_aggregate`.
fn empty_sync_committee_signature() -> BLSSignature {
    let mut bytes = [0u8; 96];
    bytes[0] = 0xc0;
    BLSSignature::from_array(bytes)
}

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
#[derive(Default)]
pub struct BlockOperations {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub attester_slashings: Vec<AttesterSlashing<VALIDATORS_PER_COMMITTEE>>,
    pub attestations: Vec<Attestation<VALIDATORS_PER_COMMITTEE>>,
    /// Always empty. Pharos has no eth1 deposit-following subsystem
    /// (`D-no-deposit-source`).
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
/// Shared as `Arc<OperationPools<E>>` by all consumers (gossip-validator path,
/// block-production, API layer) so the pool lives for the node lifetime.
///
/// Lives in `pharos-types` so `pharos-api` can reference it directly without
/// creating a `pharos-api → pharos-node` dependency.
pub struct OperationPools<E: EthSpec> {
    /// Aggregated attestations.
    attestations: RwLock<LruCache<AttKey, Attestation<VALIDATORS_PER_COMMITTEE>>>,
    /// Attester slashings.
    attester_slashings: RwLock<LruCache<u128, AttesterSlashing<VALIDATORS_PER_COMMITTEE>>>,
    /// Proposer slashings, keyed by proposer index.
    proposer_slashings: RwLock<LruCache<u64, ProposerSlashing>>,
    /// Voluntary exits, keyed by validator index.
    voluntary_exits: RwLock<LruCache<u64, SignedVoluntaryExit>>,
    /// BLS-to-execution-credential changes, keyed by validator index.
    bls_to_execution_changes: RwLock<LruCache<u64, SignedBLSToExecutionChange>>,
    /// Sync committee messages.
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

    // ── read helpers ──────────────────────────────────────────────────────────

    /// Return a snapshot of all pooled attestations (MRU order).
    pub fn attestations_snapshot(&self) -> Vec<Attestation<VALIDATORS_PER_COMMITTEE>> {
        self.attestations
            .read()
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Return a snapshot of all pooled attester slashings.
    pub fn attester_slashings_snapshot(&self) -> Vec<AttesterSlashing<VALIDATORS_PER_COMMITTEE>> {
        self.attester_slashings
            .read()
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Return a snapshot of all pooled proposer slashings.
    pub fn proposer_slashings_snapshot(&self) -> Vec<ProposerSlashing> {
        self.proposer_slashings
            .read()
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Return a snapshot of all pooled voluntary exits.
    pub fn voluntary_exits_snapshot(&self) -> Vec<SignedVoluntaryExit> {
        self.voluntary_exits
            .read()
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Return a snapshot of all pooled BLS-to-execution changes.
    pub fn bls_to_execution_changes_snapshot(&self) -> Vec<SignedBLSToExecutionChange> {
        self.bls_to_execution_changes
            .read()
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Return a snapshot of all pooled sync committee messages (flattened).
    pub fn sync_messages_snapshot(&self) -> Vec<SyncCommitteeMessage> {
        self.sync_messages
            .read()
            .iter()
            .flat_map(|(_, msgs)| msgs.clone())
            .collect()
    }

    // ── insert helpers ────────────────────────────────────────────────────────

    /// Insert an attestation into the pool.
    ///
    /// If a pooled attestation exists for the same `AttestationData` AND
    /// the aggregation bits are disjoint, the bits are merged and signatures
    /// are aggregated. Otherwise, the incoming attestation is stored under a
    /// new subkey.
    pub fn insert_attestation(&self, att: Attestation<VALIDATORS_PER_COMMITTEE>) {
        use pharos_ssz::TreeHash;

        let data_root = att.data.tree_hash_root();
        let primary_key = AttKey::primary(data_root);

        let mut cache = self.attestations.write();

        if let Some(existing) = cache.peek(&primary_key) {
            let bits_disjoint = existing
                .aggregation_bits
                .iter()
                .zip(att.aggregation_bits.iter())
                .all(|(a, b)| !(a && b));

            if bits_disjoint {
                let mut merged = existing.clone();
                for (i, bit) in att.aggregation_bits.iter().enumerate() {
                    if bit {
                        merged.aggregation_bits.set(i, true);
                    }
                }
                match aggregate(&[existing.signature, att.signature]) {
                    Ok(agg_sig) => merged.signature = agg_sig,
                    Err(_) => {
                        let subkey = next_free_subkey(&cache, data_root);
                        cache.put(AttKey::with_subkey(data_root, subkey), att);
                        return;
                    }
                }
                cache.put(primary_key, merged);
                return;
            }
        }

        if cache.peek(&primary_key).is_none() {
            cache.put(primary_key, att);
        } else {
            let subkey = next_free_subkey(&cache, data_root);
            cache.put(AttKey::with_subkey(data_root, subkey), att);
        }
    }

    /// Best (most-aggregated) attestation pooled for `data_root`, if any.
    ///
    /// `insert_attestation` keeps the merged aggregate at the primary key and
    /// non-mergeable overlaps under subkeys; this returns whichever entry for
    /// `data_root` has the most participation bits set. Backs
    /// `GET /eth/v2/validator/aggregate_attestation`.
    pub fn best_aggregate_for(
        &self,
        data_root: Root,
    ) -> Option<Attestation<VALIDATORS_PER_COMMITTEE>> {
        let cache = self.attestations.read();
        cache
            .iter()
            .filter(|(k, _)| k.att_data_root == data_root)
            .map(|(_, v)| v.clone())
            .max_by_key(|att| att.aggregation_bits.iter().filter(|b| *b).count())
    }

    /// Insert an attester slashing into the pool.
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
    /// Only attestations whose data slot falls within the spec inclusion window
    /// relative to `block_slot` are retained. Deposits are always empty.
    pub fn drain_for_block(&self, block_slot: u64) -> BlockOperations {
        let max_proposer = E::MAX_PROPOSER_SLASHINGS as usize;
        let max_attester = E::MAX_ATTESTER_SLASHINGS as usize;
        let max_att = E::MAX_ATTESTATIONS as usize;
        let max_exits = E::MAX_VOLUNTARY_EXITS as usize;
        let max_bls = E::MAX_BLS_TO_EXECUTION_CHANGES as usize;

        let min_delay = E::MIN_ATTESTATION_INCLUSION_DELAY;
        let slots_per_epoch = E::SLOTS_PER_EPOCH;

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
            let keys: Vec<AttKey> = cache
                .iter()
                .filter(|(_, att)| {
                    let att_slot = att.data.slot.0;
                    let lower_ok = att_slot.saturating_add(min_delay) <= block_slot;
                    let upper_ok = block_slot <= att_slot.saturating_add(slots_per_epoch);
                    lower_ok && upper_ok
                })
                .take(max_att)
                .map(|(k, _)| k.clone())
                .collect();
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
    /// pooled sync committee messages (typed form, requires const-generic size).
    pub fn drain_sync_aggregate<const SYNC_COMMITTEE_SIZE: u64>(
        &self,
        slot: Slot,
        block_root: Root,
        committee_pubkeys: &[[u8; 48]],
        validator_pubkey: impl Fn(u64) -> Option<[u8; 48]>,
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
                let subc_start = subc_idx as usize * subcommittee_size;
                let subc_end = (subc_start + subcommittee_size).min(committee_pubkeys.len());
                let subc_slice = &committee_pubkeys[subc_start..subc_end];

                for msg in msgs.iter() {
                    let Some(pubkey) = validator_pubkey(msg.validator_index.0) else {
                        continue;
                    };
                    for (pos_in_subc, pk) in subc_slice.iter().enumerate() {
                        if pk == &pubkey {
                            let global = subc_start + pos_in_subc;
                            if (global as u64) < SYNC_COMMITTEE_SIZE {
                                bits.set(global, true);
                                sigs.push(msg.signature);
                            }
                        }
                    }
                }
            }
        }

        let sync_committee_signature = if sigs.is_empty() {
            empty_sync_committee_signature()
        } else {
            aggregate(&sigs).unwrap_or_default()
        };

        SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature,
        }
    }

    /// Fork-agnostic sync aggregate drain.
    ///
    /// Returns `(set_bits, aggregated_signature)` instead of a `SyncAggregate<N>`.
    pub fn drain_sync_aggregate_raw(
        &self,
        slot: Slot,
        block_root: Root,
        committee_pubkeys: &[[u8; 48]],
        validator_pubkey: impl Fn(u64) -> Option<[u8; 48]>,
    ) -> (Vec<usize>, BLSSignature) {
        let subcommittee_size = E::SYNC_SUBCOMMITTEE_SIZE as usize;
        let mut set_bits: Vec<usize> = Vec::new();
        let mut sigs: Vec<BLSSignature> = Vec::new();

        let mut cache = self.sync_messages.write();

        for subc_idx in 0..E::SYNC_COMMITTEE_SUBNET_COUNT {
            let key = SyncMessageKey {
                slot,
                subcommittee_index: subc_idx,
                beacon_block_root: block_root,
            };
            if let Some(msgs) = cache.pop(&key) {
                let subc_start = subc_idx as usize * subcommittee_size;
                let subc_end = (subc_start + subcommittee_size).min(committee_pubkeys.len());
                let subc_slice = &committee_pubkeys[subc_start..subc_end];

                for msg in msgs.iter() {
                    let Some(pubkey) = validator_pubkey(msg.validator_index.0) else {
                        continue;
                    };
                    for (pos_in_subc, pk) in subc_slice.iter().enumerate() {
                        if pk == &pubkey {
                            set_bits.push(subc_start + pos_in_subc);
                            sigs.push(msg.signature);
                        }
                    }
                }
            }
        }

        let aggregated = if sigs.is_empty() {
            empty_sync_committee_signature()
        } else {
            aggregate(&sigs).unwrap_or_default()
        };

        (set_bits, aggregated)
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

    use crate::phase0::misc::{AttestationData, Checkpoint};
    use crate::phase0::operations::VoluntaryExit;
    use crate::phase0::primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex};
    use crate::{EthSpec, MinimalEthSpec};
    use pharos_ssz::Bitlist;
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

    #[test]
    fn insert_and_drain_attestation() {
        let pools = OperationPools::<E>::new();
        let att = make_att_one_bit(1, 0, 0, zero_sig());
        pools.insert_attestation(att.clone());
        let ops = pools.drain_for_block(2);
        assert_eq!(ops.attestations.len(), 1);
        assert_eq!(ops.attestations[0].data.slot.0, 1);
        let ops2 = pools.drain_for_block(2);
        assert_eq!(ops2.attestations.len(), 0);
    }

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

        let ops = pools.drain_for_block(3);
        assert_eq!(ops.attestations.len(), 1);
        let merged = &ops.attestations[0];
        assert_eq!(merged.aggregation_bits.get(0), Some(true));
        assert_eq!(merged.aggregation_bits.get(1), Some(true));
        let expected_agg = bls_aggregate(&[sig_a, sig_b]).unwrap();
        assert_eq!(merged.signature, expected_agg);
    }

    #[test]
    fn overlapping_bits_kept_separate() {
        let att_a = make_att_one_bit(3, 0, 0, zero_sig());
        let att_b = make_att_one_bit(3, 0, 0, zero_sig());

        let pools = OperationPools::<E>::new();
        pools.insert_attestation(att_a);
        pools.insert_attestation(att_b);

        let ops = pools.drain_for_block(4);
        assert_eq!(ops.attestations.len(), 2);
    }

    #[test]
    fn drain_filters_attestations_outside_inclusion_window() {
        let pools = OperationPools::<E>::new();
        pools.insert_attestation(make_att_one_bit(10, 0, 0, zero_sig()));
        assert_eq!(pools.drain_for_block(10).attestations.len(), 0);

        let too_late = 1 + <E as EthSpec>::SLOTS_PER_EPOCH + 1;
        pools.insert_attestation(make_att_one_bit(1, 0, 0, zero_sig()));
        assert_eq!(pools.drain_for_block(too_late).attestations.len(), 0);

        assert_eq!(pools.drain_for_block(2).attestations.len(), 1);
    }

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
                validator_index: ValidatorIndex(7),
            },
            signature: zero_sig(),
        };

        let pools = OperationPools::<E>::new();
        pools.insert_voluntary_exit(exit1.clone());
        pools.insert_voluntary_exit(exit2.clone());

        let ops = pools.drain_for_block(1);
        assert_eq!(ops.voluntary_exits.len(), 1);
        assert_eq!(ops.voluntary_exits[0].message.epoch.0, 1);
    }

    #[test]
    fn eviction_at_cap() {
        let cap = NonZeroUsize::new(3).unwrap();
        let mut cache: LruCache<u64, u64> = LruCache::new(cap);
        cache.put(1, 1);
        cache.put(2, 2);
        cache.put(3, 3);
        cache.put(4, 4);
        assert!(cache.peek(&1).is_none());
        assert!(cache.peek(&4).is_some());
    }

    #[test]
    fn drain_caps_at_max() {
        let pools = OperationPools::<E>::new();
        let max_att = E::MAX_ATTESTATIONS as usize;
        for i in 0..(max_att + 10) {
            let att = make_att_one_bit(4, i as u64, 0, zero_sig());
            pools.insert_attestation(att);
        }
        let ops = pools.drain_for_block(4);
        assert!(
            ops.attestations.len() <= max_att,
            "drain must cap at MAX_ATTESTATIONS"
        );
    }

    #[test]
    fn sync_aggregate_empty_when_no_messages() {
        let pools = OperationPools::<E>::new();
        let committee: Vec<[u8; 48]> =
            vec![[0u8; 48]; MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize];
        let agg = pools.drain_sync_aggregate::<{ MinimalEthSpec::SYNC_COMMITTEE_SIZE }>(
            Slot(10),
            Root::default(),
            &committee,
            |_| None,
        );
        for i in 0..(MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize) {
            assert_eq!(agg.sync_committee_bits.get(i), Some(false));
        }
        // An empty sync aggregate signs as the G2 point at infinity (0xc0 || 0*95),
        // NOT all-zeros: `eth_fast_aggregate_verify` accepts empty participants only
        // against the infinity signature.
        assert_eq!(
            agg.sync_committee_signature,
            empty_sync_committee_signature()
        );
    }

    #[test]
    fn drain_sync_aggregate_uses_true_committee_position() {
        let pools = OperationPools::<E>::new();
        const SIZE: usize = MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize;
        let mut committee: Vec<[u8; 48]> = vec![[0u8; 48]; SIZE];
        let val7_pubkey = [0x07u8; 48];
        committee[5] = val7_pubkey;

        let msg = SyncCommitteeMessage {
            slot: Slot(1),
            beacon_block_root: Root::default(),
            validator_index: ValidatorIndex(7),
            signature: BLSSignature::default(),
        };
        pools.insert_sync_message(msg, 0);

        let agg = pools.drain_sync_aggregate::<{ MinimalEthSpec::SYNC_COMMITTEE_SIZE }>(
            Slot(1),
            Root::default(),
            &committee,
            |idx| {
                if idx == 7 { Some(val7_pubkey) } else { None }
            },
        );
        assert_eq!(
            agg.sync_committee_bits.get(5),
            Some(true),
            "bit at true committee position 5 must be set"
        );
        for i in 0..SIZE {
            if i != 5 {
                assert_eq!(
                    agg.sync_committee_bits.get(i),
                    Some(false),
                    "bit {i} must not be set"
                );
            }
        }
    }

    #[test]
    fn drain_for_block_filters_by_inclusion_window() {
        type E = MinimalEthSpec;
        let min_delay = E::MIN_ATTESTATION_INCLUSION_DELAY;
        let spe = E::SLOTS_PER_EPOCH;
        let block_slot = 10u64;

        let slot_in = block_slot - min_delay;
        let slot_too_recent = block_slot;
        let slot_too_old = block_slot.saturating_sub(spe + 1);

        let pools = OperationPools::<E>::new();
        pools.insert_attestation(make_att_one_bit(slot_in, 10, 0, zero_sig()));
        pools.insert_attestation(make_att_one_bit(slot_too_recent, 11, 0, zero_sig()));
        pools.insert_attestation(make_att_one_bit(slot_too_old, 12, 0, zero_sig()));

        let ops = pools.drain_for_block(block_slot);
        assert_eq!(
            ops.attestations.len(),
            1,
            "only in-window attestation should be drained"
        );
        assert_eq!(
            ops.attestations[0].data.slot.0, slot_in,
            "drained attestation must be the in-window one"
        );
    }
}
