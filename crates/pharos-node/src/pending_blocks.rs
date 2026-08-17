//! In-memory store for orphan gossip blocks awaiting their missing parent.
//!
//! An *orphan* is a gossip block whose parent root is not yet in the
//! fork-choice store.  Rather than discarding it, the ingestion loop queues
//! it here so the lookup loop can fetch the missing ancestors and replay the
//! queued block once the parent arrives.
//!
//! # W1 — Guard-never-held-across-await invariant
//!
//! `PendingBlocks` wraps a `parking_lot::Mutex`.  Every public method acquires
//! the guard, does its work, and releases it **before returning**.  No method
//! returns a guard or a reference derived from one.  This means the lookup
//! loop can call any method from an `async` context without risking
//! a guard held across an `.await` point.

use std::collections::{HashMap, VecDeque};

use libp2p::PeerId;
use parking_lot::Mutex;

use pharos_types::phase0::primitives::{ForkDigest, Root};

// ── Caps ──────────────────────────────────────────────────────────────────────

/// Maximum pending blocks from a single peer.  Excess inserts are silently
/// rejected so a misbehaving peer cannot exhaust the global store.
pub const MAX_PENDING_PER_PEER: usize = 256;

/// Maximum total pending blocks across all peers.  When this is exceeded the
/// oldest entry (FIFO) is evicted to make room for the new one.
pub const MAX_PENDING_BLOCKS: usize = 4096;

// ── PendingEntry ──────────────────────────────────────────────────────────────

/// One queued orphan block.
pub struct PendingEntry {
    /// The peer that gossiped this block.
    pub peer: PeerId,
    /// Hash-tree-root of the block itself (used for dedup and eviction).
    pub block_root: Root,
    /// Raw SSZ bytes.  The lookup loop re-decodes when it replays the block.
    pub data: Vec<u8>,
    /// The fork digest of the gossip topic the block arrived on.
    ///
    /// Stored so `drain_and_replay` can reconstruct the correct
    /// `GossipTopic` for decoding across fork boundaries without relying on
    /// the host's current fork digest, which may have advanced.
    pub fork_digest: ForkDigest,
}

// ── PendingInner ─────────────────────────────────────────────────────────────

struct PendingInner {
    /// Blocks grouped by the parent root they are waiting on.
    by_parent: HashMap<Root, Vec<PendingEntry>>,
    /// Number of pending blocks per originating peer (DoS cap).
    per_peer_count: HashMap<PeerId, usize>,
    /// Insertion-ordered `(parent_root, block_root)` pairs for FIFO eviction.
    order: VecDeque<(Root, Root)>,
    /// Total pending blocks across all buckets.
    total: usize,
}

impl PendingInner {
    fn new() -> Self {
        Self {
            by_parent: HashMap::new(),
            per_peer_count: HashMap::new(),
            order: VecDeque::new(),
            total: 0,
        }
    }
}

// ── PendingBlocks ─────────────────────────────────────────────────────────────

/// Bounded in-memory store for orphan gossip blocks.
///
/// See the [module-level docs](self) for the W1 guard invariant.
pub struct PendingBlocks(Mutex<PendingInner>);

impl Default for PendingBlocks {
    fn default() -> Self {
        PendingBlocks(Mutex::new(PendingInner::new()))
    }
}

impl PendingBlocks {
    /// Queue an orphan block.
    ///
    /// Returns `true` if the block was newly inserted, `false` if it was
    /// rejected for any of these reasons (in order of check):
    /// 1. `(parent_root, block_root)` is already present (dedup).
    /// 2. This `peer` already has `MAX_PENDING_PER_PEER` entries queued.
    ///
    /// When the total exceeds `MAX_PENDING_BLOCKS` after a successful insert
    /// the oldest entry (FIFO) is evicted so the cap is never breached.
    ///
    /// `fork_digest` is the 4-byte digest of the gossip topic the block arrived
    /// on; stored in `PendingEntry` so `drain_and_replay` can reconstruct the
    /// correct topic across fork boundaries.
    ///
    /// **W1**: acquires and releases the inner `Mutex` within this call.
    pub fn insert(
        &self,
        parent_root: Root,
        block_root: Root,
        peer: PeerId,
        data: Vec<u8>,
        fork_digest: ForkDigest,
    ) -> bool {
        let mut inner = self.0.lock();

        // 1. Dedup: is block_root already present under this parent?
        if let Some(bucket) = inner.by_parent.get(&parent_root)
            && bucket.iter().any(|e| e.block_root == block_root)
        {
            return false;
        }

        // 2. Per-peer cap.
        let peer_count = inner.per_peer_count.entry(peer).or_insert(0);
        if *peer_count >= MAX_PENDING_PER_PEER {
            return false;
        }

        // 3. Insert.
        *peer_count += 1;
        inner
            .by_parent
            .entry(parent_root)
            .or_default()
            .push(PendingEntry {
                peer,
                block_root,
                data,
                fork_digest,
            });
        inner.order.push_back((parent_root, block_root));
        inner.total += 1;

        // 4. Evict oldest if over global cap.
        if inner.total > MAX_PENDING_BLOCKS {
            Self::evict_oldest(&mut inner);
        }

        true
    }

    /// Remove and return all blocks waiting on `parent_root`.
    ///
    /// Returns an empty `Vec` if no blocks are pending for that parent.
    /// Decrements `per_peer_count` and `total` for every returned entry;
    /// also removes the corresponding `(parent_root, *)` pairs from the FIFO
    /// order queue.
    ///
    /// **W1**: acquires and releases the inner `Mutex` within this call.
    pub fn drain_children(&self, parent_root: Root) -> Vec<PendingEntry> {
        let mut inner = self.0.lock();

        let bucket = match inner.by_parent.remove(&parent_root) {
            Some(b) => b,
            None => return Vec::new(),
        };

        // Collect block roots so we can prune the order deque.
        let block_roots: std::collections::HashSet<Root> =
            bucket.iter().map(|e| e.block_root).collect();

        for entry in &bucket {
            inner.total -= 1;
            let count = inner.per_peer_count.entry(entry.peer).or_insert(0);
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                inner.per_peer_count.remove(&entry.peer);
            }
        }

        // Prune the FIFO order queue for this parent.
        inner
            .order
            .retain(|(pr, br)| !(*pr == parent_root && block_roots.contains(br)));

        bucket
    }

    /// Total number of pending blocks across all parents.
    ///
    /// **W1**: acquires and releases the inner `Mutex` within this call.
    #[allow(dead_code)]
    pub fn total(&self) -> usize {
        self.0.lock().total
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Evict the FIFO-oldest entry, keeping all structures consistent.
    fn evict_oldest(inner: &mut PendingInner) {
        let (parent_root, block_root) = match inner.order.pop_front() {
            Some(pair) => pair,
            None => return,
        };

        if let Some(bucket) = inner.by_parent.get_mut(&parent_root)
            && let Some(pos) = bucket.iter().position(|e| e.block_root == block_root)
        {
            let entry = bucket.remove(pos);
            inner.total -= 1;

            let count = inner.per_peer_count.entry(entry.peer).or_insert(0);
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                inner.per_peer_count.remove(&entry.peer);
            }

            if bucket.is_empty() {
                inner.by_parent.remove(&parent_root);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn root(n: u8) -> Root {
        Root::from_array([n; 32])
    }

    fn root_from_bytes(bytes: [u8; 32]) -> Root {
        Root::from_array(bytes)
    }

    fn dummy_fd() -> ForkDigest {
        ForkDigest::from_array([0x00, 0x00, 0x00, 0x01])
    }

    /// Insert two children under one parent; drain returns both; total drops to 0.
    #[test]
    fn insert_then_drain_returns_children() {
        let store = PendingBlocks::default();
        let parent = root(0x01);
        let peer = PeerId::random();

        assert!(store.insert(parent, root(0x02), peer, vec![1], dummy_fd()));
        assert!(store.insert(parent, root(0x03), peer, vec![2], dummy_fd()));
        assert_eq!(store.total(), 2);

        let children = store.drain_children(parent);
        assert_eq!(children.len(), 2);
        assert_eq!(store.total(), 0);
    }

    /// 256 inserts for one peer succeed; the 257th is rejected.
    #[test]
    fn per_peer_cap_rejects_overflow() {
        let store = PendingBlocks::default();
        let parent = root(0x10);
        let peer = PeerId::random();

        for i in 0..MAX_PENDING_PER_PEER {
            let br = Root::from_array([i as u8; 32]);
            assert!(
                store.insert(parent, br, peer, vec![], dummy_fd()),
                "insert {i} should succeed"
            );
        }
        assert_eq!(store.total(), MAX_PENDING_PER_PEER);

        // 257th — same peer, new block_root.
        let overflow_br = Root::from_array([0xff; 32]);
        assert!(!store.insert(parent, overflow_br, peer, vec![], dummy_fd()));
        assert_eq!(store.total(), MAX_PENDING_PER_PEER);
    }

    /// After inserting MAX_PENDING_BLOCKS entries, one more triggers eviction;
    /// total stays at MAX_PENDING_BLOCKS and the first-inserted entry is gone.
    #[test]
    fn total_cap_evicts_fifo_oldest() {
        let store = PendingBlocks::default();

        // Use many distinct peers so the per-peer cap is never hit.
        // Spread across many distinct parents (one child per parent) so eviction
        // can locate the bucket easily.
        let first_parent = Root::from_array([0u8; 32]);
        let first_block = Root::from_array([1u8; 32]);
        let first_peer = PeerId::random();

        // Insert the "oldest" entry first.
        assert!(store.insert(
            first_parent,
            first_block,
            first_peer,
            vec![0xaa],
            dummy_fd()
        ));

        // Fill the rest with distinct peers and (parent, block) pairs.
        for i in 1..MAX_PENDING_BLOCKS {
            let mut pb = [0u8; 32];
            pb[0] = (i & 0xff) as u8;
            pb[1] = ((i >> 8) & 0xff) as u8;
            let parent = root_from_bytes(pb);

            let mut bb = [1u8; 32];
            bb[0] = (i & 0xff) as u8;
            bb[1] = ((i >> 8) & 0xff) as u8;
            let block = root_from_bytes(bb);

            assert!(store.insert(parent, block, PeerId::random(), vec![], dummy_fd()));
        }
        assert_eq!(store.total(), MAX_PENDING_BLOCKS);

        // One more entry — triggers eviction of the oldest (first_parent, first_block).
        let extra_parent = Root::from_array([0xfe; 32]);
        let extra_block = Root::from_array([0xff; 32]);
        assert!(store.insert(
            extra_parent,
            extra_block,
            PeerId::random(),
            vec![],
            dummy_fd()
        ));

        // Total must not exceed the cap.
        assert!(store.total() <= MAX_PENDING_BLOCKS);

        // The first-inserted block must have been evicted.
        let drained = store.drain_children(first_parent);
        assert!(
            drained.is_empty(),
            "first-inserted entry should have been evicted"
        );
    }

    /// Draining a never-inserted parent returns an empty Vec; total is unchanged.
    #[test]
    fn drain_unknown_parent_returns_empty() {
        let store = PendingBlocks::default();
        let peer = PeerId::random();
        store.insert(root(0x01), root(0x02), peer, vec![], dummy_fd());
        assert_eq!(store.total(), 1);

        let result = store.drain_children(root(0xde));
        assert!(result.is_empty());
        assert_eq!(store.total(), 1);
    }

    /// Inserting the same (parent_root, block_root) twice: second insert returns
    /// false and total stays at 1.
    #[test]
    fn dedup_same_block_root() {
        let store = PendingBlocks::default();
        let parent = root(0x07);
        let block = root(0x08);
        let peer = PeerId::random();

        assert!(store.insert(parent, block, peer, vec![1], dummy_fd()));
        assert!(!store.insert(parent, block, peer, vec![2], dummy_fd()));
        assert_eq!(store.total(), 1);
    }
}
