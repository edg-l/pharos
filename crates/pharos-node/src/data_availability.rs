//! Data-availability checker trait and `BlobAvailabilityChecker` implementation.
//!
//! # Design (`D-da-checker-trait`)
//!
//! `DataAvailabilityChecker<E>` is a fork-agnostic trait: the caller extracts
//! `blob_kzg_commitments` from a Deneb block body ONCE (via a per-fork match in
//! the call site, per W6) and passes the slice.  The trait impl does NO
//! fork-dispatch and never sees the block.  This is the real Fulu PeerDAS seam:
//! Fulu can swap the impl without touching the signature (which contains no
//! `Blob`, fork, or block type).
//!
//! # Invariant (`D-da-block-not-in-forkchoice-until-available`)
//!
//! A block whose DA check returns `NotAvailable` is NEVER inserted into
//! fork-choice.  The gate in `import_block` runs BEFORE `state_transition` and
//! `on_block` (RI-1): if the check fails, `import_block` returns early with
//! `ImportError::DataNotAvailable`, and the block is parked in
//! `BlobAwaitingBlocks` by the caller (the ingestion loop, not `import_block`
//! itself).  No fork-choice write has occurred at that point.
//!
//! # RI-1 ordering guarantee
//!
//! The DA gate is merged into the STF `spawn_blocking` in `import_block`, placed
//! immediately before `state_transition` (after the pre-state fetch).  RocksDB
//! reads and KZG verification are both blocking; running them inside the same
//! `spawn_blocking` as the STF avoids an extra `await` and keeps the critical
//! path tight (W7).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use pharos_kzg::{KzgError, KzgVerifier};
use pharos_network::topics::GossipTopic;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::EthSpec;
use pharos_types::deneb::KZGCommitment;
use pharos_types::phase0::primitives::Root;
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ── DataAvailabilityVerdict ───────────────────────────────────────────────────

/// The outcome of a data-availability check for a single block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAvailabilityVerdict {
    /// All required blob sidecars are present and their KZG proofs verify.
    Available,
    /// One or more required blob sidecars are missing from the local store.
    NotAvailable,
    /// The block predates Deneb; DA is vacuously satisfied (no blobs required).
    Irrelevant,
}

// ── DataAvailabilityChecker ───────────────────────────────────────────────────

/// Fork-agnostic DA checker trait.
///
/// The caller extracts `blob_kzg_commitments` from a Deneb block body and
/// passes the slice here; this trait never sees the block itself.  The
/// signature contains no `Blob`, fork variant, or block type — making it the
/// real Fulu PeerDAS seam: Fulu can swap the impl without touching the trait.
///
/// Per `D-da-checker-trait`.
pub trait DataAvailabilityChecker<E: EthSpec>: Send + Sync + 'static {
    /// Check data availability for `block_root` given its KZG commitments.
    ///
    /// - `block_root`: the `hash_tree_root` of the block (used to look up blob
    ///   sidecars in the store).
    /// - `kzg_commitments`: the `blob_kzg_commitments` list extracted from the
    ///   Deneb block body by the caller.
    ///
    /// Returns `Irrelevant` when the slice is empty AND there are no blobs to
    /// check (pre-Deneb or empty-commitment Deneb block).
    fn is_data_available(
        &self,
        block_root: Root,
        kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict;
}

// ── BlobAvailabilityChecker ───────────────────────────────────────────────────

/// Production DA checker: reads `BlobSidecar`s from the store and batch-verifies
/// their KZG proofs against the block's commitments.
///
/// Per `D-da-checker-trait`.
pub struct BlobAvailabilityChecker<E: EthSpec> {
    store: Arc<RocksStore>,
    verifier: Arc<KzgVerifier>,
    _marker: std::marker::PhantomData<E>,
}

impl<E: EthSpec> BlobAvailabilityChecker<E> {
    /// Construct a new checker from a shared store handle and KZG verifier.
    pub fn new(store: Arc<RocksStore>, verifier: Arc<KzgVerifier>) -> Self {
        Self {
            store,
            verifier,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<E: EthSpec> DataAvailabilityChecker<E> for BlobAvailabilityChecker<E> {
    /// Check data availability for `block_root`.
    ///
    /// Logic:
    /// 1. Empty commitments → `Irrelevant`. This covers pre-Deneb blocks (no
    ///    blob field at all) and Deneb blocks with zero blobs. DA is vacuously
    ///    satisfied; the import path treats `Irrelevant` the same as `Available`
    ///    (both proceed without parking). Returning `Irrelevant` instead of
    ///    `Available` lets callers distinguish "KZG verified" from "no blobs
    ///    to verify" when logging.
    /// 2. Fetch all stored sidecars for `block_root`. If fewer than
    ///    `kzg_commitments.len()` are present → `NotAvailable` (sidecars still
    ///    in flight; the import path parks the block until they arrive).
    /// 3. Batch-verify all (blob, commitment, proof) triples → `Available` on
    ///    success, `NotAvailable` on KZG failure or unexpected verify error.
    fn is_data_available(
        &self,
        block_root: Root,
        kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        // Empty commitment list: pre-Deneb block (or a Deneb block with no
        // blobs).  DA is vacuously satisfied; mark as Irrelevant so the import
        // path can skip KZG verify entirely.
        if kzg_commitments.is_empty() {
            return DataAvailabilityVerdict::Irrelevant;
        }

        // Fetch all stored sidecars for this block.
        let sidecars =
            match <RocksStore as DbStore<E>>::get_blob_sidecars_by_root(&self.store, &block_root) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        %block_root,
                        error = %e,
                        "da_checker: store read failed; treating as NotAvailable"
                    );
                    return DataAvailabilityVerdict::NotAvailable;
                }
            };

        // All expected sidecars must be present (one per commitment).
        if sidecars.len() < kzg_commitments.len() {
            return DataAvailabilityVerdict::NotAvailable;
        }

        // Build batch inputs: (blob_bytes, commitment_bytes, proof_bytes).
        // Use the commitment order from the block body, matching sidecars by
        // index.  Sidecars are returned ordered by ascending index from the
        // prefix-scan in `get_blob_sidecars_by_root`.
        let mut blobs: Vec<[u8; 131072]> = Vec::with_capacity(kzg_commitments.len());
        let mut commitments: Vec<[u8; 48]> = Vec::with_capacity(kzg_commitments.len());
        let mut proofs: Vec<[u8; 48]> = Vec::with_capacity(kzg_commitments.len());

        for (i, expected_commitment) in kzg_commitments.iter().enumerate() {
            // Find the sidecar with matching index.
            let sidecar = match sidecars.iter().find(|s| s.index == i as u64) {
                Some(s) => s,
                None => {
                    return DataAvailabilityVerdict::NotAvailable;
                }
            };

            // Extract blob bytes from the SszVector<u8, BYTES_PER_BLOB>.
            let blob_slice = sidecar.blob.as_slice();
            if blob_slice.len() != 131072 {
                warn!(
                    %block_root,
                    index = i,
                    len = blob_slice.len(),
                    "da_checker: blob has wrong length; treating as NotAvailable"
                );
                return DataAvailabilityVerdict::NotAvailable;
            }
            let mut blob_bytes = [0u8; 131072];
            blob_bytes.copy_from_slice(blob_slice);

            blobs.push(blob_bytes);
            // FixedBytes<48>::as_slice() returns &[u8; 48] conceptually; convert to array.
            let mut c = [0u8; 48];
            c.copy_from_slice(expected_commitment.as_slice());
            commitments.push(c);
            let mut p = [0u8; 48];
            p.copy_from_slice(sidecar.kzg_proof.as_slice());
            proofs.push(p);
        }

        // Batch-verify all (blob, commitment, proof) triples.
        match self
            .verifier
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
        {
            Ok(true) => DataAvailabilityVerdict::Available,
            Ok(false) => {
                warn!(%block_root, "da_checker: KZG proof batch verification failed");
                DataAvailabilityVerdict::NotAvailable
            }
            Err(KzgError::LengthMismatch { .. }) => {
                // Should never happen: we built the vectors above to be equal length.
                warn!(%block_root, "da_checker: KZG length mismatch (internal error)");
                DataAvailabilityVerdict::NotAvailable
            }
            Err(e) => {
                warn!(%block_root, error = %e, "da_checker: KZG verify error");
                DataAvailabilityVerdict::NotAvailable
            }
        }
    }
}

// ── NoopDataAvailabilityChecker ───────────────────────────────────────────────

/// A no-op DA checker that always returns `Irrelevant`.
///
/// Used in test contexts and pre-Deneb configurations where blob sidecars are
/// not present. Also serves as the backfill checker because historical blocks
/// do not carry sidecars over the wire.
pub struct NoopDataAvailabilityChecker;

impl<E: EthSpec> DataAvailabilityChecker<E> for NoopDataAvailabilityChecker {
    fn is_data_available(
        &self,
        _block_root: Root,
        _kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        DataAvailabilityVerdict::Irrelevant
    }
}

// ── BlobAwaitingBlocks ────────────────────────────────────────────────────────

/// Maximum time to hold a DA-pending block before evicting it.
///
/// 2 mainnet epochs (2 × 32 slots × 12 s/slot = 768 s).  After this duration
/// the block is evicted and dropped (the re-inject channel entry is removed and
/// no reinject_tx send is made — the block is gone).  Blobs are expected to
/// arrive within one sync period; holding for two epochs is generous.
pub const MAX_BLOB_AWAIT_HOLD: Duration = Duration::from_secs(768);

/// Raw block bytes and topic for re-injection, plus the channel to re-inject on.
struct PendingEntry {
    /// The `(GossipTopic, Vec<u8>)` pair to send on reinject_tx when blobs arrive.
    block: (GossipTopic, Vec<u8>),
    /// The re-inject channel — cloned from the ingestion loop's `reinject_tx`.
    reinject_tx: mpsc::Sender<(GossipTopic, Vec<u8>)>,
}

/// In-memory registry of DA-pending blocks awaiting their blob sidecars.
///
/// When `import_block` returns `DataNotAvailable`, the ingestion loop parks the
/// raw block bytes here via `park`.  When the blob ingestion loop receives a
/// blob sidecar that completes a set, it calls `notify_blob_arrived` with the
/// block root; this registry re-injects the block into the ingestion loop via
/// the `reinject_tx` stored at `park` time.
///
/// # Time-based eviction (W10 / RI-2)
///
/// Each call to `park` spawns one `tokio::spawn` timer for `MAX_BLOB_AWAIT_HOLD`.
/// When the timer fires, the entry is removed from the map (if it is still
/// present under the same block root).  No re-inject is sent on eviction: the
/// block is simply dropped.  This bounds memory and prevents leaks.
///
/// # Dedup on re-arrival
///
/// If a block is re-gossipped (same `block_root`) while already parked, the
/// second `park` call is a no-op: the existing entry is reused and no second
/// timer is spawned.
///
/// Per `D-blob-hold-reuses-reinject`.
#[derive(Default)]
pub struct BlobAwaitingBlocks {
    inner: Mutex<HashMap<Root, PendingEntry>>,
}

impl BlobAwaitingBlocks {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Park a DA-pending block.
    ///
    /// If `block_root` is already registered (same block re-gossipped), this
    /// call is a no-op: the existing entry and its eviction timer are reused.
    ///
    /// Otherwise, the entry is inserted and a `MAX_BLOB_AWAIT_HOLD` eviction
    /// timer is spawned.
    pub fn park(
        self: &Arc<Self>,
        block_root: Root,
        block: (GossipTopic, Vec<u8>),
        reinject_tx: mpsc::Sender<(GossipTopic, Vec<u8>)>,
    ) {
        let mut map = self.inner.lock();
        // Dedup: if already parked, ignore the re-arrival.
        if map.contains_key(&block_root) {
            debug!(%block_root, "blob_awaiting: block already parked; ignoring re-arrival");
            return;
        }
        map.insert(block_root, PendingEntry { block, reinject_tx });
        drop(map);

        // Spawn one eviction timer per parked entry (mirroring `hold_future_block`).
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(MAX_BLOB_AWAIT_HOLD).await;
            let evicted = registry.inner.lock().remove(&block_root);
            if evicted.is_some() {
                warn!(%block_root, "blob_awaiting: evicting DA-pending block after timeout (blobs never arrived)");
            }
        });
    }

    /// Notify the registry that blob sidecars for `block_root` may now be
    /// complete, and re-inject the parked block into the ingestion loop.
    ///
    /// The entry is removed from the map; the eviction timer (if it fires after
    /// this call) will find no entry and be a no-op.
    ///
    /// If no entry exists for `block_root`, this is a no-op (the block was
    /// either never parked, already re-injected, or already evicted).
    pub async fn notify_blob_arrived(&self, block_root: Root) {
        let entry = self.inner.lock().remove(&block_root);
        if let Some(PendingEntry { block, reinject_tx }) = entry {
            if reinject_tx.send(block).await.is_err() {
                warn!(%block_root, "blob_awaiting: reinject_tx closed (receiver dropped); DA-pending block lost");
            } else {
                debug!(%block_root, "blob_awaiting: re-injecting block after blob arrival");
            }
        }
    }
}
