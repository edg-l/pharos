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

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use pharos_kzg::{KzgError, KzgVerifier};
use pharos_network::topics::GossipTopic;
use pharos_stf::fulu::data_columns::{
    compute_columns_for_custody_group, get_custody_groups, verify_data_column_sidecar,
    verify_data_column_sidecar_kzg_proofs,
};
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::BeaconSpec;
use pharos_types::config::RuntimeConfig;
use pharos_types::deneb::KZGCommitment;
use pharos_types::fulu::data_column_sidecar::ColumnIndex;
use pharos_types::fulu::get_blob_parameters;
use pharos_types::phase0::primitives::{Epoch, Root};
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
pub trait DataAvailabilityChecker<E: BeaconSpec>: Send + Sync + 'static {
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
pub struct BlobAvailabilityChecker<E: BeaconSpec> {
    store: Arc<RocksStore>,
    verifier: Arc<KzgVerifier>,
    _marker: std::marker::PhantomData<E>,
}

impl<E: BeaconSpec> BlobAvailabilityChecker<E> {
    /// Construct a new checker from a shared store handle and KZG verifier.
    pub fn new(store: Arc<RocksStore>, verifier: Arc<KzgVerifier>) -> Self {
        Self {
            store,
            verifier,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<E: BeaconSpec> DataAvailabilityChecker<E> for BlobAvailabilityChecker<E> {
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

impl<E: BeaconSpec> DataAvailabilityChecker<E> for NoopDataAvailabilityChecker {
    fn is_data_available(
        &self,
        _block_root: Root,
        _kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        DataAvailabilityVerdict::Irrelevant
    }
}

// ── ColumnAvailabilityChecker (EIP-7594 PeerDAS) ──────────────────────────────

/// Production Fulu DA checker: reads `DataColumnSidecar`s from the store and
/// verifies them per the Fulu `is_data_available` (`specs/fulu/fork-choice.md`).
///
/// The trait signature is unchanged (fork-agnostic): the caller still extracts
/// `blob_kzg_commitments` from the block body and passes the slice. The column
/// impl uses the commitment slice only to distinguish a no-blob block
/// (`Irrelevant`) from one that requires data; the actual availability check
/// reads the node's expected custody+sampling column set from the store, not
/// "all 128 columns" (RI-1).
///
/// # Expected column set (RI-1)
///
/// Per `specs/fulu/das-core.md`, the node samples
/// `sampling_size = max(SAMPLES_PER_SLOT, custody_group_count)` custody groups
/// via `get_custody_groups(node_id, sampling_size)`, and the columns it must
/// retrieve are the union of `compute_columns_for_custody_group(group)` over
/// those groups. Custody groups are a subset of the sampling groups, so this
/// union already includes the node's own custody columns. The set is computed
/// once at construction (it depends only on the node id and the preset
/// constants, which never change at runtime) and cached.
pub struct ColumnAvailabilityChecker<E: BeaconSpec> {
    store: Arc<RocksStore>,
    verifier: Arc<KzgVerifier>,
    runtime_cfg: Arc<RuntimeConfig>,
    /// The sorted set of column indices this node must retrieve to satisfy the
    /// DA gate (the custody+sampling union, RI-1).
    expected_columns: BTreeSet<ColumnIndex>,
    _marker: std::marker::PhantomData<E>,
}

impl<E: BeaconSpec> ColumnAvailabilityChecker<E> {
    /// Construct a new checker from a shared store handle, KZG verifier, runtime
    /// config, the local 256-bit node id (big-endian 32-byte `NodeID`), and the
    /// node's `custody_group_count`.
    ///
    /// The expected-column set is computed once here:
    /// `sampling_size = max(SAMPLES_PER_SLOT, custody_group_count)` clamped to
    /// `NUMBER_OF_CUSTODY_GROUPS`, then the union of
    /// `compute_columns_for_custody_group(g)` over
    /// `get_custody_groups(node_id, sampling_size)`.
    pub fn new(
        store: Arc<RocksStore>,
        verifier: Arc<KzgVerifier>,
        runtime_cfg: Arc<RuntimeConfig>,
        node_id: [u8; 32],
        custody_group_count: u64,
    ) -> Self {
        // sampling_size = max(SAMPLES_PER_SLOT, custody_group_count), clamped to
        // NUMBER_OF_CUSTODY_GROUPS (the spec asserts custody_group_count <=
        // NUMBER_OF_CUSTODY_GROUPS; clamping keeps the helper assert satisfied
        // even if a misconfigured node requested more).
        let sampling_size = E::SAMPLES_PER_SLOT
            .max(custody_group_count)
            .min(E::NUMBER_OF_CUSTODY_GROUPS);

        let groups = get_custody_groups::<E>(node_id, sampling_size);
        let mut expected_columns: BTreeSet<ColumnIndex> = BTreeSet::new();
        for group in groups {
            for col in compute_columns_for_custody_group::<E>(group) {
                expected_columns.insert(col);
            }
        }

        Self {
            store,
            verifier,
            runtime_cfg,
            expected_columns,
            _marker: std::marker::PhantomData,
        }
    }

    /// The sorted set of column indices this node must retrieve (custody +
    /// sampling union, RI-1). Exposed for the column ingestion loop and tests.
    pub fn expected_columns(&self) -> &BTreeSet<ColumnIndex> {
        &self.expected_columns
    }
}

impl<E: BeaconSpec> DataAvailabilityChecker<E> for ColumnAvailabilityChecker<E> {
    /// Check data availability for `block_root` per the Fulu
    /// `is_data_available`.
    ///
    /// Logic:
    /// 1. Empty commitments → `Irrelevant` (pre-Fulu, or a Fulu block with no
    ///    blobs: no columns to retrieve).
    /// 2. For each expected column index (custody+sampling union, RI-1), read
    ///    the `DataColumnSidecar` from the store. Any missing → `NotAvailable`
    ///    (still in flight; the block parks).
    /// 3. Each retrieved sidecar must pass `verify_data_column_sidecar` (with
    ///    the epoch-driven `max_blobs_per_block` from `get_blob_parameters`) and
    ///    `verify_data_column_sidecar_kzg_proofs`. All pass → `Available`; any
    ///    failure → `NotAvailable`.
    fn is_data_available(
        &self,
        block_root: Root,
        kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        // No blobs → no columns to sample. DA is vacuously satisfied.
        if kzg_commitments.is_empty() {
            return DataAvailabilityVerdict::Irrelevant;
        }

        for &column_index in &self.expected_columns {
            let sidecar = match <RocksStore as DbStore<E>>::get_data_column_sidecar(
                &self.store,
                &block_root,
                column_index,
            ) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    // Missing expected column: still in flight.
                    return DataAvailabilityVerdict::NotAvailable;
                }
                Err(e) => {
                    warn!(
                        %block_root,
                        column_index,
                        error = %e,
                        "column_da_checker: store read failed; treating as NotAvailable"
                    );
                    return DataAvailabilityVerdict::NotAvailable;
                }
            };

            // Resolve the epoch-driven max-blobs-per-block (EIP-7892) from the
            // sidecar's own slot, matching the spec's
            // `compute_epoch_at_slot(sidecar.signed_block_header.message.slot)`.
            let slot = sidecar.signed_block_header.message.slot;
            let epoch = Epoch(slot.0 / E::SLOTS_PER_EPOCH);
            let blob_params = get_blob_parameters(
                epoch,
                &self.runtime_cfg.blob_schedule,
                Epoch(self.runtime_cfg.electra_fork_epoch),
                self.runtime_cfg.max_blobs_per_block_electra,
            );

            if let Err(e) =
                verify_data_column_sidecar::<E, 4096, 4>(&sidecar, blob_params.max_blobs_per_block)
            {
                warn!(
                    %block_root,
                    column_index,
                    error = %e,
                    "column_da_checker: data column sidecar invalid"
                );
                return DataAvailabilityVerdict::NotAvailable;
            }

            if let Err(e) =
                verify_data_column_sidecar_kzg_proofs::<4096, 4>(&sidecar, &self.verifier)
            {
                warn!(
                    %block_root,
                    column_index,
                    error = %e,
                    "column_da_checker: data column sidecar KZG proof verification failed"
                );
                return DataAvailabilityVerdict::NotAvailable;
            }
        }

        DataAvailabilityVerdict::Available
    }
}

// ── ForkAwareDataAvailabilityChecker ──────────────────────────────────────────

/// Live-node DA checker spanning the Deneb/Electra → Fulu boundary.
///
/// A long-running node imports both pre-Fulu blocks (data delivered as
/// `BlobSidecar`s) and Fulu+ blocks (data delivered as `DataColumnSidecar`s),
/// so a single static checker is wrong: a `BlobAvailabilityChecker` would gate
/// a Fulu block against blob sidecars that never arrive post-Fulu and park it
/// forever (and vice-versa for backfilled pre-Fulu blocks).
///
/// The `DataAvailabilityChecker` trait is fork-agnostic by design (it sees only
/// `(block_root, kzg_commitments)`, never the slot), so this wrapper cannot
/// learn the block's fork from its arguments. Instead it delegates to BOTH
/// sub-checkers and combines: each sub-checker returns `Available` only when
/// ITS sidecar type is present in the store, and a node only ever ingests the
/// fork-correct sidecar type for a given block, so "`Available` if either is
/// `Available`" is exactly right. Empty commitments → both `Irrelevant` →
/// `Irrelevant`. The column checker is tried first (Fulu is the active mainnet
/// fork) so the common path short-circuits without a redundant blob-store scan.
///
/// Per `D-fork-aware-live-da-checker`.
pub struct ForkAwareDataAvailabilityChecker<E: BeaconSpec> {
    blob: BlobAvailabilityChecker<E>,
    column: ColumnAvailabilityChecker<E>,
}

impl<E: BeaconSpec> ForkAwareDataAvailabilityChecker<E> {
    /// Build both sub-checkers from the shared store/verifier/runtime config and
    /// the node's `NodeID` + custody-group count (for the column sampling set).
    pub fn new(
        store: Arc<RocksStore>,
        verifier: Arc<KzgVerifier>,
        runtime_cfg: Arc<RuntimeConfig>,
        node_id: [u8; 32],
        custody_group_count: u64,
    ) -> Self {
        Self {
            blob: BlobAvailabilityChecker::new(Arc::clone(&store), Arc::clone(&verifier)),
            column: ColumnAvailabilityChecker::new(
                store,
                verifier,
                runtime_cfg,
                node_id,
                custody_group_count,
            ),
        }
    }

    /// The sorted set of column indices the node must retrieve for Fulu+ blocks
    /// (custody + sampling union, RI-1). Exposed so the lookup co-fetch and the
    /// column DA gate agree on the same column set.
    pub fn expected_columns(&self) -> &std::collections::BTreeSet<ColumnIndex> {
        self.column.expected_columns()
    }
}

impl<E: BeaconSpec> DataAvailabilityChecker<E> for ForkAwareDataAvailabilityChecker<E> {
    fn is_data_available(
        &self,
        block_root: Root,
        kzg_commitments: &[KZGCommitment],
    ) -> DataAvailabilityVerdict {
        // Column first: Fulu is the active mainnet fork, so most tip blocks
        // resolve here and skip the (redundant) blob-store scan below.
        let column_verdict = self.column.is_data_available(block_root, kzg_commitments);
        if column_verdict == DataAvailabilityVerdict::Available {
            return DataAvailabilityVerdict::Available;
        }
        let blob_verdict = self.blob.is_data_available(block_root, kzg_commitments);
        combine_da_verdicts(blob_verdict, column_verdict)
    }
}

/// Combine the blob and column sub-checker verdicts (see
/// [`ForkAwareDataAvailabilityChecker`]). `Available` if either sub-checker is
/// (only the fork-correct sidecar type is ever present); `Irrelevant` only when
/// both are (empty commitments); otherwise `NotAvailable`.
fn combine_da_verdicts(
    blob: DataAvailabilityVerdict,
    column: DataAvailabilityVerdict,
) -> DataAvailabilityVerdict {
    use DataAvailabilityVerdict::*;
    match (blob, column) {
        (Available, _) | (_, Available) => Available,
        (Irrelevant, Irrelevant) => Irrelevant,
        _ => NotAvailable,
    }
}

#[cfg(test)]
mod fork_aware_tests {
    use super::DataAvailabilityVerdict::*;
    use super::combine_da_verdicts;

    #[test]
    fn fulu_block_with_columns_present_is_available() {
        // Column sidecars present (Fulu block), blobs absent: Available.
        assert_eq!(combine_da_verdicts(NotAvailable, Available), Available);
    }

    #[test]
    fn pre_fulu_block_with_blobs_present_is_available() {
        // Blob sidecars present (pre-Fulu block), columns absent: Available.
        assert_eq!(combine_da_verdicts(Available, NotAvailable), Available);
    }

    #[test]
    fn neither_sidecar_type_present_is_not_available() {
        assert_eq!(
            combine_da_verdicts(NotAvailable, NotAvailable),
            NotAvailable
        );
    }

    #[test]
    fn empty_commitments_is_irrelevant() {
        // Both sub-checkers short-circuit on empty commitments.
        assert_eq!(combine_da_verdicts(Irrelevant, Irrelevant), Irrelevant);
    }
}

#[cfg(test)]
mod expected_columns_tests {
    use std::sync::Arc;

    use pharos_kzg::KzgVerifier;
    use pharos_storage::{RocksStore, RocksStoreConfig};
    use pharos_types::config::RuntimeConfig;
    use pharos_types::{BeaconSpec, MinimalBeaconSpec};

    use super::{ColumnAvailabilityChecker, ForkAwareDataAvailabilityChecker};

    /// The fork-aware checker's `expected_columns()` must be byte-for-byte the
    /// same custody+sampling set as the inner `ColumnAvailabilityChecker`'s for a
    /// fixed `node_id` + `cgc` — the accessor just forwards to the column
    /// sub-checker, so the lookup co-fetch and the column DA gate agree on which
    /// columns matter (accessor).
    #[test]
    fn fork_aware_expected_columns_match_inner_column_checker() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
                path: tmp.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );
        let verifier = Arc::new(KzgVerifier::mainnet());
        let runtime_cfg = Arc::new(RuntimeConfig::default());

        let node_id = [0x11u8; 32];
        let cgc = MinimalBeaconSpec::CUSTODY_REQUIREMENT;

        let inner = ColumnAvailabilityChecker::<MinimalBeaconSpec>::new(
            Arc::clone(&store),
            Arc::clone(&verifier),
            Arc::clone(&runtime_cfg),
            node_id,
            cgc,
        );
        let fork_aware = ForkAwareDataAvailabilityChecker::<MinimalBeaconSpec>::new(
            Arc::clone(&store),
            Arc::clone(&verifier),
            Arc::clone(&runtime_cfg),
            node_id,
            cgc,
        );

        assert_eq!(
            fork_aware.expected_columns(),
            inner.expected_columns(),
            "fork-aware expected_columns must forward to the inner column checker's set"
        );
        assert!(
            !fork_aware.expected_columns().is_empty(),
            "the custody+sampling union must be non-empty for a Fulu node"
        );
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
