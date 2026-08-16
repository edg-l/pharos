//! Data-column sidecar ingestion loop (EIP-7594 PeerDAS).
//!
//! `run_column_ingestion_loop` receives `NetworkEvent::GossipDataColumnSidecar`
//! events, decodes the SSZ payload into a `DataColumnSidecar`, persists it to the
//! store, and notifies `ColumnAwaitingBlocks` so that any DA-pending block whose
//! custody+sampling column set is now complete gets re-injected into the block
//! ingestion loop.
//!
//! # Design (mirrors `blob_ingestion.rs`, `D-blob-hold-reuses-reinject`)
//!
//! - Each sidecar is persisted via `put_data_column_sidecar(block_root, sidecar)`.
//! - After persist, `column_awaiting.notify_column_arrived(block_root)` is called
//!   unconditionally: if the DA gate (`ColumnAvailabilityChecker`, Phase 4.2) is
//!   satisfied on re-import, the block proceeds; otherwise it is re-parked with a
//!   fresh timer.
//! - Decoding is done via SSZ directly (no snappy: the network task decompresses
//!   before emitting `GossipDataColumnSidecar`).
//! - The loop exits when `event_rx` closes (network task shut down).
//!
//! The DA gate checks only the node's custody+sampling column union (RI-1), not
//! all 128 columns, so a block is re-injected as soon as the expected set is
//! complete. The unconditional notify keeps the ingestion loop the single source
//! of the availability decision (the registry never inspects the column set).

use std::sync::Arc;

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use pharos_network::network::NetworkEvent;
use pharos_network::topics::GossipTopic;
use pharos_ssz::Decode as _;
use pharos_ssz::TreeHash as _;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::BeaconSpec;
use pharos_types::fulu::MainnetDataColumnSidecar as DataColumnSidecar;
use pharos_types::phase0::primitives::Root;

// ── ColumnAwaitingBlocks ──────────────────────────────────────────────────────

/// Maximum time to hold a DA-pending block before evicting it.
///
/// 2 mainnet epochs (2 × 32 slots × 12 s/slot = 768 s), matching
/// `MAX_BLOB_AWAIT_HOLD`. After this duration the block is evicted and dropped
/// (no `reinject_tx` send is made). Data-column sidecars are expected to arrive
/// within one sync period; holding for two epochs is generous.
pub const MAX_DATA_COLUMN_AWAIT_HOLD: Duration = Duration::from_secs(768);

/// Raw block bytes and topic for re-injection, plus the channel to re-inject on.
struct PendingEntry {
    /// The `(GossipTopic, Vec<u8>)` pair to send on `reinject_tx` when columns arrive.
    block: (GossipTopic, Vec<u8>),
    /// The re-inject channel — cloned from the ingestion loop's `reinject_tx`.
    reinject_tx: mpsc::Sender<(GossipTopic, Vec<u8>)>,
}

/// In-memory registry of DA-pending blocks awaiting their data-column sidecars.
///
/// When `import_block` returns `DataNotAvailable` (the `ColumnAvailabilityChecker`
/// gate found a missing expected column), the ingestion loop parks the raw block
/// bytes here via `park`. When the column ingestion loop receives a data-column
/// sidecar that may complete the set, it calls `notify_column_arrived` with the
/// block root; this registry re-injects the block into the ingestion loop via the
/// `reinject_tx` stored at `park` time.
///
/// Mirrors `BlobAwaitingBlocks`: one `tokio::spawn` eviction timer per parked
/// entry; dedup on re-arrival; no re-inject on eviction.
///
/// Per `D-blob-hold-reuses-reinject` (re-applied for columns, M13-Fulu).
#[derive(Default)]
pub struct ColumnAwaitingBlocks {
    inner: Mutex<HashMap<Root, PendingEntry>>,
}

impl ColumnAwaitingBlocks {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Park a DA-pending block.
    ///
    /// If `block_root` is already registered (same block re-gossipped), this call
    /// is a no-op: the existing entry and its eviction timer are reused.
    ///
    /// Otherwise the entry is inserted and a `MAX_DATA_COLUMN_AWAIT_HOLD` eviction
    /// timer is spawned.
    pub fn park(
        self: &Arc<Self>,
        block_root: Root,
        block: (GossipTopic, Vec<u8>),
        reinject_tx: mpsc::Sender<(GossipTopic, Vec<u8>)>,
    ) {
        let mut map = self.inner.lock();
        if map.contains_key(&block_root) {
            debug!(%block_root, "column_awaiting: block already parked; ignoring re-arrival");
            return;
        }
        map.insert(block_root, PendingEntry { block, reinject_tx });
        drop(map);

        let registry = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(MAX_DATA_COLUMN_AWAIT_HOLD).await;
            let evicted = registry.inner.lock().remove(&block_root);
            if evicted.is_some() {
                warn!(%block_root, "column_awaiting: evicting DA-pending block after timeout (columns never arrived)");
            }
        });
    }

    /// Notify the registry that data-column sidecars for `block_root` may now be
    /// complete, and re-inject the parked block into the ingestion loop.
    ///
    /// The entry is removed from the map; the eviction timer (if it fires after
    /// this call) will find no entry and be a no-op.
    ///
    /// If no entry exists for `block_root`, this is a no-op (the block was either
    /// never parked, already re-injected, or already evicted).
    pub async fn notify_column_arrived(&self, block_root: Root) {
        let entry = self.inner.lock().remove(&block_root);
        if let Some(PendingEntry { block, reinject_tx }) = entry {
            if reinject_tx.send(block).await.is_err() {
                warn!(%block_root, "column_awaiting: reinject_tx closed (receiver dropped); DA-pending block lost");
            } else {
                debug!(%block_root, "column_awaiting: re-injecting block after column arrival");
            }
        }
    }
}

// ── run_column_ingestion_loop ─────────────────────────────────────────────────

/// Run the data-column-sidecar ingestion loop.
///
/// - `event_rx`: receives `NetworkEvent::GossipDataColumnSidecar` events forwarded
///   from the block ingestion loop's column demux (mirrors the blob demux).
/// - `store`: RocksDB handle for persisting sidecars.
/// - `column_awaiting`: shared registry; notified on each column arrival so
///   DA-pending blocks can be re-injected when their expected set completes.
///
/// The loop exits when `event_rx` closes.
pub async fn run_column_ingestion_loop<E: BeaconSpec>(
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    store: Arc<RocksStore>,
    column_awaiting: Arc<ColumnAwaitingBlocks>,
) {
    loop {
        let event = match event_rx.recv().await {
            Some(e) => e,
            None => {
                debug!("column_ingestion: event_rx closed; exiting");
                break;
            }
        };

        let (subnet, data) = match event {
            NetworkEvent::GossipDataColumnSidecar { subnet, data, .. } => (subnet, data),
            _ => continue, // block ingestion loop handles beacon_block / blob events
        };

        // Decode the SSZ-encoded DataColumnSidecar (snappy already decompressed
        // by the network task).
        let sidecar: DataColumnSidecar = match DataColumnSidecar::from_ssz_bytes(&data) {
            Ok(s) => s,
            Err(e) => {
                warn!(subnet, error = %e, "column_ingestion: SSZ decode failed; dropping sidecar");
                continue;
            }
        };

        // `block_root` = `hash_tree_root(sidecar.signed_block_header.message)`
        // per `specs/fulu/p2p-interface.md`. This is the key used in the DA
        // checker and in `put_data_column_sidecar`.
        let block_root = sidecar.signed_block_header.message.tree_hash_root();
        let index = sidecar.index;

        // Persist to RocksDB. RocksDB writes are sync/blocking, so spawn_blocking.
        let store_clone = Arc::clone(&store);
        let sidecar_clone = sidecar.clone();
        let persist_result = tokio::task::spawn_blocking(move || {
            <RocksStore as DbStore<E>>::put_data_column_sidecar(
                &store_clone,
                block_root,
                &sidecar_clone,
            )
        })
        .await;

        match persist_result {
            Ok(Ok(())) => {
                debug!(%block_root, index, subnet, "column_ingestion: persisted sidecar");
            }
            Ok(Err(e)) => {
                warn!(%block_root, index, error = %e, "column_ingestion: store write failed; still notifying registry");
            }
            Err(e) => {
                warn!(%block_root, index, error = %e, "column_ingestion: spawn_blocking join error");
                continue;
            }
        }

        // Notify the registry that a sidecar for this block root arrived. If a
        // block is parked awaiting DA, re-inject it; the column DA gate in
        // `import_block` re-runs and determines whether the expected custody +
        // sampling column set is complete.
        column_awaiting.notify_column_arrived(block_root).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_network::topics::GossipTopicKind;
    use pharos_network::types::ForkDigest;

    fn dummy_topic() -> GossipTopic {
        GossipTopic {
            fork_digest: ForkDigest::from_array([0u8; 4]),
            kind: GossipTopicKind::BeaconBlock,
        }
    }

    #[tokio::test]
    async fn notify_reinjects_parked_block() {
        let registry = Arc::new(ColumnAwaitingBlocks::new());
        let (tx, mut rx) = mpsc::channel::<(GossipTopic, Vec<u8>)>(4);
        let root = Root::default();
        registry.park(root, (dummy_topic(), vec![1, 2, 3]), tx);

        registry.notify_column_arrived(root).await;

        let reinjected = rx.recv().await.expect("re-inject should fire");
        assert_eq!(reinjected.1, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn double_park_is_deduped() {
        let registry = Arc::new(ColumnAwaitingBlocks::new());
        let (tx, mut rx) = mpsc::channel::<(GossipTopic, Vec<u8>)>(4);
        let root = Root::default();
        registry.park(root, (dummy_topic(), vec![1]), tx.clone());
        // Second park with different bytes is ignored (dedup).
        registry.park(root, (dummy_topic(), vec![9, 9]), tx);

        registry.notify_column_arrived(root).await;
        let reinjected = rx.recv().await.expect("re-inject should fire");
        assert_eq!(reinjected.1, vec![1], "first park wins");
        // Only one entry was ever stored.
        registry.notify_column_arrived(root).await;
        assert!(rx.try_recv().is_err(), "no second re-inject");
    }

    #[tokio::test]
    async fn notify_unknown_root_is_noop() {
        let registry = Arc::new(ColumnAwaitingBlocks::new());
        // No panic, no send.
        registry.notify_column_arrived(Root::default()).await;
    }
}
