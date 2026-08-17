//! Blob sidecar ingestion loop.
//!
//! `run_blob_ingestion_loop` receives `NetworkEvent::GossipBlobSidecar` events,
//! decodes the SSZ payload into a `BlobSidecar`, persists it to the store, and
//! notifies `BlobAwaitingBlocks` so that any DA-pending block whose sidecar set
//! is now complete gets re-injected into the block ingestion loop.
//!
//! # Design
//!
//! - Each sidecar is persisted via `put_blob_sidecar(block_root, index, sidecar)`.
//! - After persist, `blob_awaiting.notify_blob_arrived(block_root)` is called
//!   unconditionally: if the DA gate is satisfied on re-import, the block
//!   proceeds; otherwise it is re-parked with a fresh timer.
//! - Decoding is done via SSZ directly (no snappy: the network task decompresses
//!   before emitting `GossipBlobSidecar`).
//! - The loop exits when `event_rx` closes (network task shut down).
//!
//! Per `D-blob-hold-reuses-reinject`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use pharos_network::network::NetworkEvent;
use pharos_ssz::Decode as _;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::BeaconSpec;
use pharos_types::deneb::BlobSidecar;

use crate::data_availability::BlobAwaitingBlocks;

/// Run the blob-sidecar ingestion loop.
///
/// - `event_rx`: receives `NetworkEvent::GossipBlobSidecar` events from the
///   network task (shared with the block ingestion loop; the block loop filters
///   out blob events, and this loop filters out block events).
/// - `store`: RocksDB handle for persisting sidecars.
/// - `blob_awaiting`: shared registry; notified on each blob arrival so
///   DA-pending blocks can be re-injected.
///
/// The loop exits when `event_rx` closes.
pub async fn run_blob_ingestion_loop<E: BeaconSpec>(
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    store: Arc<RocksStore>,
    blob_awaiting: Arc<BlobAwaitingBlocks>,
) {
    loop {
        let event = match event_rx.recv().await {
            Some(e) => e,
            None => {
                debug!("blob_ingestion: event_rx closed; exiting");
                break;
            }
        };

        let (subnet, data) = match event {
            NetworkEvent::GossipBlobSidecar { subnet, data, .. } => (subnet, data),
            _ => continue, // block ingestion loop handles beacon_block events
        };

        // Decode the SSZ-encoded BlobSidecar (snappy already decompressed by network).
        let sidecar: BlobSidecar = match BlobSidecar::from_ssz_bytes(&data) {
            Ok(s) => s,
            Err(e) => {
                warn!(subnet, error = %e, "blob_ingestion: SSZ decode failed; dropping sidecar");
                continue;
            }
        };

        // `block_root` = `hash_tree_root(sidecar.signed_block_header.message)`
        // per `specs/deneb/p2p-interface.md`.  This is the key used in the DA
        // checker and in `put_blob_sidecar`.
        use pharos_ssz::TreeHash as _;
        let block_root = sidecar.signed_block_header.message.tree_hash_root();

        let index = sidecar.index;

        // Persist to RocksDB. This is called from the async loop; RocksDB
        // writes are sync/blocking, so we call spawn_blocking.
        let store_clone = Arc::clone(&store);
        let sidecar_clone = sidecar.clone();
        let persist_result = tokio::task::spawn_blocking(move || {
            <RocksStore as DbStore<E>>::put_blob_sidecar(
                &store_clone,
                block_root,
                index,
                &sidecar_clone,
            )
        })
        .await;

        match persist_result {
            Ok(Ok(())) => {
                debug!(
                    %block_root,
                    index,
                    subnet,
                    "blob_ingestion: persisted sidecar"
                );
            }
            Ok(Err(e)) => {
                warn!(%block_root, index, error = %e, "blob_ingestion: store write failed; still notifying registry");
                // Still notify: the DA gate will determine availability.
            }
            Err(e) => {
                warn!(%block_root, index, error = %e, "blob_ingestion: spawn_blocking join error");
                continue;
            }
        }

        // Notify the registry that a sidecar for this block root arrived.
        // If a block is parked awaiting DA, re-inject it. The DA gate in
        // `import_block` will re-run and determine whether all blobs are present.
        blob_awaiting.notify_blob_arrived(block_root).await;
    }
}
