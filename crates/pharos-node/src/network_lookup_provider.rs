//! Production `LookupBlockProvider` backed by the p2p network.
//!
//! `NetworkLookupProvider` implements `LookupBlockProvider` by issuing a
//! `BeaconBlocksByRoot` req-resp request to the peer chosen by `PeerPicker`.
//!
//! `PeerPicker` is reused from `network_backfill_provider` — it is declared
//! there as `pub` so both providers can share the trait + production impl
//! without duplication.
//!
//! Single attempt, no retry: for lookup the block either arrives or we fall
//! through to range-backfill on the next iteration.  A retry against the same
//! (possibly non-serving) peer adds latency without benefit; the depth loop
//! in `fetch_and_walk` will fall through to `notify_backfill` on repeated
//! failure, which triggers range-sync.

use std::sync::Arc;

use pharos_network::{
    NetworkCommandSender,
    rpc::types::{MAX_REQUEST_BLOB_SIDECARS, RpcRequest, RpcResponse},
};
use pharos_ssz::SszList;
use pharos_types::deneb::{BlobIdentifier, BlobSidecar, BlobSidecarsByRootRequest};
use pharos_types::{BeaconSpec, phase0::BeaconBlocksByRootRequest, phase0::primitives::Root};

use crate::lookup::{LOOKUP_REQ_TIMEOUT, LookupBlockProvider, LookupError, MAX_LOOKUP_DEPTH};
use crate::network_backfill_provider::PeerPicker;

// ── NetworkLookupProvider ─────────────────────────────────────────────────────

/// Production `LookupBlockProvider` that issues `BeaconBlocksByRoot` via the
/// p2p network.
///
/// `LookupBlockProvider` uses native `async fn` in trait (Rust 1.85 stable)
/// because it is only used as a monomorphised generic; no `async-trait` is
/// needed on the impl.
pub struct NetworkLookupProvider<E: BeaconSpec> {
    cmd: NetworkCommandSender<E>,
    peer_picker: Arc<dyn PeerPicker>,
}

impl<E: BeaconSpec> NetworkLookupProvider<E> {
    /// Create a new provider using the given command sender and peer picker.
    pub fn new(cmd: NetworkCommandSender<E>, peer_picker: Arc<dyn PeerPicker>) -> Self {
        Self { cmd, peer_picker }
    }
}

impl<E: BeaconSpec> LookupBlockProvider<E> for NetworkLookupProvider<E>
where
    E::SignedBeaconBlock: Send + Sync + 'static,
{
    async fn blocks_by_root(
        &self,
        roots: Vec<Root>,
    ) -> Result<Vec<E::SignedBeaconBlock>, LookupError> {
        debug_assert!(
            roots.len() <= MAX_LOOKUP_DEPTH,
            "blocks_by_root: roots.len() ({}) > MAX_LOOKUP_DEPTH ({})",
            roots.len(),
            MAX_LOOKUP_DEPTH
        );

        if roots.len() > MAX_LOOKUP_DEPTH {
            return Err(LookupError::TooManyRoots);
        }

        let block_roots = SszList::from_vec(roots).map_err(|_| LookupError::TooManyRoots)?;

        let req = RpcRequest::BlocksByRoot(BeaconBlocksByRootRequest { block_roots });

        let peer = self
            .peer_picker
            .pick_highest_head_peer()
            .await
            .ok_or(LookupError::NoUsablePeers)?;

        match self.cmd.request(peer, req, LOOKUP_REQ_TIMEOUT).await {
            Ok(RpcResponse::BlocksByRoot(blocks)) => Ok(blocks),
            Ok(other) => Err(LookupError::Provider(format!(
                "unexpected response variant: {other:?}"
            ))),
            Err(e) => Err(LookupError::Provider(format!(
                "request to {peer:?} failed: {e}"
            ))),
        }
    }

    async fn blobs_by_root(
        &self,
        ids: Vec<BlobIdentifier>,
    ) -> Result<Vec<BlobSidecar>, LookupError> {
        // A by-root lookup of one block's sidecars is at most
        // `MAX_BLOB_COMMITMENTS_PER_BLOCK` ids — well under
        // `MAX_REQUEST_BLOB_SIDECARS`. Guard anyway so an over-long id list never
        // exceeds the wire bound and earns a peer penalty.
        if ids.len() as u64 > MAX_REQUEST_BLOB_SIDECARS {
            return Err(LookupError::TooManyRoots);
        }

        let blob_ids = SszList::from_vec(ids).map_err(|_| LookupError::TooManyRoots)?;
        let req = RpcRequest::BlobSidecarsByRoot(BlobSidecarsByRootRequest { blob_ids });

        let peer = self
            .peer_picker
            .pick_highest_head_peer()
            .await
            .ok_or(LookupError::NoUsablePeers)?;

        match self.cmd.request(peer, req, LOOKUP_REQ_TIMEOUT).await {
            Ok(RpcResponse::BlobSidecars(sidecars)) => Ok(sidecars),
            Ok(other) => Err(LookupError::Provider(format!(
                "unexpected response variant: {other:?}"
            ))),
            Err(e) => Err(LookupError::Provider(format!(
                "request to {peer:?} failed: {e}"
            ))),
        }
    }
}
