//! Production `BackfillColumnProvider` backed by the p2p network.
//!
//! `NetworkColumnBackfillProvider` implements `BackfillColumnProvider` by
//! issuing a `DataColumnSidecarsByRange` req-resp request to the peer chosen by
//! `PeerPicker`.
//!
//! `PeerPicker` is reused from `network_backfill_provider` — it is declared
//! there as `pub` so all providers can share the trait + production impl
//! without duplication.
//!
//! `BackfillColumnProvider` uses native `async fn` in trait (Rust 1.85 stable)
//! because it is only used as a monomorphised generic; no `async-trait` is
//! needed on the impl. The 2-peer retry mirrors `NetworkBackfillProvider`.

use std::sync::Arc;

use pharos_network::{
    NetworkCommandSender,
    rpc::types::{RpcRequest, RpcResponse},
};
use pharos_ssz::SszList;
use pharos_types::fulu::{DataColumnSidecar, DataColumnSidecarsByRangeRequest};
use pharos_types::{BeaconSpec, phase0::primitives::Slot};

use crate::column_backfill::{
    BackfillColumnProvider, COLUMN_BACKFILL_REQ_TIMEOUT, ColumnBackfillError,
};
use crate::network_backfill_provider::PeerPicker;

// ── NetworkColumnBackfillProvider ───────────────────────────────────────────────

/// Production `BackfillColumnProvider` that issues `DataColumnSidecarsByRange`
/// via the p2p network.
pub struct NetworkColumnBackfillProvider<E: BeaconSpec> {
    cmd: NetworkCommandSender<E>,
    peer_picker: Arc<dyn PeerPicker>,
}

impl<E: BeaconSpec> NetworkColumnBackfillProvider<E> {
    /// Create a new provider using the given command sender and peer picker.
    pub fn new(cmd: NetworkCommandSender<E>, peer_picker: Arc<dyn PeerPicker>) -> Self {
        Self { cmd, peer_picker }
    }
}

impl<E: BeaconSpec> BackfillColumnProvider<E> for NetworkColumnBackfillProvider<E> {
    async fn data_columns_by_range(
        &self,
        start_slot: Slot,
        count: u64,
        columns: Vec<u64>,
    ) -> Result<Vec<DataColumnSidecar<4096, 4>>, ColumnBackfillError> {
        // `SszList::from_vec` enforces the wire bound `List[ColumnIndex,
        // NUMBER_OF_COLUMNS]`; an over-long list surfaces as a `Provider` error.
        let columns_ssz = SszList::from_vec(columns)
            .map_err(|e| ColumnBackfillError::Provider(format!("column list too long: {e}")))?;

        let req = RpcRequest::DataColumnSidecarsByRange(DataColumnSidecarsByRangeRequest {
            start_slot,
            count,
            columns: columns_ssz,
        });

        // Primary attempt.
        let peer1 = self
            .peer_picker
            .pick_highest_head_peer()
            .await
            .ok_or(ColumnBackfillError::NoUsablePeers)?;

        match self
            .cmd
            .request(peer1, req.clone(), COLUMN_BACKFILL_REQ_TIMEOUT)
            .await
        {
            Ok(RpcResponse::DataColumnSidecars(v)) => return Ok(v),
            Ok(other) => {
                return Err(ColumnBackfillError::Provider(format!(
                    "unexpected response variant: {other:?}"
                )));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    peer = ?peer1,
                    "column backfill: primary peer failed; trying next-best"
                );
            }
        }

        // Single retry against the next-best peer (may be the same peer if only
        // one is connected — acceptable, mirrors `NetworkBackfillProvider`).
        let peer2 = self
            .peer_picker
            .pick_highest_head_peer()
            .await
            .ok_or(ColumnBackfillError::NoUsablePeers)?;

        match self
            .cmd
            .request(peer2, req, COLUMN_BACKFILL_REQ_TIMEOUT)
            .await
        {
            Ok(RpcResponse::DataColumnSidecars(v)) => Ok(v),
            Ok(other) => Err(ColumnBackfillError::Provider(format!(
                "unexpected response variant: {other:?}"
            ))),
            Err(_) => Err(ColumnBackfillError::NoUsablePeers),
        }
    }
}
