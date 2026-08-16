//! Ethereum CL req-resp protocol identifiers.
//!
//! Protocol strings per `specs/phase0/p2p-interface.md:1077-1092`. The grammar
//! is `/ProtocolPrefix/MessageName/SchemaVersion/Encoding` with no trailing
//! slash. Only `ssz_snappy` encoding exists per `p2p-interface.md:1239-1245`.

use crate::scoring::RpcMethod;

// ── RpcProtocol newtype ───────────────────────────────────────────────────────

/// A libp2p protocol identifier for a single Ethereum CL req-resp method.
///
/// Used as `request_response::Codec::Protocol`. The inner `RpcMethod` drives
/// which encode/decode path the codec takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcProtocol(pub RpcMethod);

impl AsRef<str> for RpcProtocol {
    fn as_ref(&self) -> &str {
        self.0.protocol_id()
    }
}

// ── Protocol ID table ─────────────────────────────────────────────────────────

impl RpcMethod {
    /// Returns the exact wire protocol string for this method.
    ///
    /// Strings are verbatim from `specs/phase0/p2p-interface.md`:
    /// - Status:        line 1321
    /// - Goodbye:       line 1380
    /// - Ping:          line 1408
    /// - MetaData:      line 1494 (v2 — v1 deprecated)
    /// - BlocksByRange: line 1545 (v2 — v1 deprecated)
    /// - BlocksByRoot:  line 1579 (v2 — v1 deprecated)
    ///
    /// Light-client protocol IDs per `specs/altair/light-client/p2p-interface.md`.
    /// Handlers are wired in Phase 6 (Task 6.5); IDs are declared here so the
    /// codec can match on them in Phase 5.
    pub fn protocol_id(&self) -> &'static str {
        match self {
            RpcMethod::Status => "/eth2/beacon_chain/req/status/1/ssz_snappy",
            RpcMethod::Goodbye => "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
            RpcMethod::Ping => "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            RpcMethod::MetaData => "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
            RpcMethod::MetaDataV1 => "/eth2/beacon_chain/req/metadata/1/ssz_snappy",
            RpcMethod::BlocksByRange => {
                "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
            }
            RpcMethod::BlocksByRoot => "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
            RpcMethod::LightClientBootstrap => {
                "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy"
            }
            RpcMethod::LightClientUpdatesByRange => {
                "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy"
            }
            RpcMethod::LightClientFinalityUpdate => {
                "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy"
            }
            RpcMethod::LightClientOptimisticUpdate => {
                "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy"
            }
            RpcMethod::BlobSidecarsByRange => {
                "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
            }
            RpcMethod::BlobSidecarsByRoot => {
                "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy"
            }
            RpcMethod::DataColumnSidecarsByRange => {
                "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
            }
            RpcMethod::DataColumnSidecarsByRoot => {
                "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
            }
            RpcMethod::BeaconBlocksByHead => {
                "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy"
            }
            RpcMethod::StatusV2 => "/eth2/beacon_chain/req/status/2/ssz_snappy",
            RpcMethod::MetaDataV3 => "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
        }
    }

    /// Returns `true` if this method's response chunks are prefixed with 4
    /// context bytes (the fork digest) per `specs/altair/p2p-interface.md:445-461`.
    ///
    /// `BlocksByRange` and `BlocksByRoot` use v2 protocol IDs and therefore carry
    /// context bytes. All four light-client methods also carry context bytes per
    /// the altair light-client p2p-interface spec.
    pub fn has_context_bytes(&self) -> bool {
        matches!(
            self,
            RpcMethod::BlocksByRange
                | RpcMethod::BlocksByRoot
                | RpcMethod::LightClientBootstrap
                | RpcMethod::LightClientUpdatesByRange
                | RpcMethod::LightClientFinalityUpdate
                | RpcMethod::LightClientOptimisticUpdate
                | RpcMethod::BlobSidecarsByRange
                | RpcMethod::BlobSidecarsByRoot
                | RpcMethod::DataColumnSidecarsByRange
                | RpcMethod::DataColumnSidecarsByRoot
                | RpcMethod::BeaconBlocksByHead
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_match_spec() {
        assert_eq!(
            RpcMethod::Status.protocol_id(),
            "/eth2/beacon_chain/req/status/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::Goodbye.protocol_id(),
            "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::Ping.protocol_id(),
            "/eth2/beacon_chain/req/ping/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::MetaData.protocol_id(),
            "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::MetaDataV1.protocol_id(),
            "/eth2/beacon_chain/req/metadata/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::BlocksByRange.protocol_id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::BlocksByRoot.protocol_id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::LightClientBootstrap.protocol_id(),
            "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::LightClientUpdatesByRange.protocol_id(),
            "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::LightClientFinalityUpdate.protocol_id(),
            "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::LightClientOptimisticUpdate.protocol_id(),
            "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::BlobSidecarsByRange.protocol_id(),
            "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::BlobSidecarsByRoot.protocol_id(),
            "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::DataColumnSidecarsByRange.protocol_id(),
            "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::DataColumnSidecarsByRoot.protocol_id(),
            "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::BeaconBlocksByHead.protocol_id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::StatusV2.protocol_id(),
            "/eth2/beacon_chain/req/status/2/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::MetaDataV3.protocol_id(),
            "/eth2/beacon_chain/req/metadata/3/ssz_snappy"
        );
    }

    #[test]
    fn has_context_bytes_correct() {
        // Methods WITH context bytes.
        for method in [
            RpcMethod::BlocksByRange,
            RpcMethod::BlocksByRoot,
            RpcMethod::LightClientBootstrap,
            RpcMethod::LightClientUpdatesByRange,
            RpcMethod::LightClientFinalityUpdate,
            RpcMethod::LightClientOptimisticUpdate,
        ] {
            assert!(
                method.has_context_bytes(),
                "{method:?} should have context bytes"
            );
        }
        // Blob sidecar methods have context bytes.
        for method in [
            RpcMethod::BlobSidecarsByRange,
            RpcMethod::BlobSidecarsByRoot,
        ] {
            assert!(
                method.has_context_bytes(),
                "{method:?} should have context bytes"
            );
        }
        // Fulu data-column + by-head methods have context bytes.
        for method in [
            RpcMethod::DataColumnSidecarsByRange,
            RpcMethod::DataColumnSidecarsByRoot,
            RpcMethod::BeaconBlocksByHead,
        ] {
            assert!(
                method.has_context_bytes(),
                "{method:?} should have context bytes"
            );
        }
        // Methods WITHOUT context bytes.
        for method in [
            RpcMethod::Status,
            RpcMethod::StatusV2,
            RpcMethod::Goodbye,
            RpcMethod::Ping,
            RpcMethod::MetaData,
            RpcMethod::MetaDataV1,
            RpcMethod::MetaDataV3,
        ] {
            assert!(
                !method.has_context_bytes(),
                "{method:?} should not have context bytes"
            );
        }
    }
}
