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
    pub fn protocol_id(&self) -> &'static str {
        match self {
            RpcMethod::Status => "/eth2/beacon_chain/req/status/1/ssz_snappy",
            RpcMethod::Goodbye => "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
            RpcMethod::Ping => "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            RpcMethod::MetaData => "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
            RpcMethod::BlocksByRange => {
                "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
            }
            RpcMethod::BlocksByRoot => "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
        }
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
            RpcMethod::BlocksByRange.protocol_id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
        );
        assert_eq!(
            RpcMethod::BlocksByRoot.protocol_id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
        );
    }
}
