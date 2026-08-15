//! Per-method SSZ size bounds for req-resp length validation.
//!
//! Used by the codec to reject payloads whose declared SSZ length is outside
//! the expected range before reading the compressed body.

use crate::rpc::types::MAX_REQUEST_BLOCKS;
use crate::scoring::RpcMethod;

/// Returns `(min_ssz_bytes, max_ssz_bytes)` for a req-resp method's payload.
///
/// For fixed-size types `min == max`. For variable-size types the range covers
/// the minimum (empty) and maximum (fully packed) SSZ encoding.
///
/// Derivation:
/// - `Status`:            4 + 32 + 8 + 32 + 8 = 84 bytes (all fixed fields).
/// - `Goodbye`:           u64 = 8 bytes.
/// - `Ping`:              u64 = 8 bytes.
/// - `MetaData`:          u64 (seq_number) + 8 (attnets Bitvector[64]) = 16 bytes.
/// - `BlocksByRange`:     u64 (start_slot) + u64 (count) + u64 (step) = 24 bytes.
/// - `BlocksByRoot`:      SszList of `Root` (32 bytes each), 0 to MAX_REQUEST_BLOCKS entries.
pub fn type_size_bounds(method: &RpcMethod) -> (usize, usize) {
    match method {
        // fork_digest(4) + finalized_root(32) + finalized_epoch(8) + head_root(32) + head_slot(8)
        RpcMethod::Status => (84, 84),
        RpcMethod::Goodbye => (8, 8),
        RpcMethod::Ping => (8, 8),
        // seq_number(8) + attnets Bitvector[64](8) = 16
        RpcMethod::MetaData => (16, 16),
        // start_slot(8) + count(8) + step(8) = 24
        RpcMethod::BlocksByRange => (24, 24),
        // SszList<Root, MAX_REQUEST_BLOCKS>: 0 to MAX_REQUEST_BLOCKS * 32 bytes
        RpcMethod::BlocksByRoot => (0, (MAX_REQUEST_BLOCKS as usize) * 32),
    }
}

/// Conservative upper bound on a Phase-0 `SignedBeaconBlock` SSZ encoding.
///
/// A fully-packed Phase-0 mainnet `SignedBeaconBlock` (max proposer slashings,
/// attester slashings, attestations, deposits, voluntary exits) encodes to
/// roughly 157 KiB. 200 KiB provides a safe ceiling with headroom.
///
/// This constant is used per-chunk when accumulating `BlocksByRange` /
/// `BlocksByRoot` responses.
pub const MAX_SIGNED_BEACON_BLOCK_SSZ_BYTES: usize = 200 * 1024;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_bounds_match_spec() {
        assert_eq!(type_size_bounds(&RpcMethod::Status), (84, 84));
        assert_eq!(type_size_bounds(&RpcMethod::Goodbye), (8, 8));
        assert_eq!(type_size_bounds(&RpcMethod::Ping), (8, 8));
        assert_eq!(type_size_bounds(&RpcMethod::MetaData), (16, 16));
        assert_eq!(type_size_bounds(&RpcMethod::BlocksByRange), (24, 24));
        assert_eq!(type_size_bounds(&RpcMethod::BlocksByRoot), (0, 1024 * 32));
    }

    /// Confirm Status SSZ encoding is exactly 84 bytes.
    #[test]
    fn status_ssz_size_is_84() {
        use pharos_ssz::Encode;
        use pharos_types::phase0::Status;
        let s = Status::default();
        assert_eq!(s.as_ssz_bytes().len(), 84);
    }

    /// Confirm MetaData SSZ encoding is exactly 16 bytes.
    #[test]
    fn metadata_ssz_size_is_16() {
        use pharos_ssz::Encode;
        use pharos_types::phase0::MetaData;
        let m = MetaData::default();
        assert_eq!(m.as_ssz_bytes().len(), 16);
    }

    /// Confirm BeaconBlocksByRangeRequest SSZ encoding is exactly 24 bytes.
    #[test]
    fn blocks_by_range_request_size_is_24() {
        use pharos_ssz::Encode;
        use pharos_types::phase0::BeaconBlocksByRangeRequest;
        let r = BeaconBlocksByRangeRequest::default();
        assert_eq!(r.as_ssz_bytes().len(), 24);
    }
}
