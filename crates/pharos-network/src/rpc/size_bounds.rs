//! Per-method SSZ size bounds for req-resp length validation.
//!
//! Used by the codec to reject payloads whose declared SSZ length is outside
//! the expected range before reading the compressed body.

use crate::rpc::types::{
    MAX_REQUEST_BLOB_SIDECARS, MAX_REQUEST_BLOCKS, MAX_REQUEST_BLOCKS_DENEB, NUMBER_OF_COLUMNS,
};
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
        // v2 altair MetaData: seq_number(8) + attnets Bitvector[64](8) + syncnets Bitvector[4](1) = 17 bytes minimum.
        // syncnets is Bitvector<4>; SSZ encodes it as 1 byte (ceil(4/8) = 1 byte), not 4/8 of a byte.
        RpcMethod::MetaData => (17, 64), // lower bound 17 (altair MetaData minimum); ceiling 64 for future additions
        RpcMethod::MetaDataV1 => (16, 16),
        // start_slot(8) + count(8) + step(8) = 24
        RpcMethod::BlocksByRange => (24, 24),
        // SszList<Root, MAX_REQUEST_BLOCKS>: 0 to MAX_REQUEST_BLOCKS * 32 bytes
        RpcMethod::BlocksByRoot => (0, (MAX_REQUEST_BLOCKS as usize) * 32),
        // Light-client request bodies: bounded by respective spec limits.
        // LightClientBootstrap request: one Root = 32 bytes.
        RpcMethod::LightClientBootstrap => (32, 32),
        // LightClientUpdatesByRange request: start_period(8) + count(8) = 16 bytes.
        RpcMethod::LightClientUpdatesByRange => (16, 16),
        // LightClientFinalityUpdate and LightClientOptimisticUpdate have no request body.
        RpcMethod::LightClientFinalityUpdate | RpcMethod::LightClientOptimisticUpdate => (0, 0),
        // BlobSidecarsByRange request: start_slot(8) + count(8) = 16 bytes.
        RpcMethod::BlobSidecarsByRange => (16, 16),
        // BlobSidecarsByRoot request: bare List[BlobIdentifier, N].
        // BlobIdentifier SSZ: block_root(32) + index(8) = 40 bytes each.
        // 0 to MAX_REQUEST_BLOB_SIDECARS entries.
        RpcMethod::BlobSidecarsByRoot => (0, (MAX_REQUEST_BLOB_SIDECARS as usize) * 40),
        // DataColumnSidecarsByRange request (SSZ container):
        // start_slot(8) + count(8) + offset(4) for the variable `columns` list = 20 min;
        // max adds NUMBER_OF_COLUMNS * 8 (ColumnIndex = u64) column entries.
        RpcMethod::DataColumnSidecarsByRange => (20, 20 + (NUMBER_OF_COLUMNS as usize) * 8),
        // DataColumnSidecarsByRoot request:
        // List[DataColumnsByRootIdentifier, MAX_REQUEST_BLOCKS_DENEB] — a list of
        // VARIABLE-size containers, so it is offset-prefixed. Each identifier is
        // block_root(32) + offset(4) + up to NUMBER_OF_COLUMNS * 8 (columns); plus
        // one 4-byte outer offset per element. 0 entries = 0 bytes.
        RpcMethod::DataColumnSidecarsByRoot => (
            0,
            (MAX_REQUEST_BLOCKS_DENEB as usize) * (4 + 32 + 4 + (NUMBER_OF_COLUMNS as usize) * 8),
        ),
        // BeaconBlocksByHead request (SSZ container): beacon_root(32) + count(8) = 40 bytes.
        RpcMethod::BeaconBlocksByHead => (40, 40),
        // Status v2 request: v1 fields (84) + earliest_available_slot(8) = 92 bytes.
        RpcMethod::StatusV2 => (92, 92),
        // MetaData v3 has no request body.
        RpcMethod::MetaDataV3 => (0, 0),
    }
}

/// Conservative upper bound on a light-client object SSZ encoding.
///
/// A `LightClientBootstrap` or `LightClientUpdate` carries sync-committee data
/// (BLS pubkeys × 512 = 48 × 512 = 24 KiB) plus headers and branches.
/// 64 KiB provides a generous ceiling for mainnet objects.
pub const MAX_LIGHT_CLIENT_OBJECT_SSZ_BYTES: usize = 64 * 1024;

/// Upper bound on a single `BlobSidecar` SSZ encoding.
///
/// `BlobSidecar` contains a 131072-byte blob plus headers and proof.
/// Total: ~131072 (blob) + 48 (kzg_commitment) + 48 (kzg_proof) + ~200 (header+proof) ≈ 132 KiB.
/// 200 KiB provides a safe ceiling.
pub const MAX_BLOB_SIDECAR_SSZ_BYTES: usize = 200 * 1024;

/// Upper bound on a single `DataColumnSidecar` SSZ encoding (EIP-7594).
///
/// A column carries one `Cell` (2048 bytes) per blob plus one `KZGCommitment`
/// (48) and one `KZGProof` (48) per blob, a `SignedBeaconBlockHeader`, and a
/// depth-4 inclusion proof. With the practical blob ceiling far below the
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK` SSZ bound, real columns are a few hundred
/// KiB; 10 MiB provides a generous ceiling against the theoretical list bound.
pub const MAX_DATA_COLUMN_SIDECAR_SSZ_BYTES: usize = 10 * 1024 * 1024;

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
        // MetaData v2 (altair): seq(8) + attnets(8) + syncnets(1) = 17; ceiling 64.
        assert_eq!(type_size_bounds(&RpcMethod::MetaData), (17, 64));
        // MetaData v1 (phase-0): seq(8) + attnets(8) = 16 (fixed).
        assert_eq!(type_size_bounds(&RpcMethod::MetaDataV1), (16, 16));
        assert_eq!(type_size_bounds(&RpcMethod::BlocksByRange), (24, 24));
        assert_eq!(type_size_bounds(&RpcMethod::BlocksByRoot), (0, 1024 * 32));
        // Light-client request bodies.
        assert_eq!(type_size_bounds(&RpcMethod::LightClientBootstrap), (32, 32));
        assert_eq!(
            type_size_bounds(&RpcMethod::LightClientUpdatesByRange),
            (16, 16)
        );
        assert_eq!(
            type_size_bounds(&RpcMethod::LightClientFinalityUpdate),
            (0, 0)
        );
        assert_eq!(
            type_size_bounds(&RpcMethod::LightClientOptimisticUpdate),
            (0, 0)
        );
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
