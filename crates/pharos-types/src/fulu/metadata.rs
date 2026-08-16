//! Fulu `MetaData` (v3) per `specs/fulu/p2p-interface.md` (`MetaData`).
//!
//! Extends the Altair `MetaData` (v2, which added `syncnets`) with a
//! `custody_group_count` (`cgc`) field communicating the node's custody-group
//! count for EIP-7594 PeerDAS.

use pharos_ssz::{Bitvector, Decode, Encode, TreeHash};

use crate::altair::constants::SYNC_COMMITTEE_SUBNET_COUNT;
use crate::phase0::primitives::ATTESTATION_SUBNET_COUNT;

/// `MetaData` v3 per `specs/fulu/p2p-interface.md` (`MetaData`).
///
/// Served over `/eth2/beacon_chain/req/metadata/3/ssz_snappy`. Peers that only
/// speak `/metadata/2` receive an Altair `MetaData` (without
/// `custody_group_count`); peers that only speak `/metadata/1` receive a
/// phase-0 `MetaData` (without `syncnets`). Tri-handle per
/// `D-metadata-v2-dual-handle` (extended to v3).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct MetaData {
    /// Monotonically increasing sequence number.
    ///
    /// Bumped on every change to `attnets`, `syncnets`, or `custody_group_count`.
    pub seq_number: u64,
    /// Attestation subnet subscriptions bitfield.
    ///
    /// `Bitvector[ATTESTATION_SUBNET_COUNT]`.
    pub attnets: Bitvector<{ ATTESTATION_SUBNET_COUNT }>,
    /// Sync-committee subnet subscriptions bitfield.
    ///
    /// `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]`.
    pub syncnets: Bitvector<{ SYNC_COMMITTEE_SUBNET_COUNT }>,
    /// `custody_group_count: uint64` (`cgc`) — the node's custody group count.
    pub custody_group_count: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// SSZ roundtrip: `decode(encode(default())) == default()`.
    #[test]
    fn metadata_v3_ssz_roundtrip_default() {
        let original = MetaData::default();
        let bytes = original.as_ssz_bytes();
        let decoded = MetaData::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_eq!(original, decoded);
    }

    /// A v3 `MetaData` carries the `custody_group_count` field through SSZ.
    #[test]
    fn metadata_v3_roundtrips_custody_group_count() {
        let original = MetaData {
            seq_number: 7,
            custody_group_count: 8,
            ..Default::default()
        };
        let bytes = original.as_ssz_bytes();
        let decoded = MetaData::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_eq!(decoded.custody_group_count, 8);
        assert_eq!(original, decoded);
    }
}
