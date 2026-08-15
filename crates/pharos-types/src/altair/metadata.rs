//! Altair `MetaData` (v2) per `specs/altair/p2p-interface.md:120-139`.
//!
//! Extends the Phase-0 `MetaData` with a `syncnets` field that encodes which
//! sync-committee subnets the local node subscribes to.

use pharos_ssz::{Bitvector, Decode, Encode, TreeHash};

use crate::altair::constants::SYNC_COMMITTEE_SUBNET_COUNT;
use crate::phase0::primitives::ATTESTATION_SUBNET_COUNT;

/// `MetaData` v2 per `specs/altair/p2p-interface.md:120-139`.
///
/// Served over `/eth2/beacon_chain/req/metadata/2/ssz_snappy`.  Peers that
/// only speak `/metadata/1` receive a truncated `phase0::MetaData` (without
/// `syncnets`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct MetaData {
    /// Monotonically increasing sequence number.
    ///
    /// Bumped on every change to `attnets` or `syncnets`.
    /// Per `specs/altair/p2p-interface.md:123`.
    pub seq_number: u64,
    /// Attestation subnet subscriptions bitfield.
    ///
    /// `Bitvector[ATTESTATION_SUBNET_COUNT]` per `p2p-interface.md:125`.
    pub attnets: Bitvector<{ ATTESTATION_SUBNET_COUNT }>,
    /// Sync-committee subnet subscriptions bitfield.
    ///
    /// `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]` per `p2p-interface.md:127-139`.
    pub syncnets: Bitvector<{ SYNC_COMMITTEE_SUBNET_COUNT }>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// SSZ roundtrip: `decode(encode(default())) == default()`.
    #[test]
    fn metadata_ssz_roundtrip() {
        let original = MetaData::default();
        let bytes = original.as_ssz_bytes();
        let decoded = MetaData::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_eq!(decoded, original);
    }

    /// SSZ roundtrip with non-default values.
    #[test]
    fn metadata_ssz_roundtrip_non_default() {
        let mut attnets = Bitvector::<{ ATTESTATION_SUBNET_COUNT }>::default();
        attnets.set(0, true);
        attnets.set(3, true);
        let mut syncnets = Bitvector::<{ SYNC_COMMITTEE_SUBNET_COUNT }>::default();
        syncnets.set(1, true);
        let original = MetaData {
            seq_number: 42,
            attnets,
            syncnets,
        };

        let bytes = original.as_ssz_bytes();
        let decoded = MetaData::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_eq!(decoded, original);
    }

    /// `syncnets` field is present and independently settable.
    #[test]
    fn syncnets_field_independent() {
        let mut syncnets = Bitvector::<{ SYNC_COMMITTEE_SUBNET_COUNT }>::default();
        syncnets.set(2, true);
        let md = MetaData {
            syncnets,
            ..MetaData::default()
        };
        assert!(md.syncnets.get(2).unwrap_or(false));
        // attnets unaffected.
        assert!(!md.attnets.get(0).unwrap_or(true));
    }
}
