//! Gossipsub topic scheme: topic strings, hashes, and parsing.
//!
//! Topic string format per `specs/phase0/p2p-interface.md:457-472`:
//! `/eth2/<hex_fork_digest>/<name>/ssz_snappy`
//!
//! Topic name table per `p2p-interface.md:507-514`:
//! - `beacon_block`
//! - `beacon_aggregate_and_proof`
//! - `beacon_attestation_<subnet_id>` (decimal, no padding)
//! - `voluntary_exit`
//! - `proposer_slashing`
//! - `attester_slashing`

use std::collections::HashMap;

use libp2p::gossipsub::{IdentTopic, TopicHash};
use pharos_types::altair::SYNC_COMMITTEE_SUBNET_COUNT;

use crate::error::NetworkError;
use crate::types::{ForkDigest, SubnetId};

// ── GossipTopicKind ───────────────────────────────────────────────────────────

/// The kind of gossip topic, distinguishing the Phase-0, Altair, and Capella topics.
///
/// Phase-0 topics per `specs/phase0/p2p-interface.md:507-514`.
/// Altair topics per `specs/altair/p2p-interface.md:184-188` and
/// `specs/altair/light-client/p2p-interface.md:47-48`.
/// Capella topics per `specs/capella/p2p-interface.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipTopicKind {
    // ── Phase-0 topics ────────────────────────────────────────────────────────
    BeaconBlock,
    BeaconAggregateAndProof,
    /// Per-subnet attestation topic; the inner value is the subnet id (0-63).
    BeaconAttestation(SubnetId),
    VoluntaryExit,
    ProposerSlashing,
    AttesterSlashing,
    // ── Altair topics ─────────────────────────────────────────────────────────
    /// `sync_committee_contribution_and_proof` per `specs/altair/p2p-interface.md:186`.
    SyncCommitteeContributionAndProof,
    /// `sync_committee_<i>` per `specs/altair/p2p-interface.md:185`.
    /// Inner value is the sync-committee subnet id (0..SYNC_COMMITTEE_SUBNET_COUNT).
    SyncCommittee(SubnetId),
    /// `light_client_finality_update` per `specs/altair/light-client/p2p-interface.md:47`.
    LightClientFinalityUpdate,
    /// `light_client_optimistic_update` per `specs/altair/light-client/p2p-interface.md:48`.
    LightClientOptimisticUpdate,
    // ── Capella topics ────────────────────────────────────────────────────────
    /// `bls_to_execution_change` per `specs/capella/p2p-interface.md`.
    ///
    /// Propagates `SignedBLSToExecutionChange` messages to all potential block
    /// proposers. The message type is defined in `specs/capella/beacon-chain.md`.
    BlsToExecutionChange,
}

// ── GossipTopic ───────────────────────────────────────────────────────────────

/// A fully qualified Ethereum gossipsub topic.
///
/// Carries both the fork-digest (for fork isolation) and the topic kind (for
/// message dispatch).  Use `topic_str()` to produce the wire-format string and
/// `topic_hash()` to get the `TopicHash` used by libp2p.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipTopic {
    pub fork_digest: ForkDigest,
    pub kind: GossipTopicKind,
}

impl GossipTopic {
    /// Returns the wire-format topic string.
    ///
    /// Format: `/eth2/<hex_fork_digest>/<name>/ssz_snappy`
    /// per `p2p-interface.md:457-472`.
    pub fn topic_str(&self) -> String {
        let digest = self.fork_digest.into_inner();
        let hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        );
        let name = topic_kind_name(&self.kind);
        format!("/eth2/{hex}/{name}/ssz_snappy")
    }

    /// Returns the `TopicHash` for this topic.
    ///
    /// Equivalent to `IdentTopic::new(self.topic_str()).hash()`.
    pub fn topic_hash(&self) -> TopicHash {
        IdentTopic::new(self.topic_str()).hash()
    }

    /// Look up a `GossipTopic` by its `TopicHash` in the local subscription map.
    ///
    /// The network's `topic_map` (`HashMap<TopicHash, GossipTopic>`) is built
    /// from the topics subscribed at startup via `subscribe_base_topics`.
    /// Returns `NetworkError::InvalidTopic` when the hash is not present (e.g.
    /// a peer subscribed to a topic we are not tracking).
    pub fn from_topic_hash(
        hash: &TopicHash,
        map: &HashMap<TopicHash, GossipTopic>,
    ) -> Result<GossipTopic, NetworkError> {
        map.get(hash).cloned().ok_or_else(|| {
            NetworkError::InvalidTopic(format!("topic hash not in local subscription map: {hash}"))
        })
    }

    /// Parse a topic string into a `GossipTopic`.
    ///
    /// Expects exactly 5 slash-separated segments:
    /// `["", "eth2", "<8-hex-chars>", "<name>", "ssz_snappy"]`
    ///
    /// Returns `NetworkError::InvalidTopic` on any deviation.
    pub fn parse(s: &str) -> Result<Self, NetworkError> {
        let parts: Vec<&str> = s.split('/').collect();
        // Split "/eth2/..." produces ["", "eth2", hex, name, encoding].
        if parts.len() != 5 {
            return Err(NetworkError::InvalidTopic(format!(
                "expected 5 segments, got {}: {s:?}",
                parts.len()
            )));
        }
        if !parts[0].is_empty() {
            return Err(NetworkError::InvalidTopic(format!(
                "topic must start with '/': {s:?}"
            )));
        }
        if parts[1] != "eth2" {
            return Err(NetworkError::InvalidTopic(format!(
                "expected 'eth2' prefix, got {:?}: {s:?}",
                parts[1]
            )));
        }
        if parts[4] != "ssz_snappy" {
            return Err(NetworkError::InvalidTopic(format!(
                "expected 'ssz_snappy' encoding, got {:?}: {s:?}",
                parts[4]
            )));
        }

        let hex_str = parts[2];
        if hex_str.len() != 8 {
            return Err(NetworkError::InvalidTopic(format!(
                "fork digest hex must be 8 chars, got {}: {s:?}",
                hex_str.len()
            )));
        }
        let mut digest_bytes = [0u8; 4];
        for (i, byte) in digest_bytes.iter_mut().enumerate() {
            let hi = hex_nibble(hex_str.as_bytes()[i * 2]).map_err(|_| {
                NetworkError::InvalidTopic(format!("invalid hex in fork digest: {s:?}"))
            })?;
            let lo = hex_nibble(hex_str.as_bytes()[i * 2 + 1]).map_err(|_| {
                NetworkError::InvalidTopic(format!("invalid hex in fork digest: {s:?}"))
            })?;
            *byte = (hi << 4) | lo;
        }
        let fork_digest = ForkDigest::from_array(digest_bytes);

        let name = parts[3];
        let kind = parse_topic_kind(name).ok_or_else(|| {
            NetworkError::InvalidTopic(format!("unknown topic name: {name:?} in {s:?}"))
        })?;

        Ok(GossipTopic { fork_digest, kind })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Map a `GossipTopicKind` to its wire-format name string.
fn topic_kind_name(kind: &GossipTopicKind) -> String {
    match kind {
        GossipTopicKind::BeaconBlock => "beacon_block".to_string(),
        GossipTopicKind::BeaconAggregateAndProof => "beacon_aggregate_and_proof".to_string(),
        GossipTopicKind::BeaconAttestation(subnet) => format!("beacon_attestation_{subnet}"),
        GossipTopicKind::VoluntaryExit => "voluntary_exit".to_string(),
        GossipTopicKind::ProposerSlashing => "proposer_slashing".to_string(),
        GossipTopicKind::AttesterSlashing => "attester_slashing".to_string(),
        // Altair topics — `specs/altair/p2p-interface.md:184-188` and
        // `specs/altair/light-client/p2p-interface.md:47-48`.
        GossipTopicKind::SyncCommitteeContributionAndProof => {
            "sync_committee_contribution_and_proof".to_string()
        }
        GossipTopicKind::SyncCommittee(subnet) => format!("sync_committee_{subnet}"),
        GossipTopicKind::LightClientFinalityUpdate => "light_client_finality_update".to_string(),
        GossipTopicKind::LightClientOptimisticUpdate => {
            "light_client_optimistic_update".to_string()
        }
        // Capella topics — `specs/capella/p2p-interface.md`.
        GossipTopicKind::BlsToExecutionChange => "bls_to_execution_change".to_string(),
    }
}

/// Parse a topic kind from its wire-format name string.
///
/// Returns `None` for unknown names.
fn parse_topic_kind(name: &str) -> Option<GossipTopicKind> {
    match name {
        "beacon_block" => Some(GossipTopicKind::BeaconBlock),
        "beacon_aggregate_and_proof" => Some(GossipTopicKind::BeaconAggregateAndProof),
        "voluntary_exit" => Some(GossipTopicKind::VoluntaryExit),
        "proposer_slashing" => Some(GossipTopicKind::ProposerSlashing),
        "attester_slashing" => Some(GossipTopicKind::AttesterSlashing),
        "sync_committee_contribution_and_proof" => {
            Some(GossipTopicKind::SyncCommitteeContributionAndProof)
        }
        "light_client_finality_update" => Some(GossipTopicKind::LightClientFinalityUpdate),
        "light_client_optimistic_update" => Some(GossipTopicKind::LightClientOptimisticUpdate),
        "bls_to_execution_change" => Some(GossipTopicKind::BlsToExecutionChange),
        _ => {
            // Handle `beacon_attestation_<decimal-subnet-id>`.
            if let Some(subnet_str) = name.strip_prefix("beacon_attestation_") {
                let subnet_id: SubnetId = subnet_str.parse().ok()?;
                return Some(GossipTopicKind::BeaconAttestation(subnet_id));
            }
            // Handle `sync_committee_<decimal-subnet-id>`.
            if let Some(subnet_str) = name.strip_prefix("sync_committee_") {
                let subnet_id: SubnetId = subnet_str.parse().ok()?;
                if subnet_id >= SYNC_COMMITTEE_SUBNET_COUNT {
                    return None;
                }
                return Some(GossipTopicKind::SyncCommittee(subnet_id));
            }
            None
        }
    }
}

/// Decode a single lowercase hex nibble.
fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: [u8; 4]) -> ForkDigest {
        ForkDigest::from_array(bytes)
    }

    fn topic(fd: [u8; 4], kind: GossipTopicKind) -> GossipTopic {
        GossipTopic {
            fork_digest: digest(fd),
            kind,
        }
    }

    /// Every variant round-trips through `topic_str()` -> `parse()`.
    #[test]
    fn roundtrip_all_variants() {
        let fd = [0xde, 0xad, 0xbe, 0xef];
        let cases = vec![
            // Phase-0 topics.
            topic(fd, GossipTopicKind::BeaconBlock),
            topic(fd, GossipTopicKind::BeaconAggregateAndProof),
            topic(fd, GossipTopicKind::BeaconAttestation(0)),
            topic(fd, GossipTopicKind::BeaconAttestation(63)),
            topic(fd, GossipTopicKind::VoluntaryExit),
            topic(fd, GossipTopicKind::ProposerSlashing),
            topic(fd, GossipTopicKind::AttesterSlashing),
            // Altair topics.
            topic(fd, GossipTopicKind::SyncCommitteeContributionAndProof),
            topic(fd, GossipTopicKind::SyncCommittee(0)),
            topic(fd, GossipTopicKind::SyncCommittee(3)),
            topic(fd, GossipTopicKind::LightClientFinalityUpdate),
            topic(fd, GossipTopicKind::LightClientOptimisticUpdate),
            // Capella topics.
            topic(fd, GossipTopicKind::BlsToExecutionChange),
        ];
        for t in &cases {
            let s = t.topic_str();
            let parsed =
                GossipTopic::parse(&s).unwrap_or_else(|e| panic!("parse failed for {:?}: {e}", s));
            assert_eq!(&parsed, t, "roundtrip failed for {s:?}");
        }
    }

    /// `topic_str` for altair `sync_committee_contribution_and_proof`.
    #[test]
    fn topic_str_sync_committee_contribution_and_proof() {
        let t = topic(
            [0x01, 0x02, 0x03, 0x04],
            GossipTopicKind::SyncCommitteeContributionAndProof,
        );
        assert_eq!(
            t.topic_str(),
            "/eth2/01020304/sync_committee_contribution_and_proof/ssz_snappy"
        );
    }

    /// `topic_str` for altair `sync_committee_<i>`.
    #[test]
    fn topic_str_sync_committee_subnet_2() {
        let t = topic([0x01, 0x02, 0x03, 0x04], GossipTopicKind::SyncCommittee(2));
        assert_eq!(t.topic_str(), "/eth2/01020304/sync_committee_2/ssz_snappy");
    }

    /// `topic_str` for altair `light_client_finality_update`.
    #[test]
    fn topic_str_light_client_finality_update() {
        let t = topic(
            [0x01, 0x02, 0x03, 0x04],
            GossipTopicKind::LightClientFinalityUpdate,
        );
        assert_eq!(
            t.topic_str(),
            "/eth2/01020304/light_client_finality_update/ssz_snappy"
        );
    }

    /// Out-of-range sync-committee subnet ids must fail to parse.
    #[test]
    fn parse_rejects_out_of_range_sync_committee_subnet() {
        let oor = format!("/eth2/01020304/sync_committee_{SYNC_COMMITTEE_SUBNET_COUNT}/ssz_snappy");
        assert!(
            GossipTopic::parse(&oor).is_err(),
            "expected error for subnet id == SYNC_COMMITTEE_SUBNET_COUNT, got Ok for {oor:?}"
        );
        let way_oor = "/eth2/01020304/sync_committee_99999/ssz_snappy";
        assert!(
            GossipTopic::parse(way_oor).is_err(),
            "expected error for subnet id 99999"
        );
    }

    /// `topic_str` for altair `light_client_optimistic_update`.
    #[test]
    fn topic_str_light_client_optimistic_update() {
        let t = topic(
            [0x01, 0x02, 0x03, 0x04],
            GossipTopicKind::LightClientOptimisticUpdate,
        );
        assert_eq!(
            t.topic_str(),
            "/eth2/01020304/light_client_optimistic_update/ssz_snappy"
        );
    }

    /// `topic_str` for a known topic produces the expected string.
    #[test]
    fn topic_str_beacon_block() {
        let t = topic([0x01, 0x02, 0x03, 0x04], GossipTopicKind::BeaconBlock);
        assert_eq!(t.topic_str(), "/eth2/01020304/beacon_block/ssz_snappy");
    }

    /// `topic_str` for a BeaconAttestation with subnet 7.
    #[test]
    fn topic_str_attestation_subnet_7() {
        let t = topic(
            [0x00, 0x00, 0x00, 0x00],
            GossipTopicKind::BeaconAttestation(7),
        );
        assert_eq!(
            t.topic_str(),
            "/eth2/00000000/beacon_attestation_7/ssz_snappy"
        );
    }

    /// `topic_hash()` is deterministic and matches `IdentTopic::new(str).hash()`.
    #[test]
    fn topic_hash_deterministic() {
        let t = topic([0xff, 0x00, 0xff, 0x00], GossipTopicKind::ProposerSlashing);
        assert_eq!(t.topic_hash(), t.topic_hash());
        let expected = IdentTopic::new(t.topic_str()).hash();
        assert_eq!(t.topic_hash(), expected);
    }

    // ── Negative cases ────────────────────────────────────────────────────────

    #[test]
    fn parse_rejects_trailing_slash() {
        assert!(GossipTopic::parse("/eth2/01020304/beacon_block/ssz_snappy/").is_err());
    }

    #[test]
    fn parse_rejects_wrong_protocol_prefix() {
        assert!(GossipTopic::parse("/eth3/01020304/beacon_block/ssz_snappy").is_err());
    }

    #[test]
    fn parse_rejects_non_hex_fork_digest() {
        assert!(GossipTopic::parse("/eth2/GHIJKLMN/beacon_block/ssz_snappy").is_err());
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        // Only lowercase is valid per our encoder; uppercase chars are invalid.
        assert!(GossipTopic::parse("/eth2/DEADBEEF/beacon_block/ssz_snappy").is_err());
    }

    #[test]
    fn parse_rejects_unknown_name() {
        assert!(GossipTopic::parse("/eth2/01020304/unknown_topic/ssz_snappy").is_err());
    }

    #[test]
    fn parse_rejects_wrong_encoding_suffix() {
        assert!(GossipTopic::parse("/eth2/01020304/beacon_block/snappy").is_err());
    }

    #[test]
    fn parse_rejects_short_fork_digest() {
        assert!(GossipTopic::parse("/eth2/0102/beacon_block/ssz_snappy").is_err());
    }
}
