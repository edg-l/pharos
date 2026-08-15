//! Gossipsub topic subscription, message dispatch, and validation bridge.
//!
//! - `subscribe_phase0_topics`: subscribe to the standard Phase-0 gossip topics.
//! - `dispatch_gossip_message`: decode + validate an incoming gossip message.
//!
//! Topic list per `specs/phase0/p2p-interface.md:507-514`.

pub mod config;
pub mod message_id;

use std::collections::HashMap;

use libp2p::gossipsub::{self, IdentTopic, TopicHash};
use pharos_ssz::Bitvector;
use pharos_ssz::Decode as _;
use pharos_types::EthSpec;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use pharos_types::phase0::{
    Attestation, AttesterSlashing, ProposerSlashing, SignedAggregateAndProof, SignedVoluntaryExit,
};

use crate::codec::{MAX_PAYLOAD_SIZE, snappy_frame::decode_snappy_frame};
use crate::error::NetworkError;
use crate::host::{GossipVerdict, Host};
use crate::topics::{GossipTopic, GossipTopicKind};
use crate::types::ForkDigest;

// ── subscribe_phase0_topics ───────────────────────────────────────────────────

/// Subscribe to all Phase-0 gossipsub topics for the given fork and attnets mask.
///
/// Subscribes to the five base topics (`beacon_block`, `beacon_aggregate_and_proof`,
/// `voluntary_exit`, `proposer_slashing`, `attester_slashing`) plus
/// `beacon_attestation_<i>` for each bit `i` set in `attnets`.
///
/// Topic list per `specs/phase0/p2p-interface.md:507-514`.
pub fn subscribe_phase0_topics(
    gs: &mut gossipsub::Behaviour,
    fork_digest: ForkDigest,
    attnets: &Bitvector<ATTESTATION_SUBNET_COUNT>,
) -> Result<HashMap<TopicHash, GossipTopic>, NetworkError> {
    let mut topic_map = HashMap::new();

    let base_kinds = [
        GossipTopicKind::BeaconBlock,
        GossipTopicKind::BeaconAggregateAndProof,
        GossipTopicKind::VoluntaryExit,
        GossipTopicKind::ProposerSlashing,
        GossipTopicKind::AttesterSlashing,
    ];

    for kind in base_kinds {
        let topic = GossipTopic { fork_digest, kind };
        let ident = IdentTopic::new(topic.topic_str());
        gs.subscribe(&ident)
            .map_err(|e| NetworkError::Libp2p(format!("subscribe failed: {e}")))?;
        topic_map.insert(topic.topic_hash(), topic);
    }

    for (i, bit) in attnets.iter().enumerate() {
        if bit {
            let topic = GossipTopic {
                fork_digest,
                kind: GossipTopicKind::BeaconAttestation(i as u64),
            };
            let ident = IdentTopic::new(topic.topic_str());
            gs.subscribe(&ident)
                .map_err(|e| NetworkError::Libp2p(format!("subscribe attnets failed: {e}")))?;
            topic_map.insert(topic.topic_hash(), topic);
        }
    }

    Ok(topic_map)
}

// ── dispatch_gossip_message ───────────────────────────────────────────────────

/// Decode and validate an incoming gossip message, returning a `GossipVerdict`.
///
/// Steps:
/// 1. Snappy-decompress `raw_data` with `MAX_PAYLOAD_SIZE` cap.
/// 2. SSZ-decode by `topic.kind` and dispatch to the appropriate `host` validator.
/// 3. Return the host's verdict.
///
/// Failures at step 1 return `GossipVerdict::Reject("snappy decode")`.
/// Failures at step 2 return `GossipVerdict::Reject("ssz decode")`.
pub fn dispatch_gossip_message<E: EthSpec, H: Host<E>>(
    host: &H,
    topic: &GossipTopic,
    raw_data: &[u8],
) -> GossipVerdict {
    let decompressed = match decode_snappy_frame(raw_data, MAX_PAYLOAD_SIZE) {
        Ok(d) => d,
        Err(_) => return GossipVerdict::Reject("snappy decode".to_string()),
    };

    match &topic.kind {
        GossipTopicKind::BeaconBlock => match E::SignedBeaconBlock::from_ssz_bytes(&decompressed) {
            Ok(block) => host.validate_beacon_block(&block),
            Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
        },
        GossipTopicKind::BeaconAggregateAndProof => {
            match SignedAggregateAndProof::<2048>::from_ssz_bytes(&decompressed) {
                Ok(saap) => host.validate_aggregate_and_proof(&saap.message),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        GossipTopicKind::BeaconAttestation(subnet) => {
            match Attestation::<2048>::from_ssz_bytes(&decompressed) {
                Ok(att) => host.validate_attestation(*subnet, &att),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        GossipTopicKind::VoluntaryExit => {
            match SignedVoluntaryExit::from_ssz_bytes(&decompressed) {
                Ok(sve) => host.validate_voluntary_exit(&sve),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        GossipTopicKind::ProposerSlashing => {
            match ProposerSlashing::from_ssz_bytes(&decompressed) {
                Ok(ps) => host.validate_proposer_slashing(&ps),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        GossipTopicKind::AttesterSlashing => {
            match AttesterSlashing::<2048>::from_ssz_bytes(&decompressed) {
                Ok(as_slash) => host.validate_attester_slashing(&as_slash),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::gossipsub::MessageAuthenticity;
    use pharos_ssz::Encode as _;
    use pharos_types::MainnetEthSpec;
    use pharos_types::phase0::primitives::ForkDigest;
    use pharos_types::phase0::{
        AggregateAndProof, Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing,
        Root, SignedVoluntaryExit, Slot,
    };
    use pharos_utils::{Bytes4, Epoch};

    use crate::codec::snappy_frame::encode_snappy_frame;
    use crate::gossip::config::gossipsub_config;
    use crate::host::{BlockProvider, ForkContext, GossipValidator, GossipVerdict};
    use crate::types::SubnetId;

    // ── MockHost ─────────────────────────────────────────────────────────────

    struct MockHost;

    impl ForkContext for MockHost {
        fn current_fork_digest(&self) -> ForkDigest {
            ForkDigest::from_array([0u8; 4])
        }
        fn enr_fork_id(&self) -> ENRForkID {
            ENRForkID {
                fork_digest: Bytes4::from_array([0u8; 4]),
                next_fork_version: Bytes4::from_array([0u8; 4]),
                next_fork_epoch: Epoch(u64::MAX),
            }
        }
        fn genesis_validators_root(&self) -> Root {
            Root::default()
        }
    }

    impl BlockProvider<MainnetEthSpec> for MockHost {
        fn block_by_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            unreachable!()
        }
        fn blocks_by_range(
            &self,
            _start_slot: Slot,
            _count: u64,
        ) -> Vec<<MainnetEthSpec as EthSpec>::SignedBeaconBlock> {
            unreachable!()
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            unreachable!()
        }
        fn head(&self) -> (Root, Slot) {
            unreachable!()
        }
    }

    impl GossipValidator<MainnetEthSpec> for MockHost {
        fn validate_beacon_block(
            &self,
            _block: &<MainnetEthSpec as EthSpec>::SignedBeaconBlock,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_attestation(
            &self,
            _subnet: SubnetId,
            _att: &Attestation<2048>,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_aggregate_and_proof(&self, _msg: &AggregateAndProof<2048>) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_voluntary_exit(&self, _exit: &SignedVoluntaryExit) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_proposer_slashing(&self, _slashing: &ProposerSlashing) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_attester_slashing(&self, _slashing: &AttesterSlashing<2048>) -> GossipVerdict {
            GossipVerdict::Accept
        }
    }

    // ── subscribe_phase0_topics tests ─────────────────────────────────────────

    fn make_gossipsub() -> gossipsub::Behaviour {
        let cfg = gossipsub_config::<MainnetEthSpec>().expect("config failed");
        gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, cfg).expect("behaviour failed")
    }

    /// After `subscribe_phase0_topics` with bits 0 and 5 set, unsubscribing
    /// each expected topic returns `true` (proves it was subscribed).
    #[test]
    fn subscribe_phase0_topics_subscribes_expected_topics() {
        let mut gs = make_gossipsub();
        let fork_digest = ForkDigest::from_array([1, 2, 3, 4]);

        let mut attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();
        attnets.set(0, true);
        attnets.set(5, true);

        subscribe_phase0_topics(&mut gs, fork_digest, &attnets)
            .expect("subscribe_phase0_topics failed");

        // Verify the 5 base topics.
        let base_kinds = [
            GossipTopicKind::BeaconBlock,
            GossipTopicKind::BeaconAggregateAndProof,
            GossipTopicKind::VoluntaryExit,
            GossipTopicKind::ProposerSlashing,
            GossipTopicKind::AttesterSlashing,
        ];
        for kind in base_kinds {
            let topic = GossipTopic { fork_digest, kind };
            let ident = IdentTopic::new(topic.topic_str());
            assert!(
                gs.unsubscribe(&ident),
                "expected subscription to {:?}",
                topic.topic_str()
            );
        }

        // Verify attestation subnets 0 and 5.
        for subnet in [0u64, 5u64] {
            let topic = GossipTopic {
                fork_digest,
                kind: GossipTopicKind::BeaconAttestation(subnet),
            };
            let ident = IdentTopic::new(topic.topic_str());
            assert!(
                gs.unsubscribe(&ident),
                "expected subscription to beacon_attestation_{subnet}"
            );
        }
    }

    // ── dispatch_gossip_message tests ─────────────────────────────────────────

    /// A valid `ProposerSlashing` SSZ+snappy payload dispatches as `Accept`.
    #[test]
    fn dispatch_proposer_slashing_accept() {
        let host = MockHost;
        let fork_digest = ForkDigest::from_array([0u8; 4]);
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::ProposerSlashing,
        };

        let slashing = ProposerSlashing::default();
        let ssz = slashing.as_ssz_bytes();
        let raw = encode_snappy_frame(&ssz).expect("encode failed");

        let verdict = dispatch_gossip_message::<MainnetEthSpec, MockHost>(&host, &topic, &raw);
        assert!(
            matches!(verdict, GossipVerdict::Accept),
            "expected Accept, got {verdict:?}"
        );
    }

    /// Garbage bytes (not valid snappy) return `Reject("snappy decode")`.
    #[test]
    fn dispatch_snappy_decode_failure() {
        let host = MockHost;
        let fork_digest = ForkDigest::from_array([0u8; 4]);
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::ProposerSlashing,
        };

        let garbage = b"this is not snappy framed data at all!!!!";
        let verdict = dispatch_gossip_message::<MainnetEthSpec, MockHost>(&host, &topic, garbage);
        assert!(
            matches!(&verdict, GossipVerdict::Reject(r) if r == "snappy decode"),
            "expected Reject(snappy decode), got {verdict:?}"
        );
    }
}
