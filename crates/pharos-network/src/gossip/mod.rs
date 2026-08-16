//! Gossipsub topic subscription, message dispatch, and validation bridge.
//!
//! - `subscribe_base_topics`: subscribe to the base beacon gossip topics under the
//!   supplied (active) fork digest, plus altair-era extras when active fork ≥ altair.
//! - `dispatch_gossip_message`: SSZ-decode + validate an already-decompressed
//!   gossip payload. Snappy decompression is the caller's responsibility (the
//!   network task pulls it out of `message.data` so the decompressed bytes
//!   can be reused for the event channel without a second decompress).
//!
//! Topic list per `specs/phase0/p2p-interface.md:507-514`.
//!
//! Encoding note: gossip uses snappy **block** (raw) compression per
//! `p2p-interface.md:1038-1048`. Req/resp uses snappy frames. The
//! `snappy_block` module in `codec/` owns gossip encode/decode and is
//! called from `network::on_gossip_message` before this dispatcher runs.

pub mod config;
pub mod message_id;

use std::collections::HashMap;

use libp2p::gossipsub::{self, IdentTopic, TopicHash};
use pharos_ssz::Bitvector;
use pharos_ssz::Decode as _;
use pharos_types::BeaconSpec;
use pharos_types::altair::SyncCommitteeMessage;
use pharos_types::capella::operations::SignedBLSToExecutionChange;
use pharos_types::deneb::BlobSidecar;
use pharos_types::electra::attestation::SingleAttestation;
use pharos_types::fulu::DataColumnSidecar;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use pharos_types::phase0::{
    Attestation, AttesterSlashing, ProposerSlashing, SignedAggregateAndProof, SignedVoluntaryExit,
};

use crate::error::NetworkError;
use crate::host::{GossipVerdict, Host};
use crate::topics::{GossipTopic, GossipTopicKind};
use crate::types::ForkDigest;

// ── subscribe_base_topics ─────────────────────────────────────────────────────

/// Subscribe to the base beacon gossipsub topics under the supplied (active) fork
/// digest, plus `beacon_attestation_<i>` for each bit `i` set in `attnets`.
///
/// The five base topics (`beacon_block`, `beacon_aggregate_and_proof`,
/// `voluntary_exit`, `proposer_slashing`, `attester_slashing`) are the same
/// across all forks; only the fork-digest segment of the topic string differs.
///
/// For altair-or-later active forks, callers MUST also subscribe the altair-era
/// extras (`sync_committee_*`, `light_client_*`) via `subscribe_altair_extra_topics`
/// so a bellatrix-at-genesis node starts on the full topic set.
/// (`D-bellatrix-startup-topic-set`)
///
/// Topic list per `specs/phase0/p2p-interface.md:507-514`.
pub fn subscribe_base_topics(
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

// ── subscribe_altair_extra_topics ─────────────────────────────────────────────

/// Subscribe to the altair-era extra topics under `fork_digest` and merge them
/// into an existing `topic_map`.
///
/// Subscribes `sync_committee_contribution_and_proof`, each `sync_committee_<i>`
/// subnet, `light_client_finality_update`, and `light_client_optimistic_update`.
///
/// Called at startup when the active fork is altair or bellatrix so the node
/// starts on the complete topic set even when those forks are at epoch 0.
/// (`D-bellatrix-startup-topic-set`)
pub fn subscribe_altair_extra_topics<E: BeaconSpec>(
    gs: &mut gossipsub::Behaviour,
    fork_digest: ForkDigest,
    topic_map: &mut HashMap<TopicHash, GossipTopic>,
) -> Result<(), NetworkError> {
    // `sync_committee_contribution_and_proof`.
    let contrib_topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::SyncCommitteeContributionAndProof,
    };
    gs.subscribe(&IdentTopic::new(contrib_topic.topic_str()))
        .map_err(|e| {
            NetworkError::Libp2p(format!("subscribe sync_committee_contrib failed: {e}"))
        })?;
    topic_map.insert(contrib_topic.topic_hash(), contrib_topic);

    // `sync_committee_<i>` for each subnet.
    for i in 0..E::SYNC_COMMITTEE_SUBNET_COUNT {
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::SyncCommittee(i),
        };
        gs.subscribe(&IdentTopic::new(topic.topic_str()))
            .map_err(|e| {
                NetworkError::Libp2p(format!("subscribe sync_committee_{i} failed: {e}"))
            })?;
        topic_map.insert(topic.topic_hash(), topic);
    }

    // `light_client_finality_update`.
    let lc_fin = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::LightClientFinalityUpdate,
    };
    gs.subscribe(&IdentTopic::new(lc_fin.topic_str()))
        .map_err(|e| NetworkError::Libp2p(format!("subscribe lc_finality_update failed: {e}")))?;
    topic_map.insert(lc_fin.topic_hash(), lc_fin);

    // `light_client_optimistic_update`.
    let lc_opt = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::LightClientOptimisticUpdate,
    };
    gs.subscribe(&IdentTopic::new(lc_opt.topic_str()))
        .map_err(|e| NetworkError::Libp2p(format!("subscribe lc_optimistic_update failed: {e}")))?;
    topic_map.insert(lc_opt.topic_hash(), lc_opt);

    Ok(())
}

// ── subscribe_deneb_blob_topics ────────────────────────────────────────────────

/// Subscribe to the Deneb (EIP-4844) `blob_sidecar_<i>` subnet topics under
/// `fork_digest` and merge them into an existing `topic_map`.
///
/// Subscribes `blob_sidecar_<i>` for each subnet `i` in
/// `0..E::BLOB_SIDECAR_SUBNET_COUNT` (= 6 for both presets). Without this, a
/// node on a Deneb-or-later fork never receives blob sidecars over gossip, so a
/// blob-carrying block's data-availability gate can never be satisfied at the
/// tip (`specs/deneb/p2p-interface.md` blob-sidecar topics).
pub fn subscribe_deneb_blob_topics<E: BeaconSpec>(
    gs: &mut gossipsub::Behaviour,
    fork_digest: ForkDigest,
    topic_map: &mut HashMap<TopicHash, GossipTopic>,
) -> Result<(), NetworkError> {
    for subnet in 0..E::BLOB_SIDECAR_SUBNET_COUNT {
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::BlobSidecar(subnet),
        };
        gs.subscribe(&IdentTopic::new(topic.topic_str()))
            .map_err(|e| {
                NetworkError::Libp2p(format!("subscribe blob_sidecar_{subnet} failed: {e}"))
            })?;
        topic_map.insert(topic.topic_hash(), topic);
    }
    Ok(())
}

// ── subscribe_fulu_data_column_topics ──────────────────────────────────────────

/// Subscribe to the Fulu (EIP-7594 PeerDAS) `data_column_sidecar_<subnet>` topics
/// covering the node's CUSTODY columns under `fork_digest`, merging them into an
/// existing `topic_map`.
///
/// `columns` is the node's custodied column-index set (computed by the node
/// crate via `get_custody_groups` + `compute_columns_for_custody_group`). Only
/// the subnets covering those columns are subscribed, NOT all
/// `DATA_COLUMN_SIDECAR_SUBNET_COUNT` subnets; PeerDAS nodes custody a subset.
/// Each column maps to subnet `column % DATA_COLUMN_SIDECAR_SUBNET_COUNT`
/// (multiple columns may share a subnet; duplicates are de-duplicated via the
/// `topic_map`). Per `specs/fulu/p2p-interface.md` + `specs/fulu/das-core.md`.
pub fn subscribe_fulu_data_column_topics<E: BeaconSpec>(
    gs: &mut gossipsub::Behaviour,
    fork_digest: ForkDigest,
    columns: &[u64],
    topic_map: &mut HashMap<TopicHash, GossipTopic>,
) -> Result<(), NetworkError> {
    for &column in columns {
        let subnet = crate::topics::compute_subnet_for_data_column_sidecar(
            column,
            E::DATA_COLUMN_SIDECAR_SUBNET_COUNT,
        );
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::DataColumnSidecar(subnet),
        };
        let hash = topic.topic_hash();
        if topic_map.contains_key(&hash) {
            // Multiple custodied columns share this subnet; already subscribed.
            continue;
        }
        gs.subscribe(&IdentTopic::new(topic.topic_str()))
            .map_err(|e| {
                NetworkError::Libp2p(format!(
                    "subscribe data_column_sidecar_{subnet} failed: {e}"
                ))
            })?;
        topic_map.insert(hash, topic);
    }
    Ok(())
}

// ── dispatch_gossip_message ───────────────────────────────────────────────────

/// SSZ-decode an already-decompressed gossip payload and dispatch to the
/// host validator, returning a `GossipVerdict`.
///
/// Callers MUST snappy-block-decompress the wire payload (per
/// `specs/phase0/p2p-interface.md:1038-1048`) before invoking this. The
/// network task does this in `on_gossip_message` so the decompressed bytes
/// can be reused on the Accept path without a second decompress.
///
/// SSZ-decode failures return `GossipVerdict::Reject("ssz decode")`.
pub fn dispatch_gossip_message<E: BeaconSpec, H: Host<E>>(
    host: &H,
    topic: &GossipTopic,
    ssz_bytes: &[u8],
) -> GossipVerdict {
    match &topic.kind {
        GossipTopicKind::BeaconBlock => {
            // Gossip beacon_block carries raw fork-specific SSZ with no discriminant
            // prefix. Dispatch to the correct inner type based on the topic's fork
            // digest per `specs/altair/p2p-interface.md` and
            // `specs/bellatrix/p2p-interface.md`.
            match host.fork_from_context(&topic.fork_digest.into_inner()) {
                Some(crate::types::Fork::Fulu) => {
                    // Fulu beacon blocks share the Electra block shape; the
                    // fork-digest context selects the Fulu SSZ type. The gossip
                    // validation body itself is `validate_beacon_block` (shared
                    // across forks). Per `specs/fulu/p2p-interface.md`.
                    match E::FuluSignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::fulu_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                Some(crate::types::Fork::Electra) => {
                    match E::ElectraSignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::electra_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                Some(crate::types::Fork::Deneb) => {
                    match E::DenebSignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::deneb_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                Some(crate::types::Fork::Altair) => {
                    match E::AltairSignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::altair_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                Some(crate::types::Fork::Capella) => {
                    match E::CapellaSignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::capella_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                Some(crate::types::Fork::Bellatrix) => {
                    match E::BellatrixSignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::bellatrix_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                // Phase0 or unknown digest: fall back to phase0 block type.
                Some(crate::types::Fork::Phase0) | None => {
                    match E::Phase0SignedBeaconBlock::from_ssz_bytes(ssz_bytes) {
                        Ok(inner) => {
                            let block = E::phase0_into_signed_block(inner);
                            host.validate_beacon_block(&block)
                        }
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
            }
        }
        GossipTopicKind::BeaconAggregateAndProof => {
            // EIP-7549: from Electra onward the aggregate carries the electra
            // `Attestation` (with `committee_bits`). Pre-electra keeps the phase0
            // `SignedAggregateAndProof`. Selection is by the topic's fork digest.
            // Per `specs/electra/p2p-interface.md:225`.
            match host.fork_from_context(&topic.fork_digest.into_inner()) {
                Some(crate::types::Fork::Electra) => {
                    match E::ElectraSignedAggregateAndProof::from_ssz_bytes(ssz_bytes) {
                        Ok(saap) => host.validate_aggregate_and_proof_electra(&saap),
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                _ => match SignedAggregateAndProof::<2048>::from_ssz_bytes(ssz_bytes) {
                    Ok(saap) => host.validate_aggregate_and_proof(&saap),
                    Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                },
            }
        }
        GossipTopicKind::BeaconAttestation(subnet) => {
            // EIP-7549 PEER-BAN HAZARD: from Electra onward the subnet topic
            // carries `SingleAttestation`, NOT the multi-committee `Attestation`.
            // Decoding the wrong shape is a wrong-length SSZ decode -> instant
            // -100 peer ban. Pre-electra subnets keep phase0 `Attestation<2048>`.
            // Selection is by the topic's fork digest.
            // Per `specs/electra/p2p-interface.md:476-591`.
            match host.fork_from_context(&topic.fork_digest.into_inner()) {
                Some(crate::types::Fork::Electra) => {
                    match SingleAttestation::from_ssz_bytes(ssz_bytes) {
                        Ok(att) => host.validate_single_attestation(*subnet, &att),
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                _ => match Attestation::<2048>::from_ssz_bytes(ssz_bytes) {
                    Ok(att) => host.validate_attestation(*subnet, &att),
                    Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                },
            }
        }
        GossipTopicKind::VoluntaryExit => match SignedVoluntaryExit::from_ssz_bytes(ssz_bytes) {
            Ok(sve) => host.validate_voluntary_exit(&sve),
            Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
        },
        GossipTopicKind::ProposerSlashing => match ProposerSlashing::from_ssz_bytes(ssz_bytes) {
            Ok(ps) => host.validate_proposer_slashing(&ps),
            Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
        },
        GossipTopicKind::AttesterSlashing => {
            match AttesterSlashing::<2048>::from_ssz_bytes(ssz_bytes) {
                Ok(as_slash) => host.validate_attester_slashing(&as_slash),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        // ── Altair topics ─────────────────────────────────────────────────────
        // Per `specs/altair/p2p-interface.md:184-188` and
        // `specs/altair/light-client/p2p-interface.md:47-48`.
        GossipTopicKind::SyncCommittee(subnet) => {
            match SyncCommitteeMessage::from_ssz_bytes(ssz_bytes) {
                Ok(msg) => host.validate_sync_committee_message(*subnet, &msg),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        GossipTopicKind::SyncCommitteeContributionAndProof => {
            match E::AltairSignedContributionAndProof::from_ssz_bytes(ssz_bytes) {
                Ok(msg) => host.validate_sync_committee_contribution_and_proof(&msg),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        GossipTopicKind::LightClientFinalityUpdate => {
            // Dispatch by fork-digest: capella and later (deneb) LC objects have the
            // capella SSZ layout (execution header + branch). Per
            // `specs/capella/light-client/p2p-interface.md` and
            // `specs/deneb/light-client/p2p-interface.md` (Deneb inherits Capella LC).
            match host.fork_from_context(&topic.fork_digest.into_inner()) {
                Some(crate::types::Fork::Capella)
                | Some(crate::types::Fork::Deneb)
                | Some(crate::types::Fork::Electra)
                | Some(crate::types::Fork::Fulu) => {
                    match E::CapellaLightClientFinalityUpdate::from_ssz_bytes(ssz_bytes) {
                        Ok(msg) => host.validate_capella_light_client_finality_update(&msg),
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                _ => match E::AltairLightClientFinalityUpdate::from_ssz_bytes(ssz_bytes) {
                    Ok(msg) => host.validate_light_client_finality_update(&msg),
                    Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                },
            }
        }
        GossipTopicKind::LightClientOptimisticUpdate => {
            match host.fork_from_context(&topic.fork_digest.into_inner()) {
                Some(crate::types::Fork::Capella)
                | Some(crate::types::Fork::Deneb)
                | Some(crate::types::Fork::Electra)
                | Some(crate::types::Fork::Fulu) => {
                    match E::CapellaLightClientOptimisticUpdate::from_ssz_bytes(ssz_bytes) {
                        Ok(msg) => host.validate_capella_light_client_optimistic_update(&msg),
                        Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                    }
                }
                _ => match E::AltairLightClientOptimisticUpdate::from_ssz_bytes(ssz_bytes) {
                    Ok(msg) => host.validate_light_client_optimistic_update(&msg),
                    Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
                },
            }
        }
        // ── Capella topics ─────────────────────────────────────────────────────
        // Per `specs/capella/p2p-interface.md`.
        // BLS verify in `validate_bls_to_execution_change` is sync/CPU-bound;
        // the caller must run this in `spawn_blocking` (D-no-tokio-from-validator,
        // D-bls-on-hot-path).
        GossipTopicKind::BlsToExecutionChange => {
            match SignedBLSToExecutionChange::from_ssz_bytes(ssz_bytes) {
                Ok(msg) => host.validate_bls_to_execution_change(&msg),
                Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
            }
        }
        // ── Deneb topics ───────────────────────────────────────────────────────
        // Per `specs/deneb/p2p-interface.md:489-586`.
        // KZG verify + BLS verify in `validate_blob_sidecar` are sync/CPU-bound;
        // the caller runs this in `spawn_blocking` (D-bls-on-hot-path).
        GossipTopicKind::BlobSidecar(subnet) => match BlobSidecar::from_ssz_bytes(ssz_bytes) {
            Ok(sidecar) => host.validate_blob_sidecar(*subnet, &sidecar),
            Err(_) => GossipVerdict::Reject("ssz decode".to_string()),
        },
        // ── Fulu topics ──────────────────────────────────────────────────────
        // Per `specs/fulu/p2p-interface.md` (EIP-7594 PeerDAS). KZG + BLS
        // verify in `validate_data_column_sidecar` are sync/CPU-bound; the
        // caller runs this in `spawn_blocking` (D-bls-on-hot-path).
        GossipTopicKind::DataColumnSidecar(subnet) => {
            match DataColumnSidecar::<4096, 4>::from_ssz_bytes(ssz_bytes) {
                Ok(sidecar) => host.validate_data_column_sidecar(*subnet, &sidecar),
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
    use pharos_types::MainnetBeaconSpec;
    use pharos_types::phase0::primitives::ForkDigest;
    use pharos_types::phase0::{
        Attestation, AttesterSlashing, Checkpoint, ENRForkID, ProposerSlashing, Root,
        SignedAggregateAndProof, SignedVoluntaryExit, Slot,
    };
    use pharos_utils::{Bytes4, Epoch};

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
        fn fork_digest_for(&self, _fork: crate::types::Fork) -> ForkDigest {
            // Return zero digest for all forks in tests.
            ForkDigest::from_array([0u8; 4])
        }
        fn fork_from_context(&self, _ctx: &[u8; 4]) -> Option<crate::types::Fork> {
            // Mock: all context bytes are unknown.
            None
        }
    }

    impl BlockProvider<MainnetBeaconSpec> for MockHost {
        fn block_by_root(
            &self,
            _root: Root,
        ) -> Option<<MainnetBeaconSpec as BeaconSpec>::SignedBeaconBlock> {
            unreachable!()
        }
        fn blocks_by_range(
            &self,
            _start_slot: Slot,
            _count: u64,
        ) -> Vec<<MainnetBeaconSpec as BeaconSpec>::SignedBeaconBlock> {
            unreachable!()
        }
        fn finalized_checkpoint(&self) -> Checkpoint {
            unreachable!()
        }
        fn head(&self) -> (Root, Slot) {
            unreachable!()
        }
    }

    impl GossipValidator<MainnetBeaconSpec> for MockHost {
        fn validate_beacon_block(
            &self,
            _block: &<MainnetBeaconSpec as BeaconSpec>::SignedBeaconBlock,
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
        fn validate_aggregate_and_proof(
            &self,
            _msg: &SignedAggregateAndProof<2048>,
        ) -> GossipVerdict {
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
        fn validate_sync_committee_message(
            &self,
            _subnet: crate::types::SubnetId,
            _msg: &pharos_types::altair::SyncCommitteeMessage,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_sync_committee_contribution_and_proof(
            &self,
            _msg: &<MainnetBeaconSpec as BeaconSpec>::AltairSignedContributionAndProof,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_light_client_finality_update(
            &self,
            _msg: &<MainnetBeaconSpec as BeaconSpec>::AltairLightClientFinalityUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
        fn validate_light_client_optimistic_update(
            &self,
            _msg: &<MainnetBeaconSpec as BeaconSpec>::AltairLightClientOptimisticUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }

        fn validate_bls_to_execution_change(
            &self,
            _msg: &pharos_types::capella::operations::SignedBLSToExecutionChange,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }

        fn validate_capella_light_client_finality_update(
            &self,
            _msg: &<MainnetBeaconSpec as BeaconSpec>::CapellaLightClientFinalityUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }

        fn validate_capella_light_client_optimistic_update(
            &self,
            _msg: &<MainnetBeaconSpec as BeaconSpec>::CapellaLightClientOptimisticUpdate,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }

        fn validate_blob_sidecar(
            &self,
            _subnet: crate::types::SubnetId,
            _sidecar: &pharos_types::deneb::BlobSidecar,
        ) -> GossipVerdict {
            GossipVerdict::Accept
        }
    }

    // ── subscribe_base_topics tests ───────────────────────────────────────────

    fn make_gossipsub() -> gossipsub::Behaviour {
        let fd = ForkDigest::from_array([0u8; 4]);
        let cfg = gossipsub_config::<MainnetBeaconSpec>(fd).expect("config failed");
        gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, cfg).expect("behaviour failed")
    }

    /// After `subscribe_base_topics` with bits 0 and 5 set, unsubscribing
    /// each expected topic returns `true` (proves it was subscribed).
    #[test]
    fn subscribe_base_topics_subscribes_expected_topics() {
        let mut gs = make_gossipsub();
        let fork_digest = ForkDigest::from_array([1, 2, 3, 4]);

        let mut attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::new();
        attnets.set(0, true);
        attnets.set(5, true);

        subscribe_base_topics(&mut gs, fork_digest, &attnets)
            .expect("subscribe_base_topics failed");

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

    /// A valid `ProposerSlashing` SSZ payload dispatches as `Accept`.
    /// Snappy decompression is the caller's responsibility and is exercised
    /// by `codec::snappy_block::tests::*` plus the gossip integration tests.
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

        let verdict = dispatch_gossip_message::<MainnetBeaconSpec, MockHost>(&host, &topic, &ssz);
        assert!(
            matches!(verdict, GossipVerdict::Accept),
            "expected Accept, got {verdict:?}"
        );
    }

    /// Garbage bytes (not valid SSZ) return `Reject("ssz decode")`.
    #[test]
    fn dispatch_ssz_decode_failure() {
        let host = MockHost;
        let fork_digest = ForkDigest::from_array([0u8; 4]);
        let topic = GossipTopic {
            fork_digest,
            kind: GossipTopicKind::ProposerSlashing,
        };

        let garbage = b"not a valid ssz payload";
        let verdict =
            dispatch_gossip_message::<MainnetBeaconSpec, MockHost>(&host, &topic, garbage);
        assert!(
            matches!(&verdict, GossipVerdict::Reject(r) if r == "ssz decode"),
            "expected Reject(ssz decode), got {verdict:?}"
        );
    }
}
