//! Cross-fork ENR migration and gossip topic rotation driver.
//!
//! This loop handles BOTH the phase0→altair AND altair→bellatrix crossings
//! (and any future crossings) within a single run. It tracks the last-applied
//! fork version (`prior`) and fires `do_migration` whenever the wall-clock
//! epoch enters a new fork. The loop does NOT exit after the first crossing.
//!
//! Per `specs/altair/p2p-interface.md` and `specs/bellatrix/p2p-interface.md`
//! cross-fork ENR migration requirements and `D-fork-schedule-source` (M3b).
//!
//! **Startup no-op** (`D-bellatrix-migration-startup-no-op`): on the first
//! tick, if the active fork version is already past the genesis fork version,
//! the loop records `prior = current` WITHOUT migrating. The startup gossip
//! subscription (Phase 4) already subscribes under the active fork digest;
//! re-migrating would produce duplicate subscribes and spurious unsubscribes.
//! For configs where ALTAIR_FORK_EPOCH == BELLATRIX_FORK_EPOCH == 0, this
//! means the first tick sees `current = bellatrix_fork_version`, records it,
//! and does nothing — no spurious intermediate altair step.
//!
//! Note: attestation-subnet topics change fork digest at every boundary; the
//! subnet rotation loop handles its own re-subscription at the next epoch tick.
//! This module manages the non-attestation topics.

use std::sync::Arc;
use std::time::Duration;

use pharos_types::EthSpec;
use pharos_types::fork::{ForkSchedule, compute_fork_digest};
use pharos_types::phase0::ENRForkID;
use pharos_types::phase0::primitives::Version;
use pharos_utils::Epoch;
use tracing::info;

use pharos_network::DiscoveryHandle;
use pharos_network::NetworkCommand;
use pharos_network::NetworkCommandSender;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::ForkDigest;

// ── run_fork_migration_loop ───────────────────────────────────────────────────

/// Run the cross-fork ENR migration and gossip topic rotation loop.
///
/// Ticks every slot (`E::SLOT_DURATION_MS`). Tracks the last-applied fork
/// version (`prior`). When the wall-clock epoch crosses into a new fork:
/// - Updates the local ENR `eth2` field with the new fork's `ENRForkID`.
/// - Unsubscribes gossip topics using the old fork digest.
/// - Subscribes to gossip topics using the new fork digest.
///
/// Handles BOTH the phase0→altair AND altair→bellatrix crossings in one run.
/// The loop does NOT exit after the first crossing.
///
/// On the first tick, if `current != genesis_fork_version`, the loop records
/// `prior = current` without migrating — see module-level doc for rationale
/// (`D-bellatrix-migration-startup-no-op`).
///
/// The `genesis_time_secs` parameter is the Unix timestamp of the genesis slot.
/// When `0`, the current epoch is treated as 0.
pub async fn run_fork_migration_loop<E: EthSpec>(
    cmd: NetworkCommandSender<E>,
    discovery: DiscoveryHandle,
    fork_schedule: Arc<ForkSchedule>,
    genesis_time_secs: u64,
) {
    // If both altair and bellatrix are FAR_FUTURE_EPOCH, no migrations will
    // ever occur; exit immediately to avoid a useless spinning loop.
    if fork_schedule.altair_fork_epoch == Epoch(u64::MAX)
        && fork_schedule.bellatrix_fork_epoch == Epoch(u64::MAX)
    {
        return;
    }

    let slot_ms = E::SLOT_DURATION_MS;
    let slots_per_epoch = E::SLOTS_PER_EPOCH;
    let mut interval = tokio::time::interval(Duration::from_millis(slot_ms));

    // `prior` tracks the last-applied fork version. `None` on the very first
    // tick so we can detect startup-already-past-fork.
    let mut prior: Option<Version> = None;

    loop {
        interval.tick().await;

        // Compute current epoch from wall clock.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let epoch = if genesis_time_secs > 0 && now_secs >= genesis_time_secs {
            // Compute in milliseconds so sub-second slot durations (used in
            // tests with SLOT_DURATION_MS < 1000) don't round to zero.
            let elapsed_ms = (now_secs - genesis_time_secs).saturating_mul(1000);
            let elapsed_slots = elapsed_ms / slot_ms.max(1);
            elapsed_slots / slots_per_epoch
        } else {
            0
        };

        let current_epoch = Epoch(epoch);
        let current = fork_schedule.current_fork_version(current_epoch);

        match prior {
            None => {
                // First tick. Record the active fork version without migrating.
                // `D-bellatrix-migration-startup-no-op`: if we are already past
                // genesis_fork_version at startup, the startup subscription
                // (Phase 4) is already on the correct digest; migrating here
                // would produce spurious unsubscribes.
                prior = Some(current);
                // Do not migrate even if current != genesis_fork_version.
            }
            Some(prior_version) if current != prior_version => {
                // Fork boundary crossed: migrate from prior_version → current.
                do_migration::<E>(
                    &cmd,
                    &discovery,
                    &fork_schedule,
                    prior_version,
                    current,
                    current_epoch,
                )
                .await;
                prior = Some(current);
            }
            _ => {
                // Same fork as last tick; nothing to do.
            }
        }
    }
}

// ── do_migration ─────────────────────────────────────────────────────────────

/// Execute a fork migration: update ENR, drop old-digest topics, subscribe
/// to new-digest topics.
///
/// `old_version` and `new_version` are the fork versions before and after the
/// boundary. `epoch` is the current epoch (used for ENRForkID next-fork fields).
async fn do_migration<E: EthSpec>(
    cmd: &NetworkCommandSender<E>,
    discovery: &DiscoveryHandle,
    fork_schedule: &ForkSchedule,
    old_version: Version,
    new_version: Version,
    epoch: Epoch,
) {
    let gvr = fork_schedule.genesis_validators_root;

    let old_digest = compute_fork_digest(old_version, &gvr);
    let new_digest = compute_fork_digest(new_version, &gvr);

    info!(
        old_version = ?old_version,
        new_version = ?new_version,
        old_digest = ?old_digest,
        new_digest = ?new_digest,
        "fork migration: crossing fork boundary"
    );

    // Step 1: Update the ENR `eth2` field with the new fork identity.
    // next_fork_version/next_fork_epoch reflect what comes AFTER `new_version`.
    let enr_fork_id = ENRForkID {
        fork_digest: new_digest,
        next_fork_version: fork_schedule.next_fork_version(epoch),
        next_fork_epoch: fork_schedule.next_fork_epoch(epoch),
    };
    if let Err(e) = discovery.update_enr_eth2(enr_fork_id).await {
        tracing::warn!(%e, "fork migration: ENR eth2 update failed");
    }

    // Step 2: Unsubscribe from old-digest gossip topics.
    let old_topics = topics_for_version::<E>(old_version, fork_schedule, old_digest);
    for topic in old_topics {
        if let Err(e) = send_unsubscribe(cmd, topic).await {
            tracing::debug!(%e, "fork migration: old-digest unsubscribe error");
        }
    }

    // Step 3: Subscribe to new-digest gossip topics.
    let new_topics = topics_for_version::<E>(new_version, fork_schedule, new_digest);
    for topic in new_topics {
        if let Err(e) = send_subscribe(cmd, topic).await {
            tracing::debug!(%e, "fork migration: new-digest subscribe error");
        }
    }

    info!(
        new_fork_version = ?new_version,
        "fork migration: complete"
    );
}

// ── Topic helpers ─────────────────────────────────────────────────────────────

/// Select the full topic set appropriate for `version` at `digest`.
///
/// - genesis_fork_version → `phase0_gossip_topics` (5 base topics)
/// - altair_fork_version  → `altair_gossip_topics` (5 base + altair extras)
/// - bellatrix_fork_version (or unknown) → `bellatrix_gossip_topics`
///   (5 base + same altair extras, all under the bellatrix digest)
fn topics_for_version<E: EthSpec>(
    version: Version,
    fork_schedule: &ForkSchedule,
    digest: ForkDigest,
) -> Vec<GossipTopic> {
    if version == fork_schedule.genesis_fork_version {
        phase0_gossip_topics(digest)
    } else if version == fork_schedule.altair_fork_version {
        altair_gossip_topics::<E>(digest)
    } else {
        // Bellatrix (and any future fork): same topic shape as altair —
        // per bellatrix/p2p-interface.md only the beacon_block TYPE changes;
        // all topic names remain the same, only the fork-digest segment bumps.
        bellatrix_gossip_topics::<E>(digest)
    }
}

/// The 5 base beacon gossip topics under `digest`.
///
/// These are shared across all forks; the fork-digest segment in the topic
/// string is the only thing that differs per fork.
///
/// Attestation subnet topics are NOT included; the subnet rotation driver
/// manages them.
fn base_beacon_topics(digest: ForkDigest) -> Vec<GossipTopic> {
    [
        GossipTopicKind::BeaconBlock,
        GossipTopicKind::BeaconAggregateAndProof,
        GossipTopicKind::VoluntaryExit,
        GossipTopicKind::ProposerSlashing,
        GossipTopicKind::AttesterSlashing,
    ]
    .into_iter()
    .map(|kind| GossipTopic {
        fork_digest: digest,
        kind,
    })
    .collect()
}

/// The phase-0 gossip topics (5 base topics under the phase-0 fork digest).
///
/// Attestation topics are NOT included; the subnet rotation driver re-subscribes
/// them with the correct fork digest at the next tick.
pub(crate) fn phase0_gossip_topics(phase0_digest: ForkDigest) -> Vec<GossipTopic> {
    base_beacon_topics(phase0_digest)
}

/// The altair gossip topics: 5 base topics + altair-specific extras
/// (`sync_committee_contribution_and_proof`, `sync_committee_<i>`, and
/// light-client update topics), all under the altair fork digest.
///
/// Per `specs/altair/p2p-interface.md:184-188` and
/// `specs/altair/light-client/p2p-interface.md:47-48`.
///
/// Attestation subnet topics are handled by the subnet rotation driver.
pub(crate) fn altair_gossip_topics<E: EthSpec>(altair_digest: ForkDigest) -> Vec<GossipTopic> {
    let mut topics = base_beacon_topics(altair_digest);

    // `sync_committee_contribution_and_proof` topic.
    topics.push(GossipTopic {
        fork_digest: altair_digest,
        kind: GossipTopicKind::SyncCommitteeContributionAndProof,
    });

    // `sync_committee_<i>` for each sync committee subnet.
    for i in 0..E::SYNC_COMMITTEE_SUBNET_COUNT {
        topics.push(GossipTopic {
            fork_digest: altair_digest,
            kind: GossipTopicKind::SyncCommittee(i),
        });
    }

    // Light-client update topics.
    topics.push(GossipTopic {
        fork_digest: altair_digest,
        kind: GossipTopicKind::LightClientFinalityUpdate,
    });
    topics.push(GossipTopic {
        fork_digest: altair_digest,
        kind: GossipTopicKind::LightClientOptimisticUpdate,
    });

    topics
}

/// The bellatrix gossip topics: 5 base topics + the same altair-era extras
/// (`sync_committee_*`, `light_client_*`), all under the bellatrix fork digest.
///
/// Per `specs/bellatrix/p2p-interface.md`: Bellatrix changes only the
/// `beacon_block` container type; all topic names remain the same as Altair.
/// Every topic's fork-digest segment bumps at the Bellatrix boundary.
///
/// Attestation subnet topics are handled by the subnet rotation driver.
pub(crate) fn bellatrix_gossip_topics<E: EthSpec>(
    bellatrix_digest: ForkDigest,
) -> Vec<GossipTopic> {
    let mut topics = base_beacon_topics(bellatrix_digest);

    // `sync_committee_contribution_and_proof` topic.
    topics.push(GossipTopic {
        fork_digest: bellatrix_digest,
        kind: GossipTopicKind::SyncCommitteeContributionAndProof,
    });

    // `sync_committee_<i>` for each sync committee subnet.
    for i in 0..E::SYNC_COMMITTEE_SUBNET_COUNT {
        topics.push(GossipTopic {
            fork_digest: bellatrix_digest,
            kind: GossipTopicKind::SyncCommittee(i),
        });
    }

    // Light-client update topics.
    topics.push(GossipTopic {
        fork_digest: bellatrix_digest,
        kind: GossipTopicKind::LightClientFinalityUpdate,
    });
    topics.push(GossipTopic {
        fork_digest: bellatrix_digest,
        kind: GossipTopicKind::LightClientOptimisticUpdate,
    });

    topics
}

/// Returns the list of altair topics for a given fork digest.
///
/// Public helper used by integration tests to verify that both nodes subscribed
/// to the expected set of altair topics.
pub fn altair_topic_list<E: EthSpec>(altair_digest: ForkDigest) -> Vec<GossipTopic> {
    altair_gossip_topics::<E>(altair_digest)
}

/// Returns the list of bellatrix topics for a given fork digest.
///
/// Public helper used by integration tests to verify that the migration
/// correctly subscribes to the bellatrix topic set. The set is identical in
/// shape to the altair set (5 base + sync_committee_* + light_client_*) but
/// all topics carry the bellatrix fork digest.
pub fn bellatrix_topic_list<E: EthSpec>(bellatrix_digest: ForkDigest) -> Vec<GossipTopic> {
    bellatrix_gossip_topics::<E>(bellatrix_digest)
}

// ── Command helpers ───────────────────────────────────────────────────────────

/// Send a `Subscribe` command and await the reply.
async fn send_subscribe<E: EthSpec>(
    cmd: &NetworkCommandSender<E>,
    topic: GossipTopic,
) -> Result<(), pharos_network::NetworkError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    cmd.send(NetworkCommand::Subscribe {
        topic,
        reply: reply_tx,
    })
    .await?;
    reply_rx
        .await
        .map_err(|_| pharos_network::NetworkError::ChannelClosed)?
}

/// Send an `Unsubscribe` command and await the reply.
async fn send_unsubscribe<E: EthSpec>(
    cmd: &NetworkCommandSender<E>,
    topic: GossipTopic,
) -> Result<(), pharos_network::NetworkError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    cmd.send(NetworkCommand::Unsubscribe {
        topic,
        reply: reply_tx,
    })
    .await?;
    reply_rx
        .await
        .map_err(|_| pharos_network::NetworkError::ChannelClosed)?
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::MainnetEthSpec;
    use pharos_types::fork::compute_fork_digest;
    use pharos_types::phase0::primitives::{Root, Version};
    use pharos_utils::Epoch;

    /// Build a three-fork schedule with distinct versions.
    fn three_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(10),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(20),
            genesis_validators_root: Root::default(),
        }
    }

    /// `bellatrix_topic_list` must return exactly:
    /// - 5 base beacon topics
    /// - 1 `sync_committee_contribution_and_proof`
    /// - `SYNC_COMMITTEE_SUBNET_COUNT` `sync_committee_<i>` topics
    /// - 1 `light_client_finality_update`
    /// - 1 `light_client_optimistic_update`
    ///
    /// Total = 5 + 1 + SYNC_COMMITTEE_SUBNET_COUNT + 2
    /// For MainnetEthSpec: SYNC_COMMITTEE_SUBNET_COUNT = 4 → total = 12.
    ///
    /// All topics must carry the bellatrix digest, NOT the altair digest.
    #[test]
    fn bellatrix_topic_list_shape_and_digest() {
        use pharos_network::topics::GossipTopicKind;
        let sched = three_fork_schedule();
        let gvr = Root::default();
        let bellatrix_digest = compute_fork_digest(sched.bellatrix_fork_version, &gvr);
        let altair_digest = compute_fork_digest(sched.altair_fork_version, &gvr);

        let topics = bellatrix_topic_list::<MainnetEthSpec>(bellatrix_digest);

        // Count expected: 5 base + 1 contrib + SYNC_COMMITTEE_SUBNET_COUNT subnets + 2 lc.
        let sync_subnet_count =
            <MainnetEthSpec as pharos_types::EthSpec>::SYNC_COMMITTEE_SUBNET_COUNT as usize;
        let expected_count = 5 + 1 + sync_subnet_count + 2;
        assert_eq!(
            topics.len(),
            expected_count,
            "bellatrix topic list must have {} topics, got {}",
            expected_count,
            topics.len()
        );

        // Verify every topic carries the bellatrix digest.
        for topic in &topics {
            assert_eq!(
                topic.fork_digest, bellatrix_digest,
                "all bellatrix topics must carry the bellatrix digest, got {:?}",
                topic.kind
            );
            assert_ne!(
                topic.fork_digest, altair_digest,
                "bellatrix topics must NOT carry the altair digest (kind: {:?})",
                topic.kind
            );
        }

        // Verify the 5 base kinds are present.
        let base_kinds = [
            GossipTopicKind::BeaconBlock,
            GossipTopicKind::BeaconAggregateAndProof,
            GossipTopicKind::VoluntaryExit,
            GossipTopicKind::ProposerSlashing,
            GossipTopicKind::AttesterSlashing,
        ];
        for kind in base_kinds {
            assert!(
                topics.iter().any(|t| t.kind == kind),
                "bellatrix topic list must contain {:?}",
                kind
            );
        }

        // Verify altair-era extras are present.
        assert!(
            topics
                .iter()
                .any(|t| t.kind == GossipTopicKind::SyncCommitteeContributionAndProof),
            "bellatrix topic list must contain SyncCommitteeContributionAndProof"
        );
        assert!(
            topics
                .iter()
                .any(|t| t.kind == GossipTopicKind::LightClientFinalityUpdate),
            "bellatrix topic list must contain LightClientFinalityUpdate"
        );
        assert!(
            topics
                .iter()
                .any(|t| t.kind == GossipTopicKind::LightClientOptimisticUpdate),
            "bellatrix topic list must contain LightClientOptimisticUpdate"
        );

        // Verify all SYNC_COMMITTEE_SUBNET_COUNT sync_committee_<i> subnets are present.
        for i in 0..<MainnetEthSpec as pharos_types::EthSpec>::SYNC_COMMITTEE_SUBNET_COUNT {
            assert!(
                topics
                    .iter()
                    .any(|t| t.kind == GossipTopicKind::SyncCommittee(i)),
                "bellatrix topic list must contain SyncCommittee({i})"
            );
        }
    }

    /// `bellatrix_gossip_topics` has the same shape as `altair_gossip_topics`
    /// (topic kinds are identical), but the digests differ.
    #[test]
    fn bellatrix_gossip_topics_same_kinds_as_altair() {
        let sched = three_fork_schedule();
        let gvr = Root::default();
        let altair_digest = compute_fork_digest(sched.altair_fork_version, &gvr);
        let bellatrix_digest = compute_fork_digest(sched.bellatrix_fork_version, &gvr);

        let altair_topics = altair_topic_list::<MainnetEthSpec>(altair_digest);
        let bellatrix_topics = bellatrix_topic_list::<MainnetEthSpec>(bellatrix_digest);

        assert_eq!(
            altair_topics.len(),
            bellatrix_topics.len(),
            "altair and bellatrix topic lists must have the same length"
        );

        // Extract kinds from each list (digests differ, kinds must match).
        let altair_kinds: Vec<_> = altair_topics.iter().map(|t| &t.kind).collect();
        let bellatrix_kinds: Vec<_> = bellatrix_topics.iter().map(|t| &t.kind).collect();
        assert_eq!(
            altair_kinds, bellatrix_kinds,
            "altair and bellatrix topic lists must have identical topic kinds"
        );
    }
}
