//! Cross-fork ENR migration and gossip topic rotation driver.
//!
//! At `ALTAIR_FORK_EPOCH`, this loop:
//! 1. Updates the local ENR `eth2` field with the Altair `ENRForkID` via
//!    `DiscoveryHandle::update_enr_eth2` so that discovering peers see the
//!    correct fork digest.
//! 2. Unsubscribes from phase-0 gossip topics (which carry the phase-0 fork
//!    digest in their topic string).
//! 3. Subscribes to the altair gossip topics (which carry the altair fork
//!    digest).
//!
//! Per `specs/altair/p2p-interface.md` cross-fork ENR migration requirements
//! and `D-fork-schedule-source` (M3b).
//!
//! Note: the attestation-subnet topics also change fork digest at the boundary;
//! the subnet rotation loop handles its own re-subscription at the next epoch
//! tick. This module adds the altair-specific topics (`sync_committee_*`,
//! `light_client_*`, and the base beacon topics under the altair digest) and
//! drops the phase-0 variants.

use std::sync::Arc;
use std::time::Duration;

use pharos_types::EthSpec;
use pharos_types::fork::{ForkSchedule, compute_fork_digest};
use pharos_types::phase0::ENRForkID;
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
/// Ticks every slot (`E::SLOT_DURATION_MS`). When the fork epoch is crossed:
/// - Updates the local ENR `eth2` field with the altair `ENRForkID`.
/// - Drops gossip subscriptions that use the phase-0 fork digest.
/// - Adds gossip subscriptions for the altair gossip topics.
///
/// Idempotent: once the migration has fired it exits (there is only one such
/// crossing in the M3b scope).
///
/// The `genesis_time_secs` parameter is the Unix timestamp of the genesis slot.
/// When `0`, the current epoch is treated as 0 (suitable for tests where the
/// fork epoch is also 0 or very small).
pub async fn run_fork_migration_loop<E: EthSpec>(
    cmd: NetworkCommandSender<E>,
    discovery: DiscoveryHandle,
    fork_schedule: Arc<ForkSchedule>,
    genesis_time_secs: u64,
) {
    // If the altair fork epoch is FAR_FUTURE_EPOCH, never trigger.
    if fork_schedule.altair_fork_epoch == Epoch(u64::MAX) {
        return;
    }

    let slot_ms = E::SLOT_DURATION_MS;
    let slots_per_epoch = E::SLOTS_PER_EPOCH;
    let mut interval = tokio::time::interval(Duration::from_millis(slot_ms));

    let mut prior_fork_is_phase0: Option<bool> = None;

    loop {
        interval.tick().await;

        // Compute current epoch from wall clock.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let epoch = if genesis_time_secs > 0 && now_secs >= genesis_time_secs {
            // Compute in milliseconds so sub-second slot durations (used in tests
            // with SLOT_DURATION_MS < 1000) don't round to zero.
            let elapsed_ms = (now_secs - genesis_time_secs).saturating_mul(1000);
            let elapsed_slots = elapsed_ms / slot_ms.max(1);
            elapsed_slots / slots_per_epoch
        } else {
            0
        };

        let current_epoch = Epoch(epoch);
        let in_phase0 = current_epoch < fork_schedule.altair_fork_epoch;

        // On the first tick, record the prior fork without migrating.
        if prior_fork_is_phase0.is_none() {
            prior_fork_is_phase0 = Some(in_phase0);
            // If we are already past the fork epoch on first tick, migrate immediately.
            if !in_phase0 {
                do_migration::<E>(&cmd, &discovery, &fork_schedule).await;
                return;
            }
            continue;
        }

        // Detect transition: was phase-0, now altair.
        if prior_fork_is_phase0 == Some(true) && !in_phase0 {
            do_migration::<E>(&cmd, &discovery, &fork_schedule).await;
            return; // Migration fires once; exit the loop.
        }

        prior_fork_is_phase0 = Some(in_phase0);
    }
}

// ── do_migration ─────────────────────────────────────────────────────────────

/// Execute the one-time fork migration: update ENR, drop phase-0 topics,
/// subscribe to altair topics.
async fn do_migration<E: EthSpec>(
    cmd: &NetworkCommandSender<E>,
    discovery: &DiscoveryHandle,
    fork_schedule: &ForkSchedule,
) {
    let gvr = fork_schedule.genesis_validators_root;

    let phase0_digest = compute_fork_digest(fork_schedule.genesis_fork_version, &gvr);
    let altair_digest = compute_fork_digest(fork_schedule.altair_fork_version, &gvr);

    info!(
        altair_fork_epoch = %fork_schedule.altair_fork_epoch,
        phase0_digest = ?phase0_digest,
        altair_digest = ?altair_digest,
        "fork migration: crossing ALTAIR_FORK_EPOCH"
    );

    // Step 1: Update the ENR `eth2` field with the altair fork identity.
    let enr_fork_id = ENRForkID {
        fork_digest: altair_digest,
        next_fork_version: fork_schedule.altair_fork_version,
        next_fork_epoch: Epoch(u64::MAX), // FAR_FUTURE_EPOCH (no further forks in M3b)
    };
    if let Err(e) = discovery.update_enr_eth2(enr_fork_id).await {
        tracing::warn!(%e, "fork migration: ENR eth2 update failed");
    }

    // Step 2: Unsubscribe from phase-0 gossip topics.
    let phase0_topics = phase0_gossip_topics(phase0_digest);
    for topic in phase0_topics {
        if let Err(e) = send_unsubscribe(cmd, topic).await {
            tracing::debug!(%e, "fork migration: phase0 unsubscribe error");
        }
    }

    // Step 3: Subscribe to altair gossip topics.
    let altair_topics = altair_gossip_topics::<E>(altair_digest);
    for topic in altair_topics {
        if let Err(e) = send_subscribe(cmd, topic).await {
            tracing::debug!(%e, "fork migration: altair subscribe error");
        }
    }

    info!("fork migration: complete; now on altair topics");
}

// ── Topic helpers ─────────────────────────────────────────────────────────────

/// The phase-0 gossip topics (using the phase-0 fork digest) that must be
/// dropped when crossing to Altair.
///
/// Attestation topics are NOT included here; the subnet rotation driver
/// re-subscribes them with the correct (altair) fork digest at the next tick.
pub(crate) fn phase0_gossip_topics(phase0_digest: ForkDigest) -> Vec<GossipTopic> {
    let base_kinds = [
        GossipTopicKind::BeaconBlock,
        GossipTopicKind::BeaconAggregateAndProof,
        GossipTopicKind::VoluntaryExit,
        GossipTopicKind::ProposerSlashing,
        GossipTopicKind::AttesterSlashing,
    ];
    base_kinds
        .into_iter()
        .map(|kind| GossipTopic {
            fork_digest: phase0_digest,
            kind,
        })
        .collect()
}

/// The altair gossip topics (using the altair fork digest) to subscribe to
/// when crossing `ALTAIR_FORK_EPOCH`.
///
/// Per `specs/altair/p2p-interface.md:184-188` and
/// `specs/altair/light-client/p2p-interface.md:47-48`.
///
/// Attestation subnet topics (per-subnet `BeaconAttestation`) are handled by
/// the subnet rotation driver, not by this function.
pub(crate) fn altair_gossip_topics<E: EthSpec>(altair_digest: ForkDigest) -> Vec<GossipTopic> {
    let mut topics = Vec::new();

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

    // Also subscribe to the core beacon topics under the altair fork digest.
    // Peers will send blocks, attestations, etc. using the altair fork digest
    // once they have also crossed the boundary.
    let base_kinds = [
        GossipTopicKind::BeaconBlock,
        GossipTopicKind::BeaconAggregateAndProof,
        GossipTopicKind::VoluntaryExit,
        GossipTopicKind::ProposerSlashing,
        GossipTopicKind::AttesterSlashing,
    ];
    for kind in base_kinds {
        topics.push(GossipTopic {
            fork_digest: altair_digest,
            kind,
        });
    }

    topics
}

/// Returns the list of altair topics for a given fork digest.
///
/// Public helper used by integration tests to verify that both nodes subscribed
/// to the expected set of altair topics.
pub fn altair_topic_list<E: EthSpec>(altair_digest: ForkDigest) -> Vec<GossipTopic> {
    altair_gossip_topics::<E>(altair_digest)
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
