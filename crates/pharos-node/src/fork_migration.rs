//! Cross-fork ENR migration and gossip topic rotation driver.
//!
//! This loop handles the phase0→altair→bellatrix→capella crossings within a
//! single run. It tracks the last-applied fork version (`prior`) and fires
//! `do_migration` whenever the wall-clock epoch enters a new fork. The loop
//! does NOT exit after the first crossing.
//!
//! Per `specs/altair/p2p-interface.md`, `specs/bellatrix/p2p-interface.md`,
//! and `specs/capella/p2p-interface.md` cross-fork ENR migration requirements
//! and `D-fork-schedule-source` (M3b).
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

use pharos_types::BeaconSpec;
use pharos_types::fork::{ForkSchedule, compute_fork_digest, compute_fork_digest_for_epoch};
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
pub async fn run_fork_migration_loop<E: BeaconSpec>(
    cmd: NetworkCommandSender<E>,
    discovery: DiscoveryHandle,
    fork_schedule: Arc<ForkSchedule>,
    genesis_time_secs: u64,
    seconds_per_slot: u64,
) {
    // If altair, bellatrix, capella, deneb, and electra are all FAR_FUTURE_EPOCH,
    // no migrations will ever occur; exit immediately to avoid a useless spinning loop.
    if fork_schedule.altair_fork_epoch == Epoch(u64::MAX)
        && fork_schedule.bellatrix_fork_epoch == Epoch(u64::MAX)
        && fork_schedule.capella_fork_epoch == Epoch(u64::MAX)
        && fork_schedule.deneb_fork_epoch == Epoch(u64::MAX)
        && fork_schedule.electra_fork_epoch == Epoch(u64::MAX)
    {
        return;
    }

    // Runtime slot duration (config), NOT compile-time `E::SLOT_DURATION_MS`
    // (mainnet 12s): on a non-12s network the wrong value advances the epoch at
    // the wrong rate, firing fork/topic/ENR migrations at the wrong wall time.
    let slot_ms = seconds_per_slot.saturating_mul(1000).max(1);
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
async fn do_migration<E: BeaconSpec>(
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

// ── BPO-boundary migration (RI-2, EIP-7892) ────────────────────────────────────

/// A scheduled blob-parameter-only (BPO) boundary migration within the Fulu fork.
///
/// At each `BLOB_SCHEDULE` entry's epoch the active blob parameters change, so
/// the fork digest rotates (EIP-7892 XOR formula) even though the fork version
/// (`fulu_fork_version`) is unchanged. `new_digest` is the digest active at and
/// after `epoch`; the loop unsubscribes the prior-digest topics and subscribes
/// the new-digest topics at the boundary. Distinct from the regular
/// fork-boundary migration (`run_fork_migration_loop`), which fires on a fork
/// VERSION change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpoMigration {
    /// The epoch at which this BPO entry activates (the migration fires here).
    pub epoch: Epoch,
    /// `MAX_BLOBS_PER_BLOCK` at and after `epoch` (the parameter that rotates
    /// the digest).
    pub max_blobs_per_block: u64,
    /// The fork digest active at and after `epoch` (BPO-aware, EIP-7892).
    pub new_digest: ForkDigest,
}

/// Build the ordered list of BPO-boundary migrations from a `ForkSchedule`.
///
/// Parses `fork_schedule.blob_schedule` (EIP-7892 `BLOB_SCHEDULE`) and produces
/// one [`BpoMigration`] per entry, in ascending epoch order, each carrying the
/// fork digest computed via [`compute_fork_digest_for_epoch`] at the entry's
/// epoch with that entry's blob parameters. Returns an empty vec when no Fulu
/// fork / blob schedule is configured.
///
/// `max_blobs_per_block_electra` is `E::MAX_BLOBS_PER_BLOCK_ELECTRA` (the
/// pre-Fulu baseline the digest helper falls back to before the first entry).
///
/// RI-2 (EIP-7892): the riskiest integration point — the digest MUST rotate at
/// every BPO boundary or peers on the new digest will not gossip with us.
pub fn schedule_bpo_boundary_migrations<E: BeaconSpec>(
    fork_schedule: &ForkSchedule,
    max_blobs_per_block_electra: u64,
) -> Vec<BpoMigration> {
    let gvr = fork_schedule.genesis_validators_root;
    let fulu_version = fork_schedule.fulu_fork_version;

    let mut entries: Vec<BpoMigration> = fork_schedule
        .blob_schedule
        .iter()
        .map(|entry| {
            let epoch = Epoch(entry.epoch);
            let new_digest = compute_fork_digest_for_epoch(
                fulu_version,
                &gvr,
                epoch,
                fork_schedule.fulu_fork_epoch,
                &fork_schedule.blob_schedule,
                fork_schedule.electra_fork_epoch,
                max_blobs_per_block_electra,
            );
            BpoMigration {
                epoch,
                max_blobs_per_block: entry.max_blobs_per_block,
                new_digest,
            }
        })
        .collect();

    entries.sort_by_key(|m| m.epoch.0);
    entries
}

/// Run the BPO-boundary migration loop within the Fulu fork (RI-2, EIP-7892).
///
/// Ticks every slot. At each scheduled [`BpoMigration`] boundary (the first
/// wall-clock tick at or after `migration.epoch`), recomputes the fork digest
/// (already carried in the `BpoMigration`), unsubscribes the prior-digest
/// topics, subscribes the new-digest topics, and updates the ENR.
///
/// Distinct from `run_fork_migration_loop` (which fires on fork VERSION
/// changes): this loop fires on blob-parameter changes that rotate the digest
/// without a version change. Exits immediately when no BPO entries are
/// scheduled.
pub async fn run_bpo_migration_loop<E: BeaconSpec>(
    cmd: NetworkCommandSender<E>,
    discovery: DiscoveryHandle,
    fork_schedule: Arc<ForkSchedule>,
    genesis_time_secs: u64,
    seconds_per_slot: u64,
    max_blobs_per_block_electra: u64,
) {
    let migrations =
        schedule_bpo_boundary_migrations::<E>(&fork_schedule, max_blobs_per_block_electra);
    if migrations.is_empty() {
        return;
    }

    // Runtime slot duration (config), NOT compile-time `E::SLOT_DURATION_MS`
    // (mainnet 12s): on a non-12s network the wrong value advances the epoch at
    // the wrong rate, firing fork/topic/ENR migrations at the wrong wall time.
    let slot_ms = seconds_per_slot.saturating_mul(1000).max(1);
    let slots_per_epoch = E::SLOTS_PER_EPOCH;
    let mut interval = tokio::time::interval(Duration::from_millis(slot_ms));

    // The fulu base digest (before the first BPO entry) is the prior digest for
    // the first migration; thereafter each migration's prior is the preceding
    // migration's `new_digest`.
    let mut prior_digest = compute_fork_digest_for_epoch(
        fork_schedule.fulu_fork_version,
        &fork_schedule.genesis_validators_root,
        fork_schedule.fulu_fork_epoch,
        fork_schedule.fulu_fork_epoch,
        &fork_schedule.blob_schedule,
        fork_schedule.electra_fork_epoch,
        max_blobs_per_block_electra,
    );
    let mut next_idx = 0usize;

    loop {
        interval.tick().await;

        if next_idx >= migrations.len() {
            return;
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let epoch = if genesis_time_secs > 0 && now_secs >= genesis_time_secs {
            let elapsed_ms = (now_secs - genesis_time_secs).saturating_mul(1000);
            let elapsed_slots = elapsed_ms / slot_ms.max(1);
            elapsed_slots / slots_per_epoch
        } else {
            0
        };
        let current_epoch = Epoch(epoch);

        // Fire every boundary we have crossed (handles multiple boundaries
        // crossed in one tick, e.g. on a slow startup).
        while next_idx < migrations.len() && current_epoch >= migrations[next_idx].epoch {
            let migration = migrations[next_idx].clone();
            // The forward-looking `nfd` (next fork digest) is the digest of the
            // NEXT BPO boundary, if any remains after this one. When this is the
            // last scheduled BPO entry, there is no further BPO digest to
            // advertise (`None`).
            let next_bpo_digest = migrations.get(next_idx + 1).map(|m| m.new_digest);
            do_bpo_migration::<E>(
                &cmd,
                &discovery,
                &fork_schedule,
                prior_digest,
                &migration,
                current_epoch,
                next_bpo_digest,
            )
            .await;
            prior_digest = migration.new_digest;
            next_idx += 1;
        }
    }
}

/// Execute a BPO-boundary migration: rotate topics from `old_digest` to
/// `migration.new_digest` and update the ENR.
async fn do_bpo_migration<E: BeaconSpec>(
    cmd: &NetworkCommandSender<E>,
    discovery: &DiscoveryHandle,
    fork_schedule: &ForkSchedule,
    old_digest: ForkDigest,
    migration: &BpoMigration,
    epoch: Epoch,
    next_bpo_digest: Option<ForkDigest>,
) {
    let new_digest = migration.new_digest;
    let fulu_version = fork_schedule.fulu_fork_version;

    info!(
        bpo_epoch = migration.epoch.0,
        max_blobs_per_block = migration.max_blobs_per_block,
        old_digest = ?old_digest,
        new_digest = ?new_digest,
        "BPO migration: crossing blob-parameter boundary (EIP-7892)"
    );

    // Step 1: Update the ENR `eth2` field with the new (rotated) digest, and the
    // `nfd` (next fork digest) field with the digest of the NEXT BPO boundary
    // (forward-looking, additive). `cgc` is owned by the custody-adjustment loop
    // (Phase 6a) and is left untouched here (`None`). Per `specs/fulu/p2p-interface.md`.
    let enr_fork_id = ENRForkID {
        fork_digest: new_digest,
        next_fork_version: fork_schedule.next_fork_version(epoch),
        next_fork_epoch: fork_schedule.next_fork_epoch(epoch),
    };
    let nfd = next_bpo_digest.map(|d| d.into_inner());
    if let Err(e) = discovery.update_enr_eth2_fulu(enr_fork_id, None, nfd).await {
        tracing::warn!(%e, "BPO migration: ENR eth2/nfd update failed");
    }

    // Step 2: Unsubscribe the prior-digest topics.
    let old_topics = topics_for_version::<E>(fulu_version, fork_schedule, old_digest);
    for topic in old_topics {
        if let Err(e) = send_unsubscribe(cmd, topic).await {
            tracing::debug!(%e, "BPO migration: old-digest unsubscribe error");
        }
    }

    // Step 3: Subscribe the new-digest topics.
    let new_topics = topics_for_version::<E>(fulu_version, fork_schedule, new_digest);
    for topic in new_topics {
        if let Err(e) = send_subscribe(cmd, topic).await {
            tracing::debug!(%e, "BPO migration: new-digest subscribe error");
        }
    }

    info!(new_digest = ?new_digest, "BPO migration: complete");
}

// ── Topic helpers ─────────────────────────────────────────────────────────────

/// Select the full topic set appropriate for `version` at `digest`.
///
/// - genesis_fork_version   → `phase0_gossip_topics` (5 base topics)
/// - altair_fork_version    → `altair_gossip_topics` (5 base + altair extras)
/// - bellatrix_fork_version → `bellatrix_gossip_topics`
///   (5 base + same altair extras, all under the bellatrix digest)
/// - capella_fork_version   → `capella_gossip_topics`
///   (5 base + altair extras + `bls_to_execution_change`)
/// - deneb_fork_version     → `deneb_gossip_topics`
///   (capella topics + `blob_sidecar_<i>` subnets)
/// - electra_fork_version   → `electra_gossip_topics`
///   (same topic shape as Deneb; EIP-7549 uses `beacon_aggregate_and_proof`
///   with a new container type but the same gossip topic name)
///
/// No `_ =>` fallback: a future fork must add an explicit arm here so that
/// a missing case is a compile error, not a silent regression to a stale digest.
fn topics_for_version<E: BeaconSpec>(
    version: Version,
    fork_schedule: &ForkSchedule,
    digest: ForkDigest,
) -> Vec<GossipTopic> {
    if version == fork_schedule.genesis_fork_version {
        phase0_gossip_topics(digest)
    } else if version == fork_schedule.altair_fork_version {
        altair_gossip_topics::<E>(digest)
    } else if version == fork_schedule.bellatrix_fork_version {
        bellatrix_gossip_topics::<E>(digest)
    } else if version == fork_schedule.capella_fork_version {
        capella_gossip_topics::<E>(digest)
    } else if version == fork_schedule.deneb_fork_version {
        deneb_gossip_topics::<E>(digest)
    } else if version == fork_schedule.electra_fork_version {
        // Electra gossip topics: same topic names as Deneb (EIP-7549 reuses
        // `beacon_aggregate_and_proof`; the new `SingleAttestation` per-subnet
        // publication is a VC concern, not a topic addition).
        electra_gossip_topics::<E>(digest)
    } else if version == fork_schedule.fulu_fork_version {
        // Fulu (EIP-7594 PeerDAS) gossip topics. The custody-gated
        // `data_column_sidecar_{subnet}` topics are NOT included here: they
        // depend on the node id + custody-group count and are subscribed
        // separately at the network layer via `subscribe_fulu_data_column_topics`.
        // This helper covers only the global + blob topics whose fork-digest
        // segment rotates at the fork / BPO boundary.
        fulu_gossip_topics::<E>(digest)
    } else {
        // Unreachable: every `fork_schedule` version is matched above. A future
        // fork MUST add an explicit arm here so a missing case is a compile-time
        // gap surfaced in review, not a silent regression to a stale digest.
        // (No `_ =>` fallthrough to a wrong topic set — M12 lesson.)
        unreachable!("topics_for_version: unknown fork version {version:?}")
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
pub(crate) fn altair_gossip_topics<E: BeaconSpec>(altair_digest: ForkDigest) -> Vec<GossipTopic> {
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
pub(crate) fn bellatrix_gossip_topics<E: BeaconSpec>(
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

/// The capella gossip topics: bellatrix extras + `bls_to_execution_change`,
/// all under the capella fork digest.
///
/// Per `specs/capella/p2p-interface.md`: Capella changes the `beacon_block`
/// container type and adds the new `bls_to_execution_change` global topic.
/// All other topic names remain the same as Bellatrix; the fork-digest segment
/// bumps at the Capella boundary.
///
/// Attestation subnet topics are handled by the subnet rotation driver.
pub(crate) fn capella_gossip_topics<E: BeaconSpec>(capella_digest: ForkDigest) -> Vec<GossipTopic> {
    let mut topics = bellatrix_gossip_topics::<E>(capella_digest);

    // New in Capella: `bls_to_execution_change` topic.
    topics.push(GossipTopic {
        fork_digest: capella_digest,
        kind: GossipTopicKind::BlsToExecutionChange,
    });

    topics
}

/// The deneb gossip topics: capella topics + the EIP-4844 `blob_sidecar_<i>`
/// subnet topics, all under the deneb fork digest.
///
/// Per `specs/deneb/p2p-interface.md`: Deneb adds `blob_sidecar_<subnet_id>` for
/// each subnet in `0..BLOB_SIDECAR_SUBNET_COUNT` (= 6). Without these, a node
/// crossing into Deneb never receives blob sidecars over gossip and a
/// blob-carrying block's data-availability gate can never be satisfied at the tip.
///
/// Attestation subnet topics are handled by the subnet rotation driver.
pub(crate) fn deneb_gossip_topics<E: BeaconSpec>(deneb_digest: ForkDigest) -> Vec<GossipTopic> {
    let mut topics = capella_gossip_topics::<E>(deneb_digest);

    // New in Deneb: `blob_sidecar_<i>` for each blob subnet.
    for subnet in 0..E::BLOB_SIDECAR_SUBNET_COUNT {
        topics.push(GossipTopic {
            fork_digest: deneb_digest,
            kind: GossipTopicKind::BlobSidecar(subnet),
        });
    }

    topics
}

/// The electra gossip topics: same topic names as Deneb under the electra fork digest.
///
/// EIP-7549 reuses the `beacon_aggregate_and_proof` topic name; the new
/// `SingleAttestation` per-subnet publication is a validator-client concern
/// and does not add a new gossip topic. The blob sidecar subnets are retained
/// (electra is a superset of Deneb for DA purposes).
///
/// Attestation subnet topics are handled by the subnet rotation driver.
pub(crate) fn electra_gossip_topics<E: BeaconSpec>(electra_digest: ForkDigest) -> Vec<GossipTopic> {
    // Electra inherits the full Deneb topic set; the fork-digest segment is
    // the only thing that changes at the Electra boundary.
    deneb_gossip_topics::<E>(electra_digest)
}

/// The fulu gossip topics: the same global + blob topic shape as Electra under
/// the fulu fork digest.
///
/// Per `specs/fulu/p2p-interface.md` (EIP-7594 PeerDAS): the
/// `data_column_sidecar_{subnet}` topics are NOT included here because they are
/// custody-gated (node-id + custody-group-count dependent) and subscribed
/// separately via `subscribe_fulu_data_column_topics`. This helper covers the
/// non-custody topics whose fork-digest segment rotates at the fulu / BPO
/// boundary.
///
/// Attestation subnet topics are handled by the subnet rotation driver.
pub(crate) fn fulu_gossip_topics<E: BeaconSpec>(fulu_digest: ForkDigest) -> Vec<GossipTopic> {
    deneb_gossip_topics::<E>(fulu_digest)
}

/// Returns the list of fulu (non-custody) topics for a given fork digest.
///
/// Public helper used by integration tests to verify that the migration
/// correctly subscribes to the fulu topic set. The custody-gated
/// `data_column_sidecar` topics are excluded (see `fulu_gossip_topics`).
pub fn fulu_topic_list<E: BeaconSpec>(fulu_digest: ForkDigest) -> Vec<GossipTopic> {
    fulu_gossip_topics::<E>(fulu_digest)
}

/// Returns the list of altair topics for a given fork digest.
///
/// Public helper used by integration tests to verify that both nodes subscribed
/// to the expected set of altair topics.
pub fn altair_topic_list<E: BeaconSpec>(altair_digest: ForkDigest) -> Vec<GossipTopic> {
    altair_gossip_topics::<E>(altair_digest)
}

/// Returns the list of bellatrix topics for a given fork digest.
///
/// Public helper used by integration tests to verify that the migration
/// correctly subscribes to the bellatrix topic set. The set is identical in
/// shape to the altair set (5 base + sync_committee_* + light_client_*) but
/// all topics carry the bellatrix fork digest.
pub fn bellatrix_topic_list<E: BeaconSpec>(bellatrix_digest: ForkDigest) -> Vec<GossipTopic> {
    bellatrix_gossip_topics::<E>(bellatrix_digest)
}

/// Returns the list of capella topics for a given fork digest.
///
/// Public helper used by integration tests to verify that the migration
/// correctly subscribes to the capella topic set. The set is the bellatrix
/// set (5 base + sync_committee_* + light_client_*) plus `bls_to_execution_change`.
pub fn capella_topic_list<E: BeaconSpec>(capella_digest: ForkDigest) -> Vec<GossipTopic> {
    capella_gossip_topics::<E>(capella_digest)
}

/// Returns the list of deneb topics for a given fork digest.
///
/// Public helper used by integration tests to verify that the migration
/// correctly subscribes to the deneb topic set: the capella set plus the
/// `blob_sidecar_<i>` subnet topics (EIP-4844).
pub fn deneb_topic_list<E: BeaconSpec>(deneb_digest: ForkDigest) -> Vec<GossipTopic> {
    deneb_gossip_topics::<E>(deneb_digest)
}

/// Returns the list of electra topics for a given fork digest.
///
/// Public helper used by integration tests to verify that the migration
/// correctly subscribes to the electra topic set. The electra set is identical
/// in shape to the deneb set (same topic kinds, electra fork digest).
pub fn electra_topic_list<E: BeaconSpec>(electra_digest: ForkDigest) -> Vec<GossipTopic> {
    electra_gossip_topics::<E>(electra_digest)
}

// ── Command helpers ───────────────────────────────────────────────────────────

/// Send a `Subscribe` command and await the reply.
async fn send_subscribe<E: BeaconSpec>(
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
async fn send_unsubscribe<E: BeaconSpec>(
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
    use pharos_types::MainnetBeaconSpec;
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
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(u64::MAX),
            deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
            deneb_fork_epoch: Epoch(u64::MAX),
            electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
            electra_fork_epoch: Epoch(u64::MAX),
            fulu_fork_version: Version::from_array([0x06, 0x00, 0x00, 0x00]),
            fulu_fork_epoch: Epoch(u64::MAX),
            blob_schedule: Vec::new(),
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
    /// For MainnetBeaconSpec: SYNC_COMMITTEE_SUBNET_COUNT = 4 → total = 12.
    ///
    /// All topics must carry the bellatrix digest, NOT the altair digest.
    #[test]
    fn bellatrix_topic_list_shape_and_digest() {
        use pharos_network::topics::GossipTopicKind;
        let sched = three_fork_schedule();
        let gvr = Root::default();
        let bellatrix_digest = compute_fork_digest(sched.bellatrix_fork_version, &gvr);
        let altair_digest = compute_fork_digest(sched.altair_fork_version, &gvr);

        let topics = bellatrix_topic_list::<MainnetBeaconSpec>(bellatrix_digest);

        // Count expected: 5 base + 1 contrib + SYNC_COMMITTEE_SUBNET_COUNT subnets + 2 lc.
        let sync_subnet_count =
            <MainnetBeaconSpec as pharos_types::BeaconSpec>::SYNC_COMMITTEE_SUBNET_COUNT as usize;
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
        for i in 0..<MainnetBeaconSpec as pharos_types::BeaconSpec>::SYNC_COMMITTEE_SUBNET_COUNT {
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

        let altair_topics = altair_topic_list::<MainnetBeaconSpec>(altair_digest);
        let bellatrix_topics = bellatrix_topic_list::<MainnetBeaconSpec>(bellatrix_digest);

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

    /// Deneb topics = capella topics + exactly `BLOB_SIDECAR_SUBNET_COUNT`
    /// `blob_sidecar_<i>` subnet topics; capella must NOT contain blob topics.
    /// This guards the bug where the migration subscribed the capella set for
    /// deneb and never received blob sidecars over gossip.
    #[test]
    fn deneb_topic_list_adds_blob_subnets() {
        use pharos_network::topics::GossipTopicKind;
        let sched = three_fork_schedule();
        let gvr = Root::default();
        let capella_digest = compute_fork_digest(sched.capella_fork_version, &gvr);
        let deneb_digest = compute_fork_digest(sched.deneb_fork_version, &gvr);

        let capella_topics = capella_topic_list::<MainnetBeaconSpec>(capella_digest);
        let deneb_topics = deneb_topic_list::<MainnetBeaconSpec>(deneb_digest);

        let n_blob = MainnetBeaconSpec::BLOB_SIDECAR_SUBNET_COUNT as usize;
        assert_eq!(
            deneb_topics.len(),
            capella_topics.len() + n_blob,
            "deneb must add exactly BLOB_SIDECAR_SUBNET_COUNT blob topics over capella"
        );

        let blob_count = deneb_topics
            .iter()
            .filter(|t| matches!(t.kind, GossipTopicKind::BlobSidecar(_)))
            .count();
        assert_eq!(blob_count, n_blob, "deneb must have all blob subnet topics");

        assert!(
            !capella_topics
                .iter()
                .any(|t| matches!(t.kind, GossipTopicKind::BlobSidecar(_))),
            "capella must not contain blob_sidecar topics"
        );

        // All blob subnets 0..N present exactly once.
        for subnet in 0..MainnetBeaconSpec::BLOB_SIDECAR_SUBNET_COUNT {
            assert_eq!(
                deneb_topics
                    .iter()
                    .filter(|t| t.kind == GossipTopicKind::BlobSidecar(subnet))
                    .count(),
                1,
                "blob_sidecar_{subnet} must be present exactly once"
            );
        }
    }

    /// Build a fulu-active fork schedule with the mainnet BLOB_SCHEDULE
    /// (two BPO entries) for the BPO-migration test.
    ///
    /// Versions + epochs mirror the Phase 1.5 digest-rotation test
    /// (`crates/pharos-types/src/fork.rs::fulu_fork_digest_rotates_per_bpo_entry`):
    /// FULU_FORK_VERSION 0x06000000, FULU_FORK_EPOCH 411392,
    /// ELECTRA_FORK_EPOCH 364032, BLOB_SCHEDULE [412672->15, 419072->21].
    fn fulu_schedule_mainnet() -> ForkSchedule {
        use pharos_types::fulu::BlobScheduleEntry;
        ForkSchedule {
            genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
            altair_fork_epoch: Epoch(0),
            bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
            bellatrix_fork_epoch: Epoch(0),
            capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
            capella_fork_epoch: Epoch(0),
            deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
            deneb_fork_epoch: Epoch(0),
            electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
            electra_fork_epoch: Epoch(364_032),
            fulu_fork_version: Version::from_array([0x06, 0x00, 0x00, 0x00]),
            fulu_fork_epoch: Epoch(411_392),
            blob_schedule: vec![
                BlobScheduleEntry {
                    epoch: 412_672,
                    max_blobs_per_block: 15,
                },
                BlobScheduleEntry {
                    epoch: 419_072,
                    max_blobs_per_block: 21,
                },
            ],
            genesis_validators_root: Root::default(),
        }
    }

    /// RI-2 (EIP-7892): the two mainnet BPO entries must produce two distinct
    /// migration events, in ascending epoch order, with DISTINCT fork digests
    /// matching the BPO-aware `compute_fork_digest_for_epoch` reference values.
    #[test]
    fn bpo_migrations_two_entries_distinct_digests() {
        use pharos_types::fork::compute_fork_digest_for_epoch;
        let sched = fulu_schedule_mainnet();
        let max_blobs_electra = MainnetBeaconSpec::MAX_BLOBS_PER_BLOCK_ELECTRA;

        let migrations =
            schedule_bpo_boundary_migrations::<MainnetBeaconSpec>(&sched, max_blobs_electra);

        assert_eq!(
            migrations.len(),
            2,
            "two BLOB_SCHEDULE entries must produce two BPO migration events"
        );

        // Ascending epoch order.
        assert_eq!(migrations[0].epoch, Epoch(412_672));
        assert_eq!(migrations[1].epoch, Epoch(419_072));
        assert_eq!(migrations[0].max_blobs_per_block, 15);
        assert_eq!(migrations[1].max_blobs_per_block, 21);

        // Distinct digests between the two boundaries.
        assert_ne!(
            migrations[0].new_digest, migrations[1].new_digest,
            "fork digest must rotate between the two BPO entries (RI-2)"
        );

        // Each migration's digest matches the canonical BPO-aware reference.
        let gvr = sched.genesis_validators_root;
        let reference_first = compute_fork_digest_for_epoch(
            sched.fulu_fork_version,
            &gvr,
            Epoch(412_672),
            sched.fulu_fork_epoch,
            &sched.blob_schedule,
            sched.electra_fork_epoch,
            max_blobs_electra,
        );
        let reference_second = compute_fork_digest_for_epoch(
            sched.fulu_fork_version,
            &gvr,
            Epoch(419_072),
            sched.fulu_fork_epoch,
            &sched.blob_schedule,
            sched.electra_fork_epoch,
            max_blobs_electra,
        );
        assert_eq!(
            migrations[0].new_digest, reference_first,
            "first BPO digest must match compute_fork_digest_for_epoch reference"
        );
        assert_eq!(
            migrations[1].new_digest, reference_second,
            "second BPO digest must match compute_fork_digest_for_epoch reference"
        );

        // Both BPO digests differ from the plain fulu base digest (the XOR with
        // blob params changes the bytes).
        let plain = compute_fork_digest(sched.fulu_fork_version, &gvr);
        assert_ne!(migrations[0].new_digest, plain);
        assert_ne!(migrations[1].new_digest, plain);
    }

    /// An empty `blob_schedule` (no BPO entries) yields no migrations.
    #[test]
    fn bpo_migrations_empty_schedule_is_empty() {
        let mut sched = fulu_schedule_mainnet();
        sched.blob_schedule.clear();
        let migrations = schedule_bpo_boundary_migrations::<MainnetBeaconSpec>(
            &sched,
            MainnetBeaconSpec::MAX_BLOBS_PER_BLOCK_ELECTRA,
        );
        assert!(
            migrations.is_empty(),
            "no BLOB_SCHEDULE entries must produce no BPO migrations"
        );
    }
}
