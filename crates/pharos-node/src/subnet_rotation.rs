//! Persistent attestation-subnet rotation driver.
//!
//! Implements the node-id-derived subnet subscription rotation per
//! `specs/phase0/p2p-interface.md:1732-1751`.
//!
//! The loop ticks every slot (`E::SLOT_DURATION_MS`). At each epoch boundary
//! it recomputes `compute_subscribed_subnets(node_id, epoch)` and diffs against
//! the prior epoch's subscriptions. Any subnet no longer in the assignment is
//! unsubscribed; any new subnet is subscribed. The local `MetaData.attnets`
//! bitvector is updated atomically via `NetworkCommand::UpdateMetaData`.
//!
//! Validator-duty-driven subnet subscriptions (M8) are separate; this driver
//! handles only the two node-id-derived long-lived subnets per
//! `SUBNETS_PER_NODE = 2`.

use std::sync::Arc;
use std::time::Duration;

use pharos_network::NodeId;
use pharos_ssz::Bitvector;
use pharos_types::EthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use tracing::{debug, info};

use pharos_network::NetworkCommandSender;
use pharos_network::discovery::subnets::{SUBNETS_PER_NODE, compute_subscribed_subnets};
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::ForkDigest;

// ── run_subnet_rotation_loop ──────────────────────────────────────────────────

/// Run the persistent attestation subnet rotation loop.
///
/// Ticks every slot (`E::SLOT_DURATION_MS`). At each epoch boundary, recomputes
/// the two node-id-derived persistent attestation subnets and:
/// - Unsubscribes from subnets no longer in the assignment.
/// - Subscribes to newly assigned subnets.
/// - Sends `NetworkCommand::UpdateMetaData` with the updated `attnets` bitvector
///   so `MetaData.seq_number` increments and peers with cached metadata refresh.
///
/// The `genesis_time_secs` parameter is the Unix timestamp of the genesis slot;
/// used to compute the current epoch from wall clock. When `0`, the loop starts
/// at epoch 0 (suitable for tests).
///
/// Per `specs/phase0/p2p-interface.md:1732-1751` and `EPOCHS_PER_SUBNET_SUBSCRIPTION = 256`.
pub async fn run_subnet_rotation_loop<E: EthSpec>(
    cmd: NetworkCommandSender<E>,
    fork_schedule: Arc<ForkSchedule>,
    node_id: NodeId,
    genesis_time_secs: u64,
) {
    let slot_ms = E::SLOT_DURATION_MS;
    let slots_per_epoch = E::SLOTS_PER_EPOCH;
    let mut interval = tokio::time::interval(Duration::from_millis(slot_ms));

    // Track which subnets we are currently subscribed to.
    let mut current_subnets: [u64; SUBNETS_PER_NODE] = [u64::MAX; SUBNETS_PER_NODE];
    let mut last_epoch: u64 = u64::MAX;

    loop {
        interval.tick().await;

        // Compute current epoch from wall clock or genesis.
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

        // Only act at epoch boundaries.
        if epoch == last_epoch {
            continue;
        }
        last_epoch = epoch;

        let new_subnets = compute_subscribed_subnets::<E>(node_id, epoch);
        if new_subnets == current_subnets {
            continue;
        }

        // Compute fork digest for attestation subnet topics.
        let gvr = fork_schedule.genesis_validators_root;
        let fork_version = fork_schedule.current_fork_version(pharos_utils::Epoch(epoch));
        let fork_digest = pharos_types::fork::compute_fork_digest(fork_version, &gvr);

        // Unsubscribe from subnets no longer assigned.
        for old_subnet in &current_subnets {
            if *old_subnet == u64::MAX {
                continue;
            }
            if !new_subnets.contains(old_subnet) {
                let topic = GossipTopic {
                    fork_digest,
                    kind: GossipTopicKind::BeaconAttestation(*old_subnet),
                };
                if let Err(e) = send_unsubscribe(&cmd, topic).await {
                    debug!(%e, subnet = old_subnet, "subnet unsubscribe error");
                }
            }
        }

        // Subscribe to newly assigned subnets.
        for new_subnet in &new_subnets {
            if !current_subnets.contains(new_subnet) {
                let topic = GossipTopic {
                    fork_digest,
                    kind: GossipTopicKind::BeaconAttestation(*new_subnet),
                };
                if let Err(e) = send_subscribe(&cmd, topic).await {
                    debug!(%e, subnet = new_subnet, "subnet subscribe error");
                }
            }
        }

        // Build new attnets bitvector and push metadata update.
        let mut attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::default();
        for subnet in &new_subnets {
            attnets.set(*subnet as usize, true);
        }
        let new_meta = AltairMetaData {
            seq_number: 0, // seq_number managed by Network on UpdateMetaData
            attnets,
            syncnets: Bitvector::default(),
        };
        if let Err(e) = cmd
            .send(pharos_network::NetworkCommand::UpdateMetaData(new_meta))
            .await
        {
            debug!(%e, "metadata update error");
        }

        info!(
            epoch,
            new_subnets = ?new_subnets,
            "attestation subnet assignment rotated"
        );
        current_subnets = new_subnets;
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Send a fire-and-forget `Subscribe` command; wait for the reply but ignore errors.
async fn send_subscribe<E: EthSpec>(
    cmd: &NetworkCommandSender<E>,
    topic: GossipTopic,
) -> Result<(), pharos_network::NetworkError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    cmd.send(pharos_network::NetworkCommand::Subscribe {
        topic,
        reply: reply_tx,
    })
    .await?;
    reply_rx
        .await
        .map_err(|_| pharos_network::NetworkError::ChannelClosed)?
}

/// Send a fire-and-forget `Unsubscribe` command; wait for the reply but ignore errors.
async fn send_unsubscribe<E: EthSpec>(
    cmd: &NetworkCommandSender<E>,
    topic: GossipTopic,
) -> Result<(), pharos_network::NetworkError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    cmd.send(pharos_network::NetworkCommand::Unsubscribe {
        topic,
        reply: reply_tx,
    })
    .await?;
    reply_rx
        .await
        .map_err(|_| pharos_network::NetworkError::ChannelClosed)?
}

/// Build the attestation subnet `GossipTopic` list for `subnets` under `fork_digest`.
///
/// Helper used by `fork_migration.rs` to compute the set of attestation topics
/// to subscribe/unsubscribe when crossing a fork epoch.
pub fn attnets_topics(
    fork_digest: ForkDigest,
    subnets: &[u64; SUBNETS_PER_NODE],
) -> Vec<GossipTopic> {
    subnets
        .iter()
        .map(|&subnet| GossipTopic {
            fork_digest,
            kind: GossipTopicKind::BeaconAttestation(subnet),
        })
        .collect()
}
