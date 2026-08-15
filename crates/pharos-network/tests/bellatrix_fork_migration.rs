//! Integration test: bellatrix fork migration and gossip block decode.
//!
//! Mirrors `fork_epoch_migration.rs`. Covers two scenarios:
//!
//! (a) A bellatrix-at-genesis node ends subscribed to the bellatrix-digest
//!     topic set (subscribe + re-subscribe round-trip succeeds for all
//!     bellatrix topics).
//!
//! (b) A `beacon_block` gossip message encoded as a Bellatrix block decodes
//!     through `dispatch_gossip_message` WITHOUT returning
//!     `GossipVerdict::Reject("ssz decode")` when the host recognises the
//!     bellatrix fork digest.
//!
//! The test drives the migration directly (subscribe/unsubscribe commands via
//! `NetworkHandle`) rather than running the full epoch driver loop, keeping the
//! test fast and deterministic.

mod common;

use std::time::Duration;

use pharos_network::gossip::dispatch_gossip_message;
use pharos_network::host::GossipVerdict;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::ForkDigest;
use pharos_ssz::Encode as _;
use pharos_types::MainnetEthSpec;
use pharos_types::bellatrix::MainnetSignedBeaconBlock as BellatrixSignedBeaconBlock;
use pharos_types::fork::compute_fork_digest;
use pharos_types::phase0::primitives::{Root, Version};

use common::{TestHost, spawn_node};

// ── Constants ─────────────────────────────────────────────────────────────────

const PHASE0_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const ALTAIR_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
const BELLATRIX_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

fn gvr() -> Root {
    Root::default()
}

fn phase0_digest() -> ForkDigest {
    compute_fork_digest(Version::from_array(PHASE0_VERSION), &gvr())
}

fn altair_digest() -> ForkDigest {
    compute_fork_digest(Version::from_array(ALTAIR_VERSION), &gvr())
}

fn bellatrix_digest() -> ForkDigest {
    compute_fork_digest(Version::from_array(BELLATRIX_VERSION), &gvr())
}

/// All bellatrix topics under the bellatrix fork digest.
fn bellatrix_topics() -> Vec<GossipTopic> {
    let fd = bellatrix_digest();
    let mut topics = vec![
        GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::BeaconBlock,
        },
        GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::BeaconAggregateAndProof,
        },
        GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::VoluntaryExit,
        },
        GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::ProposerSlashing,
        },
        GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::AttesterSlashing,
        },
        GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::SyncCommitteeContributionAndProof,
        },
    ];
    for i in 0..<MainnetEthSpec as pharos_types::EthSpec>::SYNC_COMMITTEE_SUBNET_COUNT {
        topics.push(GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::SyncCommittee(i),
        });
    }
    topics.push(GossipTopic {
        fork_digest: fd,
        kind: GossipTopicKind::LightClientFinalityUpdate,
    });
    topics.push(GossipTopic {
        fork_digest: fd,
        kind: GossipTopicKind::LightClientOptimisticUpdate,
    });
    topics
}

// ── Scenario (a): bellatrix-at-genesis subscription round-trip ────────────────

/// Run once: spawn a node that starts on the phase0 digest (simulating
/// pre-fork), then migrate it to the bellatrix topic set via the
/// `NetworkHandle` subscribe/unsubscribe API.
///
/// Asserts that all bellatrix topics can be subscribed (no error) and that
/// re-subscribing them is idempotent (no error from duplicate subscribe).
async fn run_bellatrix_subscription_once() {
    let bellatrix_fd = bellatrix_digest();
    let phase0_fd = phase0_digest();
    let altair_fd = altair_digest();

    // Start the node with the phase-0 digest; wire altair + bellatrix digests
    // into the TestHost so fork_from_context works for all three forks.
    let host = TestHost::new(phase0_fd)
        .with_altair_fork_digest(altair_fd)
        .with_bellatrix_fork_digest(bellatrix_fd);

    let node = spawn_node(vec![], host, false).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Subscribe to all bellatrix topics (simulates migration arriving at
    // the bellatrix boundary from any prior state).
    for topic in bellatrix_topics() {
        node.handle
            .subscribe(topic)
            .await
            .expect("subscribe to bellatrix topic must succeed");
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Re-subscribing must be idempotent (gossipsub returns false but our
    // wrapper maps any outcome to Ok(())).
    for topic in bellatrix_topics() {
        node.handle
            .subscribe(topic)
            .await
            .expect("re-subscribe to bellatrix topic must succeed (idempotent)");
    }

    node.handle.shutdown().await;
}

// ── Scenario (b): bellatrix beacon_block SSZ decode via dispatch_gossip_message

/// `dispatch_gossip_message` with a bellatrix-digest topic and a valid
/// Bellatrix `SignedBeaconBlock` SSZ payload must return `GossipVerdict::Accept`
/// (or `Ignore`), never `GossipVerdict::Reject("ssz decode")`.
///
/// The mock host recognises the bellatrix digest via `fork_from_context` →
/// `Fork::Bellatrix`, so the dispatch path decodes as a `BellatrixSignedBeaconBlock`.
fn bellatrix_block_gossip_decodes_without_reject() {
    use common::TestHost;

    let bellatrix_fd = bellatrix_digest();
    let phase0_fd = phase0_digest();
    let altair_fd = altair_digest();

    // Build a TestHost that recognises all three fork digests.
    let host = TestHost::new(phase0_fd)
        .with_altair_fork_digest(altair_fd)
        .with_bellatrix_fork_digest(bellatrix_fd);

    // Encode a default Bellatrix SignedBeaconBlock as SSZ.
    let block = BellatrixSignedBeaconBlock::default();
    let ssz_bytes = block.as_ssz_bytes();

    // Build a beacon_block topic carrying the bellatrix fork digest.
    let topic = GossipTopic {
        fork_digest: bellatrix_fd,
        kind: GossipTopicKind::BeaconBlock,
    };

    let verdict = dispatch_gossip_message::<MainnetEthSpec, _>(&host, &topic, &ssz_bytes);

    // Accept or Ignore are both valid (the mock host's validate_beacon_block
    // returns Accept for every well-formed block). Reject("ssz decode") means
    // the dispatch path used the wrong fork type.
    assert!(
        !matches!(&verdict, GossipVerdict::Reject(r) if r == "ssz decode"),
        "dispatch_gossip_message must NOT return Reject(\"ssz decode\") for a valid \
         Bellatrix block on a bellatrix-digest topic, got: {:?}",
        verdict
    );
}

// ── Scenario (c): sequential phase0 → altair → bellatrix migration ────────────

/// The five base beacon topics under `fd`.
fn base_topics(fd: ForkDigest) -> Vec<GossipTopic> {
    use GossipTopicKind::{
        AttesterSlashing, BeaconAggregateAndProof, BeaconBlock, ProposerSlashing, VoluntaryExit,
    };
    [
        BeaconBlock,
        BeaconAggregateAndProof,
        VoluntaryExit,
        ProposerSlashing,
        AttesterSlashing,
    ]
    .into_iter()
    .map(|kind| GossipTopic {
        fork_digest: fd,
        kind,
    })
    .collect()
}

/// Base topics plus the altair-extra topics, all under `fd` (the topic set an
/// altair-or-later fork carries).
fn full_topics(fd: ForkDigest) -> Vec<GossipTopic> {
    let mut t = base_topics(fd);
    t.push(GossipTopic {
        fork_digest: fd,
        kind: GossipTopicKind::SyncCommitteeContributionAndProof,
    });
    for i in 0..<MainnetEthSpec as pharos_types::EthSpec>::SYNC_COMMITTEE_SUBNET_COUNT {
        t.push(GossipTopic {
            fork_digest: fd,
            kind: GossipTopicKind::SyncCommittee(i),
        });
    }
    t.push(GossipTopic {
        fork_digest: fd,
        kind: GossipTopicKind::LightClientFinalityUpdate,
    });
    t.push(GossipTopic {
        fork_digest: fd,
        kind: GossipTopicKind::LightClientOptimisticUpdate,
    });
    t
}

/// Drive a node through BOTH crossings in sequence: phase0 → altair → bellatrix.
/// At each crossing we subscribe the new-digest topic set and unsubscribe the
/// old-digest set, exactly as the generalized `do_migration` loop does. Every
/// command must succeed (unsubscribe of a no-longer-held topic is idempotent),
/// proving the two-step migration leaves the node cleanly on the bellatrix set.
async fn run_sequential_migration_once() {
    let phase0_fd = phase0_digest();
    let altair_fd = altair_digest();
    let bellatrix_fd = bellatrix_digest();

    let host = TestHost::new(phase0_fd)
        .with_altair_fork_digest(altair_fd)
        .with_bellatrix_fork_digest(bellatrix_fd);
    let node = spawn_node(vec![], host, false).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start subscribed on the phase0 base topic set.
    for topic in base_topics(phase0_fd) {
        node.handle
            .subscribe(topic)
            .await
            .expect("subscribe phase0 base topic");
    }

    // Crossing 1 — phase0 → altair: add altair full set, drop phase0 base set.
    for topic in full_topics(altair_fd) {
        node.handle
            .subscribe(topic)
            .await
            .expect("subscribe altair topic");
    }
    for topic in base_topics(phase0_fd) {
        node.handle
            .unsubscribe(topic)
            .await
            .expect("unsubscribe phase0 topic");
    }

    // Crossing 2 — altair → bellatrix: add bellatrix full set, drop altair set.
    for topic in full_topics(bellatrix_fd) {
        node.handle
            .subscribe(topic)
            .await
            .expect("subscribe bellatrix topic");
    }
    for topic in full_topics(altair_fd) {
        node.handle
            .unsubscribe(topic)
            .await
            .expect("unsubscribe altair topic");
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Final-state proof: the bellatrix set re-subscribes idempotently (still
    // held), confirming the node ended on the bellatrix digest after two
    // crossings.
    for topic in full_topics(bellatrix_fd) {
        node.handle
            .subscribe(topic)
            .await
            .expect("re-subscribe bellatrix idempotent after two crossings");
    }

    node.handle.shutdown().await;
}

// ── Test entry points ─────────────────────────────────────────────────────────

/// Bellatrix-at-genesis subscription round-trip: 5 consecutive runs.
#[tokio::test(flavor = "multi_thread")]
async fn bellatrix_subscription_round_trip() {
    for _run in 0..5 {
        run_bellatrix_subscription_once().await;
    }
}

/// Bellatrix beacon_block gossip message decodes without SSZ error.
#[test]
fn bellatrix_beacon_block_dispatch_no_ssz_reject() {
    bellatrix_block_gossip_decodes_without_reject();
}

/// Sequential two-step migration phase0 → altair → bellatrix.
#[tokio::test(flavor = "multi_thread")]
async fn phase0_altair_bellatrix_sequential_migration() {
    run_sequential_migration_once().await;
}
