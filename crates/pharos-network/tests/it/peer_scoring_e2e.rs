//! Peer-scoring signal-wiring end-to-end test.
//!
//! Drives synthetic misbehaviour events through the *wired* swarm-loop path
//! (`Network` built with the real `RealScorer`, no spawn) and asserts the
//! Contract:
//!
//! 1. `gossipsub::Event::SlowPeer` is score-NEUTRAL for `RealScorer`: native
//!    gossipsub v1.1 (`slow_peer_weight`) owns the slow-peer penalty, so the
//!    `RealScorer` score must NOT move (ADR `D-gossipsub-peer-scoring`, §7.4 —
//!    no double-penalty).
//! 2. Rate-limit-exceeded requests lower the score (the real per-method token
//!    bucket gate → `ScoreEvent::RateLimitExceeded`).
//! 3. A peer driven below the disconnect/ban thresholds by surviving
//!    `RealScorer` signals (req-resp / inbound-stream-reset) is selected by
//!    `worst_peers` (prune candidate) and banned by the enforcement tick.
//! 4. The `pharos_peer_score` gauge moves to reflect the distribution.
//!
//! ## Approach
//!
//! Like `dial_dedup.rs`, the swarm event loop is hard to spin up live, so we
//! build a `Network` via `NetworkBuilder::build()` (no spawn) and drive the
//! REAL wired methods through `#[doc(hidden)]` test seams
//! (`test_on_gossip_event`, `test_rate_limit_request`, `test_tick_score_prune`).
//! The gauge is observed through a process-local Prometheus recorder installed
//! with `init_metrics_with_handle()` (this integration binary owns the global
//! recorder).

use std::net::{Ipv4Addr, SocketAddr};

use libp2p::PeerId;
use libp2p::gossipsub;
use libp2p::gossipsub::FailedMessages;
use libp2p::identity::Keypair;

use pharos_network::scoring::RpcMethod;
use pharos_network::{NetworkBuilder, RealScorer};
use pharos_types::MainnetBeaconSpec;
use pharos_types::phase0::primitives::ForkDigest;
use pharos_utils::metrics::{METRIC_PEER_SCORE, init_metrics_with_handle};

use crate::common::TestHost;

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

async fn build_network() -> pharos_network::Network<MainnetBeaconSpec, TestHost, RealScorer> {
    let local_key = Keypair::generate_secp256k1();
    let discv5_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let (network, _handle, _discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(local_key)
            .tcp_listen_port(0)
            .discv5_addr(discv5_addr)
            .scorer(RealScorer::new())
            .build()
            .await
            .expect("NetworkBuilder::build failed");
    network
}

fn slow_peer_event(peer: PeerId, failed: usize) -> gossipsub::Event {
    // `FailedMessages::total()` (the severity our handler reads) sums only the
    // `priority` + `non_priority` queue-full counts, so populate `priority`.
    gossipsub::Event::SlowPeer {
        peer_id: peer,
        failed_messages: FailedMessages {
            publish: 0,
            forward: 0,
            priority: failed,
            non_priority: 0,
            timeout: 0,
        },
    }
}

/// `SlowPeer` events are score-NEUTRAL for `RealScorer`: native gossipsub v1.1
/// owns the slow-peer penalty, so the wired handler must NOT move the
/// `RealScorer` score (ADR `D-gossipsub-peer-scoring`, §7.4 subsume decision —
/// no double-penalty).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_peer_event_does_not_move_real_scorer() {
    let mut network = build_network().await;
    let peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    network.test_register_connected_peer(peer);

    let baseline = network.test_peer_score(&peer);
    assert_eq!(baseline, 0.0, "fresh peer starts at score 0");

    network.test_on_gossip_event(slow_peer_event(peer, 5)).await;

    let after = network.test_peer_score(&peer);
    assert_eq!(
        after, baseline,
        "SlowPeer must NOT touch the RealScorer score (native gossipsub owns it): \
         after {after} == baseline {baseline}"
    );
}

/// Over-limit req-resp requests are rejected and penalise the peer's score.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_exceeded_lowers_score() {
    let mut network = build_network().await;
    let peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    network.test_register_connected_peer(peer);

    // BlocksByRange burst capacity is 10; the 11th request in the same instant
    // exhausts the bucket and must be rejected.
    let m = RpcMethod::BlocksByRange;
    for i in 0..10 {
        assert!(
            network.test_rate_limit_request(peer, m),
            "request {i} within burst capacity must be allowed"
        );
    }
    let before_reject = network.test_peer_score(&peer);
    let allowed = network.test_rate_limit_request(peer, m);
    assert!(!allowed, "11th request must be rate-limited");
    let after_reject = network.test_peer_score(&peer);
    assert!(
        after_reject < before_reject,
        "a rate-limited request must penalise the peer: {after_reject} < {before_reject}"
    );
}

/// A peer driven far below the thresholds is selected by `worst_peers` and
/// banned by the enforcement tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn misbehaving_peer_is_pruned_and_banned() {
    let mut network = build_network().await;
    let bad: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    let good: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    network.test_register_connected_peer(bad);
    network.test_register_connected_peer(good);

    // Hammer the bad peer with inbound-stream-reset penalties (a surviving
    // `RealScorer` req-resp signal, -5 each) until it crosses the ban threshold
    // (-100). 21 resets in a tight loop (decay negligible over microseconds)
    // clear -100. SlowPeer is no longer a `RealScorer` signal (native gossipsub
    // owns it — ADR `D-gossipsub-peer-scoring`, §7.4).
    for _ in 0..21 {
        network.test_record_inbound_stream_reset(bad);
    }

    let bad_score = network.test_peer_score(&bad);
    assert!(
        bad_score <= -100.0,
        "bad peer must be below the ban threshold, got {bad_score}"
    );

    // worst_peers must rank the bad peer first.
    let worst = network.test_worst_peers(2);
    assert_eq!(worst.first(), Some(&bad), "bad peer must be the worst peer");

    // The enforcement tick must ban it.
    assert!(
        !network.test_peer_is_banned(&bad),
        "peer not banned before the tick"
    );
    network.test_tick_score_prune();
    assert!(
        network.test_peer_is_banned(&bad),
        "tick_score_prune must ban a peer below the ban threshold"
    );
}

/// An inbound stream reset lowers the peer's req_resp score but does NOT
/// consume any token from the Status (or any other) per-method rate-limit bucket.
///
/// Specifically: after one `InboundStreamReset`, the Status bucket must still
/// hold its full capacity of 5 tokens — all 5 requests must be allowed.
/// This verifies the fix for the pre-Phase-2 misattribution that pinned every
/// `InboundFailure` to `RpcError{Status, StreamReset}`, which consumed Status
/// tokens from peers that may never have sent a bad Status request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_stream_reset_does_not_penalise_status_bucket() {
    let mut network = build_network().await;
    let peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    network.test_register_connected_peer(peer);

    let before_reset = network.test_peer_score(&peer);

    // Record one inbound stream reset — this should lower req_resp but leave
    // every per-method token bucket untouched.
    network.test_record_inbound_stream_reset(peer);

    let after_reset = network.test_peer_score(&peer);
    assert!(
        after_reset < before_reset,
        "InboundStreamReset must lower the score: after {after_reset} < before {before_reset}"
    );

    // Status bucket must still be at full capacity (5 tokens for control-plane
    // methods per rate_limit_for). If InboundStreamReset wrongly consumed a
    // Status token, the 5th allow_request call here would fail.
    for i in 0..5 {
        assert!(
            network.test_rate_limit_request(peer, RpcMethod::Status),
            "Status request {i} must be allowed: InboundStreamReset must not consume Status tokens"
        );
    }
    // Exactly 5 tokens: the 6th must be rejected. Pins the bucket at full
    // capacity, so a future change that leaks even one token is caught.
    assert!(
        !network.test_rate_limit_request(peer, RpcMethod::Status),
        "Status bucket must be exhausted after exactly 5 requests"
    );
}

/// The `pharos_peer_score` gauge moves when a peer's score changes through the
/// wired path. This integration binary owns the global Prometheus recorder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_score_gauge_moves() {
    let handle = init_metrics_with_handle().expect("install recorder");

    let mut network = build_network().await;
    let peer: PeerId = Keypair::generate_secp256k1().public().to_peer_id();
    network.test_register_connected_peer(peer);

    // Drive the peer below the ban threshold via a surviving `RealScorer`
    // signal (inbound stream reset, -5 each); the gauge bucket counts update on
    // each score change (per-event gauge emit + the enforcement tick).
    for _ in 0..21 {
        network.test_record_inbound_stream_reset(peer);
    }
    network.test_tick_score_prune();

    let rendered = handle.render();
    assert!(
        rendered.contains(METRIC_PEER_SCORE),
        "rendered metrics must contain the peer-score gauge:\n{rendered}"
    );
    // The "banned" bucket gauge must have been observed with a non-zero value
    // for the misbehaving peer at some point.
    assert!(
        rendered.contains("bucket=\"banned\""),
        "peer-score gauge must carry a 'banned' bucket label:\n{rendered}"
    );
}
